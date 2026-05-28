import subprocess
import json
import os


class HostAudit:
    def __init__(self, target="local"):
        self.target = target
        self.findings = []
        self.daemon_config = {}
        self.host_info = {}

    def run(self):
        """
        Ejecuta todas las comprobaciones de seguridad del host Docker.
        Devuelve un diccionario con hallazgos y metadatos.
        """

        self.daemon_config = self._load_daemon_config()
        self.host_info = self._inspect_docker_socket()
        self.host_info.update(self._load_docker_info())
        self.host_info.update(self._load_kernel_info())
        self.host_info.update(self._load_audit_info())
        self.host_info.update(self._load_security_info())
        self.host_info.update(self._load_daemon_config_file_info())

        self.check_docker_version()
        self.check_docker_socket_permissions()
        self.check_daemon_configuration()

        return {
            "findings": self.findings,
            "daemon_config": self.daemon_config,
            "host_info": self.host_info
        }

    # ---------------------------------------------------
    # CHECK 1 — Versión de Docker
    # ---------------------------------------------------

    def check_docker_version(self):
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                version_output = result.stdout.strip()

                self.findings.append({
                    "id": "HOST-001",
                    "title": "Docker version detected",
                    "severity": "info",
                    "description": f"Docker version: {version_output}",
                    "recommendation": "Ensure Docker is updated to the latest stable version."
                })
            else:
                self.findings.append({
                    "id": "HOST-002",
                    "title": "Docker not accessible",
                    "severity": "critical",
                    "description": "Unable to retrieve Docker version.",
                    "recommendation": "Verify Docker installation and permissions."
                })

        except Exception as e:
            self.findings.append({
                "id": "HOST-003",
                "title": "Error executing docker command",
                "severity": "critical",
                "description": str(e),
                "recommendation": "Check execution environment."
            })

    # ---------------------------------------------------
    # CHECK 2 — Permisos del socket Docker
    # ---------------------------------------------------

    def check_docker_socket_permissions(self):
        socket_path = "/var/run/docker.sock"

        if os.path.exists(socket_path):
            stat_info = os.stat(socket_path)

            permissions = oct(stat_info.st_mode)[-3:]

            if permissions != "660":
                self.findings.append({
                    "id": "HOST-004",
                    "title": "Docker socket permissions potentially insecure",
                    "severity": "high",
                    "description": f"Current permissions: {permissions}",
                    "recommendation": "Restrict docker.sock permissions to 660 and limit group membership."
                })
            else:
                self.findings.append({
                    "id": "HOST-005",
                    "title": "Docker socket permissions correctly restricted",
                    "severity": "info",
                    "description": "docker.sock permissions are set to 660.",
                    "recommendation": "Maintain restricted access to Docker group."
                })
        else:
            self.findings.append({
                "id": "HOST-006",
                "title": "Docker socket not found",
                "severity": "medium",
                "description": "docker.sock file does not exist.",
                "recommendation": "Verify Docker daemon status."
            })

    # ---------------------------------------------------
    # CHECK 3 — Configuración del daemon
    # ---------------------------------------------------

    def check_daemon_configuration(self):
        daemon_config_path = "/etc/docker/daemon.json"

        if os.path.exists(daemon_config_path):
            try:
                with open(daemon_config_path, "r") as f:
                    config = json.load(f)

                # Ejemplo: verificar si live-restore está activado
                if not config.get("live-restore", False):
                    self.findings.append({
                        "id": "HOST-007",
                        "title": "Live-restore not enabled",
                        "severity": "medium",
                        "description": "Docker daemon live-restore option is disabled.",
                        "recommendation": "Enable 'live-restore' in daemon.json to improve resilience."
                    })
                else:
                    self.findings.append({
                        "id": "HOST-008",
                        "title": "Live-restore enabled",
                        "severity": "info",
                        "description": "Docker daemon live-restore is enabled.",
                        "recommendation": "No action required."
                    })

            except Exception as e:
                self.findings.append({
                    "id": "HOST-009",
                    "title": "Error parsing daemon.json",
                    "severity": "medium",
                    "description": str(e),
                    "recommendation": "Validate daemon.json syntax."
                })
        else:
            self.findings.append({
                "id": "HOST-010",
                "title": "daemon.json not found",
                "severity": "low",
                "description": "Docker daemon configuration file not found.",
                "recommendation": "Consider defining explicit daemon configuration."
            })

    def _load_daemon_config(self):
        daemon_config_path = "/etc/docker/daemon.json"

        if not os.path.exists(daemon_config_path):
            return {}

        try:
            with open(daemon_config_path, "r") as f:
                config = json.load(f)
            return config
        except Exception:
            return {}

    def _inspect_docker_socket(self):
        socket_path = "/var/run/docker.sock"
        info = {
            "exists": False,
            "permissions": None,
            "owner": None,
            "group": None
        }

        if os.path.exists(socket_path):
            info["exists"] = True
            stat_info = os.stat(socket_path)
            info["permissions"] = oct(stat_info.st_mode)[-3:]
            info["owner"] = stat_info.st_uid
            info["group"] = stat_info.st_gid

        return info

    def _load_docker_info(self):
        info = {}
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                check=True
            )
            docker_info = json.loads(result.stdout)
            info["docker_info"] = docker_info
            info["docker_root_dir"] = docker_info.get("DockerRootDir")
            info["logging_driver"] = docker_info.get("LoggingDriver")
            info["security_options"] = docker_info.get("SecurityOptions", [])
            info["swarm_info"] = docker_info.get("Swarm", {})
            info["registry_config"] = docker_info.get("RegistryConfig", {})
            info["docker_version"] = docker_info.get("ServerVersion") or docker_info.get("Version")
            info["dockerd_uid"] = self._get_dockerd_uid()
            return info
        except Exception:
            return info

    def _get_dockerd_uid(self):
        try:
            result = subprocess.run(
                ["ps", "-C", "dockerd", "-o", "uid="],
                capture_output=True,
                text=True,
                check=True
            )
            uids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if uids:
                return int(uids[0])
        except Exception:
            pass
        return None

    def _load_kernel_info(self):
        info = {}
        try:
            with open("/proc/cmdline", "r") as f:
                cmdline = f.read().strip()
            kernel_params = {}
            for token in cmdline.split():
                if "=" in token:
                    key, value = token.split("=", 1)
                    kernel_params[key] = value
                else:
                    kernel_params[token] = True
            info["kernel_params"] = kernel_params
        except Exception:
            info["kernel_params"] = {}

        try:
            with open("/proc/modules", "r") as f:
                info["kernel_modules"] = [line.split()[0] for line in f if line.strip()]
        except Exception:
            info["kernel_modules"] = []

        return info

    def _load_audit_info(self):
        info = {
            "audit_log_enabled": False,
            "audit_rules_present": False,
            "auditd_running": False
        }

        audit_log_dir = "/var/log/audit"
        if os.path.exists(audit_log_dir):
            info["audit_log_enabled"] = True

        audit_rules = "/etc/audit/audit.rules"
        if os.path.exists(audit_rules):
            info["audit_rules_present"] = True

        try:
            result = subprocess.run(
                ["ps", "-C", "auditd", "-o", "pid="],
                capture_output=True,
                text=True,
                check=True
            )
            info["auditd_running"] = bool(result.stdout.strip())
        except Exception:
            info["auditd_running"] = False

        return info

    def _load_security_info(self):
        info = {
            "selinux_status": None,
            "apparmor_enabled": False
        }

        try:
            result = subprocess.run(
                ["getenforce"],
                capture_output=True,
                text=True,
                check=True
            )
            info["selinux_status"] = result.stdout.strip()
        except Exception:
            info["selinux_status"] = None

        security_options = self.host_info.get("security_options", [])
        info["apparmor_enabled"] = any("apparmor" in str(opt).lower() for opt in security_options)

        return info

    def _load_daemon_config_file_info(self):
        info = {
            "daemon_config_file_exists": False,
            "daemon_config_file_permissions": None,
            "daemon_config_file_owner": None,
            "daemon_config_file_group": None
        }

        config_path = "/etc/docker/daemon.json"
        if os.path.exists(config_path):
            info["daemon_config_file_exists"] = True
            try:
                stat_info = os.stat(config_path)
                info["daemon_config_file_permissions"] = oct(stat_info.st_mode)[-3:]
                info["daemon_config_file_owner"] = stat_info.st_uid
                info["daemon_config_file_group"] = stat_info.st_gid
            except Exception:
                pass

        return info
