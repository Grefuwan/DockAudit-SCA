import subprocess
import json
import os


class HostAudit:
    def __init__(self, target="local"):
        self.target = target
        self.findings = []

    def run(self):
        """
        Ejecuta todas las comprobaciones de seguridad del host Docker.
        Devuelve una lista de hallazgos.
        """

        self.check_docker_version()
        self.check_docker_socket_permissions()
        self.check_daemon_configuration()

        return self.findings

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