"""
Compliance evaluator for correlating audit findings with CIS and ISO/IEC 27001 controls.
"""

import logging
import os

from .mapping import COMPLIANCE_MAPPING

logger = logging.getLogger(__name__)

# Dangerous kernel modules that should not be loaded (rare network protocols)
_DANGEROUS_KERNEL_MODULES = {"dccp", "tipc", "rds", "sctp"}

# Sensitive env var name patterns
_SENSITIVE_ENV_PATTERNS = [
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "credential", "private_key", "access_key", "auth_key", "db_pass",
]


class ComplianceEvaluator:
    """Evaluates audit results against CIS Docker Benchmark and ISO/IEC 27001 controls."""

    def __init__(self, audit_results, mapping=None):
        self.audit_results = audit_results or {}
        self.mapping = mapping or COMPLIANCE_MAPPING
        self.compliance_findings = []
        self._normalize_audit_results()

    # Normalisation

    def _normalize_audit_results(self):
        if "host_audit" not in self.audit_results and "host" in self.audit_results:
            host_data = self.audit_results["host"]
            self.audit_results["host_audit"] = host_data if isinstance(host_data, dict) else {"findings": host_data}

        if "container_audit" not in self.audit_results and "containers" in self.audit_results:
            container_data = self.audit_results["containers"]
            if isinstance(container_data, dict):
                self.audit_results["container_audit"] = container_data
            elif isinstance(container_data, list) and container_data:
                first = container_data[0]
                if isinstance(first, dict) and "name" in first:
                    self.audit_results["container_audit"] = {"containers": container_data}
                else:
                    self.audit_results["container_audit"] = {"findings": container_data}
            else:
                self.audit_results["container_audit"] = {"findings": container_data}

        if "image_analysis" not in self.audit_results:
            image_data = {}
            if "images" in self.audit_results:
                image_data["images"] = self.audit_results["images"]
                image_data["findings"] = self.audit_results["images"]
            if "vulnerabilities" in self.audit_results:
                image_data["vulnerabilities"] = self.audit_results["vulnerabilities"]
            self.audit_results["image_analysis"] = image_data

        if "vulnerabilities" in self.audit_results and "image_analysis" in self.audit_results:
            self.audit_results["image_analysis"].setdefault(
                "vulnerabilities", self.audit_results["vulnerabilities"]
            )

    # Helpers

    def _get_host_info(self):
        return self.audit_results.get("host_audit", {}).get("host_info", {})

    def _get_daemon_config(self):
        return self.audit_results.get("host_audit", {}).get("daemon_config", {})

    def _get_containers(self):
        return self.audit_results.get("container_audit", {}).get("containers", [])

    def _get_images(self):
        return self.audit_results.get("image_analysis", {}).get("images", [])

    def _get_mountpoints(self):
        """Return {mountpoint: device} from /proc/mounts."""
        try:
            with open("/proc/mounts", "r") as f:
                lines = f.readlines()
            mounts = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    mounts[parts[1]] = parts[0]
            return mounts
        except Exception:
            return {}

    def _is_separate_partition(self, path):
        """Return True if *path* (or a parent) is a distinct mount point != '/'."""
        mounts = self._get_mountpoints()
        if not mounts:
            return None  # can't determine
        # Walk from most-specific to root
        parts = path.rstrip("/").split("/")
        for i in range(len(parts), 0, -1):
            candidate = "/".join(parts[:i]) or "/"
            if candidate in mounts and candidate != "/":
                return True
        return False

    def _has_sensitive_env(self, env_dict):
        """Return list of suspicious env var names found in *env_dict*."""
        found = []
        for key in env_dict:
            if any(p in key.lower() for p in _SENSITIVE_ENV_PATTERNS):
                found.append(key)
        return found

    # Evaluation engine

    def evaluate(self):
        logger.debug("Evaluando controles de compliance CIS/ISO 27001")
        self.compliance_findings = []
        for cis_id, control in self.mapping.items():
            self.compliance_findings.append(self._evaluate_control(cis_id, control))
        return self.compliance_findings

    def _evaluate_control(self, cis_id, control):
        status, details = self._check_control(cis_id, control)
        return {
            "cis_control": cis_id,
            "title": control["title"],
            "description": control["description"],
            "severity": control["severity"],
            "status": status,
            "iso27001_controls": control.get("iso27001_controls", []),
            "category": control.get("category", "General"),
            "remediation": control.get("remediation", ""),
            "details": details,
        }

    def _check_control(self, cis_id, control):
        impl_path = control.get("implementation", "")
        if not impl_path:
            return "unknown", {"reason": "No implementation method defined"}

        checks_map = {
            # Host audit
            "host_audit.check_daemon_user": self._check_daemon_user,
            "host_audit.check_daemon_data_partition": self._check_daemon_data_partition,
            "host_audit.check_docker_data_partition": self._check_docker_data_partition,
            "host_audit.check_var_partition": self._check_var_partition,
            "host_audit.check_log_partition": self._check_log_partition,
            "host_audit.check_audit_partition": self._check_audit_partition,
            "host_audit.check_kernel_parameters": self._check_kernel_parameters,
            "host_audit.check_kernel_modules": self._check_kernel_modules,
            "host_audit.check_daemon_file_permissions": self._check_daemon_file_permissions,
            "host_audit.check_daemon_file_ownership": self._check_daemon_file_ownership,
            "host_audit.check_docker_version": self._check_docker_version,
            "host_audit.check_apparmor_selinux": self._check_apparmor_selinux,
            "host_audit.check_selinux_labels": self._check_selinux_labels,
            "host_audit.check_daemon_socket_permissions": self._check_daemon_socket_permissions,
            "host_audit.check_daemon_socket_ownership": self._check_daemon_socket_ownership,
            "host_audit.check_daemon_certificates": self._check_daemon_certificates,
            "host_audit.check_daemon_tls": self._check_daemon_tls,
            "host_audit.check_daemon_auth": self._check_daemon_auth,
            "host_audit.check_registry_certificates": self._check_registry_certificates,
            "host_audit.check_userland_proxy_disabled": self._check_userland_proxy_disabled,
            "host_audit.check_icc_disabled": self._check_icc_disabled,
            "host_audit.check_log_driver": self._check_log_driver,
            "host_audit.check_dockersock_ownership": self._check_dockersock_ownership,
            "host_audit.check_audit_logging": self._check_audit_logging,
            "host_audit.check_audit_log_review": self._check_audit_log_review,
            "host_audit.check_daemon_auditing": self._check_daemon_auditing,
            # Container audit
            "container_audit.check_privileged_mode": self._check_privileged_mode,
            "container_audit.check_user_not_root": self._check_user_not_root,
            "container_audit.check_linux_capabilities": self._check_linux_capabilities,
            "container_audit.check_sensitive_files_readonly": self._check_sensitive_files_readonly,
            "container_audit.check_bind_mount_sensitive": self._check_bind_mount_sensitive,
            "container_audit.check_apparmor_disabled": self._check_apparmor_disabled,
            "container_audit.check_seccomp_profile": self._check_seccomp_profile,
            "container_audit.check_secrets_usage": self._check_secrets_usage,
            "container_audit.check_env_sensitive_data": self._check_env_sensitive_data,
            "container_audit.check_container_network_policies": self._check_container_network_policies,
            "container_audit.check_restart_policy": self._check_restart_policy,
            "container_audit.check_cpu_limits": self._check_cpu_limits,
            "container_audit.check_memory_limits": self._check_memory_limits,
            "container_audit.check_rootfs_readonly": self._check_rootfs_readonly,
            "container_audit.check_volume_permissions": self._check_volume_permissions,
            "container_audit.check_cpu_shares": self._check_cpu_shares,
            "container_audit.check_pids_limit": self._check_pids_limit,
            # Image analysis
            "image_analysis.check_custom_images": self._check_custom_images,
            "image_analysis.check_image_signature_verification": self._check_image_signature_verification,
            "image_analysis.check_minimal_packages": self._check_minimal_packages,
            "image_analysis.check_trusted_base_images": self._check_trusted_base_images,
            "image_analysis.check_no_secrets_in_images": self._check_no_secrets_in_images,
            "image_analysis.check_env_in_images": self._check_env_in_images,
            "image_analysis.check_healthchecks": self._check_healthchecks,
            "image_analysis.check_vulnerability_scan": self._check_vulnerability_scan,
            # Binary analyzer
            "binary_analyzer.check_setuid_binaries": self._check_setuid_binaries,
            # Orchestrator
            "orchestrator.check_trusted_images_policy": self._check_trusted_images_policy,
            "orchestrator.check_orchestrator_version": self._check_orchestrator_version,
            "orchestrator.check_allowed_registries": self._check_allowed_registries,
            "orchestrator.check_secrets_encryption": self._check_secrets_encryption,
            "orchestrator.check_secrets_rotation": self._check_secrets_rotation,
            "orchestrator.check_registry_auth": self._check_registry_auth,
            "orchestrator.check_swarm_config": self._check_swarm_config,
            "orchestrator.check_swarm_tls": self._check_swarm_tls,
            "orchestrator.check_swarm_members": self._check_swarm_members,
            "orchestrator.check_swarm_service_configs": self._check_swarm_service_configs,
            "orchestrator.check_swarm_internal_comm": self._check_swarm_internal_comm,
            "orchestrator.check_swarm_backups": self._check_swarm_backups,
        }

        check_func = checks_map.get(impl_path)
        if not check_func:
            return "unknown", {"reason": f"Check not implemented: {impl_path}"}
        return check_func()

    # Host audit checks

    def _check_daemon_user(self):
        host_info = self._get_host_info()
        uid = host_info.get("dockerd_uid")
        if uid is None:
            return "unknown", {"reason": "Docker daemon process UID not available"}
        if uid == 0:
            return "non_compliant", {
                "issue": "Docker daemon runs as root (UID 0)",
                "uid": uid,
            }
        return "compliant", {"uid": uid, "reason": "Docker daemon runs as non-root user"}

    def _check_daemon_data_partition(self):
        return self._check_docker_data_partition()

    def _check_docker_data_partition(self):
        host_info = self._get_host_info()
        docker_root = host_info.get("docker_root_dir") or "/var/lib/docker"
        result = self._is_separate_partition(docker_root)
        if result is None:
            return "unknown", {"reason": "Cannot read /proc/mounts"}
        if result:
            return "compliant", {"path": docker_root, "reason": f"{docker_root} is on a separate partition"}
        return "non_compliant", {
            "path": docker_root,
            "issue": f"{docker_root} is not on a separate partition",
        }

    def _check_var_partition(self):
        result = self._is_separate_partition("/var")
        if result is None:
            return "unknown", {"reason": "Cannot read /proc/mounts"}
        if result:
            return "compliant", {"reason": "/var is on a separate partition"}
        return "non_compliant", {"issue": "/var is not on a separate partition"}

    def _check_log_partition(self):
        result = self._is_separate_partition("/var/log")
        if result is None:
            return "unknown", {"reason": "Cannot read /proc/mounts"}
        if result:
            return "compliant", {"reason": "/var/log is on a separate partition"}
        return "non_compliant", {"issue": "/var/log is not on a separate partition"}

    def _check_audit_partition(self):
        result = self._is_separate_partition("/var/log/audit")
        if result is None:
            return "unknown", {"reason": "Cannot read /proc/mounts"}
        if result:
            return "compliant", {"reason": "/var/log/audit is on a separate partition"}
        return "non_compliant", {"issue": "/var/log/audit is not on a separate partition"}

    def _check_kernel_parameters(self):
        host_info = self._get_host_info()
        apparmor_enabled = host_info.get("apparmor_enabled", False)
        selinux_status = host_info.get("selinux_status")
        security_opts = host_info.get("security_options", [])

        has_apparmor = apparmor_enabled or any("apparmor" in str(o).lower() for o in security_opts)
        has_selinux = selinux_status == "Enforcing"

        if has_apparmor or has_selinux:
            return "compliant", {
                "reason": "Mandatory Access Control (MAC) module is active",
                "apparmor": has_apparmor,
                "selinux": has_selinux,
            }
        if selinux_status == "Permissive":
            return "non_compliant", {
                "issue": "SELinux is in Permissive mode (not enforcing)",
                "selinux_status": selinux_status,
            }
        return "non_compliant", {
            "issue": "No MAC module (AppArmor/SELinux) detected as active",
            "apparmor": has_apparmor,
            "selinux_status": selinux_status,
        }

    def _check_kernel_modules(self):
        host_info = self._get_host_info()
        modules = host_info.get("kernel_modules", [])
        if not modules:
            return "unknown", {"reason": "Kernel module list not available"}
        loaded_dangerous = [m for m in modules if m in _DANGEROUS_KERNEL_MODULES]
        if loaded_dangerous:
            return "non_compliant", {
                "issue": "Potentially dangerous kernel modules are loaded",
                "modules": loaded_dangerous,
                "recommendation": "Blacklist unused network protocol modules via /etc/modprobe.d/",
            }
        return "compliant", {
            "reason": "No dangerous network protocol modules detected",
            "modules_checked": len(modules),
        }

    def _check_docker_version(self):
        host_info = self._get_host_info()
        version = host_info.get("docker_version", "")
        if version:
            return "compliant", {"version": version}
        return "unknown", {"reason": "Docker version not available in host info"}

    def _check_daemon_file_permissions(self):
        host_info = self._get_host_info()
        if not host_info.get("daemon_config_file_exists"):
            return "unknown", {"reason": "daemon.json does not exist — no permissions to check"}
        perms = host_info.get("daemon_config_file_permissions")
        if perms is None:
            return "unknown", {"reason": "File permissions could not be read"}
        # Acceptable: 600 or 640
        if perms in ("600", "640"):
            return "compliant", {"permissions": perms}
        return "non_compliant", {
            "issue": f"daemon.json permissions are {perms} (should be 600 or 640)",
            "permissions": perms,
        }

    def _check_daemon_file_ownership(self):
        host_info = self._get_host_info()
        if not host_info.get("daemon_config_file_exists"):
            return "unknown", {"reason": "daemon.json does not exist — no ownership to check"}
        owner = host_info.get("daemon_config_file_owner")
        group = host_info.get("daemon_config_file_group")
        if owner is None:
            return "unknown", {"reason": "File ownership could not be read"}
        if owner == 0:
            return "compliant", {"owner": owner, "group": group, "reason": "daemon.json owned by root"}
        return "non_compliant", {
            "issue": f"daemon.json not owned by root (owner UID: {owner})",
            "owner": owner,
            "group": group,
        }

    def _check_apparmor_selinux(self):
        host_info = self._get_host_info()
        security_opts = host_info.get("security_options", [])
        apparmor_enabled = host_info.get("apparmor_enabled", False)
        selinux_status = host_info.get("selinux_status")

        has_apparmor = apparmor_enabled or any("apparmor" in str(o).lower() for o in security_opts)
        has_selinux = selinux_status == "Enforcing"

        if has_apparmor or has_selinux:
            methods = []
            if has_apparmor:
                methods.append("AppArmor")
            if has_selinux:
                methods.append("SELinux")
            return "compliant", {"methods": methods}
        return "non_compliant", {"issue": "No AppArmor or SELinux enforcement detected"}

    def _check_selinux_labels(self):
        host_info = self._get_host_info()
        status = host_info.get("selinux_status")
        if status is None:
            return "unknown", {"reason": "SELinux status not available (may not be installed)"}
        if status == "Enforcing":
            return "compliant", {"selinux_status": status}
        if status == "Permissive":
            return "non_compliant", {
                "issue": "SELinux is Permissive — labels are assigned but not enforced",
                "selinux_status": status,
            }
        return "non_compliant", {
            "issue": f"SELinux is not enforcing ({status})",
            "selinux_status": status,
        }

    def _check_daemon_socket_permissions(self):
        host_info = self._get_host_info()
        permissions = host_info.get("permissions")
        if permissions:
            if permissions == "660":
                return "compliant", {"permissions": permissions}
            return "non_compliant", {
                "issue": f"Docker socket permissions are {permissions} (expected 660)",
                "permissions": permissions,
            }
        return "unknown", {"reason": "Docker socket permissions unavailable"}

    def _check_daemon_socket_ownership(self):
        host_info = self._get_host_info()
        owner = host_info.get("owner")
        group = host_info.get("group")
        if owner is not None:
            return "compliant", {"owner": owner, "group": group}
        return "unknown", {"reason": "Docker socket ownership information unavailable"}

    def _check_daemon_certificates(self):
        daemon_config = self._get_daemon_config()
        tls_configured = daemon_config.get("tlsverify") or daemon_config.get("tls")
        if tls_configured:
            return "compliant", {
                "tlsverify": daemon_config.get("tlsverify", False),
                "tls": daemon_config.get("tls", False),
            }
        # Check if explicit TCP host is configured — if not, TLS is less critical
        hosts = daemon_config.get("hosts", [])
        has_tcp = any(h.startswith("tcp://") for h in hosts) if hosts else False
        if has_tcp:
            return "non_compliant", {
                "issue": "Docker daemon exposed over TCP without TLS certificate verification",
                "hosts": hosts,
            }
        return "non_compliant", {
            "issue": "TLS certificate verification not configured for Docker daemon",
            "recommendation": "Configure tlsverify=true and provide TLS certificates",
        }

    def _check_daemon_tls(self):
        daemon_config = self._get_daemon_config()
        if daemon_config.get("tls") or daemon_config.get("tlsverify"):
            return "compliant", {
                "tls": daemon_config.get("tls", False),
                "tlsverify": daemon_config.get("tlsverify", False),
            }
        return "non_compliant", {"issue": "Docker daemon TLS not configured"}

    def _check_daemon_auth(self):
        daemon_config = self._get_daemon_config()
        plugins = daemon_config.get("authorization-plugins") or daemon_config.get("authz-plugin")
        if plugins:
            return "compliant", {"authorization_plugins": plugins}
        return "non_compliant", {
            "issue": "No authorization plugins configured for Docker daemon API",
            "recommendation": "Configure authorization plugins (e.g. OPA, authz-broker)",
        }

    def _check_registry_certificates(self):
        certs_dir = "/etc/docker/certs.d"
        if not os.path.isdir(certs_dir):
            return "non_compliant", {
                "issue": f"{certs_dir} does not exist — no custom registry certificates configured",
                "recommendation": "Create /etc/docker/certs.d/<registry>/ with CA certificates",
            }
        registries = [
            d for d in os.listdir(certs_dir)
            if os.path.isdir(os.path.join(certs_dir, d))
        ]
        if registries:
            return "compliant", {
                "reason": "Custom registry certificates configured",
                "registries": registries,
            }
        return "non_compliant", {
            "issue": f"{certs_dir} exists but is empty",
            "recommendation": "Add CA certificates for private registries",
        }

    def _check_userland_proxy_disabled(self):
        daemon_config = self._get_daemon_config()
        if "userland-proxy" in daemon_config:
            disabled = not bool(daemon_config["userland-proxy"])
            if disabled:
                return "compliant", {"userland-proxy": False}
            return "non_compliant", {
                "issue": "userland-proxy is explicitly enabled",
                "recommendation": 'Set "userland-proxy": false in daemon.json',
            }
        # Not present → Docker default is true (enabled)
        return "non_compliant", {
            "issue": "userland-proxy not disabled (Docker default: enabled)",
            "recommendation": 'Add "userland-proxy": false to daemon.json',
        }

    def _check_icc_disabled(self):
        daemon_config = self._get_daemon_config()
        if "icc" in daemon_config:
            disabled = not bool(daemon_config["icc"])
            if disabled:
                return "compliant", {"icc": False}
            return "non_compliant", {
                "issue": "Inter-container communication (icc) is explicitly enabled",
                "recommendation": 'Set "icc": false in daemon.json',
            }
        # Not present → Docker default is true (enabled)
        return "non_compliant", {
            "issue": "Inter-container communication not disabled (Docker default: enabled)",
            "recommendation": 'Add "icc": false to daemon.json',
        }

    def _check_log_driver(self):
        daemon_config = self._get_daemon_config()
        host_info = self._get_host_info()
        driver = daemon_config.get("log-driver") or host_info.get("logging_driver", "")
        if driver and driver not in ("json-file", ""):
            return "compliant", {"log_driver": driver}
        if driver == "json-file":
            return "non_compliant", {
                "issue": "Log driver is 'json-file' (local only, not centralized)",
                "log_driver": driver,
                "recommendation": "Use a centralized driver: syslog, journald, fluentd, splunk, etc.",
            }
        return "non_compliant", {
            "issue": "No log driver configured (Docker default: json-file, local only)",
            "recommendation": 'Configure "log-driver" in daemon.json for centralized logging',
        }

    def _check_dockersock_ownership(self):
        host_info = self._get_host_info()
        if not host_info.get("exists"):
            return "unknown", {"reason": "Docker socket information unavailable"}
        owner = host_info.get("owner")
        perms = host_info.get("permissions")
        if owner == 0 and perms == "660":
            return "compliant", {"owner": owner, "permissions": perms}
        return "non_compliant", {
            "issue": "Docker socket ownership or permissions are not securely configured",
            "owner": owner,
            "permissions": perms,
            "expected_owner": 0,
            "expected_permissions": "660",
        }

    def _check_audit_logging(self):
        host_info = self._get_host_info()
        log_enabled = host_info.get("audit_log_enabled", False)
        auditd_running = host_info.get("auditd_running", False)
        if log_enabled and auditd_running:
            return "compliant", {
                "audit_log_enabled": log_enabled,
                "auditd_running": auditd_running,
            }
        issues = []
        if not log_enabled:
            issues.append("Audit log directory (/var/log/audit) not found")
        if not auditd_running:
            issues.append("auditd process is not running")
        return "non_compliant", {
            "issue": "; ".join(issues),
            "audit_log_enabled": log_enabled,
            "auditd_running": auditd_running,
        }

    def _check_audit_log_review(self):
        host_info = self._get_host_info()
        rules_present = host_info.get("audit_rules_present", False)
        log_enabled = host_info.get("audit_log_enabled", False)
        if rules_present and log_enabled:
            return "compliant", {
                "reason": "Audit rules file and audit log directory are present",
                "audit_rules_present": rules_present,
                "audit_log_enabled": log_enabled,
            }
        issues = []
        if not rules_present:
            issues.append("No audit rules file at /etc/audit/audit.rules")
        if not log_enabled:
            issues.append("Audit log directory not found")
        return "non_compliant", {
            "issue": "; ".join(issues) if issues else "Audit log review infrastructure not set up",
            "audit_rules_present": rules_present,
            "audit_log_enabled": log_enabled,
        }

    def _check_daemon_auditing(self):
        host_info = self._get_host_info()
        auditd_running = host_info.get("auditd_running", False)
        rules_present = host_info.get("audit_rules_present", False)
        if auditd_running:
            return "compliant", {
                "auditd_running": auditd_running,
                "audit_rules_present": rules_present,
            }
        return "non_compliant", {
            "issue": "auditd is not running — Docker daemon events are not being audited",
            "auditd_running": auditd_running,
            "recommendation": "Install and configure auditd with Docker-specific rules",
        }

    # Container audit checks

    def _check_privileged_mode(self):
        containers = self._get_containers()
        privileged = [c for c in containers if c.get("privileged", False)]
        if privileged:
            return "non_compliant", {
                "issue": "Privileged containers detected",
                "count": len(privileged),
                "containers": [c.get("name") for c in privileged],
            }
        return "compliant", {"reason": "No privileged containers detected"}

    def _check_user_not_root(self):
        containers = self._get_containers()
        root_containers = [c for c in containers if c.get("user", "").lower() in ("root", "0", "")]
        if root_containers:
            return "non_compliant", {
                "issue": "Containers running as root",
                "count": len(root_containers),
                "containers": [c.get("name") for c in root_containers],
            }
        return "compliant", {"reason": "All containers running as non-root"}

    def _check_linux_capabilities(self):
        containers = self._get_containers()
        unrestricted = [c for c in containers if not c.get("cap_drop")]
        if unrestricted:
            return "non_compliant", {
                "issue": "Containers without capability restrictions",
                "count": len(unrestricted),
                "containers": [c.get("name") for c in unrestricted],
                "recommendation": "Use --cap-drop=ALL and add only necessary capabilities",
            }
        return "compliant", {"reason": "Linux capabilities properly restricted"}

    def _check_sensitive_files_readonly(self):
        containers = self._get_containers()
        issues = []
        for container in containers:
            for mount in container.get("volumes", []):
                dest = mount.get("destination", "")
                if dest in ("/etc/shadow", "/etc/passwd", "/root") and mount.get("rw", True):
                    issues.append({"container": container.get("name"), "mount": dest})
        if issues:
            return "non_compliant", {"issue": "Sensitive files mounted writable", "details": issues}
        return "compliant", {"reason": "Sensitive files mounted read-only or not mounted"}

    def _check_bind_mount_sensitive(self):
        containers = self._get_containers()
        sensitive = ["/etc", "/var", "/root", "/home", "/sys", "/proc"]
        issues = []
        for container in containers:
            for mount in container.get("volumes", []):
                if mount.get("type") == "bind":
                    src = mount.get("source", "")
                    if any(src.startswith(p) for p in sensitive):
                        issues.append({
                            "container": container.get("name"),
                            "source": src,
                            "destination": mount.get("destination"),
                        })
        if issues:
            return "non_compliant", {
                "issue": "Sensitive host directories bind-mounted into containers",
                "mounts": issues,
            }
        if containers:
            return "compliant", {"reason": "No sensitive host bind mounts detected"}
        return "unknown", {"reason": "No container mount information available"}

    def _check_apparmor_disabled(self):
        containers = self._get_containers()
        disabled = [c for c in containers if c.get("apparmor_disabled", False)]
        if disabled:
            return "non_compliant", {
                "issue": "AppArmor explicitly disabled in containers",
                "count": len(disabled),
                "containers": [c.get("name") for c in disabled],
            }
        return "compliant", {"reason": "AppArmor not disabled in any container"}

    def _check_seccomp_profile(self):
        containers = self._get_containers()
        without_seccomp = [c for c in containers if not c.get("seccomp_profile")]
        if without_seccomp:
            return "non_compliant", {
                "issue": "Containers without a custom Seccomp profile",
                "count": len(without_seccomp),
                "containers": [c.get("name") for c in without_seccomp],
                "recommendation": "Use --security-opt seccomp=/path/to/profile.json",
            }
        return "compliant", {"reason": "Seccomp profiles applied to all containers"}

    def _check_secrets_usage(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if swarm_info and swarm_info.get("LocalNodeState") == "active":
            return "compliant", {"reason": "Docker Swarm is active — secrets management available"}
        return "non_compliant", {
            "issue": "Docker Swarm not active — no native secrets management",
            "recommendation": "Enable Swarm mode or use a dedicated secrets manager",
        }

    def _check_env_sensitive_data(self):
        containers = self._get_containers()
        found = []
        for container in containers:
            hits = self._has_sensitive_env(container.get("env_vars", {}))
            for key in hits:
                found.append({"container": container.get("name"), "env_var": key})
        if found:
            return "non_compliant", {
                "issue": "Sensitive data detected in container environment variables",
                "findings": found,
                "recommendation": "Use Docker secrets or a vault instead of env vars",
            }
        return "compliant", {"reason": "No sensitive data detected in container environment variables"}

    def _check_container_network_policies(self):
        daemon_config = self._get_daemon_config()
        containers = self._get_containers()
        icc_disabled = not bool(daemon_config.get("icc", True))
        host_net_containers = [c.get("name") for c in containers if c.get("network_mode") == "host"]

        if host_net_containers:
            return "non_compliant", {
                "issue": "Containers using host network mode bypass network isolation",
                "containers": host_net_containers,
            }
        if icc_disabled:
            return "compliant", {
                "reason": "Inter-container communication disabled (icc=false)",
                "icc_disabled": True,
            }
        return "non_compliant", {
            "issue": "Inter-container communication is enabled (icc default: true)",
            "recommendation": 'Set "icc": false in daemon.json to restrict container traffic',
        }

    def _check_restart_policy(self):
        containers = self._get_containers()
        bad = [c.get("name") for c in containers if c.get("restart_policy") in ("always", "unless-stopped")]
        if bad:
            return "non_compliant", {
                "issue": "Containers with aggressive restart policies that may hide failures",
                "containers": bad,
            }
        return "compliant", {"reason": "Restart policies are acceptable"}

    def _check_cpu_limits(self):
        containers = self._get_containers()
        no_limits = [c.get("name") for c in containers if not c.get("cpu_limits")]
        if no_limits:
            return "non_compliant", {
                "issue": "Containers without CPU limits",
                "containers": no_limits,
            }
        return "compliant", {"reason": "CPU limits set on all containers"}

    def _check_memory_limits(self):
        containers = self._get_containers()
        no_memory = [c.get("name") for c in containers if not c.get("memory_limit")]
        if no_memory:
            return "non_compliant", {
                "issue": "Containers without memory limits",
                "containers": no_memory,
            }
        return "compliant", {"reason": "Memory limits configured on all containers"}

    def _check_rootfs_readonly(self):
        containers = self._get_containers()
        not_readonly = [c.get("name") for c in containers if not c.get("read_only_rootfs")]
        if not_readonly:
            return "non_compliant", {
                "issue": "Containers with writable root filesystem",
                "containers": not_readonly,
                "recommendation": "Use --read-only for containers that do not require write access",
            }
        return "compliant", {"reason": "Root filesystem is read-only on all containers"}

    def _check_volume_permissions(self):
        containers = self._get_containers()
        problematic = []
        for container in containers:
            for vol in container.get("volumes", []):
                if vol.get("type") == "bind" and vol.get("rw", True):
                    problematic.append({
                        "container": container.get("name"),
                        "mount": vol.get("destination"),
                    })
        if problematic:
            return "non_compliant", {
                "issue": "Writable bind mounts detected",
                "volumes": problematic,
            }
        return "compliant", {"reason": "Volume permissions appear secure or no bind mounts detected"}

    def _check_cpu_shares(self):
        containers = self._get_containers()
        no_shares = [c.get("name") for c in containers if not c.get("cpu_shares")]
        if no_shares:
            return "non_compliant", {
                "issue": "Containers without CPU shares configured",
                "containers": no_shares,
            }
        return "compliant", {"reason": "CPU shares configured on all containers"}

    def _check_pids_limit(self):
        containers = self._get_containers()
        no_limit = [
            c.get("name") for c in containers
            if not c.get("pids_limit") or c.get("pids_limit", 0) <= 0
        ]
        if no_limit:
            return "non_compliant", {
                "issue": "Containers without PID limits (fork bomb risk)",
                "containers": no_limit,
                "recommendation": "Use --pids-limit to restrict the number of processes",
            }
        return "compliant", {"reason": "PID limits configured on all containers"}

    # Image analysis checks

    def _check_custom_images(self):
        images = self._get_images()
        custom = [i for i in images if not i.get("is_official", True)]
        if custom:
            return "compliant", {
                "custom_images": len(custom),
                "reason": "Custom images detected",
            }
        return "non_compliant", {"issue": "No custom images detected — only official/generic images in use"}

    def _check_image_signature_verification(self):
        host_info = self._get_host_info()
        security_opts = host_info.get("security_options", [])
        has_dct = any("content-trust" in str(o).lower() for o in security_opts)
        if has_dct:
            return "compliant", {"reason": "Docker Content Trust detected in security options"}
        # Check DOCKER_CONTENT_TRUST env var hint in daemon environment
        return "non_compliant", {
            "issue": "Docker Content Trust (DCT) not detected",
            "recommendation": "Set DOCKER_CONTENT_TRUST=1 and enable image signing",
        }

    def _check_minimal_packages(self):
        images = self._get_images()
        bloated = []
        for image in images:
            count = image.get("packages", 0)
            pkg_count = len(count) if isinstance(count, list) else int(count or 0)
            if pkg_count > 100:
                bloated.append({"image": image.get("name"), "package_count": pkg_count})
        if bloated:
            return "non_compliant", {
                "issue": "Images with excessive package count (>100)",
                "images": bloated,
                "recommendation": "Use alpine, distroless or other minimal base images",
            }
        return "compliant", {"reason": "Images appear minimal (≤100 packages)"}

    def _check_trusted_base_images(self):
        images = self._get_images()
        trusted_registries = ("docker.io", "registry.hub.docker.com", "ghcr.io", "quay.io")
        untrusted = [
            i for i in images
            if i.get("registry") and i.get("registry") not in trusted_registries
        ]
        if untrusted:
            return "non_compliant", {
                "issue": "Images from untrusted or unknown registries",
                "count": len(untrusted),
                "images": [i.get("name") for i in untrusted],
            }
        return "compliant", {"reason": "All images from trusted registries"}

    def _check_no_secrets_in_images(self):
        images = self._get_images()
        if not images:
            return "unknown", {"reason": "No image data available"}
        found = []
        for image in images:
            env_vars = image.get("env_vars", {})
            hits = self._has_sensitive_env(env_vars)
            for key in hits:
                found.append({"image": image.get("name"), "env_var": key})
        if found:
            return "non_compliant", {
                "issue": "Sensitive environment variables detected in image configuration",
                "findings": found,
                "recommendation": "Remove secrets from image ENV instructions and use runtime secrets",
            }
        return "compliant", {"reason": "No sensitive environment variables detected in images"}

    def _check_env_in_images(self):
        images = self._get_images()
        if not images:
            return "unknown", {"reason": "No image data available"}
        found = []
        for image in images:
            env_vars = image.get("env_vars", {})
            for key, val in env_vars.items():
                if any(p in key.lower() for p in _SENSITIVE_ENV_PATTERNS) and val:
                    found.append({"image": image.get("name"), "env_var": key})
        if found:
            return "non_compliant", {
                "issue": "Image ENV instructions contain credentials or sensitive keys",
                "findings": found,
                "recommendation": "Use build args or runtime secrets instead of ENV for credentials",
            }
        return "compliant", {"reason": "No credential-bearing ENV instructions detected in images"}

    def _check_healthchecks(self):
        images = self._get_images()
        missing = [i.get("name") for i in images if not i.get("healthcheck")]
        if missing:
            return "non_compliant", {
                "issue": "Images without HEALTHCHECK instructions",
                "images": missing,
            }
        if images:
            return "compliant", {"reason": "All images define healthchecks"}
        return "unknown", {"reason": "No image data available"}

    def _check_vulnerability_scan(self):
        vulnerabilities = self.audit_results.get("vulnerabilities", [])
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        if critical > 0:
            return "non_compliant", {"issue": "Critical vulnerabilities found", "critical": critical, "high": high}
        if high > 0:
            return "non_compliant", {"issue": "High severity vulnerabilities found", "high": high}
        return "compliant", {"reason": "Vulnerability scan completed with no critical/high findings"}

    # Binary analyzer checks

    def _check_setuid_binaries(self):
        binaries = self.audit_results.get("image_analysis", {}).get("binaries", [])
        setuid = [b for b in binaries if b.get("setuid", False) or b.get("setgid", False)]
        if setuid:
            return "non_compliant", {
                "issue": "SETUID/SETGID binaries found in images",
                "count": len(setuid),
                "binaries": [b.get("path") for b in setuid[:5]],
            }
        return "compliant", {"reason": "No SETUID/SETGID binaries found"}

    # Orchestrator checks

    def _check_trusted_images_policy(self):
        images = self._get_images()
        trusted = ("docker.io", "registry.hub.docker.com", "ghcr.io", "quay.io")
        untrusted = [i for i in images if i.get("registry") and i.get("registry") not in trusted]
        if untrusted:
            return "non_compliant", {
                "issue": "Images pulled from untrusted registries",
                "registries": sorted({i.get("registry") for i in untrusted}),
            }
        if images:
            return "compliant", {"reason": "All images are from trusted registries"}
        return "unknown", {"reason": "No image metadata available"}

    def _check_orchestrator_version(self):
        orchestrator = self.audit_results.get("orchestrator", {})
        version = orchestrator.get("version", "")
        if version:
            return "compliant", {"version": version}
        return "unknown", {"reason": "Orchestrator version not detected"}

    def _check_allowed_registries(self):
        images = self._get_images()
        allowed = ("docker.io", "registry.hub.docker.com", "ghcr.io", "quay.io")
        untrusted = [i for i in images if i.get("registry") and i.get("registry") not in allowed]
        if untrusted:
            return "non_compliant", {
                "issue": "Images from non-allowlisted registries",
                "registries": [i.get("registry") for i in untrusted],
            }
        if images:
            return "compliant", {"reason": "All scanned images are from allowed registries"}
        return "unknown", {"reason": "No image registry information available"}

    def _check_secrets_encryption(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if not swarm_info or swarm_info.get("LocalNodeState") != "active":
            return "unknown", {"reason": "Docker Swarm not active — secrets encryption is Swarm-specific"}
        # Swarm encrypts secrets at rest by default when using Swarm mode
        return "compliant", {
            "reason": "Docker Swarm is active — secrets are encrypted at rest by default",
        }

    def _check_secrets_rotation(self):
        # Secrets rotation is a process/policy control that cannot be verified from system state
        return "non_compliant", {
            "issue": "No automated secret rotation policy can be verified",
            "recommendation": "Implement a secrets rotation schedule using vault or CI/CD pipelines",
        }

    def _check_registry_auth(self):
        config_paths = [
            os.path.expanduser("~/.docker/config.json"),
            "/root/.docker/config.json",
        ]
        for path in config_paths:
            if os.path.isfile(path):
                try:
                    import json
                    with open(path) as f:
                        cfg = json.load(f)
                    if cfg.get("auths") or cfg.get("credHelpers") or cfg.get("credsStore"):
                        return "compliant", {
                            "reason": "Docker credentials configured",
                            "config_path": path,
                        }
                except Exception:
                    pass
        return "non_compliant", {
            "issue": "No Docker registry authentication credentials found",
            "recommendation": "Run 'docker login <registry>' to configure authentication",
        }

    def _check_swarm_config(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if not swarm_info or swarm_info.get("LocalNodeState") != "active":
            return "unknown", {"reason": "Docker Swarm not active — check not applicable"}
        return "compliant", {"reason": "Docker Swarm is active and configured"}

    def _check_swarm_tls(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if not swarm_info or swarm_info.get("LocalNodeState") != "active":
            return "unknown", {"reason": "Docker Swarm not active — check not applicable"}
        # Swarm uses mutual TLS between nodes by default
        return "compliant", {"reason": "Docker Swarm uses mutual TLS by default"}

    def _check_swarm_members(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if not swarm_info or swarm_info.get("LocalNodeState") != "active":
            return "unknown", {"reason": "Docker Swarm not active — check not applicable"}
        managers = swarm_info.get("Managers", 0)
        nodes = swarm_info.get("Nodes", 0)
        return "compliant", {"managers": managers, "nodes": nodes}

    def _check_swarm_service_configs(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if not swarm_info or swarm_info.get("LocalNodeState") != "active":
            return "unknown", {"reason": "Docker Swarm not active — check not applicable"}
        return "unknown", {"reason": "Swarm service configuration audit requires Swarm API access"}

    def _check_swarm_internal_comm(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if not swarm_info or swarm_info.get("LocalNodeState") != "active":
            return "unknown", {"reason": "Docker Swarm not active — check not applicable"}
        return "compliant", {"reason": "Swarm internal communications are encrypted by default"}

    def _check_swarm_backups(self):
        host_info = self._get_host_info()
        swarm_info = host_info.get("swarm_info", {})
        if not swarm_info or swarm_info.get("LocalNodeState") != "active":
            return "unknown", {"reason": "Docker Swarm not active — check not applicable"}
        return "non_compliant", {
            "issue": "Swarm backup status cannot be verified automatically",
            "recommendation": "Implement regular backups of Swarm state (/var/lib/docker/swarm/)",
        }

    # Reporting methods

    def get_summary(self):
        if not self.compliance_findings:
            self.evaluate()
        total = len(self.compliance_findings)
        compliant = sum(1 for f in self.compliance_findings if f["status"] == "compliant")
        non_compliant = sum(1 for f in self.compliance_findings if f["status"] == "non_compliant")
        unknown = sum(1 for f in self.compliance_findings if f["status"] == "unknown")
        pct = (compliant / total * 100) if total > 0 else 0
        return {
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "unknown": unknown,
            "compliance_percentage": round(pct, 2),
        }

    def get_by_severity(self):
        if not self.compliance_findings:
            self.evaluate()
        by_severity = {}
        for finding in self.compliance_findings:
            sev = finding.get("severity", "unknown")
            by_severity.setdefault(sev, []).append(finding)
        return by_severity

    def get_by_category(self):
        if not self.compliance_findings:
            self.evaluate()
        by_category = {}
        for finding in self.compliance_findings:
            cat = finding.get("category", "General")
            by_category.setdefault(cat, []).append(finding)
        return by_category

    def get_iso_coverage(self):
        if not self.compliance_findings:
            self.evaluate()
        iso_coverage = {}
        for finding in self.compliance_findings:
            for iso_ctrl in finding.get("iso27001_controls", []):
                domain = iso_ctrl.get("domain", "Unknown")
                if domain not in iso_coverage:
                    iso_coverage[domain] = {
                        "total": 0,
                        "compliant": 0,
                        "non_compliant": 0,
                        "unknown": 0,
                        "controls": [],
                    }
                iso_coverage[domain]["total"] += 1
                iso_coverage[domain]["controls"].append(iso_ctrl["code"])
                status = finding.get("status")
                if status == "compliant":
                    iso_coverage[domain]["compliant"] += 1
                elif status == "non_compliant":
                    iso_coverage[domain]["non_compliant"] += 1
                else:
                    iso_coverage[domain]["unknown"] += 1
        return iso_coverage
