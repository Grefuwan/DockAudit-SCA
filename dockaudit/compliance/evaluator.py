"""
Compliance evaluator for correlating audit findings with CIS and ISO/IEC 27001 controls.
"""

from .mapping import COMPLIANCE_MAPPING


class ComplianceEvaluator:
    """Evaluates audit results against CIS Docker Benchmark and ISO/IEC 27001 controls."""
    
    def __init__(self, audit_results, mapping=None):
        """
        Initialize the compliance evaluator.
        
        Args:
            audit_results (dict): Audit results from the orchestrator
            mapping (dict, optional): Custom compliance mapping. Defaults to COMPLIANCE_MAPPING.
        """
        self.audit_results = audit_results
        self.mapping = mapping or COMPLIANCE_MAPPING
        self.compliance_findings = []
    
    def evaluate(self):
        """
        Evaluate audit results against compliance controls.
        
        Returns:
            list: List of compliance findings with status and recommendations
        """
        self.compliance_findings = []
        
        # Evaluate each control in the mapping
        for cis_id, control in self.mapping.items():
            finding = self._evaluate_control(cis_id, control)
            self.compliance_findings.append(finding)
        
        return self.compliance_findings
    
    def _evaluate_control(self, cis_id, control):
        """
        Evaluate a single CIS control.
        
        Args:
            cis_id (str): CIS control ID (e.g., "CIS-2.1")
            control (dict): Control definition from mapping
            
        Returns:
            dict: Compliance finding with status and details
        """
        status, details = self._check_control(cis_id, control)
        
        finding = {
            "cis_control": cis_id,
            "title": control["title"],
            "description": control["description"],
            "severity": control["severity"],
            "status": status,  # "compliant", "non_compliant", "unknown"
            "iso27001_controls": control.get("iso27001_controls", []),
            "category": control.get("category", "General"),
            "remediation": control.get("remediation", ""),
            "details": details
        }
        
        return finding
    
    def _check_control(self, cis_id, control):
        """
        Check if a control is compliant based on audit results.
        
        Args:
            cis_id (str): CIS control ID
            control (dict): Control definition
            
        Returns:
            tuple: (status, details) where status is "compliant", "non_compliant", or "unknown"
        """
        # Extract implementation path (e.g., "container_audit.check_privileged_mode")
        impl_path = control.get("implementation", "")
        
        if not impl_path:
            return "unknown", {"reason": "No implementation method defined"}
        
        # Map control checks to audit results
        checks_map = {
            "host_audit.check_daemon_user": self._check_daemon_user,
            "host_audit.check_daemon_data_partition": self._check_daemon_data_partition,
            "host_audit.check_docker_version": self._check_docker_version,
            "host_audit.check_apparmor_selinux": self._check_apparmor_selinux,
            "host_audit.check_selinux_labels": self._check_selinux_labels,
            "container_audit.check_privileged_mode": self._check_privileged_mode,
            "container_audit.check_user_not_root": self._check_user_not_root,
            "container_audit.check_linux_capabilities": self._check_linux_capabilities,
            "container_audit.check_sensitive_files_readonly": self._check_sensitive_files_readonly,
            "container_audit.check_bind_mount_sensitive": self._check_bind_mount_sensitive,
            "container_audit.check_apparmor_disabled": self._check_apparmor_disabled,
            "container_audit.check_seccomp_profile": self._check_seccomp_profile,
            "container_audit.check_secrets_usage": self._check_secrets_usage,
            "container_audit.check_env_sensitive_data": self._check_env_sensitive_data,
            "image_analysis.check_custom_images": self._check_custom_images,
            "image_analysis.check_image_signature_verification": self._check_image_signature,
            "image_analysis.check_minimal_packages": self._check_minimal_packages,
            "image_analysis.check_trusted_base_images": self._check_trusted_base_images,
            "binary_analyzer.check_setuid_binaries": self._check_setuid_binaries,
            "image_analysis.check_vulnerability_scan": self._check_vulnerability_scan,
            "orchestrator.check_trusted_images_policy": self._check_trusted_images_policy,
            "orchestrator.check_orchestrator_version": self._check_orchestrator_version,
        }
        
        check_func = checks_map.get(impl_path)
        if not check_func:
            return "unknown", {"reason": f"Check not implemented: {impl_path}"}
        
        return check_func()
    
    # ============================================================================
    # Host audit checks
    # ============================================================================
    
    def _check_daemon_user(self):
        """Check if Docker daemon runs as non-root."""
        host_findings = self.audit_results.get("host_audit", {}).get("findings", [])
        
        for finding in host_findings:
            if "daemon" in finding.lower() and "root" in finding.lower():
                return "non_compliant", {"issue": finding}
        
        return "compliant", {"reason": "Daemon is not running as root"}
    
    def _check_daemon_data_partition(self):
        """Check if daemon data is on separate partition."""
        # This would require specific host audit checks
        return "unknown", {"reason": "Requires host audit implementation"}
    
    def _check_docker_version(self):
        """Check if Docker Engine is up to date."""
        host_audit = self.audit_results.get("host_audit", {})
        docker_version = host_audit.get("docker_version", "")
        
        if docker_version:
            return "compliant", {"version": docker_version}
        
        return "unknown", {"reason": "Docker version not detected"}
    
    def _check_apparmor_selinux(self):
        """Check if AppArmor/SELinux is configured."""
        host_findings = self.audit_results.get("host_audit", {}).get("findings", [])
        
        has_apparmor = any("apparmor" in str(f).lower() for f in host_findings)
        has_selinux = any("selinux" in str(f).lower() for f in host_findings)
        
        if has_apparmor or has_selinux:
            return "compliant", {"methods": ["AppArmor" if has_apparmor else "", "SELinux" if has_selinux else ""]}
        
        return "non_compliant", {"issue": "No AppArmor or SELinux detected"}
    
    def _check_selinux_labels(self):
        """Check if SELinux labels are properly configured."""
        return "unknown", {"reason": "Requires SELinux-specific audit implementation"}
    
    # ============================================================================
    # Container audit checks
    # ============================================================================
    
    def _check_privileged_mode(self):
        """Check if containers are running in privileged mode."""
        containers = self.audit_results.get("container_audit", {}).get("containers", [])
        
        privileged_containers = [c for c in containers if c.get("privileged", False)]
        
        if privileged_containers:
            return "non_compliant", {
                "issue": "Privileged containers detected",
                "count": len(privileged_containers),
                "containers": [c.get("name") for c in privileged_containers]
            }
        
        return "compliant", {"reason": "No privileged containers detected"}
    
    def _check_user_not_root(self):
        """Check if containers are running as non-root user."""
        containers = self.audit_results.get("container_audit", {}).get("containers", [])
        
        root_containers = [c for c in containers if c.get("user", "").lower() in ["root", "0", ""]]
        
        if root_containers:
            return "non_compliant", {
                "issue": "Containers running as root",
                "count": len(root_containers),
                "containers": [c.get("name") for c in root_containers]
            }
        
        return "compliant", {"reason": "All containers running as non-root"}
    
    def _check_linux_capabilities(self):
        """Check if Linux capabilities are properly restricted."""
        containers = self.audit_results.get("container_audit", {}).get("containers", [])
        
        unrestricted = [c for c in containers if not c.get("cap_drop")]
        
        if unrestricted:
            return "non_compliant", {
                "issue": "Unrestricted Linux capabilities",
                "count": len(unrestricted),
                "recommendation": "Use --cap-drop=ALL and add only necessary capabilities"
            }
        
        return "compliant", {"reason": "Linux capabilities properly restricted"}
    
    def _check_sensitive_files_readonly(self):
        """Check if sensitive files are mounted as read-only."""
        return "unknown", {"reason": "Requires volume mount analysis"}
    
    def _check_bind_mount_sensitive(self):
        """Check if sensitive paths are bind-mounted."""
        containers = self.audit_results.get("container_audit", {}).get("containers", [])
        
        dangerous_mounts = []
        for container in containers:
            volumes = container.get("volumes", [])
            for vol in volumes:
                if any(path in vol for path in ["/", "/etc", "/root", "/proc"]):
                    dangerous_mounts.append({"container": container.get("name"), "mount": vol})
        
        if dangerous_mounts:
            return "non_compliant", {
                "issue": "Sensitive paths bind-mounted",
                "mounts": dangerous_mounts
            }
        
        return "compliant", {"reason": "No sensitive paths bind-mounted"}
    
    def _check_apparmor_disabled(self):
        """Check if AppArmor is disabled."""
        containers = self.audit_results.get("container_audit", {}).get("containers", [])
        
        disabled = [c for c in containers if c.get("apparmor_disabled", False)]
        
        if disabled:
            return "non_compliant", {
                "issue": "AppArmor disabled",
                "count": len(disabled),
                "containers": [c.get("name") for c in disabled]
            }
        
        return "compliant", {"reason": "AppArmor not disabled"}
    
    def _check_seccomp_profile(self):
        """Check if Seccomp profile is applied."""
        containers = self.audit_results.get("container_audit", {}).get("containers", [])
        
        without_seccomp = [c for c in containers if not c.get("seccomp_profile")]
        
        if without_seccomp:
            return "non_compliant", {
                "issue": "Seccomp profile not applied",
                "count": len(without_seccomp),
                "recommendation": "Use --security-opt seccomp=/path/to/profile.json"
            }
        
        return "compliant", {"reason": "Seccomp profiles applied"}
    
    def _check_secrets_usage(self):
        """Check if secrets are properly used."""
        return "unknown", {"reason": "Requires secrets management implementation"}
    
    def _check_env_sensitive_data(self):
        """Check if sensitive data is stored in environment variables."""
        containers = self.audit_results.get("container_audit", {}).get("containers", [])
        
        sensitive_patterns = ["password", "secret", "api_key", "token", "credential"]
        
        containers_with_sensitive = []
        for container in containers:
            env_vars = container.get("env_vars", {})
            for key in env_vars.keys():
                if any(pattern in key.lower() for pattern in sensitive_patterns):
                    containers_with_sensitive.append({
                        "container": container.get("name"),
                        "env_var": key
                    })
        
        if containers_with_sensitive:
            return "non_compliant", {
                "issue": "Sensitive data in environment variables",
                "findings": containers_with_sensitive,
                "recommendation": "Use secrets management instead"
            }
        
        return "compliant", {"reason": "No sensitive data in environment variables"}
    
    # ============================================================================
    # Image analysis checks
    # ============================================================================
    
    def _check_custom_images(self):
        """Check if custom images are used instead of generic ones."""
        images = self.audit_results.get("image_analysis", {}).get("images", [])
        
        custom = [i for i in images if not i.get("is_official", True)]
        
        if custom:
            return "compliant", {
                "custom_images": len(custom),
                "reason": "Using custom images"
            }
        
        return "non_compliant", {"issue": "Using only official/generic images"}
    
    def _check_image_signature(self):
        """Check if image signatures are verified."""
        return "unknown", {"reason": "Requires Docker Content Trust verification"}
    
    def _check_minimal_packages(self):
        """Check if images have minimal packages."""
        images = self.audit_results.get("image_analysis", {}).get("images", [])
        
        package_counts = []
        for image in images:
            packages = image.get("packages", [])
            # Handle both list and count formats
            package_count = len(packages) if isinstance(packages, list) else packages
            if package_count > 100:  # Threshold for "not minimal"
                package_counts.append({
                    "image": image.get("name"),
                    "package_count": package_count
                })
        
        if package_counts:
            return "non_compliant", {
                "issue": "Images not minimal",
                "images": package_counts,
                "recommendation": "Use alpine, distroless or other minimal base images"
            }
        
        return "compliant", {"reason": "Images appear to be minimal"}
    
    def _check_trusted_base_images(self):
        """Check if trusted base images are used."""
        images = self.audit_results.get("image_analysis", {}).get("images", [])
        
        trusted_registries = ["official", "alpine", "debian", "ubuntu"]
        
        untrusted = [i for i in images if not any(t in i.get("registry", "").lower() for t in trusted_registries)]
        
        if untrusted:
            return "non_compliant", {
                "issue": "Untrusted base images",
                "count": len(untrusted)
            }
        
        return "compliant", {"reason": "Trusted base images used"}
    
    def _check_vulnerability_scan(self):
        """Check if images have been scanned for vulnerabilities."""
        vulnerabilities = self.audit_results.get("vulnerabilities", [])
        
        if vulnerabilities:
            critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
            high = sum(1 for v in vulnerabilities if v.get("severity") == "high")
            
            if critical > 0:
                return "non_compliant", {
                    "issue": "Critical vulnerabilities found",
                    "critical": critical,
                    "high": high
                }
            elif high > 0:
                return "non_compliant", {
                    "issue": "High severity vulnerabilities found",
                    "high": high
                }
        
        return "compliant", {"reason": "Vulnerability scan completed with acceptable results"}
    
    # ============================================================================
    # Binary analyzer checks
    # ============================================================================
    
    def _check_setuid_binaries(self):
        """Check for SETUID/SETGID binaries."""
        binaries = self.audit_results.get("image_analysis", {}).get("binaries", [])
        
        setuid = [b for b in binaries if b.get("setuid", False) or b.get("setgid", False)]
        
        if setuid:
            return "non_compliant", {
                "issue": "SETUID/SETGID binaries found",
                "count": len(setuid),
                "binaries": [b.get("path") for b in setuid[:5]]  # Show first 5
            }
        
        return "compliant", {"reason": "No SETUID/SETGID binaries found"}
    
    # ============================================================================
    # Orchestrator checks
    # ============================================================================
    
    def _check_trusted_images_policy(self):
        """Check if trusted images policy is enforced."""
        return "unknown", {"reason": "Requires policy engine integration"}
    
    def _check_orchestrator_version(self):
        """Check if orchestrator is up to date."""
        orchestrator = self.audit_results.get("orchestrator", {})
        version = orchestrator.get("version", "")
        
        if version:
            return "compliant", {"version": version}
        
        return "unknown", {"reason": "Orchestrator version not detected"}
    
    # ============================================================================
    # Reporting methods
    # ============================================================================
    
    def get_summary(self):
        """
        Get compliance summary statistics.
        
        Returns:
            dict: Summary with compliance statistics
        """
        if not self.compliance_findings:
            self.evaluate()
        
        total = len(self.compliance_findings)
        compliant = sum(1 for f in self.compliance_findings if f["status"] == "compliant")
        non_compliant = sum(1 for f in self.compliance_findings if f["status"] == "non_compliant")
        unknown = sum(1 for f in self.compliance_findings if f["status"] == "unknown")
        
        compliance_percentage = (compliant / total * 100) if total > 0 else 0
        
        return {
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "unknown": unknown,
            "compliance_percentage": round(compliance_percentage, 2)
        }
    
    def get_by_severity(self):
        """Group findings by severity."""
        if not self.compliance_findings:
            self.evaluate()
        
        by_severity = {}
        for finding in self.compliance_findings:
            severity = finding.get("severity", "unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        return by_severity
    
    def get_by_category(self):
        """Group findings by category."""
        if not self.compliance_findings:
            self.evaluate()
        
        by_category = {}
        for finding in self.compliance_findings:
            category = finding.get("category", "General")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(finding)
        
        return by_category
    
    def get_iso_coverage(self):
        """Get ISO/IEC 27001 coverage analysis."""
        if not self.compliance_findings:
            self.evaluate()
        
        iso_coverage = {}
        for finding in self.compliance_findings:
            for iso_control in finding.get("iso27001_controls", []):
                domain = iso_control.get("domain", "Unknown")
                if domain not in iso_coverage:
                    iso_coverage[domain] = {
                        "total": 0,
                        "compliant": 0,
                        "non_compliant": 0,
                        "unknown": 0,
                        "controls": []
                    }
                
                iso_coverage[domain]["total"] += 1
                iso_coverage[domain]["controls"].append(iso_control["code"])
                
                status = finding.get("status")
                if status == "compliant":
                    iso_coverage[domain]["compliant"] += 1
                elif status == "non_compliant":
                    iso_coverage[domain]["non_compliant"] += 1
                else:
                    iso_coverage[domain]["unknown"] += 1
        
        return iso_coverage
