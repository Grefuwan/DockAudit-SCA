import docker
from docker.errors import DockerException


class ContainerAudit:
    def __init__(self, target="local", container_filter=None):
        self.target = target
        self.container_filter = container_filter
        self.findings = []

    def run(self):
        try:
            client = docker.from_env()
            containers = client.containers.list(all=True)
        except Exception as exc:
            return {
                "findings": [
                    {
                        "id": "CONT-000",
                        "title": "Docker API unavailable for container audit",
                        "severity": "critical",
                        "description": str(exc),
                        "recommendation": "Verify Docker daemon is running and accessible."
                    }
                ],
                "containers": []
            }

        # Filtrar por nombre si se especifica
        if self.container_filter:
            containers = [c for c in containers if c.name == self.container_filter or self.container_filter in c.name]
            if not containers:
                return {
                    "findings": [
                        {
                            "id": "CONT-002",
                            "title": f"No containers found matching filter: {self.container_filter}",
                            "severity": "info",
                            "description": f"No containers with name '{self.container_filter}' were found on the Docker host.",
                            "recommendation": "Check the container name and try again."
                        }
                    ],
                    "containers": []
                }

        if not containers:
            return {
                "findings": [
                    {
                        "id": "CONT-001",
                        "title": "No containers found",
                        "severity": "info",
                        "description": "No containers were discovered on the Docker host.",
                        "recommendation": "Run containers to audit runtime security posture."
                    }
                ],
                "containers": []
            }

        detailed_containers = []

        for container in containers:
            attrs = getattr(container, "attrs", {}) or {}
            host_config = attrs.get("HostConfig", {})
            config = attrs.get("Config", {})
            mounts = attrs.get("Mounts", [])
            privileged = host_config.get("Privileged", False)
            network_mode = host_config.get("NetworkMode", "")
            cap_add = host_config.get("CapAdd") or []
            security_opt = host_config.get("SecurityOpt") or []

            env_vars = {}
            for env in config.get("Env", []) or []:
                if "=" in env:
                    key, _, value = env.partition("=")
                    env_vars[key] = value

            mounts_metadata = []
            for mount in mounts:
                mounts_metadata.append({
                    "type": mount.get("Type"),
                    "source": mount.get("Source"),
                    "destination": mount.get("Destination"),
                    "rw": mount.get("RW", True),
                    "propagation": mount.get("Propagation")
                })

            seccomp_profile = None
            for opt in security_opt:
                if opt.startswith("seccomp="):
                    seccomp_profile = opt.split("=", 1)[1]

            apparmor_disabled = any("apparmor=unconfined" in str(opt).lower() for opt in security_opt)

            container_metadata = {
                "name": container.name,
                "image": config.get("Image"),
                "privileged": privileged,
                "user": config.get("User", ""),
                "cap_drop": host_config.get("CapDrop") or [],
                "network_mode": network_mode,
                "security_opt": security_opt,
                "apparmor_disabled": apparmor_disabled,
                "seccomp_profile": seccomp_profile,
                "read_only_rootfs": host_config.get("ReadonlyRootfs", False),
                "cpu_shares": host_config.get("CpuShares"),
                "cpu_limits": host_config.get("NanoCpus") or host_config.get("CpuQuota"),
                "memory_limit": host_config.get("Memory"),
                "restart_policy": host_config.get("RestartPolicy", {}).get("Name"),
                "pids_limit": host_config.get("PidsLimit") or 0,
                "volumes": mounts_metadata,
                "env_vars": env_vars,
                "healthcheck": bool(config.get("Healthcheck")),
                "registry": self._extract_registry(config.get("Image"))
            }

            detailed_containers.append(container_metadata)

            if privileged:
                self.findings.append({
                    "id": "CONT-002",
                    "title": f"Privileged container detected: {container.name}",
                    "severity": "high",
                    "description": "A container is running with privileged access.",
                    "recommendation": "Avoid privileged containers unless strictly required."
                })

            if network_mode == "host":
                self.findings.append({
                    "id": "CONT-003",
                    "title": f"Container using host network mode: {container.name}",
                    "severity": "high",
                    "description": "The container shares the host network stack.",
                    "recommendation": "Use bridge networking to isolate container network traffic."
                })

            if any(cap == "ALL" for cap in cap_add):
                self.findings.append({
                    "id": "CONT-004",
                    "title": f"Container adds all Linux capabilities: {container.name}",
                    "severity": "high",
                    "description": "The container is configured to add all capabilities.",
                    "recommendation": "Limit Linux capabilities to the minimum required."
                })

            if any(mount.get("Type") == "bind" for mount in mounts):
                self.findings.append({
                    "id": "CONT-005",
                    "title": f"Bind mount detected: {container.name}",
                    "severity": "medium",
                    "description": "The container uses a host bind mount, which can expose host files.",
                    "recommendation": "Restrict bind mounts and avoid mounting sensitive host directories."
                })

            if not any([privileged, network_mode == "host", any(cap == "ALL" for cap in cap_add), any(mount.get("Type") == "bind" for mount in mounts)]):
                self.findings.append({
                    "id": "CONT-006",
                    "title": f"Container appears to follow best practices: {container.name}",
                    "severity": "info",
                    "description": "No high-risk runtime configuration was detected for this container.",
                    "recommendation": "Continue applying least-privilege runtime options."
                })

        return {
            "findings": self.findings,
            "containers": detailed_containers
        }

    def _extract_registry(self, image_name):
        if not image_name:
            return ""

        if "/" not in image_name:
            return "docker.io"

        parts = image_name.split("/")
        if "." in parts[0] or ":" in parts[0]:
            return parts[0]

        return "docker.io"
