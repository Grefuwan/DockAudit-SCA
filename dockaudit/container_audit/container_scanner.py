import docker
from docker.errors import DockerException


class ContainerAudit:
    def __init__(self, target="local"):
        self.target = target
        self.findings = []

    def run(self):
        try:
            client = docker.from_env()
            containers = client.containers.list(all=True)
        except Exception as exc:
            return [
                {
                    "id": "CONT-000",
                    "title": "Docker API unavailable for container audit",
                    "severity": "critical",
                    "description": str(exc),
                    "recommendation": "Verify Docker daemon is running and accessible."
                }
            ]

        if not containers:
            return [
                {
                    "id": "CONT-001",
                    "title": "No containers found",
                    "severity": "info",
                    "description": "No containers were discovered on the Docker host.",
                    "recommendation": "Run containers to audit runtime security posture."
                }
            ]

        for container in containers:
            attrs = getattr(container, "attrs", {}) or {}
            host_config = attrs.get("HostConfig", {})
            mounts = attrs.get("Mounts", [])
            privileged = host_config.get("Privileged", False)
            network_mode = host_config.get("NetworkMode", "")
            cap_add = host_config.get("CapAdd") or []
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

        return self.findings
