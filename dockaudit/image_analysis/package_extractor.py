import re
import subprocess
import signal

from docker.errors import DockerException


class PackageExtractor:
    PACKAGE_PATTERNS = {
        "dpkg": re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>.+)$"),
        "rpm": re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>.+)$"),
        "apk": re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>.+)$")
    }

    def __init__(self, client):
        self.client = client

    def extract(self, image, timeout=15):
        """
        Extract packages from image with timeout protection.
        
        Args:
            image: Docker image object
            timeout: Maximum seconds to wait for package extraction
        """
        try:
            output = self._run_package_list(image, timeout)
        except TimeoutError:
            return [], "timeout: package extraction took too long"
        except Exception as exc:
            return [], str(exc)

        if not output:
            return [], "no output"

        if output.strip() == "NO_PKG_MGR":
            return [], "no package manager found"

        packages = self._parse_packages(output)
        return packages, "ok"

    def _run_package_list(self, image, timeout=15):
        command = [
            "sh",
            "-c",
            "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package} ${Version}\\n'; "
            "elif command -v rpm >/dev/null 2>&1; then rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n'; "
            "elif command -v apk >/dev/null 2>&1; then apk info -vv | awk '{print $1 \" \" $2}'; "
            "else echo NO_PKG_MGR; fi"
        ]

        try:
            result = self.client.containers.run(
                image.id,
                command,
                remove=True,
                stdout=True,
                stderr=True,
                tty=False,
                timeout=timeout
            )
            return result.decode("utf-8", errors="replace")
        except Exception as e:
            if "timeout" in str(e).lower():
                raise TimeoutError(f"Package extraction timeout after {timeout}s")
            raise

    def _parse_packages(self, output):
        packages = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line == "NO_PKG_MGR":
                continue

            for manager, pattern in self.PACKAGE_PATTERNS.items():
                match = pattern.match(line)
                if match:
                    name = match.group("name")
                    version = match.group("version")
                    packages.append({
                        "name": name,
                        "version": version,
                        "type": "library",
                        "package_manager": manager,
                    })
                    break
        return packages
