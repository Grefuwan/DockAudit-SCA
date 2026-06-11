import re
import subprocess


class PackageExtractor:
    PACKAGE_PATTERNS = {
        "dpkg": re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>.+)$"),
        "rpm": re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>.+)$"),
        "apk": re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>.+)$")
    }

    def __init__(self, client):
        self.client = client

    def extract(self, image, timeout=60):
        try:
            output = self._run_package_list(image, timeout)
        except subprocess.TimeoutExpired:
            return [], "timeout: package extraction took too long"
        except Exception as exc:
            return [], str(exc)

        if not output:
            return [], "no output"

        if output.strip() == "NO_PKG_MGR":
            return [], "no package manager found"

        packages = self._parse_packages(output)
        return packages, "ok"

    def _run_package_list(self, image, timeout=60):
        image_ref = image.tags[0] if image.tags else image.id
        shell_cmd = (
            "if command -v dpkg-query >/dev/null 2>&1; then "
            "dpkg-query -W -f='${Package} ${Version}\\n'; "
            "elif command -v rpm >/dev/null 2>&1; then "
            "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n'; "
            "elif command -v apk >/dev/null 2>&1; then "
            "apk info -vv | awk '{print $1 \" \" $2}'; "
            "else echo NO_PKG_MGR; fi"
        )
        result = subprocess.run(
            ["docker", "run", "--rm", image_ref, "sh", "-c", shell_cmd],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or f"docker run exited with code {result.returncode}")
        return result.stdout

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
