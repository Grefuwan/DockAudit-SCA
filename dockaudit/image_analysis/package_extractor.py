import json
import os
import re
import subprocess
import tarfile
import tempfile


class PackageExtractor:
    """
    Extracts installed packages from a Docker image.

    Primary strategy is static analysis: the image filesystem is exported with
    `docker save` and the package database files (dpkg/apk) are parsed without
    ever executing code from the audited image. RPM databases are binary
    (BerkeleyDB/SQLite with rpm-specific headers), so rpm-based images fall
    back to a hardened `docker run` (no network, read-only, all capabilities
    dropped).
    """

    DPKG_STATUS = "var/lib/dpkg/status"
    DPKG_STATUS_D = "var/lib/dpkg/status.d/"  # distroless images
    APK_INSTALLED = "lib/apk/db/installed"
    RPM_DB_PREFIXES = ("var/lib/rpm/", "usr/lib/sysimage/rpm/")

    def __init__(self, client):
        self.client = client

    def extract(self, image, timeout=120):
        image_ref = image.tags[0] if image.tags else image.id

        try:
            packages, rpm_present = self._extract_static(image_ref, timeout)
        except subprocess.TimeoutExpired:
            return [], "timeout: package extraction took too long"
        except Exception:
            # docker save failed or the tar layout was unexpected; fall back
            # to the (hardened) runtime path for any package manager.
            return self._extract_runtime(image_ref, timeout)

        if packages:
            return packages, "ok"

        if rpm_present:
            return self._extract_runtime(image_ref, timeout)

        return [], "no package manager found"

    # ------------------------------------------------------------------
    # Static extraction (docker save)
    # ------------------------------------------------------------------

    def _extract_static(self, image_ref, timeout):
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = os.path.join(tmpdir, "image.tar")
            result = subprocess.run(
                ["docker", "save", "-o", tar_path, image_ref],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode != 0:
                raise Exception(result.stderr.strip() or "docker save failed")

            with tarfile.open(tar_path) as tar:
                return self._scan_image_tar(tar)

    def _scan_image_tar(self, tar):
        manifest_member = tar.extractfile("manifest.json")
        if manifest_member is None:
            raise Exception("manifest.json not found in image tar")
        manifest = json.load(manifest_member)
        layers = manifest[0].get("Layers", [])

        dpkg_status = None
        distroless_blocks = {}
        apk_installed = None
        rpm_present = False

        # Later layers override earlier ones, so iterate in order and keep
        # the last occurrence of each database file.
        for layer_name in layers:
            layer_file = tar.extractfile(layer_name)
            if layer_file is None:
                continue
            with tarfile.open(fileobj=layer_file) as layer_tar:
                for member in layer_tar:
                    name = member.name.lstrip("./")
                    if name == self.DPKG_STATUS and member.isfile():
                        dpkg_status = layer_tar.extractfile(member).read().decode("utf-8", errors="replace")
                    elif name.startswith(self.DPKG_STATUS_D) and member.isfile():
                        distroless_blocks[name] = layer_tar.extractfile(member).read().decode("utf-8", errors="replace")
                    elif name == self.APK_INSTALLED and member.isfile():
                        apk_installed = layer_tar.extractfile(member).read().decode("utf-8", errors="replace")
                    elif name.startswith(self.RPM_DB_PREFIXES) and member.isfile():
                        rpm_present = True

        if dpkg_status:
            return self._parse_dpkg_status(dpkg_status), rpm_present
        if distroless_blocks:
            combined = "\n\n".join(distroless_blocks.values())
            return self._parse_dpkg_status(combined), rpm_present
        if apk_installed:
            return self._parse_apk_installed(apk_installed), rpm_present

        return [], rpm_present

    def _parse_dpkg_status(self, content):
        packages = []
        for block in re.split(r"\n\s*\n", content):
            fields = {}
            for line in block.splitlines():
                if ":" in line and not line.startswith(" "):
                    key, _, value = line.partition(":")
                    fields[key.strip()] = value.strip()

            name = fields.get("Package")
            version = fields.get("Version")
            status = fields.get("Status", "install ok installed")
            if name and version and "installed" in status:
                packages.append({
                    "name": name,
                    "version": version,
                    "type": "library",
                    "package_manager": "dpkg"
                })
        return packages

    def _parse_apk_installed(self, content):
        packages = []
        name = version = None
        for line in content.splitlines() + [""]:
            line = line.strip()
            if not line:
                if name and version:
                    packages.append({
                        "name": name,
                        "version": version,
                        "type": "library",
                        "package_manager": "apk"
                    })
                name = version = None
                continue
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("V:"):
                version = line[2:].strip()
        return packages

    # ------------------------------------------------------------------
    # Runtime fallback (hardened docker run)
    # ------------------------------------------------------------------

    def _extract_runtime(self, image_ref, timeout):
        try:
            output = self._run_package_list(image_ref, timeout)
        except subprocess.TimeoutExpired:
            return [], "timeout: package extraction took too long"
        except Exception as exc:
            return [], str(exc)

        if not output:
            return [], "no output"
        if output.strip() == "NO_PKG_MGR":
            return [], "no package manager found"

        return self._parse_runtime_output(output), "ok"

    def _run_package_list(self, image_ref, timeout):
        # First line of output identifies the package manager that answered.
        shell_cmd = (
            "if command -v rpm >/dev/null 2>&1; then echo '#MGR rpm'; "
            "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n'; "
            "elif command -v dpkg-query >/dev/null 2>&1; then echo '#MGR dpkg'; "
            "dpkg-query -W -f='${Package} ${Version}\\n'; "
            "elif command -v apk >/dev/null 2>&1; then echo '#MGR apk'; "
            "apk info -vv | awk '{print $1 \" \" $2}'; "
            "else echo NO_PKG_MGR; fi"
        )
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=64",
                "--memory=256m",
                "--entrypoint", "sh",
                image_ref, "-c", shell_cmd
            ],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or f"docker run exited with code {result.returncode}")
        return result.stdout

    def _parse_runtime_output(self, output):
        packages = []
        manager = "unknown"
        for line in output.splitlines():
            line = line.strip()
            if not line or line == "NO_PKG_MGR":
                continue
            if line.startswith("#MGR "):
                manager = line[5:].strip()
                continue
            match = re.match(r"^(?P<name>[^\s]+)\s+(?P<version>.+)$", line)
            if match:
                packages.append({
                    "name": match.group("name"),
                    "version": match.group("version"),
                    "type": "library",
                    "package_manager": manager
                })
        return packages
