import io
import logging
import tarfile

logger = logging.getLogger(__name__)


class GeneratorFile(io.RawIOBase):
    def __init__(self, iterator):
        self.iterator = iterator
        self.buffer = b""

    def readable(self):
        return True

    def read(self, size=-1):
        while size < 0 or len(self.buffer) < size:
            try:
                chunk = next(self.iterator)
            except StopIteration:
                break
            self.buffer += chunk
            if size >= 0 and len(self.buffer) >= size:
                break

        if size < 0:
            result, self.buffer = self.buffer, b""
        else:
            result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


class BinaryAnalyzer:
    def __init__(self, client):
        self.client = client

    def analyze_images(self, images):
        logger.debug("Analizando binarios de %s imagen(es)", len(images))
        findings = []
        for image in images:
            findings.extend(self._analyze_single_image(image))
        return findings

    def _analyze_single_image(self, image):
        image_tag = image.tags[0] if image.tags else image.id[:12]
        src = {"source": image_tag, "source_type": "image"}

        try:
            tar_stream = image.save()
            fileobj = GeneratorFile(iter(tar_stream))
            tar = tarfile.open(fileobj=fileobj, mode="r|*")
        except Exception as exc:
            return [
                {
                    "id": f"BIN-ERR-{image.id[:8]}",
                    "title": "Binary analysis failed",
                    "severity": "medium",
                    "description": str(exc),
                    "recommendation": "Verify that the Docker image is accessible and the Docker daemon is running.",
                    **src
                }
            ]

        exec_count = 0
        suid_files = []
        sgid_files = []
        library_files = []
        suspicious_files = []

        for member in tar:
            if not member.isfile():
                continue

            path = member.name
            mode = member.mode
            if mode & 0o111:
                exec_count += 1
            if mode & 0o4000:
                suid_files.append(path)
            if mode & 0o2000:
                sgid_files.append(path)
            if path.endswith(".so") or ".so." in path:
                library_files.append(path)

            lower = path.lower()
            if any(
                lower.endswith(file_name) or lower.endswith(file_name.lstrip("/"))
                for file_name in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
            ):
                suspicious_files.append(path)

        findings = []
        if suid_files:
            findings.append({
                "id": f"BIN-001-{image.id[:8]}",
                "title": "SUID binaries detected",
                "severity": "critical",
                "description": f"{len(suid_files)} SUID file(s) found: {', '.join(suid_files[:3])}",
                "recommendation": "Avoid SUID binaries in container images and use least privilege for executables.",
                **src
            })

        if sgid_files:
            findings.append({
                "id": f"BIN-002-{image.id[:8]}",
                "title": "SGID binaries detected",
                "severity": "high",
                "description": f"{len(sgid_files)} SGID file(s) found: {', '.join(sgid_files[:3])}",
                "recommendation": "Remove unnecessary SGID bits from container binaries.",
                **src
            })

        if suspicious_files:
            findings.append({
                "id": f"BIN-003-{image.id[:8]}",
                "title": "Sensitive configuration files present",
                "severity": "high",
                "description": f"Potentially sensitive file paths detected: {', '.join(suspicious_files[:3])}",
                "recommendation": "Review and remove embedded sensitive files from the container image.",
                **src
            })

        if library_files:
            findings.append({
                "id": f"BIN-004-{image.id[:8]}",
                "title": "Shared libraries detected",
                "severity": "medium",
                "description": f"{len(library_files)} shared library files discovered in the image.",
                "recommendation": "Inspect shared libraries for known vulnerabilities and remove unused libraries.",
                **src
            })

        if exec_count:
            findings.append({
                "id": f"BIN-005-{image.id[:8]}",
                "title": "Executable artifacts found",
                "severity": "info",
                "description": f"{exec_count} executable files were located in the image filesystem.",
                "recommendation": "Verify that only required binaries are included in the container image.",
                **src
            })

        return findings
