import io
import tarfile

from dockaudit.image_analysis.binary_analyzer import BinaryAnalyzer


class DummyImage:
    def __init__(self, image_id, tar_bytes):
        self.id = image_id
        self._tar_bytes = tar_bytes

    def save(self):
        yield self._tar_bytes


def make_tar_bytes(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path, content, mode in entries:
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_binary_analyzer_detects_suid_and_sensitive_files():
    entries = [
        ("etc/passwd", "root:x:0:0:root:/root:/bin/bash", 0o644),
        ("usr/bin/testprog", "#!/bin/sh\necho hi", 0o4755),
        ("lib/libexample.so", "", 0o644)
    ]
    tar_bytes = make_tar_bytes(entries)
    image = DummyImage("sha256abcdef", tar_bytes)
    analyzer = BinaryAnalyzer(None)

    findings = analyzer.analyze_images([image])
    assert any(item["id"].startswith("BIN-001") and item["severity"] == "critical" for item in findings)
    assert any(item["id"].startswith("BIN-003") for item in findings)
    assert any(item["id"].startswith("BIN-004") for item in findings)
