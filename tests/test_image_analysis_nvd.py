import json
from pathlib import Path

from dockaudit.image_analysis.image_scanner import ImageAnalysis


class DummyImage:
    def __init__(self):
        self.tags = ["python:3.11"]
        self.id = "sha256example"
        self.attrs = {"Architecture": "amd64", "Os": "linux", "Comment": "Python runtime"}


class DummyImages:
    def __init__(self, items):
        self._items = items

    def list(self):
        return self._items


class DummyContainers:
    def run(self, image_id, command, remove, stdout, stderr, tty, **kwargs):
        return b"python 3.11.5\n"


class DummyDocker:
    def __init__(self, images):
        self.images = images
        self.containers = DummyContainers()


def test_image_analysis_generates_sbom_and_matches_nvd(tmp_path, monkeypatch):
    docker_client = DummyDocker(DummyImages([DummyImage()]))
    monkeypatch.setattr("dockaudit.image_analysis.image_scanner.docker.from_env", lambda: docker_client)

    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-TEST-0004"},
                    "description": {"description_data": [{"lang": "en", "value": "Python vulnerability"}]}
                },
                "configurations": {"nodes": [{"cpeMatch": [{"vulnerable": True, "cpe23Uri": "cpe:2.3:a:python:python:3.11:*:*:*:*:*:*:*"}]}]}
            }
        ]
    }), encoding="utf-8")

    analysis = ImageAnalysis(sbom_dir=str(tmp_path / "sbom"), nvd_feed=str(feed))
    result = analysis.run()

    assert result["sbom_path"] is not None
    assert Path(result["sbom_path"]).exists()
    assert any(vuln["id"] == "CVE-TEST-0004" for vuln in result["vulnerabilities"])
