import json
from pathlib import Path

from dockaudit.image_analysis.sbom_generator import SBOMGenerator


class DummyImage:
    def __init__(self, tags, id_value, attrs):
        self.tags = tags
        self.id = id_value
        self.attrs = attrs


def test_sbom_generator_creates_sbom_file(tmp_path):
    images = [DummyImage(["alpine:3.18"], "sha256abcd1234", {"Architecture": "amd64", "Os": "linux", "Comment": "base image"})]
    generator = SBOMGenerator(output_dir=str(tmp_path / "sbom"))

    out_path, components = generator.generate(images)
    assert Path(out_path).exists()

    content = json.loads(Path(out_path).read_text(encoding="utf-8"))
    assert content["bomFormat"] == "CycloneDX"
    assert len(content["components"]) == 1
    assert content["components"][0]["name"] == "alpine:3.18"
    assert content["components"][0]["purl"].startswith("pkg:docker/alpine@")
    assert components[0]["version"] == "sha256abcd1234"[:12]


def test_sbom_package_components_have_purl(tmp_path):
    images = [DummyImage(["debian:12"], "sha256abcd1234", {"Architecture": "amd64", "Os": "linux"})]
    packages = [
        {"name": "bash", "version": "5.1-2", "package_manager": "dpkg", "image": "debian:12"},
        {"name": "musl", "version": "1.2.4-r2", "package_manager": "apk"}
    ]
    generator = SBOMGenerator(output_dir=str(tmp_path / "sbom"))

    out_path, components = generator.generate(images, package_components=packages)
    content = json.loads(Path(out_path).read_text(encoding="utf-8"))

    libs = [c for c in content["components"] if c["type"] == "library"]
    assert libs[0]["purl"] == "pkg:deb/bash@5.1-2"
    assert libs[1]["purl"] == "pkg:apk/musl@1.2.4-r2"
    assert {"name": "source-image", "value": "debian:12"} in libs[0]["properties"]
