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
    assert components[0]["version"] == "sha256abcd1234"[:12]
