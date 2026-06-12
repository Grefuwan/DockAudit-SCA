import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path


PURL_TYPE_BY_MANAGER = {
    "dpkg": "deb",
    "apk": "apk",
    "rpm": "rpm"
}


class SBOMGenerator:
    def __init__(self, output_dir="reports/sbom", output_format="json"):
        self.output_dir = output_dir
        self.output_format = output_format.lower()

    def _bom_reference(self, image_tag, image_id):
        name = image_tag.replace("/", ":").replace(" ", "_")
        return f"pkg:docker/{name}@{image_id}"

    def _build_component(self, image):
        tags = image.tags or ["<none>:<none>"]
        primary_tag = tags[0]
        image_name = primary_tag.split(":")[0].replace("/", "%2F")
        component = {
            "type": "container",
            "bom-ref": self._bom_reference(primary_tag, image.id[:12]),
            "name": primary_tag,
            "version": image.id[:12],
            "purl": f"pkg:docker/{image_name}@{image.id[:12]}",
            "description": image.attrs.get("Comment", ""),
            "properties": []
        }

        architecture = image.attrs.get("Architecture")
        os_value = image.attrs.get("Os")
        if architecture:
            component["properties"].append({"name": "architecture", "value": architecture})
        if os_value:
            component["properties"].append({"name": "os", "value": os_value})

        return component

    def _build_package_component(self, package):
        name = package.get("name")
        version = package.get("version")
        manager = package.get("package_manager", "unknown")
        purl_type = PURL_TYPE_BY_MANAGER.get(manager, "generic")
        purl = f"pkg:{purl_type}/{name}@{version}"
        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "description": f"Package installed from {manager}.",
            "properties": [
                {"name": "package-manager", "value": manager}
            ]
        }
        if package.get("image"):
            component["properties"].append({"name": "source-image", "value": package["image"]})
        return component

    def generate(self, images, package_components=None, filename=None):
        os.makedirs(self.output_dir, exist_ok=True)

        components = [self._build_component(image) for image in images]
        package_components = package_components or []
        components.extend([self._build_package_component(pkg) for pkg in package_components])
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "tools": [
                    {"vendor": "DockAudit-SCA", "name": "SBOM Generator", "version": "0.2"}
                ]
            },
            "components": components
        }

        out_path = Path(self.output_dir) / (filename or "sbom.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)

        print(f"[+] SBOM written to: {out_path}")
        return str(out_path), components
