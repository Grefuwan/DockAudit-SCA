import gzip
import json
from pathlib import Path


class NVDParser:
    def load_feed(self, feed_path):
        feed_path = Path(feed_path)
        if not feed_path.exists():
            raise FileNotFoundError(f"NVD feed not found: {feed_path}")

        opener = gzip.open if feed_path.suffix == ".gz" else open
        with opener(feed_path, "rt", encoding="utf-8") as f:
            data = json.load(f)

        if "vulnerabilities" in data:
            return [self._parse_v2_entry(entry) for entry in data["vulnerabilities"]]

        if "CVE_Items" in data:
            return [self._parse_v1_item(item) for item in data["CVE_Items"]]

        raise ValueError("Unsupported NVD feed structure")

    def _parse_v2_entry(self, entry):
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        cpes = self._extract_cpes(entry.get("configurations", {}))
        return {
            "id": cve_id,
            "description": description,
            "cpes": cpes
        }

    def _parse_v1_item(self, item):
        cve = item.get("cve", {})
        cve_id = cve.get("CVE_data_meta", {}).get("ID")
        description_data = cve.get("description", {}).get("description_data", [])
        description = next((d.get("value", "") for d in description_data if d.get("lang") == "en"), "")
        cpes = self._extract_cpes(item.get("configurations", {}))
        return {
            "id": cve_id,
            "description": description,
            "cpes": cpes
        }

    def _extract_cpes(self, configurations):
        cpes = []
        for node in configurations.get("nodes", []):
            cpes.extend(self._extract_node_cpes(node))
        return list({cp for cp in cpes if cp})

    def _extract_node_cpes(self, node):
        cpes = []
        for match in node.get("cpeMatch", []):
            if match.get("cpe23Uri"):
                cpes.append(match["cpe23Uri"])
            for name in match.get("cpeName", []):
                if name.get("cpe23Uri"):
                    cpes.append(name["cpe23Uri"])

        for child in node.get("children", []):
            cpes.extend(self._extract_node_cpes(child))

        return cpes
