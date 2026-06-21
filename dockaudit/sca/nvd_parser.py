import gzip
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class NVDParser:
    def load_feed(self, feed_path):
        logger.debug("Cargando feed NVD: %s", feed_path)
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

        # API 2.0 places configurations under cve as a list; the simplified
        # sample feed keeps a single dict at entry level. Accept both.
        configurations = cve.get("configurations") or entry.get("configurations") or []
        if isinstance(configurations, dict):
            configurations = [configurations]

        matches = []
        for config in configurations:
            for node in config.get("nodes", []):
                matches.extend(self._extract_node_matches(node))

        cvss = self._extract_cvss(cve.get("metrics") or entry.get("metrics") or {})

        return {
            "id": cve_id,
            "description": description,
            "cpes": list({m["cpe"] for m in matches}),
            "matches": matches,
            "cvss_score": cvss.get("score"),
            "cvss_severity": cvss.get("severity", ""),
            "cvss_vector": cvss.get("vector", "")
        }

    def _parse_v1_item(self, item):
        cve = item.get("cve", {})
        cve_id = cve.get("CVE_data_meta", {}).get("ID")
        description_data = cve.get("description", {}).get("description_data", [])
        description = next((d.get("value", "") for d in description_data if d.get("lang") == "en"), "")

        matches = []
        for node in item.get("configurations", {}).get("nodes", []):
            matches.extend(self._extract_node_matches(node))

        cvss = self._extract_cvss_v1(item.get("impact", {}))

        return {
            "id": cve_id,
            "description": description,
            "cpes": list({m["cpe"] for m in matches}),
            "matches": matches,
            "cvss_score": cvss.get("score"),
            "cvss_severity": cvss.get("severity", ""),
            "cvss_vector": cvss.get("vector", "")
        }

    def _extract_node_matches(self, node):
        matches = []
        for match in node.get("cpeMatch", []):
            # API 2.0 uses "criteria"; older/simplified feeds use "cpe23Uri".
            cpe = match.get("criteria") or match.get("cpe23Uri")
            if cpe and match.get("vulnerable", True):
                matches.append({
                    "cpe": cpe,
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding")
                })
            for name in match.get("cpeName", []):
                if name.get("cpe23Uri"):
                    matches.append({
                        "cpe": name["cpe23Uri"],
                        "version_start_including": None,
                        "version_start_excluding": None,
                        "version_end_including": None,
                        "version_end_excluding": None
                    })

        for child in node.get("children", []):
            matches.extend(self._extract_node_matches(child))

        return matches

    def _extract_cvss(self, metrics):
        # Prefer CVSS v3.1, then v3.0, then v2.
        for key in ("cvssMetricV31", "cvssMetricV30"):
            for metric in metrics.get(key, []):
                data = metric.get("cvssData", {})
                if data.get("baseScore") is not None:
                    return {
                        "score": data["baseScore"],
                        "severity": data.get("baseSeverity", "").lower(),
                        "vector": data.get("vectorString", "")
                    }
        for metric in metrics.get("cvssMetricV2", []):
            data = metric.get("cvssData", {})
            if data.get("baseScore") is not None:
                return {
                    "score": data["baseScore"],
                    "severity": metric.get("baseSeverity", "").lower(),
                    "vector": data.get("vectorString", "")
                }
        return {}

    def _extract_cvss_v1(self, impact):
        v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
        if v3.get("baseScore") is not None:
            return {
                "score": v3["baseScore"],
                "severity": v3.get("baseSeverity", "").lower(),
                "vector": v3.get("vectorString", "")
            }
        v2 = impact.get("baseMetricV2", {})
        if v2.get("cvssV2", {}).get("baseScore") is not None:
            return {
                "score": v2["cvssV2"]["baseScore"],
                "severity": v2.get("severity", "").lower(),
                "vector": v2["cvssV2"].get("vectorString", "")
            }
        return {}
