import gzip
import json
from pathlib import Path

from dockaudit.sca.nvd_parser import NVDParser


def test_load_nvd_json_feed(tmp_path):
    sample = {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-TEST-0001"},
                    "description": {
                        "description_data": [
                            {"lang": "en", "value": "Example vulnerability"}
                        ]
                    }
                },
                "configurations": {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "cpe23Uri": "cpe:2.3:a:python:python:3.11:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            }
        ]
    }

    path = tmp_path / "feed.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    parser = NVDParser()
    entries = parser.load_feed(path)

    assert entries[0]["id"] == "CVE-TEST-0001"
    assert any("cpe:2.3:a:python" in cpe for cpe in entries[0]["cpes"])


def test_load_nvd_gzip_feed(tmp_path):
    sample = {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-TEST-0002"},
                    "description": {
                        "description_data": [
                            {"lang": "en", "value": "Example vulnerability gzip"}
                        ]
                    }
                },
                "configurations": {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "cpe23Uri": "cpe:2.3:a:python:python:3.10:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            }
        ]
    }

    path = tmp_path / "feed.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(sample, f)

    parser = NVDParser()
    entries = parser.load_feed(path)

    assert entries[0]["id"] == "CVE-TEST-0002"
