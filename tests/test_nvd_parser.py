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


def test_load_nvd_v2_feed_with_cvss_and_ranges(tmp_path):
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST-2001",
                    "descriptions": [
                        {"lang": "en", "value": "API 2.0 entry with CVSS and version ranges"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                }
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "3.0.0",
                                            "versionEndExcluding": "3.0.12"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }

    path = tmp_path / "feed_v2.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    entries = NVDParser().load_feed(path)
    entry = entries[0]

    assert entry["id"] == "CVE-TEST-2001"
    assert entry["cvss_score"] == 9.8
    assert entry["cvss_severity"] == "critical"
    assert entry["cvss_vector"].startswith("CVSS:3.1")
    assert entry["matches"][0]["cpe"] == "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
    assert entry["matches"][0]["version_start_including"] == "3.0.0"
    assert entry["matches"][0]["version_end_excluding"] == "3.0.12"


def test_load_nvd_v2_sample_feed_entry_level_configurations(tmp_path):
    # The simplified sample feed keeps configurations at entry level as a dict
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST-2002",
                    "descriptions": [{"lang": "en", "value": "Sample style"}]
                },
                "configurations": {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "cpe23Uri": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            }
        ]
    }

    path = tmp_path / "feed_sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    entries = NVDParser().load_feed(path)

    assert entries[0]["id"] == "CVE-TEST-2002"
    assert "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*" in entries[0]["cpes"]
    assert entries[0]["cvss_score"] is None
