import json
import os

from dockaudit.reporting.report_generator import ReportGenerator


def test_generate_json_output(tmp_path, monkeypatch):
    results = {
        "host": [{"id": "HOST-001", "title": "Test", "severity": "info", "description": "desc", "recommendation": "rec"}],
        "containers": [],
        "images": []
    }

    monkeypatch.chdir(tmp_path)
    generator = ReportGenerator(output_format="json", severity="info")
    out_path = generator.generate(results)

    assert out_path.endswith("report.json")
    assert os.path.exists(out_path)
    with open(out_path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["host"][0]["id"] == "HOST-001"


def test_generate_html_output(tmp_path, monkeypatch):
    results = {
        "host": [{"id": "HOST-001", "title": "Test", "severity": "info", "description": "desc", "recommendation": "rec"}],
        "containers": [],
        "images": []
    }

    monkeypatch.chdir(tmp_path)
    generator = ReportGenerator(output_format="html", severity="info")
    out_path = generator.generate(results)

    assert out_path.endswith("report.html")
    assert os.path.exists(out_path)
    with open(out_path, encoding="utf-8") as f:
        html = f.read()
    assert "DockAudit-SCA Report" in html
    assert "HOST-001" in html
