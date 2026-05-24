import json
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportGenerator:
    SEVERITY_ORDER = {
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5
    }

    def __init__(self, output_format="html", severity="medium"):
        self.output_format = output_format.lower()
        self.severity = self.SEVERITY_ORDER.get(severity.lower(), 2)

    def _filter(self, findings):
        return [
            finding for finding in findings
            if self.SEVERITY_ORDER.get(finding.get("severity", "info"), 0) >= self.severity
        ]

    def _template(self):
        template_dir = Path(__file__).resolve().parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"])
        )
        return env.get_template("report_template.html")

    def generate(self, results):
        os.makedirs("reports", exist_ok=True)

        filtered_results = {}
        for section, items in results.items():
            if not isinstance(items, list):
                continue
            filtered = self._filter(items)
            deduped = []
            seen = set()
            for item in filtered:
                key = item.get("id") or (item.get("title"), item.get("description"))
                if key in seen:
                    continue
                seen.add(key)
                item.setdefault("risk_score", self.SEVERITY_ORDER.get(item.get("severity", "info"), 1))
                deduped.append(item)
            filtered_results[section] = deduped

        if self.output_format == "json":
            out_path = os.path.join("reports", "report.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(filtered_results, f, indent=2, ensure_ascii=False)
            print(f"[+] JSON report written to: {out_path}")
            return out_path

        template = self._template()
        report_html = template.render(
            results=filtered_results,
            summary={
                section: len(items)
                for section, items in filtered_results.items()
            },
            sbom_path=results.get("sbom_path")
        )

        out_path = os.path.join("reports", "report.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_html)

        print(f"[+] HTML report written to: {out_path}")
        return out_path
