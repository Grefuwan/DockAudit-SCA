import json
import os


class ReportGenerator:
    def __init__(self, output_format="html", severity="medium"):
        self.output_format = output_format
        self.severity = severity

    def generate(self, results):
        os.makedirs("reports", exist_ok=True)

        if self.output_format == "json":
            out_path = os.path.join("reports", "report.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"[+] JSON report written to: {out_path}")
            return out_path

        # Default: HTML
        out_path = os.path.join("examples", "sample_report.html")
        html = [
            "<html><head><meta charset='utf-8'><title>DockAudit-SCA Report</title></head><body>",
            "<h1>DockAudit-SCA - Informe</h1>",
        ]

        for section in ("host", "containers", "images"):
            html.append(f"<h2>{section.capitalize()}</h2>")
            html.append("<ul>")
            for item in results.get(section, []):
                html.append(f"<li><strong>{item.get('id')}</strong> - {item.get('title')} ({item.get('severity')})<br>{item.get('description')}<br><em>{item.get('recommendation')}</em></li>")
            html.append("</ul>")

        html.append("</body></html>")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))

        print(f"[+] HTML report written to: {out_path}")
        return out_path
