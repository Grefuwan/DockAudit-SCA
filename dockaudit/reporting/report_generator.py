import json
import logging
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)


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

    def generate(self, results, audit_target="All Containers", out_filename=None):
        logger.debug("Generando informe de auditoría para: %s", audit_target)
        os.makedirs("reports", exist_ok=True)

        # Packages are inventory data, not findings — extract before the findings filter
        raw_packages = results.get("packages", [])
        seen_pkgs = set()
        packages = []
        for pkg in raw_packages:
            key = (pkg.get("name"), pkg.get("version"), pkg.get("package_manager"))
            if key not in seen_pkgs:
                seen_pkgs.add(key)
                packages.append(pkg)

        # Build CVE index: package_name -> [CVE-IDs]
        vuln_by_package = {}
        for vuln in results.get("vulnerabilities", []):
            pkg_name = vuln.get("affected_package", "")
            if pkg_name:
                vuln_by_package.setdefault(pkg_name, []).append(vuln.get("id", ""))

        # Findings sections — filter by severity and deduplicate
        skip_keys = {"packages", "sbom_path", "image_analysis", "host_audit",
                     "container_audit", "compliance", "compliance_summary",
                     "compliance_iso_coverage"}
        filtered_results = {}
        for section, items in results.items():
            if section in skip_keys or not isinstance(items, list):
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

        base = out_filename or "report"
        if self.output_format == "json":
            out_path = os.path.join("reports", f"{base}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({**filtered_results, "packages": packages}, f, indent=2, ensure_ascii=False)
            logger.info("JSON report written to: %s", out_path)
            return out_path

        template = self._template()
        report_html = template.render(
            results=filtered_results,
            summary={
                section: len(items)
                for section, items in filtered_results.items()
            },
            packages=packages,
            vuln_by_package=vuln_by_package,
            sbom_path=results.get("sbom_path"),
            audit_target=audit_target
        )

        out_path = os.path.join("reports", f"{base}.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_html)

        logger.info("HTML report written to: %s", out_path)
        return out_path
