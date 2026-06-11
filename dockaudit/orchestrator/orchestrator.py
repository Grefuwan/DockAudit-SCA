
from dockaudit.host_audit.host_scanner import HostAudit
from dockaudit.container_audit.container_scanner import ContainerAudit
from dockaudit.image_analysis.image_scanner import ImageAnalysis
from dockaudit.reporting.report_generator import ReportGenerator
from dockaudit.compliance.evaluator import ComplianceEvaluator
from dockaudit.reporting.compliance_report import ComplianceReportGenerator


class Orchestrator:
    def __init__(
        self,
        target="local",
        output_format="html",
        severity="medium",
        sbom_dir="reports/sbom",
        nvd_feed=None,
        compliance_enabled=True,
        container_filter=None,
        image_filter=None
    ):
        self.target = target
        self.output_format = output_format
        self.severity = severity
        self.compliance_enabled = compliance_enabled
        self.container_filter = container_filter
        self.image_filter = image_filter

        self.host_audit = HostAudit(target)
        self.container_audit = ContainerAudit(target, container_filter=container_filter)
        self.image_analysis = ImageAnalysis(
            target,
            sbom_dir=sbom_dir,
            nvd_feed=nvd_feed,
            container_filter=container_filter,
            image_filter=image_filter
        )

        self.report_generator = ReportGenerator(output_format, severity)

    def run_audit(self):
        from datetime import datetime
        self._audit_timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        if self.container_filter:
            self._audit_suffix = self.container_filter.replace("/", "_")
        elif self.image_filter:
            self._audit_suffix = self.image_filter.replace("/", "_").replace(":", "_")
        else:
            self._audit_suffix = "All_Containers"

        print("[*] Iniciando auditoría Docker...")
        
        # Validate container filter if provided
        if self.container_filter:
            try:
                import docker
                client = docker.from_env()
                containers = client.containers.list(all=True)
                matching_containers = [c for c in containers if c.name == self.container_filter or self.container_filter in c.name]

                if not matching_containers:
                    print(f"[ERROR] No container found matching: '{self.container_filter}'")
                    print(f"\nAvailable containers:")
                    for c in containers[:10]:
                        print(f"  - {c.name}")
                    if len(containers) > 10:
                        print(f"  ... and {len(containers) - 10} more")
                    print(f"\nUsage: python3 main.py --container <container_name>")
                    return {}
            except Exception as e:
                print(f"[ERROR] Failed to validate container filter: {e}")
                return {}

        # Validate image filter if provided (no container required)
        if self.image_filter and not self.container_filter:
            try:
                import docker
                client = docker.from_env()
                all_images = client.images.list()
                matching_images = [
                    img for img in all_images
                    if any(self.image_filter in tag for tag in img.tags)
                ]
                if not matching_images:
                    print(f"[ERROR] No image found matching: '{self.image_filter}'")
                    print(f"\nAvailable images:")
                    for img in all_images[:10]:
                        tags = ", ".join(img.tags) if img.tags else "<none>"
                        print(f"  - {tags}")
                    if len(all_images) > 10:
                        print(f"  ... and {len(all_images) - 10} more")
                    print(f"\nUsage: python3 main.py --image <image_name:tag>")
                    return {}
            except Exception as e:
                print(f"[ERROR] Failed to validate image filter: {e}")
                return {}

        results = {
            "host": [],
            "containers": [],
            "images": [],
            "binaries": [],
            "vulnerabilities": [],
            "sbom_path": None,
            "host_audit": {},
            "container_audit": {},
            "image_analysis": {}
        }

        print("[*] Ejecutando auditoría del host...")
        host_results = self.host_audit.run()
        results["host"] = host_results.get("findings", host_results if isinstance(host_results, list) else [])
        results["host_audit"] = host_results if isinstance(host_results, dict) else {"findings": host_results}

        print("[*] Ejecutando auditoría de contenedores...")
        container_results = self.container_audit.run()
        results["containers"] = container_results.get("findings", container_results if isinstance(container_results, list) else [])
        results["container_audit"] = container_results if isinstance(container_results, dict) else {"findings": container_results}

        print("[*] Ejecutando análisis de imágenes...")
        sbom_filename = f"{self._audit_timestamp}_-_SBOM_{self._audit_suffix}.json"
        image_results = self.image_analysis.run(sbom_filename=sbom_filename)
        results["images"] = image_results.get("findings", [])
        results["binaries"] = image_results.get("binary_findings", [])
        results["vulnerabilities"] = image_results.get("vulnerabilities", [])
        results["sbom_path"] = image_results.get("sbom_path")
        results["packages"] = image_results.get("packages", [])
        results["image_analysis"] = image_results

        if self.compliance_enabled:
            print("[*] Evaluando compliance (CIS Docker Benchmark & ISO/IEC 27001)...")
            compliance_evaluator = ComplianceEvaluator(results)
            compliance_findings = compliance_evaluator.evaluate()
            results["compliance"] = compliance_findings
            results["compliance_summary"] = compliance_evaluator.get_summary()
            results["compliance_iso_coverage"] = compliance_evaluator.get_iso_coverage()
            print(f"[+] Compliance evaluation completed: {len(compliance_findings)} controls evaluated")

        print("[*] Auditoría finalizada.")

        return results

    def generate_report(self, results):
        import os

        if not results:
            return

        timestamp = getattr(self, "_audit_timestamp", None)
        suffix = getattr(self, "_audit_suffix", "All_Containers")
        if not timestamp:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        if self.container_filter:
            audit_target = f"Container: {self.container_filter}"
        elif self.image_filter:
            audit_target = f"Image: {self.image_filter}"
        else:
            audit_target = "All Containers"

        print("[*] Generando informe...")
        audit_filename = f"{timestamp}_-_Audit_Report_{suffix}"
        self.report_generator.generate(results, audit_target=audit_target, out_filename=audit_filename)

        if "compliance" in results and results["compliance"]:
            compliance_findings = results["compliance"]
            base_filename = f"{timestamp}_-_Compliance_Report_{suffix}"
            
            compliance_gen = ComplianceReportGenerator(compliance_findings, audit_target=audit_target)
            
            json_report = compliance_gen.to_json(pretty=True)
            json_path = f"reports/{base_filename}.json"
            os.makedirs("reports", exist_ok=True)
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(json_report)
            print(f"[+] Compliance JSON report written to: {json_path}")
            
            html_report = compliance_gen.to_html()
            html_path = f"reports/{base_filename}.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            print(f"[+] Compliance HTML report written to: {html_path}")
            
            summary = results.get("compliance_summary", {})
            if summary:
                print(f"\n=== CIS Docker Benchmark & ISO/IEC 27001 Compliance Summary ===")
                print(f"Total Controls: {summary.get('total_controls', 0)}")
                print(f"Compliant: {summary.get('compliant', 0)}")
                print(f"Non-Compliant: {summary.get('non_compliant', 0)}")
                print(f"Unknown: {summary.get('unknown', 0)}")
                print(f"Compliance Rate: {summary.get('compliance_percentage', 0):.1f}%")
        
        print("[*] Informe generado correctamente.")