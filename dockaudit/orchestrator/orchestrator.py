
from dockaudit.host_audit.host_scanner import HostAudit
from dockaudit.container_audit.container_scanner import ContainerAudit
from dockaudit.image_analysis.image_scanner import ImageAnalysis
from dockaudit.reporting.report_generator import ReportGenerator


class Orchestrator:
    def __init__(
        self,
        target="local",
        output_format="html",
        severity="medium",
        sbom_dir="reports/sbom",
        nvd_feed=None
    ):
        self.target = target
        self.output_format = output_format
        self.severity = severity

        # Inicialización de módulos
        self.host_audit = HostAudit(target)
        self.container_audit = ContainerAudit(target)
        self.image_analysis = ImageAnalysis(target, sbom_dir=sbom_dir, nvd_feed=nvd_feed)

        self.report_generator = ReportGenerator(output_format, severity)

    def run_audit(self):
        print("[*] Iniciando auditoría Docker...")

        results = {
            "host": [],
            "containers": [],
            "images": [],
            "binaries": []
        }

        # Ejecutar auditoría de host
        print("[*] Ejecutando auditoría del host...")
        results["host"] = self.host_audit.run()

        # Ejecutar auditoría de contenedores
        print("[*] Ejecutando auditoría de contenedores...")
        results["containers"] = self.container_audit.run()

        # Ejecutar análisis de imágenes
        print("[*] Ejecutando análisis de imágenes...")
        image_results = self.image_analysis.run()
        results["images"] = image_results.get("findings", [])
        results["binaries"] = image_results.get("binary_findings", [])
        results["vulnerabilities"] = image_results.get("vulnerabilities", [])
        results["sbom_path"] = image_results.get("sbom_path")

        print("[*] Auditoría finalizada.")

        return results

    def generate_report(self, results):
        print("[*] Generando informe...")
        self.report_generator.generate(results)
        print("[*] Informe generado correctamente.")