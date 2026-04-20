
from dockaudit.host_audit.host_scanner import HostAudit
from dockaudit.container_audit.container_scanner import ContainerAudit
from dockaudit.image_analysis.image_scanner import ImageAnalysis
from dockaudit.reporting.report_generator import ReportGenerator


class Orchestrator:
    def __init__(self, target="local", output_format="html", severity="medium"):
        self.target = target
        self.output_format = output_format
        self.severity = severity

        # Inicialización de módulos
        self.host_audit = HostAudit(target)
        self.container_audit = ContainerAudit(target)
        self.image_analysis = ImageAnalysis(target)

        self.report_generator = ReportGenerator(output_format, severity)

    def run_audit(self):
        print("[*] Iniciando auditoría Docker...")

        results = {
            "host": [],
            "containers": [],
            "images": []
        }

        # Ejecutar auditoría de host
        print("[*] Ejecutando auditoría del host...")
        results["host"] = self.host_audit.run()

        # Ejecutar auditoría de contenedores
        print("[*] Ejecutando auditoría de contenedores...")
        results["containers"] = self.container_audit.run()

        # Ejecutar análisis de imágenes
        print("[*] Ejecutando análisis de imágenes...")
        results["images"] = self.image_analysis.run()

        print("[*] Auditoría finalizada.")

        return results

    def generate_report(self, results):
        print("[*] Generando informe...")
        self.report_generator.generate(results)
        print("[*] Informe generado correctamente.")