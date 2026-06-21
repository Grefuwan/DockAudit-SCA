import argparse
import logging
import sys
from dockaudit.orchestrator.orchestrator import Orchestrator
from dockaudit.utils.logger import setup_logging

logger = logging.getLogger(__name__)


def check_docker_available(target="local"):
    if target != "local":
        return True

    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except ModuleNotFoundError:
        logger.error("Docker SDK no está instalado. Ejecuta `pip install -r requirements.txt`.")
        return False
    except Exception as e:
        logger.error("No se puede conectar al daemon Docker: %s", e)
        return False


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="DockAudit-SCA - Sistema de auditoría Docker basado en SBOM"
    )

    parser.add_argument(
        "--target",
        type=str,
        default="local",
        help="Objetivo de auditoría (local, remoto, etc.)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="html",
        help="Formato del informe (html, json)"
    )

    parser.add_argument(
        "--severity",
        type=str,
        default="medium",
        help="Nivel mínimo de severidad a mostrar"
    )

    parser.add_argument(
        "--sbom-dir",
        type=str,
        default="reports/sbom",
        help="Directorio de salida para archivos SBOM"
    )

    parser.add_argument(
        "--nvd-feed",
        type=str,
        default="",
        help="Ruta al archivo de feed NVD JSON o JSON.GZ"
    )

    parser.add_argument(
        "--container",
        type=str,
        default=None,
        help="Nombre del contenedor específico a auditar (opcional, por defecto audita todos)"
    )

    parser.add_argument(
        "--image",
        type=str,
        default=None,
        help="Nombre/tag de la imagen Docker a auditar (p.ej. 'nginx:latest'). No requiere contenedor desplegado."
    )

    parser.add_argument(
        "--skip-host",
        action="store_true",
        help="Omite la auditoría del host Docker (útil para auditar solo imágenes/contenedores)"
    )

    parser.add_argument(
        "--fail-on",
        type=str,
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Sale con código 2 si hay hallazgos con severidad igual o superior a la indicada (integración CI/CD)"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    return parser.parse_args()


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def max_severity_reached(results, threshold):
    """Returns True if any finding meets or exceeds the severity threshold."""
    if threshold == "none":
        return False
    threshold_level = SEVERITY_ORDER[threshold]
    for section in ("host", "containers", "images", "binaries", "vulnerabilities"):
        for finding in results.get(section, []) or []:
            severity = str(finding.get("severity", "info")).lower()
            if SEVERITY_ORDER.get(severity, 0) >= threshold_level:
                return True
    return False


def main():
    import os
    from datetime import datetime

    args = parse_arguments()

    log_dir = "reports/logs"
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = os.path.join(log_dir, f"{timestamp}_-_audit.log")

    setup_logging(debug=args.debug, log_file=log_file)

    if not check_docker_available(args.target):
        logger.error("Docker es necesario para ejecutar la auditoría local. Instala el daemon y asegúrate de que /var/run/docker.sock sea accesible.")
        sys.exit(1)

    orchestrator = Orchestrator(
        target=args.target,
        output_format=args.output,
        severity=args.severity,
        sbom_dir=args.sbom_dir,
        nvd_feed=args.nvd_feed or None,
        container_filter=args.container,
        image_filter=args.image,
        skip_host=args.skip_host
    )

    results = orchestrator.run_audit()

    # Only generate report if audit was successful
    if results and results.get("host") is not None:
        orchestrator.generate_report(results)
    else:
        logger.warning("Auditoría abortada. No se generaron reportes.")
        sys.exit(1)

    if max_severity_reached(results, args.fail_on):
        logger.warning("Hallazgos con severidad >= %s detectados (--fail-on). Código de salida: 2", args.fail_on)
        sys.exit(2)


if __name__ == "__main__":
    main()