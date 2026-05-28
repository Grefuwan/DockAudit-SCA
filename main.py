import argparse
import sys
from dockaudit.orchestrator.orchestrator import Orchestrator


def check_docker_available(target="local"):
    if target != "local":
        return True

    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except ModuleNotFoundError:
        print("[ERROR] Docker SDK no está instalado. Ejecuta `pip install -r requirements.txt`.")
        return False
    except Exception as e:
        print(f"[ERROR] No se puede conectar al daemon Docker: {e}")
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

    return parser.parse_args()


def main():
    args = parse_arguments()

    if not check_docker_available(args.target):
        print("Docker es necesario para ejecutar la auditoría local. Instala el daemon y asegúrate de que /var/run/docker.sock sea accesible.")
        sys.exit(1)

    orchestrator = Orchestrator(
        target=args.target,
        output_format=args.output,
        severity=args.severity,
        sbom_dir=args.sbom_dir,
        nvd_feed=args.nvd_feed or None,
        container_filter=args.container,
        image_filter=args.image
    )

    results = orchestrator.run_audit()
    
    # Only generate report if audit was successful
    if results and results.get("host") is not None:
        orchestrator.generate_report(results)
    else:
        print("[*] Auditoría abortada. No se generaron reportes.")
        sys.exit(1)


if __name__ == "__main__":
    main()