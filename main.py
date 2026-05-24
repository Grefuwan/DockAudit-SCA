import argparse
from dockaudit.orchestrator.orchestrator import Orchestrator


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

    return parser.parse_args()


def main():
    args = parse_arguments()

    orchestrator = Orchestrator(
        target=args.target,
        output_format=args.output,
        severity=args.severity,
        sbom_dir=args.sbom_dir,
        nvd_feed=args.nvd_feed or None
    )

    results = orchestrator.run_audit()
    orchestrator.generate_report(results)


if __name__ == "__main__":
    main()