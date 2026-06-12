#!/usr/bin/env python3
"""
Compares the CVEs detected by DockAudit-SCA against Trivy for the same image.

Produces detection-overlap metrics (intersection, only-DockAudit, only-Trivy)
that quantify the matcher's precision/recall against a reference scanner.

Usage:
  # Run Trivy automatically (requires trivy in PATH):
  python3 scripts/compare_with_trivy.py --report reports/<audit>.json --image nginx:latest

  # Or compare against a pre-generated Trivy JSON:
  trivy image --format json -o trivy_nginx.json nginx:latest
  python3 scripts/compare_with_trivy.py --report reports/<audit>.json --trivy-json trivy_nginx.json

The DockAudit report must be generated with --output json.
Install Trivy: https://trivy.dev/latest/getting-started/installation/
"""

import argparse
import json
import shutil
import subprocess
import sys


def load_dockaudit_cves(report_path):
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    cves = {}
    for vuln in report.get("vulnerabilities", []):
        cve_id = vuln.get("id", "")
        if cve_id.startswith("CVE-"):
            cves.setdefault(cve_id, set()).add(vuln.get("affected_package", "?"))
    return cves


def load_trivy_cves(trivy_data):
    cves = {}
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = vuln.get("VulnerabilityID", "")
            if cve_id.startswith("CVE-"):
                cves.setdefault(cve_id, set()).add(vuln.get("PkgName", "?"))
    return cves


def run_trivy(image):
    if not shutil.which("trivy"):
        sys.exit(
            "ERROR: trivy no está en el PATH y no se proporcionó --trivy-json.\n"
            "Instalación: https://trivy.dev/latest/getting-started/installation/"
        )
    print(f"[*] Ejecutando trivy image {image} (puede tardar la primera vez)...")
    result = subprocess.run(
        ["trivy", "image", "--format", "json", "--quiet", image],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.exit(f"ERROR: trivy falló:\n{result.stderr}")
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description="Compara CVEs de DockAudit-SCA con Trivy")
    parser.add_argument("--report", required=True, help="Informe JSON de DockAudit (--output json)")
    parser.add_argument("--image", help="Imagen a escanear con Trivy (p.ej. nginx:latest)")
    parser.add_argument("--trivy-json", help="JSON de Trivy pregenerado (alternativa a --image)")
    args = parser.parse_args()

    if not args.image and not args.trivy_json:
        parser.error("se requiere --image o --trivy-json")

    dockaudit_cves = load_dockaudit_cves(args.report)

    if args.trivy_json:
        with open(args.trivy_json, encoding="utf-8") as f:
            trivy_data = json.load(f)
    else:
        trivy_data = run_trivy(args.image)
    trivy_cves = load_trivy_cves(trivy_data)

    da_set = set(dockaudit_cves)
    tv_set = set(trivy_cves)
    both = da_set & tv_set
    only_da = da_set - tv_set
    only_tv = tv_set - da_set

    # Treating Trivy as ground truth:
    precision = len(both) / len(da_set) if da_set else 0.0
    recall = len(both) / len(tv_set) if tv_set else 0.0

    print("\n=== Comparativa DockAudit-SCA vs Trivy ===")
    print(f"CVEs DockAudit:        {len(da_set)}")
    print(f"CVEs Trivy:            {len(tv_set)}")
    print(f"Detectados por ambos:  {len(both)}")
    print(f"Solo DockAudit:        {len(only_da)}  (posibles falsos positivos)")
    print(f"Solo Trivy:            {len(only_tv)}  (posibles falsos negativos)")
    print(f"Precisión (vs Trivy):  {precision:.1%}")
    print(f"Recall    (vs Trivy):  {recall:.1%}")

    def show(title, cve_ids, source):
        if not cve_ids:
            return
        print(f"\n--- {title} ---")
        for cve_id in sorted(cve_ids):
            packages = ", ".join(sorted(source.get(cve_id, {"?"})))
            print(f"  {cve_id}  ({packages})")

    show("Detectados por ambos", both, dockaudit_cves)
    show("Solo DockAudit", only_da, dockaudit_cves)
    show("Solo Trivy", only_tv, trivy_cves)


if __name__ == "__main__":
    main()
