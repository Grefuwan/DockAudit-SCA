# DockAudit-SCA

Security auditing tool for Docker environments with integrated Software Composition Analysis (SCA) and SBOM generation.

## Features

- Docker host configuration auditing
- Container runtime security analysis
- Docker image metadata inspection
- Binary analysis of container image contents
- Package dependency extraction from Docker images (dpkg, rpm, apk)
- Risk-based finding classification and SBOM/NVD correlation
- HTML and JSON report generation

## Quick start

```bash
cd /home/jgv/Documentos/TFM_-_Docker/DockAudit-SCA
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py --target local --output html
```

## SBOM and NVD

The tool now extracts installed package dependencies from Docker images using common package managers (dpkg, rpm, apk), performs binary content analysis, scores findings by risk level, and correlates them with NVD vulnerabilities.

```bash
python main.py --target local --output html --sbom-dir reports/sbom --nvd-feed /path/to/nvdcve-1.1-2024.json.gz
```

## Resultados

- HTML report: `reports/report.html`
- JSON report: `reports/report.json`

## Notas

Si Docker no está disponible, el proyecto devuelve hallazgos críticos que describen el problema. Los módulos pueden extenderse para añadir más comprobaciones de imágenes y SBOM.
