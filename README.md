# DockAudit-SCA

Security auditing tool for Docker environments with integrated Software Composition Analysis (SCA) and SBOM generation.

## Objetivos

### 1.2.1. Objetivo general

Desarrollar un sistema de auditoría de seguridad para entornos Docker que permita analizar configuraciones, dependencias software y binarios presentes en imágenes de contenedor, con el fin de identificar vulnerabilidades y proponer medidas de mitigación.

### 1.2.2. Objetivos específicos

- Analizar la arquitectura de seguridad de Docker y los mecanismos de aislamiento utilizados en entornos de contenedores.
- Diseñar la arquitectura de un sistema de auditoría orientado al análisis de seguridad de contenedores e imágenes Docker.
- Implementar un sistema de análisis de composición software (Software Composition Analysis, SCA) capaz de identificar dependencias y componentes incluidos en imágenes de contenedor.
- Generar un Software Bill of Materials (SBOM) que describa los componentes software presentes en las imágenes analizadas.
- Realizar análisis de binarios presentes en imágenes de contenedor para detectar posibles vulnerabilidades o configuraciones inseguras.
- Evaluar configuraciones de seguridad del entorno Docker, incluyendo privilegios de contenedores, capacidades del kernel, políticas de aislamiento y configuraciones de red.
- Diseñar un sistema de evaluación de riesgos que permita clasificar los hallazgos de seguridad según su criticidad.
- Proponer medidas de hardening y buenas prácticas de seguridad para mejorar la protección de entornos Docker.

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

Ver: [PROJECT_STATE.md](PROJECT_STATE.md) para más comandos y opciones.

## SBOM and NVD

The tool now extracts installed package dependencies from Docker images using common package managers (dpkg, rpm, apk), performs binary content analysis, scores findings by risk level, and correlates them with NVD vulnerabilities.

Use a local NVD JSON/GZ feed to match package components to vulnerabilities:

```bash
python main.py --target local --output html --sbom-dir reports/sbom --nvd-feed sample_nvd.json
```

A sample feed is available in `sample_nvd.json` for demo purposes.

To download a real official NVD feed, run:

```bash
bash scripts/download_nvd_feed.sh 2024 feeds
```

Then use the downloaded file:

```bash
python main.py --target local --output html --sbom-dir reports/sbom --nvd-feed feeds/nvdcve-1.1-2024.json.gz
```

## Resultados

- HTML report: `reports/report.html`
- JSON report: `reports/report.json`

## Documentación adicional

- 📋 **Estado Actual del Proyecto:** [PROJECT_STATE.md](PROJECT_STATE.md) - Resumen completo, métricas, arquitectura
- 🏗️ **Arquitectura:** [docs/architecture.md](docs/architecture.md)
- 🔍 **NVD Methodology:** [docs/nvd.md](docs/nvd.md)
- 🔐 **Compliance Mapping (CIS ↔ ISO 27001):** [docs/compliance_mapping.md](docs/compliance_mapping.md)
- 📘 **Compliance Guide (Guía Práctica):** [COMPLIANCE_GUIDE.md](COMPLIANCE_GUIDE.md)

## Notas

Si Docker no está disponible, el proyecto devuelve hallazgos críticos que describen el problema. Los módulos pueden extenderse para añadir más comprobaciones de imágenes y SBOM.
