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
cd DockAudit-SCA
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Ver `docs/MANUAL.md` para la referencia completa de opciones y ejemplos.

## SBOM and NVD

The tool extracts installed package dependencies from Docker images (dpkg, rpm, apk), generates a CycloneDX 1.4 SBOM, and correlates components against NVD CVE data using a local feed.

### Demo feed (included)

`sample_nvd.json` is included in the repository and contains **15 real CVEs** covering the most common packages found in Docker images: `openssl`, `curl`, `nginx`, `python`, `sudo`, `openssh`, `zlib`, `xz-utils`, `ncurses`, `git`, `libwebp` and `log4j`.

```bash
# Audit a specific container with CVE correlation
python main.py --container <name> --nvd-feed sample_nvd.json

# Audit a pulled image without a running container
python main.py --image nginx:latest --nvd-feed sample_nvd.json
```

### Downloading a full NVD feed

The included script fetches data from the **NVD API 2.0** (the NVD 1.1 JSON feeds were retired by NIST in December 2023). Requires `curl` and `jq`.

```bash
# Download CVEs for 2024 into feeds/ directory
bash scripts/download_nvd_feed.sh 2024 feeds/

# Optional: set an API key for higher rate limits (~50 req/30s vs 5 req/30s)
# Free key at: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=<your-key>
bash scripts/download_nvd_feed.sh 2024 feeds/
```

The script paginates automatically (2 000 CVEs per request) and saves a single JSON file:

```bash
python main.py --nvd-feed feeds/nvdcve-2.0-2024.json
```

## Resultados

- HTML report: `reports/report.html`
- JSON report: `reports/report.json`

## Documentación

- **Manual completo:** [docs/MANUAL.md](docs/MANUAL.md) — arquitectura, módulos, CLI, NVD, compliance, tests y estructura de ficheros.

## Notas

Si Docker no está disponible, el proyecto devuelve hallazgos críticos que describen el problema. Los módulos pueden extenderse para añadir más comprobaciones de imágenes y SBOM.
