# DockAudit-SCA

Prototipo funcional de herramienta de auditoría de seguridad para entornos Docker con análisis de composición software (SCA) integrado y generación de SBOM.

## Objetivos

**Objetivo general:** Desarrollar un prototipo funcional de herramienta de auditoría de seguridad para entornos Docker que permita analizar configuraciones, dependencias software y binarios presentes en imágenes de contenedor, con el fin de identificar vulnerabilidades y proponer medidas de mitigación.

**Objetivos específicos:**

- Analizar la configuración de seguridad del host Docker y del daemon.
- Inspeccionar contenedores e imágenes Docker para identificar configuraciones inseguras.
- Extraer dependencias y paquetes software presentes en imágenes Docker.
- Generar SBOMs en formato CycloneDX 1.4 con identificadores purl estándar.
- Correlacionar dependencias y componentes con vulnerabilidades CVE conocidas mediante feeds NVD descargados localmente.
- Mapear hallazgos al CIS Docker Benchmark 1.6 e ISO/IEC 27001:2022.
- Producir informes estructurados en HTML y JSON.

## Features

- Docker host configuration auditing
- Container runtime security analysis
- Docker image metadata inspection
- Binary analysis of container image contents (SUID/SGID, sensitive files)
- **Static package extraction** via `docker save` (dpkg, apk, distroless) — no code from the audited image is ever executed; rpm images use a hardened fallback (`--network=none --read-only --cap-drop=ALL`)
- CVE correlation against NVD feeds with CPE version-range matching, Debian epoch handling and per-package linkage
- **CVSS v3.1 scoring**: each matched CVE carries its NVD base score, severity and vector
- SBOM generation in CycloneDX 1.4 format with standard **purl** identifiers (`pkg:deb/...`, `pkg:apk/...`)
- CIS Docker Benchmark 1.6 compliance evaluation (55 controls) mapped to ISO/IEC 27001:2022
- Interactive HTML report: sidebar navigation, collapsible findings, CVSS and source-attribution badges, and package inventory table with CVE linkage
- CI/CD integration: `--fail-on <severity>` exits with code 2 when findings reach the threshold; `--skip-host` audits only images/containers
- All output files use a consistent `YYYYMMDD-HHMMSS_-_Type_target.ext` naming convention

## Quick start

```bash
cd DockAudit-SCA
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Ver `docs/MANUAL.md` para la referencia completa de opciones y ejemplos.

## SBOM and NVD

The tool extracts installed package dependencies from Docker images (dpkg, rpm, apk), generates a CycloneDX 1.4 SBOM, and correlates components against NVD CVE data using a local feed.

### Demo feed (included)

`sample_nvd.json` is included in the repository and contains **15 real CVEs** covering the most common packages found in Docker images: `openssl`, `curl`, `nginx`, `python`, `sudo`, `openssh`, `zlib`, `xz-utils`, `ncurses`, `git`, `libwebp` and `log4j`.

```bash
# Audit a specific container with CVE correlation
python3 main.py --container <name> --nvd-feed sample_nvd.json

# Audit a pulled image without a running container
python3 main.py --image nginx:latest --nvd-feed sample_nvd.json
```

### Demo image (included)

`Dockerfile.demo` builds an image with packages matching all 15 CVEs in `sample_nvd.json` plus deliberate security misconfigurations (SUID binaries, secrets in ENV, world-writable paths):

```bash
docker build -t dockaudit-demo -f Dockerfile.demo .
python3 main.py --image dockaudit-demo --nvd-feed sample_nvd.json
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

The script splits the year into 90-day windows (NVD API limit), paginates automatically (2 000 CVEs per request), and saves a single JSON file:

```bash
python3 main.py --nvd-feed feeds/nvdcve-2.0-2024.json
```

### Validación frente a Trivy

`scripts/compare_with_trivy.py` compara los CVEs detectados por DockAudit-SCA con los de [Trivy](https://trivy.dev) sobre la misma imagen, y calcula precisión y recall tomando Trivy como referencia:

```bash
# Generar el informe en JSON y comparar
python3 main.py --image dockaudit-demo --nvd-feed sample_nvd.json --output json
python3 scripts/compare_with_trivy.py --report reports/<ts>_-_Audit_Report_dockaudit-demo.json --image dockaudit-demo
```

## Resultados

Todos los ficheros de salida siguen el patrón `YYYYMMDD-HHMMSS_-_Type_target.ext`:

| Fichero | Descripción |
|---|---|
| `reports/<ts>_-_Audit_Report_<target>.html` | Reporte de auditoría general (HTML interactivo) |
| `reports/<ts>_-_Audit_Report_<target>.json` | Mismo reporte en JSON |
| `reports/<ts>_-_Compliance_Report_<target>.html` | Reporte CIS/ISO 27001 (HTML) |
| `reports/<ts>_-_Compliance_Report_<target>.json` | Reporte CIS/ISO 27001 (JSON) |
| `reports/sbom/<ts>_-_SBOM_<target>.json` | SBOM en formato CycloneDX 1.4 |

## Documentación

- **Manual completo:** [docs/MANUAL.md](docs/MANUAL.md) — arquitectura, módulos, CLI, NVD, compliance, tests y estructura de ficheros.

## Notas

Si Docker no está disponible, el proyecto devuelve hallazgos críticos que describen el problema. Los módulos pueden extenderse para añadir más comprobaciones de imágenes y SBOM.
