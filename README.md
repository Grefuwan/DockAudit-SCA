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

## Características

- Auditoría de la configuración del host Docker y del daemon
- Análisis de seguridad de contenedores en ejecución
- Inspección de metadatos de imágenes Docker
- Análisis de binarios en imágenes (SUID/SGID, ficheros sensibles)
- **Extracción estática de paquetes** mediante `docker save` (dpkg, apk, distroless) — no se ejecuta ningún código de la imagen auditada; las imágenes RPM usan un contenedor efímero endurecido (`--network=none --read-only --cap-drop=ALL`)
- Correlación de CVEs contra feeds NVD con soporte de rangos de versión CPE, épocas Debian y atribución por paquete
- **Puntuación CVSS v3.1**: cada CVE detectado incluye puntuación base, severidad y vector NVD
- Generación de SBOM en formato CycloneDX 1.4 con identificadores **purl** estándar (`pkg:deb/...`, `pkg:apk/...`)
- Evaluación de cumplimiento del CIS Docker Benchmark 1.6 (55 controles) mapeados a ISO/IEC 27001:2022
- Informe HTML interactivo: navegación lateral, hallazgos colapsables, badges de severidad y origen, inventario de paquetes con enlace a CVEs
- Integración CI/CD: `--fail-on <severidad>` sale con código 2 si los hallazgos superan el umbral; `--skip-host` audita solo imágenes/contenedores
- Todos los ficheros de salida siguen el patrón `YYYYMMDD-HHMMSS_-_Tipo_objetivo.ext`

## Inicio rápido

```bash
cd DockAudit-SCA
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Ver `docs/MANUAL.md` para la referencia completa de opciones y ejemplos.

## SBOM y NVD

La herramienta extrae las dependencias instaladas en imágenes Docker (dpkg, rpm, apk), genera un SBOM en formato CycloneDX 1.4 y correlaciona los componentes con datos CVE de la NVD usando un feed local.

### Feed de demo (incluido)

`sample_nvd.json` está incluido en el repositorio y contiene **15 CVEs reales** de los paquetes más habituales en imágenes Docker: `openssl`, `curl`, `nginx`, `python`, `sudo`, `openssh`, `zlib`, `xz-utils`, `ncurses`, `git`, `libwebp` y `log4j`.

```bash
# Auditar un contenedor específico con correlación CVE
python3 main.py --container <nombre> --nvd-feed sample_nvd.json

# Auditar una imagen descargada sin contenedor en ejecución
python3 main.py --image nginx:latest --nvd-feed sample_nvd.json
```

### Imagen de demo (incluida)

`Dockerfile.demo` construye una imagen con los paquetes correspondientes a los 15 CVEs de `sample_nvd.json`, además de configuraciones deliberadamente inseguras (binarios SUID, secretos en variables de entorno, rutas con escritura universal):

```bash
docker build -t dockaudit-demo -f Dockerfile.demo .
python3 main.py --image dockaudit-demo --nvd-feed sample_nvd.json
```

### Descarga de un feed NVD completo

El script incluido descarga datos de la **NVD API 2.0** (los feeds NVD 1.1 fueron retirados por NIST en diciembre de 2023). Requiere `curl` y `jq`.

```bash
# Descargar CVEs del año 2024 en el directorio feeds/
bash scripts/download_nvd_feed.sh 2024 feeds/

# Opcional: clave API para mayor límite de peticiones (~50 req/30s en lugar de 5 req/30s)
# Clave gratuita en: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=<tu-clave>
bash scripts/download_nvd_feed.sh 2024 feeds/
```

El script divide el año en ventanas de 90 días (límite máximo de la NVD API), pagina automáticamente (2 000 CVEs por petición) y genera un único fichero JSON:

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

Si Docker no está disponible, la herramienta devuelve hallazgos críticos que describen el problema. La arquitectura modular permite extender el prototipo con nuevas comprobaciones de imágenes y fuentes de vulnerabilidades adicionales.
