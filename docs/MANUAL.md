# DockAudit-SCA — Manual de la herramienta

**Versión:** 0.2.0  
**Estándares:** CIS Docker Benchmark 1.6 · ISO/IEC 27001:2022  
**Lenguaje:** Python 3.11+

---

## Índice

1. [Descripción general](#1-descripción-general)
2. [Requisitos e instalación](#2-requisitos-e-instalación)
3. [Uso desde línea de comandos](#3-uso-desde-línea-de-comandos)
4. [Arquitectura del sistema](#4-arquitectura-del-sistema)
5. [Módulos](#5-módulos)
6. [Análisis de compliance CIS / ISO 27001](#6-análisis-de-compliance-cis--iso-27001)
7. [Análisis de vulnerabilidades NVD](#7-análisis-de-vulnerabilidades-nvd)
8. [Reportes generados](#8-reportes-generados)
9. [Suite de tests](#9-suite-de-tests)
10. [Estructura de ficheros](#10-estructura-de-ficheros)
11. [Cobertura de controles CIS](#11-cobertura-de-controles-cis)

---

## 1. Descripción general

DockAudit-SCA es un prototipo funcional de herramienta de auditoría de seguridad para entornos Docker, desarrollado como Trabajo Fin de Máster. Analiza tres capas del entorno:

- **Host Docker**: configuración del daemon, permisos, políticas de seguridad del sistema.
- **Contenedores**: configuración de ejecución (modo privilegiado, capacidades del kernel, volúmenes, red).
- **Imágenes**: paquetes instalados, binarios SUID, variables de entorno con secretos, vulnerabilidades conocidas.

Adicionalmente evalúa el cumplimiento normativo contra el **CIS Docker Benchmark 1.6** (55 controles) mapeado al **Anexo A de ISO/IEC 27001:2022**, y genera una SBOM en formato CycloneDX 1.4.

### Objetivos del TFM cubiertos

| Objetivo | Módulo responsable |
|---|---|
| Analizar arquitectura de seguridad de Docker | `host_audit`, `container_audit` |
| Implementar SCA (Software Composition Analysis) | `image_analysis`, `sca` |
| Generar SBOM estándar | `image_analysis.sbom_generator` |
| Analizar binarios en imágenes | `image_analysis.binary_analyzer` |
| Evaluar configuraciones de seguridad Docker | `compliance.evaluator` |
| Clasificar hallazgos por criticidad | `reporting` |
| Proponer medidas de hardening | Campos `remediation` en todos los módulos |

---

## 2. Requisitos e instalación

### Requisitos previos

- Python 3.11 o superior
- Docker Engine en ejecución y socket accesible (`/var/run/docker.sock`)
- Permisos suficientes para ejecutar comandos Docker (usuario en grupo `docker` o `root`)

### Instalación

```bash
cd DockAudit-SCA
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Dependencias principales

| Paquete | Versión | Uso |
|---|---|---|
| `docker` | 7.1.0 | Docker SDK para Python |
| `Jinja2` | 3.1.6 | Plantillas HTML del reporte principal |
| `requests` | 2.33.1 | Descarga de recursos externos |
| `pytest` | 9.0.3 | Ejecución de tests |

---

## 3. Uso desde línea de comandos

### Sintaxis

```
python3 main.py [opciones]
```

### Opciones disponibles

| Opción | Valor por defecto | Descripción |
|---|---|---|
| `--output` | `html` | Formato del reporte principal (`html` o `json`) |
| `--severity` | `medium` | Severidad mínima a mostrar (`info`, `low`, `medium`, `high`, `critical`) |
| `--sbom-dir` | `reports/sbom` | Directorio de salida para los archivos SBOM |
| `--nvd-feed` | _(vacío)_ | Ruta al feed NVD local (`.json` o `.json.gz`) |
| `--container` | _(ninguno)_ | Nombre del contenedor a auditar (filtra contenedor e imagen asociada) |
| `--image` | _(ninguno)_ | Nombre/tag de una imagen a auditar sin necesidad de contenedor desplegado |
| `--skip-host` | _(desactivado)_ | Omite la auditoría del host (útil para auditar solo imágenes/contenedores) |
| `--fail-on` | `none` | Sale con código 2 si hay hallazgos de severidad igual o superior (`low`, `medium`, `high`, `critical`). Pensado para integración en pipelines CI/CD |
| `--debug` | _(desactivado)_ | Activa el nivel de log DEBUG en la consola (el fichero de log siempre registra nivel DEBUG) |

### Ejemplos de uso

```bash
# Auditoría completa del host y todos los contenedores e imágenes locales
python3 main.py

# Auditar un contenedor específico (filtra también su imagen)
python3 main.py --container dvwa

# Auditar una imagen pulleada pero sin contenedor desplegado
python3 main.py --image nginx:latest

# Auditoría con el feed de demo incluido (15 CVEs reales)
python3 main.py --nvd-feed feeds/NVD_Sample_-_80.json

# Auditoría con feed NVD completo descargado
python3 main.py --nvd-feed feeds/nvdcve-2.0-2024.json

# Auditoría filtrando hallazgos de severidad alta o crítica
python3 main.py --severity high

# Auditoría con salida en JSON
python3 main.py --output json

# Solo imágenes/contenedores, sin auditoría del host
python3 main.py --skip-host --image nginx:latest

# Integración CI/CD: falla (exit 2) si hay hallazgos high o critical
python3 main.py --nvd-feed feeds/nvdcve-2.0-2024.json --fail-on high
```

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Auditoría completada sin superar el umbral de `--fail-on` |
| `1` | Error de ejecución (daemon inaccesible, filtro inválido...) |
| `2` | Hallazgos con severidad >= umbral de `--fail-on` |

### Comportamiento de los filtros `--container` e `--image`

- `--container NAME`: el orquestador valida primero que exista un contenedor con ese nombre (en ejecución o detenido). Si no existe, muestra la lista de contenedores disponibles y aborta. Si existe, audita el contenedor y la imagen que utiliza.
- `--image TAG`: el orquestador valida que la imagen exista localmente. Si no existe, muestra las imágenes disponibles y aborta. Solo analiza la imagen — no requiere contenedor desplegado.
- Ambas opciones son mutuamente excluyentes en la práctica; `--container` tiene precedencia si se usan juntas.

### Salida esperada en consola

```
20260621-143022_-_orchestrator.py_-_run_audit_-_INFO: Iniciando auditoría Docker...
20260621-143022_-_orchestrator.py_-_run_audit_-_INFO: Ejecutando auditoría del host...
20260621-143022_-_orchestrator.py_-_run_audit_-_INFO: Ejecutando auditoría de contenedores...
20260621-143022_-_orchestrator.py_-_run_audit_-_INFO: Ejecutando análisis de imágenes...
20260621-143022_-_sbom_generator.py_-_generate_-_INFO: SBOM written to: reports/sbom/20260621-143022_-_SBOM_<target>.json
20260621-143022_-_orchestrator.py_-_run_audit_-_INFO: Evaluando compliance (CIS Docker Benchmark & ISO/IEC 27001)...
20260621-143022_-_evaluator.py_-_evaluate_-_INFO: Compliance evaluation completed: 55 controls evaluated
20260621-143022_-_orchestrator.py_-_run_audit_-_INFO: Auditoría finalizada.
20260621-143022_-_orchestrator.py_-_run_audit_-_INFO: Generando informe...
20260621-143022_-_report_generator.py_-_to_html_-_INFO: HTML report written to: reports/20260621-143022_-_Audit_Report_<target>.html
20260621-143022_-_report_generator.py_-_to_json_-_INFO: Compliance JSON report written to: reports/20260621-143022_-_Compliance_Report_<target>.json
20260621-143022_-_report_generator.py_-_to_html_-_INFO: Compliance HTML report written to: reports/20260621-143022_-_Compliance_Report_<target>.html

=== CIS Docker Benchmark & ISO/IEC 27001 Compliance Summary ===
Total Controls: 55
Compliant: X
Non-Compliant: X
Unknown: X
Compliance Rate: X.X%
```

### Nomenclatura de ficheros de salida

Todos los ficheros generados siguen el patrón:

```
YYYYMMDD-HHMMSS_-_Tipo_objetivo.ext
```

| Invocación | Sufijo `<objetivo>` |
|---|---|
| Sin filtro | `All_Containers` |
| `--container dvwa` | `dvwa` |
| `--image nginx:latest` | `nginx_latest` |

Esto garantiza que ejecuciones sucesivas no sobreescriban los resultados anteriores.

| Tipo de fichero | Descripción |
|---|---|
| `reports/logs/<ts>_-_audit.log` | Log completo de la ejecución (DEBUG+) — generado siempre |

---

## 4. Arquitectura del sistema

### Visión general

```
main.py
  └── Orchestrator
        ├── HostAudit          → auditoría del daemon Docker (host)
        ├── ContainerAudit     → auditoría de contenedores en ejecución
        ├── ImageAnalysis      → análisis de imágenes Docker
        │     ├── PackageExtractor   → extracción de paquetes (dpkg/rpm/apk)
        │     ├── BinaryAnalyzer     → binarios SUID/SGID y ficheros sensibles
        │     ├── SBOMGenerator      → generación SBOM CycloneDX 1.4
        │     ├── NVDParser          → parseo de feeds NVD
        │     └── VulnerabilityMatcher → correlación paquetes ↔ CVEs
        ├── ComplianceEvaluator → evaluación CIS 1.6 ↔ ISO 27001
        ├── ReportGenerator     → reporte de auditoría (HTML/JSON)
        └── ComplianceReportGenerator → reporte de compliance (HTML/JSON)
```

### Flujo de ejecución

```
1. Validación del entorno (Docker disponible, filtros válidos)
       ↓
2. Host Audit
   └─ Versión Docker, usuario del daemon, AppArmor/SELinux, daemon.json
       ↓
3. Container Audit
   └─ Para cada contenedor (filtrado si se usa --container):
      · Modo privilegiado, usuario de ejecución
      · Linux capabilities (--cap-add / --cap-drop)
      · Variables de entorno con secretos
      · Volúmenes montados, modo de red
       ↓
4. Image Analysis
   └─ Para cada imagen (de contenedor si --container, por tag si --image, todas si sin filtro):
      · PackageExtractor: dpkg/rpm/apk → lista de paquetes
      · BinaryAnalyzer: binarios SUID/SGID, ficheros sensibles
      · SBOMGenerator: SBOM CycloneDX 1.4 en reports/sbom/<timestamp>_-_SBOM_<target>.json
      · NVDParser + VulnerabilityMatcher: correlación con CVEs (si --nvd-feed)
       ↓
5. Compliance Evaluation
   └─ 55 controles CIS evaluados sobre los resultados anteriores
      · Estado: compliant / non_compliant / unknown
      · Mapeo a controles ISO 27001:2022 Anexo A
       ↓
6. Report Generation
   └─ reports/<timestamp>_-_Audit_Report_<target>.html (o .json)
      reports/<timestamp>_-_Compliance_Report_<target>.html
      reports/<timestamp>_-_Compliance_Report_<target>.json
```

### Gestión del `audit_target`

El campo `audit_target` se construye en el orquestador y se propaga a los dos generadores de reportes:

| Invocación | Valor de `audit_target` |
|---|---|
| Sin filtro | `All Containers` |
| `--container dvwa` | `Container: dvwa` |
| `--image nginx:latest` | `Image: nginx:latest` |

Este valor aparece en la cabecera de ambos reportes (HTML y JSON).

---

## 5. Módulos

### 5.1 `host_audit` — Auditoría del host

**Fichero:** `dockaudit/host_audit/host_scanner.py`

Comprueba la configuración del daemon Docker y el estado del sistema host:

- Versión de Docker Engine instalada.
- Usuario bajo el que corre el daemon (debe ser no-root).
- Presencia y configuración de `daemon.json`.
- Estado de AppArmor y SELinux.
- Permisos del socket `/var/run/docker.sock`.
- Estado de Docker Swarm.

Los hallazgos se etiquetan con severidad (`info`, `medium`, `high`, `critical`).

### 5.2 `container_audit` — Auditoría de contenedores

**Fichero:** `dockaudit/container_audit/container_scanner.py`

Para cada contenedor (filtrado o todos):

- Detecta modo `--privileged`.
- Verifica que el usuario de ejecución no sea `root`.
- Analiza `CapAdd` (capacidades añadidas peligrosas: `SYS_ADMIN`, `NET_ADMIN`, etc.).
- Detecta variables de entorno con nombres sensibles (`PASSWORD`, `SECRET`, `TOKEN`, `KEY`).
- Revisa el modo de red (`host` network es un hallazgo).
- Comprueba montajes de volúmenes sensibles (`/etc`, `/var/run/docker.sock`, `/`).

Acepta parámetro `container_filter` para limitar el análisis a un contenedor específico.

### 5.3 `image_analysis` — Análisis de imágenes

**Fichero principal:** `dockaudit/image_analysis/image_scanner.py`

Coordina el análisis de imágenes. Admite tres modos:

- `container_filter` definido: analiza solo la imagen del contenedor especificado.
- `image_filter` definido: analiza la imagen cuyo tag coincida (sin necesidad de contenedor).
- Sin filtro: analiza todas las imágenes locales.

#### PackageExtractor (`package_extractor.py`)

La estrategia principal es **análisis estático**: exporta el sistema de ficheros de la imagen con `docker save` y parsea directamente las bases de datos de paquetes, **sin ejecutar nunca código de la imagen auditada**:

```
var/lib/dpkg/status        # Debian/Ubuntu
var/lib/dpkg/status.d/     # imágenes distroless de Google
lib/apk/db/installed       # Alpine
```

Las bases de datos RPM son binarias (BerkeleyDB/SQLite con cabeceras propias de rpm), por lo que las imágenes Red Hat/CentOS recurren a un **fallback endurecido**: un `docker run` efímero con `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=256m`, que mitiga el riesgo de ejecutar código de una imagen potencialmente maliciosa.

El timeout se aplica como tiempo real de ejecución del subproceso (por defecto 120 s). Si no se detecta gestor de paquetes (imagen distroless sin metadatos, scratch...), registra un hallazgo `medium`.

Cada paquete extraído incluye el campo `image` con el tag de la imagen de origen, lo que permite trazar cada paquete hasta su imagen en el reporte.

#### BinaryAnalyzer (`binary_analyzer.py`)

Detecta dentro de la imagen:

- Binarios con bit SUID o SGID activo.
- Ficheros sensibles expuestos (`.env`, `id_rsa`, `credentials.json`, etc.).

#### SBOMGenerator (`sbom_generator.py`)

Genera un SBOM en formato **CycloneDX 1.4** (JSON) en `reports/sbom/<timestamp>_-_SBOM_<target>.json`. Incluye:

- Metadatos del componente (nombre, versión, tipo, gestor de paquetes).
- Identificador **purl** (Package URL) por componente: `pkg:deb/bash@5.1-2`, `pkg:apk/musl@1.2.4-r2`, `pkg:docker/nginx@<id>`. El purl es el identificador estándar que permite a otros escáneres (Grype, Dependency-Track) consumir el SBOM directamente.
- Propiedad `source-image` con el tag de la imagen de origen de cada paquete.
- Lista de `components` compatible con herramientas de terceros.

### 5.4 `sca` — Software Composition Analysis

#### NVDParser (`sca/nvd_parser.py`)

Carga un feed NVD en formato JSON o JSON.GZ generado por la **NVD API 2.0** (los feeds 1.1 fueron retirados por NIST en diciembre de 2023). Extrae para cada entrada:

- ID del CVE.
- Descripción en inglés.
- Lista de `cpeMatch` (CPE 2.3) afectados, **incluyendo los rangos de versión** (`versionStartIncluding`, `versionEndExcluding`, etc.).
- Métricas **CVSS** (v3.1 con preferencia, luego v3.0 y v2): puntuación base, severidad y vector.

#### VulnerabilityMatcher (`sca/vulnerability_matcher.py`)

Correlaciona los paquetes extraídos con las entradas NVD usando:

1. **Nombre**: el producto del CPE debe coincidir exactamente con el nombre del paquete o con una de sus variantes normalizadas (`libssl3` genera los candidatos `ssl3`, `libssl`, `ssl`; se eliminan sufijos como `-dev` o `-common`). Se evita deliberadamente el matching por subcadena, que producía falsos positivos (producto `sh` coincidía con el paquete `bash`).
2. **Versión**: comparación numérica de tuplas de versión, con soporte de épocas Debian (`1:1.34+dfsg-1.2` → `1.34`) y de los **rangos de versión** del feed: un CPE con `versionEndExcluding: 1.2.14` coincide con `zlib 1.2.13` pero no con `1.2.14`.

Cada CVE devuelto incluye `cvss_score`, `cvss_severity` y `cvss_vector`; la severidad del hallazgo se toma directamente del CVSS del NVD (si el CVE aún no tiene análisis CVSS, se asigna `medium`).

### 5.5 `compliance` — Evaluación de compliance

Ver sección [6](#6-análisis-de-compliance-cis--iso-27001).

### 5.6 `reporting` — Generación de reportes

Ver sección [8](#8-reportes-generados).

Cada hallazgo incluye los campos `source` (nombre del contenedor, tag de imagen o nombre del paquete) y `source_type` (`host`, `container`, `image`, `package`). El reporte HTML los muestra como badges de color junto al título de cada hallazgo.

### 5.7 `orchestrator` — Coordinador

**Fichero:** `dockaudit/orchestrator/orchestrator.py`

Inicializa todos los módulos, gestiona el orden de ejecución y agrega los resultados en un único diccionario que se pasa a los generadores de reportes. Parámetros aceptados:

| Parámetro | Tipo | Descripción |
|---|---|---|
| `target` | str | Destino de auditoría (default `"local"`) |
| `output_format` | str | `"html"` o `"json"` |
| `severity` | str | Nivel mínimo de severidad |
| `sbom_dir` | str | Directorio para SBOMs |
| `nvd_feed` | str\|None | Ruta al feed NVD |
| `container_filter` | str\|None | Nombre de contenedor |
| `image_filter` | str\|None | Tag de imagen |
| `compliance_enabled` | bool | Activar evaluación CIS/ISO (default `True`) |
| `skip_host` | bool | Omite la auditoría del host |

### 5.8 `utils` — Utilidades

**Ficheros:** `dockaudit/utils/helpers.py`, `dockaudit/utils/logger.py`

- `helpers.py`: Funciones auxiliares para normalización de nombres de paquetes, parseo de strings CPE 2.3 y comparación de versiones semánticas.
- `logger.py`: Configura el sistema de logging centralizado mediante `setup_logging(debug, log_file)`. Establece dos destinos: consola (`stdout`) con nivel INFO por defecto (DEBUG si `--debug`) y fichero en `reports/logs/` con nivel DEBUG siempre. Cada módulo del proyecto obtiene su propio logger con `logging.getLogger(__name__)`, lo que produce entradas con el nombre de fichero y función exactos.

---

## 6. Análisis de compliance CIS / ISO 27001

### Descripción

El módulo `compliance` evalúa automáticamente 55 controles del **CIS Docker Benchmark 1.6** sobre los resultados de la auditoría, y mapea cada control a su correspondencia en el **Anexo A de ISO/IEC 27001:2022**.

### Ficheros

| Fichero | Contenido |
|---|---|
| `dockaudit/compliance/mapping.py` | Definición de los 55 controles: título, descripción, severidad, remediación, controles ISO asociados |
| `dockaudit/compliance/evaluator.py` | `ComplianceEvaluator`: lógica de evaluación de cada control |

### Estados posibles por control

| Estado | Significado |
|---|---|
| `compliant` | El control se cumple según los datos auditados |
| `non_compliant` | Se detecta una violación del control |
| `unknown` | No hay datos suficientes para evaluar (p.ej. `daemon.json` ausente, SELinux no instalado, Swarm inactivo) |

El estado `unknown` es legítimo y no indica un fallo de la herramienta, sino que el control no aplica o no puede verificarse en el entorno actual.

### Mapeo ISO/IEC 27001:2022

Cada control CIS lleva asignados uno o varios controles del Anexo A de ISO 27001. Los dominios cubiertos son:

| Código ISO | Dominio |
|---|---|
| A.8.1 | Control de acceso a la información |
| A.8.2 | Gestión de derechos de acceso privilegiado |
| A.8.3 | Restricción de acceso a la información |
| A.8.8 | Gestión de vulnerabilidades técnicas |
| A.8.15 | Registro y monitorización |
| A.8.19 | Instalación de software en sistemas en producción (hardening) |
| A.8.20 | Seguridad de redes |
| A.8.22 | Segregación de redes |
| A.8.24 | Uso de criptografía |
| A.8.25 | Ciclo de vida de desarrollo seguro |

### Uso programático

```python
from dockaudit.compliance.evaluator import ComplianceEvaluator
from dockaudit.reporting.compliance_report import ComplianceReportGenerator

evaluator = ComplianceEvaluator(audit_results)
findings = evaluator.evaluate()
summary  = evaluator.get_summary()

generator = ComplianceReportGenerator(findings, audit_target="Container: dvwa")
html = generator.to_html()
json_data = generator.to_json(pretty=True)
```

### Integración automática

La evaluación de compliance se ejecuta automáticamente al final de cada auditoría siempre que `compliance_enabled=True` (valor por defecto). No requiere flags adicionales.

---

## 7. Análisis de vulnerabilidades NVD

### Flujo de análisis

```
Imagen Docker
    │
    ├─ PackageExtractor → lista de paquetes (nombre + versión)
    │
    ├─ SBOMGenerator → reports/sbom/<timestamp>_-_SBOM_<target>.json (CycloneDX 1.4)
    │
    └─ VulnerabilityMatcher
          │
          ├─ NVDParser.load_feed(path)   ← feed NVD local
          │        │
          │    CVEs parseados (formato NVD API v2)
          │
          └─ match_components(paquetes)
                   │
               Lista de CVEs con ID, descripción, paquete afectado
```

### Feed de demo incluido

El repositorio incluye `feeds/NVD_Sample_-_80.json`, un feed en **formato NVD API 2.0** con **88 CVEs reales** seleccionados por su relevancia en entornos Docker. También se incluye `feeds/NVD_Sample_-_15.json`, versión reducida con los 15 CVEs originales para pruebas mínimas:

| CVE | Paquete afectado | Descripción resumida |
|---|---|---|
| CVE-2021-44228 | `log4j` | Log4Shell — ejecución remota de código |
| CVE-2021-45046 | `log4j` | Escape de contexto en Log4j 2 (RCE/DoS) |
| CVE-2022-0778 | `openssl` | Bucle infinito en BN_mod_sqrt (DoS) |
| CVE-2022-1292 | `openssl` | Inyección de comandos en c_rehash |
| CVE-2023-0286 | `openssl` | Confusión de tipos en X.400 (lectura de memoria) |
| CVE-2021-3156 | `sudo` | Baron Samedit — escalada de privilegios a root |
| CVE-2019-14287 | `sudo` | Bypass de restricción de usuario con UID -1 |
| CVE-2022-32207 | `curl` | Permisos incorrectos al guardar cookies/HSTS |
| CVE-2023-38545 | `curl` | Heap overflow en SOCKS5 proxy handshake |
| CVE-2023-38408 | `openssh` | RCE en ssh-agent vía PKCS#11 |
| CVE-2024-6387 | `openssh` | Race condition en signal handler (RCE) |
| CVE-2022-37434 | `zlib` | Heap overflow en inflate() |
| CVE-2023-44487 | `nginx` | HTTP/2 Rapid Reset (DDoS) |
| CVE-2022-41741 | `nginx` | Corrupción de memoria en módulo mp4 |
| CVE-2024-3094 | `xz-utils` | Backdoor en liblzma 5.6.0/5.6.1 |
| CVE-2023-29491 | `ncurses` | Corrupción de memoria con terminfo malformado |
| CVE-2023-24329 | `python` | Bypass de blocklist en urllib.parse |
| CVE-2022-45061 | `python` | ReDoS en codec IDNA (DoS) |
| CVE-2022-24765 | `git` | Directorio .git modificable por otro usuario |
| CVE-2014-6271 | `bash` | Shellshock — ejecución de código en variables de entorno |
| CVE-2024-2961 | `glibc` | Overflow en conversión de charset iconv |
| CVE-2022-40674 | `expat` | Use-after-free en parseado XML |
| CVE-2023-7104 | `sqlite` | Use-after-free en sessionReadRecord |
| CVE-2023-4863 | `libwebp` | Heap overflow en decodificación de imágenes WebP |
| CVE-2024-21626 | `runc` | Escape de contenedor por descriptor de fichero filtrado |
| CVE-2022-22965 | `spring-framework` | Spring4Shell — RCE en Spring MVC |
| CVE-2022-33980 | `commons-text` | Interpolación de variables no esperada (RCE) |
| CVE-2020-14343 | `pyyaml` | RCE por deserialización YAML insegura |
| CVE-2023-46136 | `werkzeug` | DoS por multipart sin límite de tamaño |
| CVE-2023-36053 | `django` | ReDoS en validadores de URL/email |

> El feed incluye 88 CVEs en total; la tabla muestra una selección representativa.

Uso para la demo:

```bash
python3 main.py --container <nombre> --nvd-feed feeds/NVD_Sample_-_80.json
python3 main.py --image nginx:latest --nvd-feed feeds/NVD_Sample_-_80.json
```

### Descarga de feeds completos (producción)

Los feeds NVD 1.1 (formato NIST antiguo) fueron **retirados en diciembre de 2023**. El script incluido usa la **NVD API 2.0**:

```bash
# Requiere: curl, jq
bash scripts/download_nvd_feed.sh 2024 feeds/

# Con API key (límite 50 req/30s en lugar de 5 req/30s)
# Clave gratuita en: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=<clave>
bash scripts/download_nvd_feed.sh 2024 feeds/
```

El script divide el año en ventanas de 90 días (límite máximo de la NVD API por petición), pagina automáticamente (2 000 CVEs por página) y genera un único fichero JSON. Un año completo contiene ~30 000 CVEs y tarda 3–4 minutos sin clave API o menos de 1 minuto con ella.

```bash
python3 main.py --nvd-feed feeds/nvdcve-2.0-2024.json
```

El script gestiona automáticamente los límites de la API NVD: reintentos ante respuestas truncadas o errores HTTP 429, validación del JSON descargado con `jq` antes de procesar, y un timeout de 300 segundos por petición para acomodar ventanas temporales con muchos CVEs.

### Consideraciones sobre el matching

- El matching es por nombre de paquete: `curl` en el nombre del componente coincide con `haxx:curl` en el CPE; `python3` coincide con `python:python`.
- Las versiones en `feeds/NVD_Sample_-_80.json` usan `*` (cualquier versión) para maximizar coincidencias en la demo.
- El matching de versiones es flexible: `3.11` en el feed coincide con `3.11.5` en el paquete.
- Un paquete sin versión detectable se correlaciona igualmente si el CPE tiene versión `*`.
- Para cobertura completa en producción se recomienda descargar feeds de los últimos 2-3 años.

---

## 8. Reportes generados

La herramienta genera hasta cinco ficheros de salida por ejecución. Todos siguen el patrón de nombres `YYYYMMDD-HHMMSS_-_Tipo_objetivo.ext` para evitar sobreescrituras.

### 8.1 Reporte de auditoría general

**Ruta:** `reports/<timestamp>_-_Audit_Report_<target>.html` / `.json`

Generado por `ReportGenerator` usando una plantilla Jinja2. El reporte HTML incluye:

- **Sidebar de navegación** fija con enlaces a cada sección y contador de hallazgos. Si se ha usado un feed NVD, el nombre del fichero aparece también en la barra lateral bajo el objetivo y en el pie del informe junto a la ruta del SBOM.
- **Tarjetas de resumen** (total, críticos, altos, medios, CVEs, paquetes).
- **Hallazgos** agrupados por sección, filtrados por severidad mínima (`--severity`). Cada hallazgo es una card colapsable que muestra:
  - Badge de severidad (`critical`, `high`, `medium`, `low`, `info`).
  - **Badge de origen** (`source`): nombre del contenedor, tag de imagen, o nombre del paquete afectado, con color por tipo (`host` → morado, `container` → azul, `image` → verde, `package` → amarillo).
  - Descripción y recomendación de remediación.
- **Inventario de paquetes** con buscador en tiempo real y columnas: Paquete, Versión, Gestor, **Imagen** (tag de imagen donde fue detectado), CVEs. Las filas con CVEs se resaltan en rojo.

Cada hallazgo incluye: `id`, `title`, `severity`, `description`, `recommendation`, `risk_score`, `source`, `source_type`.

### 8.2 Reporte de compliance

**Ruta:** `reports/<timestamp>_-_Compliance_Report_<target>.html` y `.json`

El nombre incluye la marca de tiempo y el objetivo para que múltiples ejecuciones no se sobreescriban.

Generado por `ComplianceReportGenerator`. El reporte HTML incluye:

- **Cabecera** con audit target, fecha de generación y estándares evaluados.
- **Tarjetas de resumen**: total de controles, conformes, no conformes, desconocidos, y porcentaje de compliance.
- **Gráfico de dona** (Chart.js) con la distribución de estados.
- **Barra de filtros**: filtrar por estado, severidad, categoría y texto libre; botones "Expand All" / "Collapse All".
- **Tabla de hallazgos** con filas expandibles que muestran: descripción técnica, pasos de remediación, evidencia técnica recogida y controles ISO asociados.
- **Gráfico de barras** por categoría.
- **Tabla de cobertura ISO/IEC 27001** por dominio.

El reporte JSON tiene esta estructura:

```json
{
  "metadata": {
    "generated_at": "2026-05-29T...",
    "audit_target": "Container: dvwa",
    "report_type": "Compliance - CIS Docker Benchmark 1.6 vs ISO/IEC 27001:2022"
  },
  "summary": {
    "total_controls": 55,
    "compliant": 30,
    "non_compliant": 21,
    "unknown": 4,
    "compliance_percentage": 58.8
  },
  "findings": [ ... ],
  "analysis": {
    "by_severity": { ... },
    "by_category": { ... },
    "iso_coverage": { ... }
  }
}
```

### 8.3 SBOM

**Ruta:** `reports/sbom/<timestamp>_-_SBOM_<target>.json`

Formato **CycloneDX 1.4** JSON. Contiene los componentes software identificados en todas las imágenes analizadas, incluyendo el campo `image` con el tag de origen de cada paquete. Compatible con herramientas como Dependency-Track, Grype o Trivy para análisis adicional.

### 8.4 Log de auditoría

**Ruta:** `reports/logs/<timestamp>_-_audit.log`

Generado automáticamente en cada ejecución. Registra la traza completa a nivel DEBUG: inicialización del cliente Docker, cada petición HTTP al daemon, módulo y función exactos que los originan, tiempos de procesamiento por imagen y resumen final. Útil para diagnóstico de incidencias y para auditar el propio proceso de auditoría. El flag `--debug` duplica esta salida en consola.

---

## 9. Suite de tests

### Ejecutar todos los tests

```bash
source .venv/bin/activate
python -m pytest -q
```

Resultado esperado: `51 passed`

### Ejecutar un módulo concreto

```bash
python -m pytest tests/test_compliance.py -v
```

### Ficheros de test

| Fichero | Tests | Qué cubre |
|---|---|---|
| `test_binary_analyzer.py` | 1 | Detección SUID/SGID y ficheros sensibles |
| `test_compliance.py` | 15 | Evaluación de todos los grupos de controles |
| `test_container_audit.py` | 3 | Modo privilegiado, no containers, error Docker |
| `test_fail_on.py` | 4 | Umbral `--fail-on` y códigos de salida |
| `test_host_audit.py` | 3 | Auditoría de host |
| `test_image_analysis_nvd.py` | 1 | SBOM + correlación NVD (integración) |
| `test_nvd_parser.py` | 4 | Feeds v1/v2, gzip, CVSS y rangos de versión |
| `test_package_extractor.py` | 7 | Parseo estático dpkg/apk, fallback runtime, flujo extract() |
| `test_report_generator.py` | 3 | HTML, JSON y deduplicación de CVEs |
| `test_sbom_generator.py` | 2 | Generación CycloneDX y purl |
| `test_vulnerability_matcher.py` | 8 | Rangos de versión, épocas, CVSS, falsos positivos, atribución |
| **Total** | **51** | |

Todos los tests usan objetos `Dummy` (stubs) que simulan el cliente Docker, evitando dependencias de un daemon real en ejecución durante las pruebas.

---

## 10. Estructura de ficheros

```
DockAudit-SCA/
│
├── main.py                          # Punto de entrada (CLI)
├── setup.py                         # Configuración del paquete Python
├── requirements.txt                 # Dependencias
├── Dockerfile.demo                  # Imagen con paquetes vulnerables y misconfigs para demo
├── Dockerfile.vulnerable            # Imagen ultra-vulnerable (mega-vuln:latest) para stress-testing
│
├── feeds/                           # Feeds NVD locales
│   ├── NVD_Sample_-_15.json         # Feed de demo reducido (15 CVEs reales)
│   ├── NVD_Sample_-_80.json         # Feed de demo ampliado (88 CVEs reales)
│   └── nvdcve-2.0-2024.json         # Feed completo 2024 (~40 000 CVEs, descargado con el script)
│
├── dockaudit/                       # Paquete principal (23 ficheros, ~4 200 líneas)
│   ├── host_audit/
│   │   └── host_scanner.py
│   ├── container_audit/
│   │   └── container_scanner.py
│   ├── image_analysis/
│   │   ├── image_scanner.py
│   │   ├── package_extractor.py
│   │   ├── binary_analyzer.py
│   │   └── sbom_generator.py
│   ├── sca/
│   │   ├── nvd_parser.py
│   │   └── vulnerability_matcher.py
│   ├── compliance/
│   │   ├── mapping.py               # 55 controles CIS con mapeo ISO
│   │   └── evaluator.py             # Lógica de evaluación
│   ├── reporting/
│   │   ├── report_generator.py      # Reporte de auditoría (Jinja2)
│   │   ├── compliance_report.py     # Reporte de compliance (HTML/JSON)
│   │   └── templates/
│   │       └── report_template.html
│   ├── orchestrator/
│   │   └── orchestrator.py
│   └── utils/
│       ├── helpers.py
│       └── logger.py
│
├── tests/                           # Suite de tests (11 ficheros, 51 tests)
│   ├── test_binary_analyzer.py
│   ├── test_container_audit.py
│   ├── test_host_audit.py
│   ├── test_image_analysis_nvd.py
│   ├── test_nvd_parser.py
│   ├── test_package_extractor.py
│   ├── test_report_generator.py
│   ├── test_sbom_generator.py
│   ├── test_vulnerability_matcher.py
│   └── test_compliance.py
│
├── scripts/
│   ├── run_real_integration.sh      # Auditoría completa automatizada
│   ├── compare_with_trivy.py        # Comparativa de CVEs frente a Trivy
│   └── download_nvd_feed.sh         # Descarga feeds NVD oficiales
│
├── examples/
│   ├── compliance_demo.py           # Demo ejecutable del módulo compliance
│   └── sample_report.html           # Reporte HTML de ejemplo
│
└── reports/                         # Salida de la herramienta (generado en ejecución)
    ├── <timestamp>_-_Audit_Report_<target>.html
    ├── <timestamp>_-_Audit_Report_<target>.json
    ├── <timestamp>_-_Compliance_Report_<target>.html
    ├── <timestamp>_-_Compliance_Report_<target>.json
    ├── sbom/
    │   └── <timestamp>_-_SBOM_<target>.json
    └── logs/
        └── <timestamp>_-_audit.log
```

---

## 11. Cobertura de controles CIS

La herramienta evalúa 55 de los 64 controles del CIS Docker Benchmark 1.6 cubiertos en las ocho secciones implementadas.

### Controles implementados por sección

**Sección 2 — Docker Daemon Configuration (3/12)**

| Control | Descripción |
|---|---|
| CIS-2.1 | Daemon no-root |
| CIS-2.2 | Separación de partición de datos |
| CIS-2.9 | Gestión de versiones Docker |

**Sección 3 — Daemon Runtime Configuration Files (4/6)**

| Control | Descripción |
|---|---|
| CIS-3.1 | No usar `--privileged` |
| CIS-3.2 | No ejecutar como root |
| CIS-3.3 | Capacidades Linux granulares |
| CIS-3.4 | Ficheros sensibles como read-only |

**Sección 4 — Container Images (6/10)**

| Control | Descripción |
|---|---|
| CIS-4.1 | Imágenes personalizadas |
| CIS-4.2 | Verificación de firma de imagen |
| CIS-4.3 | Paquetes mínimos instalados |
| CIS-4.4 | Imágenes base de confianza |
| CIS-4.7 | No SETUID/SETGID en imagen |
| CIS-4.10 | No montaje de rutas sensibles |

**Sección 5 — Container Runtime (4/11)**

| Control | Descripción |
|---|---|
| CIS-5.1 | AppArmor o SELinux activado |
| CIS-5.2 | Perfil Seccomp configurado |
| CIS-5.3 | Etiquetas SELinux |
| CIS-5.5 | No deshabilitar AppArmor |

**Sección 6 — Docker Security Operations (2/10)**

| Control | Descripción |
|---|---|
| CIS-6.2 | Escaneo de vulnerabilidades en imágenes |
| CIS-6.3 | Política de imágenes de confianza |

**Sección 7 — Container Orchestration (1/1)**

| Control | Descripción |
|---|---|
| CIS-7.1 | Versión del orquestador |

**Sección 8 — Docker Swarm (2/8)**

| Control | Descripción |
|---|---|
| CIS-8.1 | Uso de secretos Docker |
| CIS-8.2 | No secretos en variables de entorno |

**Sección 1 — Docker Host Configuration: no implementada (0/6).** Los controles de esta sección requieren acceso a la configuración de particiones del sistema de ficheros del host, que está fuera del alcance de la auditoría vía Docker API.

### Resumen de cobertura

| Sección | Implementados | Total sección |
|---|---|---|
| 1 — Host Config | 0 | 6 |
| 2 — Daemon Config | 3 | 12 |
| 3 — Config Files | 4 | 6 |
| 4 — Container Images | 6 | 10 |
| 5 — Container Runtime | 4 | 11 |
| 6 — Security Ops | 2 | 10 |
| 7 — Orchestration | 1 | 1 |
| 8 — Swarm | 2 | 8 |
| **Total** | **22** | **64** |

> Nota: el proyecto evalúa 55 controles en total. Los 33 controles adicionales sobre este núcleo de 22 corresponden a controles ampliados implementados en el módulo `compliance/evaluator.py` que cubren verificaciones adicionales de configuración de ficheros del daemon, variables de entorno, healthchecks, modo IPC, límites de recursos y gestión de secretos.

---

*DockAudit-SCA v0.2.0 — TFM Seguridad en Contenedores Docker*
