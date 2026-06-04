# DockAudit-SCA — Manual de la herramienta

**Versión:** 0.1.0  
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

DockAudit-SCA es una herramienta de auditoría de seguridad para entornos Docker desarrollada como Trabajo Fin de Máster. Analiza tres capas del entorno:

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
python main.py [opciones]
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

### Ejemplos de uso

```bash
# Auditoría completa del host y todos los contenedores e imágenes locales
python main.py

# Auditar un contenedor específico (filtra también su imagen)
python main.py --container dvwa

# Auditar una imagen pulleada pero sin contenedor desplegado
python main.py --image nginx:latest

# Auditoría con el feed de demo incluido (15 CVEs reales)
python main.py --nvd-feed sample_nvd.json

# Auditoría con feed NVD completo descargado
python main.py --nvd-feed feeds/nvdcve-2.0-2024.json

# Auditoría filtrando hallazgos de severidad alta o crítica
python main.py --severity high

# Auditoría con salida en JSON
python main.py --output json
```

### Comportamiento de los filtros `--container` e `--image`

- `--container NAME`: el orquestador valida primero que exista un contenedor con ese nombre (en ejecución o detenido). Si no existe, muestra la lista de contenedores disponibles y aborta. Si existe, audita el contenedor y la imagen que utiliza.
- `--image TAG`: el orquestador valida que la imagen exista localmente. Si no existe, muestra las imágenes disponibles y aborta. Solo analiza la imagen — no requiere contenedor desplegado.
- Ambas opciones son mutuamente excluyentes en la práctica; `--container` tiene precedencia si se usan juntas.

### Salida esperada en consola

```
[*] Iniciando auditoría Docker...
[*] Ejecutando auditoría del host...
[*] Ejecutando auditoría de contenedores...
[*] Ejecutando análisis de imágenes...
[*] Evaluando compliance (CIS Docker Benchmark & ISO/IEC 27001)...
[+] Compliance evaluation completed: 55 controls evaluated
[*] Auditoría finalizada.
[*] Generando informe...
[+] HTML report written to: reports/report.html
[+] Compliance JSON report written to: reports/<timestamp>_-_Compliance_Report_<target>.json
[+] Compliance HTML report written to: reports/<timestamp>_-_Compliance_Report_<target>.html

=== CIS Docker Benchmark & ISO/IEC 27001 Compliance Summary ===
Total Controls: 55
Compliant: X
Non-Compliant: X
Unknown: X
Compliance Rate: X.X%
```

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
      · SBOMGenerator: SBOM CycloneDX 1.4 en reports/sbom/sbom.json
      · NVDParser + VulnerabilityMatcher: correlación con CVEs (si --nvd-feed)
       ↓
5. Compliance Evaluation
   └─ 55 controles CIS evaluados sobre los resultados anteriores
      · Estado: compliant / non_compliant / unknown
      · Mapeo a controles ISO 27001:2022 Anexo A
       ↓
6. Report Generation
   └─ reports/report.html (o .json) — reporte de auditoría general
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

Ejecuta un contenedor efímero a partir de la imagen y lanza:

```
dpkg-query -W -f='${Package} ${Version}\n'   # Debian/Ubuntu
rpm -qa --queryformat '%{NAME} %{VERSION}...' # Red Hat/CentOS
apk info -vv                                  # Alpine
```

Timeout configurable (por defecto 10 s). Si no se detecta gestor de paquetes, registra un hallazgo `medium`.

#### BinaryAnalyzer (`binary_analyzer.py`)

Detecta dentro de la imagen:

- Binarios con bit SUID o SGID activo.
- Ficheros sensibles expuestos (`.env`, `id_rsa`, `credentials.json`, etc.).

#### SBOMGenerator (`sbom_generator.py`)

Genera un SBOM en formato **CycloneDX 1.4** (JSON) en `reports/sbom/sbom.json`. Incluye:

- Metadatos del componente (nombre, versión, tipo, gestor de paquetes).
- Hash SHA-256 del fichero cuando es posible.
- Lista de `components` compatible con herramientas de terceros (Dependency-Track, etc.).

### 5.4 `sca` — Software Composition Analysis

#### NVDParser (`sca/nvd_parser.py`)

Carga un feed NVD en formato JSON o JSON.GZ (`nvdcve-1.1-YYYY.json`). Extrae para cada entrada:

- ID del CVE.
- Descripción en inglés.
- Lista de `cpeMatch` (CPE 2.3) afectados.

#### VulnerabilityMatcher (`sca/vulnerability_matcher.py`)

Correlaciona los paquetes extraídos con las entradas NVD usando:

1. Nombre del paquete contra el componente CPE.
2. Versión extraída contra la versión del CPE (matching flexible: `3.11` coincide con `3.11.5`).

Devuelve lista de CVEs con ID, descripción y paquete afectado.

### 5.5 `compliance` — Evaluación de compliance

Ver sección [6](#6-análisis-de-compliance-cis--iso-27001).

### 5.6 `reporting` — Generación de reportes

Ver sección [8](#8-reportes-generados).

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

### 5.8 `utils` — Utilidades

Funciones auxiliares para:

- Normalización de nombres de paquetes.
- Parseo de strings CPE 2.3.
- Extracción y comparación de versiones semánticas.

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
    ├─ SBOMGenerator → reports/sbom/sbom.json (CycloneDX 1.4)
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

El repositorio incluye `sample_nvd.json`, un feed en **formato NVD API 2.0** con **15 CVEs reales** seleccionados por su relevancia en entornos Docker:

| CVE | Paquete afectado | Descripción resumida |
|---|---|---|
| CVE-2021-44228 | `log4j` | Log4Shell — ejecución remota de código |
| CVE-2022-0778 | `openssl` | Bucle infinito en BN_mod_sqrt (DoS) |
| CVE-2022-1292 | `openssl` | Inyección de comandos en c_rehash |
| CVE-2023-0286 | `openssl` | Confusión de tipos en X.400 (lectura de memoria) |
| CVE-2021-3156 | `sudo` | Baron Samedit — escalada de privilegios a root |
| CVE-2022-32207 | `curl` | Permisos incorrectos al guardar cookies/HSTS |
| CVE-2022-42915 | `curl` | Double-free en código de proxy HTTP |
| CVE-2023-38408 | `openssh` | RCE en ssh-agent vía PKCS#11 |
| CVE-2022-37434 | `zlib` | Heap overflow en inflate() |
| CVE-2023-44487 | `nginx` | HTTP/2 Rapid Reset (DDoS) |
| CVE-2024-3094 | `xz-utils` | Backdoor en liblzma 5.6.0/5.6.1 |
| CVE-2023-29491 | `ncurses` | Corrupción de memoria con terminfo malformado |
| CVE-2023-24329 | `python` | Bypass de blocklist en urllib.parse |
| CVE-2022-24765 | `git` | Directorio .git modificable por otro usuario |
| CVE-2023-4863 | `libwebp` | Heap overflow en decodificación de imágenes WebP |

Uso para la demo:

```bash
python main.py --container <nombre> --nvd-feed sample_nvd.json
python main.py --image nginx:latest --nvd-feed sample_nvd.json
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

El script pagina automáticamente (2 000 CVEs por petición) y genera un único fichero JSON. Un año completo contiene ~30 000 CVEs y tarda 3-4 minutos sin clave o menos de 1 minuto con ella.

```bash
python main.py --nvd-feed feeds/nvdcve-2.0-2024.json
```

### Consideraciones sobre el matching

- El matching es por nombre de paquete: `curl` en el nombre del componente coincide con `haxx:curl` en el CPE; `python3` coincide con `python:python`.
- Las versiones en `sample_nvd.json` usan `*` (cualquier versión) para maximizar coincidencias en la demo.
- El matching de versiones es flexible: `3.11` en el feed coincide con `3.11.5` en el paquete.
- Un paquete sin versión detectable se correlaciona igualmente si el CPE tiene versión `*`.
- Para cobertura completa en producción se recomienda descargar feeds de los últimos 2-3 años.

---

## 8. Reportes generados

La herramienta genera hasta cuatro ficheros de salida por ejecución.

### 8.1 Reporte de auditoría general

**Ruta:** `reports/report.html` o `reports/report.json`

Generado por `ReportGenerator` usando una plantilla Jinja2. Contiene:

- **Audit target**: objetivo de la auditoría (host, contenedor o imagen específica).
- **Resumen**: número de hallazgos por sección (host, contenedores, imágenes, binarios, vulnerabilidades).
- **Hallazgos**: listados por sección, filtrados por severidad mínima (`--severity`).
- **Ruta al SBOM**: enlace al fichero CycloneDX generado.

Cada hallazgo incluye: `id`, `title`, `severity`, `description`, `recommendation`, `risk_score`.

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

**Ruta:** `reports/sbom/sbom.json`

Formato **CycloneDX 1.4** JSON. Contiene los componentes software identificados en todas las imágenes analizadas. Compatible con herramientas como Dependency-Track, Grype o Trivy para análisis adicional.

---

## 9. Suite de tests

### Ejecutar todos los tests

```bash
source .venv/bin/activate
python -m pytest -q
```

Resultado esperado: `33 passed`

### Ejecutar un módulo concreto

```bash
python -m pytest tests/test_compliance.py -v
```

### Ficheros de test

| Fichero | Tests | Qué cubre |
|---|---|---|
| `test_basic.py` | 2 | Imports y estructura básica |
| `test_binary_analyzer.py` | 2 | Detección SUID/SGID |
| `test_container_audit.py` | 3 | Modo privilegiado, no containers, error Docker |
| `test_host_audit.py` | 1 | Auditoría de host |
| `test_image_analysis_nvd.py` | 1 | SBOM + correlación NVD |
| `test_nvd_parser.py` | 3 | Parseo de feeds NVD |
| `test_package_extractor.py` | 3 | dpkg, no gestor, error de contenedor |
| `test_report_generator.py` | 2 | HTML y JSON |
| `test_sbom_generator.py` | 1 | Generación CycloneDX |
| `test_vulnerability_matcher.py` | 1 | Correlación paquetes/CVEs |
| `test_compliance.py` | 14 | Evaluación de todos los grupos de controles |
| **Total** | **33** | |

Todos los tests usan objetos `Dummy` (stubs) que simulan el cliente Docker, evitando dependencias de un daemon real en ejecución durante las pruebas.

---

## 10. Estructura de ficheros

```
DockAudit-SCA/
│
├── main.py                          # Punto de entrada (CLI)
├── setup.py                         # Configuración del paquete Python
├── requirements.txt                 # Dependencias
├── sample_nvd.json                  # Feed NVD de ejemplo para pruebas
├── Dockerfile.test                  # Imagen Docker para testing
├── Dockerfile.vulnerable            # Imagen intenccionalmente vulnerable para demos
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
│
├── tests/                           # Suite de tests (11 ficheros, 33 tests)
│   ├── test_basic.py
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
│   └── download_nvd_feed.sh         # Descarga feeds NVD oficiales
│
├── examples/
│   ├── compliance_demo.py           # Demo ejecutable del módulo compliance
│   └── sample_report.html           # Reporte HTML de ejemplo
│
└── reports/                         # Salida de la herramienta (generado en ejecución)
    ├── report.html
    ├── report.json
    ├── <timestamp>_-_Compliance_Report_<target>.html
    ├── <timestamp>_-_Compliance_Report_<target>.json
    └── sbom/
        └── sbom.json
```

---

## 11. Cobertura de controles CIS

La herramienta evalúa 55 de los 69 controles del CIS Docker Benchmark 1.6.

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

*Generado para DockAudit-SCA v0.1.0 — TFM Seguridad en Contenedores Docker*
