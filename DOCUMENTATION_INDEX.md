# 📚 Índice de Documentación - DockAudit-SCA

**Todos los documentos del proyecto en un solo lugar**

---

## 📋 Documentos del Proyecto

### 🎯 **Estado Actual** (EMPEZAR AQUÍ)
📄 **[PROJECT_STATE.md](PROJECT_STATE.md)** - 484 líneas  
**Lo PRIMERO que leer.** Resumen ejecutivo del proyecto:
- Métricas completas
- Arquitectura de 8 módulos
- Estado de tests (32/32 passing)
- Características por versión
- Comandos principales
- Ejemplos de salida
- Próximos pasos

---

## 📘 Documentación Principal

### 📖 **README**
📄 **[README.md](README.md)** - Setup rápido, features, NVD usage

### 🏗️ **Arquitectura General**
📄 **[docs/architecture.md](docs/architecture.md)** - Arquitectura del proyecto y objetivos TFM
- Describe los 8 módulos
- Mapea objetivos TFM a componentes
- Flujo de ejecución

### 🔍 **Metodología NVD**
📄 **[docs/nvd.md](docs/nvd.md)** - Análisis de vulnerabilidades con NVD
- Proceso de 5 pasos
- Uso de feeds NVD
- Ejemplos prácticos
- Best practices

### 🔐 **Compliance Mapping**
📄 **[docs/compliance_mapping.md](docs/compliance_mapping.md)** - Mapping CIS ↔ ISO 27001
- Conceptos fundamentales
- Tabla de correspondencias
- 5 pasos de implementación
- Estructura de datos

### 📘 **Compliance Guide**
📄 **[COMPLIANCE_GUIDE.md](COMPLIANCE_GUIDE.md)** - Guía práctica de compliance
- Características principales
- Cómo funciona el compliance
- Uso básico (3 opciones)
- Interpretar reportes
- Testing
- Casos de uso

---

## 💻 Código & Tests

### 🐍 **Punto de Entrada**
📄 **[main.py](main.py)** - CLI principal del proyecto
- Parseador de argumentos
- Validaciones iniciales
- Orquestación de auditoría

### 🧪 **Suite de Tests**
📁 **[tests/](tests/)** - 11 archivos de test
- `test_compliance.py` - 14 tests de compliance (⭐ NUEVO)
- `test_nvd_parser.py` - 3 tests de parsing NVD
- `test_vulnerability_matcher.py` - Tests de matching
- Y 8 archivos más...

**Total: 32/32 tests PASSING ✅**

### 📦 **Módulos Principales**
📁 **[dockaudit/](dockaudit/)** - 23 archivos Python, 3,063 líneas

1. **host_audit/** - Auditoría del daemon Docker
2. **container_audit/** - Auditoría de contenedores activos
3. **image_analysis/** - Análisis de imágenes (4 submódulos)
4. **sca/** - Software Composition Analysis (NVD)
5. **compliance/** ⭐ - Mapeo CIS ↔ ISO 27001
6. **reporting/** - Generación de reportes
7. **orchestrator/** - Coordinador principal
8. **utils/** - Funciones auxiliares

---

## 🎯 Ejemplos & Demos

### 💬 **Demo de Compliance**
📄 **[examples/compliance_demo.py](examples/compliance_demo.py)** - Demo funcional
```bash
PYTHONPATH=. python examples/compliance_demo.py
```
**Qué muestra:**
- 4 controles CIS de ejemplo
- Evaluación compliance
- Generación de reportes
- Guardado en `reports/compliance_sample.*`

### 📊 **Reporte de Ejemplo**
📄 **[examples/sample_report.html](examples/sample_report.html)** - Reporte HTML de ejemplo

### 🐳 **Feed NVD de Ejemplo**
📄 **[sample_nvd.json](sample_nvd.json)** - Feed NVD para testing sin descargar

---

## 🛠️ Scripts

### ⚙️ **Integración Automatizada**
📄 **[scripts/run_real_integration.sh](scripts/run_real_integration.sh)**
```bash
./scripts/run_real_integration.sh
```
**Qué hace:**
- Crea .venv
- Instala dependencias
- Construye imagen Docker
- Ejecuta auditoría
- Genera reportes
- Limpia recursos

### 📥 **Descarga Feeds NVD**
📄 **[scripts/download_nvd_feed.sh](scripts/download_nvd_feed.sh)**
```bash
bash scripts/download_nvd_feed.sh 2024 feeds/
```
**Descarga:**
- Feeds NVD oficiales de NIST
- Años específicos
- Descomprime automáticamente

---

## 🔧 Configuración

### 📋 **Dependencias**
📄 **[requirements.txt](requirements.txt)**
- docker 7.1.0
- requests 2.33.1
- Jinja2 3.1.6
- Y otras...

### ⚙️ **Setup del Paquete**
📄 **[setup.py](setup.py)**
- Configuración del paquete Python
- Versión: 0.1.0
- Python 3.11+

---

## 🐳 Docker

### 🧪 **Imagen de Test**
📄 **[Dockerfile.test](Dockerfile.test)** - Para testing

### 🚨 **Imagen Vulnerable**
📄 **[Dockerfile.vulnerable](Dockerfile.vulnerable)** - Contenedor de prueba vulnerable
```bash
docker build -f Dockerfile.vulnerable -t dockaudit-test:vulnerable .
```

---

## 📁 Reportes Generados

### 📊 **Reporte de Auditoría**
📁 **[reports/](reports/)** - Directorio de reportes
- `report.html` - Dashboard HTML última auditoría
- `report.json` - Datos JSON última auditoría
- `compliance_sample.html` - Reporte compliance de ejemplo
- `compliance_sample.json` - Datos compliance de ejemplo
- `sbom/` - SBOMs generados por imagen

---

## 🗂️ Estructura Rápida

```
DockAudit-SCA/
├── PROJECT_STATE.md           ⭐ EMPEZAR AQUÍ
├── DOCUMENTATION_INDEX.md     ← TÚ ESTÁS AQUÍ
├── README.md                  ← Quick start
├── COMPLIANCE_GUIDE.md        ← Guía práctica
├── docs/
│   ├── architecture.md
│   ├── nvd.md
│   └── compliance_mapping.md
├── dockaudit/                 ← Código principal (8 módulos)
├── tests/                     ← 11 archivos, 32/32 passing
├── examples/
│   └── compliance_demo.py     ← Ejecutable
├── scripts/
│   ├── run_real_integration.sh
│   └── download_nvd_feed.sh
└── reports/                   ← Reportes generados
```

---

## 🎓 Guía de Lectura Recomendada

### Para entender rápido (15 min)
1. [PROJECT_STATE.md](PROJECT_STATE.md) - Resumen ejecutivo
2. [README.md](README.md) - Quick start
3. Ejecutar: `python main.py`

### Para entender bien (45 min)
1. [PROJECT_STATE.md](PROJECT_STATE.md)
2. [docs/architecture.md](docs/architecture.md)
3. [COMPLIANCE_GUIDE.md](COMPLIANCE_GUIDE.md)
4. Ejecutar demo: `PYTHONPATH=. python examples/compliance_demo.py`

### Para entender profundamente (2 horas)
1. [PROJECT_STATE.md](PROJECT_STATE.md)
2. [docs/architecture.md](docs/architecture.md)
3. [docs/compliance_mapping.md](docs/compliance_mapping.md)
4. [docs/nvd.md](docs/nvd.md)
5. Revisar [dockaudit/](dockaudit/) código
6. Revisar [tests/](tests/) tests

---

## 🚀 Comandos Rápidos

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Ejecutar
python main.py

# Demo compliance
PYTHONPATH=. python examples/compliance_demo.py

# Tests
./.venv/bin/python -m pytest -q

# Integración automatizada
./scripts/run_real_integration.sh

# Ver reporte
open reports/report.html
```

---

## 📞 Versión & Status

- **Versión:** 0.1.0
- **Estado:** ✅ Production-Ready
- **Tests:** 32/32 Passing
- **Código:** 3,063 líneas Python
- **Licencia:** MIT

---

## ✨ Última Actualización

- **Fecha:** 25 de mayo de 2026
- **Cambios:** Implementación completa de Compliance Mapping (CIS ↔ ISO 27001)

---

**¿Necesitas ayuda?** Empieza por [PROJECT_STATE.md](PROJECT_STATE.md)
