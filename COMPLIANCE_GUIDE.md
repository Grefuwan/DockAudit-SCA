# Compliance Mapping Implementation Guide

DockAudit-SCA ahora incluye una **evaluación completa de compliance** que mapea el CIS Docker Benchmark con los estándares ISO/IEC 27001. Esta guía te muestra cómo usar esta funcionalidad.

## 📋 Contenido

- [Características principales](#características-principales)
- [Cómo funciona](#cómo-funciona)
- [Uso básico](#uso-básico)
- [Interpretación de reportes](#interpretación-de-reportes)
- [Estructura de módulos](#estructura-de-módulos)

## 🎯 Características principales

### 1. **Mapeo CIS ↔ ISO 27001**
- 22 controles CIS Docker Benchmark mapeados
- Correlación con dominios ISO/IEC 27001
- Severidades asignadas (critical, high, medium)
- Pasos de remediación detallados

### 2. **Evaluación Automática**
- Evaluación de compliance integrada en auditoría
- Análisis de resultados contra 22 controles
- Cálculo de tasa de compliance
- Identificación de issues críticos

### 3. **Reportes Profesionales**
- Generación en **JSON** (máquina legible)
- Generación en **HTML** (visual dashboard)
- Análisis por severidad y categoría
- Cobertura ISO/IEC 27001 por dominio

## 🔄 Cómo funciona

```
┌─────────────────────────────────────────────────────────────┐
│ 1. AUDITORÍA (host, contenedores, imágenes)                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. EVALUADOR DE COMPLIANCE                                 │
│    - Correlaciona resultados de auditoría                  │
│    - Verifica 22 controles CIS                            │
│    - Mapea a ISO/IEC 27001                                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. GENERACIÓN DE REPORTES                                  │
│    - JSON: compliance_sample.json                          │
│    - HTML: compliance_sample.html                          │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Uso básico

### Opción 1: Ejecutar Demo

```bash
cd /home/jgv/Documentos/TFM_-_Docker/DockAudit-SCA
PYTHONPATH=. python examples/compliance_demo.py
```

**Salida esperada:**
- Muestra 4 controles CIS de ejemplo con mapeo ISO
- Evalúa compliance con datos de ejemplo
- Genera reportes (JSON + HTML)
- Guarda en `reports/compliance_sample.*`

### Opción 2: Usar en Auditoría Principal

```bash
# Modificar orchestrator para ejecutar con compliance (ya está activado)
python main.py --target local
```

### Opción 3: Programáticamente

```python
from dockaudit.compliance.evaluator import ComplianceEvaluator
from dockaudit.reporting.compliance_report import ComplianceReportGenerator

# Resultados de auditoría
audit_results = {
    "container_audit": {"containers": [...]},
    "image_analysis": {"images": [...]},
    # ...
}

# Evaluar compliance
evaluator = ComplianceEvaluator(audit_results)
findings = evaluator.evaluate()

# Generar reporte
generator = ComplianceReportGenerator(findings)
html_report = generator.to_html()
json_report = generator.to_json()
```

## 📊 Interpretación de reportes

### Dashboard HTML

El reporte HTML incluye:

1. **Summary Cards**
   - ✅ Controles conformes
   - ❌ Controles no conformes
   - ❓ Estado desconocido
   - **% Compliance Rate**

2. **Tabla de Hallazgos**
   - Control CIS
   - Título
   - Severidad (CRITICAL/HIGH/MEDIUM)
   - Estado (COMPLIANT/NON-COMPLIANT/UNKNOWN)
   - Controles ISO 27001 relacionados

3. **Análisis por Severidad**
   - CRITICAL (3 controles)
   - HIGH (8 controles)
   - MEDIUM (11 controles)

4. **Análisis por Categoría**
   - Access Control
   - Container Runtime
   - Image Security
   - Hardening
   - Patch Management
   - Secrets Management

5. **Cobertura ISO/IEC 27001**
   - Access Control (A.9)
   - Operations Security (A.12)
   - Secure Development (A.14)
   - Y otros dominios

### Reporte JSON

Estructura:
```json
{
  "metadata": {
    "generated_at": "2026-05-25T...",
    "report_type": "Compliance - CIS..."
  },
  "summary": {
    "total_controls": 22,
    "compliant": 6,
    "non_compliant": 9,
    "unknown": 7,
    "compliance_percentage": 27.3
  },
  "findings": [
    {
      "cis_control": "CIS-2.1",
      "title": "Ejecutar daemon no-root",
      "status": "non_compliant",
      "iso27001_controls": [{"code": "A.9.2.1", "domain": "Access Control"}],
      "remediation": "..."
    },
    ...
  ],
  "analysis": {
    "by_severity": {...},
    "by_category": {...},
    "iso_coverage": {...}
  }
}
```

## 📁 Estructura de módulos

### `dockaudit/compliance/mapping.py`
Define los 22 controles CIS mapeados a ISO 27001:

```python
COMPLIANCE_MAPPING = {
    "CIS-2.1": {
        "title": "Ejecutar daemon no-root",
        "severity": "high",
        "iso27001_controls": [
            {"code": "A.9.2.1", "domain": "Access Control"}
        ],
        "implementation": "host_audit.check_daemon_user",
        "remediation": "..."
    },
    # ... 21 controles más
}
```

### `dockaudit/compliance/evaluator.py`
Implementa `ComplianceEvaluator`:

**Métodos principales:**
- `evaluate()` - Evalúa todos los controles
- `get_summary()` - Estadísticas de compliance
- `get_by_severity()` - Agrupa por severidad
- `get_by_category()` - Agrupa por categoría
- `get_iso_coverage()` - Análisis de cobertura ISO

**Métodos de verificación (40+):**
- `_check_privileged_mode()` - Detecta contenedores privilegiados
- `_check_user_not_root()` - Verifica usuario no-root
- `_check_setuid_binaries()` - Detecta binarios SETUID
- Y muchos más...

### `dockaudit/reporting/compliance_report.py`
Implementa `ComplianceReportGenerator`:

- `to_json()` - Genera reporte JSON
- `to_html()` - Genera dashboard HTML
- `_generate_summary_section()` - Crea cards visuales
- Y métodos de apoyo

### `dockaudit/orchestrator/orchestrator.py`
Integración en orquestador:

```python
# Ya está integrado automáticamente
if self.compliance_enabled:
    evaluator = ComplianceEvaluator(results)
    results["compliance"] = evaluator.evaluate()
    results["compliance_summary"] = evaluator.get_summary()
```

## 🧪 Testing

Ejecutar tests de compliance:
```bash
./.venv/bin/python -m pytest tests/test_compliance.py -v
```

Resultado: **14/14 tests PASSED**

Ejecutar suite completa:
```bash
./.venv/bin/python -m pytest -q
```

Resultado: **32/32 tests PASSED**

## 📚 Documentación

- **Principal**: [docs/compliance_mapping.md](docs/compliance_mapping.md)
- **Ejemplos**: [examples/compliance_demo.py](examples/compliance_demo.py)
- **Tests**: [tests/test_compliance.py](tests/test_compliance.py)

## 🎓 Casos de uso

### 1. Auditoría de Conformidad
```bash
./scripts/run_real_integration.sh
# → Genera reporte con compliance
```

### 2. Validación Punto en Tiempo
```python
evaluator = ComplianceEvaluator(current_audit)
summary = evaluator.get_summary()
print(f"Compliance: {summary['compliance_percentage']}%")
```

### 3. Reportería Ejecutiva
```bash
PYTHONPATH=. python examples/compliance_demo.py
# → Abre reports/compliance_sample.html en navegador
```

## 🔐 Controles ISO/IEC 27001 Cubiertos

| Dominio | Controles | Estado |
|---------|-----------|--------|
| A.5: Políticas de Access | 3 | ✅ Mapeado |
| A.9: Access Control | 11 | ✅ Mapeado |
| A.12: Operations Security | 8 | ✅ Mapeado |
| A.14: Desarrollo & Maintenance | 4 | ✅ Mapeado |

**Total: 26 controles ISO/IEC 27001 cubiertos**

## 💡 Próximas Mejoras

1. **Más controles**: Agregar CIS 6, 7, 8 completos
2. **Otros estándares**: SOC 2, PCI-DSS, HIPAA
3. **Trending**: Histórico de compliance
4. **Custom mappings**: Mapeos por organización
5. **Policy engines**: Integración con OPA/Gatekeeper

---

**¿Preguntas?** Revisar [docs/compliance_mapping.md](docs/compliance_mapping.md) para más detalles técnicos.
