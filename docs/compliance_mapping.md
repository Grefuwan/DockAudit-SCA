# Compliance Mapping: CIS Docker Benchmark ↔ ISO/IEC 27001

Este documento detalla los pasos para implementar un mapping de compliance entre el **CIS Docker Benchmark** y los controles del estándar **ISO/IEC 27001**, permitiendo auditar conformidad de seguridad en contenedores.

## 1. Conceptos fundamentales

### 1.1 CIS Docker Benchmark
- **Propósito**: Guía de mejores prácticas de seguridad específicas para Docker.
- **Cobertura**: Configuración del host Docker, gestión de contenedores e imágenes, y runtime.
- **Ejemplos de controles**:
  - 2.1 Ejecutar el daemon en un grupo no raíz
  - 3.1 No usar descomposición de imágenes con privilege
  - 4.1 Configurar la política de reinicio de contenedores

### 1.2 ISO/IEC 27001
- **Propósito**: Estándar global de gestión de seguridad de la información.
- **Estructura**: 14 dominios (anteriormente 11), 93 controles (antiguamente 114 en la versión 2013).
- **Dominios relevantes para Docker**:
  - A.5: Políticas de control de acceso
  - A.6: Criptografía
  - A.7: Seguridad física y ambiental
  - A.8: Operaciones de seguridad
  - A.9: Controles de acceso
  - A.10: Criptografía
  - A.12: Seguridad de comunicaciones
  - A.13: Adquisición, desarrollo y mantenimiento de sistemas
  - A.14: Relaciones con proveedores

## 2. Estructura de un Compliance Mapping

El mapping debe documentar:

| CIS Control | Descripción | ISO/IEC 27001 | Dominio | Implementación en DockAudit-SCA |
|---|---|---|---|---|
| 2.1 | Ejecutar daemon no-root | A.9.2.1 | User access management | Auditado por `host_audit` |
| 3.1 | No usar --privileged | A.9.1.1 | Access control | Auditado por `container_audit` |
| 4.1 | Política de reinicio | A.12.4.1 | Event logging | Verificado en configuración del contenedor |

## 3. Pasos para implementar el mapping

### Paso 1: Crear estructura de datos
```python
# dockaudit/compliance/mapping.py
COMPLIANCE_MAPPING = {
    "CIS-2.1": {
        "title": "Ejecutar el daemon Docker en un grupo no-raíz",
        "description": "El daemon debe ejecutarse bajo un usuario no-raíz para limitar daños por vulnerabilidades.",
        "iso27001_controls": [
            {"code": "A.9.2.1", "domain": "Access Control", "title": "User registration and de-registration"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_user",
        "remediation": "Crear usuario no-root, añadir a grupo docker, cambiar propiedad de socket"
    },
    "CIS-3.1": {
        "title": "No usar --privileged con contenedores",
        "description": "Los contenedores no deben ejecutarse con flag --privileged.",
        "iso27001_controls": [
            {"code": "A.9.1.1", "domain": "Access Control", "title": "Access control policy"}
        ],
        "severity": "critical",
        "implementation": "container_audit.check_privileged",
        "remediation": "Ejecutar contenedores sin --privileged, usar capacidades granulares con --cap-drop/add"
    }
}
```

### Paso 2: Crear módulo de evaluación de compliance
```python
# dockaudit/compliance/evaluator.py
class ComplianceEvaluator:
    def __init__(self, audit_results, mapping=COMPLIANCE_MAPPING):
        self.audit_results = audit_results
        self.mapping = mapping
    
    def evaluate(self):
        """Correlaciona hallazgos de auditoría con controles CIS e ISO."""
        compliance_report = []
        
        for cis_id, control in self.mapping.items():
            status = self._check_control(control)
            iso_controls = control.get("iso27001_controls", [])
            
            compliance_report.append({
                "cis_control": cis_id,
                "title": control["title"],
                "status": status,  # "compliant", "non_compliant", "unknown"
                "iso_controls": iso_controls,
                "findings": self._get_related_findings(cis_id),
                "remediation": control.get("remediation")
            })
        
        return compliance_report
    
    def _check_control(self, control):
        # Implementar lógica para verificar si se cumple el control
        pass
```

### Paso 3: Integrar en el orquestador
```python
# dockaudit/orchestrator/orchestrator.py (añadir)
from dockaudit.compliance.evaluator import ComplianceEvaluator

class Orchestrator:
    def run_audit(self):
        # ... código existente ...
        
        # Evaluar compliance
        compliance_evaluator = ComplianceEvaluator(results)
        results["compliance"] = compliance_evaluator.evaluate()
        
        return results
```

### Paso 4: Generar informe de compliance
```python
# dockaudit/reporting/compliance_report.py
class ComplianceReportGenerator:
    def generate_compliance_matrix(self, compliance_results):
        """Genera matriz de compliance CIS vs ISO."""
        matrix = {
            "summary": {
                "total_controls": len(compliance_results),
                "compliant": sum(1 for c in compliance_results if c["status"] == "compliant"),
                "non_compliant": sum(1 for c in compliance_results if c["status"] == "non_compliant"),
                "compliance_percentage": self._calc_percentage(compliance_results)
            },
            "controls": compliance_results,
            "iso_27001_coverage": self._map_iso_coverage(compliance_results)
        }
        return matrix
    
    def _map_iso_coverage(self, compliance_results):
        """Mapea cobertura ISO/IEC 27001 por dominio."""
        coverage = {}
        for control in compliance_results:
            for iso_ctrl in control.get("iso_controls", []):
                domain = iso_ctrl["domain"]
                if domain not in coverage:
                    coverage[domain] = {"total": 0, "covered": 0}
                coverage[domain]["total"] += 1
                if control["status"] == "compliant":
                    coverage[domain]["covered"] += 1
        return coverage
```

### Paso 5: Template HTML para reporte
```html
<!-- dockaudit/reporting/templates/compliance_report.html -->
<section>
    <h2>Compliance Report: CIS Docker Benchmark vs ISO/IEC 27001</h2>
    
    <div class="compliance-summary">
        <p>Conformidad: {{ summary.compliance_percentage }}%</p>
        <ul>
            <li>✅ Conformes: {{ summary.compliant }}</li>
            <li>❌ No conformes: {{ summary.non_compliant }}</li>
            <li>❓ Desconocidos: {{ summary.unknown }}</li>
        </ul>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>CIS Control</th>
                <th>Título</th>
                <th>Estado</th>
                <th>ISO/IEC 27001</th>
                <th>Recomendación</th>
            </tr>
        </thead>
        <tbody>
            {% for control in controls %}
            <tr>
                <td>{{ control.cis_control }}</td>
                <td>{{ control.title }}</td>
                <td>{{ control.status }}</td>
                <td>
                    {% for iso in control.iso_controls %}
                    {{ iso.code }} ({{ iso.domain }})<br>
                    {% endfor %}
                </td>
                <td>{{ control.remediation }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <h3>ISO/IEC 27001 Domain Coverage</h3>
    <table>
        <thead><tr><th>Dominio</th><th>Cobertura</th></tr></thead>
        <tbody>
            {% for domain, cov in iso_27001_coverage.items() %}
            <tr>
                <td>{{ domain }}</td>
                <td>{{ cov.covered }} / {{ cov.total }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</section>
```

## 4. Ejemplo de uso

```bash
# Ejecutar auditoría con compliance mapping
python main.py --target local --output html --compliance-enabled --compliance-format cis-iso

# Resultado: un informe que incluya:
# - Hallazgos de auditoría (actual)
# - Mapeo a controles CIS Docker Benchmark
# - Correlación con ISO/IEC 27001
# - Recomendaciones de remediación
```

## 5. Tabla de correspondencias CIS ↔ ISO/IEC 27001

### Dominio: Control de Acceso (A.9)

| CIS Docker Benchmark | ISO 27001 |
|---|---|
| 2.1 Daemon no-root | A.9.2.1 User registration and de-registration |
| 2.2 Separar datos de runtime | A.9.1.1 Access control policy |
| 3.1 No usar --privileged | A.9.1.1 Access control policy |
| 3.2 Usar capacidades granulares | A.9.2.5 Access rights review |
| 4.1 Política de reinicio | A.12.4.1 Event logging |

### Dominio: Operaciones de Seguridad (A.12)

| CIS Docker Benchmark | ISO 27001 |
|---|---|
| 4.5 Logging de contenedores | A.12.4.1 Event logging |
| 5.1 AppArmor/SELinux | A.12.6.1 Management of technical vulnerabilities |
| 5.2 Actualizar Docker Engine | A.12.6.2 Restrictions on software installation |

### Dominio: Seguridad en Desarrolloe Implementación (A.14)

| CIS Docker Benchmark | ISO 27001 |
|---|---|
| 3.3 Verificar firmas de imágenes | A.14.2.1 Secure development policy |
| 3.4 Usar imágenes confiables | A.14.2.5 Secure development environment |
| 3.10 Desactivar setuid/setgid | A.14.2.1 Secure development policy |

## 6. Próximos pasos de implementación

1. **Crear archivo de mapping completo** con todas las correlaciones CIS-ISO 27001.
2. **Implementar evaluadores específicos** para cada control CIS.
3. **Integrar en el ReportGenerator** para generar reportes de compliance.
4. **Añadir CLI flag** `--compliance` para habilitar el mapeo.
5. **Crear documentación de evidencia** para auditorías.
6. **Validar con expertos** en compliance e ISO 27001.

## 7. Beneficios para el TFM

- **Diferenciación**: Proyecto que no solo audita seguridad, sino que **demuestra conformidad** con estándares internacionales.
- **Valor empresarial**: Herramienta útil para demostraciones de compliance en certificaciones ISO 27001.
- **Extensibilidad**: Base para mapear a otros estándares (SOC 2, PCI-DSS, HIPAA, GDPR).
- **Investigación**: Análisis de cómo DockerBenchmark y estándares globales se alinean.
