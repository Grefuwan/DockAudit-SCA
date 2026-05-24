# Arquitectura y objetivos del proyecto

Este documento recoge los objetivos principales del Trabajo Fin de Máster y la base conceptual para el diseño de `DockAudit-SCA`.

## 1.2.1. Objetivo general

Desarrollar un sistema de auditoría de seguridad para entornos Docker que permita analizar configuraciones, dependencias software y binarios presentes en imágenes de contenedor, con el fin de identificar vulnerabilidades y proponer medidas de mitigación.

## 1.2.2. Objetivos específicos

- Analizar la arquitectura de seguridad de Docker y los mecanismos de aislamiento utilizados en entornos de contenedores.
- Diseñar la arquitectura de un sistema de auditoría orientado al análisis de seguridad de contenedores e imágenes Docker.
- Implementar un sistema de análisis de composición software (Software Composition Analysis, SCA) capaz de identificar dependencias y componentes incluidos en imágenes de contenedor.
- Generar un Software Bill of Materials (SBOM) que describa los componentes software presentes en las imágenes analizadas.
- Realizar análisis de binarios presentes en imágenes de contenedor para detectar posibles vulnerabilidades o configuraciones inseguras.
- Evaluar configuraciones de seguridad del entorno Docker, incluyendo privilegios de contenedores, capacidades del kernel, políticas de aislamiento y configuraciones de red.
- Diseñar un sistema de evaluación de riesgos que permita clasificar los hallazgos de seguridad según su criticidad.
- Proponer medidas de hardening y buenas prácticas de seguridad para mejorar la protección de entornos Docker.

## Arquitectura del sistema

El sistema `DockAudit-SCA` se organiza en capas modulares que permiten auditar un entorno Docker local y generar un informe completo con análisis de seguridad, SBOM y evaluación de riesgos.

### Componentes principales

- `main.py`
  - Punto de entrada que inicia la auditoría y carga la configuración de ejecución.
- `dockaudit.orchestrator.orchestrator.Orchestrator`
  - Coordina la ejecución de las auditorías de host, contenedores e imágenes.
  - Gestiona el flujo de datos entre los distintos módulos.
- `dockaudit.host_audit.host_scanner.HostScanner`
  - Evalúa la configuración del host Docker, permisos de usuario y el estado del daemon.
- `dockaudit.container_audit.container_scanner.ContainerAudit`
  - Inspecciona contenedores en ejecución y analiza su configuración de seguridad.
- `dockaudit.image_analysis`
  - `package_extractor.py`
    - Extrae dependencias de imágenes usando gestores de paquetes como `dpkg`, `rpm` y `apk`.
  - `binary_analyzer.py`
    - Realiza análisis estático de binarios y ficheros dentro de la imagen.
  - `sbom_generator.py`
    - Genera un SBOM en formato JSON que describe los componentes software encontrados.
  - `image_scanner.py`
    - Escanea metadatos y contenidos de imágenes Docker.
- `dockaudit.sca`
  - `nvd_parser.py`
    - Procesa los datos de NVD para correlacionar vulnerabilidades.
  - `vulnerability_matcher.py`
    - Relaciona dependencias y hallazgos con CVE y clasifica riesgos.
- `dockaudit.reporting.report_generator.ReportGenerator`
  - Genera salidas en HTML y JSON con los resultados de la auditoría.

### Flujo de ejecución

1. `main.py` lanza la auditoría para un objetivo local o de contenedor.
2. El `Orchestrator` valida el entorno y arranca cada módulo de auditoría.
3. El módulo de análisis de imágenes extrae dependencias y binarios para crear la SBOM.
4. El módulo SCA correlaciona los componentes con la base de datos NVD para identificar vulnerabilidades.
5. El `ReportGenerator` combina hallazgos, nivel de riesgo y recomendaciones en un informe.

### Cobertura de objetivos

- La auditoría de host y contenedores aborda la evaluación de configuraciones Docker y aislamiento.
- La extracción de paquetes y el análisis binario cubren el análisis SCA y la identificación de componentes.
- La generación de SBOM proporciona trazabilidad de los artefactos software presentes en la imagen.
- La correlación NVD y la clasificación de riesgos permiten priorizar hallazgos según su criticidad.
- La documentación de recomendaciones apoya las medidas de hardening y buenas prácticas.
