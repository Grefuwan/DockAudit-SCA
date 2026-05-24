# NVD y análisis de vulnerabilidades

Este documento describe la metodología utilizada para correlacionar componentes extraídos de imágenes Docker con vulnerabilidades de la base de datos NVD.

## Metodología

1. Extraer componentes
   - El módulo `dockaudit.image_analysis.package_extractor.PackageExtractor` inspecciona las imágenes Docker y extrae paquetes mediante los gestores compatibles (`dpkg`, `rpm`, `apk`).
   - Los paquetes se registran como componentes dentro de la SBOM generada.

2. Generar SBOM
   - `dockaudit.image_analysis.sbom_generator.SBOMGenerator` crea un archivo SBOM en formato JSON con los componentes descubiertos.
   - La SBOM permite documentar las dependencias presentes en la imagen auditada.

3. Cargar feed NVD
   - El módulo `dockaudit.sca.nvd_parser.NVDParser` soporta feeds en formato JSON y JSON.GZ.
   - Se puede utilizar un feed oficial descargado desde `https://nvd.nist.gov/vuln/data-feeds`.

4. Correlacionar con vulnerabilidades
   - `dockaudit.sca.vulnerability_matcher.VulnerabilityMatcher` compara los componentes extraídos con las entradas NVD.
   - La correspondencia se basa en tokens extraídos de nombres, versiones y CPEs.

5. Generar informe final
   - El `ReportGenerator` combina hallazgos de host, contenedores, imágenes, binarios y vulnerabilidades.
   - El informe se genera en HTML o JSON según el parámetro `--output`.

## Uso

### Ejecutar la auditoría con un feed NVD

```bash
python main.py --target local --output html --sbom-dir reports/sbom --nvd-feed sample_nvd.json
```

### Descargar un feed NVD real

Utiliza el script proporcionado en `scripts/download_nvd_feed.sh` para descargar un feed oficial.

```bash
bash scripts/download_nvd_feed.sh 2024 feeds
```

El archivo resultante será:

```bash
feeds/nvdcve-1.1-2024.json.gz
```

Y luego ejecútalo con:

```bash
python main.py --target local --output html --sbom-dir reports/sbom --nvd-feed feeds/nvdcve-1.1-2024.json.gz
```

## Recomendaciones

- Para la defensa de TFM, es preferible usar un feed local descargado y reproducible.
- Un sistema de base de datos puede ser útil cuando la ingestión y búsqueda de vulnerabilidades se vuelve masiva, pero para la prueba de concepto y auditoría local un feed JSON/GZ es suficiente.
- Si decides evolucionar el proyecto, una base de datos como SQLite o PostgreSQL puede almacenar pares CPE–CVE y acelerar las búsquedas.
