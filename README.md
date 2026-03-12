# DockAudit-SCA

Security auditing tool for Docker environments with integrated Software Composition Analysis (SCA) and SBOM generation.

## Features

- Docker host configuration auditing
- Container runtime security analysis
- Docker image vulnerability scanning
- Binary and dependency analysis
- SBOM generation (CycloneDX)
- Vulnerability matching using NVD
- HTML report generation

## Architecture

The system follows a modular architecture:

- Orchestrator
- Host Audit Module
- Container Analysis Module
- Image & Binary Analysis Module
- SCA Module
- Reporting Module

## Execution

```bash
python -m dockaudit.main --target local --output report.html
