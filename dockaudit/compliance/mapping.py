"""
CIS Docker Benchmark to ISO/IEC 27001 compliance mapping.
"""

COMPLIANCE_MAPPING = {
    # ============================================================
    # SECTION 2: DOCKER DAEMON CONFIGURATION
    # ============================================================
    "CIS-2.1": {
        "title": "Ejecutar el daemon Docker en un grupo no-raíz",
        "description": "El daemon Docker debe ejecutarse bajo un usuario no-root para limitar los daños potenciales por vulnerabilidades.",
        "iso27001_controls": [
            {
                "code": "A.9.2.1",
                "domain": "Access Control",
                "title": "User registration and de-registration"
            }
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_user",
        "remediation": "Crear usuario no-root, añadirlo al grupo docker, cambiar propiedad de /var/run/docker.sock",
        "category": "Access Control"
    },
    
    "CIS-2.2": {
        "title": "Separar el directorio de datos del daemon en una partición",
        "description": "El directorio de datos del daemon Docker debe estar en una partición separada.",
        "iso27001_controls": [
            {
                "code": "A.9.1.1",
                "domain": "Access Control",
                "title": "Access control policy"
            }
        ],
        "severity": "medium",
        "implementation": "host_audit.check_daemon_data_partition",
        "remediation": "Configurar daemon.json con data-root en partición separada",
        "category": "Hardening"
    },

    "CIS-2.9": {
        "title": "Mantener la versión correcta de Docker",
        "description": "Mantener Docker Engine actualizado con la última versión estable.",
        "iso27001_controls": [
            {
                "code": "A.12.6.1",
                "domain": "Operations Security",
                "title": "Management of technical vulnerabilities"
            }
        ],
        "severity": "medium",
        "implementation": "host_audit.check_docker_version",
        "remediation": "Actualizar Docker Engine a la última versión estable disponible",
        "category": "Patch Management"
    },

    # ============================================================
    # SECTION 3: DOCKER DAEMON RUNTIME OPTIONS
    # ============================================================
    "CIS-3.1": {
        "title": "No usar --privileged con contenedores en producción",
        "description": "Los contenedores no deben ejecutarse con el flag --privileged en producción.",
        "iso27001_controls": [
            {
                "code": "A.9.1.1",
                "domain": "Access Control",
                "title": "Access control policy"
            },
            {
                "code": "A.9.2.5",
                "domain": "Access Control",
                "title": "Access rights review"
            }
        ],
        "severity": "critical",
        "implementation": "container_audit.check_privileged_mode",
        "remediation": "Ejecutar contenedores sin --privileged, usar capacidades específicas con --cap-drop y --cap-add",
        "category": "Container Runtime"
    },

    "CIS-3.2": {
        "title": "No usar --user=root",
        "description": "Usar el flag --user para ejecutar contenedores con usuarios no-root.",
        "iso27001_controls": [
            {
                "code": "A.9.2.1",
                "domain": "Access Control",
                "title": "User registration and de-registration"
            }
        ],
        "severity": "high",
        "implementation": "container_audit.check_user_not_root",
        "remediation": "Especificar USER en Dockerfile o usar --user en docker run",
        "category": "Container Runtime"
    },

    "CIS-3.3": {
        "title": "Usar capacidades Linux restrictivas",
        "description": "Remover capabilities innecesarias y mantener solo las requeridas.",
        "iso27001_controls": [
            {
                "code": "A.9.2.5",
                "domain": "Access Control",
                "title": "Access rights review"
            }
        ],
        "severity": "high",
        "implementation": "container_audit.check_linux_capabilities",
        "remediation": "Usar --cap-drop ALL y luego --cap-add solo para capabilities necesarias",
        "category": "Container Runtime"
    },

    "CIS-3.4": {
        "title": "Montar /etc/shadow como read-only",
        "description": "Los archivos sensibles como /etc/shadow deben montarse como read-only.",
        "iso27001_controls": [
            {
                "code": "A.9.1.1",
                "domain": "Access Control",
                "title": "Access control policy"
            }
        ],
        "severity": "medium",
        "implementation": "container_audit.check_sensitive_files_readonly",
        "remediation": "Montar con -v /etc/shadow:/etc/shadow:ro",
        "category": "Container Runtime"
    },

    # ============================================================
    # SECTION 4: CONTAINER IMAGES AND BUILD FILE
    # ============================================================
    "CIS-4.1": {
        "title": "Crear y usar imágenes personalizadas",
        "description": "Crear imágenes Docker personalizadas en lugar de usar imágenes genéricas.",
        "iso27001_controls": [
            {
                "code": "A.14.2.1",
                "domain": "Secure Development",
                "title": "Secure development policy"
            }
        ],
        "severity": "medium",
        "implementation": "image_analysis.check_custom_images",
        "remediation": "Crear Dockerfile personalizado con base images de confianza",
        "category": "Image Security"
    },

    "CIS-4.2": {
        "title": "Verificar integridad de imágenes",
        "description": "Verificar la integridad de imágenes Docker usando firmas digitales.",
        "iso27001_controls": [
            {
                "code": "A.14.2.1",
                "domain": "Secure Development",
                "title": "Secure development policy"
            }
        ],
        "severity": "high",
        "implementation": "image_analysis.check_image_signature_verification",
        "remediation": "Habilitar Docker Content Trust y verificar firmas de imágenes",
        "category": "Image Security"
    },

    "CIS-4.3": {
        "title": "Instalar solo paquetes necesarios",
        "description": "Minimizar la superficie de ataque instalando solo paquetes esenciales.",
        "iso27001_controls": [
            {
                "code": "A.12.6.2",
                "domain": "Operations Security",
                "title": "Restrictions on software installation"
            }
        ],
        "severity": "medium",
        "implementation": "image_analysis.check_minimal_packages",
        "remediation": "Usar imágenes base mínimas (alpine, distroless) y remover herramientas de build",
        "category": "Image Security"
    },

    "CIS-4.4": {
        "title": "Usar imágenes base de confianza",
        "description": "Usar solo imágenes base de registros confiables y verificadas.",
        "iso27001_controls": [
            {
                "code": "A.14.2.5",
                "domain": "Secure Development",
                "title": "Secure development environment"
            }
        ],
        "severity": "high",
        "implementation": "image_analysis.check_trusted_base_images",
        "remediation": "Usar imágenes oficiales o de registros privados verificados",
        "category": "Image Security"
    },

    "CIS-4.7": {
        "title": "Remover SETUID y SETGID en imágenes",
        "description": "Remover binarios con bit SETUID/SETGID innecesarios.",
        "iso27001_controls": [
            {
                "code": "A.14.2.1",
                "domain": "Secure Development",
                "title": "Secure development policy"
            }
        ],
        "severity": "high",
        "implementation": "binary_analyzer.check_setuid_binaries",
        "remediation": "Usar 'find / -perm /6000 -exec chmod a-s {} +' en Dockerfile",
        "category": "Image Security"
    },

    "CIS-4.10": {
        "title": "No usar bind mount de volúmenes sensibles",
        "description": "No montar volúmenes que contengan datos sensibles del host.",
        "iso27001_controls": [
            {
                "code": "A.9.1.1",
                "domain": "Access Control",
                "title": "Access control policy"
            }
        ],
        "severity": "high",
        "implementation": "container_audit.check_bind_mount_sensitive",
        "remediation": "Evitar montar directorios como / o /etc directamente",
        "category": "Container Runtime"
    },

    # ============================================================
    # SECTION 5: CONTAINER RUNTIME
    # ============================================================
    "CIS-5.1": {
        "title": "Verificar las políticas de AppArmor",
        "description": "Usar AppArmor o SELinux para controlar el acceso de contenedores.",
        "iso27001_controls": [
            {
                "code": "A.12.6.1",
                "domain": "Operations Security",
                "title": "Management of technical vulnerabilities"
            }
        ],
        "severity": "high",
        "implementation": "host_audit.check_apparmor_selinux",
        "remediation": "Habilitar AppArmor/SELinux en el host y crear políticas restrictivas",
        "category": "Hardening"
    },

    "CIS-5.2": {
        "title": "Usar Seccomp para restringir syscalls",
        "description": "Aplicar perfiles Seccomp para limitar system calls disponibles.",
        "iso27001_controls": [
            {
                "code": "A.12.6.1",
                "domain": "Operations Security",
                "title": "Management of technical vulnerabilities"
            }
        ],
        "severity": "high",
        "implementation": "container_audit.check_seccomp_profile",
        "remediation": "Usar --security-opt seccomp=/path/to/profile.json",
        "category": "Container Runtime"
    },

    "CIS-5.3": {
        "title": "Usar SELinux para limitar contenedores",
        "description": "Configurar SELinux labels para restricciones adicionales.",
        "iso27001_controls": [
            {
                "code": "A.12.6.1",
                "domain": "Operations Security",
                "title": "Management of technical vulnerabilities"
            }
        ],
        "severity": "high",
        "implementation": "host_audit.check_selinux_labels",
        "remediation": "Usar --security-opt label=type:svirt_sandbox_file_t",
        "category": "Hardening"
    },

    "CIS-5.5": {
        "title": "No deshabilitar la actualización de restricciones",
        "description": "No usar --security-opt='apparmor=unconfined'.",
        "iso27001_controls": [
            {
                "code": "A.12.6.1",
                "domain": "Operations Security",
                "title": "Management of technical vulnerabilities"
            }
        ],
        "severity": "critical",
        "implementation": "container_audit.check_apparmor_disabled",
        "remediation": "No usar flags que deshabiliten AppArmor/SELinux",
        "category": "Container Runtime"
    },

    # ============================================================
    # SECTION 6: CONTAINER IMAGES AND REGISTRIES
    # ============================================================
    "CIS-6.2": {
        "title": "Escanear imágenes en busca de vulnerabilidades",
        "description": "Escanear imágenes con herramientas de análisis de vulnerabilidades.",
        "iso27001_controls": [
            {
                "code": "A.12.6.1",
                "domain": "Operations Security",
                "title": "Management of technical vulnerabilities"
            }
        ],
        "severity": "high",
        "implementation": "image_analysis.check_vulnerability_scan",
        "remediation": "Usar herramientas como Trivy, Clair o escaneo nativo de registros",
        "category": "Image Security"
    },

    "CIS-6.3": {
        "title": "Permitir solo imágenes confiables",
        "description": "Implementar políticas para permitir solo imágenes verificadas.",
        "iso27001_controls": [
            {
                "code": "A.9.1.1",
                "domain": "Access Control",
                "title": "Access control policy"
            }
        ],
        "severity": "high",
        "implementation": "orchestrator.check_trusted_images_policy",
        "remediation": "Implementar admission controller o policy como OPA/Gatekeeper",
        "category": "Image Security"
    },

    # ============================================================
    # SECTION 7: CONTAINER ORCHESTRATION
    # ============================================================
    "CIS-7.1": {
        "title": "Actualizar Kubernetes/Orchestrator",
        "description": "Mantener la versión actualizada del orquestador.",
        "iso27001_controls": [
            {
                "code": "A.12.6.1",
                "domain": "Operations Security",
                "title": "Management of technical vulnerabilities"
            }
        ],
        "severity": "medium",
        "implementation": "orchestrator.check_orchestrator_version",
        "remediation": "Actualizar a la última versión estable del orquestador",
        "category": "Patch Management"
    },

    # ============================================================
    # SECTION 8: DOCKER SWARM CONFIGURATION
    # ============================================================
    "CIS-8.1": {
        "title": "Usar secrets para gestionar credenciales",
        "description": "Usar el sistema de secrets del orquestador en lugar de variables de entorno.",
        "iso27001_controls": [
            {
                "code": "A.9.4.2",
                "domain": "Access Control",
                "title": "Secure log-on procedures"
            }
        ],
        "severity": "high",
        "implementation": "container_audit.check_secrets_usage",
        "remediation": "Usar docker secrets o equivalente en Kubernetes",
        "category": "Secrets Management"
    },

    "CIS-8.2": {
        "title": "No usar variables de entorno para datos sensibles",
        "description": "Evitar pasar credenciales mediante variables de entorno.",
        "iso27001_controls": [
            {
                "code": "A.9.4.2",
                "domain": "Access Control",
                "title": "Secure log-on procedures"
            }
        ],
        "severity": "critical",
        "implementation": "container_audit.check_env_sensitive_data",
        "remediation": "Usar secrets, ConfigMaps o vault para datos sensibles",
        "category": "Secrets Management"
    }
}
