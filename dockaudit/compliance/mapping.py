"""
CIS Docker Benchmark to ISO/IEC 27001 compliance mapping.
Integrates all CIS Docker Benchmark 1.6 controls with ISO/IEC 27001:2022 Annexo A mappings.
"""

COMPLIANCE_MAPPING = {
    # ============================================================
    # SECTION 1: DOCKER HOST CONFIGURATION
    # ============================================================
    "CIS-1.1": {
        "title": "Separar partición /var",
        "description": "Crear una partición separada para /var en el host Docker.",
        "iso27001_controls": [
            {
                "code": "A.8.19",
                "domain": "Asset Management & Hardening",
                "title": "Installation and management of assets"
            },
            {
                "code": "A.8.20",
                "domain": "Network Security",
                "title": "Networks management"
            }
        ],
        "severity": "medium",
        "implementation": "host_audit.check_var_partition",
        "remediation": "Crear partición dedicada para /var durante instalación del sistema",
        "category": "Host Configuration"
    },

    "CIS-1.2": {
        "title": "Separar partición /var/lib/docker",
        "description": "Crear una partición separada para el directorio de datos de Docker.",
        "iso27001_controls": [
            {
                "code": "A.8.19",
                "domain": "Asset Management & Hardening",
                "title": "Installation and management of assets"
            }
        ],
        "severity": "medium",
        "implementation": "host_audit.check_docker_data_partition",
        "remediation": "Crear partición dedicada para /var/lib/docker",
        "category": "Host Configuration"
    },

    "CIS-1.3": {
        "title": "Separar partición /var/log",
        "description": "Crear una partición separada para los logs.",
        "iso27001_controls": [
            {
                "code": "A.8.19",
                "domain": "Asset Management & Hardening",
                "title": "Installation and management of assets"
            }
        ],
        "severity": "medium",
        "implementation": "host_audit.check_log_partition",
        "remediation": "Crear partición dedicada para /var/log",
        "category": "Host Configuration"
    },

    "CIS-1.4": {
        "title": "Separar partición /var/log/audit",
        "description": "Crear una partición separada para los logs de auditoría.",
        "iso27001_controls": [
            {
                "code": "A.8.19",
                "domain": "Asset Management & Hardening",
                "title": "Installation and management of assets"
            },
            {
                "code": "A.8.15",
                "domain": "Logging",
                "title": "Logging"
            }
        ],
        "severity": "medium",
        "implementation": "host_audit.check_audit_partition",
        "remediation": "Crear partición dedicada para /var/log/audit",
        "category": "Host Configuration"
    },

    "CIS-1.5": {
        "title": "Configurar parámetros restrictivos del kernel",
        "description": "Aplicar parámetros de kernel restrictivos para mayor seguridad.",
        "iso27001_controls": [
            {
                "code": "A.8.20",
                "domain": "Network Security",
                "title": "Networks management"
            }
        ],
        "severity": "high",
        "implementation": "host_audit.check_kernel_parameters",
        "remediation": "Configurar sysctl para parámetros de kernel restrictivos (net.ipv4.conf.all.forwarding, etc.)",
        "category": "Host Configuration"
    },

    "CIS-1.6": {
        "title": "Deshabilitar carga de módulos del kernel",
        "description": "Asegurar que la carga de módulos del kernel está controlada.",
        "iso27001_controls": [
            {
                "code": "A.8.20",
                "domain": "Network Security",
                "title": "Networks management"
            }
        ],
        "severity": "high",
        "implementation": "host_audit.check_kernel_modules",
        "remediation": "Configurar modprobe para deshabilitar módulos innecesarios",
        "category": "Host Configuration"
    },

    # ============================================================
    # SECTION 2: DOCKER DAEMON CONFIGURATION
    # ============================================================
    "CIS-2.3": {
        "title": "Permisos del socket del daemon",
        "description": "Asegurar permisos restrictivos en /var/run/docker.sock.",
        "iso27001_controls": [
            {"code": "A.8.2", "domain": "Access Control", "title": "Management of access rights"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_socket_permissions",
        "remediation": "Ajustar permisos a 660 y propiedad a root:docker",
        "category": "Host Configuration"
    },

    "CIS-2.4": {
        "title": "Propiedad del socket del daemon",
        "description": "Asegurar que /var/run/docker.sock pertenece al usuario y grupo correctos.",
        "iso27001_controls": [
            {"code": "A.8.2", "domain": "Access Control", "title": "Management of access rights"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_socket_ownership",
        "remediation": "chown root:docker /var/run/docker.sock",
        "category": "Host Configuration"
    },

    "CIS-2.5": {
        "title": "Verificación de certificados del daemon",
        "description": "Verificar certificados TLS configurados para el daemon.",
        "iso27001_controls": [
            {"code": "A.8.15", "domain": "Logging/Operations", "title": "Logging and monitoring"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_certificates",
        "remediation": "Configurar TLS con certificados válidos para API del daemon",
        "category": "Host Configuration"
    },

    "CIS-2.6": {
        "title": "Habilitar TLS en el daemon",
        "description": "Asegurar que el daemon exige TLS para conexiones remotas.",
        "iso27001_controls": [
            {"code": "A.8.15", "domain": "Logging/Operations", "title": "Logging and monitoring"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_tls",
        "remediation": "Configurar TLS y deshabilitar conexiones inseguras",
        "category": "Host Configuration"
    },

    "CIS-2.7": {
        "title": "Autenticación/Autorización del daemon",
        "description": "Asegurar mecanismos de autenticación y autorización para la API del daemon.",
        "iso27001_controls": [
            {"code": "A.8.2", "domain": "Access Control", "title": "Management of access rights"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_auth",
        "remediation": "Implementar autenticación y limitar accesos a la API",
        "category": "Host Configuration"
    },

    "CIS-2.8": {
        "title": "Certificados de registro y comunicación",
        "description": "Asegurar certificados para comunicación con registries privados.",
        "iso27001_controls": [
            {"code": "A.8.24", "domain": "Network Security", "title": "Network protection"}
        ],
        "severity": "medium",
        "implementation": "host_audit.check_registry_certificates",
        "remediation": "Configurar certificados de confianza para registries",
        "category": "Registry Security"
    },

    "CIS-2.1": {
        "title": "Ejecutar el daemon Docker en un grupo no-raíz",
        "description": "El daemon Docker debe ejecutarse bajo un usuario no-root para limitar los daños potenciales por vulnerabilidades.",
        "iso27001_controls": [
            {
                "code": "A.8.2",
                "domain": "Access Control",
                "title": "Management of access rights"
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
                "code": "A.8.2",
                "domain": "Access Control",
                "title": "Management of access rights"
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
                "code": "A.8.15",
                "domain": "Logging",
                "title": "Logging"
            }
        ],
        "severity": "medium",
        "implementation": "host_audit.check_docker_version",
        "remediation": "Actualizar Docker Engine a la última versión estable disponible",
        "category": "Patch Management"
    },

    "CIS-2.10": {
        "title": "Deshabilitar userland proxy",
        "description": "Deshabilitar userland proxy para mejorar seguridad de networking.",
        "iso27001_controls": [
            {"code": "A.8.24", "domain": "Network Security", "title": "Network protection"}
        ],
        "severity": "medium",
        "implementation": "host_audit.check_userland_proxy_disabled",
        "remediation": "Configurar daemon.json: \"userland-proxy\": false",
        "category": "Networking"
    },

    "CIS-2.11": {
        "title": "Deshabilitar inter-container communication (icc)",
        "description": "Deshabilitar icc para prevenir comunicación no deseada entre contenedores.",
        "iso27001_controls": [
            {"code": "A.8.24", "domain": "Network Security", "title": "Network protection"}
        ],
        "severity": "medium",
        "implementation": "host_audit.check_icc_disabled",
        "remediation": "Configurar daemon.json: \"icc\": false",
        "category": "Networking"
    },

    "CIS-2.12": {
        "title": "Configurar controlador de logs apropiado",
        "description": "Configurar un driver de logs seguro y centralizado.",
        "iso27001_controls": [
            {"code": "A.8.15", "domain": "Logging", "title": "Logging"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_log_driver",
        "remediation": "Configurar log-driver a syslog/journald o driver centralizado",
        "category": "Logging"
    },

    # ============================================================
    # SECTION 3: DOCKER DAEMON RUNTIME OPTIONS
    # ============================================================
    "CIS-3.1": {
        "title": "No usar --privileged con contenedores en producción",
        "description": "Los contenedores no deben ejecutarse con el flag --privileged en producción.",
        "iso27001_controls": [
            {"code": "A.8.1", "domain": "Access Control", "title": "Access control policy"},
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"}
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
            {"code": "A.8.1", "domain": "Access Control", "title": "Access control policy"},
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
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
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"},
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"}
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
                "code": "A.8.1",
                "domain": "Access Control",
                "title": "Access control policy"
            },
            {
                "code": "A.8.19",
                "domain": "Hardening",
                "title": "Hardening"
            }
        ],
        "severity": "medium",
        "implementation": "container_audit.check_sensitive_files_readonly",
        "remediation": "Montar con -v /etc/shadow:/etc/shadow:ro",
        "category": "Container Runtime"
    },

    "CIS-3.5": {
        "title": "Permisos de archivos de configuración del daemon",
        "description": "Asegurar permisos restrictivos en archivos de configuración del daemon Docker.",
        "iso27001_controls": [
            {"code": "A.8.1", "domain": "Access Control", "title": "Access control policy"},
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_file_permissions",
        "remediation": "Ajustar permisos de archivos de configuración a 600/640",
        "category": "Host Configuration"
    },

    "CIS-3.6": {
        "title": "Propiedad de archivos de configuración del daemon",
        "description": "Asegurar que los archivos de configuración pertenecen a root y grupo apropiado.",
        "iso27001_controls": [
            {"code": "A.8.1", "domain": "Access Control", "title": "Access control policy"},
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_file_ownership",
        "remediation": "Ajustar propiedad de archivos de configuración a root:root o root:docker",
        "category": "Host Configuration"
    },

    # ============================================================
    # SECTION 4: CONTAINER IMAGES AND BUILD FILE
    # ============================================================
    "CIS-4.1": {
        "title": "Crear y usar imágenes personalizadas",
        "description": "Crear imágenes Docker personalizadas en lugar de usar imágenes genéricas.",
        "iso27001_controls": [
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"},
            {"code": "A.8.25", "domain": "Secure Development", "title": "Secure development"}
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
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"},
            {"code": "A.8.25", "domain": "Secure Development", "title": "Secure development"}
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
            {"code": "A.8.8", "domain": "Vulnerability Management", "title": "Vulnerability management"}
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
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"},
            {"code": "A.8.25", "domain": "Secure Development", "title": "Secure development"}
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
                "code": "A.8.8",
                "domain": "Vulnerability Management",
                "title": "Vulnerability management"
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
                "code": "A.8.1",
                "domain": "Access Control",
                "title": "Access control policy"
            }
        ],
        "severity": "high",
        "implementation": "container_audit.check_bind_mount_sensitive",
        "remediation": "Evitar montar directorios como / o /etc directamente",
        "category": "Container Runtime"
    },

    "CIS-4.5": {
        "title": "No incluir secretos en las imágenes",
        "description": "Asegurarse de que las imágenes no contengan secretos hardcodeados.",
        "iso27001_controls": [
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"},
            {"code": "A.8.8", "domain": "Vulnerability Management", "title": "Vulnerability management"}
        ],
        "severity": "critical",
        "implementation": "image_analysis.check_no_secrets_in_images",
        "remediation": "Remover secretos y usar herramientas de secret scanning antes del push",
        "category": "Image Security"
    },

    "CIS-4.6": {
        "title": "No usar credenciales en variables de entorno dentro de imagen",
        "description": "Evitar variables de entorno con credenciales en las imágenes.",
        "iso27001_controls": [
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"}
        ],
        "severity": "high",
        "implementation": "image_analysis.check_env_in_images",
        "remediation": "Eliminar env sensibles y usar runtime secrets",
        "category": "Image Security"
    },

    "CIS-4.8": {
        "title": "Definir healthchecks en Dockerfile",
        "description": "Incluir instrucciones HEALTHCHECK para garantizar disponibilidad y detectar fallos.",
        "iso27001_controls": [
            {"code": "A.8.15", "domain": "Logging", "title": "Logging"}
        ],
        "severity": "medium",
        "implementation": "image_analysis.check_healthchecks",
        "remediation": "Agregar HEALTHCHECK en Dockerfile",
        "category": "Image Security"
    },

    "CIS-4.9": {
        "title": "Limitar PIDs cgroup",
        "description": "Establecer límites de PIDs por contenedor para evitar fork bombs.",
        "iso27001_controls": [
            {"code": "A.12.6.1", "domain": "Operations Security", "title": "Management of technical vulnerabilities"}
        ],
        "severity": "medium",
        "implementation": "container_audit.check_pids_limit",
        "remediation": "Usar --pids-limit al iniciar contenedores",
        "category": "Resource Controls"
    },

    # ============================================================
    # SECTION 5: CONTAINER RUNTIME
    # ============================================================
    "CIS-5.1": {
        "title": "Verificar las políticas de AppArmor",
        "description": "Usar AppArmor o SELinux para controlar el acceso de contenedores.",
        "iso27001_controls": [
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"},
            {"code": "A.8.22", "domain": "Container Security", "title": "Container security"}
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
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"},
            {"code": "A.8.22", "domain": "Container Security", "title": "Container security"}
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
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"},
            {"code": "A.8.22", "domain": "Container Security", "title": "Container security"}
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
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"},
            {"code": "A.8.22", "domain": "Container Security", "title": "Container security"}
        ],
        "severity": "critical",
        "implementation": "container_audit.check_apparmor_disabled",
        "remediation": "No usar flags que deshabiliten AppArmor/SELinux",
        "category": "Container Runtime"
    },

    "CIS-5.4": {
        "title": "Restringir tráfico entre contenedores",
        "description": "Aplicar políticas de red para restringir el tráfico entre contenedores cuando no sea necesario.",
        "iso27001_controls": [
            {"code": "A.8.22", "domain": "Container Security", "title": "Container network security"},
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
        ],
        "severity": "medium",
        "implementation": "container_audit.check_container_network_policies",
        "remediation": "Configurar políticas de red (NetworkPolicies, iptables) para restringir comunicación",
        "category": "Networking"
    },

    "CIS-5.6": {
        "title": "Configurar políticas de reinicio apropiadas",
        "description": "Evitar configuraciones de reinicio que oculten fallos repetidos.",
        "iso27001_controls": [
            {"code": "A.8.22", "domain": "Container Security", "title": "Container network security"}
        ],
        "severity": "low",
        "implementation": "container_audit.check_restart_policy",
        "remediation": "Usar restart policies que no oculten bucles de reinicio",
        "category": "Runtime"
    },

    "CIS-5.7": {
        "title": "Limitar uso de CPU",
        "description": "Establecer límites de CPU para contenedores para prevenir agotamiento de recursos.",
        "iso27001_controls": [
            {"code": "A.8.22", "domain": "Container Security", "title": "Container network security"},
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
        ],
        "severity": "medium",
        "implementation": "container_audit.check_cpu_limits",
        "remediation": "Configurar --cpus o CPU shares apropiados",
        "category": "Resource Controls"
    },

    "CIS-5.8": {
        "title": "Limitar memoria de contenedores",
        "description": "Establecer límites de memoria para cada contenedor.",
        "iso27001_controls": [
            {"code": "A.8.1", "domain": "Access Control", "title": "Access control policy"},
            {"code": "A.8.22", "domain": "Container Security", "title": "Container network security"},
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
        ],
        "severity": "high",
        "implementation": "container_audit.check_memory_limits",
        "remediation": "Configurar --memory y --memory-swap para contenedores críticos",
        "category": "Resource Controls"
    },

    "CIS-5.9": {
        "title": "Sistema de archivos raíz en solo lectura",
        "description": "Montar el sistema de archivos raíz del contenedor como read-only cuando sea posible.",
        "iso27001_controls": [
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"},
            {"code": "A.8.22", "domain": "Container Security", "title": "Container network security"}
        ],
        "severity": "high",
        "implementation": "container_audit.check_rootfs_readonly",
        "remediation": "Usar --read-only para contenedores que no requieren escritura",
        "category": "Runtime"
    },

    "CIS-5.10": {
        "title": "Verificar permisos de volúmenes montados",
        "description": "Asegurarse de que los volúmenes montados no introduzcan permisos inseguros.",
        "iso27001_controls": [
            {"code": "A.8.22", "domain": "Container Security", "title": "Container security"},
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
        ],
        "severity": "medium",
        "implementation": "container_audit.check_volume_permissions",
        "remediation": "Revisar y ajustar permisos de volúmenes montados",
        "category": "Runtime"
    },

    "CIS-5.11": {
        "title": "Configurar CPU shares",
        "description": "Establecer CPU shares para evitar que un contenedor consuma todos los recursos.",
        "iso27001_controls": [
            {"code": "A.8.22", "domain": "Container Security", "title": "Container security"},
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
        ],
        "severity": "low",
        "implementation": "container_audit.check_cpu_shares",
        "remediation": "Establecer --cpu-shares apropiado",
        "category": "Resource Controls"
    },

    # ============================================================
    # SECTION 6: CONTAINER IMAGES AND REGISTRIES
    # ============================================================
    "CIS-6.2": {
        "title": "Escanear imágenes en busca de vulnerabilidades",
        "description": "Escanear imágenes con herramientas de análisis de vulnerabilidades.",
        "iso27001_controls": [
            {
                "code": "A.8.8",
                "domain": "Vulnerability Management",
                "title": "Vulnerability management"
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
                "code": "A.8.1",
                "domain": "Access Control",
                "title": "Access control policy"
            }
        ],
        "severity": "high",
        "implementation": "orchestrator.check_trusted_images_policy",
        "remediation": "Implementar admission controller o policy como OPA/Gatekeeper",
        "category": "Image Security"
    },

    "CIS-6.1": {
        "title": "Restringir registries usados",
        "description": "Limitar registries permitidos y bloquear registries inseguros.",
        "iso27001_controls": [
            {"code": "A.8.2", "domain": "Access Control", "title": "Management of access rights"}
        ],
        "severity": "high",
        "implementation": "orchestrator.check_allowed_registries",
        "remediation": "Implementar whitelist de registries y controlar pull/push",
        "category": "Registry Security"
    },

    "CIS-6.4": {
        "title": "Cifrado de secretos en repositorios",
        "description": "Asegurar que los secretos están cifrados cuando son almacenados.",
        "iso27001_controls": [
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
        ],
        "severity": "high",
        "implementation": "orchestrator.check_secrets_encryption",
        "remediation": "Usar vault o servicios gestionados para almacenar secretos",
        "category": "Secrets Management"
    },

    "CIS-6.5": {
        "title": "Propiedad segura de docker.sock",
        "description": "Asegurar propiedad y permisos correctos de docker.sock para evitar escalada.",
        "iso27001_controls": [
            {"code": "A.8.19", "domain": "Hardening", "title": "Hardening"}
        ],
        "severity": "critical",
        "implementation": "host_audit.check_dockersock_ownership",
        "remediation": "Ajustar propietario y permisos de /var/run/docker.sock",
        "category": "Host Configuration"
    },

    "CIS-6.6": {
        "title": "Rotación de secretos",
        "description": "Implementar rotación periódica de secretos en pipelines y plataformas.",
        "iso27001_controls": [
            {"code": "A.8.3", "domain": "Privileged Access", "title": "Privileged access management"}
        ],
        "severity": "medium",
        "implementation": "orchestrator.check_secrets_rotation",
        "remediation": "Configurar rotación automática de secretos",
        "category": "Secrets Management"
    },

    "CIS-6.7": {
        "title": "Autenticación para pull/push",
        "description": "Asegurar autenticación fuerte para actividades pull/push en registries.",
        "iso27001_controls": [
            {"code": "A.8.2", "domain": "Access Control", "title": "Management of access rights"}
        ],
        "severity": "high",
        "implementation": "orchestrator.check_registry_auth",
        "remediation": "Forzar autenticación y revisar tokens de acceso",
        "category": "Registry Security"
    },

    "CIS-6.8": {
        "title": "Habilitar logging de auditoría",
        "description": "Registrar eventos relevantes de imágenes y pulls/pushes para auditoría.",
        "iso27001_controls": [
            {"code": "A.8.15", "domain": "Logging", "title": "Logging"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_audit_logging",
        "remediation": "Habilitar y centralizar logs de auditoría",
        "category": "Auditing"
    },

    "CIS-6.9": {
        "title": "Verificar logs de auditoría",
        "description": "Corroborar que los logs de auditoría son revisados y almacenados.",
        "iso27001_controls": [
            {"code": "A.8.15", "domain": "Logging", "title": "Logging"}
        ],
        "severity": "medium",
        "implementation": "host_audit.check_audit_log_review",
        "remediation": "Establecer procesos de revisión de logs",
        "category": "Auditing"
    },

    "CIS-6.10": {
        "title": "Auditoría del daemon",
        "description": "Asegurar que el daemon y eventos de contenedores son auditados.",
        "iso27001_controls": [
            {"code": "A.8.15", "domain": "Logging", "title": "Logging"}
        ],
        "severity": "high",
        "implementation": "host_audit.check_daemon_auditing",
        "remediation": "Configurar auditd y registrar llamadas relevantes",
        "category": "Auditing"
    }
}
