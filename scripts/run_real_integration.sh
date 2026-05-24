#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] docker CLI no encontrado. Intentando instalar Docker..."
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "ubuntu" ] || [ "$ID" = "debian" ]; then
      echo "[*] Sistema basado en Debian detectado."
      echo "[*] Ejecuta los siguientes comandos para instalar Docker:"
      echo ""
      echo "  sudo apt update"
      echo "  sudo apt install -y docker.io docker-compose"
      echo "  sudo systemctl start docker"
      echo "  sudo usermod -aG docker \$USER"
      echo "  newgrp docker"
      echo ""
      exit 1
    fi
  fi
  echo "ERROR: docker CLI no está instalado y no se puede detectar el sistema operativo."
  echo "Visita https://docs.docker.com/engine/install/ para instrucciones de instalación."
  exit 1
fi

if [ ! -S /var/run/docker.sock ]; then
  echo "ERROR: No se encuentra el socket Docker (/var/run/docker.sock)."
  echo "Asegúrate de que el daemon Docker está en ejecución:"
  echo "  sudo systemctl start docker"
  exit 1
fi

IMAGE_NAME="test-audit-image"
CONTAINER_NAME="test-audit-container"

echo "Construyendo imagen de prueba..."
docker build -t "$IMAGE_NAME" -f Dockerfile.test .

echo "Eliminando contenedor previo si existe..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "Lanzando contenedor de prueba..."
docker run -d --name "$CONTAINER_NAME" --privileged --cap-add=SYS_ADMIN "$IMAGE_NAME"

echo "Ejecutando auditoría real..."
if [ ! -d .venv ] || ! .venv/bin/python --version >/dev/null 2>&1; then
  rm -rf .venv
  if command -v python3 >/dev/null 2>&1; then
    python3 -m venv .venv
  else
    echo "ERROR: Python 3 no está instalado. Instala python3 e inténtalo de nuevo."
    exit 1
  fi
fi

./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

./.venv/bin/python main.py --target local --output html --sbom-dir reports/sbom

echo "Informe generado en reports/report.html y reports/report.json"

echo "Contenedor de prueba: $CONTAINER_NAME"
