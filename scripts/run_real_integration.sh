#!/bin/bash
# Full integration demo using Dockerfile.demo.
# Builds the demo image, runs a container, audits it with CVE correlation,
# then cleans up.
#
# Usage: bash scripts/run_real_integration.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

IMAGE_NAME="dockaudit-demo"
CONTAINER_NAME="dockaudit-demo-container"

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker CLI not found."
    echo "  sudo apt install docker.io && sudo usermod -aG docker \$USER"
    exit 1
fi

if [ ! -S /var/run/docker.sock ]; then
    echo "ERROR: Docker daemon not running."
    echo "  sudo systemctl start docker"
    exit 1
fi

if [ ! -d .venv ] || ! .venv/bin/python3 --version >/dev/null 2>&1; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
fi

echo "[*] Building demo image..."
docker build -t "$IMAGE_NAME" -f Dockerfile.demo . --quiet

echo "[*] Starting demo container..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER_NAME" "$IMAGE_NAME" >/dev/null

echo "[*] Running audit..."
.venv/bin/python3 main.py --container "$CONTAINER_NAME" --nvd-feed sample_nvd.json

echo ""
echo "[*] Cleaning up container..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo ""
echo "[+] Done. Reports written to reports/"
