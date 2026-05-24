#!/bin/bash
set -euo pipefail

YEAR="${1:-2024}"
OUTPUT_DIR="${2:-.}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/nvdcve-1.1-$YEAR.json.gz"
URL="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$YEAR.json.gz"

if command -v curl >/dev/null 2>&1; then
    echo "[*] Downloading NVD feed for year $YEAR..."
    curl -L -o "$OUTPUT_FILE" "$URL"
elif command -v wget >/dev/null 2>&1; then
    echo "[*] Downloading NVD feed for year $YEAR..."
    wget -O "$OUTPUT_FILE" "$URL"
else
    echo "ERROR: curl or wget is required to download NVD feeds."
    exit 1
fi

echo "[+] NVD feed downloaded to: $OUTPUT_FILE"
