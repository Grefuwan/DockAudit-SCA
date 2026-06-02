#!/bin/bash
# Downloads NVD CVE data for a given year using the NVD API 2.0.
# The NVD 1.1 JSON feeds (nvd.nist.gov/feeds) were retired in December 2023.
#
# Usage:
#   ./download_nvd_feed.sh [year] [output_dir]
#
# Optional: set NVD_API_KEY to increase rate limit (50 req/30s vs 5 req/30s).
#   export NVD_API_KEY=<your_key>   # https://nvd.nist.gov/developers/request-an-api-key
#
# Example:
#   ./download_nvd_feed.sh 2024 feeds/
#   python3 main.py --container myapp --nvd-feed feeds/nvdcve-2.0-2024.json

set -euo pipefail

YEAR="${1:-$(date +%Y)}"
OUTPUT_DIR="${2:-.}"
API_KEY="${NVD_API_KEY:-}"

BASE_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE=2000
START_DATE="${YEAR}-01-01T00:00:00.000"
END_DATE="${YEAR}-12-31T23:59:59.999"
OUTPUT_FILE="$OUTPUT_DIR/nvdcve-2.0-${YEAR}.json"

# Dependency checks
for cmd in curl jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: '$cmd' is required."
        echo "  Install: sudo apt install $cmd   /   brew install $cmd"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

# Rate limits: 5 req/30s without key, 50 req/30s with key
if [ -n "$API_KEY" ]; then
    DELAY=1
    echo "[*] NVD API key detected — using higher rate limit"
else
    DELAY=7
    echo "[!] NVD_API_KEY not set — using public rate limit (~5 req/30s)"
    echo "    Request a free key at: https://nvd.nist.gov/developers/request-an-api-key"
fi

echo "[*] Fetching NVD CVEs for year $YEAR..."

CURL_ARGS=(-s -f --retry 3 --retry-delay 5)
[ -n "$API_KEY" ] && CURL_ARGS+=(-H "apiKey: $API_KEY")

ALL_VULNS='[]'
START_INDEX=0
TOTAL_RESULTS=-1
PAGE=1

while true; do
    URL="${BASE_URL}?pubStartDate=${START_DATE}&pubEndDate=${END_DATE}&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${START_INDEX}"

    echo -n "[*] Page $PAGE (offset $START_INDEX)... "

    RESPONSE=$(curl "${CURL_ARGS[@]}" "$URL")

    if [ "$TOTAL_RESULTS" -eq -1 ]; then
        TOTAL_RESULTS=$(echo "$RESPONSE" | jq '.totalResults')
        echo -n "total: $TOTAL_RESULTS CVEs — "
    fi

    PAGE_VULNS=$(echo "$RESPONSE" | jq '.vulnerabilities // []')
    PAGE_COUNT=$(echo "$PAGE_VULNS" | jq 'length')
    echo "$PAGE_COUNT entries"

    [ "$PAGE_COUNT" -eq 0 ] && break

    ALL_VULNS=$(jq -n --argjson a "$ALL_VULNS" --argjson b "$PAGE_VULNS" '$a + $b')
    START_INDEX=$((START_INDEX + PAGE_COUNT))

    [ "$START_INDEX" -ge "$TOTAL_RESULTS" ] && break

    PAGE=$((PAGE + 1))
    sleep "$DELAY"
done

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000")
jq -n \
    --argjson vulns "$ALL_VULNS" \
    --arg ts "$TIMESTAMP" \
    '{
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": $ts,
        "totalResults": ($vulns | length),
        "vulnerabilities": $vulns
    }' > "$OUTPUT_FILE"

FINAL_COUNT=$(jq '.vulnerabilities | length' "$OUTPUT_FILE")
echo ""
echo "[+] $FINAL_COUNT CVEs written to: $OUTPUT_FILE"
echo ""
echo "    python3 main.py --nvd-feed $OUTPUT_FILE"
