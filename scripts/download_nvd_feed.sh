#!/bin/bash
# Downloads NVD CVE data for a given year using the NVD API 2.0.
# The NVD 1.1 JSON feeds (nvd.nist.gov/feeds) were retired in December 2023.
# The API enforces a 120-day maximum date range per request; this script
# splits the year into 90-day windows and paginates within each window.
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
WINDOW_DAYS=90
OUTPUT_FILE="$OUTPUT_DIR/nvdcve-2.0-${YEAR}.json"

for cmd in curl jq date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: '$cmd' is required."
        echo "  Install: sudo apt install $cmd   /   brew install $cmd"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

if [ -n "$API_KEY" ]; then
    DELAY=1
    echo "[*] NVD API key detected — using higher rate limit"
else
    DELAY=7
    echo "[!] NVD_API_KEY not set — using public rate limit (~5 req/30s)"
    echo "    Request a free key at: https://nvd.nist.gov/developers/request-an-api-key"
fi

echo "[*] Fetching NVD CVEs for year $YEAR (${WINDOW_DAYS}-day windows)..."

CURL_ARGS=(-s -f --connect-timeout 15 --max-time 300 --retry 3 --retry-delay 10)
[ -n "$API_KEY" ] && CURL_ARGS+=(-H "apiKey: $API_KEY")

# Accumulate individual CVE objects as JSONL (one JSON object per line)
TMPDIR_WORK=$(mktemp -d)
VULNS_JSONL="$TMPDIR_WORK/vulns.jsonl"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

WINDOW_START="${YEAR}-01-01"
YEAR_END="${YEAR}-12-31"

while true; do
    WINDOW_END=$(date -d "${WINDOW_START} + ${WINDOW_DAYS} days - 1 day" +%Y-%m-%d 2>/dev/null \
                 || date -v+${WINDOW_DAYS}d -v-1d -j -f "%Y-%m-%d" "$WINDOW_START" +%Y-%m-%d)

    [[ "$WINDOW_END" > "$YEAR_END" ]] && WINDOW_END="$YEAR_END"

    START_DATE="${WINDOW_START}T00:00:00.000"
    END_DATE="${WINDOW_END}T23:59:59.999"

    echo "[*] Window: $WINDOW_START → $WINDOW_END"

    START_INDEX=0
    WINDOW_TOTAL=-1
    PAGE=1

    RESP_FILE="$TMPDIR_WORK/response.json"

    while true; do
        URL="${BASE_URL}?pubStartDate=${START_DATE}&pubEndDate=${END_DATE}&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${START_INDEX}"

        echo -n "    Page $PAGE (offset $START_INDEX)... "

        # Retry loop: guard against HTTP errors (429 rate-limit) and truncated responses
        MAX_RETRIES=5
        ATTEMPT=0
        while true; do
            CURL_OK=true
            curl "${CURL_ARGS[@]}" "$URL" -o "$RESP_FILE" || CURL_OK=false
            if $CURL_OK && jq empty "$RESP_FILE" 2>/dev/null; then
                break
            fi
            ATTEMPT=$((ATTEMPT + 1))
            if [ "$ATTEMPT" -ge "$MAX_RETRIES" ]; then
                echo ""
                echo "ERROR: request failed after $MAX_RETRIES attempts. Aborting."
                exit 1
            fi
            echo -n "(retry $ATTEMPT, waiting $((DELAY * 4))s) "
            sleep $((DELAY * 4))
        done

        if [ "$WINDOW_TOTAL" -eq -1 ]; then
            WINDOW_TOTAL=$(jq '.totalResults' "$RESP_FILE")
            echo -n "total: $WINDOW_TOTAL CVEs — "
        fi

        PAGE_COUNT=$(jq '.vulnerabilities | length' "$RESP_FILE")
        echo "$PAGE_COUNT entries"

        [ "$PAGE_COUNT" -eq 0 ] && break

        # Append each CVE object as a single line to the JSONL file
        jq -c '.vulnerabilities[]' "$RESP_FILE" >> "$VULNS_JSONL"

        START_INDEX=$((START_INDEX + PAGE_COUNT))
        [ "$START_INDEX" -ge "$WINDOW_TOTAL" ] && break

        PAGE=$((PAGE + 1))
        sleep "$DELAY"
    done

    [[ "$WINDOW_END" == "$YEAR_END" ]] && break

    WINDOW_START=$(date -d "${WINDOW_END} + 1 day" +%Y-%m-%d 2>/dev/null \
                   || date -v+1d -j -f "%Y-%m-%d" "$WINDOW_END" +%Y-%m-%d)
    sleep "$DELAY"
done

echo ""
echo "[*] Assembling output file..."

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000")

# Read the JSONL file and wrap into the final NVD JSON envelope
jq -Rs '
    split("\n") |
    map(select(length > 0) | fromjson)
' "$VULNS_JSONL" | jq \
    --arg ts "$TIMESTAMP" \
    '{
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": $ts,
        "totalResults": length,
        "vulnerabilities": .
    }' > "$OUTPUT_FILE"

FINAL_COUNT=$(jq '.vulnerabilities | length' "$OUTPUT_FILE")
echo "[+] $FINAL_COUNT CVEs written to: $OUTPUT_FILE"
echo ""
echo "    python3 main.py --nvd-feed $OUTPUT_FILE"
