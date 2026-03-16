#!/usr/bin/env bash
# run_lab.sh — one-shot: generate artifacts for a lab and ingest into Elasticsearch
# Usage: ./scripts/run_lab.sh [LAB_ID] [OUTPUT_DIR] [ES_URL]
#   LAB_ID      default: uc3
#   OUTPUT_DIR  default: ./artifacts
#   ES_URL      default: http://localhost:9200

set -euo pipefail

LAB="${1:-uc3}"
OUTPUT="${2:-./artifacts}"
ES="${3:-http://localhost:9200}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║         ArtiForge — Run Lab          ║"
echo "╚══════════════════════════════════════╝"
echo "  Lab    : $LAB"
echo "  Output : $OUTPUT"
echo "  ES     : $ES"
echo ""

# ── Step 1: generate artifacts ────────────────────────────────────────────────
echo "[ 1/3 ] Generating artifacts..."
cd "$ROOT"
python cli.py generate --lab "$LAB" --output "$OUTPUT"

# ── Step 2: find the NDJSON ───────────────────────────────────────────────────
NDJSON=$(find "$OUTPUT" -name "bulk_import.ndjson" | sort | tail -1)
if [[ -z "$NDJSON" ]]; then
  echo "Error: bulk_import.ndjson not found in $OUTPUT"
  exit 1
fi

# ── Step 3: ingest ────────────────────────────────────────────────────────────
echo ""
echo "[ 2/3 ] Ingesting into Elasticsearch..."
bash "$SCRIPT_DIR/ingest.sh" "$NDJSON" "$ES"

# ── Step 4: summary ───────────────────────────────────────────────────────────
echo "[ 3/3 ] Done."
echo ""
echo "  NDJSON       : $NDJSON"
echo "  Kibana       : http://localhost:5601"
echo "  Discover URL : http://localhost:5601/app/discover"
echo ""
echo "  Suggested first query in Kibana Discover:"
echo "    winlog.channel : Security AND winlog.event_id : 4688"
echo ""
