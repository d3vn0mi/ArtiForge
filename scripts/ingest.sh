#!/usr/bin/env bash
# ingest.sh — push ArtiForge NDJSON artifacts into Elasticsearch
# Usage: ./scripts/ingest.sh <ndjson_file> [ES_URL]
#   ndjson_file  path to bulk_import.ndjson
#   ES_URL       default: http://localhost:9200

set -euo pipefail

NDJSON="${1:-}"
ES="${2:-http://localhost:9200}"

# ── Argument validation ───────────────────────────────────────────────────────
if [[ -z "$NDJSON" ]]; then
  echo "Usage: $0 <path/to/bulk_import.ndjson> [ES_URL]"
  echo ""
  echo "Example:"
  echo "  $0 artifacts/uc3_20260219_091200/elastic/bulk_import.ndjson"
  exit 1
fi

if [[ ! -f "$NDJSON" ]]; then
  echo "Error: file not found: $NDJSON"
  exit 1
fi

# ── Detect index name from first action line ──────────────────────────────────
INDEX=$(head -1 "$NDJSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['index']['_index'])")

echo ""
echo "==> ArtiForge — Ingest"
echo "    File  : $NDJSON"
echo "    Index : $INDEX"
echo "    ES    : $ES"
echo ""

# ── Wait for Elasticsearch ────────────────────────────────────────────────────
echo "--> Checking Elasticsearch..."
until curl -sf "$ES/_cluster/health" | grep -qv '"status":"red"'; do
  printf "."
  sleep 3
done
echo " ready."

# ── Bulk ingest ───────────────────────────────────────────────────────────────
echo "--> Ingesting $(( $(wc -l < "$NDJSON") / 2 )) documents..."
RESPONSE=$(curl -sf -X POST "$ES/_bulk" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary "@$NDJSON")

# Parse response
python3 - <<PYEOF
import json, sys

r = json.loads('''$RESPONSE''')
errors  = r.get("errors", False)
items   = r.get("items", [])
ok      = sum(1 for i in items if i.get("index", {}).get("result") in ("created", "updated"))
failed  = sum(1 for i in items if i.get("index", {}).get("error"))

print(f"    Indexed : {ok}")
if failed:
    print(f"    Failed  : {failed}")
    for item in items:
        err = item.get("index", {}).get("error")
        if err:
            print(f"    ERROR   : {err}")
    sys.exit(1)
else:
    print(f"    Errors  : none")
PYEOF

# ── Verify doc count ──────────────────────────────────────────────────────────
sleep 1   # let refresh_interval catch up
COUNT=$(curl -sf "$ES/$INDEX/_count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
echo "--> Verified: $COUNT documents in index '$INDEX'"

echo ""
echo "==> Ingest complete."
echo "    Query the index: curl '$ES/$INDEX/_search?pretty&size=3'"
echo ""
