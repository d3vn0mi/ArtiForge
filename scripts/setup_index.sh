#!/usr/bin/env bash
# setup_index.sh — create the ArtiForge index template and data view in Elasticsearch/Kibana
# Usage: ./scripts/setup_index.sh [ES_URL] [KIBANA_URL]
#   ES_URL      default: http://localhost:9200
#   KIBANA_URL  default: http://localhost:5601

set -euo pipefail

ES="${1:-http://localhost:9200}"
KIBANA="${2:-http://localhost:5601}"

echo ""
echo "==> ArtiForge — Index Setup"
echo "    Elasticsearch : $ES"
echo "    Kibana        : $KIBANA"
echo ""

# ── Wait for Elasticsearch ────────────────────────────────────────────────────
echo "--> Waiting for Elasticsearch..."
until curl -sf "$ES/_cluster/health" | grep -qv '"status":"red"'; do
  printf "."
  sleep 3
done
echo " ready."

# ── Index template ────────────────────────────────────────────────────────────
echo "--> Installing index template 'artiforge'..."
curl -sf -X PUT "$ES/_index_template/artiforge" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["winlogbeat-artiforge-*"],
    "priority": 100,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "1s"
      },
      "mappings": {
        "dynamic": true,
        "properties": {
          "@timestamp":        { "type": "date" },
          "winlog.event_id":   { "type": "integer" },
          "winlog.record_id":  { "type": "long" },
          "winlog.channel":    { "type": "keyword" },
          "winlog.computer_name": { "type": "keyword" },
          "winlog.provider_name": { "type": "keyword" },
          "host.name":         { "type": "keyword" },
          "host.hostname":     { "type": "keyword" },
          "event.code":        { "type": "keyword" },
          "event.provider":    { "type": "keyword" },
          "artiforge.phase_id":   { "type": "integer" },
          "artiforge.phase_name": { "type": "keyword" },
          "process.command_line": { "type": "wildcard" },
          "process.executable":   { "type": "keyword" },
          "destination.ip":    { "type": "ip" },
          "destination.port":  { "type": "integer" },
          "source.ip":         { "type": "ip" }
        }
      }
    }
  }' | python3 -c "import sys,json; r=json.load(sys.stdin); print('   OK' if r.get('acknowledged') else f'   WARN: {r}')"

# ── Wait for Kibana ───────────────────────────────────────────────────────────
echo "--> Waiting for Kibana..."
until curl -sf "$KIBANA/api/status" | grep -q '"level":"available"'; do
  printf "."
  sleep 5
done
echo " ready."

# ── Create Kibana data view ───────────────────────────────────────────────────
echo "--> Creating Kibana data view 'winlogbeat-artiforge-*'..."
curl -sf -X POST "$KIBANA/api/data_views/data_view" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "data_view": {
      "title": "winlogbeat-artiforge-*",
      "name":  "ArtiForge Labs",
      "timeFieldName": "@timestamp"
    }
  }' | python3 -c "
import sys, json
r = json.load(sys.stdin)
if 'data_view' in r:
    print(f'   OK  id={r[\"data_view\"][\"id\"]}')
elif 'error' in r and 'already exists' in str(r):
    print('   OK  (data view already exists)')
else:
    print(f'   WARN: {r}')
"

echo ""
echo "==> Setup complete."
echo "    Open Kibana at $KIBANA"
echo "    Go to: Discover → change index to 'ArtiForge Labs'"
echo ""
