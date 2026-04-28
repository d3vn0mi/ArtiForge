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
          "labels.phase_id":   { "type": "keyword" },
          "labels.phase_name": { "type": "keyword" },
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
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$KIBANA/api/data_views/data_view" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "data_view": {
      "title": "winlogbeat-artiforge-*",
      "name":  "ArtiForge Labs",
      "timeFieldName": "@timestamp"
    }
  }')

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
  DV_ID=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data_view',{}).get('id','?'))" 2>/dev/null || echo "?")
  echo "   OK  id=$DV_ID"
elif [ "$HTTP_CODE" = "409" ]; then
  echo "   OK  (data view already exists)"
else
  echo "   WARN: HTTP $HTTP_CODE"
  echo "   $BODY" | head -3
fi

echo ""
echo "==> Setup complete."
echo "    Open Kibana at $KIBANA"
echo "    Go to: Discover → change index to 'ArtiForge Labs'"
echo ""
