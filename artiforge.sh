#!/usr/bin/env bash
# ArtiForge Docker wrapper
#
# Builds the image on first use (or when Dockerfile/source changes), then
# forwards every argument straight to the artiforge CLI inside the container.
#
# Mount semantics
# ---------------
# $(pwd) is mounted to /work inside the container.
# All relative paths in artiforge commands (e.g. --output ./artifacts,
# --lab-path ./mylab/lab.yaml) resolve against that directory on the host,
# so generated files are written directly to your working directory.
#
# Usage
# -----
#   ./artiforge.sh list-labs
#   ./artiforge.sh generate --lab uc3e --format xml,elastic,evtx --seed 42
#   ./artiforge.sh check --lab uc3e --seed 42
#   ./artiforge.sh serve
#
# Elasticsearch management (runs on host, not in container)
# ----------------------------------------------------------
#   ./artiforge.sh es-list                   # list all ArtiForge indices
#   ./artiforge.sh es-delete <lab_id>        # delete all indices for a lab
#   ./artiforge.sh es-delete <full_index>    # delete a specific index
#   ./artiforge.sh es-purge                  # delete ALL ArtiForge indices
#
# Environment variables
# ---------------------
#   ARTIFORGE_IMAGE     Docker image to use (default: artiforge:latest)
#   ARTIFORGE_NO_BUILD  Set to 1 to skip the auto-build step
#   ES_URL              Elasticsearch URL (default: http://localhost:9200)

set -euo pipefail

IMAGE="${ARTIFORGE_IMAGE:-artiforge:latest}"
ES="${ES_URL:-http://localhost:9200}"

# ── Elasticsearch management commands (run on host) ──────────────────────────

case "${1:-}" in

es-list)
    echo ""
    echo "==> ArtiForge — Elasticsearch Indices"
    echo "    ES: $ES"
    echo ""
    RESULT=$(curl -s "$ES/_cat/indices/winlogbeat-artiforge-*?v&s=index&h=index,docs.count,store.size" 2>/dev/null)
    if [[ -z "$RESULT" || "$RESULT" == *"error"* ]]; then
        echo "    No ArtiForge indices found (or Elasticsearch is not running)."
    else
        echo "$RESULT" | sed 's/^/    /'
    fi
    echo ""
    exit 0
    ;;

es-delete)
    TARGET="${2:-}"
    if [[ -z "$TARGET" ]]; then
        echo "Usage: $0 es-delete <lab_id|index_name>"
        echo ""
        echo "Examples:"
        echo "  $0 es-delete uc3e                    # delete all UC3E indices"
        echo "  $0 es-delete uc3e-20260219_091200    # delete a specific run"
        echo ""
        echo "Current indices:"
        curl -s "$ES/_cat/indices/winlogbeat-artiforge-*?h=index" 2>/dev/null | sed 's/^/  /'
        exit 1
    fi

    # If target looks like a full index name, use it directly.
    # Otherwise treat it as a lab_id and wildcard it.
    if [[ "$TARGET" == winlogbeat-artiforge-* ]]; then
        PATTERN="$TARGET"
    else
        PATTERN="winlogbeat-artiforge-${TARGET}*"
    fi

    # Show what will be deleted
    MATCHES=$(curl -s "$ES/_cat/indices/${PATTERN}?h=index,docs.count" 2>/dev/null)
    if [[ -z "$MATCHES" ]]; then
        echo "No indices match '$PATTERN'"
        exit 1
    fi

    echo ""
    echo "==> ArtiForge — Delete Indices"
    echo ""
    echo "    The following indices will be deleted:"
    echo "$MATCHES" | sed 's/^/      /'
    echo ""
    read -rp "    Confirm deletion? [y/N] " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        echo "    Cancelled."
        exit 0
    fi

    RESPONSE=$(curl -s -X DELETE "$ES/${PATTERN}")
    if echo "$RESPONSE" | grep -q '"acknowledged":true'; then
        echo "    Deleted."
    else
        echo "    Error: $RESPONSE"
        exit 1
    fi
    echo ""
    exit 0
    ;;

es-purge)
    MATCHES=$(curl -s "$ES/_cat/indices/winlogbeat-artiforge-*?h=index,docs.count" 2>/dev/null)
    if [[ -z "$MATCHES" ]]; then
        echo "No ArtiForge indices found."
        exit 0
    fi

    echo ""
    echo "==> ArtiForge — Purge ALL Indices"
    echo ""
    echo "    The following indices will be deleted:"
    echo "$MATCHES" | sed 's/^/      /'
    echo ""
    read -rp "    Delete ALL ArtiForge data? [y/N] " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        echo "    Cancelled."
        exit 0
    fi

    RESPONSE=$(curl -s -X DELETE "$ES/winlogbeat-artiforge-*")
    if echo "$RESPONSE" | grep -q '"acknowledged":true'; then
        echo "    All ArtiForge indices deleted."
    else
        echo "    Error: $RESPONSE"
        exit 1
    fi
    echo ""
    exit 0
    ;;

esac

# ── Docker wrapper (all other commands) ──────────────────────────────────────

# Auto-rebuild when the git commit has changed since the image was built.
# Set ARTIFORGE_NO_BUILD=1 to skip this check entirely.
if [[ "${ARTIFORGE_NO_BUILD:-0}" != "1" ]]; then
    current_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    image_commit=$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "git-commit"}}' 2>/dev/null || echo "")
    if [[ "$current_commit" != "$image_commit" ]]; then
        echo "[artiforge.sh] Rebuilding image (code changed since last build)..." >&2
        docker build --build-arg GIT_COMMIT="$current_commit" -t "$IMAGE" "$(dirname "$0")"
    fi
fi

# Publish port 5000 automatically when the first argument is "serve"
PORT_FLAG=()
if [[ "${1:-}" == "serve" ]]; then
    PORT_FLAG=(-p 5000:5000)
fi

exec docker run --rm \
    -v "$(pwd):/work" \
    --user "$(id -u):$(id -g)" \
    "${PORT_FLAG[@]}" \
    "$IMAGE" \
    "$@"
