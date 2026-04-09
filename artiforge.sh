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
#   ./artiforge.sh generate --lab uc3
#   ./artiforge.sh generate --lab uc3 --base-time "2026-06-01T09:00:00Z"
#   ./artiforge.sh generate --lab-path ./mylab/lab.yaml --dry-run
#   ./artiforge.sh new-lab --id my-scenario --output /work
#   ./artiforge.sh validate --lab uc3
#   ./artiforge.sh navigator --lab uc3
#   ./artiforge.sh check --lab uc3
#   ./artiforge.sh serve                  # web UI on http://localhost:5000
#
# Environment variables
# ---------------------
#   ARTIFORGE_IMAGE   Docker image to use (default: artiforge:latest)
#   ARTIFORGE_NO_BUILD  Set to 1 to skip the auto-build step

set -euo pipefail

IMAGE="${ARTIFORGE_IMAGE:-artiforge:latest}"

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
