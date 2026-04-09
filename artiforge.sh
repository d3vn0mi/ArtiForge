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
#
# Environment variables
# ---------------------
#   ARTIFORGE_IMAGE   Docker image to use (default: artiforge:latest)
#   ARTIFORGE_NO_BUILD  Set to 1 to skip the auto-build step

set -euo pipefail

IMAGE="${ARTIFORGE_IMAGE:-artiforge:latest}"

# Auto-build if the image doesn't exist yet (or the user hasn't opted out)
if [[ "${ARTIFORGE_NO_BUILD:-0}" != "1" ]]; then
    if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
        echo "[artiforge.sh] Image '$IMAGE' not found — building now..." >&2
        docker build -t "$IMAGE" "$(dirname "$0")"
    fi
fi

exec docker run --rm \
    -v "$(pwd):/work" \
    --user "$(id -u):$(id -g)" \
    "$IMAGE" \
    "$@"
