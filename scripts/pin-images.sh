#!/usr/bin/env bash
###############################################################################
# OpenClaw Image Pinning Helper
#
# Pulls current dashboard images and reports their sha256 digests so they can
# be pinned in docker-compose.yml. Requires Docker daemon running.
#
# Usage: ./scripts/pin-images.sh
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

if ! docker info &>/dev/null; then
  echo "ERROR: Docker daemon is not running."
  exit 1
fi

IMAGES=(
  "nginxinc/nginx-unprivileged:alpine"
)

echo "=== Image Pinning Helper ==="
echo ""

for img in "${IMAGES[@]}"; do
  echo "Pulling $img ..."
  docker pull "$img" >/dev/null 2>&1
  digest=$(docker image inspect "$img" --format='{{index .RepoDigests 0}}')
  echo "  $digest"
  echo ""
done

echo "---"
echo "Update docker-compose.yml to use these digests:"
echo ""
for img in "${IMAGES[@]}"; do
  base="${img%:*}"
  digest=$(docker image inspect "$img" --format='{{index .RepoDigests 0}}')
  echo "  image: $digest"
done
echo ""
echo "After updating, run: ./scripts/smoke-test.sh"
