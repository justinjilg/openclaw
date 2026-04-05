#!/usr/bin/env bash
# Run all Portkey autopsy test scripts sequentially
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."

echo "═══════════════════════════════════════════"
echo "  Portkey.ai Capability Autopsy — Full Run"
echo "═══════════════════════════════════════════"
echo ""

PASS=0 FAIL=0

for script in scripts/portkey-autopsy/[0-9][0-9]-*.mjs; do
  echo "▶ Running $(basename "$script")..."
  if node "$script" 2>&1; then
    ((PASS++))
  else
    ((FAIL++))
    echo "  ⚠ Script exited with error"
  fi
done

echo ""
echo "═══════════════════════════════════════════"
echo "  Complete: $PASS scripts passed, $FAIL failed"
echo "  Results in: scripts/portkey-autopsy/results/"
echo "═══════════════════════════════════════════"
