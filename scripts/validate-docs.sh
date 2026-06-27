#!/usr/bin/env bash
###############################################################################
# OpenClaw Documentation Validator
#
# Diffs CLAUDE.md claims against actual config. Catches documentation drift
# where operators would make incorrect security assumptions.
#
# Usage: ./scripts/validate-docs.sh
# Exit 0 on match, 1 on any drift detected.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

OPENCLAW_JSON="${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}/openclaw.json"
CLAUDE_MD="$SCRIPT_DIR/CLAUDE.md"
COMPOSE="$SCRIPT_DIR/docker-compose.yml"

PASS=0
DRIFT=0

pass()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
drift() { echo "  DRIFT: $1"; DRIFT=$((DRIFT+1)); }

echo "=== OpenClaw Documentation Validator ==="
echo ""

if [ ! -f "$OPENCLAW_JSON" ]; then
  echo "ERROR: $OPENCLAW_JSON not found. This script requires the runtime config."
  exit 1
fi

# --- 1. MCP tool counts per agent ---
echo "[1/4] MCP tool counts (CLAUDE.md vs openclaw.json)"
MCP_DRIFT=$(python3 - <<PYEOF
import json, re, sys

oc = json.load(open('$OPENCLAW_JSON'))
claude_md = open('$CLAUDE_MD').read()

agents = oc.get('agents',{}).get('list',[])
drift_count = 0

# Look for table rows like: | \`main\` | 12 | ...
for a in agents:
    aid = a.get('id','?')
    allow = a.get('tools',{}).get('allow',[]) if isinstance(a.get('tools'),dict) else []
    mcp = [t for t in allow if 'mcp__' in str(t) or str(t).startswith('br_')]
    actual = len(mcp)
    # Match table row: | \`main\` | 12 |
    pattern = r'\|\s*\`' + re.escape(aid) + r'\`\s*\|\s*(\d+)\s*\|'
    m = re.search(pattern, claude_md)
    if m:
        documented = int(m.group(1))
        if documented == actual:
            print(f"  PASS: {aid}: {actual} MCP tools (CLAUDE.md matches)")
        else:
            print(f"  DRIFT: {aid}: documented={documented}, actual={actual}")
            drift_count += 1
    else:
        print(f"  DRIFT: {aid}: no count found in CLAUDE.md table (actual={actual})")
        drift_count += 1

sys.exit(drift_count)
PYEOF
) || MCP_DRIFT_COUNT=$?
echo "$MCP_DRIFT"
if [ "${MCP_DRIFT_COUNT:-0}" -gt 0 ]; then
  DRIFT=$((DRIFT + MCP_DRIFT_COUNT))
else
  PASS=$((PASS + 5))
fi

# --- 2. Image versions ---
echo ""
echo "[2/4] Image versions (CLAUDE.md vs docker-compose.yml)"
COMPOSE_IMAGE=$(grep -oE 'ghcr\.io/openclaw/openclaw:[0-9.]+' "$COMPOSE" | head -1)
CLAUDE_IMAGE=$(grep -oE '`ghcr\.io/openclaw/openclaw:[0-9.]+`' "$CLAUDE_MD" | head -1 | tr -d '`')

if [ -z "$COMPOSE_IMAGE" ]; then
  drift "No pinned openclaw image found in docker-compose.yml"
elif [ -z "$CLAUDE_IMAGE" ]; then
  drift "No image version documented in CLAUDE.md"
elif [ "$COMPOSE_IMAGE" = "$CLAUDE_IMAGE" ]; then
  pass "Image version matches: $COMPOSE_IMAGE"
else
  drift "Image mismatch: compose=$COMPOSE_IMAGE, CLAUDE.md=$CLAUDE_IMAGE"
fi

# --- 3. Agent models ---
echo ""
echo "[3/4] Agent models (openclaw.json)"
python3 - <<PYEOF
import json
oc = json.load(open('$OPENCLAW_JSON'))
agents = oc.get('agents',{}).get('list',[])
for a in agents:
    print(f"  {a.get('id','?')}: {a.get('model','?')}")
print("  Manual check: ensure CLAUDE.md agent table reflects these models.")
PYEOF

# --- 4. Security layer enforcement ---
echo ""
echo "[4/4] Security layer enforcement"

# Layer 4: workspaceOnly
if python3 -c "import json; d=json.load(open('$OPENCLAW_JSON')); assert d.get('tools',{}).get('fs',{}).get('workspaceOnly')==True" 2>/dev/null; then
  pass "Layer 4: tools.fs.workspaceOnly = true"
else
  drift "Layer 4: tools.fs.workspaceOnly is NOT true in openclaw.json"
fi

# Layer 5: gateway has seccomp
if grep -qA20 'openclaw-gateway:' "$COMPOSE" | grep -q 'seccomp:openclaw-seccomp.json' 2>/dev/null || \
   awk '/openclaw-gateway:/,/^  [a-z]/' "$COMPOSE" | grep -q 'seccomp:openclaw-seccomp.json'; then
  pass "Layer 5: gateway has seccomp"
else
  drift "Layer 5: gateway missing seccomp"
fi

# approvalMode enforcement (global vs per-agent)
if grep -q "approvalMode.*always" "$SCRIPT_DIR/gateway.yaml" 2>/dev/null || \
   grep -q "approvalMode.*always" "${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}/gateway.yaml" 2>/dev/null; then
  pass "approvalMode: always is enforced globally in gateway.yaml"
else
  drift "approvalMode: always NOT found in gateway.yaml"
fi

# --- Summary ---
echo ""
echo "=== Doc Validator Summary ==="
echo "  PASS:  $PASS"
echo "  DRIFT: $DRIFT"
echo ""

if [ "$DRIFT" -gt 0 ]; then
  echo "RESULT: DRIFT DETECTED — update CLAUDE.md to match current config"
  exit 1
else
  echo "RESULT: DOCS IN SYNC"
  exit 0
fi
