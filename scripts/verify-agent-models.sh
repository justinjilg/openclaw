#!/usr/bin/env bash
###############################################################################
# OpenClaw Agent Model Verification
#
# Verifies that every agent's configured model can actually call tools via
# a live BrainstormRouter API request. Catches the class of bug where an
# agent is configured with a model that does not support function calling.
#
# Discovered 2026-04-10: main agent was configured with moonshot/kimi-k2.5
# which does not support tools — agent was effectively blind to MCP/bash.
#
# Usage: ./scripts/verify-agent-models.sh
# Requires: 1Password CLI, BR API key in "op://Dev Keys/BrainstormRouter API Key/credential"
# Exit 0 on all agents verified, 1 on any failure.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

OPENCLAW_JSON="${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}/openclaw.json"

if [ ! -f "$OPENCLAW_JSON" ]; then
  echo "ERROR: $OPENCLAW_JSON not found"
  exit 1
fi

if ! command -v op &>/dev/null; then
  echo "ERROR: 1Password CLI (op) not found"
  exit 1
fi

BR_KEY=$(op read "op://Dev Keys/BrainstormRouter API Key/credential" 2>/dev/null) || {
  echo "ERROR: Could not read BR API key from 1Password"
  exit 1
}

echo "=== OpenClaw Agent Model Verification ==="
echo ""
echo "Part 1: Check openclaw's resolved model + auth for each agent"
echo "Part 2: Test each unique model via live BR tool-call request"
echo ""

PASS=0
FAIL=0

# --- Part 1: openclaw-side check (catches auth/provider misconfig) ---
echo "[Part 1] openclaw model resolution and auth status"
if docker compose ps openclaw-gateway 2>/dev/null | grep -q '(healthy)'; then
  for a in main ops research dev admin; do
    STATUS=$(docker compose exec -T openclaw-gateway openclaw models status --agent "$a" --json 2>/dev/null || echo '{}')
    RESULT=$(echo "$STATUS" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    missing = d.get('auth', {}).get('missingProvidersInUse', [])
    default = d.get('defaultModel', '?')
    resolved = d.get('resolvedDefault', '?')
    if missing:
        print(f'FAIL|model={default}, missing provider auth: {missing}')
    elif default != resolved:
        print(f'WARN|default={default} but resolved={resolved}')
    else:
        print(f'PASS|{default}')
except Exception as e:
    print(f'FAIL|status error: {e}')
" 2>/dev/null)

    STATUS_CODE="${RESULT%%|*}"
    DETAIL="${RESULT#*|}"

    case "$STATUS_CODE" in
      PASS)
        echo "  PASS: [$a] $DETAIL"
        PASS=$((PASS + 1))
        ;;
      WARN)
        echo "  WARN: [$a] $DETAIL"
        ;;
      *)
        echo "  FAIL: [$a] $DETAIL"
        echo "  → Agent's configured model has no provider auth in openclaw. Will fall back to brainstormrouter/auto at runtime."
        FAIL=$((FAIL + 1))
        ;;
    esac
  done
  echo ""
else
  echo "  SKIP: gateway not healthy — cannot check openclaw model resolution"
  echo ""
fi

echo "[Part 2] Live BR tool-call test for each agent's model"

# Get agent -> model mapping from openclaw.json
AGENT_MODELS=$(python3 -c "
import json
oc = json.load(open('$OPENCLAW_JSON'))
agents = oc.get('agents',{}).get('list',[])
for a in agents:
    print(f\"{a.get('id','?')}|{a.get('model','?')}\")
")

# Test each agent's model
while IFS='|' read -r agent_id model; do
  [ -z "$agent_id" ] && continue

  echo "[$agent_id] model=$model"

  # Minimal tool-calling test payload
  RESPONSE=$(curl -sSL "https://api.brainstormrouter.com/v1/chat/completions" \
    -H "Authorization: Bearer $BR_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"model\": \"$model\",
      \"messages\": [{\"role\":\"user\",\"content\":\"Call get_weather for Tokyo\"}],
      \"tools\": [{
        \"type\": \"function\",
        \"function\": {
          \"name\": \"get_weather\",
          \"description\": \"Get weather for a city\",
          \"parameters\": {
            \"type\": \"object\",
            \"properties\": {\"city\": {\"type\": \"string\"}},
            \"required\": [\"city\"]
          }
        }
      }],
      \"max_tokens\": 100
    }" 2>/dev/null)

  RESULT=$(echo "$RESPONSE" | python3 -c "
import json, sys
try:
    r = json.load(sys.stdin)
    if 'error' in r:
        msg = r['error'].get('message', 'unknown error')
        # Categorize failure type
        msg_lower = msg.lower()
        if 'tools' in msg_lower and 'capabilit' in msg_lower:
            print(f'FAIL_TOOLS|Model does not support tool calling: {msg}')
        elif 'credit' in msg_lower or 'billing' in msg_lower or 'quota' in msg_lower or 'balance' in msg_lower or 'budget exceeded' in msg_lower or 'budget_exceeded' in msg_lower:
            print(f'FAIL_BILLING|Billing/quota issue: {msg}')
        elif 'rate' in msg_lower and 'limit' in msg_lower:
            print(f'FAIL_RATE|Rate limit: {msg}')
        elif 'not found' in msg_lower or 'unknown' in msg_lower or 'invalid' in msg_lower:
            print(f'FAIL_MODEL|Model not available: {msg}')
        else:
            print(f'FAIL_OTHER|{msg}')
    else:
        choices = r.get('choices', [])
        if not choices:
            print('FAIL_OTHER|No choices in response')
        else:
            msg = choices[0].get('message', {})
            tool_calls = msg.get('tool_calls', [])
            if tool_calls:
                print(f'PASS|{len(tool_calls)} tool call(s) made')
            else:
                content = msg.get('content', '')[:100]
                print(f'FAIL_TOOLS|No tool calls in response. Content: {content}')
except Exception as e:
    print(f'FAIL_OTHER|Parse error: {e}')
" 2>/dev/null || echo "FAIL_OTHER|Response parse error")

  STATUS="${RESULT%%|*}"
  DETAIL="${RESULT#*|}"

  case "$STATUS" in
    PASS)
      echo "  PASS: $DETAIL"
      PASS=$((PASS + 1))
      ;;
    FAIL_TOOLS)
      echo "  FAIL (TOOL CALLING NOT SUPPORTED): $DETAIL"
      echo "  → Agent is BLIND. Cannot use MCP, bash, file ops, or any function calls."
      FAIL=$((FAIL + 1))
      ;;
    FAIL_BILLING)
      echo "  WARN (BILLING/QUOTA): $DETAIL"
      echo "  → Not a tool-calling failure. Budget resets at UTC midnight."
      ;;
    FAIL_MODEL)
      echo "  FAIL (MODEL UNAVAILABLE): $DETAIL"
      FAIL=$((FAIL + 1))
      ;;
    *)
      echo "  FAIL ($STATUS): $DETAIL"
      FAIL=$((FAIL + 1))
      ;;
  esac
  echo ""
done <<< "$AGENT_MODELS"

# --- Summary ---
echo "=== Model Verification Summary ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL — one or more agents have models that cannot call tools"
  echo "This means those agents cannot use MCP, bash, file operations, or any"
  echo "other function-calling features. They are effectively blind."
  exit 1
else
  echo "RESULT: PASS — all agent models support tool calling"
  exit 0
fi
