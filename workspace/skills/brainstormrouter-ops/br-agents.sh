#!/usr/bin/env bash
set -euo pipefail

# BrainstormRouter Agent Listing
# Lists all registered agents and their status.
# READ-ONLY — no modifications.

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"

if [ -z "${BRAINSTORMROUTER_ADMIN_KEY:-}" ]; then
  echo "ERROR: BRAINSTORMROUTER_ADMIN_KEY not set" >&2
  exit 1
fi

RESPONSE=$(curl -sf --max-time 10 \
  -H "Authorization: Bearer ${BRAINSTORMROUTER_ADMIN_KEY}" \
  "${BR_BASE_URL}/agent/profiles" 2>&1) || {
  echo "## BR Agents"
  echo "- Status: **ERROR** — could not fetch agent list"
  exit 1
}

echo "## BR Agents"
echo ""
echo "| Agent ID | Name | State | Budget/day | Budget/month |"
echo "|----------|------|-------|-----------|-------------|"

echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
profiles = data.get('profiles', data if isinstance(data, list) else [])
for p in profiles:
    aid = p.get('agentId', 'unknown')
    name = p.get('displayName', '-')
    state = p.get('lifecycleState', 'unknown')
    daily = p.get('budgetDailyUsd', 0)
    monthly = p.get('budgetMonthlyUsd', 0)
    print(f'| {aid} | {name} | {state} | \${daily:.2f} | \${monthly:.2f} |')
" 2>/dev/null || echo "| (parse error) | - | - | - | - |"
