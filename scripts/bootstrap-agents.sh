#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Bootstrap OpenClaw Agents on BrainstormRouter
#
# Registers all 5 agents with their budget limits via the BR API.
# Run once during initial setup, or after a BR environment reset.
#
# Usage: ./scripts/bootstrap-agents.sh
# Requires: BRAINSTORMROUTER_API_KEY (from 1Password or env)
###############################################################################

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"

# Load API key from 1Password if not already set
if [ -z "${BRAINSTORMROUTER_API_KEY:-}" ]; then
  echo "Loading BrainstormRouter API key from 1Password..."
  BRAINSTORMROUTER_API_KEY=$(op read "op://Dev Keys/BrainstormRouter API Key/credential")
fi

bootstrap_agent() {
  local agent_id="$1"
  local display_name="$2"
  local budget_daily="$3"
  local budget_monthly="$4"
  local role="$5"

  echo -n "Bootstrapping ${agent_id} (${display_name}, \$${budget_daily}/day)... "

  HTTP_CODE=$(curl -s -o /tmp/br-bootstrap-response.json -w "%{http_code}" \
    --max-time 15 \
    -X POST \
    -H "Authorization: Bearer ${BRAINSTORMROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{
      \"agent_id\": \"${agent_id}\",
      \"display_name\": \"${display_name}\",
      \"cost_center\": \"openclaw-fleet\",
      \"budget_daily_usd\": ${budget_daily},
      \"budget_monthly_usd\": ${budget_monthly}
    }" \
    "${BR_BASE_URL}/agent/bootstrap")

  if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    echo "OK (${HTTP_CODE})"
    # Save JWT for this agent
    python3 -c "
import sys, json
data = json.load(open('/tmp/br-bootstrap-response.json'))
jwt = data.get('token', data.get('jwt', ''))
if jwt:
    print(f'  JWT: {jwt[:20]}...')
" 2>/dev/null || true
  elif [ "$HTTP_CODE" = "409" ]; then
    echo "ALREADY EXISTS (409) — skipping"
  else
    echo "FAILED (${HTTP_CODE})"
    cat /tmp/br-bootstrap-response.json 2>/dev/null
    echo ""
  fi
}

echo "=== BrainstormRouter Agent Bootstrap ==="
echo "API: ${BR_BASE_URL}"
echo ""

#                  agent_id       display_name               daily  monthly  role
bootstrap_agent "oc-main"     "OpenClaw Coordinator"      5.00   150.00  "coordinator"
bootstrap_agent "oc-ops"      "OpenClaw Ops Monitor"      1.00    30.00  "operations"
bootstrap_agent "oc-research" "OpenClaw Researcher"       3.00    90.00  "research"
bootstrap_agent "oc-dev"      "OpenClaw Developer"        5.00   150.00  "development"
bootstrap_agent "oc-admin"    "OpenClaw Platform Admin"   0.50    15.00  "admin"

echo ""
echo "=== Verifying ==="
echo ""

curl -sf --max-time 10 \
  -H "Authorization: Bearer ${BRAINSTORMROUTER_API_KEY}" \
  "${BR_BASE_URL}/agent/profiles" | python3 -c "
import sys, json
data = json.load(sys.stdin)
profiles = data.get('profiles', data if isinstance(data, list) else [])
oc = [p for p in profiles if str(p.get('agentId', '')).startswith('oc-')]
print(f'Found {len(oc)} OpenClaw agents on BrainstormRouter:')
for p in oc:
    print(f'  - {p[\"agentId\"]}: \${p.get(\"budgetDailyUsd\", 0)}/day ({p.get(\"lifecycleState\", \"?\")})')
" 2>/dev/null || echo "WARNING: Could not verify via /agent/profiles — check BR dashboard"

# Cleanup
rm -f /tmp/br-bootstrap-response.json

echo ""
echo "Done. Total daily budget: \$14.50"
