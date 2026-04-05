#!/usr/bin/env bash
set -euo pipefail

# BrainstormRouter Usage Report
# Queries usage by cost center and agent budget limits.
# READ-ONLY — no modifications.

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"

if [ -z "${BRAINSTORMROUTER_ADMIN_KEY:-}" ]; then
  echo "ERROR: BRAINSTORMROUTER_ADMIN_KEY not set" >&2
  exit 1
fi

echo "## BR Usage"
echo ""

# Get usage by cost center
USAGE=$(curl -sf --max-time 10 \
  -H "Authorization: Bearer ${BRAINSTORMROUTER_ADMIN_KEY}" \
  "${BR_BASE_URL}/usage/by-cost-center" 2>&1) || {
  echo "- Cost center data: **unavailable**"
}

if [ -n "${USAGE:-}" ]; then
  echo "$USAGE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
period = d.get('period', '?')
since = d.get('since', '?')
data = d.get('data', [])
if data:
    print(f'### Cost Centers (period: {period}, since: {since})')
    print('')
    print('| Cost Center | Requests | Cost |')
    print('|-------------|----------|------|')
    for cc in data:
        print(f'| {cc.get(\"costCenter\", \"?\")} | {cc.get(\"requests\", 0)} | \${cc.get(\"costUsd\", 0):.2f} |')
else:
    print(f'No usage data yet (period: {period}, since: {since})')
" 2>/dev/null || echo "- Cost center data: (parse error)"
fi

echo ""

# Get agent budgets for context
PROFILES=$(curl -sf --max-time 10 \
  -H "Authorization: Bearer ${BRAINSTORMROUTER_ADMIN_KEY}" \
  "${BR_BASE_URL}/agent/profiles" 2>&1) || true

if [ -n "${PROFILES:-}" ]; then
  echo "### Agent Budgets"
  echo ""
  echo "| Agent | Daily Limit | Monthly Limit | State |"
  echo "|-------|------------|--------------|-------|"
  echo "$PROFILES" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('profiles', []):
    aid = p.get('agentId', '?')
    daily = p.get('budgetDailyUsd', 0)
    monthly = p.get('budgetMonthlyUsd', 0)
    state = p.get('lifecycleState', '?')
    print(f'| {aid} | \${daily:.2f} | \${monthly:.2f} | {state} |')
" 2>/dev/null || echo "| (error) | - | - | - |"
fi

# Check insights if available
INSIGHTS=$(curl -sf --max-time 10 \
  -H "Authorization: Bearer ${BRAINSTORMROUTER_ADMIN_KEY}" \
  "${BR_BASE_URL}/insights/daily" 2>&1) || true

if [ -n "${INSIGHTS:-}" ]; then
  echo ""
  echo "$INSIGHTS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
status = d.get('status', '?')
if status == 'warming_up':
    needed = d.get('minRequestsNeeded', '?')
    total = d.get('totalRequests', 0)
    print(f'### Insights: warming up ({total}/{needed} requests)')
else:
    print('### Daily Insights')
    for k, v in d.items():
        if k != 'status':
            print(f'- {k}: {v}')
" 2>/dev/null || true
fi
