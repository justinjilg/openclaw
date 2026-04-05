#!/usr/bin/env bash
set -euo pipefail

# BrainstormRouter Health Check
# Queries the BR API health endpoint and outputs a structured status report.
# READ-ONLY — no modifications.

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"

get_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

START_MS=$(get_ms)

# Health endpoint is at root path, no /v1 prefix, no auth required
BR_ROOT="${BR_BASE_URL%/v1}"
RESPONSE=$(curl -sf --max-time 10 "${BR_ROOT}/health" 2>&1) || {
  END_MS=$(get_ms)
  LATENCY=$((END_MS - START_MS))
  echo "## BR Health"
  echo "- Status: **DOWN**"
  echo "- Latency: ${LATENCY}ms"
  echo "- Error: API unreachable or returned error"
  exit 1
}

END_MS=$(get_ms)
LATENCY=$((END_MS - START_MS))

echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
status = d.get('status', 'unknown')
latency = ${LATENCY}
# Try common fields for model count
models = d.get('models_available', d.get('endpoints', d.get('modelsAvailable', 'N/A')))
uptime = d.get('uptime', d.get('uptimeSeconds', 'N/A'))
print('## BR Health')
print(f'- Status: **{status}**')
print(f'- Latency: {latency}ms')
print(f'- Models available: {models}')
if uptime != 'N/A':
    print(f'- Uptime: {uptime}s')
" 2>/dev/null || {
  echo "## BR Health"
  echo "- Status: **responded** (unparseable)"
  echo "- Latency: ${LATENCY}ms"
  echo "- Raw: $(echo "$RESPONSE" | head -c 200)"
}
