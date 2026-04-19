#!/usr/bin/env bash
set -euo pipefail

# BrainstormRouter Stress Test — Burst (Rate Limit Testing)
# Fires N concurrent requests to test rate limiting (60 RPM),
# queuing behavior, and error responses under load.
# READ-ONLY — no BR config modifications.

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"
API_KEY="${BRAINSTORMROUTER_API_KEY:?BRAINSTORMROUTER_API_KEY not set}"
RESULTS_DIR="${RESULTS_DIR:-/home/node/workspace/workspaces/ops/br-stress-results}"
mkdir -p "$RESULTS_DIR"

# Configurable parameters
CONCURRENCY="${1:-10}"        # Parallel requests
TOTAL_REQUESTS="${2:-30}"     # Total requests to send
MODEL="${3:-openai/gpt-4.1-nano}"  # Cheapest model
MAX_TOKENS=10
PROMPT="Say OK"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUTFILE="$RESULTS_DIR/burst-${TIMESTAMP}.json"
TMPDIR=$(mktemp -d)

echo "## BR Stress Test — Burst"
echo "- Concurrency: $CONCURRENCY"
echo "- Total requests: $TOTAL_REQUESTS"
echo "- Model: $MODEL"
echo "- Timestamp: $TIMESTAMP"
echo ""

# Worker function — sends one request, writes result to temp file
send_request() {
  local IDX=$1
  local START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  local RESPONSE
  local HTTP_CODE
  RESPONSE=$(curl -s --max-time 30 -w "\n%{http_code}" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}],\"max_tokens\":$MAX_TOKENS}" \
    "${BR_BASE_URL}/chat/completions" 2>&1)

  local END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  local LATENCY=$((END_MS - START_MS))

  # Split response body and HTTP code
  HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  local BODY=$(echo "$RESPONSE" | sed '$d')

  echo "$BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    if 'choices' in d:
        result = {'idx': $IDX, 'status': 'ok', 'http': $HTTP_CODE, 'latency_ms': $LATENCY,
                  'tokens': d.get('usage', {}).get('total_tokens', 0)}
    else:
        err = d.get('error', {})
        result = {'idx': $IDX, 'status': 'error', 'http': $HTTP_CODE, 'latency_ms': $LATENCY,
                  'error_type': err.get('type', 'unknown'),
                  'error_code': err.get('code', ''),
                  'error_message': err.get('message', '')[:150]}
    print(json.dumps(result))
except:
    print(json.dumps({'idx': $IDX, 'status': 'parse_error', 'http': $HTTP_CODE, 'latency_ms': $LATENCY}))
" > "$TMPDIR/result-$IDX.json" 2>/dev/null
}

# Fire requests with concurrency control
RUNNING=0
for i in $(seq 1 "$TOTAL_REQUESTS"); do
  send_request "$i" &
  RUNNING=$((RUNNING + 1))
  if [ "$RUNNING" -ge "$CONCURRENCY" ]; then
    wait -n 2>/dev/null || wait
    RUNNING=$((RUNNING - 1))
  fi
done
wait

# Collect results
echo "[" > "$OUTFILE"
FIRST=1
for f in "$TMPDIR"/result-*.json; do
  [ -f "$f" ] || continue
  if [ "$FIRST" -eq 0 ]; then echo "," >> "$OUTFILE"; fi
  cat "$f" >> "$OUTFILE"
  FIRST=0
done
echo "]" >> "$OUTFILE"

# Cleanup
rm -rf "$TMPDIR"

# Summary
python3 -c "
import json
with open('$OUTFILE') as f:
    results = json.load(f)

ok = [r for r in results if r['status'] == 'ok']
errors = [r for r in results if r['status'] != 'ok']
rate_limited = [r for r in errors if r.get('error_code') == 'rate_limit_exceeded' or r.get('http') == 429]

latencies = [r['latency_ms'] for r in ok]
avg_lat = sum(latencies) / len(latencies) if latencies else 0
p50 = sorted(latencies)[len(latencies)//2] if latencies else 0
p99 = sorted(latencies)[int(len(latencies)*0.99)] if latencies else 0

print(f'## Results')
print(f'- Passed: {len(ok)}/{len(results)}')
print(f'- Errors: {len(errors)} ({len(rate_limited)} rate-limited)')
print(f'- Latency — avg: {avg_lat:.0f}ms, p50: {p50}ms, p99: {p99}ms')
if rate_limited:
    print(f'- Rate limit hit after request #{min(r[\"idx\"] for r in rate_limited)}')
for e in errors[:5]:
    print(f'  [{e.get(\"http\",\"?\")}] #{e[\"idx\"]}: {e.get(\"error_type\",\"?\")} — {e.get(\"error_message\",\"?\")[:80]}')
print(f'')
print(f'Results saved to: $OUTFILE')
"
