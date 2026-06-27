#!/usr/bin/env bash
set -euo pipefail

# BrainstormRouter Stress Test — Provider Sweep
# Sends one request to each provider to validate routing, adapter selection,
# and response parsing. Captures latency, status, and model metadata.
# READ-ONLY — no BR config modifications.

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"
API_KEY="${BRAINSTORMROUTER_API_KEY:?BRAINSTORMROUTER_API_KEY not set}"
RESULTS_DIR="${RESULTS_DIR:-/home/node/workspace/workspaces/ops/br-stress-results}"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUTFILE="$RESULTS_DIR/sweep-${TIMESTAMP}.json"

# One representative model per provider (cheapest/fastest)
MODELS=(
  "openai/gpt-4.1-nano"
  "google/gemini-2.5-flash"
  "deepseek/deepseek-chat"
  "x-ai/grok-3-fast"
  "perplexity-ai/sonar"
  "moonshot/kimi-k2.5"
  "anthropic/claude-haiku-4-5-20251001"
)

PROMPT="Respond with exactly: PONG"
MAX_TOKENS=50

echo "## BR Stress Test — Provider Sweep"
echo "- Timestamp: $TIMESTAMP"
echo "- Models: ${#MODELS[@]}"
echo ""

# JSON array accumulator
RESULTS="["

for i in "${!MODELS[@]}"; do
  MODEL="${MODELS[$i]}"
  PROVIDER="${MODEL%%/*}"

  START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  RESPONSE=$(curl -sf --max-time 30 \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}],\"max_tokens\":$MAX_TOKENS}" \
    "${BR_BASE_URL}/chat/completions" 2>&1) && STATUS="ok" || STATUS="error"

  END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  LATENCY=$((END_MS - START_MS))

  # Parse response
  PARSED=$(echo "$RESPONSE" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    if 'choices' in d:
        content = d['choices'][0]['message'].get('content', '') or ''
        usage = d.get('usage', {})
        print(json.dumps({
            'status': 'ok',
            'content': content[:100],
            'prompt_tokens': usage.get('prompt_tokens', 0),
            'completion_tokens': usage.get('completion_tokens', 0),
            'model_returned': d.get('model', ''),
        }))
    else:
        err = d.get('error', {})
        print(json.dumps({
            'status': 'error',
            'error_type': err.get('type', 'unknown'),
            'error_message': err.get('message', str(d))[:200],
        }))
except Exception as e:
    print(json.dumps({'status': 'parse_error', 'error_message': str(e)[:200]}))
" 2>/dev/null || echo '{"status":"parse_error","error_message":"python parse failed"}')

  # Print live status
  RESULT_STATUS=$(echo "$PARSED" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','?'))")
  if [ "$RESULT_STATUS" = "ok" ]; then
    echo "  [PASS] $MODEL (${LATENCY}ms)"
  else
    ERROR_MSG=$(echo "$PARSED" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error_message','?')[:80])")
    echo "  [FAIL] $MODEL (${LATENCY}ms) — $ERROR_MSG"
  fi

  # Build JSON entry
  ENTRY=$(echo "$PARSED" | python3 -c "
import json, sys
d = json.load(sys.stdin)
d['model'] = '$MODEL'
d['provider'] = '$PROVIDER'
d['latency_ms'] = $LATENCY
print(json.dumps(d))
")

  if [ "$i" -gt 0 ]; then RESULTS="$RESULTS,"; fi
  RESULTS="$RESULTS$ENTRY"
done

RESULTS="$RESULTS]"

# Write results file
echo "$RESULTS" | python3 -m json.tool > "$OUTFILE" 2>/dev/null || echo "$RESULTS" > "$OUTFILE"

echo ""
echo "Results saved to: $OUTFILE"

# Summary
echo ""
echo "$RESULTS" | python3 -c "
import json, sys
results = json.load(sys.stdin)
passed = sum(1 for r in results if r['status'] == 'ok')
failed = len(results) - passed
avg_latency = sum(r['latency_ms'] for r in results if r['status'] == 'ok') / max(passed, 1)
print(f'## Summary: {passed}/{len(results)} passed, {failed} failed, avg latency {avg_latency:.0f}ms')
"
