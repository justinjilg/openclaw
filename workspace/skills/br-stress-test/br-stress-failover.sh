#!/usr/bin/env bash
set -euo pipefail

# BrainstormRouter Stress Test — Failover & Error Handling
# Sends requests with known-bad models, invalid params, and edge cases
# to validate error responses, recovery hints, and graceful degradation.
# READ-ONLY — no BR config modifications.

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"
API_KEY="${BRAINSTORMROUTER_API_KEY:?BRAINSTORMROUTER_API_KEY not set}"
RESULTS_DIR="${RESULTS_DIR:-/home/node/workspace/workspaces/ops/br-stress-results}"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUTFILE="$RESULTS_DIR/failover-${TIMESTAMP}.json"

echo "## BR Stress Test — Failover & Error Handling"
echo "- Timestamp: $TIMESTAMP"
echo ""

RESULTS="["
IDX=0

# Test case runner
run_test() {
  local NAME="$1"
  local MODEL="$2"
  local EXTRA_OPTS="${3:-}"

  local START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  local BODY="{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}],\"max_tokens\":10${EXTRA_OPTS}}"

  local RESPONSE
  RESPONSE=$(curl -s --max-time 15 -w "\n%{http_code}" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$BODY" \
    "${BR_BASE_URL}/chat/completions" 2>&1) || true

  local END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  local LATENCY=$((END_MS - START_MS))
  local HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  local RESP_BODY=$(echo "$RESPONSE" | sed '$d')

  local PARSED
  PARSED=$(echo "$RESP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    if 'choices' in d:
        print(json.dumps({'status': 'ok', 'content': d['choices'][0]['message'].get('content','')[:50]}))
    else:
        err = d.get('error', {})
        rec = d.get('recovery', err.get('recovery', {}))
        print(json.dumps({
            'status': 'error',
            'error_type': err.get('type', 'unknown'),
            'error_code': err.get('code', ''),
            'error_message': err.get('message', '')[:200],
            'has_recovery': bool(rec),
            'recovery_action': rec.get('action', ''),
        }))
except Exception as e:
    print(json.dumps({'status': 'parse_error', 'raw': str(e)[:100]}))
" 2>/dev/null || echo '{"status":"parse_error"}')

  local STATUS=$(echo "$PARSED" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','?'))")
  if [ "$STATUS" = "ok" ]; then
    echo "  [PASS] $NAME — responded OK (${LATENCY}ms)"
  else
    local ERR_TYPE=$(echo "$PARSED" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error_type','?'))")
    local HAS_REC=$(echo "$PARSED" | python3 -c "import json,sys; print(json.load(sys.stdin).get('has_recovery',False))")
    echo "  [${HTTP_CODE}] $NAME — $ERR_TYPE, recovery=$HAS_REC (${LATENCY}ms)"
  fi

  local ENTRY=$(echo "$PARSED" | python3 -c "
import json, sys
d = json.load(sys.stdin)
d['test_name'] = '$NAME'
d['model'] = '$MODEL'
d['http'] = $HTTP_CODE
d['latency_ms'] = $LATENCY
print(json.dumps(d))
")

  if [ "$IDX" -gt 0 ]; then RESULTS="$RESULTS,"; fi
  RESULTS="$RESULTS$ENTRY"
  IDX=$((IDX + 1))
}

# --- Test cases ---

# 1. Non-existent model
run_test "nonexistent_model" "openai/gpt-999"

# 2. Non-existent provider
run_test "nonexistent_provider" "fakeprovider/fake-model"

# 3. Model with billing issues (Anthropic)
run_test "billing_error" "anthropic/claude-haiku-4-5-20251001"

# 4. Empty model string
run_test "empty_model" ""

# 5. Deprecated model
run_test "deprecated_model" "openai/gpt-3.5-turbo-16k"

# 6. Image model via chat endpoint
run_test "wrong_modality" "openai/dall-e-3"

# 7. Embedding model via chat endpoint
run_test "embedding_via_chat" "openai/text-embedding-3-small"

# 8. Audio model via chat endpoint
run_test "audio_via_chat" "openai/whisper-1"

# 9. Valid model, zero max_tokens
run_test "zero_tokens" "openai/gpt-4.1-nano" ",\"max_tokens\":0"

# 10. Valid model, huge max_tokens
run_test "huge_tokens" "openai/gpt-4.1-nano" ",\"max_tokens\":999999"

# 11. Working model (control)
run_test "control_openai" "openai/gpt-4.1-nano"

# 12. Working model (control — different provider)
run_test "control_google" "google/gemini-2.5-flash"

RESULTS="$RESULTS]"

echo "$RESULTS" | python3 -m json.tool > "$OUTFILE" 2>/dev/null || echo "$RESULTS" > "$OUTFILE"

echo ""
python3 -c "
import json
with open('$OUTFILE') as f:
    results = json.load(f)
ok = sum(1 for r in results if r['status'] == 'ok')
errs = [r for r in results if r['status'] != 'ok']
with_recovery = sum(1 for r in errs if r.get('has_recovery'))
print(f'## Summary: {ok} passed, {len(errs)} errors ({with_recovery} with recovery hints)')
print(f'Results saved to: $OUTFILE')
"
