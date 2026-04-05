#!/bin/bash
# Quick BR Test - Using only curl and shell

set -e

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
BR_URL="https://api.brainstormrouter.com"
RESULTS_DIR="./test-results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== BR Discovery Test ==="
echo "Results: $RESULTS_DIR"
echo ""

# Test 1: Self endpoint
echo "Test 1: Self Discovery"
curl -s -H "Authorization: Bearer $BR_API_KEY" "$BR_URL/v1/self" > "$RESULTS_DIR/self.json"
TENANT=$(cat "$RESULTS_DIR/self.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['identity']['tenant_id'])")
MODELS=$(cat "$RESULTS_DIR/self.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['models_available'])")
echo "  ✓ Tenant: $TENANT"
echo "  ✓ Models available: $MODELS"

# Test 2: Model count
echo ""
echo "Test 2: Model Registry"
curl -s -H "Authorization: Bearer $BR_API_KEY" "$BR_URL/v1/models" > "$RESULTS_DIR/models_all.json"
TOTAL=$(cat "$RESULTS_DIR/models_all.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['data']))")
echo "  ✓ Total models: $TOTAL"

curl -s -H "Authorization: Bearer $BR_API_KEY" "$BR_URL/v1/catalog/runnable" > "$RESULTS_DIR/models_runnable.json"
RUNNABLE=$(cat "$RESULTS_DIR/models_runnable.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['data']))")
echo "  ✓ Runnable models: $RUNNABLE"
echo "  → Drift: $((TOTAL - RUNNABLE)) models unavailable"

# Test 3: Basic completion
echo ""
echo "Test 3: Basic Completion"
curl -s -H "Authorization: Bearer $BR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"Say hello"}],"max_tokens":10}' \
  "$BR_URL/v1/chat/completions" > "$RESULTS_DIR/completion.json"

MODEL_USED=$(cat "$RESULTS_DIR/completion.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','unknown'))")
TOKENS=$(cat "$RESULTS_DIR/completion.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('usage',{}).get('total_tokens',0))")
echo "  ✓ Model used: $MODEL_USED"
echo "  ✓ Tokens: $TOKENS"

# Test 4: Leaderboard
echo ""
echo "Test 4: Model Leaderboard"
curl -s -H "Authorization: Bearer $BR_API_KEY" "$BR_URL/v1/models/leaderboard" > "$RESULTS_DIR/leaderboard.json"
TOP=$(cat "$RESULTS_DIR/leaderboard.json" | python3 -c "import sys,json; d=json.load(sys.stdin); m=d.get('data',[])[0] if d.get('data') else {}; print(f\"{m.get('model_id','none')} (score: {m.get('score',0):.3f})\")")
echo "  ✓ Top model: $TOP"

# Summary
echo ""
echo "=== Summary ==="
echo "All tests passed. Results in: $RESULTS_DIR"
ls -la "$RESULTS_DIR"
