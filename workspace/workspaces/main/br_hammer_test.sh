#!/bin/bash
# BR Comprehensive Stress Test - Full System Hammer
# Jazz (OpenClaw) - With full logging enabled

set -e

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
BR_URL="https://api.brainstormrouter.com"
RESULTS_DIR="./test-results/hammer-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

REQUEST_COUNT=0
ERROR_COUNT=0

echo "=== BR COMPREHENSIVE STRESS TEST ==="
echo "Started: $(date)"
echo "Results: $RESULTS_DIR"
echo ""

# Helper: Make API call and track metrics
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local label=$4
    
    local start_time=$(date +%s%N)
    local http_code
    local response
    
    if [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Authorization: Bearer $BR_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$data" "$BR_URL$endpoint" 2>&1)
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Authorization: Bearer $BR_API_KEY" \
            "$BR_URL$endpoint" 2>&1)
    fi
    
    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    local end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    
    REQUEST_COUNT=$((REQUEST_COUNT + 1))
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo "  ✓ $label (${duration_ms}ms)"
        echo "$body" > "$RESULTS_DIR/${label// /_}.json"
        echo "$body"
        return 0
    else
        ERROR_COUNT=$((ERROR_COUNT + 1))
        echo "  ✗ $label FAILED (HTTP $http_code, ${duration_ms}ms)"
        echo "$body" > "$RESULTS_DIR/${label// /_}_error.json"
        echo "{}"
        return 1
    fi
}

# PHASE 1: Discovery Baseline (re-verify)
echo "=== PHASE 1: Discovery Baseline ==="
SELF=$(api_call GET "/v1/self" "" "Self Discovery")
MODELS=$(api_call GET "/v1/models" "" "Model Registry")
RUNNABLE=$(api_call GET "/v1/catalog/runnable" "" "Runnable Models")
LEADERBOARD=$(api_call GET "/v1/models/leaderboard" "" "Model Leaderboard")
BUDGET=$(api_call GET "/v1/budget/status" "" "Budget Status")

echo ""
echo "=== PHASE 2: Routing Intelligence Deep Dive ==="

# Test 2.1: Varied complexity prompts
echo "Test 2.1: Complexity-Based Routing (10 varied prompts)"

PROMPTS=(
    'Hi'
    'What is 2+2?'
    'Explain quantum computing simply'
    'Write a Python function to sort a list'
    'Analyze the economic implications of AI on labor markets'
    'Compare and contrast Keynesian vs Austrian economics'
    'Design a distributed system architecture for a real-time chat app'
    'Write a sonnet about artificial intelligence'
    'Debug this code: def foo(x): return x++'
    'Summarize the theory of relativity in one paragraph'
)

MODEL_DISTRIBUTION="{}"
for i in "${!PROMPTS[@]}"; do
    PROMPT="${PROMPTS[$i]}"
    echo "  Prompt $i: ${PROMPT:0:40}..."
    
    RESPONSE=$(api_call POST "/v1/chat/completions" "{
        \"model\": \"auto\",
        \"messages\": [{\"role\": \"user\", \"content\": \"$PROMPT\"}],
        \"max_tokens\": 100
    }" "Routing_$i" 2>/dev/null)
    
    MODEL=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','unknown'))" 2>/dev/null)
    
    # Track distribution
    MODEL_DISTRIBUTION=$(echo "$MODEL_DISTRIBUTION" | python3 -c "
import sys,json
m='$MODEL'
d=json.load(sys.stdin)
if m != 'unknown' and m != '{}':
    d[m]=d.get(m,0)+1
print(json.dumps(d))
" 2>/dev/null || echo "$MODEL_DISTRIBUTION")
    
    sleep 0.2
done

echo ""
echo "Model Distribution:"
echo "$MODEL_DISTRIBUTION" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'  {k}: {v}') for k,v in sorted(d.items(), key=lambda x: -x[1])]" 2>/dev/null || echo "  (could not parse)"
echo "$MODEL_DISTRIBUTION" > "$RESULTS_DIR/model_distribution.json"

# Test 2.2: Auto variants
echo ""
echo "Test 2.2: Auto Variants (floor, fast, best)"
for variant in "auto:floor" "auto:fast" "auto:best"; do
    echo "  Testing $variant..."
    RESPONSE=$(api_call POST "/v1/chat/completions" "{
        \"model\": \"$variant\",
        \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}],
        \"max_tokens\": 20
    }" "Variant_$variant" 2>/dev/null)
    MODEL=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','unknown'))" 2>/dev/null)
    echo "    → $MODEL"
    sleep 0.2
done

# Test 2.3: Explicit model selection
echo ""
echo "Test 2.3: Explicit Models"
EXPLICIT_MODELS=("anthropic/claude-sonnet-4" "openai/gpt-4o" "deepseek-chat")
for model in "${EXPLICIT_MODELS[@]}"; do
    echo "  Testing $model..."
    RESPONSE=$(api_call POST "/v1/chat/completions" "{
        \"model\": \"$model\",
        \"messages\": [{\"role\": \"user\", \"content\": \"Hi\"}],
        \"max_tokens\": 10
    }" "Explicit_$model" 2>/dev/null)
    sleep 0.3
done

echo ""
echo "=== PHASE 3: Agent Lifecycle ==="

# Test 3.1: Bootstrap multiple agents
echo "Test 3.1: Bootstrap 5 Agents"
AGENT_IDS=()
for i in {1..5}; do
    AGENT_ID="jazz-hammer-$(date +%s)-$i"
    RESPONSE=$(api_call POST "/v1/agent/bootstrap" "{
        \"agent_id\": \"$AGENT_ID\",
        \"name\": \"Hammer Test Agent $i\",
        \"budget_usd\": 1.00
    }" "Bootstrap_Agent_$i" 2>/dev/null)
    
    ID=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('profile',{}).get('agentId',''))" 2>/dev/null)
    if [ -n "$ID" ]; then
        AGENT_IDS+=("$ID")
        echo "  ✓ Agent $i: $ID"
    fi
    sleep 0.2
done

echo "  Bootstrapped ${#AGENT_IDS[@]} agents"

# Test 3.2: Agent delegation (if we have agents)
if [ ${#AGENT_IDS[@]} -gt 0 ]; then
    echo ""
    echo "Test 3.2: Agent Delegation"
    FIRST_AGENT="${AGENT_IDS[0]}"
    RESPONSE=$(api_call POST "/v1/agent/delegate" "{
        \"parent_agent_id\": \"$FIRST_AGENT\",
        \"child_agent_id\": \"${AGENT_IDS[1]}\",
        \"budget_slice_usd\": 0.50
    }" "Delegation_Test" 2>/dev/null || echo "  Delegation endpoint not available or failed")
fi

echo ""
echo "=== PHASE 4: Error & Edge Cases ==="

# Test 4.1: Invalid requests
echo "Test 4.1: Error Handling"
api_call POST "/v1/chat/completions" '{"model": "nonexistent-model-xyz"}' "Error_Invalid_Model" 2>/dev/null || true
api_call POST "/v1/chat/completions" '{"model": "auto"}' "Error_Missing_Messages" 2>/dev/null || true
api_call GET "/v1/nonexistent" "" "Error_Invalid_Endpoint" 2>/dev/null || true

# Test 4.2: Rate limit probe
echo ""
echo "Test 4.2: Rapid Fire (10 requests, 0.1s delay)"
for i in {1..10}; do
    RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"model": "auto", "messages": [{"role": "user", "content": "Hi"}], "max_tokens": 5}' \
        "$BR_URL/v1/chat/completions" 2>/dev/null | head -c 100)
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"model": "auto", "messages": [{"role": "user", "content": "Hi"}], "max_tokens": 5}' \
        "$BR_URL/v1/chat/completions" 2>/dev/null)
    echo -n " $http_code"
    sleep 0.1
done
echo ""

echo ""
echo "=== PHASE 5: Memory System ==="

# Test 5.1: Store memories
echo "Test 5.1: Memory Operations"
for i in {1..5}; do
    RESPONSE=$(api_call POST "/v1/memory/entries" "{
        \"content\": \"Test memory entry $i from hammer test\",
        \"block\": \"project\",
        \"tags\": [\"test\", \"hammer\", \"entry$i\"]
    }" "Memory_Store_$i" 2>/dev/null)
    sleep 0.2
done

# Test 5.2: Query memories
api_call GET "/v1/memory/entries?block=project" "" "Memory_Query" 2>/dev/null || true

# Test 5.3: Semantic search (if available)
api_call POST "/v1/memory/query" '{
    "query": "test memory",
    "block": "project"
}' "Memory_Search" 2>/dev/null || true

echo ""
echo "=== PHASE 6: Provider Health & Failover ==="

# Test 6.1: Provider status
echo "Test 6.1: Provider Health Check"
HEALTH=$(api_call GET "/v1/health/providers" "" "Provider_Health")

# Test 6.2: Insights
echo ""
echo "Test 6.2: Insights & Analytics"
api_call GET "/v1/insights/daily" "" "Insights_Daily" 2>/dev/null || true
api_call GET "/v1/insights/waste" "" "Insights_Waste" 2>/dev/null || true

# Final Summary
echo ""
echo "=========================================="
echo "STRESS TEST COMPLETE"
echo "=========================================="
echo "Total requests: $REQUEST_COUNT"
echo "Errors: $ERROR_COUNT"
echo "Success rate: $(( 100 * (REQUEST_COUNT - ERROR_COUNT) / REQUEST_COUNT ))%"
echo "Results saved to: $RESULTS_DIR"
echo "Completed: $(date)"
echo ""

# List all result files
echo "Result files:"
ls -la "$RESULTS_DIR" | tail -n +4
