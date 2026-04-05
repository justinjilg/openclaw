#!/bin/bash
# BR Stress Test Suite - Phase 2: Single-Agent Load Testing
# Jazz (OpenClaw) - BrainstormRouter M2M Testing

set -e

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
BR_URL="https://api.brainstormrouter.com"
RESULTS_DIR="./test-results/phase2-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== BR Phase 2: Single-Agent Load Testing ==="
echo "Results: $RESULTS_DIR"
echo ""

# Helper function to make API calls
call_api() {
    local method=$1
    local endpoint=$2
    local data=$3
    if [ -n "$data" ]; then
        curl -s -X "$method" -H "Authorization: Bearer $BR_API_KEY" -H "Content-Type: application/json" -d "$data" "$BR_URL$endpoint"
    else
        curl -s -X "$method" -H "Authorization: Bearer $BR_API_KEY" "$BR_URL$endpoint"
    fi
}

# Test 2.1: Bootstrap an agent
echo "Test 2.1: Agent Bootstrap"
BOOTSTRAP_RESPONSE=$(call_api POST "/v1/agent/bootstrap" '{
    "name": "jazz-load-test-agent",
    "description": "Agent for load testing BR routing intelligence",
    "budget_usd": 5.00,
    "capabilities": ["memory", "tool_use", "mesh"]
}')
echo "$BOOTSTRAP_RESPONSE" > "$RESULTS_DIR/agent_bootstrap.json"

AGENT_ID=$(echo "$BOOTSTRAP_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('agent_id','unknown'))")
AGENT_TOKEN=$(echo "$BOOTSTRAP_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))")

if [ "$AGENT_ID" != "unknown" ] && [ -n "$AGENT_TOKEN" ]; then
    echo "  ✓ Agent bootstrapped: $AGENT_ID"
    echo "  ✓ Token received (length: ${#AGENT_TOKEN})"
else
    echo "  ✗ Bootstrap failed"
    exit 1
fi

# Test 2.2: Routing intelligence - send 10 requests, track model distribution
echo ""
echo "Test 2.2: Routing Intelligence (10 requests)"

MODEL_COUNTS="{}"
for i in {1..10}; do
    RESPONSE=$(call_api POST "/v1/chat/completions" '{
        "model": "auto",
        "messages": [{"role": "user", "content": "Explain quantum computing in simple terms"}],
        "max_tokens": 50
    }')
    
    MODEL=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','unknown'))")
    echo "  Request $i: $MODEL"
    
    # Count models
    MODEL_COUNTS=$(echo "$MODEL_COUNTS" | python3 -c "import sys,json; d=json.load(sys.stdin); m='$MODEL'; d[m]=d.get(m,0)+1; print(json.dumps(d))")
    
    # Small delay to avoid rate limits
    sleep 0.5
done

echo "$MODEL_COUNTS" > "$RESULTS_DIR/routing_distribution.json"
echo "  ✓ Model distribution saved"

# Test 2.3: Test different complexity levels
echo ""
echo "Test 2.3: Complexity-Based Routing"

# Simple prompt
SIMPLE=$(call_api POST "/v1/chat/completions" '{
    "model": "auto",
    "messages": [{"role": "user", "content": "Hi"}],
    "max_tokens": 10
}')
SIMPLE_MODEL=$(echo "$SIMPLE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','unknown'))")
echo "  Simple prompt ('Hi'): $SIMPLE_MODEL"

# Complex prompt  
COMPLEX=$(call_api POST "/v1/chat/completions" '{
    "model": "auto",
    "messages": [{"role": "user", "content": "Analyze the implications of quantum supremacy on cryptography, focusing on Shor algorithm and lattice-based post-quantum approaches. Include code examples in Python."}],
    "max_tokens": 500
}')
COMPLEX_MODEL=$(echo "$COMPLEX" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','unknown'))")
echo "  Complex prompt: $COMPLEX_MODEL"

# Test 2.4: Budget tracking
echo ""
echo "Test 2.4: Budget Tracking"
BUDGET_BEFORE=$(call_api GET "/v1/budget/status" "")
echo "$BUDGET_BEFORE" > "$RESULTS_DIR/budget_before.json"
BUDGET_SPENT_BEFORE=$(echo "$BUDGET_BEFORE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('daily',{}).get('spent_usd',0))")
echo "  Budget before: $BUDGET_SPENT_BEFORE USD"

# Make 5 more requests to spend budget
for i in {1..5}; do
    call_api POST "/v1/chat/completions" '{
        "model": "auto",
        "messages": [{"role": "user", "content": "Write a short poem about AI"}],
        "max_tokens": 100
    }' > /dev/null
    sleep 0.3
done

BUDGET_AFTER=$(call_api GET "/v1/budget/status" "")
echo "$BUDGET_AFTER" > "$RESULTS_DIR/budget_after.json"
BUDGET_SPENT_AFTER=$(echo "$BUDGET_AFTER" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('daily',{}).get('spent_usd',0))")
echo "  Budget after: $BUDGET_SPENT_AFTER USD"
DELTA=$(python3 -c "print(f'{($BUDGET_SPENT_AFTER - $BUDGET_SPENT_BEFORE):.6f}')")
echo "  Spent in test: $DELTA USD"

# Test 2.5: Memory system
echo ""
echo "Test 2.5: Memory System"

# Store a memory
MEMORY=$(call_api POST "/v1/memory/entries" '{
    "content": "Jazz is testing BrainstormRouter memory system",
    "block": "project",
    "tags": ["test", "jazz", "br"]
}')
echo "$MEMORY" > "$RESULTS_DIR/memory_store.json"
MEMORY_ID=$(echo "$MEMORY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id','unknown'))")
echo "  ✓ Memory stored: $MEMORY_ID"

# Query memories
MEMORIES=$(call_api GET "/v1/memory/entries?block=project" "")
echo "$MEMORIES" > "$RESULTS_DIR/memory_query.json"
MEMORY_COUNT=$(echo "$MEMORIES" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',[])))")
echo "  ✓ Memories in project block: $MEMORY_COUNT"

# Test 2.6: Error recovery
echo ""
echo "Test 2.6: Error Recovery"

# Invalid model
ERROR_RESPONSE=$(call_api POST "/v1/chat/completions" '{
    "model": "nonexistent-model-xyz",
    "messages": [{"role": "user", "content": "Hello"}]
}' 2>/dev/null || echo '{"error": "request_failed"}')
echo "$ERROR_RESPONSE" > "$RESULTS_DIR/error_invalid_model.json"
HAS_ERROR=$(echo "$ERROR_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'error' in d else 'no')")
echo "  Invalid model error handled: $HAS_ERROR"

# Check for recovery hint
RECOVERY=$(echo "$ERROR_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('recovery_hint','none'))")
echo "  Recovery hint: $RECOVERY"

# Summary
echo ""
echo "=== Phase 2 Summary ==="
echo "Agent ID: $AGENT_ID"
echo "Total spent: $DELTA USD"
echo "Results saved to: $RESULTS_DIR"
ls -la "$RESULTS_DIR"

# Save agent info for cleanup
echo "$AGENT_ID" > "$RESULTS_DIR/agent_id.txt"
