#!/bin/bash
# BR Phase 2 v2 - Using bootstrapped agent

set -e

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
AGENT_JWT="eyJhbGciOiJIUzI1NiJ9.eyJ0aWQiOiI0YjQ5MGI1NC01YjJjLTQ5ZDktYjYyMS0xNTgwODUxYTk1NmMiLCJpYXQiOjE3NzM3NTQwODEsImlzcyI6ImJyYWluc3Rvcm1yb3V0ZXIiLCJhdWQiOiJicmFpbnN0b3Jtcm91dGVyLWFwaSIsInN1YiI6ImphenotbG9hZC10ZXN0LTAwMSIsImV4cCI6MTc3Mzc1NzY4MX0.9Vraz9v0L7kJNGLeaU0rM4_bCX5sM0UDS8fwI5m-26A"
BR_URL="https://api.brainstormrouter.com"
RESULTS_DIR="./test-results/phase2-v2-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== BR Phase 2 v2: Agent-Scoped Testing ==="
echo "Agent: jazz-load-test-001"
echo "Results: $RESULTS_DIR"
echo ""

# Test with agent JWT
echo "Test 1: Agent-scoped completion"
RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $AGENT_JWT" \
    -H "Content-Type: application/json" \
    -d '{"model": "auto", "messages": [{"role": "user", "content": "Hello from agent"}], "max_tokens": 20}' \
    "$BR_URL/v1/chat/completions")

echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  Model:', d.get('model','unknown')); print('  Content:', d.get('choices',[{}])[0].get('message',{}).get('content','')[:50])"

# Test routing distribution
echo ""
echo "Test 2: Routing Distribution (5 requests)"
for i in {1..5}; do
    RESP=$(curl -s -X POST \
        -H "Authorization: Bearer $AGENT_JWT" \
        -H "Content-Type: application/json" \
        -d '{"model": "auto", "messages": [{"role": "user", "content": "Explain AI"}], "max_tokens": 30}' \
        "$BR_URL/v1/chat/completions")
    MODEL=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','unknown'))")
    echo "  Request $i: $MODEL"
    sleep 0.3
done

# Test memory with agent
echo ""
echo "Test 3: Agent Memory"
MEM_RESP=$(curl -s -X POST \
    -H "Authorization: Bearer $AGENT_JWT" \
    -H "Content-Type: application/json" \
    -d '{"content": "Agent jazz-load-test-001 was here", "block": "project"}' \
    "$BR_URL/v1/memory/entries")

echo "$MEM_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  Memory ID:', d.get('id','failed'))"

# Query agent's memories
MEM_QUERY=$(curl -s -H "Authorization: Bearer $AGENT_JWT" "$BR_URL/v1/memory/entries?block=project")
COUNT=$(echo "$MEM_QUERY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',[])))")
echo "  Memories stored: $COUNT"

echo ""
echo "=== Phase 2 v2 Complete ==="
