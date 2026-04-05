#!/bin/bash
# Rapid BR Test - Simple and robust

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
BR_URL="https://api.brainstormrouter.com"

echo "=== Rapid BR Hammer Test ==="
echo "Started: $(date)"
echo ""

# 1. Quick self check
echo "1. Self check..."
SELF=$(curl -s -H "Authorization: Bearer $BR_API_KEY" "$BR_URL/v1/self")
TENANT=$(echo "$SELF" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['identity']['tenant_id'])")
MODELS=$(echo "$SELF" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['models_available'])")
echo "   Tenant: $TENANT"
echo "   Models: $MODELS"

# 2. Send 20 requests rapidly
echo ""
echo "2. Rapid fire 20 requests..."
for i in {1..20}; do
    RESP=$(curl -s -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"model": "auto", "messages": [{"role": "user", "content": "Test"}], "max_tokens": 5}' \
        "$BR_URL/v1/chat/completions")
    MODEL=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','ERR'))")
    echo -n "[$MODEL] "
    sleep 0.1
done
echo ""

# 3. Test different prompts
echo ""
echo "3. Varied complexity prompts..."
PROMPTS=("Hi" "Explain AI" "Write Python to sort" "Analyze quantum economics")
for PROMPT in "${PROMPTS[@]}"; do
    RESP=$(curl -s -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"model\": \"auto\", \"messages\": [{\"role\": \"user\", \"content\": \"$PROMPT\"}], \"max_tokens\": 30}" \
        "$BR_URL/v1/chat/completions")
    MODEL=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','ERR'))")
    echo "   '$PROMPT' -> $MODEL"
    sleep 0.2
done

# 4. Test auto variants
echo ""
echo "4. Auto variants..."
for VARIANT in "auto" "auto:floor" "auto:fast" "auto:best"; do
    RESP=$(curl -s -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"model\": \"$VARIANT\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}], \"max_tokens\": 10}" \
        "$BR_URL/v1/chat/completions")
    MODEL=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','ERR'))")
    echo "   $VARIANT -> $MODEL"
    sleep 0.2
done

# 5. Bootstrap agents
echo ""
echo "5. Bootstrap 3 agents..."
for i in {1..3}; do
    RESP=$(curl -s -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"agent_id\": \"hammer-agent-$i\", \"name\": \"Hammer Agent $i\", \"budget_usd\": 2.00}" \
        "$BR_URL/v1/agent/bootstrap")
    AID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('profile',{}).get('agentId','ERR'))")
    echo "   Agent $i: $AID"
    sleep 0.3
done

# 6. Memory test
echo ""
echo "6. Memory operations..."
STORE=$(curl -s -X POST \
    -H "Authorization: Bearer $BR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"content": "Hammer test memory", "block": "project"}' \
    "$BR_URL/v1/memory/entries")
MID=$(echo "$STORE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id','ERR'))")
echo "   Store: $MID"

QUERY=$(curl -s -H "Authorization: Bearer $BR_API_KEY" "$BR_URL/v1/memory/entries?block=project")
COUNT=$(echo "$QUERY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',[])))")
echo "   Query: $COUNT entries"

# 7. Error tests
echo ""
echo "7. Error handling..."
ERR1=$(curl -s -X POST \
    -H "Authorization: Bearer $BR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model": "nonexistent"}' \
    "$BR_URL/v1/chat/completions")
ETYPE=$(echo "$ERR1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('type','unknown'))")
echo "   Invalid model: $ETYPE"

echo ""
echo "=== Complete ==="
echo "Finished: $(date)"
