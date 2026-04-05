#!/bin/bash
# Project Prometheus - Phase 2: Cache Warfare
# Testing semantic cache under load

set -e

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
BR_URL="https://api.brainstormrouter.com"
RESULTS_FILE="./cache_warfare_$(date +%Y%m%d_%H%M%S).log"

echo "=== PHASE 2: CACHE WARFARE ===" | tee -a "$RESULTS_FILE"
echo "Started: $(date)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Stats
NEAR_IDENTICAL_HITS=0
NEAR_IDENTICAL_TOTAL=0
VARIATION_HITS=0
VARIATION_TOTAL=0
DIFFERENT_HITS=0
DIFFERENT_TOTAL=0

TOTAL_COST=0

# Helper: Test cache with prompt
test_cache() {
    local prompt=$1
    local category=$2
    local temp_file=$(mktemp)
    
    # Make request
    curl -s --max-time 30 \
        -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"model\": \"auto\", \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}], \"max_tokens\": 50, \"stream\": false}" \
        -o "$temp_file" \
        "$BR_URL/v1/chat/completions" 2>/dev/null
    
    # Extract cache status
    local cache_status=$(grep -o '"cache":"[^"]*"' "$temp_file" 2>/dev/null | head -1 | sed 's/"cache":"//;s/"$//')
    local cache_sim=$(grep -o '"cache_similarity":[0-9.]*' "$temp_file" 2>/dev/null | head -1 | sed 's/"cache_similarity"://')
    local cost=$(grep -o '"cost_usd":[0-9.]*' "$temp_file" 2>/dev/null | head -1 | sed 's/"cost_usd"://')
    
    if [ "$cache_status" = "hit" ]; then
        echo "HIT"
        if [ -n "$cache_sim" ]; then
            echo "Similarity: $cache_sim"
        fi
    else
        echo "MISS"
    fi
    
    if [ -n "$cost" ]; then
        TOTAL_COST=$(echo "$TOTAL_COST + $cost" | bc -l 2>/dev/null || echo "$TOTAL_COST")
    fi
    
    rm -f "$temp_file"
}

# 2.1: Near-identical prompts (expect 80%+ hit rate)
echo "--- TEST 2.1: Near-Identical Prompts (100 requests) ---" | tee -a "$RESULTS_FILE"
echo "Base: 'Write a Python function to sort a list'" | tee -a "$RESULTS_FILE"

NEAR_IDENTICAL_PROMPTS=(
    "Write a Python function to sort a list"
    "Write a Python function to sort a list"
    "How do I sort a list in Python?"
    "Python function for sorting a list"
    "Sort a list using Python"
    "Write Python code to sort a list"
    "Function to sort list in Python"
    "Python list sorting function"
    "How to sort a list with Python?"
    "Write a sort function for lists in Python"
)

for i in {1..10}; do
    for prompt in "${NEAR_IDENTICAL_PROMPTS[@]}"; do
        NEAR_IDENTICAL_TOTAL=$((NEAR_IDENTICAL_TOTAL + 1))
        result=$(test_cache "$prompt" "near_identical")
        if [ "$result" = "HIT" ]; then
            NEAR_IDENTICAL_HITS=$((NEAR_IDENTICAL_HITS + 1))
        fi
        echo -n "."
    done
    echo " ($NEAR_IDENTICAL_TOTAL requests)"
done

echo "" | tee -a "$RESULTS_FILE"
echo "Near-identical results: $NEAR_IDENTICAL_HITS / $NEAR_IDENTICAL_TOTAL hits" | tee -a "$RESULTS_FILE"
if [ $NEAR_IDENTICAL_TOTAL -gt 0 ]; then
    pct=$(echo "scale=1; $NEAR_IDENTICAL_HITS * 100 / $NEAR_IDENTICAL_TOTAL" | bc 2>/dev/null || echo "0")
    echo "Hit rate: ${pct}%" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# 2.2: True variations (expect 30-40% hit rate)
echo "--- TEST 2.2: True Variations (50 requests) ---" | tee -a "$RESULTS_FILE"

VARIATION_PROMPTS=(
    "Sort a list in Python"
    "Order elements in a list"
    "Arrange list items alphabetically"
    "Python list ordering"
    "How to arrange a list"
    "Sort array in Python"
    "Organize list elements"
    "Python sorting algorithm"
    "List arrangement in Python"
    "Order a Python list"
)

for i in {1..5}; do
    for prompt in "${VARIATION_PROMPTS[@]}"; do
        VARIATION_TOTAL=$((VARIATION_TOTAL + 1))
        result=$(test_cache "$prompt" "variation")
        if [ "$result" = "HIT" ]; then
            VARIATION_HITS=$((VARIATION_HITS + 1))
        fi
        echo -n "."
    done
    echo " ($VARIATION_TOTAL requests)"
done

echo "" | tee -a "$RESULTS_FILE"
echo "Variation results: $VARIATION_HITS / $VARIATION_TOTAL hits" | tee -a "$RESULTS_FILE"
if [ $VARIATION_TOTAL -gt 0 ]; then
    pct=$(echo "scale=1; $VARIATION_HITS * 100 / $VARIATION_TOTAL" | bc 2>/dev/null || echo "0")
    echo "Hit rate: ${pct}%" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# 2.3: Different intent (expect ~0% hit rate)
echo "--- TEST 2.3: Different Intent (30 requests) ---" | tee -a "$RESULTS_FILE"

DIFFERENT_PROMPTS=(
    "Filter a list in Python"
    "Map over a list in Python"
    "Reduce a list in Python"
    "Join two lists in Python"
    "Reverse a list in Python"
    "Find max in a list"
    "Count elements in a list"
    "Check if item exists in list"
    "Remove duplicates from list"
    "Flatten a nested list"
)

for i in {1..3}; do
    for prompt in "${DIFFERENT_PROMPTS[@]}"; do
        DIFFERENT_TOTAL=$((DIFFERENT_TOTAL + 1))
        result=$(test_cache "$prompt" "different")
        if [ "$result" = "HIT" ]; then
            DIFFERENT_HITS=$((DIFFERENT_HITS + 1))
        fi
        echo -n "."
    done
    echo " ($DIFFERENT_TOTAL requests)"
done

echo "" | tee -a "$RESULTS_FILE"
echo "Different intent results: $DIFFERENT_HITS / $DIFFERENT_TOTAL hits" | tee -a "$RESULTS_FILE"
if [ $DIFFERENT_TOTAL -gt 0 ]; then
    pct=$(echo "scale=1; $DIFFERENT_HITS * 100 / $DIFFERENT_TOTAL" | bc 2>/dev/null || echo "0")
    echo "Hit rate: ${pct}%" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Summary
echo "=== PHASE 2 SUMMARY ===" | tee -a "$RESULTS_FILE"
echo "Total requests: $((NEAR_IDENTICAL_TOTAL + VARIATION_TOTAL + DIFFERENT_TOTAL))" | tee -a "$RESULTS_FILE"
echo "Total cost: \$$TOTAL_COST" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
echo "Cache Performance:" | tee -a "$RESULTS_FILE"
echo "  Near-identical: $NEAR_IDENTICAL_HITS/$NEAR_IDENTICAL_TOTAL ($(echo "scale=1; $NEAR_IDENTICAL_HITS * 100 / $NEAR_IDENTICAL_TOTAL" | bc 2>/dev/null || echo "0")%)" | tee -a "$RESULTS_FILE"
echo "  Variations: $VARIATION_HITS/$VARIATION_TOTAL ($(echo "scale=1; $VARIATION_HITS * 100 / $VARIATION_TOTAL" | bc 2>/dev/null || echo "0")%)" | tee -a "$RESULTS_FILE"
echo "  Different: $DIFFERENT_HITS/$DIFFERENT_TOTAL ($(echo "scale=1; $DIFFERENT_HITS * 100 / $DIFFERENT_TOTAL" | bc 2>/dev/null || echo "0")%)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
echo "Results saved to: $RESULTS_FILE"
