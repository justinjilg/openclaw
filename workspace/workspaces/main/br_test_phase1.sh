#!/usr/bin/env bash
# BR Stress Test Suite - Phase 1: Discovery & Baseline
# Jazz (OpenClaw) - BrainstormRouter M2M Testing
# No jq dependency - uses grep/sed/awk

set -euo pipefail

# Configuration
BR_BASE_URL="https://api.brainstormrouter.com"
BR_API_KEY="${BRAINSTORMROUTER_API_KEY:-}"
BR_ADMIN_KEY="${BRAINSTORMROUTER_ADMIN_KEY:-}"
TEST_RESULTS_DIR="./test-results/$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_detail() { echo -e "${BLUE}[DETAIL]${NC} $1"; }

# Initialize test environment
init() {
    mkdir -p "$TEST_RESULTS_DIR"
    log_info "Test results will be saved to: $TEST_RESULTS_DIR"
    
    if [[ -z "$BR_API_KEY" ]]; then
        log_error "BRAINSTORMROUTER_API_KEY not set"
        exit 1
    fi
    
    log_info "API key detected (length: ${#BR_API_KEY})"
    
    # Create summary file
    echo "BrainstormRouter Discovery Test Report" > "$TEST_RESULTS_DIR/report.txt"
    echo "Generated: $(date)" >> "$TEST_RESULTS_DIR/report.txt"
    echo "API Key: ${BR_API_KEY:0:10}..." >> "$TEST_RESULTS_DIR/report.txt"
    echo "========================================" >> "$TEST_RESULTS_DIR/report.txt"
    echo "" >> "$TEST_RESULTS_DIR/report.txt"
}

# Extract JSON value without jq
json_val() {
    local json="$1"
    local key="$2"
    echo "$json" | grep -o "\"$key\":[^,}]*" | head -1 | sed 's/.*://' | tr -d '"'
}

# Test 1.1: Basic connectivity and self-discovery
test_connectivity() {
    log_info "=== Test 1.1: Basic Connectivity (/v1/self) ==="
    echo "" >> "$TEST_RESULTS_DIR/report.txt"
    echo "TEST 1.1: Basic Connectivity" >> "$TEST_RESULTS_DIR/report.txt"
    
    local response_file="$TEST_RESULTS_DIR/self_response.json"
    local http_code
    
    http_code=$(curl -s -o "$response_file" -w "%{http_code}" \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        "$BR_BASE_URL/v1/self" 2>/dev/null)
    
    if [[ "$http_code" == "200" ]]; then
        log_info "✓ /v1/self endpoint accessible"
        echo "STATUS: PASS (HTTP 200)" >> "$TEST_RESULTS_DIR/report.txt"
        
        # Extract key info
        local body=$(cat "$response_file")
        local agent_id=$(json_val "$body" "agent_id")
        local budget=$(json_val "$body" "remaining")
        
        log_detail "  Agent ID: ${agent_id:-unknown}"
        log_detail "  Budget remaining: ${budget:-unknown}"
        
        echo "Agent ID: ${agent_id:-unknown}" >> "$TEST_RESULTS_DIR/report.txt"
        echo "Budget: ${budget:-unknown}" >> "$TEST_RESULTS_DIR/report.txt"
        
        # Count top-level keys
        local key_count=$(echo "$body" | grep -o '"[a-z_]*":' | wc -l)
        log_detail "  Response has ~$key_count top-level fields"
        echo "Response fields: ~$key_count" >> "$TEST_RESULTS_DIR/report.txt"
    else
        log_error "✗ /v1/self failed with HTTP $http_code"
        echo "STATUS: FAIL (HTTP $http_code)" >> "$TEST_RESULTS_DIR/report.txt"
        cat "$response_file" >> "$TEST_RESULTS_DIR/report.txt"
        return 1
    fi
}

# Test 1.2: Model registry enumeration
test_model_registry() {
    log_info "=== Test 1.2: Model Registry ==="
    echo "" >> "$TEST_RESULTS_DIR/report.txt"
    echo "TEST 1.2: Model Registry" >> "$TEST_RESULTS_DIR/report.txt"
    
    # Get all models
    local models_file="$TEST_RESULTS_DIR/models_all.json"
    local http_code
    
    http_code=$(curl -s -o "$models_file" -w "%{http_code}" \
        -H "Authorization: Bearer $BR_API_KEY" \
        "$BR_BASE_URL/v1/models" 2>/dev/null)
    
    if [[ "$http_code" == "200" ]]; then
        local body=$(cat "$models_file")
        # Count models by looking for "id" fields
        local model_count=$(echo "$body" | grep -o '"id":' | wc -l)
        log_info "✓ Retrieved $model_count models"
        echo "STATUS: PASS - $model_count models total" >> "$TEST_RESULTS_DIR/report.txt"
        
        # Extract first few model names
        local models=$(echo "$body" | grep -o '"id":"[^"]*"' | head -5 | sed 's/"id":"//;s/"$//')
        log_detail "  First 5 models:"
        echo "$models" | while read -r model; do
            log_detail "    - $model"
        done
        
        # Get runnable models
        local runnable_file="$TEST_RESULTS_DIR/models_runnable.json"
        local runnable_code
        
        runnable_code=$(curl -s -o "$runnable_file" -w "%{http_code}" \
            -H "Authorization: Bearer $BR_API_KEY" \
            "$BR_BASE_URL/v1/catalog/runnable" 2>/dev/null)
        
        if [[ "$runnable_code" == "200" ]]; then
            local runnable_body=$(cat "$runnable_file")
            local runnable_count=$(echo "$runnable_body" | grep -o '"id":' | wc -l)
            log_info "✓ $runnable_count models currently runnable"
            echo "Runnable models: $runnable_count" >> "$TEST_RESULTS_DIR/report.txt"
            
            local drift=$((model_count - runnable_count))
            if [[ $drift -gt 0 ]]; then
                log_warn "  Model drift: $drift models unavailable"
                echo "Model drift: $drift unavailable" >> "$TEST_RESULTS_DIR/report.txt"
            fi
        fi
        
        # Get leaderboard
        local lb_file="$TEST_RESULTS_DIR/models_leaderboard.json"
        local lb_code
        
        lb_code=$(curl -s -o "$lb_file" -w "%{http_code}" \
            -H "Authorization: Bearer $BR_API_KEY" \
            "$BR_BASE_URL/v1/models/leaderboard" 2>/dev/null)
        
        if [[ "$lb_code" == "200" ]]; then
            log_info "✓ Retrieved model leaderboard"
            echo "Leaderboard: accessible" >> "$TEST_RESULTS_DIR/report.txt"
        else
            log_warn "  Leaderboard returned HTTP $lb_code"
            echo "Leaderboard: HTTP $lb_code" >> "$TEST_RESULTS_DIR/report.txt"
        fi
    else
        log_error "✗ /v1/models failed with HTTP $http_code"
        echo "STATUS: FAIL (HTTP $http_code)" >> "$TEST_RESULTS_DIR/report.txt"
        return 1
    fi
}

# Test 1.3: Simple completion with header capture
test_basic_completion() {
    log_info "=== Test 1.3: Basic Completion ==="
    echo "" >> "$TEST_RESULTS_DIR/report.txt"
    echo "TEST 1.3: Basic Completion" >> "$TEST_RESULTS_DIR/report.txt"
    
    local response_file="$TEST_RESULTS_DIR/completion_test.json"
    local headers_file="$TEST_RESULTS_DIR/completion_headers.txt"
    
    curl -s -D "$headers_file" \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "model": "auto",
            "messages": [{"role": "user", "content": "Say hello in exactly 3 words"}],
            "max_tokens": 20
        }' \
        "$BR_BASE_URL/v1/chat/completions" > "$response_file"
    
    if [[ -s "$response_file" ]]; then
        log_info "✓ Completion request successful"
        echo "STATUS: PASS" >> "$TEST_RESULTS_DIR/report.txt"
        
        # Check for X-BR headers
        log_info "  Response headers detected:"
        echo "Headers:" >> "$TEST_RESULTS_DIR/report.txt"
        grep -i "^x-br-" "$headers_file" 2>/dev/null | while read -r line; do
            log_detail "    $line"
            echo "  $line" >> "$TEST_RESULTS_DIR/report.txt"
        done || log_warn "    No X-BR headers found"
        
        # Extract model used
        local body=$(cat "$response_file")
        local model=$(json_val "$body" "model")
        log_info "  Model selected: ${model:-unknown}"
        echo "Model: ${model:-unknown}" >> "$TEST_RESULTS_DIR/report.txt"
        
        # Check for content
        if echo "$body" | grep -q '"content"'; then
            local content=$(echo "$body" | grep -o '"content":"[^"]*"' | head -1 | sed 's/"content":"//;s/"$//')
            log_detail "  Response content: ${content:-(empty)}"
            echo "Content: ${content:-(empty)}" >> "$TEST_RESULTS_DIR/report.txt"
        fi
        
        # Check for usage
        if echo "$body" | grep -q '"usage"'; then
            log_detail "  Usage data present"
            echo "Usage: present" >> "$TEST_RESULTS_DIR/report.txt"
        fi
    else
        log_error "✗ Completion request failed (empty response)"
        echo "STATUS: FAIL (empty response)" >> "$TEST_RESULTS_DIR/report.txt"
        return 1
    fi
}

# Test 1.4: Budget check
test_budget() {
    log_info "=== Test 1.4: Budget Status ==="
    echo "" >> "$TEST_RESULTS_DIR/report.txt"
    echo "TEST 1.4: Budget Status" >> "$TEST_RESULTS_DIR/report.txt"
    
    local response_file="$TEST_RESULTS_DIR/budget_status.json"
    local http_code
    
    http_code=$(curl -s -o "$response_file" -w "%{http_code}" \
        -H "Authorization: Bearer $BR_API_KEY" \
        "$BR_BASE_URL/v1/budget/status" 2>/dev/null)
    
    if [[ "$http_code" == "200" ]]; then
        log_info "✓ Budget endpoint accessible"
        echo "STATUS: PASS" >> "$TEST_RESULTS_DIR/report.txt"
        
        local body=$(cat "$response_file")
        local remaining=$(json_val "$body" "remaining")
        local total=$(json_val "$body" "total")
        
        log_detail "  Budget: ${remaining:-unknown} / ${total:-unknown}"
        echo "Budget: ${remaining:-unknown} / ${total:-unknown}" >> "$TEST_RESULTS_DIR/report.txt"
    else
        log_warn "  Budget endpoint returned HTTP $http_code (may not be available)"
        echo "STATUS: SKIP (HTTP $http_code)" >> "$TEST_RESULTS_DIR/report.txt"
    fi
}

# Test 1.5: MCP tools discovery
test_mcp_tools() {
    log_info "=== Test 1.5: MCP Tools Discovery ==="
    echo "" >> "$TEST_RESULTS_DIR/report.txt"
    echo "TEST 1.5: MCP Tools Discovery" >> "$TEST_RESULTS_DIR/report.txt"
    
    local endpoints=(
        "/v1/tools"
        "/v1/mcp/tools"
        "/v1/agent/tools"
        "/v1/capabilities"
    )
    
    local found=false
    for endpoint in "${endpoints[@]}"; do
        local response_file="$TEST_RESULTS_DIR/tools_${endpoint//\//_}.json"
        local http_code
        
        http_code=$(curl -s -o "$response_file" -w "%{http_code}" \
            -H "Authorization: Bearer $BR_API_KEY" \
            "$BR_BASE_URL$endpoint" 2>/dev/null)
        
        if [[ "$http_code" == "200" ]]; then
            log_info "✓ Tools endpoint found: $endpoint"
            echo "STATUS: PASS - Endpoint: $endpoint" >> "$TEST_RESULTS_DIR/report.txt"
            
            local body=$(cat "$response_file")
            # Try to count tools
            local tool_count=$(echo "$body" | grep -o '"name":\|"tool":\|"id":' | wc -l)
            log_detail "  ~$tool_count tools/capabilities found"
            echo "Tools found: ~$tool_count" >> "$TEST_RESULTS_DIR/report.txt"
            found=true
            break
        fi
    done
    
    if [[ "$found" == "false" ]]; then
        log_warn "  No tools endpoint found (tried: ${endpoints[*]})"
        echo "STATUS: NOT FOUND" >> "$TEST_RESULTS_DIR/report.txt"
    fi
}

# Test 1.6: Test error handling
test_error_handling() {
    log_info "=== Test 1.6: Error Handling ==="
    echo "" >> "$TEST_RESULTS_DIR/report.txt"
    echo "TEST 1.6: Error Handling" >> "$TEST_RESULTS_DIR/report.txt"
    
    # Test with invalid model
    local response_file="$TEST_RESULTS_DIR/error_invalid_model.json"
    local headers_file="$TEST_RESULTS_DIR/error_invalid_model_headers.txt"
    
    curl -s -D "$headers_file" \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "model": "nonexistent-model-12345",
            "messages": [{"role": "user", "content": "test"}]
        }' \
        "$BR_BASE_URL/v1/chat/completions" > "$response_file"
    
    local body=$(cat "$response_file")
    
    if echo "$body" | grep -qi "error"; then
        log_info "✓ Error response received for invalid model"
        echo "STATUS: PASS - Error handling works" >> "$TEST_RESULTS_DIR/report.txt"
        
        # Check for recovery hints
        if echo "$body" | grep -qi "recovery\|hint\|suggestion"; then
            log_detail "  Recovery hints present"
            echo "Recovery hints: present" >> "$TEST_RESULTS_DIR/report.txt"
        else
            log_detail "  No recovery hints in error"
            echo "Recovery hints: absent" >> "$TEST_RESULTS_DIR/report.txt"
        fi
    else
        log_warn "  Unexpected response for invalid model"
        echo "STATUS: UNEXPECTED" >> "$TEST_RESULTS_DIR/report.txt"
    fi
}

# Main execution
main() {
    log_info "Starting BrainstormRouter Discovery & Baseline Tests"
    log_info "======================================================"
    
    init
    test_connectivity
    test_model_registry
    test_basic_completion
    test_budget
    test_mcp_tools
    test_error_handling
    
    log_info "======================================================"
    log_info "Phase 1 complete. Results saved to: $TEST_RESULTS_DIR"
    
    # Display summary
    echo ""
    echo "========================================"
    cat "$TEST_RESULTS_DIR/report.txt"
    echo "========================================"
    echo ""
    echo "All result files:"
    ls -la "$TEST_RESULTS_DIR/"
}

main "$@"
