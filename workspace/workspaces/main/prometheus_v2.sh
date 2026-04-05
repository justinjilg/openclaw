#!/bin/bash
# Project Prometheus - Phase 1.1 v2: Robust Multi-Model Pipeline

set -e

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
BR_URL="https://api.brainstormrouter.com"
PROJECT_DIR="./prometheus-saas-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$PROJECT_DIR"/{frontend,backend,infrastructure,tests,docs}

echo "=== PROJECT PROMETHEUS v2 ==="
echo "Project: $PROJECT_DIR"
echo ""

# Stats
TOTAL_REQUESTS=0
SUCCESS_COUNT=0
ERROR_COUNT=0
TOTAL_COST=0

declare -A MODEL_USAGE

# Robust generation function
generate_robust() {
    local model=$1
    local prompt=$2
    local max_tokens=$3
    local output_file=$4
    local component=$5
    
    echo "Generating: $component (model: $model)"
    
    local temp_file=$(mktemp)
    local http_code
    
    # Make request with timeout
    http_code=$(curl -s -w "%{http_code}" --max-time 30 \
        -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"model\": \"$model\", \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}], \"max_tokens\": $max_tokens, \"stream\": false}" \
        -o "$temp_file" \
        "$BR_URL/v1/chat/completions")
    
    TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))
    
    if [ "$http_code" != "200" ]; then
        echo "  ✗ HTTP $http_code"
        cat "$temp_file" | head -c 200
        echo ""
        ERROR_COUNT=$((ERROR_COUNT + 1))
        rm -f "$temp_file"
        return 1
    fi
    
    # Extract using grep/sed to avoid JSON parsing issues
    local model_used=$(grep -o '"model":"[^"]*"' "$temp_file" | head -1 | sed 's/"model":"//;s/"$//')
    local cost=$(grep -o '"cost_usd":[0-9.]*' "$temp_file" | head -1 | sed 's/"cost_usd"://')
    
    # Extract content - find the content field and clean it
    local content=$(sed -n 's/.*"content":"\([^"]*\)".*/\1/p' "$temp_file" | head -1)
    
    # If extraction failed, try Python with error handling
    if [ -z "$content" ]; then
        content=$(python3 -c "
import sys, json
try:
    with open('$temp_file') as f:
        d = json.load(f)
        print(d.get('choices',[{}])[0].get('message',{}).get('content',''))
except:
    print('')
" 2>/dev/null)
    fi
    
    # Save content
    echo "$content" > "$output_file"
    
    # Track stats
    MODEL_USAGE["$model_used"]=$((${MODEL_USAGE["$model_used"]:-0} + 1))
    TOTAL_COST=$(echo "$TOTAL_COST + ${cost:-0}" | bc -l 2>/dev/null || echo "$TOTAL_COST")
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    
    echo "  ✓ $model_used (cost: \$${cost:-0})"
    
    rm -f "$temp_file"
    sleep 0.2
}

# Phase 1.1: Generate components
echo "=== PHASE 1.1: Multi-Model Code Generation ==="
echo ""

# Frontend (auto:best)
echo "--- Frontend (auto:best) ---"
generate_robust "auto:best" "Create a React TypeScript dashboard component with navigation, user menu, and dark mode toggle. Include TypeScript interfaces." 2000 "$PROJECT_DIR/frontend/Dashboard.tsx" "Dashboard"
generate_robust "auto:best" "Create reusable React Button, Card, and Modal components with TypeScript props." 1500 "$PROJECT_DIR/frontend/components.tsx" "UI Components"

# Backend (auto:fast)
echo ""
echo "--- Backend (auto:fast) ---"
generate_robust "auto:fast" "Create FastAPI main.py with user authentication, JWT tokens, and health check endpoint." 2000 "$PROJECT_DIR/backend/main.py" "API Main"
generate_robust "auto:fast" "Create SQLAlchemy models for User, Project, and Task with relationships." 1500 "$PROJECT_DIR/backend/models.py" "DB Models"

# Database (auto:floor)
echo ""
echo "--- Database (auto:floor) ---"
generate_robust "auto:floor" "Write PostgreSQL schema with users, projects, tasks tables, indexes, and foreign keys." 1000 "$PROJECT_DIR/backend/schema.sql" "Schema"

# Infrastructure (explicit)
echo ""
echo "--- Infrastructure (explicit models) ---"
generate_robust "anthropic/claude-sonnet-4" "Create Terraform main.tf for AWS ECS Fargate, ALB, and RDS PostgreSQL." 2000 "$PROJECT_DIR/infrastructure/main.tf" "Terraform"
generate_robust "openai/gpt-4o" "Create Docker Compose for local dev with frontend, backend, postgres." 1000 "$PROJECT_DIR/infrastructure/docker-compose.yml" "Docker Compose"

# Tests (explicit)
echo ""
echo "--- Tests (explicit models) ---"
generate_robust "openai/gpt-4o" "Create pytest tests for FastAPI endpoints with fixtures and mocks." 1500 "$PROJECT_DIR/tests/test_api.py" "API Tests"
generate_robust "deepseek-chat" "Create Jest tests for React components." 1500 "$PROJECT_DIR/tests/components.test.tsx" "Component Tests"

# Documentation
echo ""
echo "--- Documentation ---"
generate_robust "deepseek-chat" "Write comprehensive README with setup, architecture, and deployment instructions." 2000 "$PROJECT_DIR/docs/README.md" "README"

# Summary
echo ""
echo "=== PHASE 1.1 COMPLETE ==="
echo "Total requests: $TOTAL_REQUESTS"
echo "Successful: $SUCCESS_COUNT"
echo "Errors: $ERROR_COUNT"
echo "Total cost: \$$TOTAL_COST"
echo ""
echo "Model distribution:"
for model in "${!MODEL_USAGE[@]}"; do
    echo "  $model: ${MODEL_USAGE[$model]}"
done
echo ""
echo "Files generated:"
find "$PROJECT_DIR" -type f -exec ls -lh {} \; | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo "Project location: $PROJECT_DIR"
