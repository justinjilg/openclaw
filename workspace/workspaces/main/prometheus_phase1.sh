#!/bin/bash
# Project Prometheus - Phase 1.1: Multi-Model Code Pipeline
# Generating complete SaaS application across multiple models

set -e

BR_API_KEY="${BRAINSTORMROUTER_API_KEY}"
BR_URL="https://api.brainstormrouter.com"
PROJECT_DIR="./prometheus-saas-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$PROJECT_DIR"/{frontend,backend,infrastructure,tests,docs}

echo "=== PROJECT PROMETHEUS ==="
echo "Generating complete SaaS application"
echo "Project: $PROJECT_DIR"
echo ""

# Track costs and models used
declare -A MODEL_USAGE
declare -A COST_BY_COMPONENT

# Helper: Generate code with specific model
generate_code() {
    local model=$1
    local prompt=$2
    local max_tokens=$3
    local output_file=$4
    local component=$5
    
    echo "Generating $component with $model..."
    
    RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer $BR_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"model\": \"$model\", \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}], \"max_tokens\": $max_tokens, \"stream\": false}" \
        "$BR_URL/v1/chat/completions")
    
    MODEL_USED=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model','ERR'))")
    COST=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('usage',{}).get('cost_usd',0))")
    CONTENT=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('choices',[{}])[0].get('message',{}).get('content',''))")
    
    # Track usage
    MODEL_USAGE["$MODEL_USED"]=$((${MODEL_USAGE["$MODEL_USED"]:-0} + 1))
    COST_BY_COMPONENT["$component"]=$(echo "${COST_BY_COMPONENT["$component"]:-0} + $COST" | bc -l 2>/dev/null || echo "0")
    
    # Save to file
    echo "$CONTENT" > "$output_file"
    echo "  ✓ $component -> $MODEL_USED (\$$COST)"
}

# 1. React Frontend (auto:best - highest quality)
echo "=== FRONTEND (auto:best) ==="
generate_code "auto:best" \
    "Create a complete React TypeScript SaaS dashboard with: navigation, user profile, data tables, charts, and dark mode. Include all imports, types, and styling." \
    4000 \
    "$PROJECT_DIR/frontend/Dashboard.tsx" \
    "Dashboard"

generate_code "auto:best" \
    "Create React components: Button, Card, Modal, Form, Table with TypeScript props and Tailwind styling." \
    3000 \
    "$PROJECT_DIR/frontend/components.tsx" \
    "Components"

# 2. FastAPI Backend (auto:fast - speed priority)
echo ""
echo "=== BACKEND (auto:fast) ==="
generate_code "auto:fast" \
    "Create a FastAPI Python backend with: user auth, CRUD endpoints, database models using SQLAlchemy, and Pydantic schemas. Include error handling and logging." \
    3500 \
    "$PROJECT_DIR/backend/main.py" \
    "API Server"

generate_code "auto:fast" \
    "Create database models for: User, Project, Task with relationships, indexes, and timestamps. SQLAlchemy declarative base." \
    2000 \
    "$PROJECT_DIR/backend/models.py" \
    "DB Models"

# 3. Database Schema (auto:floor - cheapest)
echo ""
echo "=== DATABASE (auto:floor) ==="
generate_code "auto:floor" \
    "Write PostgreSQL schema: users, projects, tasks tables with indexes, foreign keys, and constraints. Include seed data." \
    1500 \
    "$PROJECT_DIR/backend/schema.sql" \
    "Schema"

# 4. Infrastructure (explicit Claude - complex reasoning)
echo ""
echo "=== INFRASTRUCTURE (claude-sonnet-4) ==="
generate_code "anthropic/claude-sonnet-4" \
    "Create Terraform configuration for: AWS ECS Fargate, RDS PostgreSQL, ALB, Route53, CloudWatch. Include variables and outputs." \
    3000 \
    "$PROJECT_DIR/infrastructure/main.tf" \
    "Terraform"

generate_code "anthropic/claude-sonnet-4" \
    "Create Docker Compose for local development: frontend, backend, postgres, redis. Include healthchecks and volumes." \
    1500 \
    "$PROJECT_DIR/infrastructure/docker-compose.yml" \
    "Docker Compose"

# 5. Test Suite (explicit GPT-4o)
echo ""
echo "=== TESTS (gpt-4o) ==="
generate_code "openai/gpt-4o" \
    "Create pytest test suite for FastAPI backend: unit tests, integration tests, fixtures, mocks. Test auth, CRUD, validation." \
    2500 \
    "$PROJECT_DIR/tests/test_backend.py" \
    "Backend Tests"

generate_code "openai/gpt-4o" \
    "Create Jest tests for React frontend: component tests, hook tests, snapshot tests. Use React Testing Library." \
    2000 \
    "$PROJECT_DIR/tests/frontend.test.tsx" \
    "Frontend Tests"

# 6. Documentation (explicit DeepSeek)
echo ""
echo "=== DOCS (deepseek-chat) ==="
generate_code "deepseek-chat" \
    "Write comprehensive README: project overview, architecture, setup instructions, API documentation, deployment guide." \
    2500 \
    "$PROJECT_DIR/docs/README.md" \
    "README"

generate_code "deepseek-chat" \
    "Write OpenAPI 3.0 spec for the FastAPI backend. Include all endpoints, request/response schemas, authentication." \
    2000 \
    "$PROJECT_DIR/docs/openapi.yaml" \
    "OpenAPI Spec"

# Summary
echo ""
echo "=== PHASE 1.1 COMPLETE ==="
echo "Files generated:"
find "$PROJECT_DIR" -type f | wc -l | xargs echo "  Total files:"
echo ""
echo "Model usage distribution:"
for model in "${!MODEL_USAGE[@]}"; do
    echo "  $model: ${MODEL_USAGE[$model]} files"
done
echo ""
echo "Estimated cost by component:"
for comp in "${!COST_BY_COMPONENT[@]}"; do
    echo "  $comp: \$${COST_BY_COMPONENT[$comp]}"
done
echo ""
echo "Project saved to: $PROJECT_DIR"
