#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Upload SOUL.md files to BrainstormRouter Workspace
#
# Pushes each agent's SOUL.md to BR's virtual filesystem via br_workspace_put.
# BR will automatically inject the SOUL on every completion for that agent.
#
# Usage: ./scripts/upload-souls.sh [agent_id]
#   No args: uploads all 5 agents
#   With arg: uploads only the specified agent (e.g., ./scripts/upload-souls.sh main)
#
# Requires: BRAINSTORMROUTER_ADMIN_KEY (from 1Password or env)
###############################################################################

BR_BASE_URL="${BR_BASE_URL:-https://api.brainstormrouter.com/v1}"
WORKSPACE_DIR="./workspace/workspaces"
AGENTS=("main" "ops" "research" "dev" "admin")

# Load admin key from 1Password if not already set
if [ -z "${BRAINSTORMROUTER_ADMIN_KEY:-}" ]; then
  echo "Loading BrainstormRouter admin key from 1Password..."
  BRAINSTORMROUTER_ADMIN_KEY=$(op read "op://Dev Keys/BrainstormRouter Admin Key/credential")
fi

upload_soul() {
  local agent_id="$1"
  local soul_file="${WORKSPACE_DIR}/${agent_id}/SOUL.md"

  if [ ! -f "$soul_file" ]; then
    echo "  SKIP ${agent_id}: no SOUL.md found at ${soul_file}"
    return 0
  fi

  local content
  content=$(cat "$soul_file")
  local size
  size=$(wc -c < "$soul_file" | tr -d ' ')

  echo -n "  Uploading ${agent_id}/SOUL.md (${size} bytes)... "

  # Escape content for JSON
  local json_content
  json_content=$(jq -Rs '.' < "$soul_file")

  HTTP_CODE=$(curl -s -o /tmp/br-workspace-response.json -w "%{http_code}" \
    --max-time 30 \
    -X PUT \
    -H "Authorization: Bearer ${BRAINSTORMROUTER_ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    "${BR_BASE_URL}/workspace/${agent_id}/SOUL.md" \
    -d "{\"content\": ${json_content}}")

  if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    echo "OK (${HTTP_CODE})"
  else
    echo "FAILED (${HTTP_CODE})"
    cat /tmp/br-workspace-response.json 2>/dev/null
    echo
    return 1
  fi
}

# Also upload shared files: root SOUL.md and IDENTITY.md where present
upload_workspace_file() {
  local agent_id="$1"
  local filename="$2"
  local filepath="${WORKSPACE_DIR}/${agent_id}/${filename}"

  if [ ! -f "$filepath" ]; then
    return 0
  fi

  local size
  size=$(wc -c < "$filepath" | tr -d ' ')

  echo -n "  Uploading ${agent_id}/${filename} (${size} bytes)... "

  local json_content
  json_content=$(jq -Rs '.' < "$filepath")

  HTTP_CODE=$(curl -s -o /tmp/br-workspace-response.json -w "%{http_code}" \
    --max-time 30 \
    -X PUT \
    -H "Authorization: Bearer ${BRAINSTORMROUTER_ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    "${BR_BASE_URL}/workspace/${agent_id}/${filename}" \
    -d "{\"content\": ${json_content}}")

  if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    echo "OK (${HTTP_CODE})"
  else
    echo "FAILED (${HTTP_CODE})"
    cat /tmp/br-workspace-response.json 2>/dev/null
    echo
    return 1
  fi
}

echo "=== Upload SOULs to BrainstormRouter ==="
echo "BR endpoint: ${BR_BASE_URL}"
echo

success=0
failed=0

# Filter to single agent if arg provided
if [ $# -ge 1 ]; then
  AGENTS=("$1")
fi

for agent_id in "${AGENTS[@]}"; do
  echo "[${agent_id}]"
  if upload_soul "$agent_id"; then
    ((success++))
  else
    ((failed++))
  fi
  # Also upload IDENTITY.md and HEARTBEAT.md if they have content
  upload_workspace_file "$agent_id" "IDENTITY.md"
  upload_workspace_file "$agent_id" "HEARTBEAT.md"
  echo
done

echo "=== Done: ${success} uploaded, ${failed} failed ==="

if [ "$failed" -gt 0 ]; then
  exit 1
fi
