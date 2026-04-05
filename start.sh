#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# OpenClaw — Secure Startup Script
#
# Injects secrets from 1Password at runtime into a temporary .env file
# that Docker Compose reads. The .env is chmod 600 and gitignored.
# Usage: ./start.sh [up|down|doctor|logs|cli <args>]
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
PROJECTS_DIR="${PROJECTS_DIR:-$HOME/Projects}"

# --- Generate gateway token if not already stored in 1Password ---
ensure_gateway_token() {
  if op read "op://Dev Keys/OpenClaw Gateway/credential" &>/dev/null; then
    OPENCLAW_GATEWAY_TOKEN=$(op read "op://Dev Keys/OpenClaw Gateway/credential")
  else
    echo "No gateway token found in 1Password."
    echo "Generating a new one and storing it..."
    OPENCLAW_GATEWAY_TOKEN=$(openssl rand -hex 32)
    op item create \
      --vault "Dev Keys" \
      --category "API Credential" \
      --title "OpenClaw Gateway" \
      "credential=$OPENCLAW_GATEWAY_TOKEN" >/dev/null
    echo "Gateway token stored in 1Password (Dev Keys / OpenClaw Gateway)."
  fi
}

# --- Write .env for Docker Compose ---
write_env() {
  echo "Injecting secrets from 1Password..."
  ensure_gateway_token
  MOONSHOT_API_KEY=$(op read "op://Dev Keys/Moonshot API Key/credential")
  BRAINSTORMROUTER_API_KEY=$(op read "op://Dev Keys/BrainstormRouter API Key/credential")
  BRAINSTORMROUTER_ADMIN_KEY=$(op read "op://Dev Keys/BrainstormRouter Admin Key/credential")
  DISCORD_BOT_TOKEN=$(op read "op://Dev Keys/Discord Bot Token/credential" 2>/dev/null || echo "")

  cat > "$ENV_FILE" <<EOF
OPENCLAW_CONFIG_DIR=$HOME/.openclaw
OPENCLAW_WORKSPACE=$SCRIPT_DIR/workspace
PROJECTS_DIR=$PROJECTS_DIR
OPENCLAW_GATEWAY_TOKEN=$OPENCLAW_GATEWAY_TOKEN
MOONSHOT_API_KEY=$MOONSHOT_API_KEY
BRAINSTORMROUTER_API_KEY=$BRAINSTORMROUTER_API_KEY
BRAINSTORMROUTER_ADMIN_KEY=$BRAINSTORMROUTER_ADMIN_KEY
DISCORD_BOT_TOKEN=$DISCORD_BOT_TOKEN
EOF
  chmod 600 "$ENV_FILE"
  echo "Secrets loaded into .env (chmod 600)."
}

# --- Clean up .env on exit for non-daemon commands ---
cleanup_env() {
  # Don't remove .env after 'up' — the daemon needs it for restarts
  :
}

# --- Commands ---
case "${1:-up}" in
  up)
    write_env
    docker compose up -d openclaw-gateway
    echo ""
    echo "Gateway running at http://127.0.0.1:18789"
    echo "Run './start.sh doctor' to verify security."
    ;;
  up-dashboard)
    write_env
    docker compose --profile dashboard up -d
    echo ""
    echo "Gateway running at http://127.0.0.1:18789"
    echo "Community dashboard at http://127.0.0.1:3000"
    echo "BR dashboard at http://127.0.0.1:3001"
    ;;
  down)
    docker compose --profile dashboard down
    rm -f "$ENV_FILE"
    echo ".env removed."
    ;;
  doctor)
    write_env
    echo "=== OpenClaw Doctor ==="
    docker compose exec openclaw-gateway openclaw doctor
    echo ""
    echo "=== Deep Security Audit ==="
    docker compose exec openclaw-gateway openclaw security audit --deep
    echo ""
    echo "=== Skill Audit ==="
    docker compose exec openclaw-gateway openclaw clawhub audit 2>/dev/null || echo "(clawhub audit not available on this version)"
    echo ""
    echo "=== Image Version ==="
    docker compose exec openclaw-gateway openclaw --version
    ;;
  backup)
    write_env
    BACKUP_NAME="openclaw-backup-$(date +%Y%m%d-%H%M%S)"
    docker compose exec openclaw-gateway openclaw backup create --name "$BACKUP_NAME" --no-include-workspace
    echo "Backup created: $BACKUP_NAME"
    ;;
  logs)
    docker compose logs -f openclaw-gateway
    ;;
  cli)
    write_env
    shift
    docker compose run --rm openclaw-cli openclaw "$@"
    ;;
  link-whatsapp)
    write_env
    echo "Stopping gateway to avoid session conflict..."
    docker compose stop openclaw-gateway 2>/dev/null || true
    echo ""
    echo "Linking WhatsApp (scan QR with your phone)..."
    echo "After linking, credentials are saved and the gateway will start."
    echo ""
    # Run login in the gateway container image with same volumes
    # Use -it for interactive terminal (QR code display)
    docker compose run \
      -e NODE_OPTIONS="--max-old-space-size=1536" \
      -e HOME=/home/node \
      openclaw-cli sh -c 'openclaw channels login --channel whatsapp && echo "--- Verifying credentials ---" && ls /home/node/.openclaw/credentials/whatsapp/default/ | head -5'
    echo ""
    echo "Starting gateway..."
    docker compose up -d openclaw-gateway
    echo ""
    echo "Gateway running at http://127.0.0.1:18789"
    echo "WhatsApp should be fully connected (inbound + outbound)."
    ;;
  *)
    echo "Usage: ./start.sh [up|up-dashboard|down|doctor|backup|logs|cli <args>]"
    exit 1
    ;;
esac
