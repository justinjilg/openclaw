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

# --- Dependency checks ---
check_deps() {
  local missing=()
  command -v op      &>/dev/null || missing+=("1Password CLI (op)")
  command -v docker  &>/dev/null || missing+=("docker")
  command -v openssl &>/dev/null || missing+=("openssl")
  command -v curl    &>/dev/null || missing+=("curl")
  if [ ${#missing[@]} -gt 0 ]; then
    echo "ERROR: Missing required tools: ${missing[*]}"
    echo "Install missing tools and re-run."
    exit 1
  fi
  if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon is not running. Start Docker Desktop and re-run."
    exit 1
  fi
}

# --- Wait for gateway health (up to 300s) ---
# Cold starts can take 3-4 minutes when WhatsApp has accumulated backlog.
wait_for_health() {
  echo "Waiting for gateway to be healthy (up to 300s)..."
  for i in $(seq 1 60); do
    # Check via Docker's own healthcheck status (more reliable than host-side curl
    # since gateway binds to container loopback, not host loopback)
    if docker compose ps openclaw-gateway 2>/dev/null | grep -q '(healthy)'; then
      echo "Gateway healthy after $((i * 5))s."
      return 0
    fi
    sleep 5
  done
  echo "WARNING: Gateway not healthy after 300s. Check logs: ./start.sh logs"
  return 1
}

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
  if DISCORD_BOT_TOKEN=$(op read "op://Dev Keys/Discord Bot Token/credential" 2>/dev/null); then
    :
  else
    echo "WARNING: Discord bot token not found in 1Password — Discord channel will not work."
    DISCORD_BOT_TOKEN=""
  fi
  if GITHUB_TOKEN=$(op item get "GitHub PAT (justinjilg)" --vault "Dev Keys" --fields credential --format json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['value'])" 2>/dev/null); then
    :
  else
    echo "WARNING: GitHub PAT not found in 1Password — GitHub issue integration will not work."
    GITHUB_TOKEN=""
  fi

  cat > "$ENV_FILE" <<EOF
OPENCLAW_CONFIG_DIR=$HOME/.openclaw
OPENCLAW_WORKSPACE=$SCRIPT_DIR/workspace
PROJECTS_DIR=$PROJECTS_DIR
OPENCLAW_GATEWAY_TOKEN=$OPENCLAW_GATEWAY_TOKEN
MOONSHOT_API_KEY=$MOONSHOT_API_KEY
BRAINSTORMROUTER_API_KEY=$BRAINSTORMROUTER_API_KEY
BRAINSTORMROUTER_ADMIN_KEY=$BRAINSTORMROUTER_ADMIN_KEY
DISCORD_BOT_TOKEN=$DISCORD_BOT_TOKEN
GITHUB_TOKEN=$GITHUB_TOKEN
EOF
  chmod 600 "$ENV_FILE"
  echo "Secrets loaded into .env (chmod 600)."
}

# --- .env lifecycle ---
# .env persists on disk after 'up' because the daemon needs it for auto-restarts.
# It is chmod 600 and .gitignored. It is removed on explicit './start.sh down'.
# Contains 6 secrets: gateway token, moonshot key, BR keys (2), discord token, github token.

# --- Commands ---
check_deps
case "${1:-up}" in
  up)
    write_env
    docker compose up -d openclaw-gateway
    wait_for_health
    echo ""
    echo "Gateway running at http://127.0.0.1:18789"
    echo "Run './start.sh doctor' to verify security."
    ;;
  up-dashboard)
    write_env
    docker compose --profile dashboard up -d
    wait_for_health
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
    echo ""
    echo "=== Smoke Test ==="
    ./scripts/smoke-test.sh || echo "(smoke test reported issues — review above)"
    echo ""
    echo "=== Doc Validator ==="
    ./scripts/validate-docs.sh || echo "(docs drifted from config — update CLAUDE.md)"
    echo ""
    echo "=== Agent Model Verification (live tool-call test) ==="
    ./scripts/verify-agent-models.sh || echo "(one or more agents have models that cannot call tools — fix immediately)"
    ;;
  test)
    ./scripts/smoke-test.sh
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
    echo "Usage: ./start.sh [up|up-dashboard|down|doctor|test|backup|logs|cli <args>|link-whatsapp]"
    exit 1
    ;;
esac
