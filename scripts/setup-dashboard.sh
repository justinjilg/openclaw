#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Setup Dashboard — Prepares community + custom dashboard services
#
# Usage: ./scripts/setup-dashboard.sh
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== OpenClaw Dashboard Setup ==="
echo ""

# Verify Docker is available
if ! command -v docker &>/dev/null; then
  echo "Error: docker is not installed or not in PATH"
  exit 1
fi

# Pull dashboard images
echo "Pulling nginx image for BR dashboard..."
docker pull nginx:alpine

echo ""
echo "Note: Community dashboard (openclaw-dashboard) image must be pulled separately"
echo "once a verified image is available. The BR dashboard works standalone."

# Verify dashboard HTML exists
if [ ! -f "$PROJECT_DIR/workspace/dashboard/index.html" ]; then
  echo "Error: workspace/dashboard/index.html not found"
  echo "This file should have been created during setup."
  exit 1
fi

# Create a seed dashboard-data.json so nginx has something to serve
DASHBOARD_DATA="$PROJECT_DIR/workspace/dashboard/dashboard-data.json"
if [ ! -f "$DASHBOARD_DATA" ]; then
  cat > "$DASHBOARD_DATA" <<'EOF'
{
  "timestamp": null,
  "health": { "status": "unknown", "latencyMs": null, "uptime": null },
  "agents": [],
  "models": { "leaderboard": [] },
  "costs": { "todayUsed": 0, "todayLimit": 14.50, "todayPct": 0, "forecastDaily": null, "forecastMonthly": null },
  "alerts": [{ "level": "info", "message": "Dashboard initialized. Waiting for first ops heartbeat." }]
}
EOF
  echo "Created seed dashboard-data.json"
fi

echo ""
echo "Setup complete. Start dashboards with:"
echo "  ./start.sh up-dashboard"
echo ""
echo "Endpoints:"
echo "  Gateway:             http://127.0.0.1:18789"
echo "  Community Dashboard: http://127.0.0.1:3000"
echo "  BR Dashboard:        http://127.0.0.1:3001"
