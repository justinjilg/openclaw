#!/usr/bin/env bash
###############################################################################
# OpenClaw Integration Test
#
# Runtime validation — requires a running gateway (./start.sh up).
# Tests health endpoint, doctor, version, and basic config access.
#
# Usage: ./scripts/integration-test.sh
# Exit 0 on all-pass, 1 on any FAIL.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== OpenClaw Integration Test ==="
echo ""

# --- 1. Gateway health ---
echo "[1/4] Gateway health"
# Health endpoint binds to container loopback, so we exec into the container to check
if docker compose ps openclaw-gateway 2>/dev/null | grep -q '(healthy)'; then
  pass "Docker healthcheck reports healthy"
  HEALTH=$(docker compose exec -T openclaw-gateway curl -4sf http://127.0.0.1:18789/health 2>/dev/null || echo '{}')
  if echo "$HEALTH" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok')==True or d.get('status')=='live'" 2>/dev/null; then
    pass "Gateway reports ok/live: $HEALTH"
  else
    fail "Gateway health payload unexpected: $HEALTH"
  fi
else
  fail "Gateway is not healthy. Is it running? Try: ./start.sh up"
  echo ""
  echo "=== Integration Test FAILED (gateway not healthy) ==="
  exit 1
fi

# --- 2. Container state ---
echo ""
echo "[2/4] Container state"
if docker compose ps openclaw-gateway 2>/dev/null | grep -q 'Up'; then
  pass "openclaw-gateway container is Up"
else
  fail "openclaw-gateway container is not Up"
fi

# --- 3. Doctor ---
echo ""
echo "[3/4] Doctor"
if docker compose exec -T openclaw-gateway openclaw doctor 2>&1 | tail -20; then
  pass "openclaw doctor completed"
else
  fail "openclaw doctor failed"
fi

# --- 4. Version ---
echo ""
echo "[4/4] Version check"
VERSION=$(docker compose exec -T openclaw-gateway openclaw --version 2>&1 | tail -1 || echo "unknown")
echo "  Gateway version: $VERSION"
if echo "$VERSION" | grep -qE '2026\.[0-9]+\.[0-9]+'; then
  pass "Version matches expected pattern"
else
  fail "Version does not match expected pattern: $VERSION"
fi

# --- Summary ---
echo ""
echo "=== Integration Test Summary ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL"
  exit 1
else
  echo "RESULT: PASS"
  exit 0
fi
