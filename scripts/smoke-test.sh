#!/usr/bin/env bash
###############################################################################
# OpenClaw Smoke Test
#
# Static validation — runs without requiring a running gateway.
# Verifies config syntax, file existence, and basic security hygiene.
#
# Usage: ./scripts/smoke-test.sh
# Exit 0 on all-pass, 1 on any FAIL (WARNINGs do not fail the test).
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
WARN=0

pass()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
warn()  { echo "  WARN: $1"; WARN=$((WARN+1)); }

echo "=== OpenClaw Smoke Test ==="
echo ""

# --- 1. Config validation ---
echo "[1/6] Config validation"
if command -v docker &>/dev/null && docker info &>/dev/null; then
  if docker compose config --quiet 2>/dev/null; then
    pass "docker-compose.yml parses"
  else
    fail "docker-compose.yml invalid"
  fi
else
  # Fallback: yaml parse
  if python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))" 2>/dev/null; then
    pass "docker-compose.yml parses (python yaml, docker daemon not running)"
  else
    fail "docker-compose.yml invalid YAML"
  fi
fi

if python3 -c "import json; json.load(open('openclaw-seccomp.json'))" 2>/dev/null; then
  pass "openclaw-seccomp.json parses"
else
  fail "openclaw-seccomp.json invalid"
fi

if python3 -c "import yaml; yaml.safe_load(open('gateway.yaml'))" 2>/dev/null; then
  pass "gateway.yaml parses"
else
  fail "gateway.yaml invalid"
fi

# --- 2. Required files ---
echo ""
echo "[2/6] Required files"
for f in gateway.yaml start.sh docker-compose.yml openclaw-seccomp.json CLAUDE.md .gitignore; do
  if [ -f "$f" ]; then pass "$f exists"; else fail "$f missing"; fi
done

# --- 3. Agent SOULs ---
echo ""
echo "[3/6] Agent SOULs"
for agent in main ops research dev admin; do
  f="workspace/workspaces/$agent/SOUL.md"
  if [ -f "$f" ]; then pass "$agent SOUL"; else fail "$agent SOUL missing"; fi
done

# --- 4. Skills ---
echo ""
echo "[4/6] Skills"
for skill in brainstormrouter-ops dashboard-reporter br-stress-test; do
  f="workspace/skills/$skill/SKILL.md"
  if [ -f "$f" ]; then pass "$skill SKILL.md"; else fail "$skill SKILL.md missing"; fi
done

# --- 5. Security checks (static) ---
echo ""
echo "[5/6] Security (static)"

# No hardcoded secrets in tracked files
if grep -rnE '(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|password\s*=\s*[a-zA-Z0-9])' \
  --include='*.sh' --include='*.yml' --include='*.yaml' --include='*.json' \
  --exclude-dir=node_modules --exclude-dir=.git --exclude='.env*' \
  . 2>/dev/null | grep -v 'example'; then
  fail "Possible hardcoded secrets found above"
else
  pass "No hardcoded secrets in tracked config"
fi

# .env is gitignored
if grep -qxF '.env' .gitignore 2>/dev/null || grep -qE '^\.env$' .gitignore 2>/dev/null; then
  pass ".env is gitignored"
else
  fail ".env not in .gitignore"
fi

# No :latest tags in docker-compose (except in commented TODO lines)
if grep -nE '^\s*image:.*:latest' docker-compose.yml; then
  warn ":latest image tag found (should be pinned)"
else
  pass "No :latest tags"
fi

# CLI Projects mount is :ro
if grep -q 'PROJECTS_DIR.*:/home/node/projects:ro' docker-compose.yml; then
  pass "CLI Projects mount is read-only"
else
  fail "CLI Projects mount is NOT read-only (add :ro)"
fi

# Gateway has read_only rootfs (search the openclaw-gateway service block)
if awk '/^  openclaw-gateway:/{flag=1;next} /^  [a-z]/{flag=0} flag' docker-compose.yml | grep -q 'read_only: true'; then
  pass "Gateway has read_only rootfs"
else
  warn "Gateway does not have read_only rootfs"
fi

# Seccomp on all services
seccomp_count=$(grep -c 'seccomp:openclaw-seccomp.json' docker-compose.yml || echo 0)
if [ "$seccomp_count" -ge 3 ]; then
  pass "Seccomp applied to $seccomp_count services"
else
  warn "Seccomp only applied to $seccomp_count services (expected 3+)"
fi

# --- 6. Script hygiene ---
echo ""
echo "[6/6] Script hygiene"
for s in start.sh scripts/bootstrap-agents.sh scripts/setup-dashboard.sh; do
  if [ ! -f "$s" ]; then continue; fi
  if head -15 "$s" | grep -q 'set -euo pipefail'; then
    pass "$s uses set -euo pipefail"
  else
    warn "$s does not use set -euo pipefail"
  fi
done

# --- Summary ---
echo ""
echo "=== Smoke Test Summary ==="
echo "  PASS: $PASS"
echo "  WARN: $WARN"
echo "  FAIL: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL"
  exit 1
else
  echo "RESULT: PASS"
  exit 0
fi
