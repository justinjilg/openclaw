# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A hardened, Docker-based deployment of [OpenClaw](https://github.com/openclaw/openclaw) — an open-source personal AI agent that connects to messaging platforms (WhatsApp, Telegram, Slack, Discord, etc.) and acts via LLMs.

## Architecture

```
start.sh                    # Entrypoint — injects secrets from 1Password, writes .env
docker-compose.yml          # Hardened container orchestration (seccomp, caps, ulimits)
openclaw-seccomp.json       # Custom syscall allowlist for Node.js runtime
gateway.yaml                # Gateway config: binding, auth, exec policy, DM allowlist
SOUL.md                     # Root agent personality (legacy — see workspace SOULs)
.env.example                # Template for secrets (start.sh handles this automatically)
scripts/
  bootstrap-agents.sh       # One-shot: register all agents on BrainstormRouter
  setup-dashboard.sh        # Configure community dashboard
  smoke-test.sh             # Static validation (config syntax, file existence, security hygiene)
  integration-test.sh       # Runtime validation (requires running gateway)
  validate-docs.sh          # CLAUDE.md vs openclaw.json drift check
  verify-agent-models.sh    # Live tool-call test against each agent's configured model
  pin-images.sh             # Pin dashboard images by sha256 digest (requires Docker)
workspace/
  workspaces/
    main/SOUL.md            # Coordinator — user-facing, can spawn all agents
    ops/SOUL.md             # Ops sentinel — BR health/cost monitoring (heartbeat)
    ops/HEARTBEAT.md        # Heartbeat task: health, budgets, anomalies
    research/SOUL.md        # Researcher — web search, document analysis (on-demand)
    dev/SOUL.md             # Developer — sandboxed coding (on-demand, approval required)
    admin/SOUL.md           # Platform admin — BR tenant mgmt (most restricted)
  skills/
    brainstormrouter-ops/   # BR API wrapper skill (br-health, br-usage, br-agents)
    dashboard-reporter/     # Ops skill: writes structured dashboard JSON on heartbeat
  dashboard/
    index.html              # Custom BR-integrated dashboard (served on port 3001)
~/Projects/                 # Cross-project portfolio (mounted read-only at /home/node/projects/)
~/.openclaw/openclaw.json   # Runtime config: providers, agents, tools, budgets
```

**Key architectural points:**
- **Multi-agent system:** 5 specialized agents with per-agent tool restrictions and budgets. `exec.approvalMode: always` is enforced globally in gateway.yaml.
- **LLM routing:** All 5 agents use `brainstormrouter/auto` — BR performs server-side model selection from its 294-model catalog. Direct-provider models (google/*, openai/*, anthropic/*, moonshot/*) in openclaw.json will fail unless you first configure that provider's auth via `openclaw models auth add`.
- **MCP integration:** BR exposes streamable-http MCP at `https://api.brainstormrouter.com/v1/mcp/connect`; per-agent tool grants in `openclaw.json` (counts: main=12, ops=15, research=7, dev=2, admin=11)
- **Two-key model:** Scoped key (completions, budget-capped) + Admin key (management, ops scripts)
- **Daily budget:** $14.50 total ($5 main, $1 ops, $3 research, $5 dev, $0.50 admin) — enforced at BR API layer
- Gateway listens on `127.0.0.1:18789` (loopback only) — WebSocket RPC + HTTP + Control UI on one port
- Container runs as non-root (UID 1000), all capabilities dropped, custom seccomp profile
- Filesystem restricted to workspace only (`tools.fs.workspaceOnly: true`)
- Per-agent tool allow/deny lists — enforced server-side, not just by SOUL.md
- DM policy is allowlist-based — unknown contacts are ignored
- Skills auto-install from ClawHub is disabled; only workspace skills are loaded
- **Cross-project access:** `~/Projects/` mounted **read-only** at `/home/node/projects/` on both gateway and CLI services. No agent can write to the host projects directory from within the container.
- **Dashboards:** Community dashboard (port 3000, MFA-enabled) + custom BR dashboard (port 3001, static)
- **Image pinned:** `ghcr.io/openclaw/openclaw:2026.4.5` — never use `:latest`
- Secrets injected from 1Password at runtime (`op://Dev Keys/BrainstormRouter API Key/credential`, `op://Dev Keys/BrainstormRouter Admin Key/credential`, `op://Dev Keys/Moonshot API Key/credential`, `op://Dev Keys/OpenClaw Gateway/credential`)

## Multi-Agent Architecture

| Agent | Role | Budget/day | Heartbeat | Spawn Rights |
|-------|------|-----------|-----------|-------------|
| `main` | Coordinator / personal assistant | $5.00 | 30m (08:00-23:00) | Can spawn all |
| `ops` | BR health & cost monitoring | $1.00 | 60m (06:00-00:00) | None |
| `research` | Deep web research & analysis | $3.00 | none (on-demand) | None |
| `dev` | Code development (sandboxed) | $5.00 | none (on-demand) | None |
| `admin` | BR tenant mgmt & governance | $0.50 | none (on-demand) | None |

**All agents use `brainstormrouter/auto` as their model.** BR performs server-side model selection from its 294-model catalog based on the request (tool-capable for agent calls, vision-capable when images are attached, etc.). The only provider configured in openclaw's gateway.yaml + per-agent `models.json` is `brainstormrouter`. Per-agent model overrides in `openclaw.json` (e.g., `google/gemini-2.5-flash-lite`) will fail with "No API key found for provider X" unless you also configure that provider's auth via `openclaw models auth add` — by default, all traffic routes through BR.

**Budget enforcement has two layers:**
1. **BR scoped key budget**: $50/day (resets at UTC midnight). This is the hard limit on the scoped API key itself — when exhausted, all agents return 402. CLAUDE.md previously documented $14.50/day which was wrong.
2. **Per-agent budgets registered in BR**: $19.50/day total (main $10, ops $1, research $3, dev $5, admin $0.5). These are informational today because openclaw calls aren't being tagged with agent IDs — all usage shows under `cost_center: unassigned`.

**Approval Mode:** `exec.approvalMode: always` is enforced **globally** in `gateway.yaml` (not per-agent). Every tool exec across every agent requires human approval. The dev and admin agents are additionally restricted by per-agent tool allow/deny lists (see Layer 6 below).

### BR MCP Tools (per-agent)

Source of truth: `~/.openclaw/openclaw.json`. Run `./scripts/validate-docs.sh` to verify this table matches the runtime config.

| Agent | Count | MCP Tools | Purpose |
|-------|-------|-----------|---------|
| `main` | 12 | `br_get_health`, `br_list_agents`, `br_list_models`, `br_get_usage`, `br_memory_store`, `br_memory_query`, `br_memory_list`, `br_workspace_get`, `br_workspace_list`, `br_get_heartbeat`, `br_get_agent_skill`, `br_list_agent_skills` | Overview + memory + workspace + skill access |
| `ops` | 15 | `br_get_health`, `br_get_usage`, `br_get_ops_status`, `br_agent_limits`, `br_agent_anomaly`, `br_get_insights`, `br_list_agents`, `br_get_leaderboard`, `br_get_behavioral_profiles`, `br_get_cost_forecast`, `br_get_heartbeat`, `br_workspace_list`, `br_get_agent_skill`, `br_get_skill_history`, `br_list_agent_skills` | Full monitoring + governance + skill history (read-only) |
| `research` | 7 | `br_memory_store`, `br_memory_query`, `br_memory_list`, `br_workspace_get`, `br_workspace_list`, `br_get_agent_skill`, `br_list_agent_skills` | Persistent research memory + workspace + skill read |
| `dev` | 2 | `br_workspace_get`, `br_workspace_list` | Workspace read-only (no BR API access) |
| `admin` | 11 | `br_get_governance`, `br_list_agents`, `br_agent_status`, `br_bootstrap_agent`, `br_get_memory_compliance`, `br_get_agent_manifests`, `br_workspace_put`, `br_workspace_delete`, `br_update_agent_skill`, `br_get_heartbeat`, `br_list_agent_skills` | Tenant management + compliance + workspace write + skill updates |

MCP server: `https://api.brainstormrouter.com/v1/mcp/connect` (streamable-http, authed via `BRAINSTORMROUTER_ADMIN_KEY`)

### Anti-Runaway Controls

| Control | Mechanism |
|---------|-----------|
| Budget caps | BrainstormRouter enforces per-agent daily $ limits — hard stop |
| Tool deny lists | Per-agent `tools.deny[]` — server-side enforcement |
| Spawn restriction | Only `main` has `sessions_spawn` — others cannot create sub-agents |
| Exec approval | `exec.approvalMode: always` applies globally to ALL agents (not per-agent) |
| Workspace isolation | Each agent has separate workspace dir, `fs.workspaceOnly: true` |
| Session isolation | `dmScope: "per-channel-peer"` — no cross-user data leakage |
| No cron/gateway/nodes | No agent can schedule tasks, modify gateway, or manage nodes |
| Dev sandbox | Dev agent runs in per-session Docker containers (`sandbox.mode: all`) |
| Model selection | Main uses `moonshot/kimi-k2.5` directly (not BR auto — manual change recorded in MEMORY.md after BR auto routed to audio-only models). Not an automatic failover. |
| Ops monitoring | Ops agent runs heartbeat (60m, 06:00-00:00) checking health, budgets, anomalies |

## Common Commands

```bash
./start.sh up                  # Inject secrets, start gateway, wait for /health → http://127.0.0.1:18789
./start.sh up-dashboard        # Start gateway + both dashboards
./start.sh down                # Stop all services, remove .env
./start.sh doctor              # Full audit (doctor + deep audit + skill audit + smoke test + doc validator)
./start.sh test                # Run smoke test only (fast, no gateway required)
./start.sh backup              # Create config backup (excludes workspace)
./start.sh logs                # Tail gateway logs
./start.sh cli <command>       # Run any openclaw CLI command
./start.sh link-whatsapp       # Re-link WhatsApp (scan QR)
./scripts/smoke-test.sh        # Static validation (same as ./start.sh test)
./scripts/integration-test.sh  # Runtime validation (requires gateway up)
./scripts/validate-docs.sh     # Check CLAUDE.md vs openclaw.json for drift
./scripts/pin-images.sh        # Update dashboard image digests (requires Docker)
docker compose pull && ./start.sh up  # Update image
```

**New operator workflow:**
1. `./scripts/smoke-test.sh` — verify config before any changes
2. `./start.sh up` — deploy (waits up to 150s for /health)
3. `./scripts/integration-test.sh` — verify runtime
4. `./start.sh doctor` — full audit with doc drift check

## CI/CD

GitHub Actions pipeline at `.github/workflows/ci.yml` runs on every push to `main` and every PR. Three parallel jobs:

1. **Smoke Test + Doc Validator** — runs `scripts/smoke-test.sh` (25 checks) and `scripts/validate-docs.sh` (9 checks) using `test-fixtures/openclaw.json` for CI-compatible config access
2. **Config Syntax Validation** — validates YAML/JSON parsing, checks for hardcoded secrets, flags unpinned images
3. **Security Lint** — verifies .gitignore includes .env, all scripts use strict mode, CLI mount is :ro, gateway has seccomp + read_only rootfs, cap_drop ALL on all services

The `test-fixtures/openclaw.json` file contains the agent config (tool grants, models) extracted from `~/.openclaw/openclaw.json`. **Keep it in sync** — run `./scripts/validate-docs.sh` locally to catch drift.

## Security Model — 8 Layers

This deployment implements defense-in-depth across all eight recommended security layers.

### Layer 1: Runtime
Node.js >= 22.12.0 enforced by Docker image (CVE-2025-59466, CVE-2026-21636).

### Layer 2: Gateway Auth
Token-based auth, stored in 1Password. Loopback binding skips origin checks.

### Layer 3: DM Policy
Allowlist-only (`dm.policy: "allowlist"`). Empty by default — add contacts before connecting channels.

### Layer 4: Filesystem Sandbox
`tools.fs.workspaceOnly: true` — agent cannot read/write outside `/home/node/workspace`. Applies to read, write, edit, and apply_patch.

### Layer 5: Docker Hardening
- Non-root (UID 1000), all capabilities dropped
- Custom seccomp profile (`openclaw-seccomp.json`) applied to gateway, CLI, and both dashboard services
- `no-new-privileges`, ulimits (nproc 256), PID limit (256)
- Memory cap (2GB gateway), CPU cap (2 cores gateway)
- `read_only: true` rootfs on gateway, writable paths via tmpfs (`/tmp`, `/home/node/.cache`)
- Log rotation (10MB x 3 files)
- Cross-project volume: `~/Projects` mounted at `/home/node/projects/` **read-only** on both gateway and CLI
- Dashboard images (community + br-dashboard) also pinned and hardened (caps dropped, no-new-privileges, seccomp)

### Layer 6: Tool Execution
- Tool profiles (from openclaw.json): `main`=`coding`, `dev`=`coding`, `ops`/`research`/`admin`=`minimal`
- Per-agent allow/deny lists enforced server-side. Only `main` has `sessions_spawn`.
- `ops`, `research`, `admin`: deny `bash`, `process`, `edit`, `sessions_spawn`
- `research`: additionally has `web_search`, `web_fetch`
- `admin`: additionally denies `write` (read + sessions_send only)
- `dev`: `coding` profile with sandbox mode `all` (per-session Docker containers)
- Global deny for all agents: browser, canvas, nodes, cron, gateway
- **`exec.approvalMode: always` enforced GLOBALLY in gateway.yaml** — applies to every tool exec across every agent. Not per-agent.

### Layer 7: SSRF Guards
`blockPrivateNetworks: true` — blocks requests to 10.x, 192.168.x, 172.16-31.x, 127.x from skills/tools.

### Layer 8: Skill Trust
`autoInstall: false`, `pinVersions: true`. No ClawHub auto-install. Audit every skill before use.

## Critical Rules

- **Never change `bind` from `loopback`** without also setting `auth.token` and `controlUi.allowedOrigins`
- **Never enable `autoInstall: true`** for skills (1,467 malicious payloads found on ClawHub, Feb 2026)
- **Never relax `tools.fs.workspaceOnly`** — this is the primary filesystem boundary
- **Never add tools to the allow list** without understanding what they do (especially `browser`, `gateway`, `nodes`)
- **Never give non-main agents `sessions_spawn`** — only `main` can create sub-agents
- **Never change `exec.approvalMode` from `always`** in gateway.yaml — this is the only per-exec human gate
- Secrets come from 1Password via `start.sh` — never hardcode in config files
- **Never mount `~/Projects/` read-write** — both gateway and CLI services must use `:ro`
- **Never mount `~/Projects/resources/` at all** — it contains secrets
- Run `./scripts/smoke-test.sh` before every commit — catches config drift statically
- Run `./start.sh doctor` after every update (now runs doctor + deep audit + smoke test + doc validator)
- Run `./scripts/bootstrap-agents.sh` after BR environment resets to re-register agents

## .env Lifecycle (Security-Relevant)

- `.env` is generated by `start.sh` via 1Password CLI, chmod 600, and `.gitignored`
- `.env` **persists on disk after `./start.sh up`** — the daemon needs it for automatic restarts
- `.env` contains 6 secrets: gateway token, Moonshot API key, BR API key, BR admin key, Discord bot token, GitHub PAT
- `.env` is **only removed on explicit `./start.sh down`** — not on crash, kill, or reboot
- Operators should run `./start.sh down` before leaving the machine unattended for extended periods
- For defense-in-depth, consider running on an encrypted filesystem so `.env` is protected at rest

## Known CVEs

- **CVE-2026-25253** (CVSS 8.8) — Gateway RCE via unauthenticated WebSocket. Fixed in v2026.2.x. Keep image updated.
- **CVE-2026-31147** (CVSS 7.5) — WebSocket origin bypass. Fixed in v2026.3.11. Requires v2026.3.11+.
- **CVE-2026-30892** (CVSS 6.5) — Auth lockout / enumeration. Fixed in v2026.3.7. Requires v2026.3.7+.
- **CVE-2026-28834** (CVSS 7.8) — Workspace escape via symlink traversal. Fixed in v2026.2.26. We are safe on v2026.4.5.
- **CVE-2026-27691** (CVSS 5.4) — Slack DM allowlist bypass. Fixed in v2026.2.25. We are safe on v2026.4.5.
- **GHSA-9p3r-hh9g-5cmg** (Critical) — Sandbox escape via TOCTOU race in remote FS bridge. Fixed in v2026.3.31+. We are safe on v2026.4.5.
- **GHSA-3qpv-xf3v-mm45** (High) — Workspace `.env` overrides bundled hooks root. Fixed in v2026.3.31+. We are safe on v2026.4.5.
- **GHSA-qcj9-wwgw-6gm8** (High) — Workspace `.env` overrides plugin trust root. Fixed in v2026.3.31+. We are safe on v2026.4.5.
- **ClawJacked** — WebSocket hijack from malicious browser tabs. Mitigated by loopback binding.
- **ClawHub supply chain** — 824+ malicious skills, 1,467 payloads found on ClawHub. Mitigated by `autoInstall: false`.

## Config File Locations

| File | Host Path | Container Path |
|------|-----------|---------------|
| Runtime config | `~/.openclaw/openclaw.json` | `/home/node/.openclaw/openclaw.json` |
| Gateway config | `~/.openclaw/gateway.yaml` | `/home/node/.openclaw/gateway.yaml` |
| Workspace (root) | `./workspace/` | `/home/node/workspace/` |
| Agent workspaces | `./workspace/workspaces/<agent>/` | `/home/node/workspace/workspaces/<agent>/` |
| BR ops skill | `./workspace/skills/brainstormrouter-ops/` | `/home/node/workspace/skills/brainstormrouter-ops/` |
| Dashboard reporter | `./workspace/skills/dashboard-reporter/` | `/home/node/workspace/skills/dashboard-reporter/` |
| BR Dashboard | `./workspace/dashboard/` | Served by nginx on port 3001 |
| Cross-project dirs | `~/Projects/` | `/home/node/projects/` (read-only) |
| Bootstrap script | `./scripts/bootstrap-agents.sh` | Host only (not mounted) |
| Dashboard setup | `./scripts/setup-dashboard.sh` | Host only (not mounted) |
| Seccomp profile | `./openclaw-seccomp.json` | Referenced by Docker at container creation |
