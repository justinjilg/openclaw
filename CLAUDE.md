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
- **Multi-agent system:** 5 specialized agents with per-agent tool restrictions, budgets, and approval modes
- **Primary LLM provider:** BrainstormRouter (`brainstormrouter/auto`) — Thompson sampling across 362 models / 7 providers
- **Fallback LLM provider:** Moonshot Kimi K2.5 (`moonshot/kimi-k2.5`) — used when BR is unreachable
- **MCP integration:** BR exposes 19 tools via streamable-http MCP; per-agent tool grants in `openclaw.json`
- **Two-key model:** Scoped key (completions, budget-capped) + Admin key (management, ops scripts)
- **Daily budget:** $14.50 total ($5 main, $1 ops, $3 research, $5 dev, $0.50 admin) — enforced at BR API layer
- Gateway listens on `127.0.0.1:18789` (loopback only) — WebSocket RPC + HTTP + Control UI on one port
- Container runs as non-root (UID 1000), all capabilities dropped, custom seccomp profile
- Filesystem restricted to workspace only (`tools.fs.workspaceOnly: true`)
- Per-agent tool allow/deny lists — enforced server-side, not just by SOUL.md
- DM policy is allowlist-based — unknown contacts are ignored
- Skills auto-install from ClawHub is disabled; only workspace skills are loaded
- **Cross-project access:** `~/Projects/` mounted at `/home/node/projects/` — all agents can read, only `dev` can write (with `approvalMode: always`)
- **Dashboards:** Community dashboard (port 3000, MFA-enabled) + custom BR dashboard (port 3001, static)
- **Image pinned:** `ghcr.io/openclaw/openclaw:2026.3.28` — never use `:latest`
- Secrets injected from 1Password at runtime (`op://Dev Keys/BrainstormRouter API Key/credential`, `op://Dev Keys/BrainstormRouter Admin Key/credential`, `op://Dev Keys/Moonshot API Key/credential`, `op://Dev Keys/OpenClaw Gateway/credential`)

## Multi-Agent Architecture

| Agent | Role | Budget/day | Heartbeat | Approval Mode | Spawn Rights |
|-------|------|-----------|-----------|---------------|-------------|
| `main` | Coordinator / personal assistant | $5.00 | 30m (08:00-23:00) | default | Can spawn all |
| `ops` | BR health & cost monitoring | $1.00 | 60m (06:00-00:00) | autonomous | None |
| `research` | Deep web research & analysis | $3.00 | none (on-demand) | autonomous | None |
| `dev` | Code development (sandboxed) | $5.00 | none (on-demand) | `always` for exec | None |
| `admin` | BR tenant mgmt & governance | $0.50 | none (on-demand) | `always` for everything | None |

### BR MCP Tools (per-agent)

| Agent | MCP Tools | Purpose |
|-------|-----------|---------|
| `main` | `br_get_health`, `br_list_agents`, `br_list_models`, `br_get_usage` | Overview queries |
| `ops` | `br_get_health`, `br_get_usage`, `br_get_ops_status`, `br_agent_limits`, `br_agent_anomaly`, `br_get_insights`, `br_list_agents`, `br_get_leaderboard`, `br_get_behavioral_profiles`, `br_get_cost_forecast` | Full monitoring + governance (read-only) |
| `research` | `br_memory_store`, `br_memory_query`, `br_memory_list` | Persistent research memory |
| `dev` | (none) | No BR access |
| `admin` | `br_get_governance`, `br_list_agents`, `br_agent_status`, `br_bootstrap_agent`, `br_get_memory_compliance`, `br_get_agent_manifests` | Tenant management + compliance |

MCP server: `https://api.brainstormrouter.com/v1/mcp/connect` (streamable-http, authed via `BRAINSTORMROUTER_ADMIN_KEY`)

### Anti-Runaway Controls

| Control | Mechanism |
|---------|-----------|
| Budget caps | BrainstormRouter enforces per-agent daily $ limits — hard stop |
| Tool deny lists | Per-agent `tools.deny[]` — server-side enforcement |
| Spawn restriction | Only `main` has `sessions_spawn` — others cannot create sub-agents |
| Exec approval | `dev` and `admin` require human approval for every action |
| Workspace isolation | Each agent has separate workspace dir, `fs.workspaceOnly: true` |
| Session isolation | `dmScope: "per-channel-peer"` — no cross-user data leakage |
| No cron/gateway/nodes | No agent can schedule tasks, modify gateway, or manage nodes |
| Dev sandbox | Dev agent runs in per-session Docker containers |
| Fallback model | If BR is down, falls back to Moonshot (no infinite retry) |
| Ops monitoring | Ops agent checks all budgets hourly, alerts on >80% consumption |

## Common Commands

```bash
./start.sh up               # Inject secrets, start gateway → http://127.0.0.1:18789
./start.sh up-dashboard     # Start gateway + both dashboards
./start.sh down             # Stop all services, remove .env
./start.sh doctor           # Full security audit (doctor + deep audit + skill audit)
./start.sh backup           # Create config backup (excludes workspace)
./start.sh logs             # Tail gateway logs
./start.sh cli <command>    # Run any openclaw CLI command
docker compose pull && ./start.sh up  # Update image
```

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
- Custom seccomp profile (`openclaw-seccomp.json`) — syscall allowlist (enabled)
- `no-new-privileges`, ulimits (nproc 256), PID limit (256)
- Memory cap (2GB), CPU cap (2 cores)
- Log rotation (10MB x 3 files)
- Cross-project volume: `~/Projects` mounted at `/home/node/projects/` (read-write; only `dev` has write tools)

### Layer 6: Tool Execution
- Tool profile: `sandbox` (restrictive base) — per-agent allow/deny lists
- `main`: bash, process, read, write, edit, all sessions_* (only agent with `sessions_spawn`)
- `ops`: read, write, sessions_send only — NO bash, NO process, NO edit
- `research`: read, write, web_search, web_fetch — NO bash, NO process
- `dev`: bash, process, read, write, edit — `approvalMode: always` for all exec
- `admin`: read, sessions_send ONLY — NO bash, NO write, NO edit — `approvalMode: always`
- Global deny for all agents: browser, canvas, nodes, cron, gateway
- `exec.approvalMode: always` in gateway.yaml (global fallback)

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
- **Never set `approvalMode` to anything other than `always` for `dev` or `admin`**
- Secrets come from 1Password via `start.sh` — never hardcode in config files
- **Never give non-dev agents write access to `/home/node/projects/`** — only `dev` can write, with approval
- **Never mount `~/Projects/resources/` writable** — it contains secrets
- Run `./start.sh doctor` after every update or skill install (now runs doctor + deep audit + skill audit)
- Run `./scripts/bootstrap-agents.sh` after BR environment resets to re-register agents

## Known CVEs

- **CVE-2026-25253** (CVSS 8.8) — Gateway RCE via unauthenticated WebSocket. Fixed in v2026.2.x. Keep image updated.
- **CVE-2026-31147** (CVSS 7.5) — WebSocket origin bypass. Fixed in v2026.3.11. Requires v2026.3.11+.
- **CVE-2026-30892** (CVSS 6.5) — Auth lockout / enumeration. Fixed in v2026.3.7. Requires v2026.3.7+.
- **CVE-2026-28834** (CVSS 7.8) — Workspace escape via symlink traversal. Fixed in v2026.2.26. We are safe on v2026.3.12.
- **CVE-2026-27691** (CVSS 5.4) — Slack DM allowlist bypass. Fixed in v2026.2.25. We are safe on v2026.3.12.
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
