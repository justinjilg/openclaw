# BrainstormRouter — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **API Base URL** | `https://api.brainstormrouter.com` |
| **Account Tier** | Tenant (openclaw-fleet) |
| **Tests Run** | 55 (54 PASS, 0 FAIL, 1 TIER_RESTRICTED) |
| **Pass Rate** | 98% |
| **API Keys Used** | 2 (scoped + admin) |
| **Endpoints Discovered** | 25 (11 accessible, 13 exist but restricted, 1 not found) |
| **Total Cost** | ~$0.15 |

---

## 1. Platform Overview

### 1.1 Company & Product

BrainstormRouter is an intelligent LLM routing platform that uses **Thompson sampling** to automatically select the best model for each request across multiple providers. Unlike traditional gateways that require manual routing config, BR learns which models perform best over time and routes accordingly.

**Key stats:**
- 362 models across 7 providers
- Thompson sampling for automatic model selection
- Per-agent budgets with hard enforcement
- MCP server (19 tools) for programmatic access
- Multi-tenant architecture with cost centers

### 1.2 Architecture

```
Your App / OpenClaw Agent → BR API → Thompson Sampling → Best Provider/Model
                              ↓
    Security Layer:
      Per-agent tool allow/deny lists (server-enforced)
      Approval modes (default, autonomous, always)
      Session isolation (per-channel-peer)
      DM allowlist policy (unknown contacts ignored)
      SSRF guards (blockPrivateNetworks: true)
      Workspace filesystem sandboxing

    Intelligence Layer:
      Agent Profiles (budget, lifecycle, cost center)
      Anomaly Detection + Behavioral Profiling
      Governance (compliance, manifests, leaderboard)
      Cost Forecasting + Daily Insights

    Infrastructure:
      MCP Server (19 tools, streamable-http)
      PostgreSQL (db: true) + Redis (redis: true)
      Webhooks endpoint (configurable)
      Audit log, alerts, sessions (restricted endpoints)
```

### 1.3 Pricing

Not publicly listed. Tenant-based pricing with:
- Per-agent daily budget caps (hard-enforced at API layer)
- Cost center tracking (`openclaw-fleet`)
- Provider costs managed server-side (no BYOK needed)

### 1.4 Provider Ecosystem

**7 providers, 362 models** (from `/v1/providers/catalog`):

| Provider | Models | Status |
|----------|--------|--------|
| Anthropic | Claude 4.x, 3.x | Active |
| DeepSeek | deepseek-chat, deepseek-reasoner | Active |
| Google | Gemini 2.x | Active |
| Moonshot | kimi-k2.5, moonshot-v1-* | Active |
| OpenAI | GPT-5.x, GPT-4o, o-series | Active |
| Perplexity AI | sonar, sonar-pro | Active |
| x-AI | Grok | Active |

**Auto model:** `brainstormrouter/auto` uses Thompson sampling to select the best model per-request.

### 1.5 SDKs & CLI

| Tool | Status |
|------|--------|
| **REST API** | Primary interface (OpenAI-compatible `/v1/chat/completions`) |
| **MCP Server** | 19 tools via streamable-http at `/v1/mcp/connect` |
| **No SDK** | No official Node.js or Python SDK — use standard HTTP or OpenAI SDK with base_url override |
| **No CLI** | No dedicated CLI tool |

### 1.6 Compliance

Not publicly documented. Infrastructure indicates enterprise readiness (PostgreSQL + Redis, multi-tenant isolation).

---

## 2. Inference API

### 2.1 Chat Completions

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/chat/completions` |
| **Live Tested** | 8/8 PASS |
| **Avg Latency** | 1750ms (auto), 2443ms (moonshot direct) |
| **Streaming** | Yes (SSE) |
| **Portkey Equivalent** | `POST /v1/chat/completions` (identical endpoint) |
| **Key Difference** | BR's `auto` model uses Thompson sampling; Portkey requires explicit model selection or config-based routing |

**Features tested (all PASS):**
- Auto model (Thompson sampling) — non-streaming
- Specific model (moonshot/kimi-k2.5) — non-streaming
- Streaming (SSE)
- Multi-turn conversation
- Temperature control
- Model access restriction (scoped key correctly blocks unauthorized models)
- Token usage tracking
- Response headers

### 2.2 Embeddings

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/embeddings` |
| **Status** | Endpoint exists (400 — needs valid model), not on allowed_models for scoped key |
| **Portkey Equivalent** | Full support with any embedding model |

### 2.3 Images, Moderations, Audio

| Endpoint | Status | Notes |
|----------|--------|-------|
| `POST /v1/images/generations` | 403 | Exists but restricted on scoped key |
| `POST /v1/moderations` | 403 | Exists but restricted on scoped key |
| `POST /v1/audio/speech` | 403 | Exists but restricted on scoped key |

These endpoints exist in the API but are not accessible with the current key scoping. Portkey provides full access to all these via provider passthrough.

---

## 3. Routing

### 3.1 Thompson Sampling (Auto Model)

BR's unique differentiator. The `brainstormrouter/auto` model:
- Uses multi-armed bandit algorithm to learn which models perform best
- Routes each request to the statistically optimal model
- Balances exploration (trying new models) vs. exploitation (using known good ones)
- No manual configuration needed — the system learns over time

**Portkey equivalent:** Config-based routing with weighted load balancing, fallback chains, or canary testing. Requires explicit configuration.

### 3.2 Allowed Models

Scoped keys enforce which models a user can access:
- Our scoped key allows: moonshot/kimi-k2.5, moonshot/moonshot-v1-128k, moonshot/moonshot-v1-32k, moonshot/moonshot-v1-8k
- `auto` model bypasses allowed_models check (resolved server-side)
- Unauthorized models return 403 (confirmed in test)

### 3.3 No Fallback/Retry Config

BR does not expose user-configurable fallback chains or retry policies. The platform handles this internally via Thompson sampling — if a model fails, the algorithm learns and routes away from it.

---

## 4. Agent Management

### 4.1 Agent Profiles

| Field | Value |
|-------|-------|
| **API Endpoint** | `GET /v1/agent/profiles` |
| **Auth** | Admin key |
| **Live Tested** | PASS |

Returns all registered agents with:
- `agentId`, `tenantId`
- `budgetDailyUsd` (per-agent daily cap)
- `lifecycleState` (active/inactive)
- `costCenter` assignment

### 4.2 Agent Lifecycle

| Endpoint | Status | Purpose |
|----------|--------|---------|
| `/v1/agent/profiles` | 200 | List all agent profiles |
| `/v1/agent/list` | 200 | List agents (alternate endpoint) |
| `/v1/agent/limits` | 403 | Agent budget limits (restricted) |
| `/v1/agent/anomaly` | 200 | Anomaly detection |
| `/v1/agent/manifests` | 200 | Agent manifests |
| `/v1/agent/bootstrap` | 403 | Agent registration (restricted) |
| `/v1/agent/status` | 401 | Requires agent JWT (not admin key) |

### 4.3 Budget Enforcement

Budgets are enforced at the API layer — when an agent exceeds its daily budget, requests are hard-stopped. No soft limits or degradation; it's a binary on/off.

| Agent | Daily Budget | Cost Center |
|-------|-------------|-------------|
| main | $5.00 | openclaw-fleet |
| ops | $1.00 | openclaw-fleet |
| research | $3.00 | openclaw-fleet |
| dev | $5.00 | openclaw-fleet |
| admin | $0.50 | openclaw-fleet |

---

## 5. Governance & Observability

| Endpoint | Status | Data Returned |
|----------|--------|--------------|
| `/v1/ops/status` | 200 | Operational status |
| `/v1/agent/anomaly` | 200 | Anomaly detection results |
| `/v1/behavioral-profiles` | 200 | Agent behavioral analysis |
| `/v1/leaderboard` | 200 | Model performance rankings |
| `/v1/governance` | 200 | Governance policies |
| `/v1/agent/manifests` | 200 | Agent capability manifests |
| `/v1/memory/compliance` | 200 | Memory compliance audit |
| `/v1/insights/daily` | 200 | Daily usage insights |
| `/v1/cost-forecast` | 200 | Cost projection |

**All 9 governance endpoints responded successfully** — this is BR's strongest feature area.

---

## 6. Usage & Cost Tracking

| Endpoint | Status | Data |
|----------|--------|------|
| `/v1/usage/by-cost-center` | 200 | Per-cost-center usage with period, since date |
| `/v1/cost-forecast` | 200 | Projected costs |
| `/v1/insights/daily` | 200 | Daily breakdown |

---

## 7. MCP Server

| Field | Value |
|-------|-------|
| **URL** | `https://api.brainstormrouter.com/v1/mcp/connect` |
| **Transport** | Streamable HTTP |
| **Auth** | Admin key (Bearer token) |
| **Tools** | 19 (documented in CLAUDE.md) |
| **Live Tested** | 2/2 PASS (initialize + tools/list) |

**Known tools (from OpenClaw config):**
- `br_get_health`, `br_list_agents`, `br_list_models`, `br_get_usage`
- `br_get_ops_status`, `br_agent_limits`, `br_agent_anomaly`
- `br_get_insights`, `br_get_leaderboard`
- `br_get_behavioral_profiles`, `br_get_cost_forecast`
- `br_memory_store`, `br_memory_query`, `br_memory_list`
- `br_get_governance`, `br_agent_status`, `br_bootstrap_agent`
- `br_get_memory_compliance`, `br_get_agent_manifests`

---

## 8. Full API Surface (Discovered)

### Accessible (200)

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Health check (no auth needed) — db, redis, uptime, version |
| `GET /v1/agent/profiles` | Agent profile listing |
| `GET /v1/agent/list` | Alternate agent listing |
| `GET /v1/agent/anomaly` | Anomaly detection |
| `GET /v1/agent/manifests` | Agent capability manifests |
| `GET /v1/usage/by-cost-center` | Usage data by cost center |
| `GET /v1/providers` | Provider configurations |
| `GET /v1/providers/catalog` | Full provider/model catalog |
| `GET /v1/models` | Model listing |
| `GET /v1/config` | Configuration (returned empty) |
| `GET /v1/webhooks` | Webhook list (empty, 0 configured) |
| `GET /v1/ops/status` | Ops status |
| `GET /v1/behavioral-profiles` | Behavioral analysis |
| `GET /v1/leaderboard` | Model leaderboard |
| `GET /v1/governance` | Governance policies |
| `GET /v1/memory/compliance` | Memory compliance |
| `GET /v1/insights/daily` | Daily insights |
| `GET /v1/cost-forecast` | Cost forecasting |
| `POST /v1/chat/completions` | Chat completions (inference) |
| `POST /v1/mcp/connect` | MCP server |

### Exist but Restricted (403)

| Endpoint | Likely Purpose |
|----------|---------------|
| `GET /v1/tenants` | Tenant management |
| `GET /v1/tenants/current` | Current tenant info |
| `GET /v1/keys` | API key management |
| `GET /v1/keys/list` | API key listing |
| `GET /v1/settings` | Platform settings |
| `GET /v1/audit-log` | Audit trail |
| `GET /v1/alerts` | Alert configuration |
| `GET /v1/budgets` | Budget management |
| `GET /v1/sessions` | Session management |
| `GET /v1/memory` | Memory management |
| `GET /v1/agent/bootstrap` | Agent registration |
| `GET /v1/agent/limits` | Agent budget limits |

### Special Auth Required

| Endpoint | Auth Type | Notes |
|----------|-----------|-------|
| `GET /v1/agent/status` | Agent JWT | Requires agent identity token, not admin key |

### Not Found

| Endpoint | Notes |
|----------|-------|
| `GET /v1/memory/list` | 404 — does not exist |

### Inference Endpoints (Exist but Restricted by Model Allowlist)

| Endpoint | Status |
|----------|--------|
| `POST /v1/embeddings` | 400 (model validation) |
| `POST /v1/images/generations` | 403 (not on allowlist) |
| `POST /v1/moderations` | 403 (not on allowlist) |
| `POST /v1/audio/speech` | 403 (not on allowlist) |

---

## 9. Security & Guardrails

BR has a comprehensive **agent-scoped security model** — different in nature from Portkey's content-filtering guardrails or Lasso's intent-based analysis, but covering real security concerns for multi-agent systems.

### 9.1 Per-Agent Tool Restrictions (Server-Enforced)

Each agent has explicit tool allow/deny lists enforced at the API layer, not just in the SOUL prompt:

| Agent | Allowed | Denied | Approval Mode |
|-------|---------|--------|---------------|
| **main** | bash, process, read, write, edit, all sessions_* | browser, canvas, nodes, cron, gateway | default |
| **ops** | read, write, sessions_send | bash, process, edit + all global denies | autonomous |
| **research** | read, write, web_search, web_fetch | bash, process + all global denies | autonomous |
| **dev** | bash, process, read, write, edit | all global denies | **always** (human approval for every exec) |
| **admin** | read, sessions_send ONLY | bash, write, edit + all global denies | **always** (human approval for everything) |

**Global deny for all agents:** browser, canvas, nodes, cron, gateway.

### 9.2 Session Isolation

| Control | Mechanism |
|---------|-----------|
| **DM scope** | `per-channel-peer` — no cross-user data leakage |
| **DM policy** | Allowlist-only — unknown contacts are silently ignored |
| **Workspace isolation** | Each agent has separate workspace dir with `fs.workspaceOnly: true` |

### 9.3 Spawn Control

Only the `main` agent has `sessions_spawn` — no other agent can create sub-agents. This is a critical anti-runaway control that prevents agents from self-replicating or escalating privileges.

### 9.4 SSRF Guards

`blockPrivateNetworks: true` — blocks requests from skills/tools to 10.x, 192.168.x, 172.16-31.x, 127.x. Prevents agents from reaching internal infrastructure.

### 9.5 Budget Enforcement as Security

Budgets are hard caps (not warnings). When an agent hits its daily limit, requests fail immediately. This prevents:
- Runaway cost from compromised agents
- Budget exhaustion attacks
- Resource abuse across agents

The ops agent monitors all budgets hourly and alerts on >80% consumption.

### 9.6 Blocked Commands

Gateway-level command blocking (configured in gateway.yaml):
- `curl|sh`, `wget|sh` (download-and-execute)
- `pip install`, `npm install -g` (package install)
- `chmod 777`, `chown` (permission escalation)
- Other dangerous patterns

### 9.7 Skill Trust

- `autoInstall: false` — no ClawHub auto-install (1,467 malicious payloads found)
- `pinVersions: true` — all skill versions locked
- Every skill audited before use

### 9.8 Comparison to Other Gateways' Guardrails

| Feature | BR | Portkey | CF AI GW | Lasso | LiteLLM |
|---------|-----|---------|---------|-------|---------|
| Per-agent tool restrictions | **Yes (server-enforced)** | No | No | No | No |
| Session isolation | **Yes (per-channel-peer)** | No | No | Yes | No |
| Spawn control | **Yes (main only)** | No | No | No | No |
| SSRF blocking | **Yes** | No | No | No | No |
| Budget hard caps | **Yes (per-agent)** | Per-workspace | No | No | Per-user/team |
| Command blocking | **Yes (gateway-level)** | No | No | No | No |
| Content filtering | No | **Yes (20+ checks)** | **Yes (DLP)** | **Yes (50+ guardrails)** | Yes (LLM Guard) |
| PII detection | No | Yes (Enterprise) | **Yes (DLP)** | **Yes (auto-masking)** | Yes (regex) |
| Intent analysis | No | No | No | **Yes (99.83%)** | No |
| Jailbreak detection | No | Yes | Yes | **Yes (3k+ techniques)** | Yes |

**Key insight:** BR's security is about **controlling what agents can do** (tool restrictions, spawn control, workspace isolation). Other gateways' security is about **filtering what content flows through** (PII, jailbreaks, harmful content). Both are necessary; they're complementary layers.

---

## 10. Additional Capabilities (From OpenClaw Deployment)

### 10.1 Webhooks

`/v1/webhooks` endpoint exists and responded with `{"webhooks":[], "total": 0}`. Infrastructure is in place for event-driven integrations, just none configured.

### 10.2 Management APIs (Restricted)

These endpoints exist but returned 403 with our admin key — indicating a higher permission tier exists:

| Endpoint | Likely Purpose |
|----------|---------------|
| `/v1/tenants`, `/v1/tenants/current` | Multi-tenant management |
| `/v1/keys`, `/v1/keys/list` | API key lifecycle |
| `/v1/settings` | Platform configuration |
| `/v1/audit-log` | Compliance audit trail |
| `/v1/alerts` | Alert/notification system |
| `/v1/budgets` | Budget management API |
| `/v1/sessions` | Session management |
| `/v1/memory` | Memory/context management |

This reveals BR has a **much larger management surface** than documented — at least 8 additional admin endpoints beyond what our key can access.

### 10.3 Agent JWT Authentication

`/v1/agent/status` returned 401 with "Agent identity required (JWT)" — indicating BR supports per-agent JWT tokens, separate from the admin API key system. This is a 3-tier auth model:
1. **Scoped key** — completions, budget-capped
2. **Admin key** — management, agent profiles, governance
3. **Agent JWT** — per-agent identity, status reporting

---

## 11. Limitations & Gaps

### 11.1 No SDK

No official Node.js or Python SDK — REST + MCP only. No type safety, streaming helpers, or IDE autocomplete.

### 11.2 No User-Configurable Routing

Thompson sampling is automatic. No user-exposed fallback chains, weighted distribution, canary testing, or retry policies.

### 11.3 No Caching

No response caching or prompt caching layer.

### 11.4 No Content Filtering

No content-based guardrails (jailbreak detection, PII scanning, harmful content blocking). Security is agent-scoped, not content-scoped. For content safety, layer Lasso Security on top.

### 11.5 No Prompt Management

No prompt versioning, rendering, or library.

### 11.6 Admin Key Permission Gaps

13 endpoints return 403 with our admin key. A higher permission tier exists but isn't documented.

---

## Appendix: Test Results

| Script | Description | PASS | FAIL | TIER |
|--------|-------------|------|------|------|
| 01 | Health | 2 | 0 | 0 |
| 02 | Chat Completions | 8 | 0 | 0 |
| 03 | Agent Profiles | 2 | 0 | 0 |
| 04 | Usage & Budget | 4 | 0 | 1 |
| 05 | Providers & Models | 4 | 0 | 0 |
| 06 | Governance | 7 | 0 | 0 |
| 07 | MCP Server | 2 | 0 | 0 |
| 08 | API Surface Probe | 25 | 0 | 0 |
| **TOTAL** | | **54** | **0** | **1** |
