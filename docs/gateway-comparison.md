# AI Gateway & Security Landscape: 13-Platform Analysis

> Audit date: 2026-03-21 | 4 platforms tested live (218 tests), 9 research-only | 13 autopsy documents

## Platforms by Category

| # | Platform | Category | Architecture | Unique Angle |
|---|----------|----------|-------------|-------------|
| 1 | **Portkey** | Orchestration | Unified API (SaaS) | Most features (prompts, guardrails, 14 endpoints) |
| 2 | **BrainstormRouter** | Orchestration | Intelligent router (SaaS) | Agent-purpose-built (Thompson, per-agent security) |
| 3 | **OpenRouter** | Orchestration | Unified API (SaaS) | Largest marketplace (400+ models, 50+ free) |
| 4 | **LiteLLM** | Orchestration | SDK + Proxy (self-hosted) | Open-source powerhouse (2,600+ models, 4-level RBAC) |
| 5 | **Helicone** | Orchestration + Observability | Rust proxy | Fastest gateway (8ms P50) + eval framework |
| 6 | **Martian** | Intelligent Routing | Per-query router | Interpretable model mapping + compliance |
| 7 | **Not Diamond** | Intelligent Routing | Recommendation API | Only non-proxy (zero inference overhead) |
| 8 | **Kong AI Gateway** | Infrastructure | API gateway + AI plugins | 100k+ deployments, multi-protocol |
| 9 | **Cloudflare AI GW** | Infrastructure | Edge proxy | 300+ city CDN, DLP, visual routing |
| 10 | **Langfuse** | Observability | Async SDK | Deepest evaluation (MIT, PostgreSQL) |
| 11 | **Lasso Security** | AI Security | Gateway/API/SDK | Intent analysis (99.83%, <50ms) |
| 12 | **Cequence** | API Security | UAP platform | Behavioral fingerprinting (10B req/day) |
| 13 | **Wallarm** | Agentic Security | WAF + AI gateway | A2AS standard, model self-defense, 24/7 SOC |

---

## Executive Summary

### Orchestration Gateways (route LLM traffic)

| Dimension | Portkey | BrainstormRouter | OpenRouter | LiteLLM | Helicone |
|-----------|---------|-----------------|------------|---------|----------|
| **Test pass rate** | 75/100 (75%) | 54/55 (98%) | 30/40 (75%) | N/A | N/A |
| **Models** | 250+ / 40 providers | 362 / 7 providers | 400+ / 60 providers | **2,600+ / 140+** | 100+ / 24+ |
| **Architecture** | Unified API (SaaS) | Intelligent router (SaaS) | Unified API (SaaS) | SDK + Proxy (self-hosted) | **Rust proxy (8ms P50)** |
| **Routing** | Config-based (manual) | Thompson sampling | Thompson + variants | 5 strategies | Latency/cost/weighted |
| **Caching** | Simple + semantic | None | Provider-native | Response + prompt | **Semantic (intent-based)** |
| **Guardrails** | **20+ content checks, PII** | Agent-scoped (tool/spawn/SSRF) | Spending limits | LLM Guard, PII regex | Basic (injection, PII) |
| **Prompt management** | **Yes (full suite)** | None | None | None | **Yes (versions, A/B)** |
| **Evaluation** | Limited | None | None | None | **Yes (free, datasets, scoring)** |
| **Observability** | **40+ metrics, traces** | 9 governance endpoints | Broadcast | OTEL, Prometheus | **Native dashboard + MCP** |
| **Agent management** | None | **9 endpoints, per-agent** | None | A2A protocol | None |
| **Multi-tenancy** | Workspaces | Agents + cost centers | Orgs (10 max) | **4-level RBAC** | Teams + vaults |
| **MCP** | Gateway (proxies) | **Server (19 tools)** | Community | Native (`/v1/mcp`) | **Native (query + route)** |
| **Open source** | Gateway only | No | No | **Yes (Apache 2.0)** | **Yes (Apache 2.0)** |
| **Self-hostable** | No | No | No | **Yes ($0)** | **Yes ($0)** |
| **Free tier** | 10k req/mo | None | 50+ free models | Free forever | 10k req/mo |
| **P50 Latency** | ~230ms | Unknown | ~5.5s (auto) | ~150ms | **8ms (Rust)** |
| **Unique strength** | Feature breadth | Agent intelligence | Largest catalog | Most models + self-hosted | **Fastest + obs + eval** |

### Intelligent Routing (model selection)

| Dimension | Martian | Not Diamond |
|-----------|---------|-------------|
| **Architecture** | Per-query router (proxy) | **Recommendation API (non-proxy)** |
| **Routing method** | Model mapping (interpretable) | Neural network (learned) |
| **Inference overhead** | Yes (proxy) | **Zero (not in request path)** |
| **Decision speed** | Real-time | <50ms |
| **Accuracy improvement** | Interpretable per-query | Up to 25% over static |
| **Cost reduction** | Per-query optimization | Up to 10x |
| **Compliance** | **Approval workflows** | None |
| **Interpretability** | **Explains WHY each model chosen** | Black-box neural |
| **Unique strength** | Interpretable + compliance | Zero-overhead recommendations |

### Observability (logging + evaluation)

| Dimension | Helicone | Langfuse |
|-----------|----------|----------|
| **Architecture** | **Proxy (inline, 8ms)** | SDK (async, zero overhead) |
| **Routing** | **Yes** | No |
| **Caching** | **Yes (semantic)** | No |
| **Evaluation depth** | Basic (scoring, datasets) | **Deep (experiments, annotations, statistics)** |
| **Prompt management** | Yes | **Yes (with variables)** |
| **SDK required** | **No** | Yes |
| **License** | Apache 2.0 | **MIT** |
| **Backend** | Distributed (Rust) | **PostgreSQL** |
| **Free tier** | 10k req/mo | **50k events/mo (cloud) or unlimited (self-hosted)** |
| **Unique strength** | Gateway + observability unified | Deepest evaluation framework |

### Infrastructure & Security Layers

| Dimension | Kong AI GW | Cloudflare AI GW | Lasso Security | Cequence | Wallarm |
|-----------|-----------|-----------------|----------------|----------|---------|
| **Test pass rate** | N/A | 16/23 (70%) | N/A | N/A | N/A |
| **Category** | API gateway + AI | Edge proxy | Content security | API security | Agentic AI security |
| **Architecture** | API gateway + plugins | Reverse proxy (edge) | Gateway/API/SDK | UAP platform | WAF + AI Gateway |
| **Caching** | Semantic (plugin) | **Edge (300+ cities)** | None | None | None |
| **Content guardrails** | Prompt guard (plugin) | DLP (PII, financial) | **50+ guardrails, intent (99.83%)** | OWASP LLM Top 10 testing | Prompt Guard + A2AS |
| **Bot/fraud defense** | Rate limiting | Rate limiting | None | **10B req/day behavioral ML** | **Inline ML + bot list** |
| **API discovery** | None | None | Shadow AI discovery | **Continuous, auto-inventory** | **Shadow API detection** |
| **MCP security** | **MCP registry (governance)** | None | Open-source MCP gateway | Trusted MCP registry | **MCP protection + A2A** |
| **Multi-protocol** | **REST, GraphQL, gRPC, WS** | REST only | REST only | REST only | REST, GraphQL, WS |
| **Compliance** | Enterprise (100k deploys) | DLP, unified billing | FedRAMP, DoD, HIPAA | PCI DSS, GDPR, DORA | SOC2 + OWASP co-author |
| **Open source** | **Kong Gateway OSS** | No | MCP gateway | No | **API Firewall (1B+ pulls)** |
| **SOC service** | No | No | No | No | **24/7/365 managed** |
| **Unique strength** | **API→AI bridge (100k deploys)** | Edge performance + DLP | Intent analysis | Scale (10B/day) | A2AS + model self-defense |

---

## Category Comparisons

### 1. Chat Completions

| Feature | Portkey | BR | OpenRouter |
|---------|---------|-----|-----------|
| Non-streaming | PASS (680ms) | PASS (1750ms) | PASS (5885ms auto, 818ms direct) |
| Streaming | PASS | PASS | PASS |
| Tool calling | PASS | Not tested | PASS |
| JSON mode | PASS | Not tested | PASS |
| Multi-turn | PASS | PASS | PASS |
| Temperature/seed | PASS | PASS | PASS |
| Token usage | PASS | PASS | PASS |
| **Verdict** | Fastest, most features tested | Reliable, moderate latency | Slowest auto, fast direct |

### 2. Routing Intelligence

| Feature | Portkey | BR | OpenRouter |
|---------|---------|-----|-----------|
| **Algorithm** | None (config-based) | Thompson sampling | Thompson sampling |
| Auto-select | No | `brainstormrouter/auto` | `openrouter/auto` |
| Free models | No | No | `openrouter/free` (50+ models) |
| Weighted | Yes (config) | Automatic | Automatic |
| Fallback | Yes (ordered config) | Automatic | Yes (`models` array) |
| Canary/A-B | Yes (% split) | No | No |
| Speed variant | No | No | `:nitro` |
| Price variant | No | No | `:floor` |
| Search variant | No | No | `:online` |
| Provider filter | No | No | `only/ignore/zdr` |
| **Verdict** | Most manual control | Best for agents | Most variant options |

### 3. Provider Management

| Feature | Portkey | BR | OpenRouter |
|---------|---------|-----|-----------|
| Model catalog API | Yes | Yes | Yes (richest metadata) |
| Provider credentials | BYOK (virtual keys) | Platform-managed | BYOK (OR account) |
| Per-provider endpoints | No | Yes (`/v1/providers`) | Yes (`/models/:id/endpoints`) |
| ZDR enforcement | No | No | Yes (`zdr: true`) |
| Data collection filter | No | No | Yes (`data_collection: "exclude"`) |
| **Verdict** | Most key management | Simplest (zero config) | Most filtering options |

### 4. Agent & Multi-Tenant

| Feature | Portkey | BR | OpenRouter |
|---------|---------|-----|-----------|
| Agent concept | None | First-class (5 agents) | None |
| Per-agent budgets | Via virtual keys | Native ($X/day, hard cap) | Per-key spending caps |
| Anomaly detection | None | Yes | None |
| Behavioral profiling | None | Yes | None |
| Cost centers | Via metadata | Native | Per-key tracking |
| Lifecycle management | None | Active/inactive | None |
| **Verdict** | Generic | **Purpose-built** | Generic |

### 5. Observability

| Feature | Portkey | BR | OpenRouter |
|---------|---------|-----|-----------|
| Request logging | 40+ auto metrics | Via usage APIs | Via broadcast |
| Custom metadata | `x-portkey-metadata` | No | HTTP-Referer, X-Title |
| Trace IDs | Custom + auto | No | Via broadcast |
| External integrations | Not native | No | Langfuse, Datadog, Sentry |
| Cost forecasting | No | Yes (`/v1/cost-forecast`) | No |
| Daily insights | Via log analysis | Yes (`/v1/insights/daily`) | No |
| Dashboard | Web UI | No (API only) | Web dashboard |
| **Verdict** | Richest native | Best agent insights | Best external integrations |

### 6. Safety & Guardrails

| Feature | Portkey | BR | OpenRouter |
|---------|---------|-----|-----------|
| Content filtering | 20+ checks | None | None |
| PII detection | Enterprise | None | None |
| Model access control | Virtual key limits | `allowed_models` per key | Org guardrails per key |
| Spending limits | Per workspace | Per agent daily | Per key/user daily/weekly/monthly |
| ZDR | No | No | Yes (default) |
| **Verdict** | Most comprehensive | Budget-only | Privacy-focused |

### 7. Plugins & Extensions

| Feature | Portkey | BR | OpenRouter |
|---------|---------|-----|-----------|
| Web search | No | Via MCP tool | `:online` variant + plugin |
| Response healing | No | No | Yes (auto-repair JSON) |
| Context compression | No | No | Yes (middle-out) |
| PDF processing | No | No | Yes (file-parser plugin) |
| **Verdict** | None | MCP tools | **Most plugins** |

### 8. API Surface Size

| Metric | Portkey | BR | OpenRouter |
|--------|---------|-----|-----------|
| Inference endpoints | 14 types | 5 types | 1 type (chat only) |
| Admin endpoints | 36+ resources | 25 discovered | ~5 (key mgmt) |
| SDK methods | 200+ | N/A | Auto-generated |
| MCP tools | N/A | 19 | Community |
| OpenAPI spec | No | No | Yes (13 paths) |
| **Total surface** | ~250 methods | ~50 endpoints | ~20 endpoints |

---

## Decision Matrix: When to Use Which

| Scenario | Best Gateway | Why |
|----------|-------------|-----|
| **Multi-agent system (OpenClaw)** | BrainstormRouter | Per-agent budgets, anomaly detection, behavioral profiling |
| **Broadest LLM access** | OpenRouter | 400+ models, 60+ providers, free tier |
| **Full-featured gateway** | Portkey | Caching, guardrails, prompts, 14 inference types |
| **Zero-config routing** | BR or OpenRouter | Both use Thompson sampling |
| **Privacy-first** | OpenRouter | ZDR by default, provider data collection filter |
| **Content safety** | Portkey | 20+ guardrail checks, PII redaction |
| **Cost optimization** | OpenRouter | `:floor` variant, no markup, 50+ free models |
| **Speed optimization** | OpenRouter | `:nitro` variant sorts by throughput |
| **Enterprise compliance** | Portkey | SOC2, ISO 27001, HIPAA, air-gapped |
| **SDK/TypeScript** | Portkey | 200+ typed methods |
| **Web search integration** | OpenRouter | `:online` variant, native plugin |
| **Bring-your-own keys** | Portkey | Virtual key management, multi-provider |
| **Managed credentials** | BrainstormRouter | Server-side provider management |
| **Embeddings/Images/Audio** | Portkey | Only gateway with non-chat inference |
| **Prompt management** | Portkey | Only gateway with prompt versioning |

---

## Architecture Comparison

```
PORTKEY (Feature-Rich Middleware)
App → SDK (200+ methods) → Gateway → Config Router → Provider [YOUR keys]
     Caching | Guardrails | Prompts | Logs | Virtual Keys

BRAINSTORMROUTER (Agent-Aware Intelligence)
App → REST/MCP → Thompson Sampling → Best Model → Provider [BR keys]
     Agent Budgets | Anomaly Detection | Behavioral Profiling | Governance

OPENROUTER (Transparent Model Marketplace)
App → REST/SDK → Auto/Free Router → Best Provider [OR account]
     Variants (:nitro/:floor/:online) | Plugins | Broadcast | ZDR
```

**Fundamental difference:**
- **Portkey** = Swiss Army knife (most features, most complexity)
- **BrainstormRouter** = Agent specialist (best for multi-agent, least features otherwise)
- **OpenRouter** = Model marketplace (most models, transparent pricing, best routing variants)

---

## Decision Matrix: When to Use Which

| Scenario | Best Gateway | Why |
|----------|-------------|-----|
| **Multi-agent system (OpenClaw)** | BrainstormRouter | Per-agent budgets, anomaly detection, behavioral profiling |
| **Broadest LLM access** | LiteLLM | 2,600+ models, 140+ providers |
| **Zero-config routing** | BR or OpenRouter | Thompson sampling, no config needed |
| **Full control (self-hosted)** | LiteLLM or Helicone | LiteLLM: most models + RBAC; Helicone: fastest + eval |
| **Fastest gateway latency** | Helicone | 8ms P50 (Rust) — 19x faster than Portkey, 29x faster than OpenRouter |
| **Gateway + observability (unified)** | Helicone | Single proxy gives routing + logging + eval + prompt mgmt |
| **LLM evaluation framework** | Helicone | Free evals on all tiers, datasets, scoring, A/B testing |
| **No-SDK integration** | Helicone | Just change base URL — works with any OpenAI client, any language |
| **Full-featured SaaS** | Portkey | Caching, guardrails, prompts, 14 inference types, SDK |
| **Content safety** | Portkey or CF or Lasso | Portkey: 20+ checks; CF: DLP; Lasso: intent-based |
| **Agent security (tool/spawn control)** | BrainstormRouter | Only gateway with per-agent tool allow/deny, spawn restriction, workspace sandbox |
| **Edge performance** | Cloudflare | 300+ cities, sub-100ms cache hits |
| **Cost optimization** | OpenRouter | `:floor` variant, no markup, 50+ free models |
| **Speed optimization** | OpenRouter or LiteLLM | OR: `:nitro` variant; LiteLLM: 150ms P95 |
| **Enterprise compliance** | Portkey | SOC2, ISO 27001, HIPAA, air-gapped |
| **Privacy-first** | OpenRouter | ZDR by default, provider filtering |
| **TypeScript SDK** | Portkey | 200+ typed methods, best DX |
| **Python SDK** | LiteLLM | Native SDK with cost tracking |
| **Web search** | OpenRouter | `:online` variant + plugin |
| **Agent protocol (A2A)** | LiteLLM | LangGraph, Vertex AI, Bedrock |
| **MCP native server** | BrainstormRouter | 19 tools for programmatic mgmt |
| **MCP native client** | LiteLLM | `/v1/mcp` + tool registry |
| **Prompt management** | Portkey | Only gateway with versioning/render |
| **Embeddings/Images/Audio** | Portkey or LiteLLM | Both have full inference types |
| **Managed credentials** | BrainstormRouter | Server-side, zero key mgmt |
| **Unified billing** | Cloudflare | Single invoice for 5 providers |
| **AI security (intent-based)** | Lasso Security | Only behavioral intent analysis, 99.83% accuracy |
| **Jailbreak/injection defense** | Lasso Security | 3,000+ evasion techniques, semantic-layer |
| **Shadow AI discovery** | Lasso Security | Only platform that finds unauthorized AI usage |
| **Federal compliance (FedRAMP)** | Lasso Security | FedRAMP High, DoD SRG, ITAR, CJIS |
| **Red teaming** | Lasso Security | Automated adversarial testing built-in |
| **Security + routing combo** | Lasso + Portkey/BR/LiteLLM | Lasso layers on top of routing gateways |
| **API-level bot/fraud defense** | Cequence | Only platform with behavioral fingerprinting at 10B req/day |
| **API discovery (shadow APIs)** | Cequence | Finds undocumented endpoints across infrastructure |
| **OWASP LLM Top 10 testing** | Cequence | Only automated adversarial testing for LLM apps |
| **MCP server vetting** | Cequence | Trusted MCP registry — vets servers before agent connects |
| **A2A attack detection** | Wallarm | Only platform detecting multi-agent prompt injection chains |
| **Model self-defense** | Wallarm | Embeds security reasoning in model context window |
| **Managed security (SOC)** | Wallarm | Only platform with 24/7 human security operations |
| **Full security stack** | Lasso + Wallarm + Cequence + CF | Content + Agentic + API + Edge |

## Architecture Comparison

```
PORTKEY (Feature-Rich SaaS)
App → SDK (200+ methods) → Gateway → Config Router → Provider [YOUR keys]
     Caching | Guardrails | Prompts | Logs | Virtual Keys

BRAINSTORMROUTER (Agent-Aware SaaS)
App → REST/MCP → Thompson Sampling → Best Model → Provider [BR keys]
     Agent Budgets | Anomaly Detection | Behavioral Profiling | Governance
     Tool Allow/Deny | Spawn Control | SSRF Guards | Session Isolation
     Command Blocking | Workspace Sandbox | 3-Tier Auth (Scoped/Admin/JWT)

OPENROUTER (Transparent Marketplace)
App → REST/SDK → Auto/Free Router → Best Provider [OR account]
     Variants (:nitro/:floor/:online) | Plugins | Broadcast | ZDR

CLOUDFLARE AI GATEWAY (Edge Proxy)
App → CF Edge (300+ cities) → Proxy → Provider [YOUR keys / BYOK / Unified Billing]
     Edge Caching | DLP | Guardrails | Dynamic Routing | Logpush

LITELLM (Open-Source Self-Hosted)
App → Python SDK or Proxy (:4000) → 5 Routing Strategies → Provider [YOUR keys]
     4-Level RBAC | MCP | A2A | Cost Tracking | Prometheus | Admin UI
     PostgreSQL + Redis | Docker/K8s | $0 License

HELICONE (Rust Gateway + Observability)
App → Helicone Proxy (Rust, 8ms P50) → Latency/Cost Routing → Provider [YOUR keys]
     Semantic Caching | Prompt Mgmt | Eval Framework | MCP Server
     Native Dashboard | Vaults (AEAD encryption) | Apache 2.0 | $0 Free Tier

LASSO SECURITY (AI-Native Content Security)
App → Lasso Gateway/API/SDK → Intent Analysis (<50ms) → Provider
     ↕ Can layer on top of ANY gateway above
     Intent Deputy (behavioral fingerprinting, 99.83% accuracy)
     50+ Guardrails | PII Masking | 3,000+ Evasion Decoders
     Shadow AI Discovery | Red Teaming | FedRAMP/DoD

CEQUENCE (API Infrastructure Security)
[Any Gateway API] → Cequence UAP → Behavioral Fingerprinting → Allow/Block
     10B+ req/day | Bot/Fraud Detection | API Discovery
     OWASP LLM Top 10 Testing | Trusted MCP Registry
     Compliance Auto-Mapping (PCI DSS, GDPR, DORA, SOC2)

WALLARM (API + Agentic AI Security)
[Any API/Agent] → Wallarm (inline proxy/sidecar) → ML Analysis → Allow/Block
     A2AS Standard (AWS/Google/Meta/JPMorgan) | A2A Attack Detection
     Model Self-Defense Reasoning | MCP Server Protection
     Request-Sequence ML | 24/7 SOC-as-a-Service | Open-Source API Firewall
```

### Full Stack Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  APPLICATION:  Your Code / OpenClaw Agents                       │
├─────────────────────────────────────────────────────────────────┤
│  ROUTING INTELLIGENCE: Martian (interpretable) / Not Diamond     │
│    Per-query model selection, accuracy optimization              │
├─────────────────────────────────────────────────────────────────┤
│  ORCHESTRATION: Portkey / BR / OpenRouter / LiteLLM / Helicone   │
│    Gateway proxy, cost tracking, caching, agent budgets          │
├─────────────────────────────────────────────────────────────────┤
│  OBSERVABILITY: Helicone (inline) / Langfuse (async)             │
│    Traces, evals, prompt mgmt, cost analytics                    │
├─────────────────────────────────────────────────────────────────┤
│  CONTENT SECURITY: Lasso Security                                │
│    Intent analysis, jailbreak, PII masking                       │
├─────────────────────────────────────────────────────────────────┤
│  AGENTIC SECURITY: Wallarm                                       │
│    A2A attack detection, model self-defense, MCP protection      │
├─────────────────────────────────────────────────────────────────┤
│  API INFRASTRUCTURE: Kong / Cloudflare / Cequence                │
│    API management, edge caching, DLP, bot defense, discovery     │
├─────────────────────────────────────────────────────────────────┤
│  PROVIDERS: OpenAI / Anthropic / Google / DeepSeek / etc.        │
└─────────────────────────────────────────────────────────────────┘
```

## Test Results Summary

| Platform | Tests | Pass | Fail | Tier | Rate |
|----------|-------|------|------|------|------|
| **Portkey** | 100 | 75 | 25 | 0 | 75% |
| **BrainstormRouter** | 55 | 54 | 0 | 1 | 98% |
| **OpenRouter** | 40 | 30 | 10 | 0 | 75% |
| **Cloudflare AI GW** | 23 | 16 | 5 | 2 | 70% |
| **LiteLLM** | — | — | — | — | Research only |
| **Lasso Security** | — | — | — | — | Research only (enterprise) |
| **Cequence** | — | — | — | — | Research only (enterprise) |
| **Helicone** | — | — | — | — | Research only |
| **Martian** | — | — | — | — | Research only |
| **Not Diamond** | — | — | — | — | Research only |
| **Kong AI GW** | — | — | — | — | Research only |
| **Langfuse** | — | — | — | — | Research only |
| **Wallarm** | — | — | — | — | Research only |
| **TOTAL (tested)** | **218** | **175** | **40** | **3** | **80%** |

---

*Generated by openclaw autopsy framework — 2026-03-21*
*13 autopsy documents: portkey | brainstormrouter | openrouter | cloudflare-ai | litellm | helicone | martian | notdiamond | kong | langfuse | lasso | cequence | wallarm*
