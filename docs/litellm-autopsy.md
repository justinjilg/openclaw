# LiteLLM — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **Version** | v1.80.18+ (latest stable) |
| **License** | Apache 2.0 (fully open-source) |
| **GitHub** | `github.com/BerriAI/litellm` |
| **Modes** | Python SDK (library) + Proxy Server (standalone gateway) |
| **Tests Run** | 0 (research-only — requires Docker + PostgreSQL to run proxy) |
| **Models** | 2,600+ across 140+ providers |
| **Pricing** | $0 self-hosted / $2,500/month enterprise |

---

## 1. Platform Overview

### 1.1 What It Is

LiteLLM is an **open-source, dual-mode LLM gateway** that operates as both a Python library (direct SDK calls) and a standalone proxy server (OpenAI-compatible REST API). It's the most feature-dense gateway in this comparison and the only one that's fully self-hostable for free.

### 1.2 Architecture

**Mode 1: Python SDK (Direct Library)**
```
Your Python Code → litellm.completion() → Provider API
                         ↓
                   Routing / Retry / Cost Tracking
```

**Mode 2: Proxy Server (Standalone Gateway)**
```
Any Client → LiteLLM Proxy (:4000) → Provider API
                  ↓
            PostgreSQL (keys, teams, budgets)
            Redis (rate limits, routing state)
            Admin Dashboard (/ui)
            Observability (OTEL, Langfuse, etc.)
```

### 1.3 Performance

| Metric | 4-Instance | 2-Instance |
|--------|-----------|-----------|
| P95 Latency | 150ms | 630ms |
| P99 Latency | 240ms | — |
| Throughput | ~1,170 RPS | ~1,036 RPS |
| Infrastructure | 4-8 CPU, 16GB RAM | 2-4 CPU, 8GB RAM |

**150ms P95 beats Portkey's observed 230ms** at comparable throughput.

### 1.4 Pricing

| Tier | Cost | Includes |
|------|------|---------|
| **Self-hosted** | $0 + infra ($300-700/mo) | Full source code, all features except SSO/SAML |
| **Professional support** | $250/month | Priority support |
| **Enterprise** | $2,500/month ($30k/year) | SSO/SAML, audit logs, advanced RBAC, cloud or self-hosted |

**Total estimated TCO:** $300-700/month (self-support) or $2,280-2,680/month (professional).

---

## 2. Provider & Model Coverage

### 2.1 Scale

- **2,600+ models** catalogued with pricing, context windows, feature flags
- **140+ providers** supported
- **Largest model catalog** of any gateway in this comparison (vs Portkey's 250+, OR's 400+, BR's 362)

### 2.2 Provider Categories

| Category | Providers |
|----------|----------|
| **Cloud** | OpenAI, Azure OpenAI, Google (Vertex AI, AI Studio, Gemini), AWS (Bedrock, SageMaker) |
| **Specialized** | Anthropic, Mistral AI, Cohere, Together AI, Groq, Perplexity AI, DeepSeek, xAI, Fireworks AI |
| **Open-Source Infra** | Ollama, vLLM, LM Studio, Llamafile, HuggingFace |
| **Regional** | Moonshot (Kimi), Hyperbolic, Nscale, ModelsLab |

### 2.3 Model Types

| Type | SDK Method | Proxy Endpoint |
|------|-----------|---------------|
| Chat completions | `completion()` | `/v1/chat/completions` |
| Text completions | `completion()` | `/v1/completions` |
| Embeddings | `embedding()` | `/v1/embeddings` |
| Image generation | `image_generation()` | `/v1/images/generations` |
| Audio transcription | — | `/v1/audio/transcriptions` |
| Text-to-speech | — | `/v1/audio/speech` |
| Reranking | — | `/v1/rerank` |
| Batch processing | `batch.create_batch()` | `/v1/batches` |
| Moderation | — | `/v1/moderations` |
| OCR | — | — |
| Fine-tuning | — | — |
| Real-time (WebRTC) | — | — |

---

## 3. REST API (Proxy Server)

### 3.1 Inference Endpoints (OpenAI-Compatible)

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/chat/completions` | Chat completions (streaming + non-streaming) |
| `POST /v1/completions` | Text completions |
| `POST /v1/embeddings` | Dense embeddings |
| `POST /v1/images/generations` | Image generation |
| `POST /v1/audio/transcriptions` | Audio transcription |
| `POST /v1/audio/speech` | Text-to-speech |
| `POST /v1/rerank` | Reranking |
| `POST /v1/batches` | Batch processing |
| `GET /v1/models` | List available models |
| `POST /v1/messages` | Native Anthropic message format |

### 3.2 Agent & MCP Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/a2a` | Agent-to-Agent protocol (LangGraph, Vertex AI, Bedrock, Pydantic AI) |
| `POST /v1/mcp` | MCP tool integration |
| `GET /v1/mcp/registry.json` | MCP tool registry |

### 3.3 Virtual Key Management

| Endpoint | Purpose |
|----------|---------|
| `POST /key/generate` | Create virtual API key (with budget/rate limits) |
| `POST /key/update` | Update key settings |
| `GET /key/info` | Get key metadata |
| `GET /key/list` | List all keys (admin) |
| `POST /key/delete` | Revoke key |

### 3.4 User & Team Management

| Endpoint | Purpose |
|----------|---------|
| `POST /user/new` | Create user with rate limits/budget |
| `GET /user/info` | Get user metadata |
| `POST /team/new` | Create team |
| `POST /team/member_add` | Add member with role |
| `POST /team/update` | Update team settings |

### 3.5 Model Management

| Endpoint | Purpose |
|----------|---------|
| `POST /model/new` | Add model (no restart needed) |
| `GET /model/info` | Get model info (costs, context, features) |
| `POST /model/delete` | Remove model |

### 3.6 Observability

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Health check |
| `GET /metrics` | Prometheus-compatible metrics |
| `GET /spend/report` | Aggregate cost analytics |

### 3.7 Pass-Through

Configurable routes to external APIs with custom headers and pricing:
```yaml
pass_through_endpoints:
  - path: "/bria"
    target_url: "https://api.bria.ai/v1"
    headers:
      - key: "Authorization"
        value: "Bearer ${BRIA_API_KEY}"
    pricing:
      cost_per_request: 0.05
```

---

## 4. Python SDK

### 4.1 Core Methods

```python
# Chat completions (supports all providers)
litellm.completion(model="openai/gpt-4o", messages=[...], **params)

# Streaming
litellm.completion(..., stream=True)

# Embeddings
litellm.embedding(model="openai/text-embedding-3-small", input="text")

# Image generation
litellm.image_generation(model="openai/dall-e-3", prompt="...", n=1, size="1024x1024")

# Cost calculation
litellm.completion_cost(response)  # Returns USD

# Router (load balancing)
router = Router(model_list=[...], routing_strategy="cost-based")
router.completion(model="gpt-4", messages=[...])
```

### 4.2 Key Parameters

| Parameter | Description |
|-----------|-------------|
| `model` | Provider/model string (e.g., `openai/gpt-4o`) |
| `messages` | OpenAI-format message array |
| `temperature`, `top_p`, `max_tokens` | Standard sampling params |
| `stream` | Enable SSE streaming |
| `tools` | Function/tool calling definitions |
| `response_format` | JSON mode / structured output |
| `num_retries` | Retry count |
| `fallbacks` | Fallback model list |
| `metadata` | Custom tracking metadata |
| `drop_params` | Drop unsupported params silently |
| `seed` | Deterministic output |

---

## 5. Routing & Load Balancing

### 5.1 Strategies

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| **Simple-Shuffle** (default) | Random selection weighted by RPM/TPM limits | General purpose |
| **Usage-Based** | Routes to lowest TPM deployment (Redis-backed) | Even distribution |
| **Latency-Based** | Selects fastest-responding deployment | Speed-critical |
| **Cost-Based** | Chooses cheapest deployment | Cost optimization |
| **Least-Busy** | Routes to fewest concurrent requests | Load balancing |

### 5.2 Reliability

| Feature | Details |
|---------|---------|
| **Fallbacks** | Context window, model group, API key/base, content policy |
| **Retries** | Exponential backoff with jitter, 45s timeout window |
| **Cooldowns** | 60s cooldown for rate-limited models |
| **Priority** | Ordering-based or weighted selection |

### 5.3 Error-Specific Retries

| Error | Default Retries |
|-------|----------------|
| AuthenticationError | 0 |
| TimeoutError | 2 |
| RateLimitError | 3 |
| ContentPolicyViolation | 0 |
| InternalServerError | 2 |

---

## 6. Multi-Tenancy & RBAC

### 6.1 Hierarchy (4 Levels)

```
Organization (Enterprise)
  └─ Team
       └─ User
            └─ API Key
```

### 6.2 Roles

| Scope | Roles |
|-------|-------|
| **Global** | `proxy_admin`, `proxy_admin_viewer` |
| **Org/Team** (Premium) | `org_admin`, `team_admin`, `team_member`, `internal_user`, `internal_user_viewer` |

### 6.3 Key Types

1. **User-only keys** — individual developer, tracked to user
2. **Team service account keys** — production use, persists across staffing
3. **User + Team keys** — individual accountability within team

### 6.4 Team Member Permissions (Premium)

Each permission independently toggleable: `/key/generate`, `/key/delete`, `/key/update`, `/key/list` — all scoped to their team.

---

## 7. Cost Tracking & Budgets

### 7.1 Cost Tracking

| Input Type | How Tracked |
|-----------|-------------|
| Per-token (input/output) | Standard |
| Per-reasoning-token | o1/o3 models |
| Per-image | Vision/generation |
| Per-second | SageMaker |
| Per-request | Custom APIs |

### 7.2 Budget Levels

| Level | Endpoint | Features |
|-------|----------|----------|
| **Global** | `litellm.max_budget` | Hard limit for entire proxy |
| **Organization** | — | Cascading limits |
| **Team** | `/team/new` | Daily + monthly budgets |
| **User** | `/user/new` | Daily + monthly budgets, reset frequency |
| **API Key** | `/key/generate` | Per-key spending limit |
| **Custom Tag** | `metadata.cost_center` | Aggregate by tag |

### 7.3 Analytics

- `/spend/report` endpoint for CSV export
- Per-user/team/model/provider breakdown
- Cloud storage integration for ETL

---

## 8. Caching

### 8.1 Response Caching
- Semantic matching of identical requests
- Configurable TTL
- Redis or in-memory backend

### 8.2 Prompt Caching

| Provider | Method |
|----------|--------|
| OpenAI | Automatic (1024+ tokens) |
| Anthropic | `cache_control` injection points |
| Bedrock Claude | Same as Anthropic |
| DeepSeek | Automatic |
| Gemini | Automatic |

Config:
```yaml
model_info:
  cache_control_injection_points: ["prompt"]
```

Up to **90% cost savings** on repeated long prompts.

---

## 9. MCP Integration

| Feature | Details |
|---------|---------|
| **Endpoint** | `/v1/mcp` |
| **Registry** | `/v1/mcp/registry.json` |
| **Tool namespacing** | `mcp__<server>__<tool_name>` |
| **Protocol version** | 2025-11-25 |
| **Execution control** | `execute_tool()` method |
| **Security** | Per-server access control, token tracking |

LiteLLM transforms MCP tools to OpenAI-compatible format and routes to any LLM.

---

## 10. Agent-to-Agent (A2A) Protocol

Unified interface for invoking agents from multiple platforms:

| Platform | Support |
|----------|---------|
| LangGraph | OpenAI-compatible endpoint |
| Vertex AI Agent Engine | Native API translation |
| AWS Bedrock AgentCore | Native API translation |
| Azure AI Foundry | Native API translation |
| Pydantic AI | Framework integration |

Cost tracking and token usage automatically captured per agent invocation.

---

## 11. Guardrails & Security

### 11.1 Content Safety

| Provider | Type |
|----------|------|
| LLM Guard | Open-source guardrails |
| LlamaGuard | Meta's moderation model |
| Google Text Moderation | Google Cloud |
| Custom | User-defined logic |

### 11.2 Data Protection

- Secret detection and regex-based PII redaction
- IP-based ACLs (allow/deny)
- Blocked user lists, banned keywords
- Per-key/per-request guardrail config
- Model allow/deny lists per team/user

### 11.3 Authentication

| Method | Details |
|--------|---------|
| Master Key | X-Admin-Key header (legacy) |
| JWT | HTTP-only cookies, session-based, RBAC |
| SSO/SAML (Enterprise) | Okta, Google, Azure AD, custom OIDC |
| Custom hooks | User-defined validation |

### 11.4 Secret Management

AWS Secrets Manager, Google Secret Manager, Azure Key Vault, HashiCorp Vault.

---

## 12. Observability

### 12.1 Integrations

| Platform | Method |
|----------|--------|
| **Langfuse** | Native + OpenTelemetry |
| **Helicone** | OSS observability |
| **OpenTelemetry** | Jaeger, Zipkin, Datadog, New Relic, Traceloop |
| **MLflow** | Experiment tracking |
| **Lunary** | LLM monitoring |
| **Prometheus** | `/metrics` endpoint |
| **Custom** | `CustomLogger` class inheritance |

### 12.2 What's Tracked

Tokens (input, output, cache read, cache creation), latency (e2e, TTFT), cost (USD), model/provider, API key/user/team, error details, custom metadata.

---

## 13. Admin Dashboard

| Feature | Details |
|---------|---------|
| **URL** | `http://<proxy>:4000/ui` |
| **Stack** | React/Next.js |
| **Auth** | JWT-based with role restrictions |
| **Capabilities** | Model CRUD, key management, team/user management, usage analytics, rate limit config, audit logs |

---

## 14. Deployment Options

| Method | Complexity | Best For |
|--------|-----------|----------|
| **Local** | Lowest | Development/testing |
| **Docker** | Low | Small deployments |
| **Docker Compose** | Medium | Proxy + PostgreSQL + Redis |
| **Kubernetes** | High | Production HA |
| **Cloud instances** | Medium | AWS/GCP/Azure |
| **Enterprise cloud** | Lowest | Managed SaaS |

### Minimum Production Stack

```yaml
services:
  litellm:
    image: ghcr.io/berriai/litellm:main-latest
    ports: ["4000:4000"]
    environment:
      DATABASE_URL: postgresql://...
      REDIS_HOST: redis
      LITELLM_MASTER_KEY: sk-...
    volumes:
      - ./config.yaml:/app/config.yaml
  postgres:
    image: postgres:16
  redis:
    image: redis:7
```

---

## 15. Limitations & Gaps

### 15.1 Requires Self-Hosting
Unlike Portkey/OpenRouter/CF (SaaS), LiteLLM requires DevOps expertise. You manage PostgreSQL, Redis, Docker/K8s, scaling, upgrades, and security patches.

### 15.2 No Thompson Sampling
Routing is strategy-based (shuffle, cost, latency, usage, least-busy) but does NOT learn over time like BR's or OR's Thompson sampling.

### 15.3 No Edge Caching
Response caching is at the proxy level only. No global edge network like CF's 300+ city CDN.

### 15.4 No Built-in DLP
PII redaction exists but no comprehensive DLP like CF (financial, healthcare, government ID scanning).

### 15.5 No Prompt Management
No prompt versioning, rendering, or library (Portkey is the only one with this).

### 15.6 Enterprise Features Gated
SSO/SAML, advanced RBAC, audit logs require $2,500/month enterprise license.

### 15.7 Python-First
SDK is Python-only. No official Node.js/TypeScript SDK (proxy is language-agnostic via REST, but SDK features like `completion_cost()` aren't available in JS).

### 15.8 No Free Tier Models
Unlike OpenRouter's 50+ free models, LiteLLM doesn't provide model access — you bring all provider keys.

---

## 16. What Makes LiteLLM Unique

1. **Open-source** — Only fully self-hostable gateway (Apache 2.0, $0)
2. **Dual-mode** — SDK for Python apps + proxy server for any language
3. **Most models** — 2,600+ models, 140+ providers (largest catalog)
4. **4-level RBAC** — Org → Team → User → Key hierarchy (deepest multi-tenancy)
5. **A2A protocol** — Agent-to-Agent support (LangGraph, Vertex AI, Bedrock)
6. **MCP native** — Built-in MCP integration with tool registry
7. **5 routing strategies** — More routing options than any competitor
8. **Best latency** — 150ms P95 beats Portkey (230ms) and all others
9. **Secret manager integration** — AWS/GCP/Azure/Vault (no other gateway does this)
10. **Admin dashboard** — Built-in React UI (only LiteLLM and Portkey have this)

---

## Appendix A: SDK Method Summary

| Category | Methods |
|----------|---------|
| **Completions** | `completion()`, `acompletion()` (async) |
| **Embeddings** | `embedding()`, `aembedding()` |
| **Images** | `image_generation()` |
| **Batch** | `batch.create_batch()` |
| **Cost** | `completion_cost()`, `token_counter()` |
| **Router** | `Router()`, `router.completion()`, `router.embedding()` |
| **Budget** | `BudgetManager()` |
| **Cache** | `Cache()`, `cache.get()`, `cache.set()` |

## Appendix B: Proxy Endpoint Summary

| Category | Count | Endpoints |
|----------|-------|-----------|
| Inference | 10 | `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/images/generations`, `/v1/audio/*`, `/v1/rerank`, `/v1/batches`, `/v1/models`, `/v1/messages` |
| Agent/MCP | 3 | `/v1/a2a`, `/v1/mcp`, `/v1/mcp/registry.json` |
| Key mgmt | 5 | `/key/generate`, `/key/update`, `/key/info`, `/key/list`, `/key/delete` |
| User mgmt | 2 | `/user/new`, `/user/info` |
| Team mgmt | 3 | `/team/new`, `/team/member_add`, `/team/update` |
| Model mgmt | 3 | `/model/new`, `/model/info`, `/model/delete` |
| Observability | 3 | `/health`, `/metrics`, `/spend/report` |
| **Total** | **~29** | Plus pass-through endpoints |

## Appendix C: Configuration Reference (config.yaml)

```yaml
model_list:
  - model_name: "gpt-4"
    litellm_params:
      model: "openai/gpt-4o"
      api_key: "sk-..."
    model_info:
      input_cost_per_token: 0.00003
      output_cost_per_token: 0.00006

litellm_settings:
  database_url: "postgresql://..."
  master_key: "sk-..."
  max_budget: 100.0
  cache: true
  cache_params:
    type: "redis"
    host: "redis"
    port: 6379

router_settings:
  routing_strategy: "cost-based"
  cooldown_period: 60
  num_retries: 3

general_settings:
  enable_jwt_auth: true
  enforce_user_param: true
```
