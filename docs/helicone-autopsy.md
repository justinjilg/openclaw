# Helicone — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **Gateway URL** | `https://gateway.helicone.ai` (cloud) / `localhost:8080` (self-hosted) |
| **Category** | LLM Gateway + Observability (unified) |
| **License** | Apache 2.0 (fully open-source) |
| **GitHub** | `github.com/Helicone/helicone` |
| **Tests Run** | 0 (research-only) |
| **Providers** | 24+ providers, 100+ models |
| **Performance** | 8ms P50 latency (Rust-based) |
| **Pricing** | Free (10k req/mo) → $20/seat/mo (Pro) → Custom (Enterprise) |

---

## 1. Platform Overview

### 1.1 What It Is

Helicone is a **unified gateway + observability platform** — not just logging, not just routing, but both integrated into a single Rust-based proxy. You point your OpenAI SDK at `gateway.helicone.ai` instead of `api.openai.com` and get routing, caching, rate limiting, observability, prompt management, and evaluation out of the box.

**Key differentiator:** Written entirely in **Rust** — 8ms P50 gateway latency (vs ~20ms Python gateways, ~230ms Portkey observed).

### 1.2 Architecture

```
App → Helicone Gateway (Rust, 8ms P50) → Provider API
          ↓
     Semantic Caching (Redis, 7-day TTL)
     Provider Routing (latency/cost/weighted)
     Rate Limiting (request/cost/token dimensions)
     Prompt Injection Detection (Prompt Guard + Llama Guard)
     Observability (real-time dashboard)
     Prompt Management (versions, A/B testing)
     Evaluation Framework (datasets, scoring)
     MCP Server (query + route from AI tools)
```

### 1.3 Pricing

| Tier | Cost | Requests | Retention | Key Features |
|------|------|----------|-----------|-------------|
| **Free** | $0 | 10k/month | 1 month | Gateway + observability + evals |
| **Pro** | $20/seat/month | Unlimited | 3 months | Advanced routing, caching, rate limits |
| **Team** | Custom | Unlimited | 6 months | Collaboration, shared vaults |
| **Enterprise** | Custom | Unlimited | Forever | SSO, custom SLA, dedicated support |

**0% markup on provider costs.** You pay providers directly + Helicone subscription.

---

## 2. Integration Methods

| Method | Description | SDK Required? |
|--------|-------------|---------------|
| **Proxy (primary)** | Change base URL to `gateway.helicone.ai` + add `Helicone-Auth` header | No |
| **OpenAI SDK** | Point any OpenAI SDK at Helicone endpoint | Existing SDK only |
| **Async logging** | `@helicone/async` for non-proxy logging | Yes (Node.js) |
| **Webhooks** | Callbacks on request completion | No |
| **Manual logger** | `HeliconeLogBuilder` for streaming | Yes |
| **MCP Server** | Query observability + route from AI tools | MCP client |

**No SDK lock-in** — proxy approach works with any language, any OpenAI-compatible client.

---

## 3. Gateway Features

### 3.1 Provider Routing

| Strategy | Algorithm | Description |
|----------|-----------|-------------|
| **Latency-based** | P2C + PeakEWMA | Routes to fastest provider in real-time |
| **Cost-based** | Cheapest first | Route to cheapest provider meeting quality thresholds |
| **Weighted** | Custom distribution | Split traffic by percentages |
| **Fallback sequences** | Ordered list | `"gpt-4o/openai,claude-sonnet-4/anthropic,gemini-2.5-flash/google"` |

Auto-failover: switches provider when error rate exceeds 10% or rate limits hit.

### 3.2 Semantic Caching

| Feature | Value |
|---------|-------|
| **Type** | Intent-based matching (not exact input) |
| **Default TTL** | 7 days (configurable via `max-age`) |
| **Cost reduction** | Up to 95% |
| **Backend** | Redis |
| **Header** | `Helicone-Cache-Enabled: true` |

### 3.3 Rate Limiting

| Dimension | Description |
|-----------|-------------|
| **Request count** | X requests per time window (min 60 seconds) |
| **Cost-based** | Limit by dollars spent, not just request count |
| **Token-based** | Limit by token consumption |
| **Granularity** | Per-user, per-team, per-custom-property |

### 3.4 Retry & Failover

- Automatic retry on 429, 500, 503 with exponential backoff
- Header: `Helicone-Retry-Enabled: true`
- Provider failover on >10% error rate
- Custom fallback sequences with retry count and backoff factor

### 3.5 Security

| Feature | Implementation |
|---------|---------------|
| Prompt injection | Meta Prompt Guard + Llama Guard (two-tier) |
| PII detection | Automated sensitive data identification |
| Content filtering | Safety checks before reaching users |
| Rate limiting as DDoS | Global, per-team, per-user levels |

---

## 4. Observability

### 4.1 Request Logging

- Full request/response logging with metadata
- Session tracking and user management
- Token-level cost tracking (exact per model)
- Real-time agent trace visualization
- Multi-step LLM interaction tracing
- Custom properties for arbitrary tagging

### 4.2 Analytics Dashboard

| Metric | Tracked |
|--------|---------|
| Cost | Per-model, per-user, per-project, trends |
| Latency | P50, P95, P99, time-series |
| Throughput | Request volume per model/user/project |
| Errors | Rate, type breakdown, alerting |
| Tokens | Input, output, cached |

### 4.3 Alerting

Configurable alerts (e.g., Slack on budget threshold, error rate spike).

---

## 5. Prompt Management

| Feature | Details |
|---------|---------|
| **Version control** | Automatic versioning on every change |
| **Deployment** | Deploy new versions through gateway without code changes |
| **A/B testing** | Run experiments using real-time production data |
| **Regression detection** | Prevent prompt quality degradation |

---

## 6. Evaluation Framework

| Feature | Details |
|---------|---------|
| **Datasets** | Capture and organize rated example datasets |
| **Eval runs** | Free for all tiers (even free tier) |
| **Custom evals** | RAGAS, LangSmith, or custom frameworks |
| **Benchmarking** | Compare experiments without pre-existing baselines |
| **User feedback** | Binary (positive/negative) or custom scoring |
| **Export** | CSV/JSON for external analysis |

---

## 7. Key Management (Vaults)

| Feature | Details |
|---------|---------|
| **Encryption** | Advanced AEAD, transparent column-level |
| **Proxy keys** | One-way hashed, non-reversible |
| **Multi-key mapping** | Multiple proxy keys → single provider key |
| **Use cases** | Department isolation, per-client proxies, temporary access |
| **BYOK** | Bring-your-own-keys supported |

---

## 8. MCP Integration

**Official Helicone MCP Server** (`@helicone/mcp` on npm):

| Capability | Description |
|-----------|-------------|
| Query observability | Search logs, filter by model/provider/status/cost/latency |
| Route through gateway | Make LLM requests through Helicone from MCP clients |
| Debug errors | Investigate issues without leaving AI assistant |
| Pagination | Handle large result sets |

Works with Claude Desktop, Cursor, and any MCP-compatible client.

---

## 9. Compliance

| Standard | Status |
|----------|--------|
| SOC 2 Type II | Certified |
| HIPAA | Compliant |
| GDPR | Aligned |
| End-to-end encryption | Yes |
| PII detection/masking | Yes |
| Self-hosted option | Yes (data stays on your infra) |

---

## 10. Supported Providers (24+)

OpenAI, Anthropic, Google Vertex AI/Gemini, Azure OpenAI, Groq, Mistral, DeepSeek, Together AI, Anyscale, OpenRouter, LiteLLM, Moonshot, Perplexity, Cohere, Hugging Face, + custom domains.

---

## 11. Deployment

| Method | Details |
|--------|---------|
| **Cloud SaaS** | `gateway.helicone.ai` — zero setup |
| **Docker** | Single binary (Rust) |
| **Docker Compose** | Gateway + Redis + dashboard |
| **Kubernetes** | Helm charts |
| **Bare metal** | Single binary deployment |

---

## 12. Limitations

### 12.1 No Thompson Sampling
Routing is latency/cost/weighted — does not learn over time like BR or OpenRouter's auto model.

### 12.2 No Agent Management
Designed for teams managing shared infrastructure, not autonomous agents. No per-agent budgets, anomaly detection, or behavioral profiling.

### 12.3 No Deep Guardrails
Basic prompt injection + PII detection. No intent analysis (Lasso), no DLP (CF/Cequence), no 50+ checks (Portkey).

### 12.4 No A2A/Agentic Security
No multi-agent attack detection, no MCP server vetting, no agent behavioral certificates.

### 12.5 Basic Multi-Tenancy
Team/org features exist but no 4-level hierarchy like LiteLLM (Org→Team→User→Key).

---

## 13. What Makes Helicone Unique

1. **Rust performance** — 8ms P50 latency, fastest gateway measured (85% less memory than Python)
2. **Gateway + observability unified** — not two products stitched together
3. **Semantic caching** — intent-based, not exact-match (up to 95% cost reduction)
4. **Open source** — Apache 2.0, full self-hosting, no vendor lock-in
5. **No SDK required** — just change base URL (lowest integration friction)
6. **Native MCP** — query observability + route from AI tools
7. **Evaluation framework** — free for all tiers, dataset management, benchmarking
8. **Prompt management** — version control + A/B testing + regression detection
9. **$0 free tier** — 10k requests/month, no credit card
10. **0% markup** — pay providers directly

---

## 14. Positioning in 9-Platform Landscape

| Layer | Products | Helicone Fit |
|-------|----------|-------------|
| **LLM Orchestration** | Portkey, BR, OpenRouter, LiteLLM, **Helicone** | **Yes — gateway + observability** |
| **Infrastructure Proxy** | Cloudflare AI GW | Overlaps (both proxy, but Helicone adds observability) |
| **Content Security** | Lasso | No (basic security only) |
| **API Security** | Cequence, Wallarm | No |

### Head-to-Head: Helicone vs Portkey vs LiteLLM

| Feature | Helicone | Portkey | LiteLLM |
|---------|----------|---------|---------|
| **Architecture** | Rust proxy | SaaS gateway | Python SDK + proxy |
| **P50 Latency** | **8ms** | ~230ms | ~150ms (4-inst) |
| **Open source** | **Yes (Apache 2.0)** | No | **Yes (Apache 2.0)** |
| **Self-hosted** | **Yes** | No | **Yes** |
| **Models** | 100+ | 250+ | **2,600+** |
| **Semantic caching** | **Yes** | Enterprise only | Response caching |
| **Prompt management** | **Yes** | **Yes** | No |
| **Evaluation** | **Yes (free)** | Limited | No |
| **MCP** | **Yes (native)** | Gateway | **Yes (native)** |
| **Guardrails** | Basic (PII, injection) | **20+ checks** | LLM Guard |
| **Agent management** | No | No | A2A protocol |
| **Multi-tenancy** | Basic teams | Workspaces | **4-level RBAC** |
| **SDK required** | **No (proxy only)** | Yes (for full features) | Yes (Python) |
| **Free tier** | 10k req/mo | 10k req/mo | **Free forever** |
| **Compliance** | SOC 2, HIPAA | SOC 2, ISO 27001, HIPAA | Secret managers |
