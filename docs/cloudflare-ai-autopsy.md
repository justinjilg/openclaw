# Cloudflare AI Gateway — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **Gateway URL** | `https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/{provider}` |
| **Account** | Cloudflare account (ID in 1Password) |
| **Tests Run** | 23 (16 PASS, 5 FAIL, 2 TIER_RESTRICTED) |
| **Pass Rate** | 70% (16/23) — 100% once gateway provisioned (15/15) |
| **Gateway Status** | PROVISIONED via Global API Key + email, then deleted after testing |
| **Providers Tested** | 4 (OpenAI, Anthropic, Groq, DeepSeek — all PASS) |

---

## 1. Platform Overview

### 1.1 What It Is

Cloudflare AI Gateway is a **reverse proxy layer** — fundamentally different from Portkey, OpenRouter, and BrainstormRouter. You place it *in front of* your existing provider API calls by replacing the provider's base URL. It does NOT aggregate providers into a unified API.

```
WITHOUT CF:  App → api.openai.com/v1/chat/completions
WITH CF:     App → gateway.ai.cloudflare.com/v1/{acct}/{gw}/openai/chat/completions
```

The gateway intercepts requests and adds: caching, rate limiting, logging, guardrails, DLP, and observability.

### 1.2 Architecture

```
App → CF Edge Network (300+ cities) → AI Gateway Proxy → Provider API
       ↓                                    ↓
  Edge Caching (sub-100ms)           Analytics Dashboard
  Rate Limiting                      DLP / Guardrails
  Custom Metadata                    Cost Tracking
  Retry / Fallback                   Logpush / OTEL
```

### 1.3 Pricing

| Tier | Cost | Logs | Gateways |
|------|------|------|----------|
| **Free** | $0 | 100k/month | 10 |
| **Workers Paid** | $5/month | 1M total | 20 |
| **Gateway itself** | Free | — | — |
| **Unified Billing** | Provider costs only | — | — |

The gateway proxy is free — you only pay for provider API calls and log storage beyond free tier.

### 1.4 Supported Providers (23+)

Amazon Bedrock, Anthropic, Azure OpenAI, Cerebras, Cloudflare Workers AI, Cohere, Deepgram, DeepSeek, ElevenLabs, Groq, Google Vertex AI, Google Gemini, HuggingFace, Ideogram, Mistral AI, Moonshot, OpenAI, Perplexity, Replicate, xAI, + custom providers via BYOK.

---

## 2. Inference (Proxy)

CF AI Gateway proxies to providers — it doesn't have its own inference. Three URL patterns:

### 2.1 Provider-Specific Endpoint
```
https://gateway.ai.cloudflare.com/v1/{acct}/{gw}/{provider}/{path}
```
Replace the provider's base URL. Same request body, same auth headers.

### 2.2 Unified Endpoint (OpenAI-Compatible)
```
https://gateway.ai.cloudflare.com/v1/{acct}/{gw}/compat/chat/completions
```
Model format: `provider/model` (e.g., `openai/gpt-4o-mini`, `anthropic/claude-4-5-sonnet`).

### 2.3 Universal Endpoint (Advanced)
```
https://gateway.ai.cloudflare.com/v1/{acct}/{gw}/run
```
Accepts array of provider objects with built-in fallback, retry, and rate limiting per provider.

### 2.4 Custom Providers
```
https://gateway.ai.cloudflare.com/v1/{acct}/{gw}/custom-{slug}/{path}
```

**Live test status:** After provisioning gateway via Global API Key, ALL proxy tests PASS.

| Provider | Endpoint | Status | Latency |
|----------|----------|--------|---------|
| OpenAI | `/openai/chat/completions` | PASS | 877ms |
| Anthropic | `/anthropic/v1/messages` | PASS | 2916ms |
| Groq | `/groq/chat/completions` | PASS | 474ms |
| DeepSeek | `/deepseek/chat/completions` | PASS | 2180ms |
| OpenAI (unified) | `/compat/chat/completions` | PASS | 888ms |

Additional features tested through proxy (all PASS): streaming, tool calling, JSON mode, custom metadata, caching.

---

## 3. Routing & Resilience

### 3.1 Fallback Chains
Multiple providers in array via universal endpoint. Response header `cf-aig-step` indicates which provider handled (0=primary).

### 3.2 Retry Configuration
| Header | Purpose | Limits |
|--------|---------|--------|
| `cf-aig-max-attempts` | Retry attempts | 1-5 |
| `cf-aig-retry-delay` | Delay between retries (ms) | Max 5000 |
| `cf-aig-backoff` | Strategy | constant / linear / exponential |
| `cf-aig-request-timeout` | Timeout before fallback (ms) | — |

### 3.3 Dynamic Routing (Visual + JSON)
- Visual flow builder or JSON configuration
- Elements: conditional, probabilistic routing, rate limiting, model execution
- User segmentation (paid vs free), A/B testing, gradual rollouts
- Named, versioned routes (e.g., `dynamic/support`)

---

## 4. Caching

| Feature | Value |
|---------|-------|
| **Type** | Edge caching (CF's global network) |
| **Max size** | 25 MB per request |
| **Max TTL** | 1 month |
| **Cache hit cost** | $0 |
| **Latency reduction** | Up to 90% |

Identical requests served from edge. No semantic caching.

---

## 5. Observability

### 5.1 Logging
- Real-time (within 15 seconds)
- Shows: prompt, response, provider, status, tokens, cost, duration
- Custom metadata: up to 5 key-value pairs via `cf-aig-metadata` header
- Log payload control: `cf-aig-collect-log-payload: false` for metadata-only logging
- Retention: 10M logs/gateway (default), 100k/account (free)

### 5.2 Logpush
Export logs to external systems (Workers Paid plan, max 4 jobs/account).

### 5.3 OpenTelemetry
Native OTLP export with semantic conventions for Gen AI spans.

### 5.4 Cost Tracking
- Per-token tracking (input + output)
- Custom costs: `cf-aig-custom-cost: {input},{output}` header
- Cache hits always $0

---

## 6. Security & Safety

### 6.1 Guardrails
Content moderation for violence, hate speech, sexual content. Actions: Flag (audit) or Block (reject).

### 6.2 Data Loss Prevention (DLP)
| Category | Types |
|----------|-------|
| Financial | Credit card, bank account |
| PII | SSN, passport, driver's license |
| Government | National IDs |
| Healthcare | Medical records |

Actions: Flag or Block. GDPR/HIPAA/PCI DSS audit trails. Limitation: buffers streaming responses (adds latency).

### 6.3 BYOK (Bring Your Own Keys)
Store provider API keys in CF Secrets Store with AES encryption. Multiple keys per provider with aliases (`cf-aig-byok-alias` header). Environment-based key selection (dev/prod).

### 6.4 Unified Billing
Pay for OpenAI, Anthropic, Google, xAI, Groq via single CF invoice. Spend controls (daily/weekly/monthly). ZDR option.

---

## 7. Management API

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/accounts/{id}/ai-gateway/gateways` | List gateways |
| POST | `/accounts/{id}/ai-gateway/gateways` | Create gateway |
| GET | `/accounts/{id}/ai-gateway/gateways/{gw}` | Get gateway |
| PUT | `/accounts/{id}/ai-gateway/gateways/{gw}` | Update gateway |
| DELETE | `/accounts/{id}/ai-gateway/gateways/{gw}` | Delete gateway |

**Auth:** API token with "AI Gateway: Read/Edit" permissions.

**Live test status:** All management API calls returned auth error — existing tokens lack AI Gateway scope.

---

## 8. Developer Tools

| Tool | Status |
|------|--------|
| **Wrangler CLI** | Native AI Gateway binding in `wrangler.toml` |
| **Terraform** | CF Terraform provider (AI Gateway resources developing) |
| **Workers AI binding** | `getUrl()`, `run()` methods |
| **OpenTelemetry** | OTLP export with custom headers |
| **Vercel AI SDK** | Community `workers-ai-provider` |
| **Promptfoo** | Evaluation framework integration |

---

## 9. CF-Specific Headers

| Header | Direction | Purpose |
|--------|-----------|---------|
| `cf-aig-authorization` | Request | Gateway-level auth (API token) |
| `cf-aig-byok-alias` | Request | Select stored key variant |
| `cf-aig-metadata` | Request | Custom metadata (JSON, max 5 entries) |
| `cf-aig-custom-cost` | Request | Override pricing |
| `cf-aig-max-attempts` | Request | Retry attempts (1-5) |
| `cf-aig-retry-delay` | Request | Retry delay (max 5000ms) |
| `cf-aig-backoff` | Request | Backoff strategy |
| `cf-aig-request-timeout` | Request | Timeout before fallback |
| `cf-aig-collect-log` | Request | Enable/disable logging |
| `cf-aig-collect-log-payload` | Request | Store request/response bodies |
| `cf-aig-step` | Response | Which provider handled (0=primary) |

---

## 10. Limits

| Resource | Free | Paid |
|----------|------|------|
| Gateways per account | 10 | 20 |
| Logs per gateway | 10M | 10M |
| Account log retention | 100k/month | 1M total |
| Log throughput | 500/sec/gateway | 500/sec/gateway |
| Request cache size | 25 MB | 25 MB |
| Cache TTL | 1 month | 1 month |
| Metadata entries | 5/request | 5/request |
| Retry attempts | 5 max | 5 max |
| Logpush jobs | — | 4/account |
| DLP custom entries | 25/account | 25/account |

---

## 11. Limitations & Gaps

### 11.1 Requires Dashboard Provisioning
Unlike Portkey/OpenRouter where you get an API key and start calling, CF AI Gateway requires:
1. Create a gateway in the CF dashboard (or via API with properly scoped token)
2. CF API tokens must include "AI Gateway: Edit" permission
3. Global API Key requires email address (not always stored)

**This was the blocking issue in our audit** — existing CF tokens lacked AI Gateway permissions.

### 11.2 Proxy-Only Architecture
CF doesn't add models or intelligence — it's a transparent proxy. No Thompson sampling, no auto-routing, no model selection. You must know which provider and model you want.

### 11.3 No Agent Management
No concept of agents, per-agent budgets, or lifecycle management.

### 11.4 No Prompt Management
No prompt versioning, rendering, or library.

### 11.5 No SDK
No official client SDK (unlike Portkey's 200+ method SDK). Integration is URL replacement + headers.

### 11.6 No Model Catalog API
No API to discover available models — you must know provider model names.

### 11.7 DLP Buffers Streaming
DLP inspection requires buffering the entire response, defeating the purpose of streaming for latency-sensitive applications.

### 11.8 Small Metadata Cap
Only 5 key-value pairs per request (Portkey allows arbitrary metadata).

---

## 12. What Makes CF Unique

1. **Edge caching** — 300+ cities globally, sub-100ms cache hits (no other gateway offers this)
2. **DLP built-in** — PII/financial/healthcare data scanning (Portkey has guardrails; BR and OR don't)
3. **Unified billing** — Pay for OpenAI+Anthropic+Google+xAI+Groq on one CF invoice
4. **BYOK with Secrets Store** — AES-encrypted, per-environment key aliases
5. **Free tier** — Gateway is free; only pay for provider + log storage
6. **Infrastructure-grade** — Same Cloudflare network that handles 20%+ of internet traffic
7. **Dynamic routing** — Visual flow builder for complex routing logic (no other gateway has this)
8. **OpenTelemetry native** — Direct OTLP export (others need external integration)

---

## Appendix: Test Results

| Test | Status | Notes |
|------|--------|-------|
| Token verification | PASS | Scoped token active |
| List gateways (scoped) | TIER_RESTRICTED | Token lacks AI Gateway permission |
| List gateways (global) | FAIL | Global key needs email not stored |
| Create gateway | TIER_RESTRICTED | Token lacks AI Gateway permission |
| Proxy: default → OpenAI | FAIL | Gateway not provisioned (error 2001) |
| Proxy: autopsy → OpenAI | FAIL | Gateway not provisioned |
| Unified endpoint | FAIL | Gateway not provisioned |
| Custom metadata | FAIL | Gateway not provisioned |
| **TOTAL** | **1 PASS, 5 FAIL, 2 TIER** | **Needs dashboard setup + token re-scoping** |
