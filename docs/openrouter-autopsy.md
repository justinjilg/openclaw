# OpenRouter — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **API Base URL** | `https://openrouter.ai/api/v1` |
| **Account Tier** | Pay-as-you-go |
| **Tests Run** | 40 (30 PASS, 10 FAIL) |
| **Pass Rate** | 75% |
| **Models Discovered** | 400+ across 60+ providers |
| **Free Models** | 50+ at $0 cost |
| **Total Cost** | ~$0.10 |

---

## 1. Platform Overview

### 1.1 Company & Product

OpenRouter is a unified AI model gateway providing access to **400+ models across 60+ providers** through a single normalized OpenAI-compatible API. It emphasizes transparent pricing (no markup), privacy (ZDR by default), and intelligent routing.

**Key stats:**
- 5M+ global users, 250k+ applications
- ~30 trillion tokens/month
- Top models: Claude Opus 4.6 (1.1T tokens/week), Trinity Large (395B/week), Gemini 3.1 Pro (292B/week)

### 1.2 Architecture

```
Your App → OpenRouter API → Smart Router → Best Provider
              ↓
         Auto/Free Router (Thompson sampling)
         Model Fallbacks (ordered array)
         Provider Filtering (only/ignore/ZDR)
         Plugins (web-search, response-healing, compression)
         Broadcast Observability (Langfuse, Datadog, Sentry)
```

### 1.3 Pricing

- **Per-token billing** — input and completion priced separately
- **No platform markup** — pass-through provider pricing
- **5.5% fee per credit purchase** ($0.80 minimum)
- **50+ free models** at zero cost (rate-limited)
- **No subscriptions or minimums**

### 1.4 Provider Ecosystem

**60+ providers, 400+ models.** Tested via chat completions:

| Provider | Model Tested | Status | Latency |
|----------|-------------|--------|---------|
| Google | gemini-2.0-flash-001 | PASS | 818ms |
| DeepSeek | deepseek-chat | PASS | 572ms |
| OpenAI | (via auto router) | PASS | — |
| Anthropic | (via auto router) | PASS | — |
| Auto Router | openrouter/auto | PASS | 5885ms |
| Free Router | openrouter/free | PASS | 2236ms |

### 1.5 SDKs

| Tool | Package | Status |
|------|---------|--------|
| **TypeScript SDK** | `@openrouter/sdk` | Auto-generated from OpenAPI |
| **Python SDK** | `openrouter-sdk` | Auto-generated from OpenAPI |
| **OpenAI compat** | Any OpenAI SDK | base_url override |
| **OpenAPI spec** | `openrouter.ai/openapi.json` | 13+ paths documented |
| **MCP** | Community (`physics91/openrouter-mcp`) | Not official |

---

## 2. Inference API

### 2.1 Chat Completions

| Field | Value |
|-------|-------|
| **Endpoint** | `POST /api/v1/chat/completions` |
| **Live Tested** | 9/10 PASS |
| **Streaming** | Yes (SSE) |
| **Tool Calling** | Yes |
| **JSON Mode** | Yes |
| **Structured Output** | Yes (json_schema with strict) |
| **Multi-turn** | Yes |
| **Vision** | Yes (tested, image URL issue) |
| **Model Fallback** | Yes (`models` array, format TBD) |

**Unique features:**
- `provider` parameter for routing control (sort, only, ignore, ZDR, throughput thresholds)
- `plugins` parameter for web-search, response-healing, context-compression
- `models` array for multi-model fallback

### 2.2 No Other Inference Endpoints

OpenRouter is **chat completions only**. No embeddings, images, audio, moderations, files, batches, or fine-tuning endpoints (unlike Portkey which has 14 types).

---

## 3. Routing (Strongest Feature)

### 3.1 Auto Router (`openrouter/auto`)

Thompson sampling that considers: cost, availability (last 30s), quality, inverse-squared price weighting. Tested PASS.

### 3.2 Free Router (`openrouter/free`)

Intelligently selects from 50+ free models matching request requirements. Tested PASS.

### 3.3 Dynamic Model Variants

| Variant | Purpose | Tested |
|---------|---------|--------|
| `:nitro` | Sorted by throughput (fastest) | PASS |
| `:floor` | Sorted by price (cheapest) | PASS |
| `:online` | Web search integrated | PASS |
| `:free` | Free-tier version | Not tested |
| `:extended` | Longer context window | Not tested |
| `:thinking` | Reasoning enabled | Not tested |
| `:exacto` | Quality-first for tools | Not tested |

### 3.4 Provider Filtering

| Feature | Tested | Status |
|---------|--------|--------|
| `only: [provider]` | Yes | FAIL (returned wrong provider) |
| `ignore: [provider]` | Yes | PASS |
| `zdr: true` | Yes | PASS |
| `sort: "throughput"` | Yes | PASS |
| `data_collection: "exclude"` | No | — |
| `quantizations` filter | No | — |

### 3.5 Model Endpoints

`GET /api/v1/models/:author/:slug/endpoints` — returns which providers serve a model. Tested PASS.

### 3.6 ZDR Endpoints

`GET /api/v1/endpoints/zdr` — lists zero data retention compatible endpoints. Tested PASS.

---

## 4. Plugins

| Plugin | Purpose | Tested | Status |
|--------|---------|--------|--------|
| `web-search` | Real-time info retrieval | FAIL (API format changed) |
| `response-healing` | Auto-repair malformed JSON | PASS |
| `file-parser` | PDF processing | Not tested |
| `context-compression` | Middle-out prompt compression | Not tested |

---

## 5. Observability (Broadcast)

OpenRouter streams traces to external platforms:
- **Langfuse** — trace naming, user/session IDs, metadata
- **Datadog** — LLM observability, tags, costs
- **Sentry** — span attributes, error tracking

Privacy mode available (strips prompt/completion content, retains metrics).

---

## 6. Guardrails

Organization-level access controls:
- **Spending caps** — daily/weekly/monthly per-user/per-key
- **Model restrictions** — allowlist per-user/per-key
- **Provider restrictions** — allowlist per-user/per-key
- **ZDR enforcement** — force across all requests

Not directly tested (requires organization setup).

---

## 7. Management API

| Feature | Endpoint | Status |
|---------|----------|--------|
| Key management | `POST/GET/PATCH/DELETE /api/v1/keys/` | Requires management key (not tested) |
| Credit check | `GET /api/v1/key` | PASS |
| Model catalog | `GET /api/v1/models` | PASS |
| Model endpoints | `GET /api/v1/models/:id/endpoints` | PASS |
| ZDR endpoints | `GET /api/v1/endpoints/zdr` | PASS |
| OpenAPI spec | `GET /openapi.json` | PASS (13 paths) |

---

## 8. Limitations & Gaps

### 8.1 Chat Completions Only
No embeddings, images, audio, moderations, files, batches, or fine-tuning. If you need these, you must go directly to the provider.

### 8.2 No Agent Management
No concept of agents, per-agent budgets, or lifecycle management. Organizations with per-key limits are the closest equivalent.

### 8.3 No Server-Side Caching
No simple or semantic caching. Prompt caching relies on provider-native support (Anthropic, DeepSeek, Gemini).

### 8.4 No Prompt Management
No prompt versioning, rendering, or library.

### 8.5 Model Name Volatility
Models are added/removed frequently. Several models that exist in the catalog returned 404 during testing (`:free` variants, specific model IDs). The auto router handles this gracefully.

### 8.6 Higher Latency on Auto Router
Auto router averaged ~5.5s per request — significantly slower than direct model selection (~0.8s). This suggests routing adds substantial overhead or selects slower models.

### 8.7 Small Organization Cap
Max 10 members per organization. Not suitable for large teams.

---

## Appendix: Test Results

| Script | Description | PASS | FAIL |
|--------|-------------|------|------|
| 01 | Key & Models | 4 | 0 |
| 02 | Chat Completions | 9 | 1 |
| 03 | Providers & Routing | 7 | 1 |
| 04 | Plugins & Features | 4 | 3 |
| 05 | Multi-Provider Matrix | 6 | 5 |
| **TOTAL** | | **30** | **10** |
