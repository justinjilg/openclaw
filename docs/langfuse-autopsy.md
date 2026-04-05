# Langfuse — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **URL** | `https://langfuse.com/` |
| **Category** | LLM Observability + Evaluation (self-hosted) |
| **License** | MIT (open-source) |
| **GitHub** | `github.com/langfuse/langfuse` |
| **Tests Run** | 0 (research-only) |
| **Pricing** | Free (self-hosted) → $59/mo (Cloud Pro) → Custom (Enterprise) |
| **Backend** | PostgreSQL |

---

## 1. What It Is

Langfuse is an **open-source LLM observability and evaluation platform** — NOT a gateway/proxy. Unlike Helicone (proxy + observability), Langfuse is **SDK-based**: you instrument your code with the Langfuse SDK, which sends traces asynchronously. The LLM calls go directly to providers.

This is architecturally different from every gateway in our comparison — Langfuse never touches the inference path.

### Architecture

```
App → Provider API (direct, no proxy)
  ↓ (async)
Langfuse SDK → Langfuse Server (PostgreSQL)
                  ↓
             Tracing & Spans
             Cost Analytics
             Evaluation Framework
             Prompt Management
             Dataset Management
             Experiments & A/B
```

## 2. Key Features

| Feature | Details |
|---------|---------|
| **Tracing** | Multi-step LLM interaction traces with spans, generations, scores |
| **Cost tracking** | Per-model, per-user, per-trace cost analytics |
| **Evaluation** | Dataset management, custom evaluators, annotation workflows |
| **Prompt management** | Version control, deployment, variables |
| **Experiments** | Compare prompt/model variants with statistical significance |
| **Datasets** | Curate test sets from production traces |
| **Scoring** | Manual annotation + automated evaluators |
| **OpenTelemetry** | OTLP ingestion at `/api/public/otel` |
| **Integrations** | LangChain, LlamaIndex, OpenAI SDK, Vercel AI SDK, LiteLLM, Instructor |

## 3. Comparison: Langfuse vs Helicone

| Feature | Langfuse | Helicone |
|---------|----------|----------|
| **Architecture** | SDK-based (async) | **Proxy-based (inline)** |
| **Inference path** | Not in path (zero overhead) | In path (8ms P50 overhead) |
| **Routing** | No | **Yes (latency/cost/weighted)** |
| **Caching** | No | **Yes (semantic)** |
| **Evaluation depth** | **Deep (datasets, experiments, annotations)** | Basic (scoring, datasets) |
| **Prompt management** | **Yes (with variables, versioning)** | Yes |
| **Open source** | **MIT** | Apache 2.0 |
| **Backend** | **PostgreSQL (self-hosted)** | Distributed (Rust) |
| **SDK required** | Yes | **No (proxy only)** |
| **Complexity** | Higher (more powerful) | Lower (simpler) |
| **Free tier** | 50k events/mo (cloud) or unlimited (self-hosted) | 10k req/mo |

## 4. What Makes It Unique

- **Deepest evaluation framework** — datasets, experiments, annotation queues, statistical comparison
- **MIT licensed** — most permissive open-source license in the comparison
- **Zero inference overhead** — async SDK, never in the request path
- **PostgreSQL-backed** — simple, proven, self-hostable infrastructure
- **Strongest LangChain integration** — first-class support for the most popular LLM framework

## 5. Gaps

Not a gateway — no routing, no caching, no rate limiting, no guardrails, no key management. Pure observability + evaluation. Requires SDK instrumentation (vs. Helicone's no-SDK proxy approach).
