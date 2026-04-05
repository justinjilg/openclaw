# Not Diamond — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **URL** | `https://www.notdiamond.ai/` |
| **Category** | Meta-Model Router (recommendation-only) |
| **Tests Run** | 0 (research-only) |
| **Funding** | IBM venture investment |
| **Performance** | <50ms routing decisions, up to 25% accuracy improvement, 10x cost reduction |

---

## 1. What It Is

Not Diamond is architecturally unique: it's a **recommendation layer**, not a proxy. It tells you WHICH model to use but doesn't route the request itself. You call the provider directly. This means zero added latency on the inference path.

### Architecture

```
App → Not Diamond API → "Use claude-sonnet-4 for this query" → App calls provider directly
          ↓
     Neural network trained on model performance
     <50ms recommendation latency
     No proxy overhead on inference
```

## 2. Key Features

| Feature | Details |
|---------|---------|
| **Recommendation-only** | Returns model recommendation; you call provider |
| **Neural network** | Learned routing (not rules-based) |
| **<50ms decisions** | Fast enough for real-time routing |
| **25% accuracy gain** | Over static model selection |
| **10x cost reduction** | By routing cheap queries to cheap models |
| **Zero inference overhead** | Not in the request path |

## 3. What Makes It Unique

- **Only recommendation-layer architecture** — all other gateways are proxies
- **Zero inference overhead** — doesn't add latency to LLM calls
- **Learned neural routing** — improves over time (like BR's Thompson sampling but neural)
- **Decoupled from providers** — works with any provider setup you already have

## 4. Gaps

Not a gateway — no caching, guardrails, observability, prompt management, key management, or team features. Pure recommendation API.
