# Martian — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **URL** | `https://route.withmartian.com/` |
| **Category** | Intelligent Model Router (accuracy-optimized) |
| **Tests Run** | 0 (research-only) |
| **Funding** | $9M (Accenture investment) |
| **Pricing** | Usage-based (contact for details) |

---

## 1. What It Is

Martian is a **per-query model router** that optimizes for accuracy vs. cost on every individual request. Unlike BrainstormRouter (Thompson sampling across a fleet) or OpenRouter (marketplace with variants), Martian uses **model mapping** — an interpretable system that explains WHY it chose a specific model for each query.

### Architecture

```
App → Martian Router → Model Mapping Analysis → Best Model → Provider
          ↓
     Per-query accuracy/cost optimization
     Interpretable decision reasoning
     Compliance/approval workflows
```

## 2. Key Features

| Feature | Details |
|---------|---------|
| **Per-query routing** | Selects optimal model for each individual request |
| **Model mapping** | Interpretable: explains routing decisions |
| **Accuracy optimization** | Routes based on expected accuracy, not just latency/cost |
| **Compliance workflows** | Approval pipelines for model changes |
| **Cost optimization** | Balances accuracy vs. cost per query |

## 3. What Makes It Unique

- **Only router with interpretable model mapping** — you can see WHY it chose each model
- **Accuracy-first** (vs. latency-first like Helicone, cost-first like OpenRouter `:floor`)
- **Compliance/approval workflows** — enterprise governance for model selection changes
- **Per-query granularity** — different model for every request based on content analysis

## 4. Gaps

No caching, no guardrails, no observability dashboard, no prompt management, no evaluation framework, no MCP support. Pure routing only.
