# Lasso Security — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **API Endpoint** | `https://server.lasso.security/gateway/v3` |
| **Category** | AI Security Platform (not a routing gateway) |
| **Tests Run** | 0 (research-only — enterprise pricing, no free tier) |
| **Models** | 200+ via 7 providers + 100+ OpenAI-compatible |
| **Pricing** | Enterprise custom (contact sales) |
| **Recognition** | Gartner Cool Vendor 2024, FedRAMP compliant |

---

## 1. Platform Overview

### 1.1 What It Is

Lasso Security is NOT a traditional AI gateway like Portkey or OpenRouter. It's an **AI-native security platform** that sits in the request pipeline to detect and block threats. While it can route to 200+ models, its primary value is **behavioral intent analysis** — understanding *why* AI acts, not just *what* it says.

Think of it as: Cloudflare WAF, but purpose-built for LLM traffic.

### 1.2 Architecture

```
App → Lasso Gateway/API/SDK → Intent Analysis (<50ms) → LLM Provider
              ↓
     50+ Guardrails (pre-call + post-call)
     Intent Deputy (behavioral fingerprinting)
     PII Masking (auto-redaction)
     3,000+ Evasion Technique Decoder
     Session Isolation & Audit
```

**Five Pillars:**
1. **Discover** — Shadow AI identification (unauthorized tool usage)
2. **Assess** — AI risk & supply chain analysis
3. **Test** — Automated red teaming
4. **Enforce** — Guardrails & behavioral governance
5. **Protect** — Real-time malicious intent detection

### 1.3 Pricing

Enterprise custom only. No published tiers. Available on AWS Marketplace (including GovCloud).

---

## 2. Core Feature: Intent Deputy

Lasso's flagship differentiator (launched Feb 2026):

| Feature | Detail |
|---------|--------|
| **Accuracy** | 99.83% |
| **Latency** | <50ms |
| **Cost efficiency** | 570× cheaper than cloud-native guardrails |
| **Evasion coverage** | 3,000+ techniques (obfuscation, Unicode, cross-lingual) |

**How it works:**
- Creates behavioral fingerprints from historical patterns
- Detects anomalies at the **semantic layer** (not pattern matching)
- Analyzes intent alignment — why the AI acts, not what it says
- Context-aware (uses full session history)
- Pattern-free (not regex/keyword-based)

This is fundamentally different from every other gateway's guardrails (Portkey, CF, LiteLLM all use pattern-based detection).

---

## 3. API Surface

### 3.1 Gateway Endpoint

| Field | Value |
|-------|-------|
| **Base URL** | `https://server.lasso.security/gateway/v3` |
| **Auth** | `lasso-api-key` header |
| **Rate Limit** | 500 req/min per key |
| **Core endpoint** | `/gateway/v3/classify` |

### 3.2 Classify Endpoint

Two modes:

**Pre-Call** (before LLM):
- Detects jailbreaks, harmful prompts, PII, policy violations
- Blocks or sanitizes before the request reaches the provider

**Post-Call** (after LLM):
- Detects harmful outputs, policy violations, sensitive info
- Blocks or redacts problematic responses

Returns action-based control: `block`, `pass`, `warn`.

### 3.3 Integration Methods

| Method | Description |
|--------|-------------|
| **Gateway** | Proxy mode (drop-in replacement for provider URL) |
| **API** | Direct HTTP calls to `/gateway/v3/classify` |
| **SDK** | Python SDK embedded in application code |
| **Proxy chain** | Native integration with LiteLLM and Portkey as guardrail provider |

---

## 4. Guardrails (50+)

### 4.1 Content Filtering

| Category | Capabilities |
|----------|-------------|
| **Jailbreak** | Prompt injection, instruction bypass, adversarial prompts |
| **Harmful** | Violence, sexual, hateful, illegal content |
| **PII** | Emails, phones, credit cards, SSN, auto-masking with placeholders |
| **Secrets** | API keys, tokens, credentials |
| **Code security** | Dangerous code patterns, injection vectors |
| **Custom regex** | User-defined detection patterns |

### 4.2 Intent-Based (Unique to Lasso)

| Feature | Description |
|---------|-------------|
| Behavioral anomaly | Detects deviations from established patterns |
| Semantic manipulation | Catches encoding tricks that bypass keyword filters |
| Cross-lingual attacks | Detects harmful intent in any language |
| Adversarial embeddings | Catches hidden instructions in seemingly benign text |
| Risky tool combinations | Flags dangerous multi-tool sequences |

### 4.3 PII Masking

- **Pre-call**: Sanitize user input → `<EMAIL_ADDRESS>`, `<PHONE_NUMBER>`, etc.
- **Post-call**: Redact model output
- Customizable via regex patterns
- HIPAA/GDPR compliant

---

## 5. Supported Providers

### 5.1 Native (7 providers)

| Provider | Status |
|----------|--------|
| Anthropic (Claude) | Supported |
| OpenAI (GPT-4/5) | Supported |
| Google (Vertex AI) | Supported |
| DeepSeek | Supported |
| Azure OpenAI | Supported |
| AWS Bedrock | Supported |
| Custom/internal LLMs | Supported |

### 5.2 OpenAI-Compatible (100+)

Any provider with OpenAI-compatible API: Cohere, HuggingFace, Replicate, Groq, Moonshot, Perplexity, etc.

---

## 6. MCP Gateway (Open Source)

**GitHub:** `lasso-security/mcp-gateway`

First security-centric MCP proxy:

| Feature | Description |
|---------|-------------|
| **Orchestration** | Multiple MCP servers with unified security |
| **Risk scoring** | Per-MCP server security assessment |
| **Supply chain** | Scans servers before loading |
| **Guardrail plugins** | basic (secrets), presidio (PII), lasso (full suite), xetrack (logging) |
| **License** | Open source |

---

## 7. Enterprise & Compliance

### 7.1 Compliance

| Standard | Status |
|----------|--------|
| HIPAA | Supported (BAA available) |
| GDPR | Compliant |
| SOC 2 | Supported |
| FedRAMP High | Lasso Federal LLC |
| DoD SRG | Lasso Federal |
| ITAR, CJIS | Lasso Federal |

### 7.2 Shadow AI Discovery

- Detects unauthorized AI tool usage across organization
- 55% of employees use unauthorized GenAI tools (per Lasso research)
- Categorizes risk by severity
- Customizable policy enforcement

### 7.3 Deployment

| Mode | Description |
|------|-------------|
| **Cloud/SaaS** | Lasso-managed (AWS, GovCloud) |
| **On-premises** | Self-hosted gateway |
| **Hybrid** | Mix of cloud + on-prem |

---

## 8. Ecosystem Partnerships

| Partner | Integration |
|---------|-------------|
| **Portkey** | Lasso as guardrail provider in Portkey pipeline |
| **LiteLLM** | Lasso as guardrail provider via `/gateway/v3/classify` |
| **Cloudflare** | Real-time monitoring integration |
| **AWS** | Marketplace + GovCloud |

---

## 9. Limitations & Gaps

### 9.1 Not a Routing Gateway

Lasso can route to providers, but has:
- No Thompson sampling or auto-routing
- No load balancing strategies
- No fallback chains
- No canary/A-B testing
- No model variants (`:nitro`, `:floor`, etc.)

### 9.2 No Cost Tracking

No per-token cost analytics, budget management, or spend reports.

### 9.3 No Caching

No response caching or prompt caching.

### 9.4 No Prompt Management

No prompt versioning, rendering, or library.

### 9.5 No Observability Integrations

No Langfuse, Datadog, Prometheus, or OpenTelemetry export. Logging is internal only.

### 9.6 No Free Tier

Enterprise pricing only — not accessible for evaluation without sales contact.

### 9.7 No SDK Beyond Python

Python SDK only. No TypeScript/Node.js SDK.

---

## 10. What Makes Lasso Unique

1. **Only intent-based security** — Behavioral fingerprinting, not pattern matching
2. **3,000+ evasion techniques** decoded at semantic layer
3. **570× cost efficiency** vs cloud-native guardrails
4. **99.83% accuracy** with <50ms latency
5. **Shadow AI discovery** — Finds unauthorized AI tool usage
6. **FedRAMP/DoD compliance** — Only gateway with federal certification
7. **Open-source MCP gateway** — First security-centric MCP proxy
8. **Red teaming** — Automated adversarial testing built-in
9. **Gartner Cool Vendor** recognition
10. **Ecosystem player** — Partners with Portkey, LiteLLM, Cloudflare (not competing)

---

## 11. Positioning in 6-Gateway Landscape

| Gateway | Primary Role | Lasso Relationship |
|---------|-------------|-------------------|
| **Portkey** | Production observability | **Partner** — Lasso provides security layer |
| **BrainstormRouter** | Agent cost optimization | **Complementary** — Lasso secures agents |
| **OpenRouter** | Model marketplace | **Orthogonal** — No security overlap |
| **Cloudflare AI GW** | Edge performance | **Partner** — Real-time monitoring |
| **LiteLLM** | Self-hosted routing | **Integration** — Lasso as guardrail plugin |
| **Lasso** | **AI-native threat detection** | **Unique layer** — sits alongside any gateway |

**Key insight:** Lasso is the only platform designed to be **layered on top of** other gateways, not replace them. You'd use Portkey/BR/OR for routing + Lasso for security.
