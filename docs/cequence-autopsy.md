# Cequence Security — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **Category** | API Security Platform + AI Gateway (MCP-focused) |
| **Primary Product** | Unified Application Protection (UAP) Platform |
| **AI Product** | AI Gateway (agentic AI security, launched 2025) |
| **Tests Run** | 0 (research-only — enterprise pricing, no free tier) |
| **Scale** | 10B+ daily API interactions, 4B user accounts protected |
| **Pricing** | Enterprise custom (contact sales) |
| **Recognition** | KuppingerCole Leader (API Security), Gartner Peer Insights |

---

## 1. Platform Overview

### 1.1 What It Is

Cequence is **NOT an LLM routing gateway**. It's an **API security platform** that recently added an AI Gateway product for securing agentic AI workflows via MCP. The core business is protecting APIs from bots, fraud, abuse, and vulnerabilities at scale.

The AI Gateway specifically secures the connection between AI agents and enterprise applications — it governs what agents can access, not which LLM they talk to.

### 1.2 Architecture

```
                    ┌─ Cequence UAP Platform ─────────────────────┐
                    │                                              │
AI Agents ──────────┤  AI Gateway (MCP Security)                   │
                    │    ├─ Trusted MCP Registry                   │
                    │    ├─ OAuth 2.1 + RBAC                       │
                    │    ├─ Agent Personas & Token Lifecycle        │
                    │    └─ 140+ App Integrations                  │
                    │                                              │
API Traffic ────────┤  Unified Application Protection              │
(10B req/day)       │    ├─ Behavioral Fingerprinting (ML)         │
                    │    ├─ Bot/Fraud Detection (inline)            │
                    │    ├─ API Discovery & Inventory               │
                    │    ├─ Vulnerability Testing (OWASP Top 10)    │
                    │    └─ Compliance (PCI DSS, GDPR, DORA, SOC2) │
                    └──────────────────────────────────────────────┘
```

### 1.3 Two Distinct Products

| Product | Purpose | Relevance to AI Gateways |
|---------|---------|-------------------------|
| **UAP Platform** | API security (bots, fraud, DDoS, vulnerabilities) | Protects the APIs that gateways expose |
| **AI Gateway** | MCP server security for agentic AI | Secures agent-to-app connections |

---

## 2. AI Gateway (MCP Security)

### 2.1 Purpose

Safely connect AI agents to enterprise applications via Model Context Protocol. This is NOT about routing to LLMs — it's about governing what agents can DO with enterprise tools.

### 2.2 Setup (3 Steps, No Code)

1. Select APIs or upload OpenAPI/Swagger specs
2. Choose OAuth 2.1 or passthrough auth
3. Deploy SaaS or self-hosted (Helm Chart)

### 2.3 Features

| Feature | Details |
|---------|---------|
| **Trusted MCP Registry** | Vets MCP servers before agents connect (industry-first) |
| **OAuth 2.1** | Standard auth for all MCP connections |
| **RBAC** | Role-based access per agent/user |
| **Agent Personas** | Define what each agent can access |
| **Token Lifecycle** | Issue, rotate, revoke tokens |
| **140+ Integrations** | Snowflake, Atlassian, Slack, Sentry, etc. |
| **No-code** | Transforms APIs into MCP-compatible endpoints in minutes |

### 2.4 Documentation

- Production: `https://docs.aigateway.cequence.ai/`
- Beta: `https://docs.beta.aigateway.cequence.ai/`

---

## 3. UAP Platform (Core Business)

### 3.1 Behavioral Fingerprinting Engine

Cequence's core differentiator:
- Real-time ML analysis of every API request/response
- Global ML models encode automated attack traits
- Local models determine behavior and intent per deployment
- Tracks attacker infrastructure despite evasion attempts
- **Inline deployment** — blocks threats directly (no separate enforcement)

### 3.2 Threat Detection

| Threat | Detection Method |
|--------|-----------------|
| Credential stuffing | Behavioral fingerprinting |
| Account takeover | ML pattern analysis |
| Inventory hoarding | API abuse detection |
| Content scraping | Bot identification |
| Fake accounts | Behavioral anomaly |
| AI-backed bots | Auto-refreshed global AI bot list |
| DDoS | Inline mitigation |

### 3.3 API Discovery & Inventory

| Feature | Details |
|---------|---------|
| Continuous discovery | Internal, external, third-party APIs |
| Infrastructure visibility | Cloud hosting, gateways, edge providers |
| Sensitive data detection | Pre-defined + custom patterns (worldwide) |
| OpenAPI/Swagger | Auto-generation from traffic |
| Shadow API detection | Finds undocumented endpoints |

### 3.4 Compliance & Governance

| Standard | Support |
|----------|---------|
| PCI DSS | Auto-mapping |
| GDPR | Auto-mapping |
| DORA | Auto-mapping |
| SOC 2 Type II | Certified |
| ISO 27001 | Certified |
| OWASP API Top 10 | Default rules (2023 edition) |
| OWASP LLM Top 10 | Automated testing (industry-first) |

---

## 4. GenAI-Specific Features

### 4.1 OWASP LLM Top 10 Testing

First and only vendor offering automated testing against OWASP's LLM-specific vulnerability list:
- Prompt injection
- Insecure output handling
- Training data poisoning
- Model denial of service
- Supply chain vulnerabilities
- Sensitive information disclosure
- Insecure plugin design
- Excessive agency
- Overreliance
- Model theft

### 4.2 AI Bot Detection

New ML models specifically trained to detect AI-backed bot attacks:
- Distinguishes AI-generated traffic from human
- Auto-refreshed global threat intelligence
- Inline blocking (no delayed enforcement)

### 4.3 Agentic AI Protection

Network-based governance for agent behavior:
- What data agents can access
- Which APIs agents can call
- Compliance enforcement per agent
- Behavioral baseline tracking

---

## 5. Deployment

| Method | Details |
|--------|---------|
| **SaaS** | Cequence-managed, SOC 2/ISO 27001/PCI DSS compliant |
| **Self-hosted** | Helm Chart for Kubernetes |
| **Hybrid** | Mix of cloud + on-prem |
| **Inline (proxy)** | Blocks threats directly |
| **Passive (sensor)** | Monitor-only mode |
| **Regions** | 31+ geographic regions |
| **Setup time** | ~15 minutes (zero-code) |

---

## 6. Integrations

| Category | Count | Examples |
|----------|-------|---------|
| **MCP servers** | 140+ | Snowflake, Atlassian, Slack, Sentry |
| **SOAR/alerting** | 300+ | ServiceNow, Jira, PagerDuty, Slack |
| **Cloud** | Multi | AWS, Azure, GCP |
| **API infrastructure** | Multi | Cloudflare, load balancers, API gateways |
| **SIEM** | Multi | Splunk, etc. |

---

## 7. Limitations & Gaps (as an AI Gateway)

### 7.1 No LLM Routing

Cannot route to LLM providers. No model selection, no Thompson sampling, no fallbacks, no load balancing.

### 7.2 No Cost Tracking

No per-token cost analytics, budget management, or spend reports for LLM usage.

### 7.3 No Caching

No response caching or prompt caching.

### 7.4 No Prompt Management

No prompt versioning, rendering, or library.

### 7.5 No LLM Observability

No token counts, latency tracking, or model performance analytics for LLM calls.

### 7.6 No SDK for LLM Calls

No Python/Node.js SDK for making LLM completions. The SDK is for API security policy management.

### 7.7 No Free Tier

Enterprise pricing only — not accessible without sales engagement.

---

## 8. What Makes Cequence Unique

1. **Scale** — 10B+ daily API interactions (no other vendor in this comparison operates at this scale)
2. **Behavioral fingerprinting** — ML-based, not pattern-based, tracks attackers despite evasion
3. **API discovery** — Finds shadow APIs you don't know about (unique capability)
4. **OWASP LLM Top 10 testing** — Only automated testing suite for LLM-specific vulnerabilities
5. **Trusted MCP registry** — Vets MCP servers before agents connect (industry-first)
6. **Inline enforcement** — Blocks threats directly in the request path (no separate enforcement layer)
7. **Zero-code** — 15-minute deployment, 300+ integrations, no app changes
8. **Compliance auto-mapping** — PCI DSS, GDPR, DORA, SOC 2, ISO 27001 mapped automatically

---

## 9. Positioning in 7-Gateway Landscape

| Layer | Gateways | What They Do |
|-------|----------|-------------|
| **LLM Orchestration** | Portkey, BrainstormRouter, OpenRouter, LiteLLM | Route requests, manage costs, track tokens |
| **Infrastructure Proxy** | Cloudflare AI Gateway | Edge caching, DLP, rate limiting |
| **LLM Content Security** | Lasso Security | Intent analysis, jailbreak detection, PII masking |
| **API Infrastructure Security** | **Cequence** | **Bot defense, API discovery, behavioral detection, MCP governance** |

```
Application Layer:
  Portkey / BR / OpenRouter / LiteLLM  →  LLM Provider
           ↕
  Lasso Security (content/intent layer)
           ↕
  Cequence (API infrastructure layer)
           ↕
  Cloudflare (edge/network layer)
```

**Cequence operates at a different layer than the other 6.** It protects the API infrastructure that gateways expose, rather than the LLM traffic flowing through them. It's the foundation layer — if your gateway's API gets attacked by bots, credential stuffing, or DDoS, Cequence is what stops it.

### Complementary Pairings

| Combo | What You Get |
|-------|-------------|
| **BR + Cequence** | Agent routing + API-level bot defense for exposed gateway |
| **Portkey + Lasso + Cequence** | Full stack: orchestration + content security + API security |
| **LiteLLM + Cequence** | Self-hosted routing + API discovery/protection |
| **Any gateway + Cequence AI Gateway** | Secure agent-to-tool MCP connections |
