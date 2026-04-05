# Wallarm — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **Category** | API Security Platform + Agentic AI Defense |
| **Primary Product** | Unified API Security (WAF + Bot + Discovery + Abuse Prevention) |
| **AI Product** | Agentic AI Security (MCP protection, A2A attack detection) |
| **Tests Run** | 0 (research-only — enterprise pricing) |
| **Scale** | 1B+ Docker pulls (API Firewall), 24/7 SOC |
| **Pricing** | Enterprise custom (~$325/mo starter, $50k+/yr enterprise) |
| **Recognition** | Gartner API Protection, A2AS standard co-author (AWS/Google/Meta/JPMorgan) |

---

## 1. Platform Overview

### 1.1 What It Is

Wallarm is a **WAF/API security platform** that has pivoted aggressively into **agentic AI security**. It operates at the HTTP/API infrastructure layer — protecting any backend including LLM APIs, agent workflows, and MCP servers. NOT an LLM routing gateway.

The key differentiator from Cequence and Lasso: Wallarm co-authored the **A2AS (Agent-to-Agent Security) standard** with AWS, Google, Meta, JPMorganChase, Cisco, and Salesforce. This positions them as the thought leader in multi-agent attack prevention.

### 1.2 Architecture

```
Internet / Agents → Wallarm (inline proxy or sidecar)
                      ├─ API Discovery (shadow APIs, inventory)
                      ├─ Behavioral Analysis (ML, request sequences)
                      ├─ Bot/Abuse Prevention (credential stuffing, ATO)
                      ├─ Agentic AI Protection
                      │    ├─ MCP Server Security
                      │    ├─ A2A Attack Detection (multi-agent prompt injection)
                      │    ├─ Behavior Certificates (agent permission model)
                      │    └─ Model Self-Defense Reasoning
                      ├─ WAF (OWASP Top 10, DDoS L7)
                      └─ 24/7 SOC-as-a-Service
                    → Your Backend / LLM Gateway / Provider
```

### 1.3 Pricing

| Tier | Cost | Includes |
|------|------|---------|
| **Starter** | ~$325/month | Basic API protection |
| **Enterprise** | $50k+/year | Full platform + SOC |
| **AASM** | Custom | Attack surface management (no deployment needed) |
| **Security Edge** | Custom | Fully managed, global PoPs |

---

## 2. Core Products

### 2.1 API Security Platform

| Capability | Details |
|-----------|---------|
| **API Discovery** | Automated inventory, shadow/orphan API detection |
| **Abuse Prevention** | ML behavioral analysis across request sequences (patented) |
| **Bot Detection** | Credential stuffing, account takeover, scraping, DDoS L7 |
| **Vulnerability Scanning** | Active security testing |
| **Inline Blocking** | Real-time, sub-millisecond (Go-based reverse proxy) |
| **Protocol Support** | REST, SOAP, GraphQL, WebSocket, custom |
| **OWASP Coverage** | API Top 10 (2023) + LLM Top 10 + Business Logic Abuse |

### 2.2 Agentic AI Security (2025-2026)

**A2AS Framework** (co-developed with AWS, Google, Meta, JPMorganChase, Cisco, Salesforce):

| Feature | Description |
|---------|-------------|
| **Behavior Certificates** | Declare & enforce what each agent can/cannot do |
| **Model Self-Defense Reasoning** | Embed security in the model's context window — model rejects malicious instructions |
| **Prompt-Level Sandboxing** | Policy-as-code for prompt interactions |
| **A2A Attack Detection** | Multi-stage prompt injection across agent-to-agent workflows |
| **MCP Server Protection** | Real-time malicious prompt detection, unauthorized tool blocking, granular access policies |

### 2.3 Behavioral Analysis (Patented)

Wallarm's behavioral analysis works across **request sequences**, not single requests:

| Method | What It Detects |
|--------|----------------|
| Request rate analysis | RPS threshold violations |
| Request interval analysis | Timing randomness (bot vs human) |
| Query abuse analysis | Parameter mutation patterns |
| Statistical anomaly | Deviation from behavioral baselines |
| Suspicious behavior scoring | Per-detector attribution |

### 2.4 SOC-as-a-Service

**24/7/365 managed security operations** — unique among all 8 platforms:
- Expert threat analysts monitoring your deployment
- Not just alerts — active investigation and response
- Included with enterprise tier

---

## 3. Deployment

| Method | Details |
|--------|---------|
| **Docker** | 1B+ pulls on DockerHub |
| **Kubernetes** | Ingress Controller + Sidecar modes (EKS, GKE, AKS, private) |
| **NGINX-based** | Inline proxy |
| **Envoy-based** | Sidecar proxy |
| **Cloud images** | AWS AMI, GCP, Azure, IBM Cloud |
| **Security Edge** | Fully managed global PoPs (SaaS) |
| **Linux packages** | Direct install |
| **Terraform** | AWS module available |

### Deployment Regions
31+ geographic regions, multi-cloud (AWS + GCP + Azure simultaneously).

---

## 4. Open Source Component

**Wallarm API Firewall** (`github.com/wallarm/api-firewall`):

| Feature | Details |
|---------|---------|
| **Language** | Go (fasthttp) |
| **Docker pulls** | 1B+ |
| **Modes** | PROXY (validate + forward), API (validate only), GraphQL (WS + GQL) |
| **Specs** | OpenAPI 3.0 validation |
| **Rules** | ModSecurity + OWASP CRS support |
| **Version** | v0.9.5 (Dec 2025) |

---

## 5. API & Integration

### 5.1 API Reference

| Detail | Value |
|--------|-------|
| **US Cloud** | `apiconsole.us1.wallarm.com` |
| **EU Cloud** | `apiconsole.eu1.wallarm.com` |
| **Auth** | API token (Settings → API tokens) |
| **Format** | Swagger/OpenAPI-based |

### 5.2 Integrations

300+ integrations: Kong, AWS API Gateway, ServiceNow, Jira, Slack, PagerDuty, SIEM platforms.

---

## 6. Comparison: Wallarm vs Cequence vs Lasso

All three are security layers, but at different abstraction levels:

| Feature | Wallarm | Cequence | Lasso |
|---------|---------|----------|-------|
| **Primary layer** | API infrastructure | API infrastructure | LLM content |
| **Detection method** | Request-sequence ML | Behavioral fingerprinting | Semantic intent analysis |
| **Agentic AI** | A2AS standard, MCP protection | MCP registry, agent personas | Intent Deputy, behavioral baselines |
| **A2A attacks** | **Yes (multi-agent prompt injection)** | No | No |
| **Model Self-Defense** | **Yes (embed security in context)** | No | No |
| **SOC service** | **24/7/365 included** | No | No |
| **Open source** | API Firewall (Go) | No | MCP Gateway |
| **Scale** | 1B+ Docker pulls | 10B req/day | <50ms per request |
| **OWASP LLM** | Co-authored | Automated testing | No |
| **Bot detection** | Yes (inline ML) | Yes (inline ML) | No |
| **API discovery** | Yes | Yes | No |
| **PII detection** | Via WAF rules | Auto patterns | Auto masking |
| **Deployment** | Self-hosted + managed | Self-hosted + SaaS | SaaS + self-hosted |
| **Unique** | A2AS standard, model self-defense | Scale (10B/day), zero-code | Intent analysis (99.83%) |

---

## 7. Limitations (as an AI Gateway)

### 7.1 No LLM Routing
Cannot route to providers. No model selection, Thompson sampling, fallbacks, or load balancing.

### 7.2 No Cost Tracking
No per-token cost analytics or budget management for LLM usage.

### 7.3 No Caching
No response or prompt caching.

### 7.4 No Prompt Management
No prompt versioning, rendering, or library.

### 7.5 No LLM Observability
No token counts, model latency tracking, or performance analytics.

### 7.6 Agentic AI Features Still Emerging
MCP protection is new (2026). A2AS framework is research-stage — co-authored with big players but not yet battle-tested at scale.

### 7.7 No Free Tier
Enterprise pricing only. Starter tier exists (~$325/mo) but still requires sales contact.

---

## 8. What Makes Wallarm Unique

1. **A2AS standard co-author** — with AWS, Google, Meta, JPMorganChase, Cisco, Salesforce (strongest industry backing)
2. **Model Self-Defense Reasoning** — embeds security awareness IN the model's context window (no other vendor does this)
3. **A2A attack detection** — catches multi-stage prompt injection across agent-to-agent workflows (emerging threat)
4. **24/7 SOC-as-a-Service** — only platform with managed human security operations included
5. **Open-source API Firewall** — 1B+ Docker pulls, Go-based, ModSecurity-compatible
6. **Request-sequence analysis** — behavioral ML across multiple requests (not single-request pattern matching)
7. **OWASP LLM Top 10 co-author** — wrote the standard, not just implementing it

---

## 9. Positioning in 8-Gateway Landscape

| Layer | Products | What They Protect |
|-------|----------|-------------------|
| **LLM Orchestration** | Portkey, BR, OpenRouter, LiteLLM | Model routing, costs, tokens |
| **Infrastructure Proxy** | Cloudflare AI Gateway | Edge caching, DLP, rate limiting |
| **LLM Content Security** | Lasso Security | Prompt intent, jailbreaks, PII in prompts |
| **API Behavioral Security** | Cequence | Bot defense, API discovery, compliance |
| **API + Agentic AI Security** | **Wallarm** | **A2A attacks, MCP protection, model self-defense, 24/7 SOC** |

### For OpenClaw Specifically

Wallarm's relevance to your 5-agent OpenClaw deployment:
- **A2A attack detection** — your `main` agent spawns sub-agents; Wallarm can detect if an agent-to-agent interaction is malicious
- **MCP protection** — BR exposes 19 MCP tools; Wallarm can monitor for unauthorized tool invocations
- **Model Self-Defense** — could be injected into agent SOUL prompts to make models reject malicious instructions
- **Gateway protection** — your gateway at `127.0.0.1:18789` could be fronted by Wallarm's API Firewall
