# Kong AI Gateway — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **URL** | `https://konghq.com/products/kong-ai-gateway` |
| **Category** | Traditional API Gateway extended to AI |
| **Tests Run** | 0 (research-only) |
| **Deployments** | 100k+ (Kong overall) |
| **License** | Open-source (Kong Gateway OSS) + Enterprise |

---

## 1. What It Is

Kong AI Gateway is the AI extension of **Kong**, the most widely deployed API gateway (100k+ deployments). Unlike AI-native gateways (Portkey, OpenRouter), Kong adds AI capabilities to an existing enterprise API infrastructure — meaning organizations already running Kong can add LLM routing without a new platform.

### Architecture

```
App → Kong Gateway → AI Plugins → Provider API
          ↓
     Existing API management (rate limiting, auth, transforms)
     + AI Proxy Plugin (multi-provider routing)
     + Semantic Caching Plugin
     + Prompt Guard Plugin
     + MCP Registry Plugin
```

## 2. Key Features

| Feature | Details |
|---------|---------|
| **Multi-provider routing** | OpenAI, Anthropic, Bedrock, Azure, custom |
| **Semantic caching** | Reduce costs on similar requests |
| **Prompt guard** | Content filtering + injection detection |
| **MCP registry** | Tool governance for agent workflows |
| **Rate limiting** | Enterprise-grade (Kong's core strength) |
| **Auth** | OAuth, JWT, API keys, mTLS (Kong's core strength) |
| **Transforms** | Request/response manipulation |
| **Plugin ecosystem** | 100+ plugins (logging, auth, traffic control, etc.) |
| **Service mesh** | Kong Mesh for Kubernetes |

## 3. What Makes It Unique

- **Only platform bridging traditional API management → AI** — if you already run Kong, zero new infrastructure
- **100k+ deployments** — most battle-tested infrastructure in the comparison
- **Plugin architecture** — AI is modular, not monolithic
- **Multi-protocol** — REST, GraphQL, gRPC, WebSocket + LLM (no other AI gateway does gRPC)
- **Service mesh** — Kubernetes-native service-to-service communication

## 4. Gaps

Not AI-native — no Thompson sampling, no model mapping, no evaluation framework, no prompt management, no observability dashboard (uses external integrations). Plugin-based AI means less depth than purpose-built platforms.
