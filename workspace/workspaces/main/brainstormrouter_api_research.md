# BrainstormRouter API Research Report

## Executive Summary

**BrainstormRouter** (api.brainstormrouter.com) is a **runtime control plane for production AI agents** — a drop-in OpenAI-compatible proxy that routes across AI providers, enforces budgets, and logs every decision. It is currently a **free research project** with no markup on model costs (BYOK - Bring Your Own Key).

---

## 1. API Overview

### Base URL
```
https://api.brainstormrouter.com
```

### OpenAPI/Swagger Specification
Available at: `https://api.brainstormrouter.com/openapi.json`

### Health Check
```bash
GET https://api.brainstormrouter.com/health
# Returns: {"status":"ok","db":true,"redis":true,"uptime":42731,"version":"0.1.0"}
```

---

## 2. Authentication

### API Key Format
- **Format**: `br_live_...` or `br_test_...`
- **Header**: `Authorization: Bearer <api_key>`
- **Created via**: Dashboard at https://brainstormrouter.com/dashboard

### Getting an API Key
1. Sign in at https://brainstormrouter.com/dashboard (GitHub or Google OAuth)
2. Navigate to **Configure → API Keys**
3. Click **Create Key**
4. Configure name, rate limit (RPM), and budget cap (optional)
5. Copy the key (shown only once)

### Key Scopes/Roles
| Scope | Description |
|-------|-------------|
| `admin` | Full tenant administration |
| `operator` | Operations and configuration |
| `developer` | Standard API access |
| `auditor` | Read-only access |
| `agent` | Agent-specific access |

### Alternative Auth Methods
- **Supabase JWT**: For dashboard authentication
- **Agent JWT**: For agent bootstrap/identity
- **mTLS**: For service mesh agent-to-agent communication

---

## 3. Core Endpoints

### Chat Completions (OpenAI-Compatible)
```http
POST /v1/chat/completions
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "model": "auto",
  "messages": [
    {"role": "system", "content": "You are helpful."},
    {"role": "user", "content": "Hello!"}
  ],
  "stream": false,
  "temperature": 0.7,
  "max_tokens": 1000
}
```

**Model Options:**
- `"auto"` - Thompson Sampling selects optimal model
- `"auto:floor"` - Cheapest model above quality threshold
- `"auto:fast"` - Lowest latency model
- `"auto:best"` - Highest quality regardless of cost
- Specific models: `anthropic/claude-sonnet-4-20250514`, `openai/gpt-4o`, `google/gemini-2.0-flash`

### Anthropic Messages API
```http
POST /v1/messages
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "model": "auto",
  "max_tokens": 1000,
  "messages": [{"role": "user", "content": "Hello!"}],
  "stream": false
}
```

### List Models
```http
GET /v1/models
Authorization: Bearer br_live_...
```

### Agent Self-Awareness (MNI - Machine-Native Interface)
```http
GET /v1/self
Authorization: Bearer br_live_...
```
Returns: identity, capabilities, health, budget, memory, configuration, suggestions, recent errors

### List Runnable Models
```http
GET /v1/catalog/runnable
Authorization: Bearer br_live_...
```
Returns only models guaranteed to work (filtered by circuit breakers, health, BYOK keys)

---

## 4. Provider Management (BYOK)

### Add Provider
```http
POST /v1/providers
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "provider": "anthropic",
  "api_key": "sk-ant-..."
}
```

**Supported Providers:**
- `anthropic` (Claude models)
- `openai` (GPT models)
- `google` (Gemini models)
- `groq` (Fast inference)

### Batch Add Providers
```http
POST /v1/providers/batch
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "providers": [
    {"provider": "anthropic", "api_key": "sk-ant-...", "test_first": true},
    {"provider": "openai", "api_key": "sk-..."}
  ]
}
```

### List Providers
```http
GET /v1/providers
Authorization: Bearer br_live_...
```

---

## 5. Budget & Kill Switch

### Get Budget Status
```http
GET /v1/budget/status
Authorization: Bearer br_live_...
```

### Update Budget Limits
```http
PUT /v1/budget/limits
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "daily_limit_usd": 100.00,
  "monthly_limit_usd": 1000.00
}
```

### Get Budget Forecast
```http
GET /v1/budget/forecast
Authorization: Bearer br_live_...
```

### Kill Switch Operations
```http
# Activate
POST /v1/killswitch/activate
Authorization: Bearer br_live_...
{"reason": "Emergency spend control"}

# Deactivate
POST /v1/killswitch/deactivate
Authorization: Bearer br_live_...

# Status
GET /v1/killswitch/status
Authorization: Bearer br_live_...
```

---

## 6. Memory (RMM - Relational Memory Manager)

### Store Memory
```http
POST /v1/memory/entries
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "context": "User prefers concise responses",
  "block": "human",
  "pinned": true
}
```

**Memory Blocks:**
- `human` - User preferences and facts
- `project` - Project-specific knowledge
- `system` - System configuration
- `general` - General knowledge

### Query Memory
```http
POST /v1/memory/query
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "query": "What does the user prefer?",
  "agent_id": "my-agent"
}
```

### List Memory Blocks
```http
GET /v1/memory/blocks
Authorization: Bearer br_live_...
```

---

## 7. Guardrails

### List Guardrail Providers
```http
GET /v1/guardrails/providers
Authorization: Bearer br_live_...
```

### Update Guardrail Config
```http
PUT /v1/guardrails/config
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "enabled": true,
  "mode": "block",
  "confidenceThreshold": 0.8,
  "providers": [{"id": "builtin-pii", "enabled": true}]
}
```

### Test Guardrails
```http
POST /v1/guardrails/test
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "text": "Sample text to test"
}
```

---

## 8. Routing Presets

### Create Preset
```http
POST /v1/presets
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "slug": "fast-cheap",
  "name": "Fast and Cheap",
  "model": "auto:fast",
  "strategy": "price",
  "fallbacks": ["anthropic/claude-haiku", "google/gemini-flash"],
  "max_cost_usd": 0.01
}
```

### List Presets
```http
GET /v1/presets
Authorization: Bearer br_live_...
```

**Usage:** Reference as `@preset/fast-cheap` in requests

---

## 9. Agent Management

### Bootstrap Agent
```http
POST /v1/agent/bootstrap
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "agent_id": "my-agent-001",
  "display_name": "My Agent",
  "budget_daily_usd": 10.00,
  "metadata": {"can_delegate": true}
}
```

### Get Agent Status
```http
GET /v1/agent/status
# Requires agent JWT auth
```

### Delegate to Sub-Agent
```http
POST /v1/agent/delegate
# Requires agent JWT auth
{
  "agent_id": "child-agent",
  "budget_allocation_usd": 5.00,
  "requested_role": "agent"
}
```

---

## 10. Observability

### Get Ops Status
```http
GET /v1/ops/status
Authorization: Bearer br_live_...
```

### Add Observability Destination
```http
POST /v1/observability/destinations
Authorization: Bearer br_live_...
Content-Type: application/json

{
  "name": "Datadog",
  "type": "datadog",
  "config": {"api_key": "..."},
  "event_types": ["usage", "audit", "error"]
}
```

---

## 11. Response Headers

Every response includes these headers:

| Header | Description |
|--------|-------------|
| `X-BR-Selected-Model` | Model that handled the request |
| `X-BR-Guardian-Status` | Guardian processing status |
| `X-BR-Estimated-Cost` | Predicted cost in USD |
| `X-BR-Actual-Cost` | Actual cost in USD |
| `X-BR-Efficiency` | Cost efficiency ratio |
| `X-BR-Guardian-Overhead-Ms` | Routing overhead in milliseconds |

---

## 12. Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `auth_error` | 401 | Missing or invalid API key |
| `budget_exceeded` | 402 | Budget limit reached |
| `rate_limit` | 429 | Rate limit exceeded |
| `invalid_request` | 400 | Malformed request |
| `circuit_open` | 503 | Provider circuit breaker open |

---

## 13. Code Examples

### Python (OpenAI SDK)
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://api.brainstormrouter.com/v1",
    api_key="br_live_...",
)

response = client.chat.completions.create(
    model="auto",
    messages=[{"role": "user", "content": "Hello!"}],
)

print(response.choices[0].message.content)
print(response.headers["X-BR-Actual-Cost"])
```

### TypeScript/JavaScript
```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "https://api.brainstormrouter.com/v1",
  apiKey: "br_live_...",
});

const response = await client.chat.completions.create({
  model: "auto",
  messages: [{ role: "user", content: "Hello!" }],
});

console.log(response.choices[0].message.content);
```

### cURL
```bash
curl https://api.brainstormrouter.com/v1/chat/completions \
  -H "Authorization: Bearer br_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

---

## 14. SDKs & Tools

### MCP Server (Model Context Protocol)
**NPM Package**: `@brainstormrouter/mcp`

```bash
# Install
npx -y @brainstormrouter/mcp

# Claude Desktop config
{
  "mcpServers": {
    "brainstormrouter": {
      "command": "npx",
      "args": ["-y", "@brainstormrouter/mcp"],
      "env": {
        "BRAINSTORMROUTER_API_KEY": "your-api-key"
      }
    }
  }
}
```

**Available MCP Tools:**
- `br_route_completion` - Route chat completion
- `br_list_models` - List available models
- `br_get_usage` - Get usage summary
- `br_set_alias` - Set model alias
- `br_get_health` - Get gateway health
- `br_memory_list/store/query` - Memory operations
- `br_list_prompts/presets` - Template management
- `br_get_ops_status` - Operations center
- `br_get_insights` - Cost optimization
- `br_get_governance` - Compliance audit
- `br_list_agents` - Agent profiles
- `br_get_leaderboard` - Model rankings

### Homebrew Tap
```bash
brew tap justinjilg/brainstormrouter
brew install brainstormrouter-mcp
```

---

## 15. Architecture & Key Features

### 13 Systems, 5 Pillars
1. **Identity** - SPIFFE, mTLS, agent certificates
2. **Authorization** - RBAC, graduated trust, behavioral profiles
3. **Runtime Enforcement** - Circuit breakers, streaming firewall, guardrails
4. **Economics** - Thompson Sampling routing, budget enforcement, Guardian cost prediction
5. **Evidence** - Audit trails, forensics, compliance scanning

### Request Pipeline (3 Stages)
1. **Ingest**: Auth, rate limit, key vault, guardrail pre-scan, semantic cache
2. **Route**: Thompson Sampling, CAF identity, ARM budget, provider dispatch
3. **Return**: Streaming firewall, Guardian output, RMM store, observability

### Thompson Sampling Router
- Bayesian posterior over model quality
- UCB1 exploration
- Automatic model selection based on task complexity
- Variants: `:floor`, `:fast`, `:best`, `auto`

---

## 16. Pricing

**Currently FREE during research phase.**

Planned tiers:
- **Free**: 1,000 requests/day, 3 providers, 100MB cache
- **Team**: 50,000 requests/day, unlimited providers, 10GB cache
- **Enterprise**: Unlimited, dedicated infrastructure, SSO/SAML

**No markup on model costs** - you pay providers directly at their published rates.

---

## 17. Documentation & Resources

- **Main Site**: https://brainstormrouter.com
- **Dashboard**: https://brainstormrouter.com/dashboard
- **Documentation**: https://docs.brainstormrouter.com
- **OpenAPI Spec**: https://api.brainstormrouter.com/openapi.json
- **GitHub**: https://github.com/justinjilg/brainstormrouter
- **NPM**: https://www.npmjs.com/package/@brainstormrouter/mcp

---

## 18. GitHub Repositories

| Repository | Description |
|------------|-------------|
| `justinjilg/homebrew-brainstormrouter` | Homebrew tap for MCP server |
| `justinjilg/brainstormrouter` | Main repository (monorepo) |

---

## 19. Best Practices

1. **Use `model: "auto"`** for intelligent routing
2. **Set budget limits** on API keys for cost control
3. **Add multiple providers** for redundancy
4. **Use conversation_id** for threaded memory
5. **Check response headers** for cost and routing info
6. **Enable guardrails** for PII/compliance
7. **Use presets** for consistent routing strategies
8. **Monitor `/v1/self`** for agent health awareness

---

## 20. Rate Limits

- Registration: 5 per hour per IP
- API key rate limits: Configurable per key (RPM)
- Default: Varies by plan tier

---

*Report compiled: March 17, 2026*
*API Version: 1.0.0*
*Status: Research Project (Free)*
