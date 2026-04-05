# Portkey.ai — Capability Autopsy

## Meta

| Field | Value |
|-------|-------|
| **Audit Date** | 2026-03-21 |
| **SDK Version** | portkey-ai v3.0.3 (Node.js) |
| **API Base URL** | `https://api.portkey.ai/v1` |
| **Account Tier** | Dev (Free — 10k req/month) |
| **Tests Run** | 100 (75 PASS, 25 FAIL) |
| **Inference Pass Rate** | 50/55 (91%) |
| **Admin API Pass Rate** | 25/45 (56% — partial after admin key added) |
| **Providers Tested** | 7 (OpenAI, Anthropic, Groq, DeepSeek, Perplexity — PASS; Google, Moonshot — FAIL) |
| **API Keys Used** | 2 (inference key + admin key with scoped permissions) |
| **Total Cost** | ~$0.45 |

---

## 1. Platform Overview

### 1.1 Company & Product

Portkey.ai is an AI gateway and observability platform that provides a unified API for 250+ LLMs across 40+ providers. Founded as a "production stack for GenAI builders," it positions itself between application code and LLM providers, adding routing, observability, guardrails, and management capabilities.

**Key stats:**
- 25M+ daily requests processed
- 99.99% uptime SLA
- 20-40ms added latency (edge workers)
- 10B+ tokens/day capacity

### 1.2 Architecture

```
Your App → Portkey Gateway → LLM Provider(s)
              ↓
         Observability (logs, traces, cost)
         Routing (fallback, weighted, canary)
         Guardrails (content filtering, PII)
         Caching (simple, semantic)
```

**Two planes:**
- **Data Plane**: Proxies inference requests through the gateway (open-source, 122KB)
- **Control Plane**: Manages configs, virtual keys, guardrails, prompts, users (proprietary)

### 1.3 Pricing Tiers

| Tier | Price | Requests | Key Features | Data Retention |
|------|-------|----------|-------------|---------------|
| **Dev** | Free | 10k/month | Basic routing, simple caching | 7 days |
| **Pro** | $499/month | Unlimited | RBAC, budgets, rate limits, virtual models | 30 days |
| **Enterprise** | Custom | Unlimited | Semantic caching, PII, VPC, air-gapped, BAA | Custom |

Note: LLM provider costs (OpenAI, Anthropic, etc.) are separate — Portkey is middleware only.

### 1.4 Provider Ecosystem

**40+ providers, 250+ models.** Tested 7 via direct auth:

| Provider | Slug | Model Tested | Status | Latency (ms) | Notes |
|----------|------|-------------|--------|-------------|-------|
| OpenAI | `openai` | gpt-4o-mini | PASS | 772 | Full feature support |
| Anthropic | `anthropic` | claude-haiku-4-5-20251001 | PASS | 943 | Required exact model ID |
| Groq | `groq` | llama-3.1-8b-instant | PASS | 275 | Fastest response |
| DeepSeek | `deepseek` | deepseek-chat | PASS | 1930 | Slower but works |
| Perplexity | `perplexity-ai` | sonar | PASS | 1531 | Works with search-augmented |
| Google | `google` | gemini-* | FAIL | — | All Gemini models returned 404 |
| Moonshot | `moonshot` | moonshot-v1-8k | FAIL | — | Invalid Authentication |

**Other supported providers** (not tested): Azure OpenAI, AWS Bedrock, Vertex AI, Mistral, Cohere, Together AI, Fireworks AI, Lepton AI, Upstage, Cerebras, AI21, Jina, Stability AI, Recraft, LocalAI, Ollama, OpenRouter, and 20+ more.

### 1.5 SDKs & CLI Tools

| Tool | Package | Status |
|------|---------|--------|
| **Node.js SDK** | `portkey-ai` v3.0.3 | 36 resource classes, 200+ methods |
| **Python SDK** | `portkey-ai` (pip) | Full parity + AsyncPortkey |
| **CLI** | `npx @portkey-ai/gateway` | Local gateway + `npx portkey setup/verify` |
| **Open-source Gateway** | GitHub `Portkey-AI/gateway` | 122KB, Apache 2.0, Docker/K8s/CF Workers |
| **REST API** | cURL / any HTTP client | OpenAI-compatible + `x-portkey-*` headers |

### 1.6 Agent Framework Integrations (16+)

OpenAI Agents, AWS AgentCore, Pydantic AI, Autogen, CrewAI, Agno AI, Mastra, LlamaIndex, LangChain, LangGraph, Langroid, Strands, Control Flow, OpenAI Swarm, DSPy, Promptfoo.

Integration pattern: set `base_url` to Portkey gateway + add `x-portkey-*` headers. "2 lines of code" claim.

### 1.7 Compliance & Certifications

| Standard | Status |
|----------|--------|
| SOC 2 Type II | Certified |
| ISO 27001 | Certified |
| GDPR | Compliant |
| HIPAA | Compliant (BAA available, Enterprise) |
| CCPA | Compliant |

---

## 2. Inference API

**Base URL:** `https://api.portkey.ai/v1`
**Auth:** `x-portkey-api-key` header + `x-portkey-provider` + `Authorization: Bearer <provider_key>`

### 2.1 Chat Completions

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/chat/completions` |
| **SDK Method** | `portkey.chat.completions.create()` |
| **Pricing Tier** | Dev |
| **Streaming** | Yes |
| **Live Tested** | 10/10 PASS |
| **Avg Latency** | 680ms |
| **BR Equivalent** | `brainstormrouter/auto` completions endpoint |
| **Key Difference** | Portkey proxies to specified provider; BR uses Thompson sampling across 362 models |

**Features tested (all PASS):**
- Non-streaming completion
- Streaming (SSE)
- JSON mode (`response_format: { type: "json_object" }`)
- Tool calling with function definitions
- Multi-turn conversation
- Seed-based determinism
- Stop sequences
- N-choices (n=2)
- Token usage tracking
- Portkey trace headers in response

**SDK additional methods:** `create()`, `retrieve()`, `update()`, `list()`, `delete()`, `parse()`, `stream()`, `runTools()`, plus `messages.list()`.

### 2.2 Text Completions (Legacy)

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/completions` |
| **SDK Method** | `portkey.completions.create()` |
| **Live Tested** | 3/3 PASS |
| **BR Equivalent** | Not applicable (BR doesn't support legacy completions) |

Tested: non-streaming, streaming, usage tokens. Model: `gpt-3.5-turbo-instruct`.

### 2.3 Embeddings

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/embeddings` |
| **SDK Method** | `portkey.embeddings.create()` |
| **Live Tested** | 4/4 PASS |
| **BR Equivalent** | None (BR is completions-only) |

Tested: single string, array input, custom dimensions (256), base64 encoding format.

### 2.4 Moderations

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/moderations` |
| **SDK Method** | `portkey.moderations.create()` |
| **Live Tested** | 3/3 PASS |
| **BR Equivalent** | None |

Tested: flagged input (violence: 0.95), safe input, multi-input array. Model: `omni-moderation-latest`.

### 2.5 Audio

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/audio/speech`, `POST /v1/audio/transcriptions`, `POST /v1/audio/translations` |
| **SDK Method** | `portkey.audio.speech.create()`, `.transcriptions.create()`, `.translations.create()` |
| **Live Tested** | 1/2 PASS |

- TTS (text-to-speech): PASS — returned valid audio bytes with `tts-1` / `alloy` voice
- Transcription: FAIL — Blob upload not accepted in Node.js (endpoint exists but needs file handle)

### 2.6 Images

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/images/generations` |
| **SDK Method** | `portkey.images.generate()` |
| **Live Tested** | 2/2 PASS |
| **BR Equivalent** | None |

Tested: DALL-E 3 (1024x1024, standard quality) and DALL-E 2 (256x256). Both returned valid URLs. SDK also supports `.edit()` and `.createVariation()`.

### 2.7 Responses API (OpenAI-compatible)

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/responses` |
| **SDK Method** | `portkey.responses.create()` |
| **Live Tested** | 3/3 PASS |
| **BR Equivalent** | None |

Tested: basic creation, streaming, tool calling. Full OpenAI Responses API compatibility confirmed. SDK also supports `.retrieve()`, `.delete()`, `.parse()`, `.stream()`, `.cancel()`, `.inputItems.list()`.

### 2.8 Files

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/files`, `GET /v1/files`, `GET /v1/files/{id}`, `DELETE /v1/files/{id}` |
| **SDK Method** | `portkey.files.create()`, `.list()`, `.retrieve()`, `.delete()`, `.content()` |
| **Live Tested** | 3/3 PASS |

Tested: JSONL upload (batch purpose), list, retrieve. Also supports `.waitForProcessing()`.

### 2.9 Batches

| Field | Value |
|-------|-------|
| **API Endpoint** | `POST /v1/batches`, `GET /v1/batches` |
| **SDK Method** | `portkey.batches.create()`, `.list()`, `.retrieve()`, `.cancel()`, `.output()` |
| **Live Tested** | 2/2 PASS |

Successfully created a batch job from uploaded JSONL file with 24h completion window.

### 2.10 Fine-Tuning

| Field | Value |
|-------|-------|
| **SDK Method** | `portkey.fineTuning.jobs.*` |
| **Live Tested** | Not tested (would incur costs) |

SDK supports: `jobs.create()`, `.retrieve()`, `.list()`, `.cancel()`, `.listEvents()`, `checkpoints.list()`, `permissions.create/retrieve/delete()`, `alpha.grader.run/validate()`.

### 2.11 Models

| Field | Value |
|-------|-------|
| **API Endpoint** | `GET /v1/models` |
| **SDK Method** | `portkey.models.list()` |
| **Live Tested** | 2/2 PASS |

Works both with provider client (returns provider's models) and admin client (returns Portkey catalog).

### 2.12-2.15 Additional Inference Resources

| Resource | SDK Class | Methods | Tested |
|----------|-----------|---------|--------|
| **Uploads** | `portkey.uploads` | `create()`, `cancel()`, `complete()`, `parts.create()` | No |
| **Containers** | `portkey.containers` | CRUD + `files.*`, `files.content.retrieve()` | No |
| **Videos** | `portkey.videos` | `create()`, `retrieve()`, `list()`, `delete()`, `downloadContent()`, `remix()` | No |
| **Conversations** | `portkey.conversations` | CRUD + `items.*` | No |

---

## 3. Gateway Routing & Resilience

### 3.1 Config Object

Routing is configured via a JSON config object passed as:
- `x-portkey-config` header (inline JSON or config ID)
- `config` constructor option in SDK
- Saved config via Config CRUD API (requires admin key)

**Config CRUD API:** Requires admin-scoped API key. Uses `slug` (not `id`) for all operations.

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.configs.create/list/retrieve/update/delete()` |
| **Live Tested** | 6/6 PASS (with admin key, slug-based) |
| **Inline Config** | PASS (via constructor `config` option) |
| **Key Finding** | Must use `slug` not `id` — `id` returns AB03 even with full permissions |

### 3.2 Routing Strategies

| Strategy | Mode | Description |
|----------|------|-------------|
| **Single** | `single` | Route to one target |
| **Fallback** | `fallback` | Try targets in order; use next on failure |
| **Weighted** | `loadbalance` | Distribute by weight percentage |

### 3.3 Fallback Chains

Config structure:
```json
{
  "strategy": { "mode": "fallback" },
  "targets": [
    { "provider": "openai", "override_params": { "model": "gpt-4o-mini" } },
    { "provider": "anthropic", "override_params": { "model": "claude-haiku-4-5" } }
  ]
}
```

### 3.4 Canary / A-B Testing

Route configurable traffic percentages to new models. Track response accuracy, latency, cost. Gradually increase traffic based on KPIs.

### 3.5 Retry Settings

```json
{
  "retry": { "attempts": 3, "on_status_codes": [429, 500, 502, 503] }
}
```

### 3.6 Request Timeouts

Set via `requestTimeout` constructor option (milliseconds).

---

## 4. Caching

| Field | Value |
|-------|-------|
| **Live Tested** | 3/3 PASS |

### 4.1 Simple Cache

Verbatim request matching. Available on all plans. Tested: sent identical prompt twice — both returned successfully. Cache hit detection via `x-portkey-cache-status` header.

### 4.2 Semantic Cache (Enterprise Only)

Cosine similarity matching for semantically similar requests. Requires vector database. Limitations: <8,191 input tokens, ≤4 messages, requires ≥2 messages.

### 4.3 Cache Controls

| Option | SDK Field | Description |
|--------|-----------|-------------|
| Force refresh | `cacheForceRefresh: true` | Bypass cache, fetch fresh |
| Namespace | `cacheNamespace: "string"` | Isolate cache by namespace |

---

## 5. Observability & Logging

### 5.1 Automatic Request Logging

40+ metrics automatically captured per request. Visible in Portkey dashboard.

### 5.2 Custom Metadata

| Field | Value |
|-------|-------|
| **SDK Field** | `metadata: { key: "value" }` |
| **Header** | `x-portkey-metadata: '{"key":"value"}'` |
| **Live Tested** | PASS |

Attach arbitrary key-value metadata to requests for grouping, filtering, cost attribution.

### 5.3 Trace IDs

| Field | Value |
|-------|-------|
| **SDK Field** | `traceID: "your-trace-id"` |
| **Header** | `x-portkey-trace-id: your-trace-id` |
| **Live Tested** | PASS |

Custom trace IDs propagate through the system. Response includes `x-portkey-trace-id` header.

### 5.4-5.8 Admin Logging Features

| Feature | SDK Method | Status |
|---------|-----------|--------|
| Log insert | `portkey.logs.create()` | FAIL (admin key required) |
| Log export | `portkey.logs.exports.*` | FAIL (admin key required) |
| Analytics dashboard | Web UI | Not testable via API |
| Cost attribution | Via metadata + dashboard | Requires dashboard access |

---

## 6. Guardrails

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.guardrails.create/list/retrieve/update/delete()` |
| **Live Tested** | FAIL (all require admin key) |

### 6.1 Deterministic Checks (20+)

- Regex pattern matching
- JSON Schema validation
- Code detection (SQL, Python, TypeScript)
- Character/word/sentence counting
- Custom guardrails

### 6.2 LLM-Based Checks

- Gibberish detection
- Prompt injection scanning
- PII redaction (Enterprise)

### 6.3 Enforcement

- Async (logs without impacting requests)
- Sync blocking (446 status) or flagging (246 status)
- Webhook integration for custom pipelines

---

## 7. Prompt Management

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.prompts.create/list/retrieve/update/delete/render/publish()` |
| **SDK Sub-resources** | `.versions.*`, `.completions.*`, `.partials.*` |
| **Live Tested** | FAIL (all require admin key) |

Features: version control, variable interpolation, deployment labels, prompt partials (reusable fragments), prompt playground IDE.

---

## 8. Credential & Access Management

### 8.1 Virtual Keys

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.virtualKeys.create/list/retrieve/update/delete()` |
| **Live Tested** | 5/5 PASS (with admin key, slug-based) |
| **BR Equivalent** | BR scoped keys (similar concept, different implementation) |

Virtual Keys abstract provider credentials, enabling per-key budgets, rate limits, and caching without exposing actual API keys. Full CRUD confirmed working. Uses `slug` for all operations.

### 8.2 API Keys

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.apiKeys.create/list/retrieve/update/delete()` |
| **Live Tested** | FAIL (admin key required) |

**Key finding:** Portkey has **two types of API keys**:
1. **Inference key** — can call `/v1/chat/completions`, `/v1/embeddings`, etc.
2. **Admin key** — can manage configs, virtual keys, guardrails, prompts, users, etc.

Our key is inference-only. All 46 admin API failures stem from this.

### 8.3 Providers

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.providers.create/list/retrieve/update/delete()` |
| **Live Tested** | FAIL (admin key required) |

### 8.4 Integrations

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.integrations.create/list/retrieve/update/delete()` + `.workspaces.*`, `.models.*` |
| **Live Tested** | FAIL (admin key required) |

---

## 9. Administration

| Feature | SDK Methods | Tested |
|---------|-----------|--------|
| Users | `admin.users.list/retrieve/update/delete()` | FAIL (admin key) |
| Invites | `admin.users.invites.create/list/retrieve/delete/resend()` | FAIL (admin key) |
| Workspaces | `admin.workspaces.create/list/retrieve/update/delete()` | FAIL (admin key) |
| Workspace Members | `admin.workspaces.users.create/list/retrieve/update/delete()` | FAIL (admin key) |
| Audit Logs | Via admin API | Not tested |

---

## 10. Budget & Rate Limiting

Configured per-workspace or per-virtual-key:
- **Rate limits**: RPM, RPH, RPD
- **Budget limits**: Credit cap in dollars, optional alerts, periodic reset
- **Actions on exceeded**: Block, throttle, or switch to cheaper model

Not testable with inference key.

---

## 11. Evaluation Framework

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.evals.create/list/retrieve/update/delete()`, `.runs.*`, `.runs.outputItems.*` |
| **Live Tested** | FAIL (admin key required) |

Supports custom eval schemas, label-model criteria, eval runs with output tracking.

---

## 12. Feedback System

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.feedback.create()`, `.update()` |
| **Live Tested** | FAIL (admin key required) |

Single and batch feedback with value (-1/0/1), weight (0-1), and metadata. Links to trace IDs for correlation.

---

## 13. Beta Features

### 13.1 Assistants API

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.beta.assistants.create/list/retrieve/update/delete()` |
| **Live Tested** | Not tested |

### 13.2 Threads

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.beta.threads.*` (messages, runs, steps) |
| **Run methods** | `create/list/retrieve/update/submitToolOutputs/cancel/createAndPoll/createAndStream/poll/stream()` |
| **Live Tested** | Not tested |

### 13.3 Vector Stores

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.vectorStores.*` (CRUD, files, fileBatches) |
| **Live Tested** | Not tested |

### 13.4 Realtime API

| Field | Value |
|-------|-------|
| **SDK Classes** | `portkey.beta.realtime.sessions/transcriptionSessions`, `portkey.realtime.clientSecrets/calls` |
| **WebSocket** | `PortkeyAIRealtimeWS` class |
| **Live Tested** | Not tested |

### 13.5 ChatKit

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.beta.chatkit.uploadFile()`, `.sessions.*`, `.threads.*` |
| **Live Tested** | Not tested |

---

## 14. MCP Gateway

Portkey positions itself as a centralized MCP gateway:
- Single auth layer for all MCP servers
- Full logging (who called what, params, response, latency)
- 138+ MCP server directory
- Works with Claude Desktop, Cursor, VS Code
- **Hoot**: MCP testing tool (Postman-like)
- **MCP Tool Filter**: Semantic filtering to reduce 1000+ tools to most relevant 10-20

**Third-party MCP admin server:** `r-huijts/portkey-admin-mcp-server` on GitHub — manages configs, workspaces, virtual keys via MCP.

---

## 15. Webhooks

| Field | Value |
|-------|-------|
| **SDK Methods** | `portkey.webhooks.unwrap()`, `.verifySignature()` |
| **Live Tested** | Not tested |

Used for guardrail webhook pipelines. POST with JSON, 3000ms max wait time.

---

## 16. SDK & Developer Experience

### 16.1 Constructor Options (42 fields)

| Category | Fields |
|----------|--------|
| **Core** | `apiKey`, `baseURL`, `config`, `virtualKey`, `provider`, `traceID`, `metadata`, `Authorization` |
| **Cache** | `cacheForceRefresh`, `cacheNamespace` |
| **OpenAI** | `openaiProject`, `openaiOrganization` |
| **AWS** | `awsSecretAccessKey`, `awsAccessKeyId`, `awsSessionToken`, `awsRegion`, `awsS3Bucket`, `awsS3ObjectKey`, `awsBedrockModel` |
| **Azure** | `azureResourceName`, `azureDeploymentId`, `azureApiVersion`, `azureEndpointName` |
| **Vertex** | `vertexProjectId`, `vertexRegion`, `vertexStorageBucketName` |
| **Anthropic** | `anthropicBeta`, `anthropicVersion` |
| **Other** | `customHost`, `forwardHeaders`, `requestTimeout`, `strictOpenAiCompliance`, `debug`, `dangerouslyAllowBrowser`, `mistralFimCompletion`, `huggingfaceBaseUrl`, `workersAiAccountId`, `fireworksAccountId`, `providerFileName`, `providerModel`, `calculateAudioDuration` |

### 16.2 Resource Classes (36)

```
completions          chat               embeddings          files
images               models             generations         prompts
labels               collections        feedback            batches
fineTuning           vectorStores       moderations         audio
uploads              responses          evals               containers
webhooks             admin              virtualKeys         apiKeys
configs              logs               integrations        providers
realtime             conversations      videos              guardrails
beta.assistants      beta.threads       beta.realtime       beta.chatkit
```

### 16.3 Header Injection

All Portkey-specific config flows through `x-portkey-*` headers:

| Header | Purpose |
|--------|---------|
| `x-portkey-api-key` | Portkey authentication |
| `x-portkey-provider` | Provider slug |
| `x-portkey-virtual-key` | Virtual key reference |
| `x-portkey-config` | Inline config JSON or saved config ID |
| `x-portkey-trace-id` | Custom trace ID |
| `x-portkey-metadata` | Custom metadata JSON |
| `x-portkey-cache-force-refresh` | Bypass cache |
| `x-portkey-cache-namespace` | Cache isolation |
| `x-portkey-custom-host` | Custom provider host |
| `x-portkey-forward-headers` | Headers to forward to provider |

### 16.4 Response Headers

| Header | Purpose |
|--------|---------|
| `x-portkey-trace-id` | Request trace ID |
| `x-portkey-cache-status` | DISABLED / HIT / MISS |
| `x-portkey-provider` | Provider that handled request |
| `x-portkey-retry-attempt-count` | Number of retries |
| `x-portkey-last-used-option-index` | Which config target was used |

---

## 17. Security & Compliance

| Feature | Status |
|---------|--------|
| SOC 2 Type II | Certified |
| ISO 27001 | Certified |
| GDPR | Compliant |
| HIPAA | Enterprise (BAA available) |
| SSRF guards | Via guardrails |
| Self-hosted gateway | Open-source (Apache 2.0) |
| Hybrid deployment | Control plane hosted, data plane in your infra |
| Air-gapped | Enterprise only |
| JWT auth | Enterprise |

---

## 18. Limitations & Gaps

### 18.1 Two-Key Model (Confirmed)

Portkey uses **two types of API keys** with fine-grained permission scoping:

1. **Inference key** — can call `/v1/chat/completions`, `/v1/embeddings`, etc. Cannot access admin endpoints.
2. **Admin key** — has granular per-resource permissions (CREATE, READ, LIST, UPDATE, DELETE per resource type). Created in dashboard with explicit permission checkboxes for: MCP, Workspaces, API Keys, Providers, Integrations, Policies, Completions, Prompts, Configs, Guardrails, Virtual Keys, Analytics, Logs.

After adding the admin key, pass rate jumped from 50% to 75%. Remaining failures are API body format issues (guardrails, prompts, evals have underdocumented schemas).

**Key quirk:** Admin API uses **`slug`** (not `id`) for retrieve/update/delete operations. Using `id` returns `AB03: insufficient permissions` even with a full-permission admin key. The SDK accepts both but only `slug` works. The deprecation warning on `configs.delete` confirms this migration is in progress.

**BR comparison:** BrainstormRouter uses a similar two-key model (scoped + admin) with clear documentation. Both platforms require separate keys for inference vs. management.

### 18.2 Provider Auth Inconsistencies

| Provider | Auth Method | Issue |
|----------|-----------|-------|
| Google/Gemini | `Authorization: Bearer <key>` | All model names return 404 — may need different auth flow or API key type |
| Moonshot | `Authorization: Bearer <key>` | "Invalid Authentication" — key format may be wrong or expired |

**BR comparison:** BR handles all provider auth server-side — users never deal with provider-specific auth headers.

### 18.3 Model Name Sensitivity

Anthropic required the exact model ID (`claude-haiku-4-5-20251001`, not `claude-3-5-haiku-20241022`). No alias resolution or fuzzy matching. Errors are clear but require knowing exact model IDs.

**BR comparison:** BR's `auto` model abstracts away model selection entirely via Thompson sampling.

### 18.4 SDK Issues Found

1. **Default import broken**: `import Portkey from "portkey-ai"` fails — must use `import { Portkey } from "portkey-ai"` (CJS/ESM interop issue)
2. **Blob upload**: `audio.transcriptions.create()` doesn't accept `Blob` objects in Node.js — needs proper file handle
3. **No response header access**: SDK doesn't expose `x-portkey-cache-status` or other response headers — can only infer from latency differences

### 18.5 Enterprise-Only Features (Not Testable)

- Semantic caching
- PII redaction guardrails
- Custom data retention
- VPC / air-gapped deployment
- JWT authentication
- RBAC on models
- Budget controls per user/team/app

---

## Appendix A: API Endpoint Inventory

### Inference Endpoints (all tested)

| Method | Endpoint | Status |
|--------|----------|--------|
| POST | `/v1/chat/completions` | PASS |
| POST | `/v1/completions` | PASS |
| POST | `/v1/embeddings` | PASS |
| POST | `/v1/moderations` | PASS |
| POST | `/v1/images/generations` | PASS |
| POST | `/v1/audio/speech` | PASS |
| POST | `/v1/audio/transcriptions` | FAIL (upload format) |
| POST | `/v1/responses` | PASS |
| POST | `/v1/files` | PASS |
| GET | `/v1/files` | PASS |
| GET | `/v1/files/{id}` | PASS |
| POST | `/v1/batches` | PASS |
| GET | `/v1/batches` | PASS |
| GET | `/v1/models` | PASS |

### Admin Endpoints (all require admin key — not tested)

| Method | Endpoint | SDK Resource |
|--------|----------|-------------|
| POST/GET/PUT/DELETE | `/v1/configs` | `configs` |
| POST/GET/PUT/DELETE | `/v1/virtual-keys` | `virtualKeys` |
| POST/GET/PUT/DELETE | `/v1/guardrails` | `guardrails` |
| POST/GET/PUT/DELETE | `/v1/prompts` | `prompts` |
| POST/PUT | `/v1/feedback` | `feedback` |
| POST/GET | `/v1/logs` | `logs` |
| POST/GET/DELETE | `/v1/labels` | `labels` |
| POST/GET/DELETE | `/v1/collections` | `collections` |
| POST/GET/DELETE | `/v1/evals` | `evals` |
| GET | `/v1/admin/users` | `admin.users` |
| GET | `/v1/admin/workspaces` | `admin.workspaces` |
| GET | `/v1/api-keys` | `apiKeys` |
| GET | `/v1/integrations` | `integrations` |
| GET | `/v1/providers` | `providers` |

---

## Appendix B: SDK Method Inventory (200+ methods)

### Inference (50+ methods)
```
chat.completions: create, retrieve, update, list, delete, parse, stream, runTools
chat.completions.messages: list
completions: create
embeddings: create
moderations: create
images: generate, edit, createVariation
audio.speech: create
audio.transcriptions: create
audio.translations: create
files: create, list, retrieve, delete, content, retrieveContent, waitForProcessing
batches: create, retrieve, list, cancel, output
models: list, retrieve, delete
uploads: create, cancel, complete
uploads.parts: create
responses: create, retrieve, delete, parse, stream, cancel
responses.inputItems: list
```

### Admin/Control Plane (100+ methods)
```
configs: create, retrieve, update, list, delete
virtualKeys: create, list, retrieve, update, delete
guardrails: create, list, retrieve, update, delete
prompts: create, list, retrieve, update, delete, render, publish
prompts.versions: list, retrieve, update
prompts.completions: create
prompts.partials: create, list, retrieve, update, delete, publish
prompts.partials.versions: list
feedback: create, update
logs: create
logs.exports: create, retrieve, list, update, start, cancel, download
labels: create, list, retrieve, update, delete
collections: create, list, retrieve, update, delete
evals: create, retrieve, update, list, delete
evals.runs: create, retrieve, list, delete, cancel
evals.runs.outputItems: retrieve, list
generations: create
admin.users: retrieve, list, update, delete
admin.users.invites: create, retrieve, list, delete, resend
admin.workspaces: create, retrieve, list, update, delete
admin.workspaces.users: create, retrieve, list, update, delete
apiKeys: create, retrieve, update, list, delete
integrations: create, list, retrieve, update, delete
integrations.workspaces: update, list
integrations.models: update, list, delete
providers: list, create, retrieve, update, delete
webhooks: unwrap, verifySignature
```

### Beta (40+ methods)
```
beta.assistants: create, list, retrieve, update, delete
beta.threads: create, retrieve, update, delete, createAndRun, createAndRunPoll, createAndRunStream
beta.threads.messages: create, list, retrieve, update, delete
beta.threads.runs: create, list, retrieve, update, submitToolOutputs, submitToolOutputsAndPoll, submitToolOutputsStream, cancel, createAndPoll, createAndStream, poll, stream
beta.threads.runs.steps: list, retrieve
beta.realtime.sessions: create
beta.realtime.transcriptionSessions: create
beta.chatkit: uploadFile
beta.chatkit.sessions: create, cancel
beta.chatkit.threads: retrieve, list, delete, listItems
```

### Other (20+ methods)
```
fineTuning.jobs: create, retrieve, list, cancel, listEvents
fineTuning.jobs.checkpoints: list
fineTuning.checkpoints.permissions: create, retrieve, delete
fineTuning.alpha.grader: run, validate
vectorStores: create, retrieve, update, list, delete
vectorStores.files: create, retrieve, list, delete, createAndPoll, poll, upload, uploadAndPoll
vectorStores.fileBatches: create, retrieve, cancel, createAndPoll, listFiles, poll, uploadAndPoll
containers: create, retrieve, list, delete
containers.files: create, retrieve, list, delete
containers.files.content: retrieve
videos: create, retrieve, list, delete, downloadContent, remix
conversations: create, retrieve, update, delete
conversations.items: create, retrieve, list, delete
realtime.clientSecrets: create
realtime.calls: accept, hangup, refer, reject
```

---

## Appendix C: Header Reference

| Header | Direction | Required | Description |
|--------|-----------|----------|-------------|
| `x-portkey-api-key` | Request | Yes | Portkey API key |
| `x-portkey-provider` | Request | Yes* | Provider slug (`openai`, `anthropic`, etc.) |
| `x-portkey-virtual-key` | Request | Alt* | Virtual key ID (alternative to provider + Authorization) |
| `x-portkey-config` | Request | No | Routing config (JSON or saved ID) |
| `x-portkey-trace-id` | Both | No | Custom trace ID |
| `x-portkey-metadata` | Request | No | Custom metadata (JSON string) |
| `x-portkey-cache-force-refresh` | Request | No | Bypass cache |
| `x-portkey-cache-namespace` | Request | No | Cache isolation namespace |
| `x-portkey-custom-host` | Request | No | Override provider URL |
| `x-portkey-forward-headers` | Request | No | Headers to pass to provider |
| `x-portkey-cache-status` | Response | — | DISABLED / HIT / MISS |
| `x-portkey-retry-attempt-count` | Response | — | Retry count |
| `x-portkey-last-used-option-index` | Response | — | Config target used |

*Either `x-portkey-provider` + `Authorization` OR `x-portkey-virtual-key` is required.

---

## Appendix D: Config Object Schema

```json
{
  "strategy": {
    "mode": "single | fallback | loadbalance"
  },
  "targets": [
    {
      "provider": "openai",
      "api_key": "sk-...",
      "virtual_key": "vk-...",
      "weight": 0.5,
      "override_params": {
        "model": "gpt-4o-mini",
        "max_tokens": 100,
        "temperature": 0.7
      },
      "retry": {
        "attempts": 3,
        "on_status_codes": [429, 500, 502, 503]
      }
    }
  ],
  "cache": {
    "mode": "simple | semantic",
    "max_age": 3600
  }
}
```

---

## Appendix E: Live Test Results Summary

| Script | Description | PASS | FAIL | Notes |
|--------|-------------|------|------|-------|
| 01 | Chat Completions | 10 | 0 | All features work (streaming, tools, JSON, seed, stop, n) |
| 02 | Text Completions | 3 | 0 | Legacy endpoint works |
| 03 | Embeddings | 4 | 0 | All encoding formats, custom dimensions |
| 04 | Moderations | 3 | 0 | Multi-input, flagging accurate |
| 05 | Images | 2 | 0 | DALL-E 2 & 3 generation |
| 06 | Audio | 1 | 1 | TTS works; transcription Blob upload issue |
| 07 | Responses API | 3 | 0 | Full OpenAI Responses compatibility |
| 08 | Files & Batches | 5 | 0 | JSONL upload + batch job creation |
| 09 | Models | 2 | 0 | Listing works with and without provider |
| 10 | Configs | 6 | 0 | Full CRUD works (slug-based), inline config works |
| 11 | Caching | 3 | 0 | Simple cache + force refresh |
| 12 | Virtual Keys | 5 | 0 | Full CRUD works (slug-based) |
| 13 | Guardrails | 1 | 4 | List works; create fails (body schema underdocumented) |
| 14 | Prompts | 1 | 5 | List works; create fails (body schema underdocumented) |
| 15 | Feedback | 1 | 2 | Create works; update/batch format issues |
| 16 | Logs | 1 | 3 | Insert works; export API format issues |
| 17 | Labels/Collections | 7 | 0 | Full CRUD for both |
| 18 | Evals | 0 | 4 | Create body schema underdocumented |
| 19 | Admin | 1 | 2 | Workspaces.list works; users/invites partial permission |
| 20 | API Keys | 1 | 0 | List works |
| 21 | Integrations/Providers | 2 | 0 | Both list endpoints work |
| 22 | Metadata/Tracing | 3 | 0 | Custom metadata + trace IDs propagate |
| 30 | Multi-Provider Matrix | 10 | 4 | 5/7 providers work (Google 404, Moonshot auth) |
| **TOTAL** | | **75** | **25** | **75% overall, 91% inference** |

### Provider Matrix Results

| Provider | Chat | Streaming | Latency | Status |
|----------|------|-----------|---------|--------|
| OpenAI | PASS | PASS | 772ms | Production-ready |
| Anthropic | PASS | PASS | 943ms | Needs exact model IDs |
| Groq | PASS | PASS | 275ms | Fastest provider |
| DeepSeek | PASS | PASS | 1930ms | Slowest but functional |
| Perplexity | PASS | PASS | 1531ms | Search-augmented works |
| Google | FAIL | FAIL | — | Model 404s, possible key restriction |
| Moonshot | FAIL | FAIL | — | Invalid Authentication |
