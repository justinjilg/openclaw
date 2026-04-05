// 02: Full CF AI Gateway test suite — now that gateway is provisioned
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(__dirname, "results"), { recursive: true });

function opRead(ref) {
  try { return execFileSync("op", ["read", ref], { encoding: "utf-8" }).trim(); } catch { return null; }
}

const CF_ACCT = opRead("op://Dev Keys/Cloudflare Account ID/credential");
const CF_KEY = opRead("op://Dev Keys/Cloudflare Global API Key/credential");
const CF_EMAIL = "justin.jilg@gmail.com";
const OPENAI_KEY = opRead("op://Dev Keys/OpenAI API Key/credential");
const ANTHROPIC_KEY = opRead("op://Dev Keys/Anthropic API Key/credential");
const GROQ_KEY = opRead("op://Dev Keys/Groq API Key/credential");
const DEEPSEEK_KEY = opRead("op://Dev Keys/DeepSeek API Key/credential");

const GW = `https://gateway.ai.cloudflare.com/v1/${CF_ACCT}/openclaw-autopsy`;
const CF_API = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCT}/ai-gateway`;

const _results = [];
async function test(name, fn) {
  const start = Date.now();
  const entry = { name, status: "SKIP", latency_ms: 0, notes: "", response_preview: null };
  try {
    const result = await fn();
    entry.status = "PASS";
    entry.latency_ms = Date.now() - start;
    if (result !== undefined) entry.response_preview = JSON.stringify(result).slice(0, 200);
  } catch (e) {
    entry.latency_ms = Date.now() - start;
    entry.status = "FAIL";
    entry.notes = (e.message || String(e)).slice(0, 300);
  }
  _results.push(entry);
  const icon = { PASS: "✓", FAIL: "✗", SKIP: "○" }[entry.status];
  console.log(`  ${icon} ${entry.status.padEnd(16)} ${entry.latency_ms.toString().padStart(5)}ms  ${name}`);
}

async function cfAdmin(path, opts = {}) {
  const r = await fetch(`${CF_API}${path}`, {
    ...opts,
    headers: { "X-Auth-Key": CF_KEY, "X-Auth-Email": CF_EMAIL, "Content-Type": "application/json", ...opts.headers },
  });
  return r.json();
}

console.log("\n═══ 02: Full CF AI Gateway Test Suite ═══\n");

// --- Management API ---
console.log("  --- Management API ---\n");

await test("mgmt: list gateways", async () => {
  const d = await cfAdmin("/gateways");
  return { count: d.result?.length, gateways: d.result?.map(g => g.id) };
});

await test("mgmt: get gateway details", async () => {
  const d = await cfAdmin("/gateways/openclaw-autopsy");
  return { id: d.result?.id, cache_ttl: d.result?.cache_ttl, rate_limit: d.result?.rate_limiting_limit };
});

await test("mgmt: update gateway", async () => {
  const d = await cfAdmin("/gateways/openclaw-autopsy", {
    method: "PUT",
    body: JSON.stringify({
      id: "openclaw-autopsy",
      name: "OpenClaw Autopsy (Updated)",
      collect_logs: true,
      rate_limiting_interval: 60,
      rate_limiting_limit: 200,
      rate_limiting_technique: "fixed",
      cache_ttl: 600,
      cache_invalidate_on_update: true,
    }),
  });
  return { success: d.success, new_limit: d.result?.rate_limiting_limit };
});

// --- Provider Proxying ---
console.log("\n  --- Provider Proxying ---\n");

await test("proxy: OpenAI chat", async () => {
  const r = await fetch(`${GW}/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Say hi in one word." }], max_tokens: 10 }),
  });
  const d = await r.json();
  return { model: d.model, content: d.choices[0].message.content, step: r.headers.get("cf-aig-step") };
});

await test("proxy: OpenAI streaming", async () => {
  const r = await fetch(`${GW}/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Count to 3." }], max_tokens: 20, stream: true }),
  });
  const text = await r.text();
  const chunks = text.split("\n").filter(l => l.startsWith("data: "));
  return { chunks: chunks.length, streaming: true };
});

await test("proxy: Anthropic messages", async () => {
  const r = await fetch(`${GW}/anthropic/v1/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: "claude-haiku-4-5-20251001", messages: [{ role: "user", content: "Say hi." }], max_tokens: 10 }),
  });
  const d = await r.json();
  return { model: d.model, content: d.content?.[0]?.text, stop: d.stop_reason };
});

await test("proxy: Groq chat", async () => {
  const r = await fetch(`${GW}/groq/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${GROQ_KEY}` },
    body: JSON.stringify({ model: "llama-3.1-8b-instant", messages: [{ role: "user", content: "Say hi." }], max_tokens: 10 }),
  });
  const d = await r.json();
  return { model: d.model, content: d.choices?.[0]?.message?.content };
});

await test("proxy: DeepSeek chat", async () => {
  const r = await fetch(`${GW}/deepseek/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${DEEPSEEK_KEY}` },
    body: JSON.stringify({ model: "deepseek-chat", messages: [{ role: "user", content: "Say hi." }], max_tokens: 10 }),
  });
  const d = await r.json();
  return { model: d.model, content: d.choices?.[0]?.message?.content };
});

// --- Unified Compat Endpoint ---
console.log("\n  --- Unified Endpoint ---\n");

await test("unified: openai/gpt-4o-mini", async () => {
  const r = await fetch(`${GW}/compat/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "openai/gpt-4o-mini", messages: [{ role: "user", content: "Hi" }], max_tokens: 5 }),
  });
  const d = await r.json();
  if (d.error || d.errors) throw new Error(JSON.stringify(d.error || d.errors));
  return { model: d.model, content: d.choices?.[0]?.message?.content };
});

// --- Caching ---
console.log("\n  --- Caching ---\n");

const cacheMsg = [{ role: "user", content: `CF cache test ${Date.now()}: say "cached"` }];

await test("cache: first request (miss)", async () => {
  const r = await fetch(`${GW}/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: cacheMsg, max_tokens: 10 }),
  });
  const d = await r.json();
  return { content: d.choices[0].message.content, cache: r.headers.get("cf-cache-status") || r.headers.get("cf-aig-cache-status") };
});

await test("cache: second identical request (hit?)", async () => {
  const r = await fetch(`${GW}/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: cacheMsg, max_tokens: 10 }),
  });
  const d = await r.json();
  return { content: d.choices[0].message.content, cache: r.headers.get("cf-cache-status") || r.headers.get("cf-aig-cache-status") };
});

// --- Custom Metadata ---
console.log("\n  --- Metadata & Headers ---\n");

await test("custom metadata header", async () => {
  const r = await fetch(`${GW}/openai/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_KEY}`,
      "cf-aig-metadata": JSON.stringify({ env: "test", script: "02", user: "autopsy" }),
    },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Hi" }], max_tokens: 5 }),
  });
  const d = await r.json();
  return { content: d.choices[0].message.content, step: r.headers.get("cf-aig-step") };
});

// --- Tool Calling ---
console.log("\n  --- Tool Calling ---\n");

await test("tool calling via proxy", async () => {
  const r = await fetch(`${GW}/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "What's the weather in Tokyo?" }],
      max_tokens: 50,
      tools: [{ type: "function", function: { name: "get_weather", description: "Get weather", parameters: { type: "object", properties: { location: { type: "string" } }, required: ["location"] } } }],
    }),
  });
  const d = await r.json();
  const tc = d.choices[0].message.tool_calls;
  return { tool_calls: tc?.length, name: tc?.[0]?.function?.name };
});

// --- JSON Mode ---
await test("JSON mode via proxy", async () => {
  const r = await fetch(`${GW}/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [{ role: "system", content: "Respond with JSON only." }, { role: "user", content: 'Return {"color":"blue"}' }],
      max_tokens: 30,
      response_format: { type: "json_object" },
    }),
  });
  const d = await r.json();
  return { content: d.choices[0].message.content };
});

// --- Cleanup: delete gateway ---
console.log("\n  --- Cleanup ---\n");

await test("mgmt: delete gateway", async () => {
  const d = await cfAdmin("/gateways/openclaw-autopsy", { method: "DELETE" });
  return { success: d.success };
});

// Write results
const output = { script: "02-full-test", timestamp: new Date().toISOString(), platform: "cloudflare-ai-gateway", tests: _results };
writeFileSync(join(__dirname, "results/02-full-test.json"), JSON.stringify(output, null, 2));
const pass = _results.filter(t => t.status === "PASS").length;
const fail = _results.filter(t => t.status === "FAIL").length;
console.log(`\n  Results: ${pass} PASS, ${fail} FAIL → results/02-full-test.json\n`);
