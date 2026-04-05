// 01: Auth probes + Gateway availability
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
const CF_TOKEN = opRead("op://Dev Keys/Cloudflare Scoped Token/credential");
const CF_GLOBAL = opRead("op://Dev Keys/Cloudflare Global API Key/credential");
const OPENAI_KEY = opRead("op://Dev Keys/OpenAI API Key/credential");

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
    entry.status = e.message?.includes("403") || e.message?.includes("10000") ? "TIER_RESTRICTED" : "FAIL";
    entry.notes = (e.message || String(e)).slice(0, 300);
  }
  _results.push(entry);
  const icon = { PASS: "✓", FAIL: "✗", SKIP: "○", TIER_RESTRICTED: "⊘" }[entry.status];
  console.log(`  ${icon} ${entry.status.padEnd(16)} ${entry.latency_ms.toString().padStart(5)}ms  ${name}`);
}

console.log("\n═══ 01: Auth & Gateway Probes ═══\n");

// Token verification
await test("scoped token verify", async () => {
  const r = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
    headers: { Authorization: `Bearer ${CF_TOKEN}` },
  });
  const d = await r.json();
  if (!d.success) throw new Error(JSON.stringify(d.errors));
  return { status: d.result.status };
});

// List gateways with scoped token
await test("list gateways (scoped token)", async () => {
  const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${CF_ACCT}/ai-gateway/gateways`, {
    headers: { Authorization: `Bearer ${CF_TOKEN}`, "Content-Type": "application/json" },
  });
  const d = await r.json();
  if (!d.success) throw new Error(`${d.errors[0]?.code}: ${d.errors[0]?.message}`);
  return d.result;
});

// List gateways with global key (Bearer)
await test("list gateways (global key as Bearer)", async () => {
  const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${CF_ACCT}/ai-gateway/gateways`, {
    headers: { Authorization: `Bearer ${CF_GLOBAL}`, "Content-Type": "application/json" },
  });
  const d = await r.json();
  if (!d.success) throw new Error(`${d.errors[0]?.code}: ${d.errors[0]?.message}`);
  return d.result;
});

// Create gateway
await test("create gateway 'openclaw-autopsy'", async () => {
  const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${CF_ACCT}/ai-gateway/gateways`, {
    method: "POST",
    headers: { Authorization: `Bearer ${CF_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ id: "openclaw-autopsy", name: "OpenClaw Autopsy" }),
  });
  const d = await r.json();
  if (!d.success) throw new Error(`${d.errors[0]?.code}: ${d.errors[0]?.message}`);
  return d.result;
});

// Test gateway proxy (default)
await test("proxy: default gateway → OpenAI", async () => {
  const r = await fetch(`https://gateway.ai.cloudflare.com/v1/${CF_ACCT}/default/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Hi" }], max_tokens: 5 }),
  });
  const d = await r.json();
  if (d.error || d.errors) throw new Error(JSON.stringify(d.error || d.errors));
  return { model: d.model, content: d.choices?.[0]?.message?.content };
});

// Test gateway proxy (openclaw-autopsy)
await test("proxy: openclaw-autopsy gateway → OpenAI", async () => {
  const r = await fetch(`https://gateway.ai.cloudflare.com/v1/${CF_ACCT}/openclaw-autopsy/openai/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Hi" }], max_tokens: 5 }),
  });
  const d = await r.json();
  if (d.error || d.errors) throw new Error(JSON.stringify(d.error || d.errors));
  return { model: d.model, content: d.choices?.[0]?.message?.content };
});

// Unified compat endpoint
await test("unified endpoint (compat)", async () => {
  const r = await fetch(`https://gateway.ai.cloudflare.com/v1/${CF_ACCT}/openclaw-autopsy/compat/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: "openai/gpt-4o-mini", messages: [{ role: "user", content: "Hi" }], max_tokens: 5 }),
  });
  const d = await r.json();
  if (d.error || d.errors) throw new Error(JSON.stringify(d.error || d.errors));
  return { model: d.model, content: d.choices?.[0]?.message?.content };
});

// Custom metadata
await test("custom metadata header", async () => {
  const r = await fetch(`https://gateway.ai.cloudflare.com/v1/${CF_ACCT}/openclaw-autopsy/openai/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_KEY}`,
      "cf-aig-metadata": JSON.stringify({ env: "test", script: "01" }),
    },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Hi" }], max_tokens: 5 }),
  });
  const d = await r.json();
  if (d.error || d.errors) throw new Error(JSON.stringify(d.error || d.errors));
  return { model: d.model, step: r.headers?.get("cf-aig-step") };
});

// Write results
const output = { script: "01-auth-gateway", timestamp: new Date().toISOString(), platform: "cloudflare-ai-gateway", tests: _results };
writeFileSync(join(__dirname, "results/01-auth-gateway.json"), JSON.stringify(output, null, 2));
const pass = _results.filter(t => t.status === "PASS").length;
const fail = _results.filter(t => t.status === "FAIL").length;
const tier = _results.filter(t => t.status === "TIER_RESTRICTED").length;
console.log(`\n  Results: ${pass} PASS, ${fail} FAIL, 0 SKIP, ${tier} TIER_RESTRICTED\n`);
