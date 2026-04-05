// Shared setup for OpenRouter autopsy test scripts
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = join(__dirname, "results");
mkdirSync(RESULTS_DIR, { recursive: true });

function opRead(ref) {
  try {
    return execFileSync("op", ["read", ref], { encoding: "utf-8" }).trim();
  } catch (e) {
    console.warn(`[WARN] Could not read ${ref}: ${e.message}`);
    return null;
  }
}

export const OR_BASE_URL = "https://openrouter.ai/api/v1";
export const OR_API_KEY = opRead("op://Dev Keys/OpenRouter API Key/credential");

export async function orFetch(path, { method = "GET", body, headers = {} } = {}) {
  const url = path.startsWith("http") ? path : `${OR_BASE_URL}${path}`;
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OR_API_KEY}`,
      "HTTP-Referer": "https://openclaw.dev",
      "X-OpenRouter-Title": "OpenClaw Autopsy",
      ...headers,
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) {
    throw new Error(`${res.status}: ${typeof data === "string" ? data.slice(0, 200) : JSON.stringify(data).slice(0, 200)}`);
  }
  return { status: res.status, headers: Object.fromEntries(res.headers.entries()), data };
}

export async function orComplete(model, messages, extra = {}) {
  return orFetch("/chat/completions", {
    method: "POST",
    body: { model, messages, max_tokens: 30, ...extra },
  });
}

const _results = [];

export async function test(name, fn) {
  const start = Date.now();
  const entry = { name, status: "SKIP", latency_ms: 0, notes: "", response_preview: null };
  try {
    const result = await fn();
    entry.status = "PASS";
    entry.latency_ms = Date.now() - start;
    if (result !== undefined) {
      entry.response_preview = typeof result === "string" ? result.slice(0, 200) : JSON.stringify(result).slice(0, 200);
    }
  } catch (e) {
    entry.latency_ms = Date.now() - start;
    const msg = e.message || String(e);
    if (msg.includes("402") || msg.includes("Payment")) {
      entry.status = "TIER_RESTRICTED";
    } else if (msg.includes("403")) {
      entry.status = "TIER_RESTRICTED";
    } else {
      entry.status = "FAIL";
    }
    entry.notes = msg.slice(0, 300);
  }
  _results.push(entry);
  const icon = { PASS: "✓", FAIL: "✗", SKIP: "○", TIER_RESTRICTED: "⊘" }[entry.status];
  console.log(`  ${icon} ${entry.status.padEnd(16)} ${entry.latency_ms.toString().padStart(5)}ms  ${name}`);
  return entry;
}

export function writeResults(scriptName) {
  const output = {
    script: scriptName,
    timestamp: new Date().toISOString(),
    platform: "openrouter",
    tests: [..._results],
  };
  const path = join(RESULTS_DIR, `${scriptName}.json`);
  writeFileSync(path, JSON.stringify(output, null, 2));
  _results.length = 0;
  const pass = output.tests.filter(t => t.status === "PASS").length;
  const fail = output.tests.filter(t => t.status === "FAIL").length;
  const skip = output.tests.filter(t => t.status === "SKIP").length;
  const tier = output.tests.filter(t => t.status === "TIER_RESTRICTED").length;
  console.log(`\n  Results: ${pass} PASS, ${fail} FAIL, ${skip} SKIP, ${tier} TIER_RESTRICTED → ${path}\n`);
  return output;
}
