// Shared setup for BrainstormRouter autopsy test scripts
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

export const BR_BASE_URL = "https://api.brainstormrouter.com";
export const BR_API_KEY = opRead("op://Dev Keys/BrainstormRouter API Key/credential");
export const BR_ADMIN_KEY = opRead("op://Dev Keys/BrainstormRouter Admin Key/credential");

// HTTP helper — BR uses standard REST, not OpenAI SDK
export async function brFetch(path, { method = "GET", body, auth = "scoped", headers = {} } = {}) {
  const key = auth === "admin" ? BR_ADMIN_KEY : BR_API_KEY;
  const url = path.startsWith("http") ? path : `${BR_BASE_URL}${path}`;
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(key ? { Authorization: `Bearer ${key}` } : {}),
      ...headers,
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}: ${typeof data === "string" ? data.slice(0, 200) : JSON.stringify(data).slice(0, 200)}`);
  }
  return { status: res.status, headers: Object.fromEntries(res.headers.entries()), data };
}

// OpenAI-compatible completions endpoint
export async function brComplete(model, messages, { max_tokens = 30, stream = false, auth = "scoped", ...extra } = {}) {
  return brFetch("/v1/chat/completions", {
    method: "POST",
    auth,
    body: { model, messages, max_tokens, stream, ...extra },
  });
}

// Test harness (same pattern as Portkey)
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
    if (msg.includes("402") || msg.includes("403") || msg.includes("insufficient_permissions")) {
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
    platform: "brainstormrouter",
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
