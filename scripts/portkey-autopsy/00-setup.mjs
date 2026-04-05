// Shared setup for all Portkey autopsy test scripts
// Reads all provider keys from 1Password, exports clients and test harness

import { Portkey } from "portkey-ai";
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = join(__dirname, "results");
mkdirSync(RESULTS_DIR, { recursive: true });

// --- 1Password secret reader ---
function opRead(ref) {
  try {
    return execFileSync("op", ["read", ref], { encoding: "utf-8" }).trim();
  } catch (e) {
    console.warn(`[WARN] Could not read ${ref}: ${e.message}`);
    return null;
  }
}

// --- Load all keys ---
export const PORTKEY_API_KEY = opRead("op://Dev Keys/Portkey AI API Key/credential");

const PROVIDER_KEYS = {
  openai:        opRead("op://Dev Keys/OpenAI API Key/credential"),
  anthropic:     opRead("op://Dev Keys/Anthropic API Key/credential"),
  google:        opRead("op://Dev Keys/Gemini API Key/credential"),
  groq:          opRead("op://Dev Keys/Groq API Key/credential"),
  deepseek:      opRead("op://Dev Keys/DeepSeek API Key/credential"),
  moonshot:      opRead("op://Dev Keys/Moonshot API Key/credential"),
  "perplexity-ai": opRead("op://Dev Keys/Perplexity API Key/credential"),
};

// --- Provider registry ---
export const PROVIDERS = {
  openai: {
    slug: "openai",
    model: "gpt-4o-mini",
    key: PROVIDER_KEYS.openai,
    capabilities: ["chat", "completions", "embeddings", "moderations", "images", "audio", "files", "batches", "fine-tuning", "assistants", "threads", "vector-stores", "responses", "tools", "vision", "streaming", "structured-output"],
  },
  anthropic: {
    slug: "anthropic",
    model: "claude-haiku-4-5-20251001",
    key: PROVIDER_KEYS.anthropic,
    capabilities: ["chat", "streaming", "tools", "vision", "structured-output"],
  },
  google: {
    slug: "google",
    model: "gemini-1.5-flash",
    key: PROVIDER_KEYS.google,
    capabilities: ["chat", "embeddings", "streaming", "tools", "vision", "structured-output"],
  },
  groq: {
    slug: "groq",
    model: "llama-3.1-8b-instant",
    key: PROVIDER_KEYS.groq,
    capabilities: ["chat", "streaming", "tools"],
  },
  deepseek: {
    slug: "deepseek",
    model: "deepseek-chat",
    key: PROVIDER_KEYS.deepseek,
    capabilities: ["chat", "streaming", "tools", "structured-output"],
  },
  moonshot: {
    slug: "moonshot",
    model: "moonshot-v1-8k",
    key: PROVIDER_KEYS.moonshot,
    capabilities: ["chat", "streaming"],
  },
  "perplexity-ai": {
    slug: "perplexity-ai",
    model: "sonar",
    key: PROVIDER_KEYS["perplexity-ai"],
    capabilities: ["chat", "streaming"],
  },
};

// --- Client factories ---
export function createClient(providerSlug, providerKey) {
  return new Portkey({
    apiKey: PORTKEY_API_KEY,
    provider: providerSlug,
    Authorization: `Bearer ${providerKey}`,
  });
}

export function createVKeyClient(virtualKeyId) {
  return new Portkey({
    apiKey: PORTKEY_API_KEY,
    virtualKey: virtualKeyId,
  });
}

// Default client (OpenAI)
export const portkey = createClient("openai", PROVIDER_KEYS.openai);

// Admin client (uses admin-scoped key for control plane APIs)
const PORTKEY_ADMIN_KEY = opRead("op://Dev Keys/Portkey AI Admin Key/credential");
export const adminClient = new Portkey({ apiKey: PORTKEY_ADMIN_KEY || PORTKEY_API_KEY });

// --- Test harness ---
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
    if (msg.includes("402") || msg.includes("upgrade") || msg.includes("tier")) {
      entry.status = "TIER_RESTRICTED";
    } else if (msg.includes("403") || msg.includes("insufficient_permissions")) {
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
    sdk_version: "3.0.3",
    tests: [..._results],
  };
  const path = join(RESULTS_DIR, `${scriptName}.json`);
  writeFileSync(path, JSON.stringify(output, null, 2));
  _results.length = 0; // reset for next script if imported multiple times

  const pass = output.tests.filter(t => t.status === "PASS").length;
  const fail = output.tests.filter(t => t.status === "FAIL").length;
  const skip = output.tests.filter(t => t.status === "SKIP").length;
  const tier = output.tests.filter(t => t.status === "TIER_RESTRICTED").length;
  console.log(`\n  Results: ${pass} PASS, ${fail} FAIL, ${skip} SKIP, ${tier} TIER_RESTRICTED → ${path}\n`);
  return output;
}
