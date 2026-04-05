// 08: API Surface Probe — discover all endpoints
import { brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 08: API Surface Probe ═══\n");

// Probe every endpoint mentioned in CLAUDE.md + memory
const endpoints = [
  // Known working
  { path: "/health", auth: "none", method: "GET" },
  { path: "/v1/agent/profiles", auth: "admin", method: "GET" },
  { path: "/v1/usage/by-cost-center", auth: "admin", method: "GET" },
  { path: "/v1/agent/limits", auth: "admin", method: "GET" },
  // Probe for additional endpoints
  { path: "/v1/providers", auth: "admin", method: "GET" },
  { path: "/v1/providers/catalog", auth: "admin", method: "GET" },
  { path: "/v1/tenants", auth: "admin", method: "GET" },
  { path: "/v1/tenants/current", auth: "admin", method: "GET" },
  { path: "/v1/keys", auth: "admin", method: "GET" },
  { path: "/v1/keys/list", auth: "admin", method: "GET" },
  { path: "/v1/config", auth: "admin", method: "GET" },
  { path: "/v1/settings", auth: "admin", method: "GET" },
  { path: "/v1/audit-log", auth: "admin", method: "GET" },
  { path: "/v1/webhooks", auth: "admin", method: "GET" },
  { path: "/v1/alerts", auth: "admin", method: "GET" },
  { path: "/v1/budgets", auth: "admin", method: "GET" },
  { path: "/v1/sessions", auth: "admin", method: "GET" },
  { path: "/v1/memory", auth: "admin", method: "GET" },
  { path: "/v1/memory/list", auth: "admin", method: "GET" },
  { path: "/v1/agent/bootstrap", auth: "admin", method: "GET" },
  { path: "/v1/agent/status", auth: "admin", method: "GET" },
  { path: "/v1/embeddings", auth: "scoped", method: "POST" },
  { path: "/v1/images/generations", auth: "scoped", method: "POST" },
  { path: "/v1/moderations", auth: "scoped", method: "POST" },
  { path: "/v1/audio/speech", auth: "scoped", method: "POST" },
];

for (const ep of endpoints) {
  await test(`${ep.method} ${ep.path} (${ep.auth})`, async () => {
    try {
      const body = ep.method === "POST" ? { model: "test", input: "test" } : undefined;
      const res = await fetch(`https://api.brainstormrouter.com${ep.path}`, {
        method: ep.method,
        headers: {
          "Content-Type": "application/json",
          ...(ep.auth !== "none" ? {
            Authorization: `Bearer ${ep.auth === "admin" ? (await import("./00-setup.mjs")).BR_ADMIN_KEY : (await import("./00-setup.mjs")).BR_API_KEY}`
          } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = text.slice(0, 100); }
      return { status: res.status, exists: res.status !== 404, data_preview: JSON.stringify(data).slice(0, 150) };
    } catch (e) {
      return "error: " + e.message.slice(0, 100);
    }
  });
}

writeResults("08-api-surface");
