// 03: Provider routing, variants, endpoints
import { orFetch, orComplete, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 03: Providers & Routing ═══\n");

// Model endpoints (which providers serve a model)
await test("GET model endpoints (anthropic/claude-sonnet-4)", async () => {
  try {
    const r = await orFetch("/models/anthropic/claude-sonnet-4/endpoints");
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

// ZDR endpoints
await test("GET /endpoints/zdr (zero data retention)", async () => {
  try {
    const r = await orFetch("/endpoints/zdr");
    return { count: Array.isArray(r.data) ? r.data.length : "not_array" };
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

// Dynamic variants
await test(":nitro variant (throughput optimized)", async () => {
  const r = await orComplete("openrouter/auto:nitro", [
    { role: "user", content: "Hi" },
  ], { max_tokens: 5 });
  return { model: r.data.model };
});

await test(":floor variant (cheapest)", async () => {
  const r = await orComplete("openrouter/auto:floor", [
    { role: "user", content: "Hi" },
  ], { max_tokens: 5 });
  return { model: r.data.model };
});

await test(":online variant (web search)", async () => {
  const r = await orComplete("openrouter/auto:online", [
    { role: "user", content: "What is today's date?" },
  ], { max_tokens: 30 });
  return { model: r.data.model, content: r.data.choices[0].message.content };
});

// Provider filtering
await test("provider only: [anthropic]", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Hi" },
  ], { provider: { only: ["anthropic"] }, max_tokens: 5 });
  return { model: r.data.model };
});

await test("provider ignore: [openai]", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Hi" },
  ], { provider: { ignore: ["openai"] }, max_tokens: 5 });
  return { model: r.data.model };
});

// ZDR enforcement
await test("ZDR enforcement (zdr: true)", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Hi" },
  ], { provider: { zdr: true }, max_tokens: 5 });
  return { model: r.data.model };
});

writeResults("03-providers-routing");
