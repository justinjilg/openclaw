// 04: Plugins, caching, multimodal, guardrails
import { orComplete, orFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 04: Plugins & Advanced Features ═══\n");

// Web search plugin
await test("web-search plugin", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "What is today's date and top news?" },
  ], { plugins: [{ id: "web-search" }], max_tokens: 50 });
  return { model: r.data.model, content: r.data.choices[0].message.content?.slice(0, 150) };
});

// Response healing plugin
await test("response-healing plugin", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: 'Return this JSON: {"name": "test"' },
  ], { plugins: [{ id: "response-healing" }], response_format: { type: "json_object" }, max_tokens: 30 });
  return { content: r.data.choices[0].message.content };
});

// Prompt caching info
await test("prompt caching (check usage details)", async () => {
  const r = await orComplete("anthropic/claude-haiku-4-5-20251001", [
    { role: "system", content: "You are a helpful assistant. ".repeat(50) },
    { role: "user", content: "Hi" },
  ], { max_tokens: 5 });
  return {
    usage: r.data.usage,
    cache_details: r.data.usage?.prompt_tokens_details,
  };
});

// Vision (image URL)
await test("vision — image URL", async () => {
  const r = await orComplete("openrouter/auto", [
    {
      role: "user",
      content: [
        { type: "text", text: "What color is this image?" },
        { type: "image_url", image_url: { url: "https://via.placeholder.com/100/FF0000/FFFFFF?text=Red" } },
      ],
    },
  ], { max_tokens: 20 });
  return { model: r.data.model, content: r.data.choices[0].message.content };
});

// Stop sequences
await test("stop sequences", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Count: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10" },
  ], { stop: [", 5"], max_tokens: 50 });
  return { content: r.data.choices[0].message.content };
});

// Seed determinism
await test("seed for determinism", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Say exactly: test123" },
  ], { temperature: 0, seed: 42, max_tokens: 10 });
  return { content: r.data.choices[0].message.content };
});

// OpenAPI spec availability
await test("GET /openapi.json (API spec)", async () => {
  const res = await fetch("https://openrouter.ai/openapi.json");
  const data = await res.json();
  return { openapi_version: data.openapi, paths_count: Object.keys(data.paths || {}).length, title: data.info?.title };
});

writeResults("04-plugins-features");
