// 02: Chat Completions via BR — auto model + specific models
import { brComplete, brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 02: Chat Completions ═══\n");

// 1. Auto model (Thompson sampling)
await test("auto model — non-streaming", async () => {
  const r = await brComplete("brainstormrouter/auto", [
    { role: "user", content: "Say hello in one word." },
  ]);
  return {
    model_used: r.data.model,
    content: r.data.choices?.[0]?.message?.content,
    usage: r.data.usage,
  };
});

// 2. Specific model — Moonshot (allowed on scoped key)
await test("moonshot/kimi-k2.5 — non-streaming", async () => {
  const r = await brComplete("moonshot/kimi-k2.5", [
    { role: "user", content: "Say hello in one word." },
  ]);
  return {
    model_used: r.data.model,
    content: r.data.choices?.[0]?.message?.content,
    usage: r.data.usage,
  };
});

// 3. Streaming
await test("moonshot/kimi-k2.5 — streaming", async () => {
  const res = await fetch("https://api.brainstormrouter.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${(await import("./00-setup.mjs")).BR_API_KEY}`,
    },
    body: JSON.stringify({
      model: "moonshot/kimi-k2.5",
      messages: [{ role: "user", content: "Count to 3." }],
      max_tokens: 30,
      stream: true,
    }),
  });
  const text = await res.text();
  const lines = text.split("\n").filter(l => l.startsWith("data: "));
  return { chunks: lines.length, starts_with: text.slice(0, 100) };
});

// 4. Multi-turn conversation
await test("auto — multi-turn", async () => {
  const r = await brComplete("brainstormrouter/auto", [
    { role: "system", content: "You are a helpful assistant." },
    { role: "user", content: "My name is Alice." },
    { role: "assistant", content: "Hello Alice!" },
    { role: "user", content: "What is my name?" },
  ]);
  return { content: r.data.choices?.[0]?.message?.content };
});

// 5. Temperature control
await test("auto — temperature 0 (deterministic)", async () => {
  const params = {
    max_tokens: 10,
    temperature: 0,
  };
  const r = await brComplete("brainstormrouter/auto", [
    { role: "user", content: "Say exactly: test123" },
  ], params);
  return { content: r.data.choices?.[0]?.message?.content };
});

// 6. Restricted model (should fail on scoped key)
await test("openai/gpt-4o-mini — BLOCKED by scoped key", async () => {
  try {
    const r = await brComplete("openai/gpt-4o-mini", [
      { role: "user", content: "Hi" },
    ]);
    return { unexpected: "should have been blocked", content: r.data.choices?.[0]?.message?.content };
  } catch (e) {
    if (e.message.includes("403") || e.message.includes("allowed_models") || e.message.includes("not allowed")) {
      return "correctly_blocked";
    }
    throw e;
  }
});

// 7. Usage/token tracking
await test("auto — usage tokens returned", async () => {
  const r = await brComplete("brainstormrouter/auto", [
    { role: "user", content: "Hi" },
  ], { max_tokens: 5 });
  return {
    prompt_tokens: r.data.usage?.prompt_tokens,
    completion_tokens: r.data.usage?.completion_tokens,
    total_tokens: r.data.usage?.total_tokens,
  };
});

// 8. Response headers
await test("auto — response headers", async () => {
  const r = await brComplete("brainstormrouter/auto", [
    { role: "user", content: "Hi" },
  ], { max_tokens: 5 });
  return {
    model: r.data.model,
    id: r.data.id,
    object: r.data.object,
    headers_keys: Object.keys(r.headers).filter(k => k.startsWith("x-")),
  };
});

writeResults("02-chat-completions");
