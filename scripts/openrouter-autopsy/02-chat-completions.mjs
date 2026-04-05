// 02: Chat Completions — multi-model, streaming, tools, structured output
import { orComplete, orFetch, OR_API_KEY, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 02: Chat Completions ═══\n");

// 1. Auto router
await test("openrouter/auto — non-streaming", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Say hello in one word." },
  ]);
  return { model_used: r.data.model, content: r.data.choices[0].message.content, usage: r.data.usage };
});

// 2. Free router
await test("openrouter/free — non-streaming", async () => {
  const r = await orComplete("openrouter/free", [
    { role: "user", content: "Say hello in one word." },
  ]);
  return { model_used: r.data.model, content: r.data.choices[0].message.content };
});

// 3. Specific model — cheap
await test("google/gemini-2.0-flash-001 — non-streaming", async () => {
  const r = await orComplete("google/gemini-2.0-flash-001", [
    { role: "user", content: "Say hello in one word." },
  ]);
  return { model: r.data.model, content: r.data.choices[0].message.content };
});

// 4. Streaming
await test("openrouter/auto — streaming", async () => {
  const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OR_API_KEY}`,
    },
    body: JSON.stringify({
      model: "openrouter/auto",
      messages: [{ role: "user", content: "Count to 3." }],
      max_tokens: 30,
      stream: true,
    }),
  });
  const text = await res.text();
  const lines = text.split("\n").filter(l => l.startsWith("data: "));
  return { chunks: lines.length, preview: text.slice(0, 150) };
});

// 5. JSON mode
await test("structured output (json_object)", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "system", content: "Respond with JSON only." },
    { role: "user", content: 'Return {"color":"blue"}' },
  ], { response_format: { type: "json_object" } });
  return { content: r.data.choices[0].message.content };
});

// 6. Tool calling
await test("tool calling", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "What's the weather in Tokyo?" },
  ], {
    tools: [{
      type: "function",
      function: {
        name: "get_weather",
        description: "Get weather",
        parameters: { type: "object", properties: { location: { type: "string" } }, required: ["location"] },
      },
    }],
    tool_choice: "auto",
  });
  const tc = r.data.choices[0].message.tool_calls;
  return { tool_calls: tc?.length, name: tc?.[0]?.function?.name };
});

// 7. Multi-turn
await test("multi-turn conversation", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "system", content: "You are helpful." },
    { role: "user", content: "My name is Alice." },
    { role: "assistant", content: "Hello Alice!" },
    { role: "user", content: "What is my name?" },
  ]);
  return { content: r.data.choices[0].message.content };
});

// 8. Model fallback
await test("model fallback (array)", async () => {
  const r = await orFetch("/chat/completions", {
    method: "POST",
    body: {
      models: ["nonexistent/model", "openrouter/auto"],
      messages: [{ role: "user", content: "Hi" }],
      max_tokens: 10,
    },
  });
  return { model_used: r.data.model, content: r.data.choices[0].message.content };
});

// 9. Provider routing (nitro = throughput)
await test("provider routing (sort: throughput)", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Hi" },
  ], {
    provider: { sort: "throughput" },
  });
  return { model: r.data.model, content: r.data.choices[0].message.content };
});

// 10. Usage tracking
await test("usage tokens returned", async () => {
  const r = await orComplete("openrouter/auto", [
    { role: "user", content: "Hi" },
  ], { max_tokens: 5 });
  return r.data.usage;
});

writeResults("02-chat-completions");
