// 01: Chat Completions — non-streaming, streaming, structured output, tool calling
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 01: Chat Completions ═══\n");

// 1. Basic non-streaming
await test("chat.completions.create (non-streaming)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Say hello in one word." }],
    max_tokens: 10,
  });
  return r.choices[0].message.content;
});

// 2. Streaming
await test("chat.completions.create (streaming)", async () => {
  const stream = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Count to 3." }],
    max_tokens: 20,
    stream: true,
  });
  let text = "";
  for await (const chunk of stream) {
    const delta = chunk.choices?.[0]?.delta?.content;
    if (delta) text += delta;
  }
  return text;
});

// 3. Structured output (JSON mode)
await test("chat.completions.create (response_format: json_object)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Respond with JSON only." },
      { role: "user", content: 'Return {"color":"blue"}' },
    ],
    max_tokens: 30,
    response_format: { type: "json_object" },
  });
  const parsed = JSON.parse(r.choices[0].message.content);
  return parsed;
});

// 4. Tool calling
await test("chat.completions.create (tool calling)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "What's the weather in Tokyo?" }],
    max_tokens: 50,
    tools: [
      {
        type: "function",
        function: {
          name: "get_weather",
          description: "Get weather for a location",
          parameters: {
            type: "object",
            properties: { location: { type: "string" } },
            required: ["location"],
          },
        },
      },
    ],
    tool_choice: "auto",
  });
  const tc = r.choices[0].message.tool_calls;
  return { tool_calls: tc?.length, function_name: tc?.[0]?.function?.name };
});

// 5. Multiple messages (multi-turn)
await test("chat.completions.create (multi-turn)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are a helpful assistant." },
      { role: "user", content: "My name is Alice." },
      { role: "assistant", content: "Hello Alice!" },
      { role: "user", content: "What is my name?" },
    ],
    max_tokens: 20,
  });
  return r.choices[0].message.content;
});

// 6. Temperature and seed (determinism)
await test("chat.completions.create (seed for determinism)", async () => {
  const params = {
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Say exactly: test123" }],
    max_tokens: 10,
    temperature: 0,
    seed: 42,
  };
  const r1 = await portkey.chat.completions.create(params);
  const r2 = await portkey.chat.completions.create(params);
  return {
    response1: r1.choices[0].message.content,
    response2: r2.choices[0].message.content,
    fingerprint1: r1.system_fingerprint,
    fingerprint2: r2.system_fingerprint,
  };
});

// 7. Stop sequences
await test("chat.completions.create (stop sequences)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Count: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10" }],
    max_tokens: 50,
    stop: [", 5"],
  });
  return r.choices[0].message.content;
});

// 8. N choices
await test("chat.completions.create (n=2 choices)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Pick a random number 1-100." }],
    max_tokens: 10,
    n: 2,
  });
  return { choices: r.choices.length, c0: r.choices[0].message.content, c1: r.choices[1].message.content };
});

// 9. Usage tracking
await test("chat.completions — usage tokens returned", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hi" }],
    max_tokens: 5,
  });
  return { prompt_tokens: r.usage?.prompt_tokens, completion_tokens: r.usage?.completion_tokens, total_tokens: r.usage?.total_tokens };
});

// 10. Portkey headers in response
await test("chat.completions — portkey trace headers", async () => {
  // The SDK doesn't expose response headers easily; test by checking the response object
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hi" }],
    max_tokens: 5,
  });
  return { model: r.model, id: r.id, object: r.object };
});

writeResults("01-chat-completions");
