// 05: Multi-provider matrix — test specific providers through OpenRouter
import { orComplete, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 05: Multi-Provider Matrix ═══\n");

const models = [
  { name: "OpenAI", model: "openai/gpt-4.1-nano" },
  { name: "Anthropic", model: "anthropic/claude-haiku-4-5-20251001" },
  { name: "Google", model: "google/gemini-2.0-flash-001" },
  { name: "DeepSeek", model: "deepseek/deepseek-chat" },
  { name: "Meta/Llama", model: "meta-llama/llama-3.1-8b-instruct:free" },
  { name: "Mistral", model: "mistralai/mistral-small-3.1-24b-instruct:free" },
  { name: "Qwen", model: "qwen/qwen3-8b:free" },
];

for (const { name, model } of models) {
  await test(`${name} / ${model}`, async () => {
    const r = await orComplete(model, [
      { role: "user", content: "Say hello in one word." },
    ], { max_tokens: 10 });
    return {
      provider: name,
      model_returned: r.data.model,
      content: r.data.choices[0].message.content,
      usage: r.data.usage,
    };
  });
}

// Streaming across providers
console.log("\n  --- Streaming ---\n");
for (const { name, model } of models.slice(0, 4)) {
  await test(`${name} — streaming`, async () => {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${(await import("./00-setup.mjs")).OR_API_KEY}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: "Count to 3." }],
        max_tokens: 20,
        stream: true,
      }),
    });
    const text = await res.text();
    const lines = text.split("\n").filter(l => l.startsWith("data: "));
    return { chunks: lines.length };
  });
}

writeResults("05-multi-provider");
