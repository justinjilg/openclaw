// 30: Multi-Provider Matrix — chat completions across all 7 providers (direct auth)
import { PROVIDERS, createClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 30: Multi-Provider Matrix (Direct Auth) ═══\n");

const prompt = [{ role: "user", content: "Say hello in one word." }];

for (const [name, provider] of Object.entries(PROVIDERS)) {
  if (!provider.key) {
    await test(`${name} — SKIPPED (no key)`, async () => { throw new Error("No API key found"); });
    continue;
  }

  const client = createClient(provider.slug, provider.key);

  await test(`${name} / ${provider.model} — chat completion`, async () => {
    const r = await client.chat.completions.create({
      model: provider.model,
      messages: prompt,
      max_tokens: 10,
    });
    return {
      provider: name,
      model_returned: r.model,
      content: r.choices[0].message.content,
      prompt_tokens: r.usage?.prompt_tokens,
      completion_tokens: r.usage?.completion_tokens,
    };
  });
}

// Streaming test across all providers
console.log("\n  --- Streaming ---\n");

for (const [name, provider] of Object.entries(PROVIDERS)) {
  if (!provider.key) continue;
  const client = createClient(provider.slug, provider.key);

  await test(`${name} / ${provider.model} — streaming`, async () => {
    const stream = await client.chat.completions.create({
      model: provider.model,
      messages: [{ role: "user", content: "Count to 3." }],
      max_tokens: 20,
      stream: true,
    });
    let text = "";
    let chunks = 0;
    for await (const chunk of stream) {
      chunks++;
      const delta = chunk.choices?.[0]?.delta?.content;
      if (delta) text += delta;
    }
    return { provider: name, chunks, text: text.slice(0, 80) };
  });
}

writeResults("30-multi-provider-matrix");
