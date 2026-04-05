// 11: Simple Caching test
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 11: Caching ═══\n");

const cachePrompt = [{ role: "user", content: `Cache test ${Date.now()}: say exactly "cached"` }];

await test("cache — first request (miss expected)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: cachePrompt,
    max_tokens: 10,
  });
  return { content: r.choices[0].message.content };
});

await test("cache — second identical request (hit expected)", async () => {
  const r = await portkey.chat.completions.create({
    model: "gpt-4o-mini",
    messages: cachePrompt,
    max_tokens: 10,
  });
  return { content: r.choices[0].message.content };
});

await test("cache — force refresh", async () => {
  // The cacheForceRefresh option should bypass cache
  const { Portkey } = await import("portkey-ai");
  const { execFileSync } = await import("node:child_process");
  const key = execFileSync("op", ["read", "op://Dev Keys/Portkey AI API Key/credential"], { encoding: "utf-8" }).trim();
  const openaiKey = execFileSync("op", ["read", "op://Dev Keys/OpenAI API Key/credential"], { encoding: "utf-8" }).trim();
  const freshClient = new Portkey({
    apiKey: key,
    provider: "openai",
    Authorization: `Bearer ${openaiKey}`,
    cacheForceRefresh: true,
  });
  const r = await freshClient.chat.completions.create({
    model: "gpt-4o-mini",
    messages: cachePrompt,
    max_tokens: 10,
  });
  return { content: r.choices[0].message.content };
});

writeResults("11-caching");
