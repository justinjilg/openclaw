// 22: Custom Metadata + Trace ID propagation
import { PORTKEY_API_KEY, test, writeResults } from "./00-setup.mjs";
import { Portkey } from "portkey-ai";
import { execFileSync } from "node:child_process";

console.log("\n═══ 22: Metadata & Tracing ═══\n");

const openaiKey = execFileSync("op", ["read", "op://Dev Keys/OpenAI API Key/credential"], { encoding: "utf-8" }).trim();

const customTraceId = `autopsy-trace-${Date.now()}`;
const customMetadata = { environment: "test", script: "22-metadata", user_id: "autopsy-bot" };

await test("chat with custom traceID", async () => {
  const client = new Portkey({
    apiKey: PORTKEY_API_KEY,
    provider: "openai",
    Authorization: `Bearer ${openaiKey}`,
    traceID: customTraceId,
  });
  const r = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hi" }],
    max_tokens: 5,
  });
  return { trace_id: customTraceId, response: r.choices[0].message.content };
});

await test("chat with custom metadata", async () => {
  const client = new Portkey({
    apiKey: PORTKEY_API_KEY,
    provider: "openai",
    Authorization: `Bearer ${openaiKey}`,
    metadata: customMetadata,
  });
  const r = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hi" }],
    max_tokens: 5,
  });
  return { metadata_sent: customMetadata, response: r.choices[0].message.content };
});

await test("chat with traceID + metadata combined", async () => {
  const client = new Portkey({
    apiKey: PORTKEY_API_KEY,
    provider: "openai",
    Authorization: `Bearer ${openaiKey}`,
    traceID: `combined-${Date.now()}`,
    metadata: { ...customMetadata, combined: true },
  });
  const r = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hi" }],
    max_tokens: 5,
  });
  return { content: r.choices[0].message.content };
});

writeResults("22-metadata-tracing");
