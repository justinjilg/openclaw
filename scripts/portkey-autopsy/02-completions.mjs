// 02: Legacy Text Completions
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 02: Text Completions ═══\n");

await test("completions.create (non-streaming)", async () => {
  const r = await portkey.completions.create({
    model: "gpt-3.5-turbo-instruct",
    prompt: "The capital of France is",
    max_tokens: 10,
  });
  return r.choices[0].text;
});

await test("completions.create (streaming)", async () => {
  const stream = await portkey.completions.create({
    model: "gpt-3.5-turbo-instruct",
    prompt: "1, 2, 3,",
    max_tokens: 15,
    stream: true,
  });
  let text = "";
  for await (const chunk of stream) {
    if (chunk.choices?.[0]?.text) text += chunk.choices[0].text;
  }
  return text;
});

await test("completions.create — usage tokens", async () => {
  const r = await portkey.completions.create({
    model: "gpt-3.5-turbo-instruct",
    prompt: "Hi",
    max_tokens: 5,
  });
  return r.usage;
});

writeResults("02-completions");
