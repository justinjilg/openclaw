import { Portkey } from "portkey-ai";
import { execFileSync } from "node:child_process";

const apiKey = execFileSync("op", [
  "read",
  "op://Dev Keys/Portkey AI API Key/credential",
], { encoding: "utf-8" }).trim();

const openaiKey = execFileSync("op", [
  "read",
  "op://Dev Keys/OpenAI API Key/credential",
], { encoding: "utf-8" }).trim();

const portkey = new Portkey({
  apiKey,
  provider: "openai",
  Authorization: `Bearer ${openaiKey}`,
});

// Test 1: Chat completion
const chat = await portkey.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Say hello in one sentence." }],
  max_tokens: 50,
});

console.log("Chat response:", chat.choices[0].message.content);

// Test 2: Moderation
try {
  const moderation = await portkey.moderations.create({
    input: "I want to kill them.",
    model: "omni-moderation-latest",
  });
  console.log("\nModeration:", JSON.stringify(moderation.results[0], null, 2));
} catch (e) {
  console.log("\nModeration endpoint not available — you may need to add an OpenAI provider in Portkey dashboard.");
}
