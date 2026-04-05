// 07: OpenAI Responses API compatibility
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 07: Responses API ═══\n");

await test("responses.create (basic)", async () => {
  const r = await portkey.responses.create({
    model: "gpt-4o-mini",
    input: "Say hello in one word.",
  });
  return { id: r.id, output_text: r.output_text?.slice(0, 100), status: r.status };
});

await test("responses.create (streaming)", async () => {
  const stream = await portkey.responses.create({
    model: "gpt-4o-mini",
    input: "Count to 3.",
    stream: true,
  });
  let events = 0;
  for await (const event of stream) {
    events++;
  }
  return { events_received: events };
});

await test("responses.create (with tools)", async () => {
  const r = await portkey.responses.create({
    model: "gpt-4o-mini",
    input: "What's the weather in Paris?",
    tools: [
      {
        type: "function",
        name: "get_weather",
        description: "Get weather for a location",
        parameters: {
          type: "object",
          properties: { location: { type: "string" } },
          required: ["location"],
        },
      },
    ],
  });
  return { id: r.id, output_length: r.output?.length, status: r.status };
});

writeResults("07-responses");
