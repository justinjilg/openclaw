// 15: Feedback API
import { adminClient, portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 15: Feedback ═══\n");

// First make a chat request to get a trace ID
let traceId = `autopsy-trace-${Date.now()}`;

await test("feedback.create (single)", async () => {
  const r = await adminClient.feedback.create({
    trace_id: traceId,
    value: 1,
    weight: 1.0,
    metadata: { source: "autopsy-test", script: "15" },
  });
  return r;
});

await test("feedback.update", async () => {
  const r = await adminClient.feedback.update({
    trace_id: traceId,
    value: 0,
    weight: 0.5,
    metadata: { source: "autopsy-test", updated: true },
  });
  return r;
});

await test("feedback.create (batch)", async () => {
  const r = await adminClient.feedback.create([
    { trace_id: `batch-trace-1-${Date.now()}`, value: 1, weight: 1.0 },
    { trace_id: `batch-trace-2-${Date.now()}`, value: -1, weight: 0.8 },
  ]);
  return r;
});

writeResults("15-feedback");
