// 16: Logs — insert + export lifecycle
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 16: Logs ═══\n");

await test("logs.create (manual log insert)", async () => {
  const r = await adminClient.logs.create({
    request: { method: "POST", url: "/v1/chat/completions", body: { model: "gpt-4o-mini" } },
    response: { status: 200, body: { choices: [{ message: { content: "test" } }] } },
    metadata: { source: "autopsy-test", script: "16" },
  });
  return r;
});

let exportId = null;

await test("logs.exports.create", async () => {
  const r = await adminClient.logs.exports.create({
    filters: { metadata: { source: "autopsy-test" } },
  });
  exportId = r.id;
  return { id: r.id, status: r.status };
});

await test("logs.exports.list", async () => {
  const r = await adminClient.logs.exports.list();
  return { count: r.data?.length ?? r.length };
});

await test("logs.exports.retrieve", async () => {
  if (!exportId) throw new Error("No export to retrieve");
  const r = await adminClient.logs.exports.retrieve({ id: exportId });
  return { id: r.id, status: r.status };
});

writeResults("16-logs");
