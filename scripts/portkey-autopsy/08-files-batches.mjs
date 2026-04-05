// 08: Files and Batches
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 08: Files & Batches ═══\n");

let uploadedFileId = null;

await test("files.create (upload JSONL)", async () => {
  const content = JSON.stringify({ custom_id: "test-1", method: "POST", url: "/v1/chat/completions", body: { model: "gpt-4o-mini", messages: [{ role: "user", content: "Hi" }], max_tokens: 5 } });
  const blob = new Blob([content], { type: "application/jsonl" });
  const file = new File([blob], "test-batch.jsonl", { type: "application/jsonl" });
  const r = await portkey.files.create({ file, purpose: "batch" });
  uploadedFileId = r.id;
  return { id: r.id, filename: r.filename, purpose: r.purpose, status: r.status };
});

await test("files.list", async () => {
  const r = await portkey.files.list();
  return { count: r.data?.length };
});

await test("files.retrieve", async () => {
  if (!uploadedFileId) throw new Error("No file to retrieve — upload failed");
  const r = await portkey.files.retrieve(uploadedFileId);
  return { id: r.id, bytes: r.bytes, status: r.status };
});

await test("batches.create", async () => {
  if (!uploadedFileId) throw new Error("No file for batch — upload failed");
  const r = await portkey.batches.create({
    input_file_id: uploadedFileId,
    endpoint: "/v1/chat/completions",
    completion_window: "24h",
  });
  return { id: r.id, status: r.status, endpoint: r.endpoint };
});

await test("batches.list", async () => {
  const r = await portkey.batches.list();
  return { count: r.data?.length };
});

// Cleanup
if (uploadedFileId) {
  try { await portkey.files.delete(uploadedFileId); } catch (e) { /* ok */ }
}

writeResults("08-files-batches");
