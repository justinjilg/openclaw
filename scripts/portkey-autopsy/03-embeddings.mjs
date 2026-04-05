// 03: Embeddings
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 03: Embeddings ═══\n");

await test("embeddings.create (single string)", async () => {
  const r = await portkey.embeddings.create({
    model: "text-embedding-3-small",
    input: "The quick brown fox",
  });
  return { dimensions: r.data[0].embedding.length, model: r.model, usage: r.usage };
});

await test("embeddings.create (array input)", async () => {
  const r = await portkey.embeddings.create({
    model: "text-embedding-3-small",
    input: ["Hello world", "Goodbye world"],
  });
  return { count: r.data.length, dim0: r.data[0].embedding.length, dim1: r.data[1].embedding.length };
});

await test("embeddings.create (custom dimensions)", async () => {
  const r = await portkey.embeddings.create({
    model: "text-embedding-3-small",
    input: "Test",
    dimensions: 256,
  });
  return { dimensions: r.data[0].embedding.length };
});

await test("embeddings.create (base64 encoding)", async () => {
  const r = await portkey.embeddings.create({
    model: "text-embedding-3-small",
    input: "Test",
    encoding_format: "base64",
  });
  return { encoding: typeof r.data[0].embedding === "string" ? "base64" : "float" };
});

writeResults("03-embeddings");
