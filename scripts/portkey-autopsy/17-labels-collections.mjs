// 17: Labels + Collections CRUD
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 17: Labels & Collections ═══\n");

let labelSlug = null;
let collectionSlug = null;

// Labels
await test("labels.create", async () => {
  const r = await adminClient.labels.create({
    name: `autopsy-label-${Date.now()}`,
    color: "#FF5733",
  });
  labelSlug = r.slug || r.id;
  return { slug: labelSlug, name: r.name, color: r.color, keys: Object.keys(r) };
});

await test("labels.list", async () => {
  const r = await adminClient.labels.list();
  return { count: r.data?.length ?? r.length };
});

await test("labels.retrieve", async () => {
  if (!labelSlug) throw new Error("No label");
  const r = await adminClient.labels.retrieve(labelSlug);
  return { name: r.name };
});

await test("labels.delete", async () => {
  if (!labelSlug) throw new Error("No label");
  await adminClient.labels.delete(labelSlug);
  labelSlug = null;
  return "deleted";
});

// Collections
await test("collections.create", async () => {
  const r = await adminClient.collections.create({
    name: `autopsy-collection-${Date.now()}`,
  });
  collectionSlug = r.slug || r.id;
  return { slug: collectionSlug, name: r.name, keys: Object.keys(r) };
});

await test("collections.list", async () => {
  const r = await adminClient.collections.list();
  return { count: r.data?.length ?? r.length };
});

await test("collections.delete", async () => {
  if (!collectionSlug) throw new Error("No collection");
  await adminClient.collections.delete(collectionSlug);
  collectionSlug = null;
  return "deleted";
});

writeResults("17-labels-collections");
