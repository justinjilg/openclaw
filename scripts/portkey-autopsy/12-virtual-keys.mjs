// 12: Virtual Keys CRUD
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 12: Virtual Keys ═══\n");

let vkeySlug = null;

await test("virtualKeys.list", async () => {
  const r = await adminClient.virtualKeys.list();
  return { count: r.data?.length ?? r.total, keys: Object.keys(r) };
});

await test("virtualKeys.create", async () => {
  const r = await adminClient.virtualKeys.create({
    name: `autopsy-test-vk-${Date.now()}`,
    provider: "openai",
    key: "sk-test-not-real-key-for-testing",
    note: "Created by portkey-autopsy script 12",
  });
  vkeySlug = r.slug || r.id;
  return { slug: vkeySlug, name: r.name, provider: r.provider, keys: Object.keys(r) };
});

await test("virtualKeys.retrieve", async () => {
  if (!vkeySlug) throw new Error("No virtual key to retrieve");
  const r = await adminClient.virtualKeys.retrieve({ slug: vkeySlug });
  return { slug: r.slug, name: r.name };
});

await test("virtualKeys.update", async () => {
  if (!vkeySlug) throw new Error("No virtual key to update");
  const r = await adminClient.virtualKeys.update({
    slug: vkeySlug,
    name: `autopsy-test-vk-updated-${Date.now()}`,
    note: "Updated by autopsy",
  });
  return { slug: r.slug, name: r.name };
});

await test("virtualKeys.delete", async () => {
  if (!vkeySlug) throw new Error("No virtual key to delete");
  await adminClient.virtualKeys.delete({ slug: vkeySlug });
  vkeySlug = null;
  return "deleted";
});

writeResults("12-virtual-keys");
