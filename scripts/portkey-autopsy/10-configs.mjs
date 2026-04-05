// 10: Gateway Config CRUD + routing strategies
import { adminClient, portkey, PORTKEY_API_KEY, test, writeResults } from "./00-setup.mjs";
import { Portkey } from "portkey-ai";

console.log("\n═══ 10: Gateway Configs ═══\n");

let configSlug = null;
let configId = null;

await test("configs.create (simple)", async () => {
  const r = await adminClient.configs.create({
    name: `autopsy-test-${Date.now()}`,
    config: {
      strategy: { mode: "single" },
      targets: [{ provider: "openai", api_key: "test" }],
    },
  });
  configId = r.id;
  configSlug = r.slug;
  return { id: r.id, slug: r.slug, name: r.name, keys: Object.keys(r) };
});

await test("configs.list", async () => {
  const r = await adminClient.configs.list();
  const items = r.data || r;
  if (Array.isArray(items) && items.length > 0 && !configSlug) {
    configSlug = items[0].slug;
    configId = items[0].id;
  }
  return { count: items.length, first_slug: items[0]?.slug };
});

await test("configs.retrieve (by slug)", async () => {
  if (!configSlug) throw new Error("No config slug to retrieve");
  const r = await adminClient.configs.retrieve({ slug: configSlug });
  return { id: r.id, slug: r.slug, name: r.name };
});

await test("configs.update (by slug)", async () => {
  if (!configSlug) throw new Error("No config slug to update");
  const r = await adminClient.configs.update({
    slug: configSlug,
    name: `autopsy-test-updated-${Date.now()}`,
  });
  return { id: r.id, name: r.name };
});

await test("configs.delete (by slug)", async () => {
  if (!configSlug) throw new Error("No config slug to delete");
  await adminClient.configs.delete({ slug: configSlug });
  configSlug = null;
  return "deleted";
});

// Test using a config with actual routing
await test("chat via config header (weighted routing)", async () => {
  const configObj = {
    strategy: { mode: "fallback" },
    targets: [
      { provider: "openai", override_params: { model: "gpt-4o-mini", max_tokens: 10 } },
    ],
  };
  const client = new Portkey({
    apiKey: PORTKEY_API_KEY,
    provider: "openai",
    Authorization: portkey.Authorization,
    config: configObj,
  });
  try {
    const r = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "Hi" }],
      max_tokens: 10,
    });
    return { content: r.choices[0].message.content };
  } catch (e) {
    return "config_routing_error: " + e.message.slice(0, 150);
  }
});

writeResults("10-configs");
