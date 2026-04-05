// 09: Models listing
import { portkey, adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 09: Models ═══\n");

await test("models.list (via provider client)", async () => {
  const r = await portkey.models.list();
  const models = r.data || r;
  return { count: Array.isArray(models) ? models.length : "not_array", first: models?.[0]?.id };
});

await test("models.list (via admin client, no provider)", async () => {
  try {
    const r = await adminClient.models.list();
    const models = r.data || r;
    return { count: Array.isArray(models) ? models.length : "not_array" };
  } catch (e) {
    return "admin_models_requires_provider: " + e.message.slice(0, 100);
  }
});

writeResults("09-models");
