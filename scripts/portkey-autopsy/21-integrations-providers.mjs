// 21: Integrations + Providers (read-only)
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 21: Integrations & Providers (Read-Only) ═══\n");

await test("integrations.list", async () => {
  const r = await adminClient.integrations.list();
  return { count: r.data?.length ?? r.total };
});

await test("providers.list", async () => {
  const r = await adminClient.providers.list();
  return { count: r.data?.length ?? r.total };
});

writeResults("21-integrations-providers");
