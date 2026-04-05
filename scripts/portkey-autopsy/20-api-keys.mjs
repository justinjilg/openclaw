// 20: API Keys (read-only)
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 20: API Keys (Read-Only) ═══\n");

await test("apiKeys.list", async () => {
  const r = await adminClient.apiKeys.list();
  return { count: r.data?.length ?? r.total };
});

writeResults("20-api-keys");
