// 19: Admin — Users, Invites, Workspaces (read-only)
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 19: Admin (Read-Only) ═══\n");

await test("admin.users.list", async () => {
  const r = await adminClient.admin.users.list();
  return { count: r.data?.length ?? r.total };
});

await test("admin.workspaces.list", async () => {
  const r = await adminClient.admin.workspaces.list();
  return { count: r.data?.length ?? r.total };
});

await test("admin.users.invites.list", async () => {
  const r = await adminClient.admin.users.invites.list();
  return { count: r.data?.length ?? r.total };
});

writeResults("19-admin");
