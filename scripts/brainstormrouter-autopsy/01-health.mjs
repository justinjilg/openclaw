// 01: Health endpoint (no auth)
import { BR_BASE_URL, brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 01: Health ═══\n");

await test("GET /health (no auth)", async () => {
  const r = await brFetch("/health", { auth: "none" });
  return r.data;
});

await test("GET /health (IPv4 check)", async () => {
  // BR health only works on IPv4
  const res = await fetch(`${BR_BASE_URL}/health`);
  const data = await res.json();
  return { ok: data.ok, status: data.status };
});

writeResults("01-health");
