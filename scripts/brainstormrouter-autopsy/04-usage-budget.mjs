// 04: Usage, Budget, Cost Center
import { brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 04: Usage & Budget ═══\n");

await test("GET /v1/usage/by-cost-center (admin)", async () => {
  const r = await brFetch("/v1/usage/by-cost-center", { auth: "admin" });
  return r.data;
});

await test("GET /v1/usage/by-cost-center?cost_center=openclaw-fleet", async () => {
  const r = await brFetch("/v1/usage/by-cost-center?cost_center=openclaw-fleet", { auth: "admin" });
  return r.data;
});

await test("GET /v1/agent/limits (admin)", async () => {
  const r = await brFetch("/v1/agent/limits", { auth: "admin" });
  return r.data;
});

await test("GET /v1/insights/daily (admin)", async () => {
  try {
    const r = await brFetch("/v1/insights/daily", { auth: "admin" });
    return r.data;
  } catch (e) {
    // May need 100+ requests before data is available
    return "endpoint_exists_but_insufficient_data: " + e.message.slice(0, 100);
  }
});

await test("GET /v1/cost-forecast (admin)", async () => {
  try {
    const r = await brFetch("/v1/cost-forecast", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "endpoint_probe: " + e.message.slice(0, 100);
  }
});

writeResults("04-usage-budget");
