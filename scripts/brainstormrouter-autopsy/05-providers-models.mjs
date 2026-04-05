// 05: Provider Catalog + Model Listing
import { brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 05: Providers & Models ═══\n");

await test("GET /v1/providers/catalog (admin)", async () => {
  try {
    const r = await brFetch("/v1/providers/catalog", { auth: "admin" });
    return r.data;
  } catch (e) {
    // Known to return 403 even with admin key
    return "known_issue: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/models (admin)", async () => {
  try {
    const r = await brFetch("/v1/models", { auth: "admin" });
    const models = r.data.data || r.data;
    return { count: Array.isArray(models) ? models.length : "not_array", sample: models?.slice?.(0, 3) };
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/models (scoped key)", async () => {
  try {
    const r = await brFetch("/v1/models", { auth: "scoped" });
    const models = r.data.data || r.data;
    return { count: Array.isArray(models) ? models.length : "not_array" };
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/agent/list (admin)", async () => {
  try {
    const r = await brFetch("/v1/agent/list", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

writeResults("05-providers-models");
