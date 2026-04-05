// 06: Governance — anomaly, behavioral profiles, ops status, leaderboard
import { brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 06: Governance ═══\n");

await test("GET /v1/ops/status (admin)", async () => {
  try {
    const r = await brFetch("/v1/ops/status", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/agent/anomaly (admin)", async () => {
  try {
    const r = await brFetch("/v1/agent/anomaly", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/behavioral-profiles (admin)", async () => {
  try {
    const r = await brFetch("/v1/behavioral-profiles", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/leaderboard (admin)", async () => {
  try {
    const r = await brFetch("/v1/leaderboard", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/governance (admin)", async () => {
  try {
    const r = await brFetch("/v1/governance", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/agent/manifests (admin)", async () => {
  try {
    const r = await brFetch("/v1/agent/manifests", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

await test("GET /v1/memory/compliance (admin)", async () => {
  try {
    const r = await brFetch("/v1/memory/compliance", { auth: "admin" });
    return r.data;
  } catch (e) {
    return "probe: " + e.message.slice(0, 150);
  }
});

writeResults("06-governance");
