// 03: Agent Profiles (admin key)
import { brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 03: Agent Profiles ═══\n");

await test("GET /v1/agent/profiles (admin)", async () => {
  const r = await brFetch("/v1/agent/profiles", { auth: "admin" });
  const agents = Array.isArray(r.data) ? r.data : r.data.agents || r.data.data;
  return {
    count: agents?.length,
    agents: agents?.map(a => ({
      id: a.agentId,
      budget: a.budgetDailyUsd,
      state: a.lifecycleState,
    })),
  };
});

await test("GET /v1/agent/profiles (scoped key — should fail)", async () => {
  try {
    const r = await brFetch("/v1/agent/profiles", { auth: "scoped" });
    return { unexpected: "scoped key should not access profiles" };
  } catch (e) {
    if (e.message.includes("403") || e.message.includes("insufficient")) {
      return "correctly_blocked";
    }
    throw e;
  }
});

writeResults("03-agent-profiles");
