// 07: MCP Server — probe tools and capabilities
import { brFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 07: MCP Server ═══\n");

// BR MCP endpoint: https://api.brainstormrouter.com/v1/mcp/connect (streamable-http)
// Authed via BR_ADMIN_KEY

await test("MCP /v1/mcp/connect — probe availability", async () => {
  try {
    // MCP uses streamable-http, try a basic JSON-RPC initialize
    const res = await fetch("https://api.brainstormrouter.com/v1/mcp/connect", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${(await import("./00-setup.mjs")).BR_ADMIN_KEY}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "autopsy-test", version: "1.0" },
        },
      }),
    });
    const text = await res.text();
    return { status: res.status, content_type: res.headers.get("content-type"), body_preview: text.slice(0, 300) };
  } catch (e) {
    return "mcp_probe: " + e.message.slice(0, 200);
  }
});

await test("MCP — list tools via JSON-RPC", async () => {
  try {
    const res = await fetch("https://api.brainstormrouter.com/v1/mcp/connect", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${(await import("./00-setup.mjs")).BR_ADMIN_KEY}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      }),
    });
    const text = await res.text();
    return { status: res.status, body_preview: text.slice(0, 500) };
  } catch (e) {
    return "mcp_tools_probe: " + e.message.slice(0, 200);
  }
});

writeResults("07-mcp");
