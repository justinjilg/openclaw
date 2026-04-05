// 01: Key info + Model catalog
import { orFetch, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 01: Key & Models ═══\n");

await test("GET /key (check credits + limits)", async () => {
  const r = await orFetch("/key");
  return r.data;
});

await test("GET /models (full catalog)", async () => {
  const r = await orFetch("/models");
  const models = r.data.data || r.data;
  const providers = [...new Set(models.map(m => m.id.split("/")[0]))];
  return { total_models: models.length, providers: providers.length, provider_list: providers.sort(), sample: models.slice(0, 3).map(m => m.id) };
});

await test("GET /models — free models count", async () => {
  const r = await orFetch("/models");
  const models = r.data.data || r.data;
  const free = models.filter(m => m.pricing?.prompt === "0" || m.pricing?.prompt === 0);
  return { free_models: free.length, sample: free.slice(0, 5).map(m => m.id) };
});

await test("GET /models — model metadata structure", async () => {
  const r = await orFetch("/models");
  const m = (r.data.data || r.data)[0];
  return { keys: Object.keys(m), pricing_keys: Object.keys(m.pricing || {}), context_length: m.context_length, top_provider: m.top_provider };
});

writeResults("01-key-models");
