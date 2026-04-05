// 18: Evaluation Framework
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 18: Evals ═══\n");

let evalId = null;

await test("evals.create", async () => {
  const r = await adminClient.evals.create({
    name: `autopsy-eval-${Date.now()}`,
    data_source_config: {
      type: "custom",
      item_schema: {
        type: "object",
        properties: { input: { type: "string" }, expected: { type: "string" } },
      },
    },
    testing_criteria: [
      {
        type: "label_model",
        name: "accuracy",
        model: "gpt-4o-mini",
        input: [{ role: "user", content: "Is this accurate? Input: {{item.input}} Expected: {{item.expected}}" }],
        passing_labels: ["yes"],
      },
    ],
  });
  evalId = r.id;
  return { id: r.id, name: r.name };
});

await test("evals.list", async () => {
  const r = await adminClient.evals.list();
  return { count: r.data?.length ?? r.length };
});

await test("evals.retrieve", async () => {
  if (!evalId) throw new Error("No eval");
  const r = await adminClient.evals.retrieve(evalId);
  return { id: r.id, name: r.name };
});

await test("evals.delete", async () => {
  if (!evalId) throw new Error("No eval");
  await adminClient.evals.delete(evalId);
  evalId = null;
  return "deleted";
});

writeResults("18-evals");
