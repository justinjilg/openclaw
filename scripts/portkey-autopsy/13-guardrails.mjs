// 13: Guardrails CRUD + inline test
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 13: Guardrails ═══\n");

let guardrailSlug = null;

await test("guardrails.list", async () => {
  const r = await adminClient.guardrails.list();
  return { count: r.data?.length ?? r.length, keys: Object.keys(r) };
});

await test("guardrails.create", async () => {
  const r = await adminClient.guardrails.create({
    name: `autopsy-guardrail-${Date.now()}`,
    checks: [
      {
        id: "default",
        type: "model_based",
        parameters: { model: "gpt-4o-mini" },
        on: "output",
      },
    ],
    actions: [
      { type: "block", on: "fail" },
    ],
  });
  guardrailSlug = r.slug || r.id;
  return { slug: guardrailSlug, name: r.name, keys: Object.keys(r) };
});

await test("guardrails.retrieve", async () => {
  if (!guardrailSlug) throw new Error("No guardrail to retrieve");
  const r = await adminClient.guardrails.retrieve({ slug: guardrailSlug });
  return { slug: r.slug, name: r.name };
});

await test("guardrails.update", async () => {
  if (!guardrailSlug) throw new Error("No guardrail to update");
  const r = await adminClient.guardrails.update({
    slug: guardrailSlug,
    name: `autopsy-guardrail-updated-${Date.now()}`,
  });
  return { slug: r.slug, name: r.name };
});

await test("guardrails.delete", async () => {
  if (!guardrailSlug) throw new Error("No guardrail to delete");
  await adminClient.guardrails.delete({ slug: guardrailSlug });
  guardrailSlug = null;
  return "deleted";
});

writeResults("13-guardrails");
