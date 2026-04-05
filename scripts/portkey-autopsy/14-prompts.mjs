// 14: Prompt Management — CRUD, versions, render, completions, partials
import { adminClient, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 14: Prompt Management ═══\n");

let promptSlug = null;

await test("prompts.list", async () => {
  const r = await adminClient.prompts.list();
  return { count: r.data?.length ?? r.total, keys: Object.keys(r) };
});

await test("prompts.create", async () => {
  const r = await adminClient.prompts.create({
    name: `autopsy-prompt-${Date.now()}`,
    template: [
      { role: "system", content: "You are a helpful assistant. Topic: {{topic}}" },
      { role: "user", content: "{{question}}" },
    ],
  });
  promptSlug = r.slug || r.id;
  return { slug: promptSlug, name: r.name, keys: Object.keys(r) };
});

await test("prompts.retrieve", async () => {
  if (!promptSlug) throw new Error("No prompt to retrieve");
  const r = await adminClient.prompts.retrieve({ slug: promptSlug });
  return { slug: r.slug, name: r.name };
});

await test("prompts.render (variable interpolation)", async () => {
  if (!promptSlug) throw new Error("No prompt to render");
  const r = await adminClient.prompts.render({
    slug: promptSlug,
    variables: { topic: "science", question: "What is gravity?" },
  });
  return { rendered: JSON.stringify(r).slice(0, 200) };
});

await test("prompts.update", async () => {
  if (!promptSlug) throw new Error("No prompt to update");
  const r = await adminClient.prompts.update({
    slug: promptSlug,
    name: `autopsy-prompt-updated-${Date.now()}`,
  });
  return { slug: r.slug, name: r.name };
});

await test("prompts.delete", async () => {
  if (!promptSlug) throw new Error("No prompt to delete");
  await adminClient.prompts.delete({ slug: promptSlug });
  promptSlug = null;
  return "deleted";
});

writeResults("14-prompts");
