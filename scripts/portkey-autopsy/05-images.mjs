// 05: Image Generation
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 05: Images ═══\n");

await test("images.generate (dall-e-3)", async () => {
  const r = await portkey.images.generate({
    model: "dall-e-3",
    prompt: "A simple blue circle on white background",
    n: 1,
    size: "1024x1024",
    quality: "standard",
  });
  return { url_length: r.data[0].url?.length, revised_prompt: r.data[0].revised_prompt?.slice(0, 100) };
});

await test("images.generate (dall-e-2, smaller)", async () => {
  const r = await portkey.images.generate({
    model: "dall-e-2",
    prompt: "A red square",
    n: 1,
    size: "256x256",
  });
  return { url_present: !!r.data[0].url };
});

writeResults("05-images");
