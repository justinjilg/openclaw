// 04: Moderations
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 04: Moderations ═══\n");

await test("moderations.create (flagged input)", async () => {
  const r = await portkey.moderations.create({
    input: "I want to kill them.",
    model: "omni-moderation-latest",
  });
  return { flagged: r.results[0].flagged, violence: r.results[0].category_scores.violence > 0.5 };
});

await test("moderations.create (safe input)", async () => {
  const r = await portkey.moderations.create({
    input: "The weather is nice today.",
    model: "omni-moderation-latest",
  });
  return { flagged: r.results[0].flagged };
});

await test("moderations.create (multi-input array)", async () => {
  const r = await portkey.moderations.create({
    input: ["Hello friend", "I hate everything"],
    model: "omni-moderation-latest",
  });
  return { count: r.results.length, first_flagged: r.results[0].flagged, second_flagged: r.results[1].flagged };
});

writeResults("04-moderations");
