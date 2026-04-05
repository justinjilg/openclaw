// 06: Audio — TTS and Transcription
import { portkey, test, writeResults } from "./00-setup.mjs";

console.log("\n═══ 06: Audio ═══\n");

await test("audio.speech.create (TTS)", async () => {
  const r = await portkey.audio.speech.create({
    model: "tts-1",
    voice: "alloy",
    input: "Hello world",
  });
  // Response is a readable stream / buffer
  const chunks = [];
  const reader = r.body.getReader();
  let done = false;
  while (!done) {
    const { value, done: d } = await reader.read();
    if (value) chunks.push(value);
    done = d;
  }
  const totalBytes = chunks.reduce((s, c) => s + c.length, 0);
  return { bytes: totalBytes, has_audio: totalBytes > 1000 };
});

await test("audio.transcriptions.create (whisper)", async () => {
  // We need an audio file — create a tiny one or skip if no file available
  // For now, test that the endpoint exists and returns proper error for missing file
  try {
    const r = await portkey.audio.transcriptions.create({
      model: "whisper-1",
      file: new Blob(["not real audio"], { type: "audio/mp3" }),
    });
    return r.text;
  } catch (e) {
    // Expected to fail with invalid audio, but endpoint should exist
    if (e.message.includes("Invalid file format") || e.message.includes("audio")) {
      return "endpoint_exists_but_invalid_audio";
    }
    throw e;
  }
});

writeResults("06-audio");
