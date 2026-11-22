// Module worker: runs the real Basilisk engine (WASM) off the main thread.
import init, { obfuscate, version } from "./pkg/basilisk_wasm.js";

let ready = null;
function ensureReady() {
  if (!ready) ready = init();
  return ready;
}

self.onmessage = async (ev) => {
  const { id, source, options } = ev.data || {};
  try {
    await ensureReady();
    const raw = obfuscate(source, JSON.stringify(options));
    const result = JSON.parse(raw);
    self.postMessage({ id, result, engineVersion: safeVersion() });
  } catch (e) {
    self.postMessage({
      id,
      result: { ok: false, error: String((e && e.message) || e) },
    });
  }
};

function safeVersion() {
  try {
    return version();
  } catch {
    return null;
  }
}
