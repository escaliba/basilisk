import { createEditor } from "./editor.js";
import { DEFAULT_SAMPLE, SAMPLES, MACROS } from "./samples.js";

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const byteLen = (s) => enc.encode(s).length;

const input = createEditor($("input-editor"), { value: DEFAULT_SAMPLE });
const output = createEditor($("output-editor"), { readOnly: true, value: "" });

// ---- Worker orchestration (with hung-worker recovery) --------------------
let worker = null;
let reqId = 0;
let pending = null; // { id, timer, startedAt }
const TIMEOUT_MS = 10000;

function spawnWorker() {
  worker = new Worker("./worker.js", { type: "module" });
  worker.onmessage = (ev) => {
    const { id, result, engineVersion } = ev.data || {};
    if (engineVersion) setEngineVersion(engineVersion);
    if (!pending || id !== pending.id) return; // stale
    const elapsed = Math.max(0, Math.round(performance.now() - pending.startedAt));
    clearTimeout(pending.timer);
    const p = pending;
    pending = null;
    finish(result, elapsed, p);
  };
  worker.onerror = (e) => {
    if (!pending) return;
    clearTimeout(pending.timer);
    const p = pending;
    pending = null;
    finish({ ok: false, error: "worker error: " + (e.message || "failed to load engine") }, 0, p);
  };
}

function resetWorker() {
  try { if (worker) worker.terminate(); } catch {}
  spawnWorker();
}

function obfuscate() {
  if (pending) return; // one at a time
  const source = input.value;
  const options = currentOptions();
  const id = ++reqId;
  setBusy(true);
  clearError();
  const startedAt = performance.now();
  const timer = setTimeout(() => {
    if (!pending || pending.id !== id) return;
    const p = pending;
    pending = null;
    resetWorker();
    finish({ ok: false, error: "obfuscation timed out; the worker was reset. try a smaller input or fewer options." }, TIMEOUT_MS, p);
  }, TIMEOUT_MS);
  pending = { id, timer, startedAt, inputBytes: byteLen(source), seed: options.seed };
  if (!worker) spawnWorker();
  worker.postMessage({ id, source, options });
}

function finish(result, elapsed, p) {
  setBusy(false);
  if (result && result.ok) {
    output.value = result.output;
    setStats({
      inputBytes: p.inputBytes,
      outputBytes: byteLen(result.output),
      elapsed,
      seed: p.seed,
    });
  } else {
    output.value = "";
    setStats({ inputBytes: p.inputBytes, outputBytes: 0, elapsed, seed: p.seed });
    showError((result && result.error) || "unknown error");
  }
}

// ---- Options / presets ---------------------------------------------------
const TOGGLES = ["flatten", "opaque", "junk", "fuse", "minify", "compress"];

function currentOptions() {
  const o = { seed: readSeed(), shell: $("shell").value };
  for (const t of TOGGLES) o[t] = $("opt-" + t).checked;
  return o;
}

function readSeed() {
  const v = parseInt($("seed").value, 10);
  if (!Number.isFinite(v) || v < 0) return 1;
  return v;
}

function applyPreset(name) {
  const set = (obj) => {
    for (const t of TOGGLES) $("opt-" + t).checked = !!obj[t];
  };
  if (name === "minimal") set({});
  else if (name === "balanced") set({ flatten: true, opaque: true, fuse: true, minify: true });
  else if (name === "maximum") set({ flatten: true, opaque: true, junk: true, fuse: true, minify: true });
}

// ---- Stats / errors ------------------------------------------------------
function setStats({ inputBytes, outputBytes, elapsed, seed }) {
  $("stat-in").textContent = fmtBytes(inputBytes);
  $("stat-out").textContent = outputBytes ? fmtBytes(outputBytes) : "·";
  $("stat-ratio").textContent =
    outputBytes && inputBytes ? (outputBytes / inputBytes).toFixed(1) + "×" : "·";
  $("stat-time").textContent = elapsed + " ms";
  $("stat-seed").textContent = String(seed);
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(2) + " MB";
}

function showError(msg) {
  const el = $("error-panel");
  el.textContent = msg;
  el.hidden = false;
}
function clearError() {
  const el = $("error-panel");
  el.hidden = true;
  el.textContent = "";
}

function setBusy(busy) {
  const btn = $("run");
  btn.disabled = busy;
  btn.textContent = busy ? "working…" : "obfuscate";
  document.body.classList.toggle("is-busy", busy);
}

function setEngineVersion(v) {
  const el = $("engine-version");
  if (el && v) el.textContent = "engine v" + v;
}

// ---- Download / copy -----------------------------------------------------
function download(ext) {
  const text = output.value;
  if (!text) return;
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "obfuscated." + ext;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const TICK_SVG =
  '<svg class="tick" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">' +
  '<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
  'stroke-linejoin="round" d="M3.5 8.5l3 3 6-7"/></svg>';

async function copyOutput() {
  const text = output.value;
  if (!text) return;
  const btn = $("copy");
  if (btn.dataset.state) return;
  let ok = true;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    ok = false;
  }
  btn.dataset.state = ok ? "done" : "err";
  btn.innerHTML = ok ? TICK_SVG : "failed";
  setTimeout(() => {
    btn.dataset.state = "";
    btn.textContent = "copy";
  }, 1400);
}

function resetAll() {
  input.value = DEFAULT_SAMPLE;
  output.value = "";
  clearError();
  setStats({ inputBytes: byteLen(DEFAULT_SAMPLE), outputBytes: 0, elapsed: 0, seed: readSeed() });
  input.focus();
}

// ---- Dropdown population -------------------------------------------------
function fillSelect(sel, items, placeholder) {
  const ph = document.createElement("option");
  ph.value = "";
  ph.textContent = placeholder;
  sel.appendChild(ph);
  items.forEach((it, i) => {
    const o = document.createElement("option");
    o.value = String(i);
    o.textContent = it.name;
    sel.appendChild(o);
  });
}

// ---- Wire up -------------------------------------------------------------
function init() {
  fillSelect($("sample"), SAMPLES, "Load a sample…");
  fillSelect($("macro"), MACROS, "Load a macro example…");

  $("sample").addEventListener("change", (e) => {
    const i = e.target.value;
    if (i !== "") { input.value = SAMPLES[+i].source; clearError(); }
    e.target.value = "";
    input.focus();
  });
  $("macro").addEventListener("change", (e) => {
    const i = e.target.value;
    if (i !== "") { input.value = MACROS[+i].source; clearError(); }
    e.target.value = "";
    input.focus();
  });

  $("run").addEventListener("click", obfuscate);
  $("copy").addEventListener("click", copyOutput);
  $("clear").addEventListener("click", resetAll);
  $("dl-lua").addEventListener("click", () => download("lua"));
  $("rand-seed").addEventListener("click", () => {
    $("seed").value = String(1 + Math.floor(Math.random() * 0x7fffffff));
  });
  document.querySelectorAll("[data-preset]").forEach((b) =>
    b.addEventListener("click", () => applyPreset(b.dataset.preset))
  );

  // Ctrl/Cmd+Enter obfuscates from anywhere
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      obfuscate();
    }
  });

  setStats({ inputBytes: byteLen(DEFAULT_SAMPLE), outputBytes: 0, elapsed: 0, seed: readSeed() });
  spawnWorker(); // warm the engine (also surfaces load errors early)
}

init();
