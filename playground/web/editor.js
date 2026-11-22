// Lightweight, dependency-free Luau editor: a transparent <textarea> over a
// highlighted <pre>. The two stay pixel-aligned (same font/size/padding/scroll).

const KEYWORDS = new Set([
  "local", "function", "if", "then", "else", "elseif", "end", "for", "in",
  "do", "while", "repeat", "until", "return", "break", "continue",
  "and", "or", "not", "nil", "true", "false",
]);

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Tokenize a chunk of Luau into highlighted HTML. Robust: never throws.
export function highlight(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  const span = (cls, text) => `<span class="tok-${cls}">${escapeHtml(text)}</span>`;

  while (i < n) {
    const c = src[i];

    // long bracket [[ ... ]] / [=[ ... ]=] (string or comment prefix handled below)
    // comments
    if (c === "-" && src[i + 1] === "-") {
      let j = i + 2;
      // long comment --[[ ... ]] / --[=[ ... ]=]
      const lb = matchLongBracketOpen(src, j);
      if (lb >= 0) {
        const close = findLongBracketClose(src, lb, j);
        const end = close < 0 ? n : close;
        out += span("comment", src.slice(i, end));
        i = end;
        continue;
      }
      let k = j;
      while (k < n && src[k] !== "\n") k++;
      out += span("comment", src.slice(i, k));
      i = k;
      continue;
    }

    // long string [[ ... ]]
    if (c === "[") {
      const lvl = matchLongBracketOpen(src, i);
      if (lvl >= 0) {
        const close = findLongBracketClose(src, lvl, i);
        const end = close < 0 ? n : close;
        out += span("string", src.slice(i, end));
        i = end;
        continue;
      }
    }

    // quoted strings
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === c || src[j] === "\n") { j++; break; }
        j++;
      }
      out += span("string", src.slice(i, j));
      i = j;
      continue;
    }

    // numbers (hex, decimal, float, exponent, underscores)
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(src[i + 1] || ""))) {
      let j = i;
      if (c === "0" && (src[j + 1] === "x" || src[j + 1] === "X")) {
        j += 2;
        while (j < n && /[0-9a-fA-F_]/.test(src[j])) j++;
      } else {
        while (j < n && /[0-9a-fA-F_.xXeEpP+-]/.test(src[j])) {
          // stop a trailing +/- that is not part of an exponent
          if ((src[j] === "+" || src[j] === "-") && !/[eEpP]/.test(src[j - 1])) break;
          j++;
        }
      }
      out += span("number", src.slice(i, j));
      i = j;
      continue;
    }

    // identifiers / keywords / BASIL_* macros
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j);
      if (word.startsWith("BASIL_") || word === "BASILISK_RUNTIME_KEY") {
        out += span("macro", word);
      } else if (KEYWORDS.has(word)) {
        out += span("keyword", word);
      } else {
        out += escapeHtml(word);
      }
      i = j;
      continue;
    }

    // punctuation / whitespace / anything else
    out += escapeHtml(c);
    i++;
  }
  return out;
}

// If src[pos] opens a long bracket ("[", then zero+ "=", then "["), return the
// level (number of "="); otherwise -1.
function matchLongBracketOpen(src, pos) {
  if (src[pos] !== "[") return -1;
  let j = pos + 1;
  let eq = 0;
  while (src[j] === "=") { eq++; j++; }
  return src[j] === "[" ? eq : -1;
}

// Find index just past the matching close "]" + eq "=" + "]" for a long bracket
// opened at `pos` with level `lvl`; -1 if unterminated.
function findLongBracketClose(src, lvl, pos) {
  const needle = "]" + "=".repeat(lvl) + "]";
  const from = pos + 2 + lvl;
  const idx = src.indexOf(needle, from);
  return idx < 0 ? -1 : idx + needle.length;
}

export function createEditor(container, { readOnly = false, value = "" } = {}) {
  container.classList.add("editor");
  if (readOnly) container.classList.add("editor--readonly");

  const gutter = document.createElement("div");
  gutter.className = "editor__gutter";
  gutter.setAttribute("aria-hidden", "true");
  const gutterInner = document.createElement("div");
  gutterInner.className = "editor__gutter-inner";
  gutter.appendChild(gutterInner);

  const sel = document.createElement("div");
  sel.className = "editor__sel";
  sel.setAttribute("aria-hidden", "true");

  const pre = document.createElement("pre");
  pre.className = "editor__pre";
  pre.setAttribute("aria-hidden", "true");
  const code = document.createElement("code");
  pre.appendChild(code);

  const ta = document.createElement("textarea");
  ta.className = "editor__ta";
  ta.spellcheck = false;
  ta.autocapitalize = "off";
  ta.autocomplete = "off";
  ta.setAttribute("autocorrect", "off");
  ta.setAttribute("wrap", "off");
  if (readOnly) ta.readOnly = true;

  container.appendChild(gutter);
  container.appendChild(sel);
  container.appendChild(pre);
  container.appendChild(ta);

  let selOk = true;
  function nodeAt(root, offset) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let acc = 0;
    let node = null;
    while ((node = walker.nextNode())) {
      const len = node.nodeValue.length;
      if (offset <= acc + len) return [node, offset - acc];
      acc += len;
    }
    return [root, 0];
  }
  function renderSelection() {
    if (!selOk) return;
    const s = ta.selectionStart;
    const e = ta.selectionEnd;
    if (s === e) {
      sel.textContent = "";
      return;
    }
    try {
      const [n1, o1] = nodeAt(code, s);
      const [n2, o2] = nodeAt(code, e);
      const range = document.createRange();
      range.setStart(n1, o1);
      range.setEnd(n2, o2);
      const box = container.getBoundingClientRect();
      const pitch = parseFloat(getComputedStyle(pre).lineHeight);
      let html = "";
      for (const r of range.getClientRects()) {
        if (r.width < 0.5) continue;
        const h = pitch > 0 ? pitch : r.height;
        const x = r.left - box.left;
        const y = (r.top + r.bottom) / 2 - box.top - h / 2;
        html +=
          '<div class="editor__sel-rect" style="transform:translate(' +
          x + "px," + y + "px);width:" + r.width + "px;height:" + h + 'px"></div>';
      }
      sel.innerHTML = html;
    } catch (_e) {
      selOk = false;
      sel.textContent = "";
      container.classList.add("editor--native-sel");
    }
  }

  let lastLines = -1;
  function renderGutter() {
    let n = 1;
    const v = ta.value;
    for (let i = 0; i < v.length; i++) if (v.charCodeAt(i) === 10) n++;
    if (n === lastLines) return;
    lastLines = n;
    let s = "";
    for (let i = 1; i <= n; i++) s += i + "\n";
    gutterInner.textContent = s;
    container.style.setProperty("--gutter-w", String(n).length + "ch");
  }
  function render() {
    // trailing newline keeps the last line scrollable/visible
    code.innerHTML = highlight(ta.value + "\n");
    renderGutter();
  }
  function syncScroll() {
    pre.scrollTop = ta.scrollTop;
    pre.scrollLeft = ta.scrollLeft;
    gutterInner.style.transform = "translateY(" + -ta.scrollTop + "px)";
    renderSelection();
  }

  ta.addEventListener("input", () => { render(); syncScroll(); });
  ta.addEventListener("scroll", syncScroll);
  ta.addEventListener("select", renderSelection);
  ta.addEventListener("keyup", renderSelection);
  ta.addEventListener("pointerup", renderSelection);
  document.addEventListener("selectionchange", () => {
    if (document.activeElement === ta) renderSelection();
  });

  ta.value = value;
  render();

  return {
    el: container,
    textarea: ta,
    get value() { return ta.value; },
    set value(v) { ta.value = v; render(); ta.scrollTop = 0; ta.scrollLeft = 0; syncScroll(); },
    focus() { ta.focus(); },
  };
}
