# Basilisk macros

`BASIL_*` macros let a Luau script opt into specific Basilisk behaviours from its own
source. They are recognised by the frontend, expanded **before** bytecode compilation, and
every macro name is stripped from the generated artifact. Most are always available and act
only where they appear in your source; two native-escape markers additionally require a CLI
flag.

The implementation is authoritative. If this document and the source ever disagree, the
source wins (`crates/frontend/src/`).

## How macros are processed

1. You write the macro in your source (optionally pasting `runtime/basil_sdk.luau` at the top
   so the script also runs unchanged under plain `luau` during development, see
   [Development SDK](#development-sdk)).
2. During a build, the frontend expands every macro into real IR **before** the IR is lowered
   to bytecode and virtualized. Macro expansion is not source-text substitution.
3. Every `BASIL_` name is removed from the artifact. A bare `BASIL_`-prefixed identifier that
   is **not** a recognised macro is a hard build error (`... uses the reserved BASIL_ prefix
   but is not a recognized macro`), so misspellings fail loudly instead of leaking.

Each entry below lists the macro's **placement** (statement position, expression position, or
first-statement directive) and any compilation constraints. A source that does not use a given
macro builds byte-identically to one that never had it.

## Built-in vs. opt-in

- **Built-in (always available):** no CLI flag. Works wherever the macro appears.
- **Explicit opt-in:** recognised only with `--experimental-explicit-optin`. If one of these
  markers is present **without** the flag, the build fails closed (it is never silently
  ignored). The two opt-in markers are `BASIL_NATIVE_LEAF` and `BASIL_PRIVATE_SCAN`.

"Reduces protection" below means the selected code ships as **ordinary native plaintext Luau**
and no longer runs inside the VM. That is a deliberate speed/compatibility trade, not a
stronger form of protection.

## Quick reference

| Macro | Purpose | Placement | Availability |
|---|---|---|---|
| `BASIL_CRASH` | Terminal silent halt of the whole invocation | statement call | built-in |
| `BASIL_OPAQUE` | Turn a `true`/`false` literal into an opaque predicate | expression | built-in |
| `BASIL_OPCODE` | Emit a semantics-neutral seed-polymorphic VM opcode bundle | statement | built-in |
| `BASIL_STACKALLOC` | Fixed-size frame-register scratch array (no table allocation) | expression (local binding) | built-in |
| `BASIL_INLINE` | Inline a small capture-free helper at its call sites | expression (local binding) | built-in |
| `BASIL_ATTRIBUTES` | First-statement directives: `INLINE` / `VM(...)` / `ENCRYPT` / `UNROLL` | first statement | built-in |
| `BASIL_ENCFUNC` | Seal a function body in an authenticated encrypted blob | expression | built-in |
| `BASIL_ENCFUNC_SEED` | `ENCFUNC` keyed by a numeric compile seed | expression | built-in |
| `BASIL_ENCSTR` / `BASIL_ENCBUF` / `BASIL_ENCNUM` | Seal a string / buffer / number | expression | built-in |
| `BASIL_PRECHECK` | Load-time check folded into the payload key | statement | built-in |
| `BASIL_HASH` | SHA-256 of a string (compile-time or via native helper) | expression | built-in |
| `BASIL_LINE` | The source line number of the call site | expression | built-in |
| `BASIL_OBFUSCATED` | Compile-time flag, always `true` in a build | bare identifier | built-in |
| `BASIL_NO_VIRTUALIZE` | Ship a function body as native plaintext (**reduces protection**) | expression | built-in |
| `BASIL_NATIVE_LEAF` | Extract one validated helper as native plaintext (**reduces protection**) | statement | opt-in flag |
| `BASIL_PRIVATE_SCAN` | Restructure a scan idiom; matcher becomes native plaintext (**reduces protection**) | statement | opt-in flag |

---

## Core protection macros

### `BASIL_CRASH`

Terminal fail-closed sink: halts the entire virtualized invocation when reached.

```lua
if tamperDetected() then BASIL_CRASH() end
```

**Restrictions:** must be a direct call `BASIL_CRASH(...)`; any bare or indirect reference is a
reserved-name build error. Arguments are accepted but ignored.

**Behaviour:** sets the VM-wide `dead` flag so the dispatch loop returns; unwinds all parent
frames and is not recoverable by `pcall`/`xpcall`. It terminates within a bounded time. It
does **not** hang, throw a host error, print a stack trace, or crash the host process. It is
not anti-tamper (deleting the single shared handler bypasses it). Use `BASIL_CRASH` only to
stop unconditionally.

### `BASIL_OPAQUE`

Expands a boolean literal into a seed-varied opaque predicate that evaluates to the same value
but resists constant-folding.

```lua
if BASIL_OPAQUE(true) and authorized then grant() end
```

**Restrictions:** exactly one argument, which must be the bare literal `true` or `false`.
Static-analysis surface friction only (one of four seed-chosen comparison shapes), small added
bytecode, semantics-preserving. Stays virtualized.

### `BASIL_OPCODE`

Statement macro `BASIL_OPCODE("FAMILY"[, intensity])` emits a semantics-neutral, seed-
polymorphic bundle of real VM instructions from the requested family at that point,
static/analysis friction only, never changing program behaviour.

```lua
BASIL_OPCODE("CALL", 3)
```

**Restrictions:** family is one of `MOVE` / `LOADK` / `CALL` / `EQ` / `LT` / `LE` / `CONCAT`;
optional intensity `1..8`. Family and intensity must be literals (dynamic values are rejected).
Statement position only. Uses compiler-owned scratch registers and goes through the normal
bytecode/integrity pipeline. Rejected inside `BASIL_NO_VIRTUALIZE`.

---

## Data / structure macros

### `BASIL_STACKALLOC`

Reserves a fixed-size, function-local scratch array in the VM frame's registers instead of a
heap table. It does **not** lower to `{}` / `table.create(n)` / any per-allocation table; each
slot is a distinct frame local, and a static index compiles to a direct register read/write.

```lua
local v = BASIL_STACKALLOC(4)
v[1] = a  v[2] = b
local s = v[1] + v[2]
```

**Restrictions:** compile-time integer size `1..=64`; exactly one local; **static integer
indices only** (a dynamic/loop index `v[i]` is a hard error; there is no runtime table to
index); `#v` is the declared size; `v:clear/pack/unpack(...)` are the only methods. The
allocation cannot escape (bare use, return, store, pass, reassign, field access, shadow, or
nested-function capture are hard errors). A performance/allocation lever, not secrecy.

---

## Performance / size macros

### `BASIL_INLINE`

Inlines one small capture-free, non-recursive local helper at every call site and deletes its
proto. A performance/size lever; the inlined body stays virtualized.

```lua
local add = BASIL_INLINE(function(a, b) return a + b end)
local r = add(2, 3)
```

**Restrictions:** exactly one function literal bound to exactly one local. The helper must be
capture-free (no enclosing-local reads), non-recursive, and have a single terminal `return` of
one value (or be void); varargs and multi-value returns are rejected. Every use must be a
**direct call** in a supported site (`f(x)` statement, `local r = f(x)`, `r = f(x)`, or a sole
`return f(x)`); storing, aliasing, comparing, passing as a callback, or `f:m()`/`f.x` is a hard
build error.

### `BASIL_ATTRIBUTES`

A structured **first-statement** directive that annotates the function or numeric-for loop it
opens. It is a real IR transform that lowers into the existing macro mechanisms (the same
inliner, native-escape and authenticated-sealing backends), so it adds no new backend. Every
attribute name is stripped before bytecode.

```lua
local function f(a, b)
    BASIL_ATTRIBUTES(INLINE(), VM(PROTECTED))
    return a + b
end

for i = 1, 8 do
    BASIL_ATTRIBUTES(UNROLL())
    sum = sum + values[i]
end
```

**Attributes:** `INLINE()` (→ `BASIL_INLINE`), `VM(PROTECTED)` (default, no-op), `VM(NONE)`
(→ `BASIL_NO_VIRTUALIZE`, native plaintext), `ENCRYPT(key, runtimeKey)` (→ `BASIL_ENCFUNC`,
AEAD-sealed), and `UNROLL()` / `UNROLL(false)` on a numeric-for body. The inner names
(`INLINE`/`VM`/`NONE`/`PROTECTED`/`ENCRYPT`/`UNROLL`) are recognised **only inside**
`BASIL_ATTRIBUTES(...)`; ordinary identifiers of those names elsewhere are untouched.

**Restrictions:** must be the first statement of the annotated body; the annotated function
must be a single-local binding (`local function f` / `local f = function`), never a global or
method form. Incompatible pairs (`VM(NONE)`+`ENCRYPT`, `VM(NONE)`+`INLINE`, `INLINE`+`ENCRYPT`),
duplicate attributes, unknown attributes, a misplaced directive, a recursive attributed
function, and mixing loop/function attributes are hard build errors. `UNROLL` requires compile-
time-constant integer bounds and is bounded by a cost model (trip ≤ 64, trip×body ≤ 256); it is
the only way to request loop unrolling.

---

## Sealed function / value protection

### `BASIL_ENCFUNC`

Seals one function literal into an authenticated (ChaCha20 + HMAC) encrypted blob that
materialises only when a runtime-supplied key authenticates; the compile key never ships in the
artifact.

```lua
local f = BASIL_ENCFUNC(function(a, b) return a + b end,
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",  -- 64-hex compile key
    runtimeKey)                                                          -- a runtime value
```

**Restrictions:** exactly 3 args: (1) a function **literal**, (2) a constant 64-hex string
literal compile key that must not appear in any other string constant, (3) a runtime key that
must be a genuine runtime value (a literal or literal-derived expression is rejected). The
sealed body must be a **leaf** (no enclosing-
local capture); nested functions are allowed only if provably confined; escaping closures are
rejected. Bounded synchronous callbacks (`pcall`, `xpcall`, `table.sort`, `string.gsub`) are
allowed. `BASIL_NO_VIRTUALIZE` inside a sealed body is refused, and `ENCFUNC` cannot nest inside
another `ENCFUNC`.

**Runtime:** a wrong, missing, tampered, or replayed key fails AEAD authentication before
decryption; nothing materialises and no child side effect runs. The host supplies the runtime
key via a global the artifact reads (e.g. `BASILISK_RUNTIME_KEY`).

### `BASIL_ENCFUNC_SEED`

Identical sealing to `BASIL_ENCFUNC`, keyed by a **numeric compile seed** instead of a hex
string; the VM derives the actual key at runtime via the same KDF and AEAD.

```lua
local f = BASIL_ENCFUNC_SEED(function(a, b) return a + b end, 1234567890123456, runtimeSeed)
```

**Restrictions:** exactly 3 args: (1) a function literal, (2) a numeric integer literal seed in
`[0, 2^53-1]`, (3) a runtime-sourced seed (literals/literal-derived are rejected). All the leaf,
escape, ownership, callback-allowlist, no-nesting and no-`NO_VIRTUALIZE` rules of `BASIL_ENCFUNC`
apply. The numeric seed is a key-source convenience, not a different protection level.

### `BASIL_ENCSTR` / `BASIL_ENCBUF` / `BASIL_ENCNUM`

Seal a string, buffer, or number into an authenticated blob. They **desugar into the
`BASIL_ENCFUNC` AEAD path** (the value is sealed inside a function that returns it), so they
inherit its ChaCha20 + HMAC, per-slot nonce and fail-closed behaviour; no plaintext copy ships.

```lua
local s = BASIL_ENCSTR("license-template")                      -- one-arg (isolated, self-keyed)
local s = BASIL_ENCSTR("secret", "…64hex…", runtimeKey)         -- externally keyed
local b = BASIL_ENCBUF("\0\1\255")                              -- -> Luau buffer, byte-exact
local n = BASIL_ENCNUM(4242, { [hwid()] = 7 })                  -- runtime-bound (1..8 bindings)
```

**Forms:** `ENCSTR`/`ENCBUF` take one string literal, or `(literal, compileKey, runtimeKey)`
where the compile key is a 64-hex string literal; `ENCNUM` takes
one numeric literal, or `(literal, { [runtimeExpr] = expectedInteger, … })`.

**Security (precise):** ordinary constants are *already* encrypted; these are not "make
plaintext secret". The **one-arg** form gives an isolated, authenticated, fail-closed value but
no external secret (its key is derivable from what the artifact must ship to run; friction /
isolation only). The **external-key** form ships no compile key and authenticates only under a
correct runtime key (ENCFUNC strength). The **runtime-bound** `ENCNUM` folds the runtime
observations into the seal key, so wrong values fail authenticated materialisation. All forms
fail closed (`dead`), keep no plaintext cache, and materialise use-locally. `ENCBUF` needs Luau
`buffer` support.

### `BASIL_PRECHECK`

A statement macro `BASIL_PRECHECK(function() … end, expected)` that runs an owner-authored
no-parameter check at load time and folds its integer result into the payload-release key
**before** any protected constant materialises. It is **load-bearing, not a branch**: a correct
result is zero-on-success (the derived key is byte-identical to a no-precheck build); a wrong
result corrupts the whole key → constant authentication → the `dead` fail-closed path. The check
callback runs natively (before the VM), so its logic is plaintext.

```lua
BASIL_PRECHECK(function() return hwidHash() end, 305419896)
```

**Restrictions:** statement position; inline no-parameter callback returning integer(s);
`expected` is an integer literal or a `{ int, … }` list (1..=8); no `BASIL_*` macro inside the
callback. Runtime binding + fail-closed gating, not external secrecy (the expected value is
build-known).

---

## Native / plaintext escape

These emit selected code as **ordinary native Luau in cleartext**; it runs outside the VM and
receives **less** protection. Use them only for hot, non-sensitive, author-chosen logic. None is
auto-inferred by any wizard mode.

### `BASIL_NO_VIRTUALIZE`

Always available (no CLI flag). Pulls one function literal out of the VM and ships it as a native
closure with ordinary Luau lexical-closure semantics, except its body runs plaintext.

```lua
local fast = BASIL_NO_VIRTUALIZE(function(x) return x * 2 end)
```

**Captures:** enclosing locals are captured with normal closure semantics; reassigned/shared
captures preserve lexical aliasing through an internal cell; a captured virtualized helper is
passed as a callable value and stays virtualized. Capture-free bodies are byte-identical to
earlier builds. **Restrictions:** the argument must be an inline function **literal**; exactly
one argument; no `BASIL_*` macro inside the body; cannot appear inside a `BASIL_ENCFUNC`. Body
string/number literals ship in cleartext; identifiers are renamed only with
`--strip-source-names`.

### `BASIL_NATIVE_LEAF`  *(requires `--experimental-explicit-optin`)*

A statement-position marker naming one whole function binding to extract as native plaintext.

```lua
BASIL_NATIVE_LEAF(FindInTable)
```

**Restrictions:** exactly one bare binding name resolving to a single, non-reassigned function.
The body must pass the native-leaf validator: non-variadic, no nested closure, not recursive, no
enclosing-local capture, no writes outside its own locals, no encrypted/crash/guard/native node,
and no high-confidence secret literal. A present marker without the flag aborts the build; any
unmet clause fails closed and leaves the module unmutated.

### `BASIL_PRIVATE_SCAN`  *(requires `--experimental-explicit-optin`)*

A statement-position marker describing a producer → scalar → matcher scan idiom by three
bindings: the shared scalar becomes a private state cell and the matcher predicate is extracted
native.

```lua
BASIL_PRIVATE_SCAN(IndexContents, topCommand, Match)
```

**Restrictions:** exactly three bare names: producer (function), scalar (chunk-level local, one
declaration), matcher (function). The matcher must independently pass the full native-leaf
validator. The producer must read and write the scalar; exactly one read-only consumer may also
read it, and no other function may write it. Producer and consumer stay virtualized; only the
matcher becomes plaintext. Fails closed on any unmet clause or a missing flag.

---

## Utility macros

### `BASIL_HASH`

SHA-256 of its one string argument. A **string literal** is hashed at compile time and baked as a
normal (encrypted) constant; a **runtime string** is hashed by a shared native SHA-256 helper.

```lua
if BASIL_HASH(key) == BASIL_HASH("alpha-license-7741") then ok() end
```

**Restrictions:** exactly one argument; non-string literals are rejected; indirect use is a
reserved-name error. The digest is deterministic and seed-independent. Literal args are unescaped
before hashing so compile-time and runtime digests match. Allowed inside `BASIL_ENCFUNC`.

### `BASIL_LINE`

Resolves at lowering time to the source line number of the call, as a plain numeric constant.

```lua
local ln = BASIL_LINE()
```

**Restrictions:** must be called with no arguments. The value follows `--line-info`: the source
line when on, `0` when off (off is the executor default). Semantics-only; no security effect.

### `BASIL_OBFUSCATED`

A bare compile-time identifier that always folds to `true` in a Basilisk build, used to strip
dev-only fallback stubs. It is a name, not a call.

```lua
if not BASIL_OBFUSCATED then
    BASIL_CRASH = function() end   -- dev stub, dropped in a real build
end
```

**Behaviour:** folded to `true` before expansion; constant-true `if`/`elseif` arms are promoted
and dead arms dropped (the kept branch becomes a `do` block so its locals don't leak).
Semantics-only, zero runtime cost. It enables unobfuscated fallbacks for `BASIL_*` names during
development while the reserved-prefix check still catches genuine misspellings.

---

## Interaction rules

- **Inside `BASIL_ENCFUNC` / `BASIL_ENCFUNC_SEED`:** `CRASH`, `HASH`, `OPAQUE` and `LINE` are
  allowed. `BASIL_NO_VIRTUALIZE` inside a sealed body is refused, and `ENCFUNC` cannot nest
  inside another `ENCFUNC`.
- **`--roundtrip` does not expand macros:** `BASIL_OPAQUE` appears verbatim in round-trip
  output.

## No macro makes plaintext more secure

No macro makes code *more* secure by emitting plaintext, and none provides runtime-plaintext
secrecy against an instrumented executor. The native-escape macros (`NO_VIRTUALIZE`,
`NATIVE_LEAF`, `PRIVATE_SCAN`) are speed/compatibility trades that **reduce** protection for the
chosen body.

## Common errors

```lua
local a, b = BASIL_INLINE(function() end)  -- error: must bind exactly one local
BASIL_ENCFUNC(fn, "..", "literal-key")     -- error: runtime key must be a runtime value
BASIL_NATIVE_LEAF(Helper)                  -- error without --experimental-explicit-optin
local h = BASIL_HASH                       -- error: reserved name, must be called
```

Diagnostics name the macro, the binding, and why rewriting would change semantics.

## Development SDK

`runtime/basil_sdk.luau` is a paste-at-the-top passthrough SDK for local development. It defines
the core stable `BASIL_*` macros (and the attribute tokens `INLINE`/`VM`/`ENCRYPT`/`UNROLL`/
`NONE`/`PROTECTED`) as transparent no-ops/passthroughs, so a script runs unchanged under plain
`luau`. The whole block is guarded by `if not BASIL_OBFUSCATED then … end`, so a Basilisk build
folds `BASIL_OBFUSCATED` to `true` and dead-eliminates it; nothing in the SDK reaches the
artifact. It covers the core stable surface only; the opt-in native-escape markers
(`BASIL_NATIVE_LEAF` / `BASIL_PRIVATE_SCAN`) are intentionally omitted.

## Source references

For maintainers, the primary modules are under `crates/frontend/src/`: the macro recogniser and
core macros in `macros.rs`; `BASIL_LINE` in `lower.rs`; `attributes.rs`, `inline.rs`,
`stackalloc.rs`, `precheck.rs`, `encval.rs`
(`ENCSTR`/`ENCBUF`/`ENCNUM`), `encfunc_escape.rs`, and the native-escape opt-in in `optin.rs` /
`audit.rs`.
