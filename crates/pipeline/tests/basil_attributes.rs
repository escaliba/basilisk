use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_attr_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
    Command::new("luau")
        .arg("--version")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

const SHIM: &str = "if not BASIL_OBFUSCATED then\n\
     BASIL_ATTRIBUTES = function(...) end\n\
     INLINE = function(...) end\n\
     VM = function(...) end\n\
     ENCRYPT = function(...) end\n\
     UNROLL = function(...) end\n\
     NONE = 0\n\
     PROTECTED = 1\n\
     end\n";

fn src(body: &str) -> String {
    format!("{SHIM}{body}\n")
}

fn build(s: &str, seed: u64) -> Result<String, String> {
    let s = s.to_string();
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_with(&s, seed, true, true, true, true, true, false, false)
                .map_err(|e| format!("{e:#}"))
        })
        .unwrap()
        .join()
        .unwrap()
}

fn run(luau: &str, text: &str, tag: &str, key: Option<&str>) -> String {
    let p = tmp(tag);
    let mut full = String::new();
    if let Some(k) = key {
        full.push_str(&format!("BASILISK_RUNTIME_KEY = \"{k}\"\n"));
    }
    full.push_str(text);
    std::fs::write(&p, &full).unwrap();
    let o = Command::new(luau).arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
    .trim()
    .to_string()
}

fn no_markers(tag: &str, art: &str) {
    for m in [
        "BASIL_ATTRIBUTES",
        "BASIL_INLINE",
        "BASIL_NO_VIRTUALIZE",
        "BASIL_ENCFUNC",
    ] {
        assert!(
            !art.contains(m),
            "[{tag}] no {m} marker may survive into the artifact"
        );
    }
}

fn accept(tag: &str, body: &str) -> String {
    let s = src(body);
    let art = build(&s, 305419896).unwrap_or_else(|e| panic!("[{tag}] must build, got: {e}"));
    no_markers(tag, &art);
    if let Some(luau) = find_luau() {
        let plain = run(&luau, &s, &format!("{tag}_plain"), None);
        let got = run(&luau, &art, &format!("{tag}_obf"), None);
        assert!(!plain.is_empty(), "[{tag}] fixture must print something");
        assert_eq!(got, plain, "[{tag}] attributed build must match plain Luau");
    }
    art
}

fn reject(tag: &str, body: &str) -> String {
    match build(&src(body), 42) {
        Ok(_) => panic!("[{tag}] must be REJECTED but the build succeeded"),
        Err(e) => e,
    }
}

#[test]
fn a01_vm_none_runs_like_plain() {
    accept(
        "vm_none",
        "local function dbl(x)\n\tBASIL_ATTRIBUTES(VM(NONE))\n\treturn x * 2\nend\nprint(dbl(21))",
    );
}

#[test]
fn a02_vm_protected_default_is_a_noop() {
    accept("vm_protected", "local function id(x)\n\tBASIL_ATTRIBUTES(VM(PROTECTED))\n\treturn x\nend\nprint(id(7), id(\"ok\"))");
}

#[test]
fn a03_inline_runs_like_plain() {
    accept("inline", "local function add(a, b)\n\tBASIL_ATTRIBUTES(INLINE())\n\treturn a + b\nend\nlocal r = add(2, 3)\nprint(r)");
}

#[test]
fn a04_inline_plus_vm_protected_ok() {
    accept("inline_protected", "local function sq(a)\n\tBASIL_ATTRIBUTES(INLINE(), VM(PROTECTED))\n\treturn a * a\nend\nlocal r = sq(6)\nprint(r)");
}

#[test]
fn a05_bound_anonymous_function_form() {
    accept(
        "bound_anon",
        "local dbl = function(x)\n\tBASIL_ATTRIBUTES(VM(NONE))\n\treturn x * 2\nend\nprint(dbl(9))",
    );
}

#[test]
fn a06_empty_attributes_is_a_noop() {
    accept(
        "empty",
        "local function f(x)\n\tBASIL_ATTRIBUTES()\n\treturn x + 1\nend\nprint(f(4))",
    );
}

#[test]
fn a10_vm_none_is_byte_identical_to_no_virtualize() {
    let attr =
        "local function dbl(x)\n\tBASIL_ATTRIBUTES(VM(NONE))\n\treturn x * 2\nend\nprint(dbl(5))\n";
    let direct = "local dbl = BASIL_NO_VIRTUALIZE(function(x) return x * 2 end)\nprint(dbl(5))\n";
    let a = build(attr, 305419896).expect("attr builds");
    let b = build(direct, 305419896).expect("direct builds");
    assert_eq!(
        a, b,
        "VM(NONE) attribute must desugar byte-identically to BASIL_NO_VIRTUALIZE"
    );
}

#[test]
fn a11_inline_is_byte_identical_to_basil_inline() {
    let attr = "local function add(a, b)\n\tBASIL_ATTRIBUTES(INLINE())\n\treturn a + b\nend\nlocal r = add(2, 3)\nprint(r)\n";
    let direct = "local add = BASIL_INLINE(function(a, b) return a + b end)\nlocal r = add(2, 3)\nprint(r)\n";
    let a = build(attr, 305419896).expect("attr builds");
    let b = build(direct, 305419896).expect("direct builds");
    assert_eq!(
        a, b,
        "INLINE() attribute must desugar byte-identically to BASIL_INLINE"
    );
}

#[test]
fn a20_encrypt_seals_and_authenticates() {
    let Some(luau) = find_luau() else { return };
    let body = format!(
        "local rk = BASILISK_RUNTIME_KEY\nlocal function sealed(n)\n\tBASIL_ATTRIBUTES(ENCRYPT(\"{KEY}\", rk))\n\treturn n * 2 + 1\nend\nprint(sealed(20))"
    );
    let art = build(&src(&body), 305419896).expect("encrypt attribute builds");
    no_markers("encrypt", &art);
    let ok = run(&luau, &art, "encrypt_ok", Some(KEY));
    assert!(
        ok.contains("41"),
        "correct key must materialize and run the sealed body; got {ok:?}"
    );
    let bad = run(
        &luau,
        &art,
        "encrypt_bad",
        Some("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"),
    );
    assert!(
        !bad.contains("41"),
        "a wrong key must fail closed; got {bad:?}"
    );
}

#[test]
fn a21_encrypt_extracts_one_encfunc() {
    let body = format!("local rk = BASILISK_RUNTIME_KEY\nlocal function sealed(n)\n\tBASIL_ATTRIBUTES(ENCRYPT(\"{KEY}\", rk))\n\treturn n + 1\nend\nprint(sealed(1))");
    let module = frontend::lower_str(&src(&body)).expect("lower");
    let module = frontend::macros::expand(module, 42).expect("expand");
    assert_eq!(
        module.encfuncs.len(),
        1,
        "ENCRYPT attribute must extract exactly one ENCFUNC"
    );
}

#[test]
fn a30_unroll_ascending_matches_plain() {
    accept("unroll_asc", "local acc = 0\nfor i = 1, 4 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tacc = acc + i\nend\nprint(acc)");
}

#[test]
fn a31_unroll_with_step_matches_plain() {
    accept("unroll_step", "local acc = 0\nfor i = 0, 10, 2 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tacc = acc + i\nend\nprint(acc)");
}

#[test]
fn a32_unroll_descending_matches_plain() {
    accept("unroll_desc", "local out = {}\nfor i = 5, 1, -1 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tout[#out + 1] = i\nend\nprint(table.concat(out, \",\"))");
}

#[test]
fn a33_unroll_preserves_per_iteration_closure_capture() {
    accept(
        "unroll_capture",
        "local fns = {}\nfor i = 1, 3 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tfns[i] = function() return i end\nend\nprint(fns[1](), fns[2](), fns[3]())",
    );
}

#[test]
fn a34_unroll_nested_loop_matches_plain() {
    accept(
        "unroll_nested",
        "local acc = 0\nfor i = 1, 3 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tfor j = 1, i do acc = acc + j end\nend\nprint(acc)",
    );
}

#[test]
fn a35_unroll_conditional_early_return_matches_plain() {
    accept(
        "unroll_ret",
        "local function first_ge(t)\n\tfor i = 1, 4 do\n\t\tBASIL_ATTRIBUTES(UNROLL())\n\t\tif t[i] >= 3 then return i end\n\tend\n\treturn -1\nend\nprint(first_ge({1, 2, 3, 4}), first_ge({9, 9, 9, 9}))",
    );
}

#[test]
fn a36_unroll_best_effort_keeps_nonconstant_loop() {
    accept(
        "unroll_besteffort",
        "local n = tonumber(\"3\")\nlocal acc = 0\nfor i = 1, n do\n\tBASIL_ATTRIBUTES(UNROLL(false))\n\tacc = acc + i\nend\nprint(acc)",
    );
}

#[test]
fn a37_unroll_zero_trips_matches_plain() {
    accept("unroll_zero", "local acc = 100\nfor i = 1, 0 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tacc = acc + i\nend\nprint(acc)");
}

#[test]
fn r01_unknown_attribute() {
    assert!(reject(
        "unknown",
        "local function f()\n\tBASIL_ATTRIBUTES(TURBO())\n\treturn 1\nend\nprint(f())"
    )
    .contains("unknown attribute"));
}

#[test]
fn r02_duplicate_vm() {
    assert!(reject("dup_vm", "local function f()\n\tBASIL_ATTRIBUTES(VM(NONE), VM(PROTECTED))\n\treturn 1\nend\nprint(f())").contains("duplicate"));
}

#[test]
fn r03_vm_none_with_encrypt() {
    let e = reject("none_encrypt", &format!("local rk = BASILISK_RUNTIME_KEY\nlocal function f()\n\tBASIL_ATTRIBUTES(VM(NONE), ENCRYPT(\"{KEY}\", rk))\n\treturn 1\nend\nprint(f())"));
    assert!(
        e.contains("VM(NONE) cannot be combined with ENCRYPT"),
        "got: {e}"
    );
}

#[test]
fn r04_inline_with_encrypt() {
    let e = reject("inline_encrypt", &format!("local rk = BASILISK_RUNTIME_KEY\nlocal function f()\n\tBASIL_ATTRIBUTES(INLINE(), ENCRYPT(\"{KEY}\", rk))\n\treturn 1\nend\nprint(f())"));
    assert!(
        e.contains("INLINE cannot be combined with ENCRYPT"),
        "got: {e}"
    );
}

#[test]
fn r05_vm_none_with_inline() {
    let e = reject(
        "none_inline",
        "local function f()\n\tBASIL_ATTRIBUTES(VM(NONE), INLINE())\n\treturn 1\nend\nprint(f())",
    );
    assert!(
        e.contains("VM(NONE) cannot be combined with INLINE"),
        "got: {e}"
    );
}

#[test]
fn r06_misplaced_not_first_statement() {
    let e = reject("misplaced", "local function f(x)\n\tlocal y = x + 1\n\tBASIL_ATTRIBUTES(VM(NONE))\n\treturn y\nend\nprint(f(1))");
    assert!(e.contains("must be the first statement"), "got: {e}");
}

#[test]
fn r07_unroll_on_a_function() {
    let e = reject(
        "unroll_fn",
        "local function f()\n\tBASIL_ATTRIBUTES(UNROLL())\n\treturn 1\nend\nprint(f())",
    );
    assert!(
        e.contains("UNROLL applies to a numeric-for loop"),
        "got: {e}"
    );
}

#[test]
fn r08_inline_on_a_loop() {
    let e = reject(
        "inline_loop",
        "for i = 1, 3 do\n\tBASIL_ATTRIBUTES(INLINE())\n\tprint(i)\nend",
    );
    assert!(
        e.contains("only UNROLL applies to a numeric-for loop"),
        "got: {e}"
    );
}

#[test]
fn r09_inline_on_unbound_anonymous() {
    let e = reject("inline_anon", "local t = { fn = function(x)\n\tBASIL_ATTRIBUTES(INLINE())\n\treturn x\nend }\nprint(t.fn(1))");
    assert!(
        e.contains("INLINE requires the function to be bound to a single local"),
        "got: {e}"
    );
}

#[test]
fn r10_checked_unroll_nonconstant_bounds() {
    let e = reject(
        "unroll_nonconst",
        "local n = tonumber(\"4\")\nfor i = 1, n do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tprint(i)\nend",
    );
    assert!(
        e.contains("compile-time-constant integer loop bounds"),
        "got: {e}"
    );
}

#[test]
fn r11_checked_unroll_explosion_guard() {
    let e = reject("unroll_big", "local acc = 0\nfor i = 1, 1000 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tacc = acc + i\nend\nprint(acc)");
    assert!(e.contains("too large to unroll"), "got: {e}");
}

#[test]
fn r12_checked_unroll_with_break() {
    let e = reject("unroll_break", "for i = 1, 4 do\n\tBASIL_ATTRIBUTES(UNROLL())\n\tif i == 2 then break end\n\tprint(i)\nend");
    assert!(e.contains("break or continue"), "got: {e}");
}

#[test]
fn r13_global_function_attribute_rejected() {
    let e = reject(
        "global_fn",
        "function g()\n\tBASIL_ATTRIBUTES(VM(NONE))\n\treturn 1\nend\nprint(g())",
    );
    assert!(
        e.contains("global or method function is not supported"),
        "got: {e}"
    );
}

#[test]
fn r14_recursive_attributed_function_rejected() {
    let e = reject("recursive", "local function fac(n)\n\tBASIL_ATTRIBUTES(VM(NONE))\n\tif n <= 1 then return 1 end\n\treturn n * fac(n - 1)\nend\nprint(fac(5))");
    assert!(e.contains("refers to itself"), "got: {e}");
}

#[test]
fn r15_absent_attribute_is_byte_identical() {
    let s = "local function f(x) return x * 2 end\nlocal acc = 0\nfor i = 1, 3 do acc = acc + f(i) end\nprint(acc)\n";
    let a = build(s, 305419896).expect("builds");
    let b = build(s, 305419896).expect("builds");
    assert_eq!(a, b);
}
