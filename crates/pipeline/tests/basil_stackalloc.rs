use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_sa_{p}_{}_{}.luau",
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

fn build(body: &str, seed: u64) -> Result<String, String> {
    let s = format!("{body}\n");
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

fn run(luau: &str, text: &str, tag: &str) -> String {
    let p = tmp(tag);
    std::fs::write(&p, text).unwrap();
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

fn accept(tag: &str, body: &str, expected: &str) -> String {
    let art = build(body, 305419896).unwrap_or_else(|e| panic!("[{tag}] must build, got: {e}"));
    assert!(
        !art.contains("BASIL_STACKALLOC"),
        "[{tag}] no BASIL_STACKALLOC marker may survive"
    );
    if let Some(luau) = find_luau() {
        let got = run(&luau, &art, &format!("{tag}_obf"));
        assert_eq!(got, expected, "[{tag}] obfuscated output mismatch");
    }
    art
}

fn reject(tag: &str, body: &str) -> String {
    match build(body, 42) {
        Ok(_) => panic!("[{tag}] must be REJECTED but the build succeeded"),
        Err(e) => e,
    }
}

#[test]
fn s01_static_read_write() {
    accept("rw", "local v = BASIL_STACKALLOC(4)\nv[1] = 10\nv[2] = 20\nv[4] = 40\nprint(v[1], v[2], v[3], v[4])", "10\t20\tnil\t40");
}

#[test]
fn s02_length_is_declared_size() {
    accept(
        "len",
        "local v = BASIL_STACKALLOC(8)\nv[1] = 1\nprint(#v)",
        "8",
    );
}

#[test]
fn s03_clear_range() {
    accept("clear", "local v = BASIL_STACKALLOC(4)\nv[1] = 1 v[2] = 2 v[3] = 3 v[4] = 4\nv:clear(2, 3)\nprint(v[1], v[2], v[3], v[4])", "1\tnil\tnil\t4");
}

#[test]
fn s04_pack_returns_table() {
    accept("pack", "local v = BASIL_STACKALLOC(3)\nv[1] = 7 v[2] = 8 v[3] = 9\nlocal t = v:pack()\nprint(t.n, t[1], t[2], t[3])", "3\t7\t8\t9");
}

#[test]
fn s05_unpack_into_call() {
    accept(
        "unpack_call",
        "local v = BASIL_STACKALLOC(3)\nv[1] = 1 v[2] = 2 v[3] = 3\nprint(v:unpack())",
        "1\t2\t3",
    );
}

#[test]
fn s06_unpack_multi_assign() {
    accept("unpack_assign", "local v = BASIL_STACKALLOC(3)\nv[1] = 5 v[2] = 6 v[3] = 7\nlocal a, b = v:unpack()\nprint(a, b)", "5\t6");
}

#[test]
fn s07_zero_base() {
    accept(
        "base0",
        "local v = BASIL_STACKALLOC(3, 0)\nv[0] = 100 v[2] = 300\nprint(v[0], v[1], v[2], #v)",
        "100\tnil\t300\t3",
    );
}

#[test]
fn s08_static_across_do_block() {
    accept("do", "local v = BASIL_STACKALLOC(3)\nv[1] = 1 v[2] = 2 v[3] = 3\nlocal s = 0\ndo s = v[1] + v[2] + v[3] end\nprint(s, #v)", "6\t3");
}

#[test]
fn s09_function_local_scratch() {
    accept(
        "scratch",
        "local function f(n)\n\tlocal v = BASIL_STACKALLOC(3)\n\tv[1] = n v[2] = n * 2 v[3] = n * 3\n\treturn v[1] + v[2] + v[3]\nend\nprint(f(2), f(3))",
        "12\t18",
    );
}

#[test]
fn s10_two_allocations() {
    accept("two", "local a = BASIL_STACKALLOC(2)\nlocal b = BASIL_STACKALLOC(2)\na[1] = 1 a[2] = 2 b[1] = 10 b[2] = 20\nprint(a[1] + b[1], a[2] + b[2])", "11\t22");
}

#[test]
fn s20_lowers_to_locals_not_a_table() {
    let m = frontend::lower_str(
        "local v = BASIL_STACKALLOC(4)\nv[1] = 1\nv[2] = 2\nprint(v[1] + v[2])\n",
    )
    .expect("lower");
    let m = frontend::macros::expand(m, 42).expect("expand");
    let mut has_macro = false;
    let mut multi_local = false;
    let mut new_table = false;
    walk(&m.block, &mut |st| {
        if let ir::Stmt::Local { names, exprs } = st {
            if names.len() >= 4 && exprs.is_empty() {
                multi_local = true;
            }
            for e in exprs {
                match e {
                    ir::Expr::Call { func, .. } if matches!(&**func, ir::Expr::Name(n) if n == "BASIL_STACKALLOC") => {
                        has_macro = true
                    }
                    ir::Expr::Table(_) => new_table = true,
                    _ => {}
                }
            }
        }
    });
    assert!(
        !has_macro,
        "the BASIL_STACKALLOC call must be gone after expansion"
    );
    assert!(
        multi_local,
        "the allocation must lower to a multi-name local declaration (frame slots)"
    );
    assert!(
        !new_table,
        "the allocation must not lower to a table constructor"
    );
}

fn walk(b: &ir::Block, f: &mut impl FnMut(&ir::Stmt)) {
    for s in &b.stmts {
        f(s);
        each_sub(s, f);
    }
}

fn each_sub(s: &ir::Stmt, f: &mut impl FnMut(&ir::Stmt)) {
    use ir::Stmt::*;
    match s {
        Do(b) | While { body: b, .. } | Repeat { body: b, .. } => walk(b, f),
        NumericFor { body, .. } | GenericFor { body, .. } => walk(body, f),
        If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            walk(body, f);
            for (_, bb) in else_ifs {
                walk(bb, f);
            }
            if let Some(bb) = otherwise {
                walk(bb, f);
            }
        }
        Function { body, .. } | LocalFunction { body, .. } => walk(&body.block, f),
        _ => {}
    }
}

#[test]
fn r01_dynamic_index_rejected() {
    let e = reject(
        "dyn",
        "local v = BASIL_STACKALLOC(4)\nlocal i = 2\nv[i] = 9\nprint(v[i])",
    );
    assert!(e.contains("compile-time integer indices"), "got: {e}");
}

#[test]
fn r02_dynamic_loop_index_rejected() {
    let e = reject(
        "dynloop",
        "local v = BASIL_STACKALLOC(4)\nfor i = 1, 4 do v[i] = i end\nprint(v[1])",
    );
    assert!(e.contains("compile-time integer indices"), "got: {e}");
}

#[test]
fn r03_out_of_bounds_index() {
    let e = reject(
        "oob",
        "local v = BASIL_STACKALLOC(4)\nv[5] = 1\nprint(v[5])",
    );
    assert!(e.contains("out of bounds"), "got: {e}");
}

#[test]
fn r04_bare_value_use_rejected() {
    let e = reject(
        "bare",
        "local v = BASIL_STACKALLOC(4)\nlocal w = v\nprint(w)",
    );
    assert!(e.contains("bare value"), "got: {e}");
}

#[test]
fn r05_return_rejected() {
    let e = reject("ret", "local function f()\n\tlocal v = BASIL_STACKALLOC(4)\n\tv[1] = 1\n\treturn v\nend\nprint(f())");
    assert!(e.contains("bare value") || e.contains("cannot"), "got: {e}");
}

#[test]
fn r06_capture_in_closure_rejected() {
    let e = reject(
        "capture",
        "local v = BASIL_STACKALLOC(4)\nv[1] = 1\nlocal f = function() return v[1] end\nprint(f())",
    );
    assert!(e.contains("captured by a nested function"), "got: {e}");
}

#[test]
fn r07_reassign_rejected() {
    let e = reject("reassign", "local v = BASIL_STACKALLOC(4)\nv = 5\nprint(v)");
    assert!(e.contains("reassigned"), "got: {e}");
}

#[test]
fn r08_shadow_rejected() {
    let e = reject(
        "shadow",
        "local v = BASIL_STACKALLOC(4)\ndo local v = 5 print(v) end\nv[1] = 1\nprint(v[1])",
    );
    assert!(e.contains("declared more than once"), "got: {e}");
}

#[test]
fn r09_non_constant_size() {
    let e = reject(
        "dynsize",
        "local n = tonumber(\"4\")\nlocal v = BASIL_STACKALLOC(n)\nprint(v[1])",
    );
    assert!(e.contains("compile-time integer literal"), "got: {e}");
}

#[test]
fn r10_oversized() {
    let e = reject(
        "big",
        "local v = BASIL_STACKALLOC(4096)\nv[1] = 1\nprint(v[1])",
    );
    assert!(e.contains("size must be in"), "got: {e}");
}

#[test]
fn r11_field_access_rejected() {
    let e = reject("field", "local v = BASIL_STACKALLOC(4)\nprint(v.foo)");
    assert!(e.contains("field-indexed"), "got: {e}");
}

#[test]
fn r12_unknown_method_rejected() {
    let e = reject("method", "local v = BASIL_STACKALLOC(4)\nprint(v:sort())");
    assert!(e.contains("method"), "got: {e}");
}

#[test]
fn r13_not_a_local_binding_rejected() {
    let e = reject("notlocal", "print(BASIL_STACKALLOC(4))");
    assert!(e.contains("may only appear as"), "got: {e}");
}
