use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const WRONG: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_ecp_{p}_{}_{}.luau",
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

fn wrap(body: &str) -> String {
    format!(
        "if not BASIL_OBFUSCATED then\n\
         BASIL_ENCFUNC = function(fn, _, _) return fn end\n\
         end\n\
         local rk = BASILISK_RUNTIME_KEY\n{body}\n"
    )
}

fn build(src: &str, seed: u64) -> String {
    let s = src.to_string();
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_with(&s, seed, true, true, true, true, true, false, false)
                .expect("build succeeds")
        })
        .unwrap()
        .join()
        .unwrap()
}

fn run(luau: &str, art: &str, key: Option<&str>) -> String {
    let mut full = String::new();
    if let Some(k) = key {
        full.push_str(&format!("BASILISK_RUNTIME_KEY = \"{k}\"\n"));
    }
    full.push_str(art);
    let p = tmp("run");
    std::fs::write(&p, full).unwrap();
    let o = Command::new(luau).arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const ONE_CHILD: &str = "local f = BASIL_ENCFUNC(function(n)\n\
     local function double(x) return x * 2 end\n\
     return double(n) + 1\n\
     end, \"KEY\", rk)\n\
     print(f(20))";

#[test]
fn proof_one_child_proto_compiles_serializes_authenticates_and_executes() {
    let Some(luau) = find_luau() else { return };
    let src = wrap(&ONE_CHILD.replace("KEY", KEY));
    let art = build(&src, 305419896);
    let out = run(&luau, &art, Some(KEY));
    assert!(
        out.contains("41"),
        "sealed body with a child proto must execute; got {out:?}"
    );
}

#[test]
fn proof_child_proto_is_actually_produced_by_the_compiler() {
    let src = wrap(&ONE_CHILD.replace("KEY", KEY));
    let module = frontend::lower_str(&src).expect("lower");
    let module = frontend::macros::expand(module, 42).expect("macro expand");
    assert_eq!(module.encfuncs.len(), 1, "one ENCFUNC extracted");
    let inner = bytecode::compile::compile_func(&module.encfuncs[0].body).expect("compile");
    assert_eq!(
        inner.protos.len(),
        1,
        "the sealed parent must carry exactly one child Proto"
    );
    assert!(
        !inner.protos[0].code.is_empty(),
        "the child Proto must carry real instructions"
    );
}

#[test]
fn proof_wrong_key_fails_closed_with_a_child_proto() {
    let Some(luau) = find_luau() else { return };
    let src = wrap(&format!(
        "print(\"start\")\n{}\nprint(\"done\")",
        ONE_CHILD.replace("KEY", KEY)
    ));
    let art = build(&src, 42);
    let ok = run(&luau, &art, Some(KEY));
    assert!(
        ok.contains("41") && ok.contains("done"),
        "correct key must materialize; got {ok:?}"
    );
    let bad = run(&luau, &art, Some(WRONG));
    assert!(
        !bad.contains("41") && !bad.contains("done"),
        "wrong key must fail closed; got {bad:?}"
    );
    let none = run(&luau, &art, None);
    assert!(
        !none.contains("41") && !none.contains("done"),
        "missing key must fail closed; got {none:?}"
    );
}

#[test]
fn proof_same_seed_is_deterministic_and_different_seeds_vary() {
    let src = wrap(&ONE_CHILD.replace("KEY", KEY));
    let a = build(&src, 7);
    let b = build(&src, 7);
    assert_eq!(a, b, "same seed must reproduce byte-for-byte");
    let c = build(&src, 1337);
    assert_ne!(a, c, "different seeds must vary the artifact");
}

#[test]
fn proof_no_child_function_plaintext_leaks_outside_the_sealed_blob() {
    let src = wrap(
        &"local f = BASIL_ENCFUNC(function(n)\n\
          local function veryDistinctChildName(x) return x * 2 end\n\
          return veryDistinctChildName(n)\n\
          end, \"KEY\", rk)\nprint(f(3))"
            .replace("KEY", KEY),
    );
    let art = build(&src, 99);
    assert!(
        !art.contains("veryDistinctChildName"),
        "child identifier must not ship in cleartext"
    );
    assert!(!art.contains(KEY), "compile key must not ship");
}

fn raw_shim(body: &str) -> String {
    format!(
        "if not BASIL_OBFUSCATED then\n\
         BASIL_ENCFUNC = function(fn, _, _) return fn end\n\
         BASIL_HASH = function(s) return s end\n\
         BASIL_OPAQUE = function(v) return v end\n\
         BASIL_CRASH = function() end\n\
         end\n\
         local rk = BASILISK_RUNTIME_KEY\n{body}\n"
    )
}

fn sealed(inner: &str, call: &str) -> String {
    raw_shim(&format!(
        "local f = BASIL_ENCFUNC(function(n)\n{inner}\nend, \"{KEY}\", rk)\nprint({call})"
    ))
}

fn accepted_cases() -> Vec<(&'static str, String)> {
    vec![
        ("one_helper", sealed("local function d(x) return x * 2 end\nreturn d(n)", "f(20)")),
        (
            "several_helpers",
            sealed(
                "local function a(x) return x + 1 end\nlocal function b(x) return x * 2 end\n\
                 local function c(x) return a(b(x)) end\nreturn c(n)",
                "f(5)",
            ),
        ),
        ("iife", sealed("local v = (function(x) return x + 1 end)(n)\nreturn v", "f(41)")),
        (
            "table_sort_literal",
            sealed(
                "local t = { 5, 3, 9, 1 }\ntable.sort(t, function(a, b) return a < b end)\nreturn t[1] .. \",\" .. t[4] .. \",\" .. n",
                "f(7)",
            ),
        ),
        (
            "table_sort_alias",
            sealed(
                "local t = { 5, 3, 9, 1 }\nlocal function cmp(a, b) return a > b end\ntable.sort(t, cmp)\nreturn t[1] .. \",\" .. n",
                "f(7)",
            ),
        ),
        ("param_capture", sealed("local function add(x) return x + n end\nreturn add(5)", "f(10)")),
        (
            "body_local_capture",
            sealed("local base = 100\nlocal function add(x) return x + base end\nreturn add(n)", "f(23)"),
        ),
        (
            "mutable_capture",
            sealed("local acc = 0\nlocal function bump(x) acc = acc + x return acc end\nbump(n)\nbump(n)\nreturn acc", "f(21)"),
        ),
        (
            "shared_mutable_capture",
            sealed(
                "local acc = 0\nlocal function inc() acc = acc + 1 end\nlocal function get() return acc end\n\
                 inc()\ninc()\ninc()\nreturn get() + n",
                "f(10)",
            ),
        ),
        (
            "parent_writes_seen_by_child",
            sealed("local v = 1\nlocal function get() return v end\nv = n\nreturn get()", "f(77)"),
        ),
        (
            "direct_recursion",
            sealed("local function fac(x) if x <= 1 then return 1 end return x * fac(x - 1) end\nreturn fac(n)", "f(6)"),
        ),
        (
            "mutual_recursion",
            sealed(
                "local isEven, isOdd\nfunction isEven(x) if x == 0 then return true end return isOdd(x - 1) end\n\
                 function isOdd(x) if x == 0 then return false end return isEven(x - 1) end\n\
                 return tostring(isEven(n))",
                "f(10)",
            ),
        ),
        (
            "shadowed_recursive_name",
            sealed("local function g(x) return x + 1 end\ndo local g = 5 end\nreturn g(n)", "f(9)"),
        ),
        (
            "hash_in_child",
            sealed("local function c(x) if BASIL_HASH(x) == BASIL_HASH(\"admin\") then return \"granted\" end return \"denied\" end\nreturn c(n)", "f(\"admin\")"),
        ),
        (
            "opaque_in_child",
            sealed("local function c(x) if BASIL_OPAQUE(true) and x > 0 then return \"pos\" end return \"np\" end\nreturn c(n)", "f(5)"),
        ),
        (
            "function_table",
            sealed(
                "local ops = { inc = function(x) return x + 1 end, dec = function(x) return x - 1 end }\n\
                 return ops.inc(n) .. \",\" .. ops.dec(n)",
                "f(50)",
            ),
        ),
        (
            "method_on_local_table",
            sealed(
                "local obj = { base = 10 }\nfunction obj.plain(x) return x + 1 end\nfunction obj:m(x) return self.base + x end\n\
                 return obj.plain(n) .. \",\" .. obj:m(n)",
                "f(5)",
            ),
        ),
        (
            "child_multiple_returns",
            sealed("local function c(x) return x, x + 1, x + 2 end\nlocal a, b, d = c(n)\nreturn a + b + d", "f(10)"),
        ),
        (
            "child_in_loop",
            sealed("local s = 0\nfor i = 1, 4 do local function g(x) return x + i end s = s + g(n) end\nreturn s", "f(2)"),
        ),
        (
            "outer_varargs_with_child",
            raw_shim(&format!(
                "local f = BASIL_ENCFUNC(function(...)\n\
                 local function count(...) return select(\"#\", ...) end\nreturn count(...)\n\
                 end, \"{KEY}\", rk)\nprint(f(1, 2, 3, 4))"
            )),
        ),
        (
            "outer_multiple_returns_with_child",
            raw_shim(&format!(
                "local f = BASIL_ENCFUNC(function(a, b)\n\
                 local function s(x, y) return x + y end\nlocal function d(x, y) return x - y end\n\
                 return s(a, b), d(a, b)\n\
                 end, \"{KEY}\", rk)\nprint(f(9, 4))"
            )),
        ),
        (
            "pcall_success",
            sealed("local function work() return n * 2 end\nlocal ok, r = pcall(work)\nreturn tostring(ok) .. \",\" .. tostring(r)", "f(21)"),
        ),
        (
            "pcall_error_is_caught",
            sealed(
                "local function work() error(\"boom\" .. n) end\nlocal ok, err = pcall(work)\nreturn tostring(ok) .. \",\" .. tostring(err ~= nil)",
                "f(5)",
            ),
        ),
        (
            "pcall_multiple_returns",
            sealed("local function work() return 1, n, n + 1 end\nlocal ok, a, b, c = pcall(work)\nreturn tostring(ok) .. \",\" .. a .. \",\" .. b .. \",\" .. c", "f(10)"),
        ),
        (
            "pcall_callback_mutates_capture",
            sealed("local acc = 0\nlocal function bump() acc = acc + n end\nlocal ok1 = pcall(bump)\nlocal ok2 = pcall(bump)\nreturn tostring(ok1 and ok2) .. \",\" .. acc", "f(5)"),
        ),
        (
            "pcall_direct_anonymous_callback",
            sealed("local ok, r = pcall(function() return n + 1 end)\nreturn tostring(ok) .. \",\" .. tostring(r)", "f(41)"),
        ),
        (
            "pcall_nested_helper_callback",
            sealed("local function outer() local function inner() return n * 2 end return inner() end\nlocal ok, r = pcall(outer)\nreturn tostring(ok) .. \",\" .. tostring(r)", "f(6)"),
        ),
        (
            "pcall_direct_recursion_from_callback",
            sealed("local function fac(x) if x <= 1 then return 1 end return x * fac(x - 1) end\nlocal ok, r = pcall(function() return fac(n) end)\nreturn tostring(ok) .. \",\" .. tostring(r)", "f(5)"),
        ),
        (
            "pcall_mutual_recursion_from_callback",
            sealed(
                "local isEven, isOdd\nfunction isEven(x) if x == 0 then return true end return isOdd(x - 1) end\n\
                 function isOdd(x) if x == 0 then return false end return isEven(x - 1) end\n\
                 local ok, r = pcall(function() return isEven(n) end)\nreturn tostring(ok) .. \",\" .. tostring(r)",
                "f(10)",
            ),
        ),
        (
            "xpcall_success",
            sealed("local ok, r = xpcall(function() return n * 3 end, function(m) return \"H\" end)\nreturn tostring(ok) .. \",\" .. tostring(r)", "f(4)"),
        ),
        (
            "xpcall_failure_with_handler",
            sealed("local function work() error(\"x\") end\nlocal ok, r = xpcall(work, function(m) return \"handled\" end)\nreturn tostring(ok) .. \",\" .. tostring(r)", "f(1)"),
        ),
        (
            "xpcall_handler_mutates_shared_state",
            sealed(
                "local fails = 0\nlocal function work() error(\"x\" .. n) end\nlocal function handle(m) fails = fails + 1 return \"h\" end\n\
                 local ok = xpcall(work, handle)\nreturn tostring(ok) .. \",\" .. fails",
                "f(2)",
            ),
        ),
        (
            "xpcall_multiple_returns",
            sealed("local function work() return 7, n end\nlocal ok, a, b = xpcall(work, function() return -1 end)\nreturn tostring(ok) .. \",\" .. a .. \",\" .. b", "f(9)"),
        ),
        (
            "gsub_callback_zero_one_and_many_calls",
            sealed(
                "local count = 0\nlocal function rep(w) count = count + 1 return w end\n\
                 local s0 = string.gsub(\"...\", \"%a\", rep)\nlocal s1 = string.gsub(\"a..\", \"%a\", rep)\nlocal s2 = string.gsub(\"abc\", \"%a\", rep)\n\
                 return count .. \",\" .. tostring(s0) .. \",\" .. tostring(s1) .. \",\" .. tostring(s2)",
                "f(0)",
            ),
        ),
        (
            "gsub_callback_mutates_capture_and_returns_strings",
            sealed(
                "local total = 0\nlocal function rep(w) total = total + tonumber(w) return tostring(tonumber(w) * n) end\n\
                 local s = string.gsub(\"1 2 3\", \"%d\", rep)\nreturn s .. \"|\" .. total",
                "f(2)",
            ),
        ),
        (
            "gsub_callback_returns_number_replacement",
            sealed("local function rep(w) return tonumber(w) + n end\nlocal s = string.gsub(\"5\", \"%d\", rep)\nreturn tostring(s)", "f(10)"),
        ),
        (
            "gsub_callback_alias_in_sealed_body",
            sealed("local function rep(w) return \"[\" .. w .. \"]\" end\nlocal alias = rep\nlocal s = string.gsub(\"ab\", \"%a\", alias)\nreturn s", "f(0)"),
        ),
        (
            "owned_function_table_field_store",
            sealed("local handlers = {}\nhandlers.run = function(v) return v * 2 end\nreturn handlers.run(n)", "f(20)"),
        ),
        (
            "owned_function_table_method_declarations",
            sealed(
                "local handlers = {}\nfunction handlers.run(v) return v + 1 end\nfunction handlers:method(v) return v + 2 end\n\
                 return handlers.run(n) + handlers:method(n)",
                "f(10)",
            ),
        ),
        (
            "owned_function_table_alias_store",
            sealed("local handlers = {}\nlocal alias = handlers\nalias.run = function(v) return v * 3 end\nreturn handlers.run(n)", "f(4)"),
        ),
        (
            "owned_function_table_multiple_handlers",
            sealed(
                "local ops = {}\nops.inc = function(v) return v + 1 end\nops.dec = function(v) return v - 1 end\n\
                 return ops.inc(n) .. \",\" .. ops.dec(n)",
                "f(50)",
            ),
        ),
        (
            "owned_function_table_branch_join",
            sealed("local t\nif n > 0 then t = {} else t = {} end\nt.run = function(v) return v * 2 end\nreturn t.run(n)", "f(9)"),
        ),
    ]
}

fn callback_cases() -> Vec<(&'static str, String)> {
    accepted_cases()
        .into_iter()
        .filter(|(n, _)| {
            n.starts_with("pcall_") || n.starts_with("xpcall_") || n.starts_with("gsub_")
        })
        .collect()
}

fn owned_table_cases() -> Vec<(&'static str, String)> {
    accepted_cases()
        .into_iter()
        .filter(|(n, _)| n.starts_with("owned_function_table_"))
        .collect()
}

#[test]
fn accepted_nested_function_classes_match_unobfuscated_behaviour() {
    let Some(luau) = find_luau() else { return };
    for (name, src) in accepted_cases() {
        let expect = run(&luau, &src, Some(KEY));
        assert!(
            !expect.trim().is_empty(),
            "[{name}] raw produced nothing (fixture broken)"
        );
        let art = build(&src, 305419896);
        let got = run(&luau, &art, Some(KEY));
        assert_eq!(
            expect, got,
            "[{name}] virtualized behaviour differs from raw"
        );
    }
}

#[test]
fn accepted_classes_survive_minify_nominify_and_the_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let cases = accepted_cases();
    for (name, src) in cases.iter().take(8) {
        let expect = run(&luau, src, Some(KEY));
        for (label, minify, profile) in [
            ("minified", true, pipeline::TargetProfile::CliTest),
            ("no-minify", false, pipeline::TargetProfile::CliTest),
            ("executor", true, pipeline::TargetProfile::Executor),
        ] {
            let s = src.clone();
            let art = std::thread::Builder::new()
                .stack_size(256 << 20)
                .spawn(move || {
                    pipeline::virtualize_full_prof(
                        &s,
                        424242,
                        true,
                        true,
                        true,
                        true,
                        minify,
                        false,
                        false,
                        false,
                        false,
                        pipeline::SurfaceVolume::Off,
                        false,
                        pipeline::SensitiveOpts::default(),
                        profile,
                        false,
                        false,
                    )
                    .expect("build")
                })
                .unwrap()
                .join()
                .unwrap();
            let p = tmp("cc");
            std::fs::write(&p, &art).unwrap();
            let st = Command::new("luau-compile")
                .arg("--binary")
                .arg(&p)
                .output()
                .expect("luau-compile");
            let _ = std::fs::remove_file(&p);
            assert!(
                st.status.success(),
                "[{name}/{label}] artifact must compile"
            );
            if profile == pipeline::TargetProfile::CliTest {
                assert_eq!(
                    run(&luau, &art, Some(KEY)),
                    expect,
                    "[{name}/{label}] behaviour"
                );
            }
        }
    }
}

#[test]
fn callback_allowlist_classes_match_unobfuscated_behaviour() {
    let Some(luau) = find_luau() else { return };
    for (name, src) in callback_cases() {
        let expect = run(&luau, &src, Some(KEY));
        assert!(
            !expect.trim().is_empty(),
            "[{name}] raw produced nothing (fixture broken)"
        );
        let art = build(&src, 305419896);
        let got = run(&luau, &art, Some(KEY));
        assert_eq!(
            expect, got,
            "[{name}] virtualized callback behaviour differs from raw"
        );
    }
}

#[test]
fn callback_classes_survive_minify() {
    let Some(luau) = find_luau() else { return };
    for (name, src) in callback_cases() {
        let expect = run(&luau, &src, Some(KEY));
        for (label, minify, profile) in [
            ("minified", true, pipeline::TargetProfile::CliTest),
            ("no-minify", false, pipeline::TargetProfile::CliTest),
            ("executor", true, pipeline::TargetProfile::Executor),
        ] {
            let s = src.clone();
            let art = std::thread::Builder::new()
                .stack_size(256 << 20)
                .spawn(move || {
                    pipeline::virtualize_full_prof(
                        &s,
                        424242,
                        true,
                        true,
                        true,
                        true,
                        minify,
                        false,
                        false,
                        false,
                        false,
                        pipeline::SurfaceVolume::Off,
                        false,
                        pipeline::SensitiveOpts::default(),
                        profile,
                        false,
                        false,
                    )
                    .expect("build")
                })
                .unwrap()
                .join()
                .unwrap();
            let p = tmp("cc");
            std::fs::write(&p, &art).unwrap();
            let st = Command::new("luau-compile")
                .arg("--binary")
                .arg(&p)
                .output()
                .expect("luau-compile");
            let _ = std::fs::remove_file(&p);
            assert!(
                st.status.success(),
                "[{name}/{label}] artifact must compile"
            );
            if profile == pipeline::TargetProfile::CliTest {
                assert_eq!(
                    run(&luau, &art, Some(KEY)),
                    expect,
                    "[{name}/{label}] behaviour"
                );
            }
        }
    }
}

#[test]
fn callback_allowlist_classes_fail_closed_on_wrong_key() {
    let Some(luau) = find_luau() else { return };
    for (name, src) in callback_cases() {
        let good = run(&luau, &src, Some(KEY));
        let art = build(&src, 777);
        let ok = run(&luau, &art, Some(KEY));
        assert_eq!(
            ok, good,
            "[{name}] correct key must reproduce raw behaviour"
        );
        let bad = run(&luau, &art, Some(WRONG));
        assert_ne!(
            bad, good,
            "[{name}] wrong key must not reproduce the sealed result"
        );
        let none = run(&luau, &art, None);
        assert_ne!(
            none, good,
            "[{name}] missing key must not reproduce the sealed result"
        );
    }
}

#[test]
fn owned_table_classes_survive_minify() {
    let Some(luau) = find_luau() else { return };
    for (name, src) in owned_table_cases() {
        let expect = run(&luau, &src, Some(KEY));
        assert!(
            !expect.trim().is_empty(),
            "[{name}] raw produced nothing (fixture broken)"
        );
        for (label, minify) in [("minified", true), ("no-minify", false)] {
            let s = src.clone();
            let art = std::thread::Builder::new()
                .stack_size(256 << 20)
                .spawn(move || {
                    pipeline::virtualize_full_prof(
                        &s,
                        20240806,
                        true,
                        true,
                        true,
                        true,
                        minify,
                        false,
                        false,
                        false,
                        false,
                        pipeline::SurfaceVolume::Off,
                        false,
                        pipeline::SensitiveOpts::default(),
                        pipeline::TargetProfile::CliTest,
                        false,
                        false,
                    )
                    .expect("build")
                })
                .unwrap()
                .join()
                .unwrap();
            let p = tmp("cc");
            std::fs::write(&p, &art).unwrap();
            let st = Command::new("luau-compile")
                .arg("--binary")
                .arg(&p)
                .output()
                .expect("luau-compile");
            let _ = std::fs::remove_file(&p);
            assert!(
                st.status.success(),
                "[{name}/{label}] artifact must compile"
            );
            assert_eq!(
                run(&luau, &art, Some(KEY)),
                expect,
                "[{name}/{label}] behaviour"
            );
        }
        let art = build(&src, 20240806);
        let bad = run(&luau, &art, Some(WRONG));
        assert_ne!(
            bad, expect,
            "[{name}] wrong key must not reproduce the sealed result"
        );
        let none = run(&luau, &art, None);
        assert_ne!(
            none, expect,
            "[{name}] missing key must not reproduce the sealed result"
        );
    }
}

#[test]
fn nested_bodies_are_deterministic_across_the_required_seeds() {
    let (_, src) = accepted_cases()
        .into_iter()
        .find(|(n, _)| *n == "several_helpers")
        .unwrap();
    let mut arts = Vec::new();
    for seed in [1u64, 42, 1337] {
        let a = build(&src, seed);
        let b = build(&src, seed);
        assert_eq!(a, b, "seed {seed} must reproduce byte-for-byte");
        arts.push(a);
    }
    assert_ne!(arts[0], arts[1], "seeds 1 and 42 must differ");
    assert_ne!(arts[1], arts[2], "seeds 42 and 1337 must differ");
    assert_ne!(arts[0], arts[2], "seeds 1 and 1337 must differ");
}

fn build_nomin(src: &str, seed: u64) -> String {
    let s = src.to_string();
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_full(
                &s,
                seed,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Off,
            )
            .expect("build succeeds")
        })
        .unwrap()
        .join()
        .unwrap()
}

fn blob_mutated(art: &str, offset: usize) -> String {
    let at = art.find("BLOBS").expect("BLOBS present");
    let open = art[at..].find("[==[").expect("blob bracket") + at + 4;
    let mut bytes = art.to_string().into_bytes();
    let i = open + offset;
    bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap()
}

#[test]
fn mutating_any_part_of_a_sealed_blob_with_children_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let src = raw_shim(&format!(
        "print(\"start\")\n\
         local f = BASIL_ENCFUNC(function(n)\n\
         local function d(x) return x * 2 end\n\
         local tag = \"SECRETCHILD\"\n\
         return tag .. tostring(d(n))\n\
         end, \"{KEY}\", rk)\nprint(f(21))\nprint(\"done\")"
    ));
    let art = build_nomin(&src, 42);
    let ok = run(&luau, &art, Some(KEY));
    assert!(
        ok.contains("SECRETCHILD42"),
        "correct key must materialize; got {ok:?}"
    );

    let blob_len = {
        let at = art.find("BLOBS").expect("BLOBS");
        let open = art[at..].find("[==[").expect("open") + at + 4;
        art[open..].find("]==]").expect("close")
    };

    for (label, off) in [
        ("head", 0usize),
        ("mid", blob_len / 2),
        ("late", blob_len - 8),
    ] {
        let t = blob_mutated(&art, off);
        let out = run(&luau, &t, Some(KEY));
        assert!(
            !out.contains("SECRETCHILD") && !out.contains("done"),
            "[{label}] mutated sealed blob must fail closed; got {out:?}"
        );
    }
}

#[test]
fn a_sealed_blob_from_another_build_cannot_be_replayed_into_this_one() {
    let Some(luau) = find_luau() else { return };
    let mk = |tag: &str| {
        raw_shim(&format!(
            "print(\"start\")\n\
             local f = BASIL_ENCFUNC(function(n)\n\
             local function d(x) return x * 2 end\n\
             return \"{tag}\" .. tostring(d(n))\n\
             end, \"{KEY}\", rk)\nprint(f(21))\nprint(\"done\")"
        ))
    };
    let a = build_nomin(&mk("AAA"), 42);
    let b = build_nomin(&mk("BBB"), 4242);
    let grab = |s: &str| {
        let at = s.find("BLOBS").expect("BLOBS");
        let open = s[at..].find("[==[").expect("open") + at + 4;
        let close = s[open..].find("]==]").expect("close") + open;
        (open, close, s[open..close].to_string())
    };
    let (ao, ac, _) = grab(&a);
    let (_, _, bblob) = grab(&b);
    let swapped = format!("{}{}{}", &a[..ao], bblob, &a[ac..]);
    let out = run(&luau, &swapped, Some(KEY));
    assert!(
        !out.contains("AAA") && !out.contains("BBB") && !out.contains("done"),
        "a blob lifted from another build must fail closed; got {out:?}"
    );
}

#[test]
fn wrong_key_fails_before_any_child_behaviour_is_observable() {
    let Some(luau) = find_luau() else { return };
    let src = raw_shim(&format!(
        "print(\"start\")\n\
         local f = BASIL_ENCFUNC(function(n)\n\
         local function d(x) print(\"CHILDRAN\") return x * 2 end\n\
         return d(n)\n\
         end, \"{KEY}\", rk)\nprint(f(21))\nprint(\"done\")"
    ));
    let art = build(&src, 42);
    let bad = run(&luau, &art, Some(WRONG));
    assert!(
        !bad.contains("CHILDRAN"),
        "no child side effect may run on a wrong key; got {bad:?}"
    );
    assert!(
        !bad.contains("done"),
        "wrong key must fail closed; got {bad:?}"
    );
}

#[test]
fn builds_without_encfunc_are_unchanged_by_this_feature() {
    let src = "local function add(a, b) return a + b end\n\
               local t = { 3, 1, 2 }\n\
               table.sort(t, function(x, y) return x < y end)\n\
               print(add(t[1], t[3]))\n";
    let art = build(src, 305419896);
    assert!(
        !art.contains("makeEncWrapper"),
        "no ENCFUNC machinery in a build without ENCFUNC"
    );
    let again = build(src, 305419896);
    assert_eq!(art, again, "no-ENCFUNC builds stay deterministic");
}

fn child_shape(inner: &str) -> (usize, usize) {
    let src = raw_shim(&format!(
        "local f = BASIL_ENCFUNC(function(n)\n{inner}\nend, \"{KEY}\", rk)\nprint(f(7))"
    ));
    let m =
        frontend::macros::expand(frontend::lower_str(&src).expect("lower"), 42).expect("expand");
    let p = bytecode::compile::compile_func(&m.encfuncs[0].body).expect("compile");
    fn walk(p: &bytecode::Proto) -> (usize, usize) {
        let mut c = p.protos.len();
        let mut i = p.code.len();
        for k in &p.protos {
            let (cc, ii) = walk(k);
            c += cc;
            i += ii;
        }
        (c, i)
    }
    walk(&p)
}

#[test]
fn sealed_bodies_carry_the_expected_child_proto_shape() {
    let cases: [(&str, &str, usize); 6] = [
        ("parent_only", "return n * 2 + 1", 0),
        ("one_child", "local function d(x) return x * 2 end\nreturn d(n) + 1", 1),
        (
            "several_children",
            "local function a(x) return x + 1 end\nlocal function b(x) return x * 2 end\nlocal function c(x) return a(b(x)) end\nreturn c(n)",
            3,
        ),
        ("recursive", "local function fac(x) if x <= 1 then return 1 end return x * fac(x - 1) end\nreturn fac(n)", 1),
        (
            "mutual",
            "local e, o\nfunction e(x) if x == 0 then return 1 end return o(x - 1) end\nfunction o(x) if x == 0 then return 0 end return e(x - 1) end\nreturn e(n)",
            2,
        ),
        (
            "nested_child",
            "local function outer(x) local function inner(y) return y + 1 end return inner(x) * 2 end\nreturn outer(n)",
            2,
        ),
    ];
    for (name, inner, want) in cases {
        let (children, instrs) = child_shape(inner);
        println!("{name}: children={children} instructions={instrs}");
        assert_eq!(children, want, "[{name}] child proto count");
    }
}
