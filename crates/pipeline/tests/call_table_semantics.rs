use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_cts_{p}_{}_{}.luau",
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

fn build(src: &str, seed: u64, minify: bool) -> String {
    let s = src.to_string();
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_full_prof(
                &s,
                seed,
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
        .unwrap()
}

fn run_luau(luau: &str, code: &str) -> String {
    let p = tmp("run");
    std::fs::write(&p, code).unwrap();
    let o = Command::new(luau).arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const TABLE_CALL_ERR: &str = "attempt to call a table value";

fn iteration_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("array_table", "local t = {10, 20, 30}\nlocal s = 0\nfor i, v in t do s += v end\nprint(s)"),
        ("mixed_table", "local t = {100, 200, x = 5, y = 6}\nlocal o = {}\nfor k, v in t do o[#o+1] = tostring(k)..\":\"..tostring(v) end\nprint(table.concat(o, \",\"))"),
        ("single_var", "local t = {7, 8, 9}\nlocal n = 0\nfor v in t do n += v end\nprint(n)"),
        ("table_literal", "local s = 0\nfor i, v in {1, 2, 3, 4} do s += i * v end\nprint(s)"),
        ("nested_loops", "local g = {{1, 2}, {3, 4}}\nlocal s = 0\nfor i, row in g do for j, v in row do s += v end end\nprint(s)"),
        (
            "crypto_buffer_fill",
            "local C = buffer.create(16)\nlocal bytes = { string.byte(\"expand 32-byte k\", 1, -1) }\nfor i, b in bytes do buffer.writeu8(C, i - 1, b) end\nlocal o = {}\nfor j = 0, 15 do o[#o+1] = buffer.readu8(C, j) end\nprint(table.concat(o, \",\"))",
        ),
        (
            "iter_metamethod",
            "local t = setmetatable({}, { __iter = function(self) local i = 0 return function() i += 1 if i <= 3 then return i, i * i end end end })\nlocal s = \"\"\nfor k, v in t do s = s .. k .. \":\" .. v .. \";\" end\nprint(s)",
        ),
        (
            "callable_table_for_in",
            "local t = setmetatable({}, { __call = function(_, _, c) c = (c or 0) + 1 if c <= 3 then return c, c * 10 end return nil end })\nlocal s = \"\"\nfor k, v in t do s = s .. k .. \":\" .. v .. \";\" end\nprint(s)",
        ),
        ("break_and_continue", "local t = {1, 2, 3, 4, 5}\nlocal s = 0\nfor i, v in t do if v == 2 then continue end if v == 5 then break end s += v end\nprint(s)"),
        (
            "multi_return_receiver",
            "local t = {a = 1, b = 2, c = 3}\nlocal keys, vals = 0, 0\nfor k, v in t do keys += 1 vals += v end\nprint(keys .. \",\" .. vals)",
        ),
    ]
}

fn explicit_iterator_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("pairs", "local t = {10, 20, 30}\nlocal s = 0\nfor k, v in pairs(t) do s += v end\nprint(s)"),
        ("ipairs", "local t = {10, 20, 30}\nlocal s = 0\nfor k, v in ipairs(t) do s += v end\nprint(s)"),
        (
            "explicit_function_iterator",
            "local function it(_, i) i += 1 if i <= 3 then return i, i * 10 end end\nlocal s = 0\nfor i, v in it, nil, 0 do s += v end\nprint(s)",
        ),
    ]
}

#[test]
fn generalized_iteration_matches_plain_luau_at_the_failing_seed() {
    let Some(luau) = find_luau() else { return };
    for (name, src) in iteration_cases() {
        let expect = run_luau(&luau, src);
        assert!(
            !expect.contains(TABLE_CALL_ERR) && !expect.is_empty(),
            "[{name}] raw fixture broken: {expect:?}"
        );
        let art = build(src, 1, true);
        let got = run_luau(&luau, &art);
        assert!(
            !got.contains(TABLE_CALL_ERR),
            "[{name}] virtualized still hits the table-call miscompile: {got:?}"
        );
        assert_eq!(
            expect, got,
            "[{name}] virtualized output differs from plain Luau"
        );
    }
}

#[test]
fn generalized_iteration_holds_across_seeds_and_minify() {
    let Some(luau) = find_luau() else { return };
    let cases = iteration_cases();
    for (name, src) in cases.iter().take(7) {
        let expect = run_luau(&luau, src);
        for seed in [1u64, 42, 1337] {
            for minify in [true, false] {
                let art = build(src, seed, minify);
                let got = run_luau(&luau, &art);
                assert!(
                    !got.contains(TABLE_CALL_ERR),
                    "[{name} seed={seed} minify={minify}] table-call miscompile"
                );
                assert_eq!(
                    expect, got,
                    "[{name} seed={seed} minify={minify}] behaviour differs from raw"
                );
            }
        }
    }
}

#[test]
fn explicit_iterators_remain_correct() {
    let Some(luau) = find_luau() else { return };
    for (name, src) in explicit_iterator_cases() {
        let expect = run_luau(&luau, src);
        let art = build(src, 1, true);
        let got = run_luau(&luau, &art);
        assert_eq!(expect, got, "[{name}] explicit-iterator behaviour changed");
    }
}

#[test]
fn callable_table_direct_call_still_works() {
    let Some(luau) = find_luau() else { return };
    let src =
        "local t = setmetatable({}, { __call = function(_, x) return x * 2 end })\nprint(t(21))";
    let expect = run_luau(&luau, src);
    let got = run_luau(&luau, &build(src, 1, true));
    assert_eq!(expect.trim(), "42", "raw __call broken");
    assert_eq!(expect, got, "virtualized __call direct call differs");
}

#[test]
fn non_callable_table_call_still_errors_like_plain_luau() {
    let Some(luau) = find_luau() else { return };
    let src = "local t = {}\nlocal ok, err = pcall(function() return t() end)\nprint(ok, (type(err) == \"string\" and string.find(err, \"call a table\", 1, true) ~= nil))";
    let expect = run_luau(&luau, src);
    let got = run_luau(&luau, &build(src, 1, true));
    assert_eq!(
        expect.trim(),
        "false\ttrue",
        "raw non-callable-table call must error"
    );
    assert_eq!(
        expect, got,
        "virtualized ordinary table call must still error like plain Luau"
    );
}

#[test]
fn non_iterable_for_in_still_errors() {
    let Some(luau) = find_luau() else { return };
    let src = "local ok = pcall(function() for k, v in 42 do end end)\nprint(ok)";
    let expect = run_luau(&luau, src);
    let got = run_luau(&luau, &build(src, 1, true));
    assert_eq!(expect.trim(), "false", "raw non-iterable for-in must error");
    assert_eq!(
        expect, got,
        "virtualized non-iterable for-in must still error"
    );
}

#[test]
fn same_seed_deterministic_different_seeds_vary() {
    let src = iteration_cases()[0].1;
    let a = build(src, 1, true);
    let b = build(src, 1, true);
    assert_eq!(a, b, "same seed must reproduce byte-for-byte");
    let c = build(src, 1337, true);
    assert_ne!(a, c, "different seeds must vary the artifact");
}

#[test]
fn protected_iteration_artifact_compiles_with_luau_compile_binary() {
    if Command::new("luau-compile").arg("--help").output().is_err() {
        return;
    }
    for (name, src) in iteration_cases().iter().take(4) {
        for minify in [true, false] {
            let art = build(src, 1, minify);
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
                "[{name} minify={minify}] artifact must compile with luau-compile --binary"
            );
        }
    }
}
