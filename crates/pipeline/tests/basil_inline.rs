use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_inl_{p}_{}_{}.luau",
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
     BASIL_INLINE = function(f) return f end\n\
     BASIL_CRASH = function() end\n\
     BASIL_HASH = function(s) return s end\n\
     BASIL_OPAQUE = function(v) return v end\n\
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

fn accept(tag: &str, body: &str) -> String {
    let s = src(body);
    let art = build(&s, 305419896).unwrap_or_else(|e| panic!("[{tag}] must build, got: {e}"));
    assert!(
        !art.contains("BASIL_INLINE"),
        "[{tag}] no BASIL_INLINE marker may survive into the artifact"
    );
    if let Some(luau) = find_luau() {
        let plain = run(&luau, &s, &format!("{tag}_plain"));
        let got = run(&luau, &art, &format!("{tag}_obf"));
        assert!(!plain.is_empty(), "[{tag}] fixture must print something");
        assert_eq!(got, plain, "[{tag}] inlined build must match plain Luau");
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
fn i01_tiny_value_helper_one_site() {
    accept(
        "tiny",
        "local add = BASIL_INLINE(function(a, b) return a + b end)\nlocal r = add(2, 3)\nprint(r)",
    );
}

#[test]
fn i02_void_helper_statement_position() {
    accept(
        "void",
        "local out = {}\nlocal emit = BASIL_INLINE(function(t, s) t[#t + 1] = s end)\n\
         emit(out, \"a\")\nemit(out, \"b\")\nprint(#out, table.concat(out, \",\"))",
    );
}

#[test]
fn i03_call_site_counts_one_two_four_eight_sixteen() {
    for n in [1usize, 2, 4, 8, 16] {
        let calls: Vec<String> = (1..=n)
            .map(|i| format!("local q{i} = sq({i}) s = s + q{i}"))
            .collect();
        accept(
            &format!("sites{n}"),
            &format!(
                "local sq = BASIL_INLINE(function(x) return x * x end)\nlocal s = 0\n{}\nprint(s)",
                calls.join("\n")
            ),
        );
    }
}

#[test]
fn i04_argument_side_effect_evaluated_exactly_once() {
    accept(
        "once",
        "local log = {}\nlocal function side(v) log[#log + 1] = v return v end\n\
         local add = BASIL_INLINE(function(a, b) return a + b end)\n\
         local r = add(side(1), side(2))\nlocal n = #log\nprint(r, n, table.concat(log, \",\"))",
    );
}

#[test]
fn i05_left_to_right_argument_order() {
    accept(
        "order",
        "local log = {}\nlocal function side(v) log[#log + 1] = v return v end\n\
         local pick = BASIL_INLINE(function(a, b, c) return tostring(a) .. tostring(b) .. tostring(c) end)\n\
         local r = pick(side(\"a\"), side(\"b\"), side(\"c\"))\n\
         print(r, table.concat(log, \",\"))",
    );
}

#[test]
fn i06_missing_argument_is_nil_and_extra_arguments_are_evaluated_then_ignored() {
    accept(
        "arity",
        "local f = BASIL_INLINE(function(a, b) return tostring(a) .. \"/\" .. tostring(b) end)\n\
         local x = f(1)\nlocal y = f(1, 2)\nprint(x, y)",
    );
    accept(
        "extra",
        "local log = {}\nlocal function side(v) log[#log + 1] = v return v end\n\
         local g = BASIL_INLINE(function(a) return a end)\n\
         local v = g(side(1), side(2))\nprint(v, table.concat(log, \",\"))",
    );
}

#[test]
fn i07_local_shadowing_is_hygienic() {
    accept(
        "shadow",
        "local x = \"outer\"\nlocal f = BASIL_INLINE(function(v) local x = v * 2 return x end)\n\
         local r = f(4)\nprint(r, x)",
    );
}

#[test]
fn i08_nested_blocks_and_branches_inside_the_helper() {
    accept(
        "branch",
        "local classify = BASIL_INLINE(function(n) local r if n > 0 then r = \"pos\" \
         elseif n < 0 then r = \"neg\" else r = \"zero\" end return r end)\n\
         local a = classify(5)\nlocal b = classify(-5)\nlocal c = classify(0)\nprint(a, b, c)",
    );
}

#[test]
fn i09_loop_inside_the_helper_and_calls_inside_a_caller_loop() {
    accept(
        "loops",
        "local tri = BASIL_INLINE(function(n) local s = 0 for i = 1, n do s = s + i end return s end)\n\
         local total = 0\nfor k = 1, 4 do local t = tri(k) total = total + t end\nlocal big = tri(10)\nprint(total, big)",
    );
}

#[test]
fn i10_globals_resolve_normally_inside_the_helper() {
    accept(
        "globals",
        "GLOBAL_BASE = 100\nlocal f = BASIL_INLINE(function(a) return GLOBAL_BASE + a end)\nlocal r = f(5)\nprint(r)",
    );
}

#[test]
fn i11_assignment_and_return_call_sites() {
    accept(
        "assign",
        "local f = BASIL_INLINE(function(a) return a * 3 end)\nlocal r = 0\nr = f(4)\nprint(r)",
    );
    accept(
        "retpos",
        "local function outer()\n  local f = BASIL_INLINE(function(a) return a + 1 end)\n  return f(41)\nend\nprint(outer())",
    );
}

#[test]
fn i12_crash_hash_opaque_inside_the_helper() {
    accept(
        "opaque",
        "local f = BASIL_INLINE(function(a) local r = 0 if BASIL_OPAQUE(true) and a > 0 then r = a end return r end)\nlocal x = f(3)\nlocal y = f(-3)\nprint(x, y)",
    );
    accept(
        "hash",
        "local f = BASIL_INLINE(function(a) return BASIL_HASH(a) end)\nlocal h = f(\"admin\")\nprint(h ~= nil)",
    );
    accept(
        "crash",
        "local f = BASIL_INLINE(function(a) if a < 0 then BASIL_CRASH() end return a * 2 end)\nlocal r = f(21)\nprint(r)",
    );
}

#[test]
fn i13_seeds_minified_nominified_and_executor_profile() {
    let body = "local add = BASIL_INLINE(function(a, b) return a + b end)\nlocal s = 0\nfor i = 1, 5 do s = add(s, i) end\nprint(s)";
    let s = src(body);
    let Some(luau) = find_luau() else { return };
    let plain = run(&luau, &s, "matrix_plain");
    for seed in [1u64, 42, 1337] {
        let a = build(&s, seed).expect("build");
        let b = build(&s, seed).expect("build");
        assert_eq!(a, b, "seed {seed} must be deterministic");
        assert_eq!(run(&luau, &a, "matrix"), plain, "seed {seed} behaviour");
    }
    for (label, minify, profile) in [
        ("minified", true, pipeline::TargetProfile::CliTest),
        ("nomin", false, pipeline::TargetProfile::CliTest),
        ("executor", true, pipeline::TargetProfile::Executor),
    ] {
        let t = s.clone();
        let art = std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(move || {
                pipeline::virtualize_full_prof(
                    &t,
                    7,
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
        assert!(st.status.success(), "[{label}] must compile");
        if profile == pipeline::TargetProfile::CliTest {
            assert_eq!(run(&luau, &art, label), plain, "[{label}] behaviour");
        }
    }
}

#[test]
fn i14_the_helper_proto_is_removed() {
    let with = "local sq = BASIL_INLINE(function(x) return x * x end)\nlocal r = sq(6)\nprint(r)";
    let without = "local function sq(x) return x * x end\nlocal r = sq(6)\nprint(r)";
    let mut a = pipeline::BuildStats::default();
    let mut b = pipeline::BuildStats::default();
    let ia = tmp("pa");
    let oa = tmp("pao");
    std::fs::write(&ia, src(with)).unwrap();
    let mut g: Option<pipeline::BuildStats> = None;
    pipeline::run_capturing_stats(&ia, &oa, &cfg_for(), None, &mut g).unwrap();
    a = g.unwrap();
    let ib = tmp("pb");
    let ob = tmp("pbo");
    std::fs::write(&ib, src(without)).unwrap();
    let mut h: Option<pipeline::BuildStats> = None;
    pipeline::run_capturing_stats(&ib, &ob, &cfg_for(), None, &mut h).unwrap();
    b = h.unwrap();
    for f in [ia, oa, ib, ob] {
        let _ = std::fs::remove_file(f);
    }
    assert_eq!(
        a.protos + 1,
        b.protos,
        "inlining removes exactly the helper proto ({} vs {})",
        a.protos,
        b.protos
    );
}

fn cfg_for() -> pipeline::Config {
    pipeline::Config {
        seed: 42,
        mode: pipeline::Mode::Virtualize,
        flatten: false,
        opaque: false,
        junk: false,
        fuse: false,
        minify: true,
        compress: false,
        anti_envlog: false,
        hard_dispatch: false,
        surface: false,
        heavy: pipeline::SurfaceVolume::Off,
        aggressive: false,
        sensitive: pipeline::SensitiveOpts::default(),
        profile: pipeline::TargetProfile::CliTest,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: false,
        strip_source_names: false,
        poly_stream: pipeline::PolyStream::Off,
        optimization: 1,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: pipeline::FrameConstReuseMode::Off,
        hot_callback_policy: pipeline::HotCallbackPolicy::Report,
        ablate_fragment: false,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
        shell_family: None,
        notices: pipeline::NoticeConfig::default(),
        stateful_recovery: false,
        stateful_framing: false,
        property_key_rename: pipeline::PropKeyMode::Off,
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

#[test]
fn i15_builds_without_the_macro_are_unaffected() {
    let plain = "local function add(a, b) return a + b end\nprint(add(1, 2))\n";
    let a = build(plain, 42).unwrap();
    let b = build(plain, 42).unwrap();
    assert_eq!(a, b, "no-macro builds stay deterministic");
    assert!(!a.contains("BASIL_INLINE"));
}

#[test]
fn r01_arity_and_argument_shape() {
    assert!(reject("noargs", "local f = BASIL_INLINE()\nprint(f)").contains("exactly one"));
    assert!(reject(
        "twoargs",
        "local f = BASIL_INLINE(function() end, 1)\nprint(f)"
    )
    .contains("exactly one"));
    assert!(reject("nonfn", "local f = BASIL_INLINE(42)\nprint(f)").contains("function-literal"));
    let e = reject(
        "ref",
        "local g = function() end\nlocal f = BASIL_INLINE(g)\nprint(f)",
    );
    assert!(e.contains("function literal"), "got: {e}");
}

#[test]
fn r02_binding_shape() {
    let multi = reject(
        "multi",
        "local f, x = BASIL_INLINE(function() end), 1\nprint(f, x)",
    );
    assert!(
        multi.contains("exactly one local") || multi.contains("BASIL_INLINE"),
        "got: {multi}"
    );
    for (tag, body) in [
        ("assign", "f = BASIL_INLINE(function() end)\nprint(f)"),
        (
            "return",
            "local function o() return BASIL_INLINE(function() end) end\nprint(o())",
        ),
        (
            "table",
            "local t = {}\ntable.insert(t, BASIL_INLINE(function() end))\nprint(#t)",
        ),
        (
            "field",
            "local t = {}\nt.f = BASIL_INLINE(function() end)\nprint(t.f)",
        ),
    ] {
        let e = reject(tag, body);
        assert!(
            e.contains("BASIL_INLINE"),
            "[{tag}] must name the macro, got: {e}"
        );
    }
}

#[test]
fn r03_escape_and_identity_uses() {
    for (tag, body) in [
        ("returned", "local function o() local f = BASIL_INLINE(function() return 1 end) return f end\nprint(o())"),
        ("stored", "local t = {}\nlocal f = BASIL_INLINE(function() return 1 end)\nt[1] = f\nprint(t[1]())"),
        ("callback", "local f = BASIL_INLINE(function(a, b) return a < b end)\nlocal t = {2,1}\ntable.sort(t, f)\nprint(t[1])"),
        ("alias", "local f = BASIL_INLINE(function() return 1 end)\nlocal g = f\nprint(g())"),
        ("tostring", "local f = BASIL_INLINE(function() return 1 end)\nprint(tostring(f))"),
        ("compare", "local f = BASIL_INLINE(function() return 1 end)\nprint(f == nil)"),
        ("pcall", "local f = BASIL_INLINE(function() return 1 end)\nprint(pcall(f))"),
    ] {
        let e = reject(tag, body);
        assert!(e.contains("used as a value"), "[{tag}] escape diagnostic, got: {e}");
    }
}

#[test]
fn r04_unsupported_call_site_context() {
    let e = reject(
        "expr",
        "local f = BASIL_INLINE(function(a) return a + 1 end)\nlocal s = 0\ns = s + f(1)\nprint(s)",
    );
    assert!(e.contains("expression context"), "got: {e}");
    let e2 = reject(
        "nested-call",
        "local f = BASIL_INLINE(function(a) return a end)\nprint(f(1))",
    );
    assert!(
        e2.contains("expression context") || e2.contains("used as a value"),
        "a call nested inside another expression is rejected, got: {e2}"
    );
}

#[test]
fn r05_recursion_and_varargs_and_arity_shapes() {
    let rec = reject("rec", "local f\nf = BASIL_INLINE(function(n) if n <= 0 then return 0 end return f(n - 1) end)\nprint(f(3))");
    assert!(rec.contains("BASIL_INLINE"), "got: {rec}");
    let va = reject("vararg", "local f = BASIL_INLINE(function(...) return select(\"#\", ...) end)\nlocal r = f(1, 2)\nprint(r)");
    assert!(va.contains("varargs"), "got: {va}");
}

#[test]
fn r06_return_shape() {
    let multi = reject(
        "multi-ret",
        "local f = BASIL_INLINE(function(a) return a, a + 1 end)\nlocal r = f(1)\nprint(r)",
    );
    assert!(multi.contains("several values"), "got: {multi}");
    let mixed = reject("mixed", "local f = BASIL_INLINE(function(a) if a then return end return 1 end)\nlocal r = f(true)\nprint(r)");
    assert!(
        mixed.contains("mixed return arity") || mixed.contains("early return"),
        "got: {mixed}"
    );
    let early = reject("early", "local f = BASIL_INLINE(function(a) if a == nil then return 0 end return a + 1 end)\nlocal r = f(2)\nprint(r)");
    assert!(early.contains("early return"), "got: {early}");
    let void_val = reject(
        "void-in-value",
        "local f = BASIL_INLINE(function(a) local x = a end)\nlocal r = f(1)\nprint(r)",
    );
    assert!(void_val.contains("no value"), "got: {void_val}");
}

#[test]
fn r07_capture_is_rejected() {
    let e = reject(
        "capture",
        "local base = 10\nlocal f = BASIL_INLINE(function(a) return a + base end)\nlocal r = f(1)\nprint(r)",
    );
    assert!(e.contains("captures the enclosing local"), "got: {e}");
}

#[test]
fn r08_growth_budget_is_enforced_and_explicit() {
    let long: Vec<String> = (1..=30).map(|i| format!("  local v{i} = {i}")).collect();
    let e = reject(
        "budget-body",
        &format!(
            "local f = BASIL_INLINE(function(a)\n{}\n  return a end)\nlocal r = f(1)\nprint(r)",
            long.join("\n")
        ),
    );
    assert!(
        e.contains("inline budget"),
        "body budget diagnostic, got: {e}"
    );

    let calls: Vec<String> = (1..=20)
        .map(|i| format!("s = s + 0 local q{i} = f({i})"))
        .collect();
    let e2 = reject(
        "budget-sites",
        &format!(
            "local f = BASIL_INLINE(function(a) return a * 2 end)\nlocal s = 0\n{}\nprint(s)",
            calls.join("\n")
        ),
    );
    assert!(
        e2.contains("inline budget"),
        "call-site budget diagnostic, got: {e2}"
    );
}

#[test]
fn r09_never_called_is_rejected_rather_than_silently_kept() {
    let e = reject(
        "unused",
        "local f = BASIL_INLINE(function() return 1 end)\nprint(\"hi\")",
    );
    assert!(e.contains("never called"), "got: {e}");
}

#[test]
fn r10_encfunc_and_native_boundaries() {
    let k = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let enc = reject(
        "encfunc",
        &format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal e = BASIL_ENCFUNC(function(u)\n\
             local f = BASIL_INLINE(function(a) return a end)\n  return f(u)\nend, \"{k}\", rk)\nprint(e(1))"
        ),
    );
    assert!(
        enc.contains("BASIL_INLINE") || enc.contains("BASIL_"),
        "got: {enc}"
    );
    let nat = reject(
        "native",
        "local n = BASIL_NO_VIRTUALIZE(function(a) local f = BASIL_INLINE(function(x) return x end) return f(a) end)\nprint(n(1))",
    );
    assert!(nat.contains("BASIL_"), "got: {nat}");
}

#[test]
fn r11_nested_inline_is_rejected() {
    let e = reject(
        "nested",
        "local f = BASIL_INLINE(function(a)\n  local g = BASIL_INLINE(function(b) return b + 1 end)\n  return g(a)\nend)\nlocal r = f(1)\nprint(r)",
    );
    assert!(e.contains("BASIL_INLINE"), "got: {e}");
}

#[test]
fn i16_differential_plain_hand_and_macro_agree() {
    let Some(luau) = find_luau() else { return };
    let cases: [(&str, &str, &str); 4] = [
        (
            "value",
            "local function f(a, b) return a * 10 + b end\nlocal r = f(2, 3)\nprint(r)",
            "local __a, __b = 2, 3\nlocal r = __a * 10 + __b\nprint(r)",
        ),
        (
            "loop-site",
            "local function sq(x) return x * x end\nlocal s = 0\nfor i = 1, 6 do local q = sq(i) s = s + q end\nprint(s)",
            "local s = 0\nfor i = 1, 6 do local __x = i local q = __x * __x s = s + q end\nprint(s)",
        ),
        (
            "shadow",
            "local function f(v) local x = v + 1 return x end\nlocal x = 99\nlocal r = f(4)\nprint(r, x)",
            "local x = 99\nlocal __v = 4\nlocal __x = __v + 1\nlocal r = __x\nprint(r, x)",
        ),
        (
            "void",
            "local out = {}\nlocal function push(t, v) t[#t + 1] = v * 2 end\npush(out, 3)\npush(out, 4)\nprint(table.concat(out, \",\"))",
            "local out = {}\nlocal __t, __v = out, 3\n__t[#__t + 1] = __v * 2\nlocal __t2, __v2 = out, 4\n__t2[#__t2 + 1] = __v2 * 2\nprint(table.concat(out, \",\"))",
        ),
    ];
    for (tag, plain, hand) in cases {
        let macro_src = match tag {
            "value" => "local f = BASIL_INLINE(function(a, b) return a * 10 + b end)\nlocal r = f(2, 3)\nprint(r)",
            "loop-site" => "local sq = BASIL_INLINE(function(x) return x * x end)\nlocal s = 0\nfor i = 1, 6 do local q = sq(i) s = s + q end\nprint(s)",
            "shadow" => "local f = BASIL_INLINE(function(v) local x = v + 1 return x end)\nlocal x = 99\nlocal r = f(4)\nprint(r, x)",
            "void" => "local out = {}\nlocal push = BASIL_INLINE(function(t, v) t[#t + 1] = v * 2 end)\npush(out, 3)\npush(out, 4)\nprint(table.concat(out, \",\"))",
            _ => unreachable!(),
        };
        let want = run(&luau, plain, &format!("{tag}_plain"));
        assert_eq!(
            run(&luau, hand, &format!("{tag}_hand")),
            want,
            "[{tag}] hand-inlined must match plain"
        );
        let art = build(&src(macro_src), 1337).unwrap_or_else(|e| panic!("[{tag}] build: {e}"));
        assert_eq!(
            run(&luau, &art, &format!("{tag}_macro")),
            want,
            "[{tag}] BASIL_INLINE must match plain"
        );
    }
}

#[test]
fn i17_mutation_of_inputs_tracks_plain_execution() {
    let Some(luau) = find_luau() else { return };
    let body = "local clamp = BASIL_INLINE(function(v, lo, hi) local r = v if v < lo then r = lo elseif v > hi then r = hi end return r end)\n\
        local sum = 0\nfor i = START, STOP do local c = clamp(i, 3, 7) sum = sum + c end\nprint(sum)";
    for (start, stop) in [(1, 1), (1, 5), (0, 10), (5, 5), (8, 2)] {
        let src_txt = src(&body
            .replace("START", &start.to_string())
            .replace("STOP", &stop.to_string()));
        let want = run(&luau, &src_txt, "mut_plain");
        let art = build(&src_txt, 42).expect("build");
        assert_eq!(
            run(&luau, &art, "mut_obf"),
            want,
            "trip [{start},{stop}] must match plain"
        );
    }

    let na = "local f = BASIL_INLINE(function(a) local r = \"nil\" if a ~= nil then r = \"val:\" .. tostring(a) end return r end)\n\
        local x = f()\nlocal y = f(7)\nprint(x, y)";
    let want = run(&luau, &src(na), "na_plain");
    assert_eq!(
        run(&luau, &build(&src(na), 9).unwrap(), "na_obf"),
        want,
        "nil-argument path must match"
    );
}

#[test]
fn i18_two_separate_helpers_with_overlapping_internal_names() {
    accept(
        "two-helpers",
        "local addOne = BASIL_INLINE(function(x) local t = x + 1 return t end)\n\
         local double = BASIL_INLINE(function(x) local t = x * 2 return t end)\n\
         local a = addOne(4)\nlocal b = double(4)\nprint(a, b)",
    );
}

#[test]
fn i19_identical_local_names_in_caller_and_helper_do_not_interfere() {
    accept(
        "same-names",
        "local t = 100\nlocal x = 7\nlocal f = BASIL_INLINE(function(a) local t = a * 2 local x = t + 1 return x end)\n\
         local r = f(3)\nprint(r, t, x)",
    );
}

#[test]
fn i21_different_seeds_vary_the_artifact() {
    let body =
        "local f = BASIL_INLINE(function(a, b) return a * a + b end)\nlocal r = f(3, 4)\nprint(r)";
    let s = src(body);
    let a = build(&s, 1).expect("build");
    let b = build(&s, 1337).expect("build");
    assert_ne!(a, b, "different seeds must vary the inlined artifact");
}

#[test]
fn i22_parentheses_around_the_macro_name_are_transparent() {
    let art = accept(
        "parens",
        "local f = (BASIL_INLINE)(function(a) return a + 1 end)\nlocal r = f(41)\nprint(r)",
    );
    assert!(
        !art.contains("BASIL_INLINE"),
        "the macro is consumed, not left in the artifact"
    );
}

#[test]
fn r12_reassignment_after_declaration_is_rejected() {
    let e = reject(
        "reassign",
        "local f = BASIL_INLINE(function() return 1 end)\nf = function() return 2 end\nlocal r = f()\nprint(r)",
    );
    assert!(
        e.contains("used as a value"),
        "reassigning the binding is rejected, got: {e}"
    );
}

#[test]
fn r13_method_and_field_access_on_the_helper_are_rejected() {
    let m = reject(
        "method",
        "local f = BASIL_INLINE(function() return 1 end)\nlocal r = f:call()\nprint(r)",
    );
    assert!(
        m.contains("used as a value"),
        "method call on the helper is rejected, got: {m}"
    );
    let field = reject(
        "field",
        "local f = BASIL_INLINE(function() return 1 end)\nlocal r = f.name\nprint(r)",
    );
    assert!(
        field.contains("used as a value"),
        "field access on the helper is rejected, got: {field}"
    );
}

#[test]
fn r14_async_and_protected_call_targets_are_rejected() {
    for (tag, body) in [
        ("coroutine", "local f = BASIL_INLINE(function() return 1 end)\nlocal c = coroutine.wrap(f)\nprint(c())"),
        ("xpcall", "local f = BASIL_INLINE(function() return 1 end)\nlocal ok = xpcall(f, function() end)\nprint(ok)"),
        ("connect", "local f = BASIL_INLINE(function() return 1 end)\nsignal:Connect(f)\nprint(\"ok\")"),
    ] {
        let e = reject(tag, body);
        assert!(e.contains("used as a value"), "[{tag}] passing the helper to {tag} is rejected, got: {e}");
    }
}

#[test]
fn r15_mutual_recursion_is_rejected_via_the_helper_reference_rule() {
    let e = reject(
        "mutual",
        "local isEven = BASIL_INLINE(function(n) if n == 0 then return true end return isOdd(n - 1) end)\n\
         local isOdd = BASIL_INLINE(function(n) if n == 0 then return false end return isEven(n - 1) end)\n\
         local r = isEven(4)\nprint(r)",
    );
    assert!(
        e.contains("references another BASIL_INLINE helper") || e.contains("early return"),
        "mutual recursion between two inline helpers is rejected, got: {e}"
    );
}

#[test]
fn r16_a_helper_referencing_another_helper_is_rejected_not_miscompiled() {
    let e = reject(
        "helper-ref",
        "local g = BASIL_INLINE(function(x) return x + 1 end)\n\
         local f = BASIL_INLINE(function(n) local r = g(n) return r end)\n\
         local out = f(5)\nprint(out)",
    );
    assert!(
        e.contains("references another BASIL_INLINE helper"),
        "got: {e}"
    );
}

#[test]
fn r17_a_nested_function_literal_inside_the_helper_is_rejected() {
    for (tag, body) in [
        ("returned", "local f = BASIL_INLINE(function(a) local g = function() return a end return g end)\nlocal h = f(5)\nprint(h())"),
        ("local-fn", "local f = BASIL_INLINE(function(a) local function g() return a end return g() end)\nlocal r = f(5)\nprint(r)"),
        ("callback", "local f = BASIL_INLINE(function(t) table.sort(t, function(a, b) return a < b end) return t[1] end)\nlocal r = f({3, 1, 2})\nprint(r)"),
    ] {
        let e = reject(tag, body);
        assert!(e.contains("nested function literal"), "[{tag}] got: {e}");
    }
}

#[test]
fn r18_a_name_alias_to_the_macro_is_rejected() {
    let e = reject(
        "name-alias",
        "local M = BASIL_INLINE\nlocal f = M(function() return 1 end)\nlocal r = f()\nprint(r)",
    );
    assert!(
        e.contains("BASIL_INLINE"),
        "binding the macro to a name is rejected, got: {e}"
    );
}

#[test]
fn r19_assignment_to_a_global_is_not_recognized_and_rejected() {
    let e = reject(
        "global",
        "GLOB = BASIL_INLINE(function() return 1 end)\nlocal r = GLOB()\nprint(r)",
    );
    assert!(
        e.contains("BASIL_INLINE"),
        "a global-target assignment is rejected, got: {e}"
    );
}

#[test]
fn r20_an_alias_chain_is_rejected_at_the_first_alias() {
    let e = reject(
        "alias-chain",
        "local f = BASIL_INLINE(function() return 1 end)\nlocal a = f\nlocal b = a\nlocal r = b()\nprint(r)",
    );
    assert!(
        e.contains("used as a value"),
        "aliasing the helper is rejected, got: {e}"
    );
}
