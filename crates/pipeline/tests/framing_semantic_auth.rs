use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    BuildStats, Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_fsa_{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    std::process::Command::new("luau")
        .arg("--help")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn cfg(seed: u64) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: true,
        junk: false,
        fuse: true,
        minify: true,
        compress: false,
        anti_envlog: false,
        hard_dispatch: false,
        surface: false,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile: TargetProfile::CliTest,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: false,
        strip_source_names: false,
        poly_stream: PolyStream::Off,
        optimization: 0,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: Default::default(),
        hot_callback_policy: HotCallbackPolicy::Report,
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

fn build(src: &str, cfg: Config) -> (String, BuildStats) {
    let input = tmp("in");
    let output = tmp("out");
    std::fs::write(&input, src).unwrap();
    let (i, o) = (input.clone(), output.clone());
    let stats = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let mut s = None;
            pipeline::run_capturing_stats(&i, &o, &cfg, None, &mut s).expect("build succeeds");
            s.expect("stats")
        })
        .expect("spawn")
        .join()
        .expect("build thread");
    let art = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    (art, stats)
}

fn run(luau: &str, code: &str) -> String {
    let p = tmp("run");
    std::fs::write(&p, code).unwrap();
    let out = std::process::Command::new(luau)
        .arg(&p)
        .output()
        .expect("spawn luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const CASES: &[(&str, &str)] = &[
    ("zero_args", "local function f() return 42 end print(f())"),
    ("one_arg", "local function f(a) return a * 3 end print(f(7))"),
    ("two_args", "local function f(a, b) return a - b end print(f(10, 4))"),
    (
        "five_args",
        "local function f(a, b, c, d, e) return a + b + c + d + e end print(f(1, 2, 3, 4, 5))",
    ),
    (
        "vararg",
        "local function f(...) local s = 0 for _, v in ipairs({...}) do s = s + v end return s, select('#', ...) end print(f(3, 4, 5))",
    ),
    (
        "multret",
        "local function f() return 1, 2, nil, 'tail' end local a, b, c, d = f() print(a, b, c, d, select('#', f()))",
    ),
    (
        "high_max_stack",
        "local function f() local a,b,c,d,e,g,h,i,j,k,l,m = 1,2,3,4,5,6,7,8,9,10,11,12 return a+b+c+d+e+g+h+i+j+k+l+m end print(f())",
    ),
    (
        "nested_closures",
        "local function outer(x) local function mid(y) local function inner(z) return x + y + z end return inner end return mid end print(outer(1)(2)(3))",
    ),
    (
        "captured_argument",
        "local function make(n) return function() return n * 2 end end print(make(21)())",
    ),
    (
        "captured_mutable_local",
        "local function counter() local c = 0 return function() c = c + 1 return c end end local nx = counter() print(nx(), nx(), nx())",
    ),
    (
        "sibling_closures_share_local",
        "local function pair() local v = 0 local function set(x) v = x end local function get() return v end return set, get end local s, g = pair() s(99) print(g())",
    ),
    (
        "capture_of_capture",
        "local function a() local x = 5 local function b() local function c() return x end return c end return b end print(a()()())",
    ),
    (
        "recursive_closure",
        "local function fact(n) if n <= 1 then return 1 end return n * fact(n - 1) end print(fact(6))",
    ),
    (
        "mutual_recursion",
        "local isEven, isOdd isEven = function(n) if n == 0 then return true end return isOdd(n - 1) end isOdd = function(n) if n == 0 then return false end return isEven(n - 1) end print(isEven(10), isOdd(7))",
    ),
    (
        "loop_created_closures",
        "local t = {} for i = 1, 3 do t[i] = function() return i end end print(t[1](), t[2](), t[3]())",
    ),
    (
        "method_self_param",
        "local obj = { v = 8 } function obj:add(n) return self.v + n end print(obj:add(5))",
    ),
    (
        "pcall_around_closure",
        "local function risky(x) if x < 0 then error('neg', 0) end return x * x end print(pcall(risky, 4)) print(pcall(risky, -1))",
    ),
    (
        "generalized_iteration_closure",
        "local function range(n) local i = 0 return function() i = i + 1 if i <= n then return i end end end local s = 0 for v in range(5) do s = s + v end print(s)",
    ),
];

const SEEDS: [u64; 3] = [1, 42, 1337];

#[test]
fn params_and_upvalues_corpus_matches_plain_luau_across_seeds() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping framing-semantic differential");
        return;
    };
    let mut failures = Vec::new();
    for (name, src) in CASES {
        let want = run(&luau, src);
        for seed in SEEDS {
            let (art, _) = build(src, cfg(seed));
            let got = run(&luau, &art);
            if got != want {
                failures.push(format!("[{name} seed={seed}] plain={want:?} virt={got:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "framing-authentication broke semantics:\n{}",
        failures.join("\n")
    );
}

#[test]
fn deterministic_per_seed_and_distinct_across_seeds() {
    let (name, src) = CASES[10];
    let _ = name;
    let (a, sa) = build(src, cfg(1));
    let (b, _) = build(src, cfg(1));
    assert_eq!(a, b, "same source+seed+config → byte-identical artifact");
    let (c, sc) = build(src, cfg(42));
    assert_ne!(a, c, "different seed → distinct artifact");
    assert_eq!(
        sa.protos, sc.protos,
        "seed change must not move structural proto count"
    );
}

#[test]
fn vm_template_folds_framing_into_the_wire_digest() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vm = std::fs::read_to_string(root.join("runtime/vm_template.luau")).unwrap();
    assert!(
        vm.contains("FM1 = MK - MK % 2 + 1")
            && vm.contains("FM2 = MAPKEY - MAPKEY % 2 + 1")
            && vm.contains("* FM1")
            && vm.contains("* FM2"),
        "the nonlinear fmix mixer (seed-derived odd multipliers) must stay present in the VM"
    );
    let cut = vm
        .find("local main = readProto(true)")
        .expect("readProto driver present");
    let read_proto = &vm[..cut];
    for needle in [
        "proto[14] = bxor(proto[14], bxor(lrotate(MK, 11), lrotate(MAPKEY, 23)))",
        "fmix((proto[14] + proto[6]) %",
        "fmix((proto[14] + (proto[7] and 1 or 0)) %",
        "fmix((proto[14] + proto[8]) %",
        "fmix((proto[14] + #proto[3]) %",
        "proto[3][i][KIS]",
        "proto[3][i][KIX]",
    ] {
        assert!(
            read_proto.contains(needle),
            "the VM framing fold must stay present: `{needle}` missing"
        );
    }
}
