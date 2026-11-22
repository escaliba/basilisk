use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, PropKeyMode, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{prefix}_{}_{}.luau",
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

fn run_luau(bin: &str, path: &std::path::Path) -> String {
    let out = std::process::Command::new(bin)
        .arg(path)
        .output()
        .expect("spawn luau");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim()
    .to_string()
}

fn cfg(seed: u64, d1: bool) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: false,
        junk: false,
        fuse: false,
        minify: false,
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
        ablate_fragment: true,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
        shell_family: None,
        notices: pipeline::NoticeConfig::default(),
        stateful_recovery: d1,
        stateful_framing: false,
        property_key_rename: PropKeyMode::Off,
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let input = tmp("mc_in");
    let output = tmp("mc_out");
    std::fs::write(&input, src).unwrap();
    let (i, o) = (input.clone(), output.clone());
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || pipeline::run(&i, &o, &cfg).unwrap())
        .unwrap()
        .join()
        .unwrap();
    std::fs::read_to_string(&output).unwrap()
}

fn matches_plain(src: &str, seed: u64) {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("mc_raw");
    std::fs::write(&raw, src).unwrap();
    let reference = run_luau(&luau, &raw);
    let art = build(src, cfg(seed, true));
    let ap = tmp("mc_art");
    std::fs::write(&ap, &art).unwrap();
    assert_eq!(
        run_luau(&luau, &ap),
        reference,
        "D1 metadata-cache build must match plain Luau:\n{src}"
    );
}

#[test]
fn d1_emits_separate_bounded_metadata_cache_and_non_d1_does_not() {
    let d1 = build(
        "local t = { a = 1, b = 2 } local s = 0 for i = 1, 3 do s = s + t.a + t.b end return s",
        cfg(7, true),
    );
    assert!(
        d1.contains("kc[-6]"),
        "D1 artifact uses the separate metadata cache slot"
    );
    assert!(
        d1.contains("local KMCAP = 32"),
        "D1 artifact declares the bounded capacity"
    );
    assert!(
        d1.contains("kc[-8] = (mp % KMCAP) + 1"),
        "D1 artifact uses a bounded ring index"
    );
    assert!(
        !d1.contains("kc[i] = dvar(plain)"),
        "D1 number consts do not enter the ordinary KCAP cache"
    );

    let base = build(
        "local t = { a = 1, b = 2 } local s = 0 for i = 1, 3 do s = s + t.a + t.b end return s",
        cfg(7, false),
    );
    assert!(
        !base.contains("kc[-6]") && !base.contains("KMCAP"),
        "non-D1 emits no metadata cache"
    );
}

#[test]
fn d1_recursion_independent_per_frame_caches() {
    matches_plain(
        "local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end print(fib(12))",
        0x5eed,
    );
}

#[test]
fn d1_coroutine_correct() {
    matches_plain(
        "local co = coroutine.wrap(function() for i = 1, 5 do coroutine.yield(i * 3 + 1) end end)\nlocal s = 0 for _ = 1, 5 do s = s + co() end print(s)",
        0x5eee,
    );
}

#[test]
fn d1_nested_child_protos_correct() {
    matches_plain(
        "local function outer(a) local function inner(b) return a * b + 7 end return inner(a + 1) + inner(a + 2) end local s = 0 for i = 1, 6 do s = s + outer(i) end print(s)",
        0x5eef,
    );
}

#[test]
fn d1_bounded_eviction_over_capacity_stays_correct() {
    let mut src = String::from("local t = { a = 1, b = 2 }\nlocal s = 0\nfor i = 1, 500 do\n");
    let mods = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43];
    for (k, m) in mods.iter().enumerate() {
        let kw = if k == 0 { "if" } else { "elseif" };
        src.push_str(&format!(
            "{kw} i % {m} == 0 then s = s + {} * t.a - {} + t.b\n",
            m * 3 + 1,
            m * 2
        ));
    }
    src.push_str("else s = s + t.a end\nend\nprint(s)\n");
    matches_plain(&src, 0x5ef0);
}

#[test]
fn d1_warm_cache_wrong_state_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let src = "local x = 0\nfor j = 1, 100 do x = x + 42 + 7 end\nprint(x)\n";
    let art = build(src, cfg(0xC0FFEE, true));
    assert!(
        art.contains("ms[i] == ep"),
        "cache reuse is state-qualified"
    );
    assert!(
        art.contains("ms[i] = ep"),
        "populate records the authenticated block state"
    );
    assert!(art.contains("kc[-9]"), "dedicated state table present");
    let step = {
        let anchor = "kc[-4] = bxor(fmix(kc[-4]), a %";
        let s = art.find(anchor).expect("bstate step present");
        let from = s + anchor.len();
        let e = art[from..]
            .find(')')
            .map(|p| from + p + 1)
            .expect("step closes");
        art[s..e].to_string()
    };
    let call = "makeClosure(mainProto, {})()";
    assert!(
        art.contains(step.as_str()) && art.contains(call),
        "bstate step + entry call present"
    );

    let wrap = format!(
        "(function() local _o = pcall(function() return {call} end) print(\"BYP=\" .. tostring(_BYP)) return nil end)()"
    );
    let prep = |strip: bool| -> String {
        let mut s = art.replace(
            step.as_str(),
            &format!("_bsc = (_bsc or 0) + 1\nif _bsc > 20 then kc[-4] = 0x1234 else {step} end"),
        );
        if strip {
            s = s.replace(" and ms[i] == ep", "");
        }
        for ret in ["return hit", "return mc[i]", "return cv"] {
            s = s.replace(
                ret,
                &format!("if ms[i] ~= ep then _BYP = _BYP + 1 end {ret}"),
            );
        }
        s = s.replacen(
            "return (function(unpack",
            "_bsc = 0\n_BYP = 0\nreturn (function(unpack",
            1,
        );
        s.replacen(call, &wrap, 1)
    };
    let byp = |src: String, name: &str| -> i64 {
        let p = tmp(name);
        std::fs::write(&p, &src).unwrap();
        let out = run_luau(&luau, &p);
        out.rsplit("BYP=")
            .next()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or_else(|| panic!("no BYP in: {out}"))
    };
    assert_eq!(
        byp(prep(false), "d1_warm_sq"),
        0,
        "no warm entry may be reused under a mismatched block state"
    );
    assert!(
        byp(prep(true), "d1_warm_alias") > 0,
        "control: alias-only reuse would bypass the wrong-state check"
    );
}

#[test]
fn d1_loop_reuse_matches_plain_across_seeds() {
    let src = "local cfg = { x = 3, y = 5, z = 7 }\nlocal acc = 0\nfor i = 1, 40 do\nif i % 2 == 0 then acc = acc + cfg.x * cfg.y\nelseif i % 3 == 0 then acc = acc - cfg.z\nelse acc = acc + cfg.y end\nend\nprint(acc)";
    for seed in [1u64, 42, 1337, 90210] {
        matches_plain(src, seed);
    }
}
