use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, PropKeyMode, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
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
        .expect("luau");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim()
    .to_string()
}

fn cfg(seed: u64, minify: bool, instruction_family: bool, semantic_family: bool) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: false,
        junk: false,
        fuse: false,
        minify,
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
        stateful_recovery: false,
        stateful_framing: false,
        property_key_rename: PropKeyMode::Off,
        string_frag_mode: pipeline::StringFragMode::Full,
        semantic_family,
        instruction_family,
        state_family: false,
        microir: false,
        semgroup: false,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let i = tmp("if_in");
    let o = tmp("if_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).unwrap())
        .unwrap()
        .join()
        .unwrap();
    std::fs::read_to_string(&o).unwrap()
}

const SRC: &str = "local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end\nlocal s = 0\nfor i = 1, 12 do if i % 3 == 0 then s = s + i * 2 elseif i % 2 == 0 then s = s - i else s = s + 1 end end\nlocal j = 0 while j < 8 do s = s + j j = j + 1 end\nlocal co = coroutine.wrap(function() for k = 1, 4 do coroutine.yield(k) end end)\nfor _ = 1, 4 do s = s + co() end\nprint(fib(10), s)";

const ABS_MARK: &str = "inst[kk] = inst[kk] - (i + 1)";

const REL_SEED: u64 = 1;
const ABS_SEED: u64 = 2;

#[test]
fn both_families_reachable_and_off_is_rel_only() {
    let rel = build(SRC, cfg(REL_SEED, false, true, false));
    let abs = build(SRC, cfg(ABS_SEED, false, true, false));
    assert!(
        !rel.contains(ABS_MARK),
        "REL family emits no absolute->offset conversion"
    );
    assert!(
        abs.contains(ABS_MARK),
        "ABS family emits the absolute->offset conversion"
    );
    let off = build(SRC, cfg(ABS_SEED, false, false, false));
    assert!(
        !off.contains(ABS_MARK),
        "OFF must never emit the ABS conversion even for an ABS-bit seed"
    );
}

#[test]
fn cross_build_controlflow_model_does_not_transfer() {
    let rel = build(SRC, cfg(REL_SEED, false, true, false));
    let abs = build(SRC, cfg(ABS_SEED, false, true, false));
    let rel_model = |art: &str| !art.contains(ABS_MARK);
    assert!(
        rel_model(&rel),
        "a relative-offset control-flow model describes the REL build"
    );
    assert!(
        !rel_model(&abs),
        "the REL model must NOT describe the ABS build (low single-family transfer)"
    );
}

#[test]
fn behaviour_matches_plain_for_both_families() {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("if_raw");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    for seed in [REL_SEED, ABS_SEED, 3u64, 4, 5, 6, 42, 305419896] {
        let art = build(SRC, cfg(seed, true, true, false));
        let p = tmp("if_art");
        std::fs::write(&p, &art).unwrap();
        assert_eq!(
            run_luau(&luau, &p),
            reference,
            "seed {seed}: instruction family must match plain Luau"
        );
    }
}

#[test]
fn stacks_with_const_section_family() {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("if_raw2");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    for seed in [1u64, 2, 3, 4] {
        let art = build(SRC, cfg(seed, true, true, true));
        let p = tmp("if_stack");
        std::fs::write(&p, &art).unwrap();
        assert_eq!(
            run_luau(&luau, &p),
            reference,
            "seed {seed}: instruction + const-section families compose correctly"
        );
    }
}

#[test]
fn off_is_deterministic_and_default() {
    let a = build(SRC, cfg(9, true, false, false));
    let b = build(SRC, cfg(9, true, false, false));
    assert_eq!(a, b, "OFF deterministic");
    assert_eq!(cfg(0, true, false, false).instruction_family, false);
}
