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

fn cfg(seed: u64, minify: bool, semantic_family: bool) -> Config {
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
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let i = tmp("sf_in");
    let o = tmp("sf_out");
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

const SRC: &str = "local t = { a = 1, b = 2, c = 3 }\nlocal s = 0\nfor i = 1, 15 do if i % 2 == 0 then s = s + t.a * t.b else s = s + t.c end end\nlocal names = { \"alpha\", \"beta\" }\nfor _, n in ipairs(names) do s = s + #n end\nprint(s)";

const STREAMED: &str = "for i = 1, n do consts[i] = rawbytes(vu()) end";
const DIRECTORY: &str = "for i = 1, n do ln[i] = vu() end";

const STREAMED_SEED: u64 = 2;
const DIRECTORY_SEED: u64 = 1;
fn seed_for(family: u8) -> u64 {
    if family == 1 {
        DIRECTORY_SEED
    } else {
        STREAMED_SEED
    }
}

#[test]
fn both_families_are_reachable_and_off_is_streamed_only() {
    let s0 = seed_for(0);
    let s1 = seed_for(1);
    let a0 = build(SRC, cfg(s0, false, true));
    let a1 = build(SRC, cfg(s1, false, true));
    assert!(
        a0.contains(STREAMED) && !a0.contains(DIRECTORY),
        "family 0 = STREAMED grammar"
    );
    assert!(
        a1.contains(DIRECTORY) && !a1.contains(STREAMED),
        "family 1 = DIRECTORY grammar"
    );
    let off1 = build(SRC, cfg(s1, false, false));
    assert!(
        off1.contains(STREAMED) && !off1.contains(DIRECTORY),
        "OFF must never emit the DIRECTORY grammar"
    );
}

#[test]
fn cross_build_reader_model_does_not_transfer() {
    let a0 = build(SRC, cfg(seed_for(0), false, true));
    let a1 = build(SRC, cfg(seed_for(1), false, true));
    let streamed_model = |art: &str| art.contains(STREAMED);
    assert!(
        streamed_model(&a0),
        "STREAMED model describes the STREAMED build"
    );
    assert!(
        !streamed_model(&a1),
        "STREAMED model must NOT describe the DIRECTORY build (low transfer)"
    );
}

#[test]
fn behaviour_matches_plain_for_both_families() {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("sf_raw");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    for seed in [seed_for(0), seed_for(1), 1u64, 2, 3, 4, 7, 42] {
        let art = build(SRC, cfg(seed, true, true));
        let p = tmp("sf_art");
        std::fs::write(&p, &art).unwrap();
        assert_eq!(
            run_luau(&luau, &p),
            reference,
            "seed {seed}: both families must match plain Luau"
        );
    }
}

#[test]
fn off_is_deterministic_and_default() {
    let a = build(SRC, cfg(9, true, false));
    let b = build(SRC, cfg(9, true, false));
    assert_eq!(a, b, "OFF is deterministic");
    assert_eq!(cfg(0, true, false).semantic_family, false);
}
