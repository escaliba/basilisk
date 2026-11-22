use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, PropKeyMode, SensitiveOpts, StringFragMode,
    SurfaceVolume, TargetProfile,
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
        .expect("luau");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim()
    .to_string()
}

fn cfg(seed: u64, minify: bool, microir: bool) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: false,
        junk: false,
        fuse: true,
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
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir,
        semgroup: false,
        string_frag_mode: StringFragMode::Full,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let i = tmp("mi_in");
    let o = tmp("mi_out");
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

const SRC: &str = r#"
local function f(x)
	local a = x + 3
	local b = a - 7
	local c = b * 2
	local d = a + 1000000
	return a + b + c + d
end
local mt = setmetatable({v=10}, { __add=function(s,o) return s.v + o end, __sub=function(s,o) return s.v - o end, __mul=function(s,o) return s.v * o end })
local s = 0
for i = 1, 8 do s = s + f(i) end
print("MI", s, f(0), f(-4), f(2.5), "7" + 3, mt + 5, mt - 2, mt * 3, (1/0), (0/0 ~= 0/0))
"#;

#[test]
fn microir_on_matches_plain_including_metamethods_and_coercion() {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("mi_raw");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    assert!(
        reference.starts_with("MI"),
        "raw reference sane: {reference}"
    );
    for seed in [1u64, 2, 5, 7, 42, 305419896, 3816332487991545974] {
        let art = build(SRC, cfg(seed, true, true));
        let p = tmp("mi_art");
        std::fs::write(&p, &art).unwrap();
        assert_eq!(
            run_luau(&luau, &p),
            reference,
            "seed {seed}: microir must match plain Luau"
        );
    }
}

#[test]
fn microir_lowers_cold_arithmetic_to_shared_micro_ops() {
    let art = build(SRC, cfg(5, false, true));
    let handlers = art.matches("sel % 3").count();
    assert!(
        handlers >= 1,
        "at least one MApply* handler emitted (cold arithmetic lowered): {handlers}"
    );
    assert!(art.contains("1000003"), "selector mix constant present");
}

#[test]
fn off_is_byte_identical_and_default() {
    let off1 = build(SRC, cfg(9, true, false));
    let off2 = build(SRC, cfg(9, true, false));
    assert_eq!(off1, off2, "OFF deterministic");
    assert_eq!(cfg(0, true, false).microir, false, "OFF is the default");
    let on = build(SRC, cfg(9, true, true));
    assert_ne!(on, off1, "ON changes the artifact (arithmetic was lowered)");
}
