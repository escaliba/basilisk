use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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

fn frag_cfg(seed: u64) -> Config {
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
        strip_source_names: true,
        poly_stream: PolyStream::Off,
        optimization: 2,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: pipeline::FrameConstReuseMode::Off,
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

fn build(src: &str, cfg: Config) -> String {
    let i = tmp("fpa_in");
    let o = tmp("fpa_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    std::thread::Builder::new()
        .stack_size(128 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).expect("build"))
        .unwrap()
        .join()
        .unwrap();
    let out = std::fs::read_to_string(&o).unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn run_with(prelude: &str, artifact: &str) -> String {
    let p = tmp("fpa_run");
    std::fs::write(&p, format!("{prelude}{artifact}")).unwrap();
    let out = std::process::Command::new("luau")
        .arg(&p)
        .output()
        .expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const ENV_HOOKS: &str = r##"
local _rt, _rs = table, string
local _rc, _sc = _rt.concat, _rs.char
local buf, bn = {}, 0
local function scan(src, s)
	if type(s) ~= "string" then return end
	for _, w in ipairs({ "ALPHA_91D7", "BETA_42AC", "GAMMA_7F20", "BASIL_FRAGMENT", "FRAGMENT_PATH" }) do
		if string.find(s, w, 1, true) then print("LEAK[" .. src .. "]") end
	end
end
local hookedTable = setmetatable({ concat = function(t, sep, i, j)
	local r = _rc(t, sep, i, j)
	scan("concat-result", r)
	for k = 1, #t do scan("concat-arg", t[k]) end
	return r
end }, { __index = _rt })
local hookedString = setmetatable({ char = function(...)
	local r = _sc(...)
	scan("char-result", r)
	bn = bn + 1
	buf[bn] = r
	if bn >= 64 then scan("char-sequence", _rc(buf)) buf, bn = {}, 0 end
	return r
end }, { __index = _rs })
local _base = getfenv(1)
setfenv(1, setmetatable({ table = hookedTable, string = hookedString }, { __index = _base }))
"##;

const SAMPLE_SRC: &str = "\
local A = \"BASIL_FRAGMENT_PATH_ALPHA_91D7_LONG_CONSTANT\"
local B = \"BASIL_FRAGMENT_PATH_BETA_42AC_LONG_CONSTANT\"
local G = \"BASIL_FRAGMENT_PATH_GAMMA_7F20_LONG_CONSTANT\"
local n = 0
local function useAll()
\tn = n + #A + #B + #G
\treturn n
end
for i = 1, 3 do useAll() end
print(n, A ~= B, G ~= B)
";

#[test]
fn fragmentation_is_actually_active_in_this_fixture() {
    let frag = build(SAMPLE_SRC, frag_cfg(42));
    let mut off = frag_cfg(42);
    off.ablate_fragment = true;
    let plain = build(SAMPLE_SRC, off);
    assert!(
        frag.len() > plain.len(),
        "fragmentation must actually transform the fixture"
    );
}

#[test]
fn fragmented_constants_never_reach_table_concat_or_string_char() {
    let Some(_) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    for seed in [1u64, 42, 999] {
        let out = run_with(ENV_HOOKS, &build(SAMPLE_SRC, frag_cfg(seed)));
        assert!(
            out.contains("393"),
            "seed {seed}: output must stay correct: {out}"
        );
        assert!(
            !out.contains("LEAK["),
            "seed {seed}: a hook observed a fragment:\n{out}"
        );
    }
}

#[test]
fn the_env_hook_fixture_still_detects_the_historical_fragment_shape() {
    let Some(_) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let legacy = "\
local parts = { \"BASIL_FRAGMENT\", \"_PATH_ALPHA_91D7\", \"_LONG_CONSTANT\" }
local viaConcat = table.concat(parts)
local bytes = { 66, 65, 83, 73, 76, 95, 70, 82, 65, 71, 77, 69, 78, 84 }
local viaChar = string.char(unpack and unpack(bytes) or table.unpack(bytes))
print(#viaConcat, #viaChar)
";
    let out = run_with(ENV_HOOKS, legacy);
    assert!(
        out.contains("LEAK["),
        "the env-hook fixture must detect the historical shape:\n{out}"
    );
}

#[test]
fn fragmented_binary_strings_and_nuls_round_trip() {
    let Some(_) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let src = "\
local M = \"long-binary-payload-x\\0y\\255z-with-embedded-nul-and-high-bytes\"
local U = \"long-utf8-constant-\\228\\184\\173\\230\\150\\135-tail-padding-here\"
local R = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
print(#M, #U, #R, M == \"long-binary-payload-x\\0y\\255z-with-embedded-nul-and-high-bytes\", U == \"long-utf8-constant-\\228\\184\\173\\230\\150\\135-tail-padding-here\")
";
    let plain = {
        let p = tmp("fpa_plain");
        std::fs::write(&p, src).unwrap();
        let o = std::process::Command::new("luau").arg(&p).output().unwrap();
        let _ = std::fs::remove_file(&p);
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    for seed in [7u64, 4242] {
        let got = run_with("", &build(src, frag_cfg(seed)));
        assert_eq!(
            plain.trim(),
            got.trim(),
            "seed {seed}: fragmented binary round-trip differs"
        );
    }
}

#[test]
fn evaluation_order_and_side_effects_are_preserved() {
    let Some(_) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let src = "\
local log = {}
local function tag(s) log[#log + 1] = s return s end
local A = \"ORDER_SENSITIVE_CONSTANT_ALPHA_LONG\"
local B = \"ORDER_SENSITIVE_CONSTANT_BETA_LONG\"
local r = tag(A) .. tag(B)
print(#r, log[1] == A, log[2] == B, #log)
";
    let plain = {
        let p = tmp("fpa_ord");
        std::fs::write(&p, src).unwrap();
        let o = std::process::Command::new("luau").arg(&p).output().unwrap();
        let _ = std::fs::remove_file(&p);
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    for seed in [3u64, 77] {
        let got = run_with("", &build(src, frag_cfg(seed)));
        assert_eq!(
            plain.trim(),
            got.trim(),
            "seed {seed}: evaluation order changed"
        );
    }
}

#[test]
fn fragmented_builds_stay_deterministic_per_seed() {
    for seed in [5u64, 55] {
        let a = build(SAMPLE_SRC, frag_cfg(seed));
        let b = build(SAMPLE_SRC, frag_cfg(seed));
        assert_eq!(a, b, "seed {seed}: fragmented build must be deterministic");
    }
}
