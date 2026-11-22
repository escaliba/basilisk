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
        strip_source_names: true,
        poly_stream: PolyStream::Off,
        optimization: 2,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: pipeline::FrameConstReuseMode::Off,
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
    let i = tmp("pca_in");
    let o = tmp("pca_out");
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
    let p = tmp("pca_run");
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

const SAMPLE_SRC: &str = "\
local A = \"BASIL_PRIVATE_ASSEMBLY_ALPHA_91D7\"
local B = \"BASIL_PRIVATE_ASSEMBLY_BETA_42AC\"
local G = \"BASIL_PRIVATE_ASSEMBLY_GAMMA_7F20\"
local LONG = \"BASIL_PRIVATE_ASSEMBLY_GAMMA_7F20-tail-padding-crossing-multiple-chacha-blocks-0123456789abcdef\"
local NULS = \"a\\0b\\0c\"
local REP = \"aaaaaaaaaaaaaaaa\"
local U8 = \"\\228\\184\\173\\230\\150\\135\"
local HI = \"\\200\\201\\202\\255\"
local n = 0
local function useAll()
\tn = n + #A + #B + #G + #LONG + #NULS + #REP + #U8 + #HI
\treturn n
end
for i = 1, 3 do useAll() end
print(n, A ~= B, G ~= B, NULS == \"a\\0b\\0c\", U8 == \"\\228\\184\\173\\230\\150\\135\", HI == \"\\200\\201\\202\\255\", 1234, 5.5, true)
";

const HOOKS: &str = r##"
local _rt, _rs = table, string
local _rc, _sc = _rt.concat, _rs.char
local buf, bn = {}, 0
local function scan(src, s)
	if type(s) ~= "string" then return end
	for _, w in ipairs({ "ALPHA_91D7", "BETA_42AC", "GAMMA_7F20", "BASIL_PRIVATE" }) do
		if string.find(s, w, 1, true) then print("LEAK:" .. src) end
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
-- Replace the CHUNK ENVIRONMENT, not just lexical names: the VM resolves `table`/`string` through
-- getfenv, so a lexical shadow alone is a false negative for anything the VM calls at runtime.
local _base = getfenv(1)
setfenv(1, setmetatable({ table = hookedTable, string = hookedString }, { __index = _base }))
"##;

#[test]
fn no_user_constant_reaches_table_concat_or_string_char() {
    let Some(_) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let out = run_with(HOOKS, &build(SAMPLE_SRC, cfg(0x5EED_1234)));
    assert!(
        out.contains("672"),
        "program output must remain correct: {out}"
    );
    assert!(
        out.contains("true"),
        "binary/UTF-8 comparisons must hold: {out}"
    );
    assert!(
        !out.contains("LEAK:"),
        "a hook observed a user constant:\n{out}"
    );
}

#[test]
fn the_hook_fixture_still_detects_the_historical_vulnerable_shape() {
    let Some(_) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let legacy = "\
local bytes = { 66,65,83,73,76,95,80,82,73,86,65,84,69,95,65,83,83,69,77,66,76,89,95,65,76,80,72,65,95,57,49,68,55 }
local out = {}
for i = 1, #bytes, 4 do
\tlocal a, b, c, d = bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]
\tif d then out[#out+1] = string.char(a, b, c, d)
\telseif c then out[#out+1] = string.char(a, b, c)
\telseif b then out[#out+1] = string.char(a, b)
\telse out[#out+1] = string.char(a) end
end
local s = table.concat(out)
print(#s)
";
    let out = run_with(HOOKS, legacy);
    assert!(
        out.contains("LEAK:"),
        "the hook fixture must detect the historical char()+concat reconstruction:\n{out}"
    );
}

#[test]
fn constants_are_absent_from_the_artifact_at_rest() {
    for private in [false, true] {
        let art = build(SAMPLE_SRC, cfg(0x5EED_1234));
        for s in ["ALPHA_91D7", "BETA_42AC", "GAMMA_7F20", "BASIL_PRIVATE"] {
            assert!(
                !art.contains(s),
                "`{s}` must not appear at rest (private={private})"
            );
        }
    }
}

#[test]
fn binary_strings_round_trip_exactly() {
    let Some(_) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let src = "\
local N = \"\\0\\0\\0\"
local M = \"x\\0y\\255z\"
local U = \"\\228\\184\\173\\230\\150\\135\"
local E = \"\"
local L = string.rep and \"unused\" or \"unused\"
print(#N, #M, #U, #E, M == \"x\\0y\\255z\", U == \"\\228\\184\\173\\230\\150\\135\", N == \"\\0\\0\\0\")
";
    let plain = {
        let p = tmp("pca_plain");
        std::fs::write(&p, src).unwrap();
        let o = std::process::Command::new("luau").arg(&p).output().unwrap();
        let _ = std::fs::remove_file(&p);
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    for private in [false, true] {
        let got = run_with("", &build(src, cfg(0x4242)));
        assert_eq!(
            plain.trim(),
            got.trim(),
            "binary round-trip differs (private={private})"
        );
    }
}

#[test]
fn the_private_path_keeps_chacha_and_avoids_hookable_reconstruction() {
    let mut c = cfg(0x5EED_1234);
    c.minify = false;
    let vm = build("local s = \"probe-constant\"\nprint(#s)\n", c);

    assert!(
        vm.contains("local function chachaBlock"),
        "ChaCha block function retained"
    );
    assert!(
        vm.contains("for _ = 1, 10 do"),
        "all 20 rounds (10 double-rounds) retained"
    );
    assert!(
        vm.contains("BYTETAB[_bi] = char(_bi)"),
        "byte table built from the fixed 0-255 sequence"
    );
    assert!(
        vm.contains("dead = true"),
        "byte-table verification fails closed"
    );

    let mut saw_string_family = false;
    let mut saw_buffer_family = false;
    for seed in [0x5EED_1234u64, 1, 2, 3, 5, 7, 42, 999] {
        let mut sc = cfg(seed);
        sc.minify = false;
        let art = build("local s = \"probe-constant\"\nprint(#s)\n", sc);
        assert!(
            !art.contains("char(R % 256"),
            "seed {seed}: word chunk must not char() plaintext"
        );
        assert!(
            !art.contains("char(bxor(byte(data"),
            "seed {seed}: tail byte must not char() plaintext"
        );
        assert!(
            !art.contains("return concat(out)"),
            "seed {seed}: reduce must not table.concat plaintext"
        );
        assert!(
            art.contains("BYTETAB["),
            "seed {seed}: plaintext bytes come from the private lookup"
        );
        if art.contains("local function streamXor") {
            saw_string_family = true;
        }
        if art.contains("return _bt(buf)") {
            saw_buffer_family = true;
        }
    }
    assert!(
        saw_string_family,
        "seed set must exercise the string streamXor family"
    );
    assert!(
        saw_buffer_family,
        "seed set must exercise the buffer streamXor family"
    );
}

#[test]
fn promoted_output_is_deterministic_per_seed_and_distinct_across_seeds() {
    let src = "local s = \"identity-probe\"\nlocal n = 42\nprint(#s, n)\n";
    let mut prev: Option<String> = None;
    for seed in [1u64, 0x5EED_1234, 17906244878785717735] {
        let a = build(src, cfg(seed));
        let b = build(src, cfg(seed));
        assert_eq!(a, b, "seed {seed}: repeated builds must be byte-identical");
        if let Some(p) = &prev {
            assert_ne!(*p, a, "different seeds must remain structurally distinct");
        }
        prev = Some(a);
    }
}
