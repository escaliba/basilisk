use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    BuildStats, Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume,
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
    let input = tmp("cdkb_in");
    let output = tmp("cdkb_out");
    std::fs::write(&input, src).unwrap();
    let (i, o) = (input.clone(), output.clone());
    let stats = std::thread::Builder::new()
        .stack_size(64 << 20)
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

fn run(luau: &str, artifact: &str, prelude: &str) -> String {
    let p = tmp("cdkb_run");
    std::fs::write(&p, format!("{prelude}{artifact}")).unwrap();
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

fn g_prelude(fields: &str) -> String {
    format!("_G = setmetatable({{{fields}}}, {{__index = getfenv()}})\n")
}

const KEY: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

const ENCFUNC_SRC: &str = r##"
if not BASIL_OBFUSCATED then
	BASIL_ENCFUNC = function(fn) return fn end
end
local function fetchKey()
	return _G.BASILISK_RUNTIME_KEY
end
local runtimeKey = fetchKey()
local function inner(x)
	if x > 2 then return x * 5 end
	return x + 100
end
local sealed = BASIL_ENCFUNC(function(n)
	local TAG = "encfunc-sealed-secret"
	local acc = 0
	for i = 1, n do
		if i > 2 then acc = acc + i * 5 else acc = acc + i + 100 end
	end
	return acc, TAG, nil, "tail"
end, "__KEY__", runtimeKey)
local a, b, c, d = sealed(4)
local viaChild = 0
for i = 1, 4 do viaChild = viaChild + inner(i) end
print(a, b, c, d, select("#", sealed(4)), viaChild)
"##;

fn encfunc_src() -> String {
    ENCFUNC_SRC.replace("__KEY__", KEY)
}

#[test]
fn encfunc_correct_key_unlocks_through_the_bound_non_root_contract() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let art = pipeline::virtualize_with(
        &encfunc_src(),
        305419896,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
    )
    .expect("build succeeds");
    assert!(!art.contains(KEY), "the compile key must never ship");

    let good = g_prelude(&format!("BASILISK_RUNTIME_KEY = \"{KEY}\""));
    let out = run(&luau, &art, &good);

    assert!(
        out.contains("encfunc-sealed-secret"),
        "correct key must unlock the sealed body: {out}"
    );
    assert!(
        out.contains("238"),
        "the sealed body's computed value must be returned: {out}"
    );
    assert!(
        out.contains("tail"),
        "the value after the nil gap survives: {out}"
    );
    assert!(
        out.contains("nil"),
        "the nil gap itself is preserved: {out}"
    );
    assert!(
        out.contains("\t4\t"),
        "select('#') still reports 4 returns: {out}"
    );

    assert!(
        out.trim_end().ends_with("238"),
        "the nested child proto also executes: {out}"
    );

    assert_eq!(
        out,
        run(&luau, &art, &good),
        "same artifact + key -> identical output"
    );
}

#[test]
fn encfunc_is_deterministic_for_a_fixed_seed_and_distinct_across_seeds() {
    let (a, _) = build(&encfunc_src(), cfg(0x_C0DE_2222));
    let (b, _) = build(&encfunc_src(), cfg(0x_C0DE_2222));
    assert_eq!(a, b, "fixed seed -> byte-identical artifact");
    let (c, _) = build(&encfunc_src(), cfg(0x_C0DE_3333));
    assert_ne!(a, c, "different seeds must remain structurally distinct");
}

#[test]
fn encfunc_still_fails_closed_on_a_wrong_runtime_key() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let (art, _) = build(&encfunc_src(), cfg(0x_C0DE_4444));

    let wrong = g_prelude(&format!("BASILISK_RUNTIME_KEY = \"{}\"", "0".repeat(64)));
    let out = run(&luau, &art, &wrong);
    assert!(
        !out.contains("encfunc-sealed-secret"),
        "a wrong runtime key must never reveal the sealed constant: {out}"
    );

    let missing = run(&luau, &art, &g_prelude(""));
    assert!(
        !missing.contains("encfunc-sealed-secret"),
        "a missing runtime key must never reveal the sealed constant: {missing}"
    );
}

const NATIVE_SRC: &str = r##"
local nativeLeaf = BASIL_NO_VIRTUALIZE(function(t, want)
	for _, x in pairs(t) do
		if x == want then return true end
	end
	return false
end)
local function virtualized(list, needle)
	local LABEL = "virtualized-constant"
	local hit = nativeLeaf(list, needle)
	if hit then return LABEL, nil, string.upper(needle) end
	return "miss", nil, string.upper(needle)
end
local a, b, c = virtualized({ "alpha", "beta" }, "beta")
local d = virtualized({ "alpha" }, "gamma")
print(a, b, c, d, select("#", virtualized({ "alpha" }, "gamma")))
"##;

#[test]
fn native_escape_semantics_are_unchanged_under_the_bound_key_contract() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let (art, stats) = build(NATIVE_SRC, cfg(0x_BEEF_1111));
    assert_eq!(
        stats.natives, 1,
        "exactly the one marked leaf is native: {stats:?}"
    );

    let out = run(&luau, &art, "");
    assert!(
        out.contains("virtualized-constant"),
        "the virtualized caller's encrypted constant must still decrypt: {out}"
    );
    assert!(
        out.contains("BETA"),
        "native -> library behavior crossing must work: {out}"
    );
    assert!(out.contains("miss"), "the not-found path runs too: {out}");
    assert!(
        out.contains("\t3"),
        "select('#') sees 3 returns incl. the nil gap: {out}"
    );

    let again = run(&luau, &art, "");
    assert_eq!(out, again, "native escape output stays deterministic");
}

#[test]
fn the_native_body_is_plaintext_and_carries_no_digest_or_key_metadata() {
    let (art, stats) = build(NATIVE_SRC, cfg(0x_BEEF_2222));
    assert_eq!(stats.natives, 1);

    assert!(
        art.contains("pairs("),
        "the marked leaf ships as plaintext Luau, which is the documented native-escape tradeoff"
    );

    for leaked in ["BASIL_NO_VIRTUALIZE", "virtualized-constant"] {
        assert!(
            !art.contains(leaked),
            "`{leaked}` must not appear in the artifact"
        );
    }

    let (again, _) = build(NATIVE_SRC, cfg(0x_BEEF_2222));
    assert_eq!(
        art, again,
        "native escape build is deterministic for a fixed seed"
    );
}

#[test]
fn valid_unmodified_non_root_code_executes_normally() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let src = "\
local SECRET = \"plain-path-secret\"
local function inner(x)
\tif x > 3 then return x * 7, SECRET, nil, \"tail\" end
\treturn x + 1
end
local function outer(n)
\tlocal acc = 0
\tfor i = 1, n do acc = acc + (inner(i) or 0) end
\tlocal a, b, c, d = inner(9)
\treturn acc, a, b, c, d
end
print(outer(3))
";
    let (art, _) = build(src, cfg(0x_1234_5678));
    let out = run(&luau, &art, "");
    assert!(
        out.contains("63") && out.contains("plain-path-secret") && out.contains("tail"),
        "unmodified code must execute normally under the bound key contract: {out}"
    );
}

#[test]
fn encoder_paging_contract_matches_the_vm_paging_branch() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let enc = std::fs::read_to_string(root.join("crates/bytecode/src/encoder.rs")).unwrap();
    let vg = std::fs::read_to_string(root.join("crates/vmgen/src/lib.rs")).unwrap();

    assert!(
        !enc.contains("if this_pid == 0 {\n        wire_dg"),
        "the key contract must not infer paging from pid"
    );
    assert_eq!(
        enc.matches("RootPaging::Paged").count(),
        2,
        "paged-root keying in the encoder: the keying match arm and the vm-trap chain gate (the paging DECISION is centralized in format.rs ProtoEncodingMode)"
    );
    assert!(
        enc.contains("RootPaging::Unpaged => crypt::combined_code_digest("),
        "the unpaged arm must bind the semantic code digest"
    );
    let fmt = std::fs::read_to_string(root.join("crates/bytecode/src/format.rs")).unwrap();
    assert!(
        fmt.contains("ProtoEncodingMode::PagedRoot { .. } => RootPaging::Paged"),
        "single source: only the PagedRoot encoding mode maps to paged; every other mode is unpaged"
    );
    assert!(
        enc.contains("ProtoEncodingMode::PagedRoot {")
            && enc.contains("activation_ticket: crypt::activation_root("),
        "the main-payload root is serialized via the PagedRoot encoding mode"
    );
    assert!(
        enc.contains("ProtoEncodingMode::SealedInner"),
        "ENCFUNC sealed roots are serialized via the SealedInner (unpaged) encoding mode"
    );
    assert!(
        vg.contains("proto[16] = nil"),
        "ENCFUNC must still clear proto[16], i.e. sealed roots execute unpaged"
    );
    assert_eq!(
        vg.matches(
            "cdg = bxor(kdg, lrotate(proto[14], {r}), lrotate(genkey[5], band(proto[5], 31)))"
        )
        .count(),
        3,
        "all three seed-varied UNPAGED setup shapes use the per-build+proto keyed combined digest"
    );
    assert!(
        vg.contains("cdg = bxor(proto[14], lrotate(genkey[5], band(proto[5], 31)))"),
        "the PAGED setup key is no longer the bare wire digest (per-proto genkey term)"
    );
    assert!(
        !vg.contains("lrotate(proto[14], 16))"),
        "the release-wide rot-16 child-commitment formula must be gone"
    );
}
