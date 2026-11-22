use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

const ENCFUNC_KEY: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn require_luau() {
    if let Err(e) = std::process::Command::new("luau").arg("--help").output() {
        panic!("the `luau` interpreter is required for these regressions and was not found ({e})");
    }
}

fn cfg(seed: u64, optimization: u8) -> Config {
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
        optimization,
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

fn try_build(src: &str, cfg: Config) -> Result<String, String> {
    let i = tmp("rm_in");
    let o = tmp("rm_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    let r = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).map_err(|e| e.to_string()))
        .unwrap()
        .join()
        .unwrap();
    let out = r.map(|_| std::fs::read_to_string(&o).unwrap());
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn run(artifact: &str) -> String {
    let p = tmp("rm_run");
    std::fs::write(&p, artifact).unwrap();
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

#[test]
fn basil_encstr_is_reintroduced_as_a_sealed_value() {
    let art = try_build(
        "local v = BASIL_ENCSTR(\"reintro-encstr-marker\")\nprint(v)\n",
        cfg(7, 1),
    )
    .expect("BASIL_ENCSTR builds again as a sealed value");
    assert!(
        !art.contains("reintro-encstr-marker"),
        "the sealed string must not ship in plaintext"
    );
    if std::process::Command::new("luau")
        .arg("--help")
        .output()
        .is_ok()
    {
        assert_eq!(
            run(&art).trim(),
            "reintro-encstr-marker",
            "and materializes at runtime"
        );
    }
}

#[test]
fn basil_encnum_is_reintroduced_as_a_sealed_value() {
    let art = try_build("local n = BASIL_ENCNUM(1230077)\nprint(n)\n", cfg(7, 1))
        .expect("BASIL_ENCNUM builds again as a sealed value");
    assert!(
        !art.contains("1230077"),
        "the sealed number must not ship in plaintext"
    );
    if std::process::Command::new("luau")
        .arg("--help")
        .output()
        .is_ok()
    {
        assert_eq!(run(&art).trim(), "1230077", "and materializes at runtime");
    }
}

#[test]
fn ordinary_literals_keep_the_default_constant_protection() {
    require_luau();
    let src = "local v = \"sensitive-removal-marker\"\nlocal n = 123456\nprint(v, n)\n";
    let art = try_build(src, cfg(7, 1)).expect("ordinary literals build");
    assert!(
        !art.contains("sensitive-removal-marker"),
        "string constant must not ship in plaintext"
    );
    assert!(
        !art.contains("123456"),
        "number constant must not ship in plaintext"
    );
    assert_eq!(
        run(&art).trim(),
        "sensitive-removal-marker\t123456",
        "and must still round-trip"
    );
}

#[test]
fn sensitive_audit_still_detects_secret_looking_ordinary_literals() {
    let leak = "deadbeefcafe0001deadbeefcafe0002deadbeefcafe0003deadbeefcafe0004";
    let src = format!("local note = \"{leak}\"\nlocal pub = \"hello world\"\nprint(note, pub)\n");
    let report = pipeline::sensitive_audit(&src).expect("audit runs");
    assert!(
        report.contains("secret-looking literal"),
        "an ordinary secret-looking literal must still be reported: {report}"
    );
    assert!(report.contains("Tier 1"), "it belongs to Tier 1: {report}");
    assert!(
        !report.contains("BASIL_ENCSTR") && !report.contains("BASIL_ENCNUM"),
        "the removed macros must not appear in the tier headings any more: {report}"
    );
}

#[test]
fn roundtrip_preserves_source_text() {
    let src = "local v = BASIL_NONEXISTENT_MACRO(\"x\")\nprint(v)\n";
    let out = pipeline::roundtrip(src).expect("roundtrip re-emits source");
    assert!(
        out.contains("BASIL_NONEXISTENT_MACRO"),
        "roundtrip deliberately skips macro expansion AND macro validation, so an unknown \
         BASIL_ name survives verbatim rather than being diagnosed: {out}"
    );
    let e = try_build(src, cfg(7, 1)).expect_err("the virtualizing path must still reject it");
    assert!(
        e.contains("not a recognized macro"),
        "virtualize rejects what roundtrip passes: {e}"
    );
}

#[test]
fn a_plain_concatenation_of_sub_32_hex_pieces_folds_and_is_rejected_as_key_material() {
    let src = format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(f) return f end end\n\
         local auth = \"e68646c9f0351b3fa07127\" .. \"b2cbc2f7f301a3f8e45e8c\" .. \"f33a3381c7933a9f576a\"\n\
         local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", auth)\n\
         print(f)\n"
    );

    let folded = try_build(&src, cfg(7, 1)).expect_err("at optimization >= 1 the pieces fold");
    assert!(
        folded.contains("literal key material"),
        "the folded 64-hex value must be caught by the runtime-key taint gate, got: {folded}"
    );

    let unfolded =
        try_build(&src, cfg(7, 0)).expect_err("optimization 0 still refuses a literal key");
    assert!(
        unfolded.contains("literal or literal-derived"),
        "without folding the same expression is still refused, by the literal-derived rule: {unfolded}"
    );
}

#[test]
fn folding_is_what_exposes_the_key_material_not_the_macro_removal() {
    let single = format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(f) return f end end\n\
         local auth = \"e68646c9f0351b3fa07127b2cbc2f7f301a3f8e45e8cf33a3381c7933a9f576a\"\n\
         local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", auth)\n\
         print(f)\n"
    );
    let e = try_build(&single, cfg(7, 0))
        .expect_err("a single 64-hex literal is key material at any level");
    assert!(
        e.contains("literal key material") || e.contains("literal or literal-derived"),
        "the gate is unchanged for an unsplit literal: {e}"
    );
}

#[test]
fn a_non_key_shaped_test_credential_is_accepted_as_an_http_header_value() {
    let src = format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(f) return f end end\n\
         local auth = \"basilisk-test-worker-auth-v1\"\n\
         local function fetchKey()\n\
         \tlocal r = _G.httpFetch(\"https://example.invalid/key\", {{ [\"x-basil-test-auth\"] = auth }})\n\
         \treturn r.key\n\
         end\n\
         local rk = fetchKey()\n\
         local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", rk)\n\
         print(f)\n"
    );
    assert!(
        try_build(&src, cfg(7, 1)).is_ok(),
        "a credential that is not compile-key shaped must not trip the runtime-key gate"
    );
}

#[test]
fn first_party_sources_build() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/leak_fixtures/password_gui_encfunc_worker_fixture.luau");
    let src = std::fs::read_to_string(&fixture).expect("fixture present");
    assert!(
        !src.contains("BASIL_ENCSTR") && !src.contains("BASIL_ENCNUM"),
        "the migrated fixture must not reference the removed macros"
    );

    let at_default = try_build(&src, cfg(7, 1)).expect("fixture builds at the default level");
    let at_zero = try_build(&src, cfg(7, 0)).expect("fixture builds with the optimizer off");
    assert!(!at_default.is_empty() && !at_zero.is_empty());
    assert!(
        !at_default.contains("bananamonkey"),
        "the migrated fixture must keep its leak-scan expectations"
    );
}

#[test]
fn call_shaped_node_blocks_folding() {
    let plain = format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(f) return f end end\n\
         local auth = \"e68646c9f0351b3fa07127\" .. \"b2cbc2f7f301a3f8e45e8c\" .. \"f33a3381c7933a9f576a\"\n\
         local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", auth)\n\
         print(f)\n"
    );
    let wrapped = format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(f) return f end end\n\
         local function id(s) return s end\n\
         local auth = id(\"e68646c9f0351b3fa07127\") .. id(\"b2cbc2f7f301a3f8e45e8c\") .. id(\"f33a3381c7933a9f576a\")\n\
         local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", auth)\n\
         print(f)\n"
    );

    let folded =
        try_build(&plain, cfg(7, 1)).expect_err("plain literals fold into one 64-hex value");
    assert!(
        folded.contains("literal key material"),
        "folded form is caught: {folded}"
    );

    assert!(
        try_build(&wrapped, cfg(7, 1)).is_ok(),
        "with a call-shaped operand the pieces never fold, the key-material rule never sees a \
         64-hex literal, and the build is accepted. This is exactly the accidental barrier the \
         removed BASIL_ENCSTR wrappers provided. Recorded so the mechanism is understood and can \
         be spotted again -- NOT endorsed, and never to be reintroduced deliberately."
    );
}

#[test]
fn dropping_an_unused_third_return_value_is_behaviour_neutral() {
    require_luau();
    let three = "\
local function f()
\tlocal r = { tag = \"diag\" }
\treturn \"data\", nil, r
end
local a, b = f()
print(tostring(a), tostring(b), select(\"#\", f()))
";
    let two = "\
local function f()
\tlocal r = { tag = \"diag\" }
\tlocal _ = r
\treturn \"data\", nil
end
local a, b = f()
print(tostring(a), tostring(b), select(\"#\", f()))
";
    let a3 = run(&try_build(three, cfg(7, 1)).expect("builds"));
    let a2 = run(&try_build(two, cfg(7, 1)).expect("builds"));
    assert!(
        a3.starts_with("data\tnil\t3"),
        "the 3-value form reports arity 3: {a3}"
    );
    assert!(
        a2.starts_with("data\tnil\t2"),
        "the 2-value form reports arity 2: {a2}"
    );
    assert_eq!(
        a3.split('\t').take(2).collect::<Vec<_>>(),
        a2.split('\t').take(2).collect::<Vec<_>>(),
        "a caller that consumes only two values receives identical values either way"
    );
}
