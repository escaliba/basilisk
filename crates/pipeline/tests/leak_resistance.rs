use std::path::{Path, PathBuf};
use std::process::Command;

use pipeline::{leakscan, Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

const SEED: u64 = 0x_1EA4_5EED;

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/leak_fixtures")
        .join(name)
}

fn unique_tmp(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

struct Run {
    stdout: String,
    code: Option<i32>,
}

fn run_luau(bin: &str, path: &Path) -> Run {
    let output = Command::new(bin)
        .arg(path)
        .output()
        .expect("failed to spawn luau");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        code: output.status.code(),
    }
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    match Command::new("luau").arg("--help").output() {
        Ok(_) => Some("luau".to_string()),
        Err(_) => None,
    }
}

fn executor_config(compress: bool) -> Config {
    Config {
        seed: SEED,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: true,
        junk: false,
        fuse: true,
        minify: true,
        compress,
        anti_envlog: false,
        hard_dispatch: false,
        surface: true,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile: TargetProfile::Executor,
        loadstring_canary: true,
        lph_collapse: true,
        line_info: false,
        strip_source_names: true,
        poly_stream: PolyStream::Aggressive,
        optimization: 2,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: Default::default(),
        hot_callback_policy: Default::default(),
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

fn clitest_config(strip: bool) -> Config {
    Config {
        seed: SEED,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: true,
        junk: true,
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
        line_info: true,
        strip_source_names: strip,
        poly_stream: PolyStream::Off,
        optimization: 1,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: Default::default(),
        hot_callback_policy: Default::default(),
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

fn parses(artifact: &str) -> bool {
    let src = artifact.to_string();
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(move || full_moon::parse(&src).is_ok())
        .expect("spawn parse thread")
        .join()
        .expect("parse thread panicked")
}

fn build(name: &str, config: &Config) -> String {
    let input = fixture_path(name);
    let output = unique_tmp("leakscan_out");
    pipeline::run(&input, &output, config).unwrap_or_else(|e| panic!("building {name}: {e:#}"));
    let artifact = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    artifact
}

const GENERAL: &[(&str, &str)] = &[
    ("BASIL_", "reserved-prefix"),
    ("BASIL_ENCFUNC_SEED:v1", "encfunc-marker"),
    ("line_map", "debug-section"),
    ("traceback_remap", "debug-section"),
    ("decrypted_constants", "vm-internal"),
    ("decoded_constants", "vm-internal"),
    ("inst.op", "vm-internal"),
    ("inst.a", "vm-internal"),
    ("inst.b", "vm-internal"),
    ("inst.c", "vm-internal"),
    ("REG_A", "vm-internal"),
    ("REG_B", "vm-internal"),
    ("REG_C", "vm-internal"),
    ("Insts", "vm-internal"),
    (".op", "vm-internal"),
    (".ops", "vm-internal"),
    ("root_closure", "vm-internal"),
];

const PASSWORD: &[(&str, &str)] = &[
    ("bananamonkey", "password"),
    ("monkeybanana6", "password"),
    ("/unlock", "worker-url"),
    ("basil-key-worker", "worker-url"),
    ("workers.dev", "worker-url"),
    ("example-unlock-test.invalid", "worker-url"),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "encfunc-compile-key",
    ),
    ("access granted", "success-string"),
    ("wrong password", "failure-string"),
    ("password gui loaded", "log-string"),
    ("Enter test password", "gui-string"),
    ("Submit", "gui-string"),
    ("Password", "gui-string"),
    ("PASSWORD_SHA256", "identifier"),
    ("UNLOCK_KEY_HEX", "identifier"),
    ("BASIL_ENCFUNC", "macro-name"),
    ("BASIL_ENCSTR", "macro-name"),
    ("BASIL_ENCNUM", "macro-name"),
    ("password_gui_encfunc_worker_fixture", "source-filename"),
];

const WHITELIST: &[(&str, &str)] = &[
    ("validateWhitelistToken", "identifier"),
    ("LicenseGateway", "identifier"),
    ("internalAuthState", "identifier"),
    ("decryptSessionTicket", "identifier"),
    ("whitelistDecision", "identifier"),
    ("secretUserId", "identifier"),
    ("sessionTicket", "identifier"),
    ("remoteName", "identifier"),
    ("allowedUser", "identifier"),
    ("identifier_leak_test", "source-filename"),
    ("whitelist_identifier_fixture", "source-filename"),
];

const NATIVE: &[(&str, &str)] = &[
    ("secretArgName", "identifier"),
    ("hiddenLocalName", "identifier"),
    ("nativeWhitelistDecision", "identifier"),
    ("native_no_virtualize_identifier_fixture", "source-filename"),
];

fn assert_no_leaks(name: &str, artifact: &str, lists: &[&[(&str, &str)]]) {
    let input = fixture_path(name);
    let path_str = input.to_string_lossy().into_owned();
    let mut forbidden: Vec<(&str, &str)> = lists.iter().flat_map(|l| l.iter().copied()).collect();
    forbidden.push((path_str.as_str(), "input-path"));

    let findings = leakscan::scan(artifact, &forbidden);
    let hard: Vec<leakscan::Finding> = leakscan::hard(&findings).into_iter().cloned().collect();
    let advisory: Vec<leakscan::Finding> =
        leakscan::advisory(&findings).into_iter().cloned().collect();

    if !advisory.is_empty() {
        println!(
            "{name}: advisory tokens (<{} chars, base85 chance, not a failure):",
            leakscan::HARD_FAIL_MIN_LEN
        );
        println!("{}", leakscan::report(&path_str, &advisory));
    }
    assert!(
        hard.is_empty(),
        "{name} executor release artifact leaked sensitive plaintext:\n{}",
        leakscan::report(&path_str, &hard)
    );
}

#[test]
fn password_gui_fixture_executor_release_parses_and_leaks_nothing() {
    let artifact = build(
        "password_gui_encfunc_worker_fixture.luau",
        &executor_config(true),
    );
    assert!(
        artifact.len() > 10_000,
        "artifact suspiciously small: {} bytes",
        artifact.len()
    );
    assert!(parses(&artifact), "executor artifact must be valid Luau");
    assert_no_leaks(
        "password_gui_encfunc_worker_fixture.luau",
        &artifact,
        &[GENERAL, PASSWORD],
    );
}

#[test]
fn whitelist_fixture_executor_release_leaks_no_identifiers() {
    let artifact = build("whitelist_identifier_fixture.luau", &executor_config(false));
    assert!(parses(&artifact));
    assert_no_leaks(
        "whitelist_identifier_fixture.luau",
        &artifact,
        &[GENERAL, WHITELIST],
    );
}

#[test]
fn native_fixture_executor_release_strips_native_identifiers() {
    let artifact = build(
        "native_no_virtualize_identifier_fixture.luau",
        &executor_config(false),
    );
    assert!(parses(&artifact));
    assert_no_leaks(
        "native_no_virtualize_identifier_fixture.luau",
        &artifact,
        &[GENERAL, NATIVE],
    );
}

#[test]
fn native_fixture_strip_off_leaks_identifiers_strip_on_does_not() {
    let name = "native_no_virtualize_identifier_fixture.luau";
    let off = build(name, &clitest_config(false));
    let on = build(name, &clitest_config(true));
    for (tok, _) in NATIVE.iter().take(3) {
        assert!(
            off.contains(tok),
            "strip off must retain native identifier `{tok}` (guard would be vacuous otherwise)"
        );
        assert!(
            !on.contains(tok),
            "strip on must remove native identifier `{tok}`"
        );
    }
}

fn raw_equals_virt(name: &str) {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping raw==virt for {name} (set LUAU_BIN)");
        return;
    };
    let virt = build(name, &clitest_config(true));
    let virt_path = unique_tmp("leak_virt");
    std::fs::write(&virt_path, &virt).unwrap();
    let raw = run_luau(&luau, &fixture_path(name));
    let got = run_luau(&luau, &virt_path);
    let _ = std::fs::remove_file(&virt_path);
    assert_eq!(raw.stdout, got.stdout, "{name}: stdout differs raw vs virt");
    assert_eq!(raw.code, got.code, "{name}: exit code differs raw vs virt");
}

#[test]
fn whitelist_fixture_raw_equals_virt() {
    raw_equals_virt("whitelist_identifier_fixture.luau");
}

#[test]
fn native_fixture_raw_equals_virt() {
    raw_equals_virt("native_no_virtualize_identifier_fixture.luau");
}
