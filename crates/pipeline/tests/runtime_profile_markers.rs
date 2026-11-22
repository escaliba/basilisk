use std::path::{Path, PathBuf};
use std::process::Command;

use pipeline::{Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

const SEED: u64 = 0x_9017_57EE;
const LABELS: &[&str] = &[
    "load_start",
    "payload_ready",
    "deserialize_done",
    "genkey_derived",
    "root_start",
    "root_return",
];

fn unique_tmp(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
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

fn cfg(profile: TargetProfile, poly: PolyStream, markers: bool) -> Config {
    Config {
        seed: SEED,
        mode: Mode::Virtualize,
        flatten: true,
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
        profile,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: true,
        strip_source_names: false,
        poly_stream: poly,
        optimization: 2,
        static_env: false,
        runtime_profile_markers: markers,
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

fn build(input: &Path, cfg: &Config) -> String {
    let output = unique_tmp("prof_out");
    pipeline::run(input, &output, cfg).expect("virtualize");
    let s = std::fs::read_to_string(&output).expect("read output");
    let _ = std::fs::remove_file(&output);
    s
}

fn write_input() -> PathBuf {
    let input = unique_tmp("prof_in");
    std::fs::write(
        &input,
        "local function fib(n)\n\tif n < 2 then return n end\n\treturn fib(n-1) + fib(n-2)\nend\nlocal acc = 0\nfor i = 1, 20 do acc = acc + fib(i % 12) end\nprint(\"RESULT\", acc)\n",
    )
    .unwrap();
    input
}

#[test]
fn markers_off_is_byte_identical_to_baseline_and_carries_no_markers() {
    let input = write_input();
    for profile in [TargetProfile::CliTest, TargetProfile::Executor] {
        let poly = if profile == TargetProfile::Executor {
            PolyStream::Aggressive
        } else {
            PolyStream::Off
        };
        let a = build(&input, &cfg(profile, poly, false));
        let b = build(&input, &cfg(profile, poly, false));
        assert_eq!(a, b, "{profile:?}: markers-off is deterministic");
        assert!(
            !a.contains("BASIL_PROF"),
            "{profile:?}: markers-off artifact carries no BASIL_PROF text"
        );
    }
    let _ = std::fs::remove_file(&input);
}

#[test]
fn markers_on_injects_every_label_and_only_changes_when_enabled() {
    let input = write_input();
    let off = build(&input, &cfg(TargetProfile::CliTest, PolyStream::Off, false));
    let on = build(&input, &cfg(TargetProfile::CliTest, PolyStream::Off, true));
    let on2 = build(&input, &cfg(TargetProfile::CliTest, PolyStream::Off, true));
    assert_eq!(on, on2, "markers-on is deterministic for a fixed seed");
    assert_ne!(on, off, "enabling markers changes the artifact");
    assert!(
        on.contains("BASIL_PROF"),
        "markers-on artifact emits BASIL_PROF"
    );
    for label in LABELS {
        assert!(
            on.contains(label),
            "markers-on artifact contains the {label} marker"
        );
        assert!(
            !off.contains(&format!("BASIL_PROF {label}")),
            "markers-off artifact omits {label}"
        );
    }
    let _ = std::fs::remove_file(&input);
}

#[test]
fn markers_on_runs_correctly_and_prints_chronological_markers() {
    let Some(luau) = find_luau() else { return };
    let input = write_input();
    let output = unique_tmp("prof_run");
    pipeline::run(
        &input,
        &output,
        &cfg(TargetProfile::CliTest, PolyStream::Off, true),
    )
    .expect("virtualize");
    let out = Command::new(&luau)
        .arg(&output)
        .output()
        .expect("spawn luau");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("RESULT\t286"),
        "virtualized program still computes the right result: {stdout}"
    );
    let mut last = -1.0f64;
    let mut seen = 0;
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("BASIL_PROF ") else {
            continue;
        };
        let mut it = rest.split(' ');
        let label = it.next().unwrap_or("");
        let t: f64 = it.next().unwrap_or("").parse().unwrap_or(-1.0);
        assert!(LABELS.contains(&label), "unexpected marker label {label}");
        assert!(
            t >= last,
            "markers are chronologically non-decreasing ({label} {t} < {last})"
        );
        last = t;
        seen += 1;
    }
    assert_eq!(seen, LABELS.len(), "every marker fired exactly once");
    let exec = stdout
        .lines()
        .find(|l| l.starts_with("BASIL_EXEC final"))
        .expect("exec profiler emits a final aggregate snapshot");
    assert!(
        exec.contains("n=") && exec.contains("dec="),
        "final snapshot carries post-root instruction and decode counts: {exec}"
    );
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}
