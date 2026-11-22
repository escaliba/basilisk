use std::path::{Path, PathBuf};
use std::process::Command;

use pipeline::{Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

const SEED: u64 = 0x_9017_57EE;

const KNOWN_DIVERGENCES: &[&str] = &["setfenv.luau"];

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

fn run_luau(bin: &str, path: &Path) -> (String, Option<i32>) {
    let out = Command::new(bin).arg(path).output().expect("spawn luau");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code(),
    )
}

fn cfg(seed: u64, poly: PolyStream) -> Config {
    Config {
        seed,
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
        strip_source_names: false,
        poly_stream: poly,
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

fn build(input: &Path, poly: PolyStream) -> String {
    let output = unique_tmp("poly_out");
    pipeline::run(input, &output, &cfg(SEED, poly))
        .unwrap_or_else(|e| panic!("building {}: {e:#}", input.display()));
    let s = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    s
}

fn corpus_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading corpus dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "luau"))
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            !KNOWN_DIVERGENCES.contains(&name)
        })
        .collect();
    files.sort();
    files
}

fn poly_fixtures() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/poly_fixtures");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "luau"))
        .collect();
    files.sort();
    files
}

fn assert_raw_equals_virt(luau: &str, input: &Path, poly: PolyStream, label: &str) {
    let virt = build(input, poly);
    let virt_path = unique_tmp("poly_virt");
    std::fs::write(&virt_path, &virt).unwrap();
    let (raw_out, raw_code) = run_luau(luau, input);
    let (got_out, got_code) = run_luau(luau, &virt_path);
    let _ = std::fs::remove_file(&virt_path);
    assert_eq!(
        raw_out,
        got_out,
        "{label}: stdout differs for {}",
        input.display()
    );
    assert_eq!(
        raw_code,
        got_code,
        "{label}: exit code differs for {}",
        input.display()
    );
}

#[test]
fn full_corpus_raw_equals_virt_conservative() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping (set LUAU_BIN)");
        return;
    };
    for f in corpus_files() {
        assert_raw_equals_virt(&luau, &f, PolyStream::Conservative, "conservative");
    }
}

#[test]
fn full_corpus_raw_equals_virt_aggressive() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping (set LUAU_BIN)");
        return;
    };
    for f in corpus_files() {
        assert_raw_equals_virt(&luau, &f, PolyStream::Aggressive, "aggressive");
    }
}

#[test]
fn poly_fixtures_raw_equals_virt_all_modes() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping (set LUAU_BIN)");
        return;
    };
    for f in poly_fixtures() {
        for poly in [
            PolyStream::Off,
            PolyStream::Conservative,
            PolyStream::Aggressive,
        ] {
            assert_raw_equals_virt(&luau, &f, poly, "fixture");
        }
    }
}

#[test]
fn off_is_deterministic_and_enabled_adds_structure() {
    let input = &poly_fixtures()[0];
    let off_a = build(input, PolyStream::Off);
    let off_b = build(input, PolyStream::Off);
    assert_eq!(off_a, off_b, "off must be deterministic byte-for-byte");
    let cons = build(input, PolyStream::Conservative);
    let aggr = build(input, PolyStream::Aggressive);
    assert_ne!(
        off_a, cons,
        "conservative must add self-mutation structure over off"
    );
    assert_ne!(
        off_a, aggr,
        "aggressive must add self-mutation structure over off"
    );
    assert!(
        cons.len() > off_a.len(),
        "poly structure enlarges the artifact"
    );
}

#[test]
fn enabled_seed_variance_changes_the_artifact() {
    let input = &poly_fixtures()[0];
    let a = build_seed(input, 0x1111, PolyStream::Aggressive);
    let b = build_seed(input, 0x2222, PolyStream::Aggressive);
    assert_ne!(
        a, b,
        "different seed must yield a different self-mutation plan"
    );
}

fn wide_register_source() -> String {
    let n = 125u32;
    let mut src = String::from(
        "local function big(seed)\n  local function g(...) local t = {...} local s = 0 for i = 1, #t do s = s + t[i] end return s end\n",
    );
    for i in 1..=n {
        src.push_str(&format!("  local v{i} = (seed * {i} + {}) % 251\n", i * i));
    }
    let args: Vec<String> = (1..=n).map(|i| format!("v{i}")).collect();
    src.push_str(&format!(
        "  return g({}) % 1000000\nend\nprint(big(3), big(37), big(200))\n",
        args.join(", ")
    ));
    src
}

#[test]
fn wide_register_operands_skip_kepoch_and_stay_behaviorally_correct() {
    let input = unique_tmp("kepoch_wide_in");
    std::fs::write(&input, wide_register_source()).unwrap();

    let output = unique_tmp("kepoch_wide_out");
    let mut stats = None;
    pipeline::run_capturing_stats(
        &input,
        &output,
        &cfg(SEED, PolyStream::Aggressive),
        None,
        &mut stats,
    )
    .unwrap_or_else(|e| panic!("a wide-register function must virtualize, not panic: {e:#}"));
    let stats = stats.unwrap();
    assert!(
        stats.kepoch_wide_skips > 0,
        "fixture must actually exercise the out-of-domain skip (else the regression is vacuous — bump the local count); got {}",
        stats.kepoch_wide_skips
    );

    if let Some(luau) = find_luau() {
        let (raw_out, raw_code) = run_luau(&luau, &input);
        let (virt_out, virt_code) = run_luau(&luau, &output);
        assert_eq!(raw_out, virt_out, "wide-register function must behave identically after KEPOCH skips its out-of-domain operands");
        assert_eq!(
            raw_code, virt_code,
            "wide-register function exit code must match"
        );
    } else {
        println!("luau not found; verified the no-panic + skip-count path only (set LUAU_BIN for behavioral)");
    }
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

fn build_seed(input: &Path, seed: u64, poly: PolyStream) -> String {
    let output = unique_tmp("poly_seed_out");
    pipeline::run(input, &output, &cfg(seed, poly)).unwrap();
    let s = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    s
}
