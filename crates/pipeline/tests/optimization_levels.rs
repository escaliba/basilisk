use std::path::{Path, PathBuf};
use std::process::Command;

use pipeline::{Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

const SEED: u64 = 0x_0F71_1234;

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

fn cfg(level: u8) -> Config {
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
        profile: TargetProfile::CliTest,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: true,
        strip_source_names: false,
        poly_stream: PolyStream::Off,
        optimization: level,
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

fn build(input: &Path, level: u8) -> Vec<u8> {
    let output = unique_tmp("optlvl_out");
    pipeline::run(input, &output, &cfg(level))
        .unwrap_or_else(|e| panic!("building {} at L{level}: {e:#}", input.display()));
    let s = std::fs::read(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    s
}

fn files_in(subdir: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(subdir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
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

fn assert_raw_equals_virt(luau: &str, input: &Path, level: u8) {
    let virt = build(input, level);
    let virt_path = unique_tmp("optlvl_virt");
    std::fs::write(&virt_path, &virt).unwrap();
    let (raw_out, raw_code) = run_luau(luau, input);
    let (got_out, got_code) = run_luau(luau, &virt_path);
    let _ = std::fs::remove_file(&virt_path);
    assert_eq!(
        raw_out,
        got_out,
        "L{level}: stdout differs for {}",
        input.display()
    );
    assert_eq!(
        raw_code,
        got_code,
        "L{level}: exit code differs for {}",
        input.display()
    );
}

#[test]
fn full_corpus_raw_equals_virt_every_level() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping (set LUAU_BIN)");
        return;
    };
    for f in files_in("tests/corpus") {
        for level in [0u8, 1, 2, 3] {
            assert_raw_equals_virt(&luau, &f, level);
        }
    }
}

#[test]
fn fold_fixtures_raw_equals_virt_every_level() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping (set LUAU_BIN)");
        return;
    };
    for f in files_in("tests/opt_fixtures") {
        for level in [0u8, 1, 2, 3] {
            assert_raw_equals_virt(&luau, &f, level);
        }
    }
}

#[test]
fn folding_differentiates_level_0_and_1() {
    let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/opt_fixtures/opt_fold.luau");
    let l0 = build(&f, 0);
    let l1 = build(&f, 1);
    let l2 = build(&f, 2);
    let l3 = build(&f, 3);
    assert_ne!(
        l0, l1,
        "level 1 must fold literals that level 0 leaves alone"
    );
    assert_eq!(l1, l2, "true/false-literal branch pruning is subsumed by the always-on macros::fold_if, so level 2 adds nothing here");
    assert_eq!(l2, l3, "level 3 currently has no behavior beyond level 2");
}

#[test]
fn dead_branch_pruning_differentiates_level_1_and_2() {
    let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/opt_fixtures/opt_dead_branch.luau");
    let l0 = build(&f, 0);
    let l1 = build(&f, 1);
    let l2 = build(&f, 2);
    let l3 = build(&f, 3);
    assert_eq!(
        l0, l1,
        "nothing folds here: the conditions are already nil/number/string literals"
    );
    assert_ne!(
        l1, l2,
        "level 2 prunes nil/number/string-literal branches that level 1 keeps"
    );
    assert_eq!(l2, l3, "level 3 currently has no behavior beyond level 2");
}
