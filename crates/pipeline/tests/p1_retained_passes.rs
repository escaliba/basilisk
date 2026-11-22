use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    Config, FrameConstReuseMode, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn find_luau() -> Option<String> {
    match Command::new("luau").arg("--help").output() {
        Ok(_) => Some("luau".to_string()),
        Err(_) => None,
    }
}

fn run_luau(bin: &str, path: &Path) -> String {
    let out = Command::new(bin)
        .arg(path)
        .output()
        .expect("failed to spawn luau");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn p1_config(seed: u64) -> Config {
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
        surface: true,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile: TargetProfile::CliTest,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: false,
        strip_source_names: true,
        poly_stream: PolyStream::Aggressive,
        optimization: 2,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: FrameConstReuseMode::All,
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

fn tmp(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{prefix}_{}_{}.luau",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn zero_arg_method_calls_survive_the_p1_retained_pass_combination() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping behavioral check");
        return;
    };
    let source = corpus_dir().join("self_method_zero_arg.luau");
    let expected = run_luau(&luau, &source);
    assert!(expected.contains("x\ty"), "reference output: {expected}");

    for seed in [1u64, 2, 3, 7, 11, 23, 8_675_309] {
        let out = tmp("p1_retained");
        pipeline::run(&source, &out, &p1_config(seed)).unwrap();
        let got = run_luau(&luau, &out);
        assert_eq!(
            expected, got,
            "seed {seed} diverged under the P1 retained passes"
        );
        let _ = std::fs::remove_file(out);
    }
}

#[test]
fn whole_corpus_survives_the_p1_retained_pass_combination() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping behavioral check");
        return;
    };
    let mut files: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "luau"))
        .collect();
    files.sort();
    assert!(
        files.len() > 20,
        "corpus should not be empty: {}",
        files.len()
    );

    for file in files {
        if file.file_name().is_some_and(|n| n == "setfenv.luau") {
            continue;
        }
        let expected = run_luau(&luau, &file);
        let out = tmp("p1_corpus");
        pipeline::run(&file, &out, &p1_config(0xC0FFEE)).unwrap();
        let got = run_luau(&luau, &out);
        assert_eq!(
            expected,
            got,
            "{} diverged under the P1 retained passes",
            file.display()
        );
        let _ = std::fs::remove_file(out);
    }
}
