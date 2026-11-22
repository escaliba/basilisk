use std::path::{Path, PathBuf};

use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};

fn cfg(profile: TargetProfile, poly: PolyStream, opt: u8, line_info: bool, junk: bool) -> Config {
    Config {
        seed: 0xABCD_1234_5678_9909,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: true,
        junk,
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
        line_info,
        strip_source_names: false,
        poly_stream: poly,
        optimization: opt,
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

fn big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn corpus_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading corpus dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .map(|x| x == "luau" || x == "lua")
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

fn matrix() -> Vec<Config> {
    vec![
        cfg(TargetProfile::CliTest, PolyStream::Off, 0, true, false),
        cfg(
            TargetProfile::Executor,
            PolyStream::Conservative,
            0,
            true,
            false,
        ),
        cfg(
            TargetProfile::Executor,
            PolyStream::Aggressive,
            3,
            false,
            true,
        ),
        cfg(
            TargetProfile::CliTest,
            PolyStream::Aggressive,
            0,
            false,
            false,
        ),
    ]
}

#[test]
fn corpus_streaming_digest_matches_reference_every_config() {
    big_stack(|| {
        let files = corpus_files();
        assert!(!files.is_empty(), "no corpus files found");
        let mut total = 0usize;
        for f in &files {
            let src = std::fs::read_to_string(f).unwrap();
            for c in matrix() {
                let n = pipeline::verify_streaming_digests(&src, &c).unwrap_or_else(|e| {
                    panic!(
                        "{}: profile {:?} poly {:?} opt {} line_info {}: {e}",
                        f.display(),
                        c.profile,
                        c.poly_stream,
                        c.optimization,
                        c.line_info
                    )
                });
                assert!(
                    n >= 1,
                    "{}: verified {n} protos (expected >=1)",
                    f.display()
                );
                total += n;
            }
        }
        println!(
            "streaming-digest: verified {total} protos across {} corpus files",
            files.len()
        );
        assert!(total > 0);
    });
}

#[test]
fn encfunc_streaming_digest_matches_reference() {
    big_stack(|| {
        let key = "0".repeat(64);
        let src = format!(
            "local add = BASIL_ENCFUNC(function(a, b) local t = a + b return t end, \"{key}\", getKey())\nlocal mul = BASIL_ENCFUNC(function(x) return x * x end, \"{key}\", getKey())\nprint(add(2, 3), mul(4))\n"
        );
        for c in matrix() {
            let n = pipeline::verify_streaming_digests(&src, &c).unwrap_or_else(|e| {
                panic!(
                    "encfunc profile {:?} poly {:?}: {e}",
                    c.profile, c.poly_stream
                )
            });
            assert!(n >= 3, "main + 2 ENCFUNC inners verified (got {n})");
        }
    });
}

#[test]
fn streaming_digest_is_deterministic() {
    big_stack(|| {
        let src = std::fs::read_to_string(&corpus_files()[0]).unwrap();
        let c = cfg(
            TargetProfile::Executor,
            PolyStream::Aggressive,
            0,
            false,
            false,
        );
        let a = pipeline::verify_streaming_digests(&src, &c).unwrap();
        let b = pipeline::verify_streaming_digests(&src, &c).unwrap();
        assert_eq!(a, b, "verified count is deterministic");
    });
}

fn real_world(name: &str) -> Option<String> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/bench-inputs/real-world")
        .join(name);
    std::fs::read_to_string(&p).ok()
}

#[test]
fn real_world_scripts_streaming_digest_matches_reference() {
    big_stack(|| {
        let scripts = [
            "fates_admin_main.lua",
            "rogue_ui.lua",
            "infinite_yield_source.lua",
        ];
        let mut ran = 0;
        for name in scripts {
            let Some(src) = real_world(name) else {
                println!("real-world {name} absent; skipping");
                continue;
            };
            for c in [
                cfg(TargetProfile::Executor, PolyStream::Off, 0, false, false),
                cfg(
                    TargetProfile::Executor,
                    PolyStream::Aggressive,
                    0,
                    false,
                    false,
                ),
            ] {
                let n = pipeline::verify_streaming_digests(&src, &c)
                    .unwrap_or_else(|e| panic!("{name} poly {:?}: {e}", c.poly_stream));
                assert!(n > 10, "{name}: real script has many protos (got {n})");
                println!(
                    "real-world {name} poly {:?}: verified {n} protos",
                    c.poly_stream
                );
            }
            ran += 1;
        }
        if ran == 0 {
            println!("no real-world scripts present; real-world coverage skipped");
        }
    });
}

#[test]
fn semgroup_stream_digest_consistency() {
    let src = "local y = math.floor(3.7)\nprint(y)\nprint(string.rep(\"ab\", 3))\n";
    let mut c = cfg(TargetProfile::CliTest, PolyStream::Off, 0, false, false);
    c.semgroup = true;
    let n =
        pipeline::verify_streaming_digests(src, &c).expect("semgroup stream digest must verify");
    assert!(n > 0);
}
