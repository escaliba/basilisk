use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn require_luau() {
    for t in ["luau", "luau-compile"] {
        if Command::new(t).arg("--help").output().is_err() {
            panic!("`{t}` is required for decoy-removal tests");
        }
    }
}

fn cfg(seed: u64, heavy: SurfaceVolume, minify: bool, profile: TargetProfile) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: true,
        junk: false,
        fuse: true,
        minify,
        compress: false,
        anti_envlog: false,
        hard_dispatch: false,
        surface: false,
        heavy,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: false,
        strip_source_names: true,
        poly_stream: PolyStream::Off,
        optimization: 1,
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

fn build(src: &str, c: Config) -> String {
    let i = tmp("dr_in");
    let o = tmp("dr_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&a, &b, &c).expect("build succeeds"))
        .unwrap()
        .join()
        .unwrap();
    let out = std::fs::read_to_string(&o).unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn run(art: &str) -> String {
    let p = tmp("dr_run");
    std::fs::write(&p, art).unwrap();
    let o = Command::new("luau").arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
    .trim()
    .to_string()
}

fn compiles(art: &str) -> bool {
    let p = tmp("dr_cc");
    std::fs::write(&p, art).unwrap();
    let st = Command::new("luau-compile")
        .arg("--binary")
        .arg(&p)
        .output()
        .expect("luau-compile");
    let _ = std::fs::remove_file(&p);
    st.status.success()
}

fn alphabet_rebuilds(art: &str) -> usize {
    art.matches("= 33, 126 do").count() + art.matches("=33,126 do").count()
}

const SMALL: &str = "local function add(a, b) return a + b end\nprint(add(2, 3))\n";
const MEDIUM: &str = "local M = {}\nfunction M.f(x) if x > 2 then return x * 2 end return x end\nlocal t = { a = 1, b = \"two\" }\nlocal s = 0\nfor i = 1, 8 do s = s + M.f(i) end\nprint(s, t.a, t.b)\n";
const CFLOW: &str = "local function f(n)\n\tlocal r, i = 0, 1\n\twhile i <= n do\n\t\tif i % 3 == 0 then r = r + i elseif i % 3 == 1 then r = r - i else repeat r = r + 1 until r % 2 == 0 end\n\t\ti = i + 1\n\tend\n\treturn r\nend\nprint(f(30), f(7))\n";

const HEAVY: [SurfaceVolume; 3] = [
    SurfaceVolume::Small,
    SurfaceVolume::Medium,
    SurfaceVolume::Large,
];

#[test]
fn every_heavy_budget_emits_exactly_one_alphabet_rebuild() {
    for h in HEAVY {
        for seed in [1u64, 42, 1337] {
            for src in [SMALL, MEDIUM, CFLOW] {
                let a = build(src, cfg(seed, h, true, TargetProfile::CliTest));
                assert_eq!(
                    alphabet_rebuilds(&a),
                    1,
                    "heavy {h:?} seed {seed}: exactly one real alphabet rebuild; decoy packers were removed"
                );
            }
        }
    }
}

#[test]
fn non_heavy_builds_also_have_exactly_one_alphabet_rebuild() {
    for seed in [1u64, 42, 1337] {
        for minify in [true, false] {
            let a = build(
                MEDIUM,
                cfg(seed, SurfaceVolume::Off, minify, TargetProfile::CliTest),
            );
            assert_eq!(alphabet_rebuilds(&a), 1, "seed {seed} minify={minify}");
        }
    }
}

#[test]
fn heavy_output_still_differs_from_default_output() {
    let d = build(
        MEDIUM,
        cfg(42, SurfaceVolume::Off, true, TargetProfile::CliTest),
    );
    for h in HEAVY {
        let a = build(MEDIUM, cfg(42, h, true, TargetProfile::CliTest));
        assert_ne!(
            a, d,
            "heavy {h:?} must still change the artifact after decoy removal"
        );
        assert!(
            a.len() > d.len(),
            "heavy {h:?} must still add surface volume"
        );
    }
}

#[test]
fn heavy_artifacts_compile_and_behave_identically_to_default() {
    require_luau();
    for (src, name) in [(SMALL, "small"), (MEDIUM, "medium"), (CFLOW, "cflow")] {
        let expect = run(&build(
            src,
            cfg(42, SurfaceVolume::Off, true, TargetProfile::CliTest),
        ));
        for h in HEAVY {
            for minify in [true, false] {
                let a = build(src, cfg(42, h, minify, TargetProfile::CliTest));
                assert!(
                    compiles(&a),
                    "{name} heavy {h:?} minify={minify}: must compile"
                );
                assert_eq!(
                    run(&a),
                    expect,
                    "{name} heavy {h:?} minify={minify}: behaviour"
                );
            }
        }
    }
}

#[test]
fn the_executor_target_profile_builds_and_compiles_under_heavy() {
    require_luau();
    for h in HEAVY {
        let a = build(MEDIUM, cfg(42, h, true, TargetProfile::Executor));
        assert!(compiles(&a), "executor profile heavy {h:?} must compile");
        assert_eq!(alphabet_rebuilds(&a), 1, "executor profile heavy {h:?}");
    }
}

#[test]
fn the_serialized_payload_is_unaffected_by_heavy_budget_choice() {
    let mut prev: Option<(usize, usize)> = None;
    for h in [SurfaceVolume::Medium, SurfaceVolume::Large] {
        let i = tmp("dr_m_in");
        let o = tmp("dr_m_out");
        std::fs::write(&i, MEDIUM).unwrap();
        let c = cfg(42, h, true, TargetProfile::CliTest);
        let (a, b) = (i.clone(), o.clone());
        let st = std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(move || {
                let mut got: Option<pipeline::BuildStats> = None;
                pipeline::run_capturing_stats(&a, &b, &c, None, &mut got).expect("build");
                got.expect("stats")
            })
            .unwrap()
            .join()
            .unwrap();
        let _ = std::fs::remove_file(&i);
        let _ = std::fs::remove_file(&o);
        let cur = (st.serialized_total_bytes, st.instructions);
        if let Some(p) = prev {
            assert_eq!(
                p, cur,
                "the heavy budget must not change the real serialized payload"
            );
        }
        prev = Some(cur);
    }
}

#[test]
fn a_fixed_seed_stays_deterministic_and_seeds_still_vary_heavy_output() {
    for h in HEAVY {
        let a = build(MEDIUM, cfg(42, h, true, TargetProfile::CliTest));
        let b = build(MEDIUM, cfg(42, h, true, TargetProfile::CliTest));
        assert_eq!(a, b, "heavy {h:?}: same seed must reproduce byte-for-byte");
        let c = build(MEDIUM, cfg(1337, h, true, TargetProfile::CliTest));
        assert_ne!(a, c, "heavy {h:?}: different seeds must still vary output");
    }
}

#[test]
fn no_short_random_blob_declaration_survives_under_heavy() {
    for h in HEAVY {
        for seed in [1u64, 42, 1337] {
            let a = build(MEDIUM, cfg(seed, h, false, TargetProfile::CliTest));
            let lens: Vec<usize> = a
                .match_indices("[==[")
                .map(|(i, _)| a[i + 4..].find("]==]").unwrap_or(0))
                .collect();
            assert!(
                lens.iter().all(|&l| l >= 64),
                "heavy {h:?} seed {seed}: no tiny leftover-decoy blob may remain: {lens:?}"
            );
        }
    }
}

#[test]
fn unrelated_decoy_mechanisms_remain_present_and_untouched() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../passes/src/pad.rs"))
        .expect("passes/src/pad.rs");
    assert!(
        src.contains("decoy"),
        "pad_decoys is a different mechanism and must survive"
    );
    let frag = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../passes/src/fragment.rs"
    ))
    .expect("passes/src/fragment.rs");
    assert!(
        frag.contains("decoy"),
        "fragment decoys are a different mechanism and must survive"
    );
    let route = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vmgen/src/route.rs"
    ))
    .expect("vmgen/src/route.rs");
    assert!(
        route.contains("decoy_count"),
        "route decoys (the extra unmapped arms, named decoy_count) are a separate mechanism and must survive"
    );
}

#[test]
fn the_packer_no_longer_emits_a_discarded_reference_table() {
    for h in HEAVY {
        let a = build(MEDIUM, cfg(42, h, false, TargetProfile::CliTest));
        let decoders = a.matches("local function ").count();
        assert!(
            decoders >= 1,
            "heavy {h:?}: the real decoder must still exist ({decoders} found)"
        );
        assert_eq!(
            alphabet_rebuilds(&a),
            1,
            "heavy {h:?}: one alphabet rebuild implies one packer"
        );
    }
}
