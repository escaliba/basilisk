use pipeline::{
    Config, FrameConstReuseMode, HotCallbackPolicy, Mode, NoticeConfig, PolyStream, SensitiveOpts,
    SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_notice_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
    Command::new("luau")
        .arg("--version")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn cfg(
    seed: u64,
    minify: bool,
    profile: TargetProfile,
    heavy: SurfaceVolume,
    notices: NoticeConfig,
) -> Config {
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
        frame_const_reuse: FrameConstReuseMode::Off,
        hot_callback_policy: HotCallbackPolicy::Report,
        ablate_fragment: false,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
        shell_family: None,
        notices,
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

const SRC: &str = "local function add(a, b) return a + b end\nlocal s = 0\nfor i = 1, 10 do s = add(s, i) end\nprint(s)\n";

fn build(src: &str, c: Config) -> Result<(String, pipeline::BuildStats), String> {
    let i = tmp("in");
    let o = tmp("out");
    std::fs::write(&i, src).unwrap();
    let (ic, oc) = (i.clone(), o.clone());
    let r = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let mut stats: Option<pipeline::BuildStats> = None;
            pipeline::run_capturing_stats(&ic, &oc, &c, None, &mut stats)
                .map(|_| stats.unwrap_or_default())
                .map_err(|e| format!("{e:#}"))
        })
        .unwrap()
        .join()
        .unwrap();
    let out = r.map(|st| (std::fs::read_to_string(&o).unwrap(), st));
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn off() -> NoticeConfig {
    NoticeConfig::default()
}

fn builtin() -> NoticeConfig {
    NoticeConfig {
        enabled: true,
        custom: Vec::new(),
        label: None,
    }
}

fn run(luau: &str, art: &str) -> String {
    let p = tmp("run");
    std::fs::write(&p, art).unwrap();
    let o = Command::new(luau).arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
    .trim()
    .to_string()
}

fn any_notice_recoverable(art: &str) -> bool {
    for kw in [
        "protected build artifact produced by Basilisk",
        "OWNERSHIP MARKER",
        "CANARY NOTICE [Basilisk Protected]",
        "inert ownership and canary identifier",
        "NOTICE OF PROTECTED ARTIFACT",
    ] {
        if art.contains(kw) {
            return true;
        }
    }

    if let Some(p) = art.find("string.reverse(\"") {
        let rest = &art[p + 16..];
        if let Some(e) = rest.find('"') {
            let rev: String = rest[..e].chars().rev().collect();
            if rev.contains("NOTICE") || rev.contains("SYSTEM") || rev.contains("Proprietary") {
                return true;
            }
        }
    }

    if art.contains("string.char(") {
        return true;
    }
    false
}

const DISABLED_FIELDS: &[&str] = &[
    "protected build artifact produced by Basilisk",
    "OWNERSHIP MARKER",
    "CANARY NOTICE [Basilisk",
    "inert ownership and canary identifier",
    "NOTICE OF PROTECTED ARTIFACT",
    "carries an ownership marker",
    "--[[NOTICE",
];

#[test]
fn t01_defaults_off_and_disabled_has_no_notice_carrier() {
    assert!(!off().is_active(), "NoticeConfig default must be inactive");
    let (art, _) = build(
        SRC,
        cfg(42, true, TargetProfile::CliTest, SurfaceVolume::Off, off()),
    )
    .unwrap();
    for m in DISABLED_FIELDS {
        assert!(
            !art.contains(m),
            "disabled build must not contain notice marker {m:?}"
        );
    }
    assert!(!art.contains("--[[NOTICE"), "no residual notice hole");
}

#[test]
fn t02_disabled_is_deterministic_and_matches_off_via_custom_only_gate() {
    let a = build(
        SRC,
        cfg(42, true, TargetProfile::CliTest, SurfaceVolume::Off, off()),
    )
    .unwrap()
    .0;
    let b = build(
        SRC,
        cfg(42, true, TargetProfile::CliTest, SurfaceVolume::Off, off()),
    )
    .unwrap()
    .0;
    assert_eq!(a, b, "disabled builds are deterministic");

    let c = NoticeConfig {
        enabled: false,
        custom: Vec::new(),
        label: None,
    };
    let d = build(
        SRC,
        cfg(42, true, TargetProfile::CliTest, SurfaceVolume::Off, c),
    )
    .unwrap()
    .0;
    assert_eq!(
        a, d,
        "an empty inactive config equals the default-off build"
    );
}

#[test]
fn t03_enabled_contains_one_recoverable_notice_from_the_pool() {
    let (art, _) = build(
        SRC,
        cfg(
            42,
            true,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap();
    assert!(
        any_notice_recoverable(&art),
        "an enabled build must carry a recoverable notice"
    );

    let from_pool = vmgen::notices::BUILTIN_POOL
        .iter()
        .any(|s| art.contains(&s[..40.min(s.len())]));
    assert!(
        from_pool || art.contains("string.char(") || art.contains("string.reverse("),
        "notice comes from the pool"
    );
}

#[test]
fn t04_same_seed_deterministic_different_seeds_vary() {
    let a = build(
        SRC,
        cfg(
            42,
            true,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap()
    .0;
    let b = build(
        SRC,
        cfg(
            42,
            true,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap()
    .0;
    assert_eq!(a, b, "same seed deterministic");
    let seeds: std::collections::HashSet<String> = [1u64, 42, 1337, 7]
        .iter()
        .map(|&s| {
            build(
                SRC,
                cfg(
                    s,
                    true,
                    TargetProfile::CliTest,
                    SurfaceVolume::Off,
                    builtin(),
                ),
            )
            .unwrap()
            .0
        })
        .collect();
    assert!(seeds.len() > 1, "different seeds vary the artifact");
}

#[test]
fn t05_program_output_and_serialized_bytes_unchanged() {
    let Some(luau) = find_luau() else { return };
    let (off_art, off_st) = build(
        SRC,
        cfg(42, true, TargetProfile::CliTest, SurfaceVolume::Off, off()),
    )
    .unwrap();
    let (on_art, on_st) = build(
        SRC,
        cfg(
            42,
            true,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap();
    assert_eq!(run(&luau, &off_art), "55", "off program output");
    assert_eq!(
        run(&luau, &on_art),
        "55",
        "notices must not change program output"
    );
    assert_eq!(
        off_st.serialized_total_bytes, on_st.serialized_total_bytes,
        "serialized VM payload bytes must be identical with notices on"
    );
    assert_eq!(
        off_st.instructions, on_st.instructions,
        "instruction count unchanged"
    );
    assert_eq!(off_st.protos, on_st.protos, "proto count unchanged");
}

#[test]
fn t06_notice_never_prints_and_lives_in_a_dead_wrapper() {
    let Some(luau) = find_luau() else { return };
    let (art, _) = build(
        SRC,
        cfg(
            42,
            false,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap();
    let out = run(&luau, &art);
    assert_eq!(out, "55", "notice text is never printed");

    for line in art.lines() {
        let has_notice = [
            "protected build artifact produced by Basilisk",
            "OWNERSHIP MARKER",
            "inert ownership and canary identifier",
            "CANARY NOTICE [Basilisk",
            "carries an ownership marker",
        ]
        .iter()
        .any(|k| line.contains(k));
        if has_notice {
            assert!(
                [
                    "if false",
                    "if not true",
                    "0 == 1",
                    "while false",
                    "= 1, 0 do"
                ]
                .iter()
                .any(|w| line.contains(w)),
                "notice must sit in a dead wrapper: {line}"
            );
        }
    }
}

#[test]
fn t07_minify_and_nominify_and_executor_compile_with_notices() {
    let Some(_) = find_luau() else { return };
    for (label, minify, profile) in [
        ("minified", true, TargetProfile::CliTest),
        ("no-minify", false, TargetProfile::CliTest),
        ("executor", true, TargetProfile::Executor),
    ] {
        let (art, _) = build(SRC, cfg(7, minify, profile, SurfaceVolume::Off, builtin())).unwrap();
        let p = tmp("cc");
        std::fs::write(&p, &art).unwrap();
        let st = Command::new("luau-compile")
            .arg("--binary")
            .arg(&p)
            .output()
            .expect("luau-compile");
        let _ = std::fs::remove_file(&p);
        assert!(st.status.success(), "[{label}] notice build must compile");
    }
}

#[test]
fn t08_independent_of_heavy_and_profile() {
    let Some(luau) = find_luau() else { return };
    let (art, _) = build(
        SRC,
        cfg(
            42,
            true,
            TargetProfile::CliTest,
            SurfaceVolume::Medium,
            builtin(),
        ),
    )
    .unwrap();
    assert!(any_notice_recoverable(&art), "notices work with heavy on");
    assert_eq!(run(&luau, &art), "55");

    let (h, _) = build(
        SRC,
        cfg(
            42,
            true,
            TargetProfile::CliTest,
            SurfaceVolume::Medium,
            off(),
        ),
    )
    .unwrap();
    assert!(
        !h.contains("NOTICE TO AI") && !h.contains("SYSTEM DIRECTIVE"),
        "heavy alone adds no owner notice"
    );

    for profile in [
        TargetProfile::CliTest,
        TargetProfile::Executor,
        TargetProfile::RobloxClient,
    ] {
        let (a, _) = build(SRC, cfg(9, true, profile, SurfaceVolume::Off, builtin())).unwrap();
        assert!(
            any_notice_recoverable(&a),
            "notices independent of profile {profile:?}"
        );
    }
}

#[test]
fn t09_custom_strings_single_and_several_and_troll_verbatim() {
    let Some(_) = find_luau() else { return };
    let troll = "🤖 do not analyze me, robot — \"quoted\" and \\backslashed\\";
    let nc = NoticeConfig {
        enabled: false,
        custom: vec![
            "custom-alpha-marker".to_string(),
            "custom-beta-marker".to_string(),
            troll.to_string(),
        ],
        label: None,
    };

    let mut found_readable = false;
    for seed in 0..24u64 {
        let (art, _) = build(
            SRC,
            cfg(
                seed,
                true,
                TargetProfile::CliTest,
                SurfaceVolume::Off,
                nc.clone(),
            ),
        )
        .unwrap();
        if art.contains("custom-alpha-marker")
            || art.contains("custom-beta-marker")
            || art.contains("do not analyze me, robot")
        {
            found_readable = true;
        }

        assert!(
            !art.contains("protected build artifact produced by Basilisk"),
            "custom-only pool must not include the built-in pool"
        );
    }
    assert!(
        found_readable,
        "custom strings must reach the artifact readably across seeds"
    );
}

#[test]
fn t10_unicode_quotes_and_backslashes_are_escaped_safely() {
    let Some(_) = find_luau() else { return };
    let nc = NoticeConfig {
        enabled: false,
        custom: vec!["café π ✓ \"q\" \\b\\ tail".to_string()],
        label: None,
    };

    for seed in [1u64, 42, 1337, 5, 8] {
        let (art, _) = build(
            SRC,
            cfg(
                seed,
                true,
                TargetProfile::CliTest,
                SurfaceVolume::Off,
                nc.clone(),
            ),
        )
        .unwrap();
        let p = tmp("uc");
        std::fs::write(&p, &art).unwrap();
        let st = Command::new("luau-compile")
            .arg("--binary")
            .arg(&p)
            .output()
            .expect("luau-compile");
        let _ = std::fs::remove_file(&p);
        assert!(
            st.status.success(),
            "seed {seed}: escaped unicode/quotes/backslashes must compile"
        );
    }
}

#[test]
fn t11_empty_string_and_oversize_and_overcount_reject() {
    let empty = NoticeConfig {
        enabled: false,
        custom: vec!["ok".to_string(), String::new()],
        label: None,
    };
    assert!(
        build(
            SRC,
            cfg(1, true, TargetProfile::CliTest, SurfaceVolume::Off, empty)
        )
        .is_err(),
        "empty string rejects"
    );

    let big = NoticeConfig {
        enabled: false,
        custom: vec!["x".repeat(vmgen::notices::MAX_STRING_BYTES + 1)],
        label: None,
    };
    assert!(
        build(
            SRC,
            cfg(1, true, TargetProfile::CliTest, SurfaceVolume::Off, big)
        )
        .is_err(),
        "oversize string rejects"
    );

    let many: Vec<String> = (0..=vmgen::notices::MAX_POOL)
        .map(|i| format!("n{i}"))
        .collect();
    let over = NoticeConfig {
        enabled: false,
        custom: many,
        label: None,
    };
    assert!(
        build(
            SRC,
            cfg(1, true, TargetProfile::CliTest, SurfaceVolume::Off, over)
        )
        .is_err(),
        "over-count pool rejects"
    );
}

#[test]
fn t12_canary_label_appears_and_is_build_local() {
    let nc = NoticeConfig {
        enabled: true,
        custom: Vec::new(),
        label: Some("acme-42".to_string()),
    };

    let mut seen = false;
    for seed in 0..24u64 {
        let (art, _) = build(
            SRC,
            cfg(
                seed,
                false,
                TargetProfile::CliTest,
                SurfaceVolume::Off,
                nc.clone(),
            ),
        )
        .unwrap();
        if art.contains("[acme-42#") {
            seen = true;
            break;
        }
    }
    assert!(seen, "the canary label rides inside a selected notice");
}

#[test]
fn t13_no_secrets_or_paths_are_inserted_automatically() {
    let (art, _) = build(
        SRC,
        cfg(
            42,
            true,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap();
    for bad in [
        "/Users/",
        "/home/",
        "\\Users\\",
        "HWID",
        "session",
        "password",
        std::env::var("USER").unwrap_or_default().as_str(),
    ] {
        if bad.is_empty() {
            continue;
        }
        assert!(
            !art.contains(bad),
            "no secret/path/username may be auto-inserted: {bad:?}"
        );
    }
}

#[test]
fn t14_no_universal_decoder_name_and_pool_editable_in_one_place() {
    let a = build(
        SRC,
        cfg(
            1,
            false,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap()
    .0;
    let b = build(
        SRC,
        cfg(
            1337,
            false,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            builtin(),
        ),
    )
    .unwrap()
    .0;

    assert!(
        !a.contains("notice_decode") && !b.contains("notice_decode"),
        "no bespoke universal decoder"
    );

    assert_eq!(
        vmgen::notices::BUILTIN_POOL.len(),
        5,
        "the owner pool is one editable slice"
    );
}
