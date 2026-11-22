use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

fn tmp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "basilisk_senv_{}_{}_{}.luau",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn executor_cfg(seed: u64, static_env: bool) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: true,
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
        profile: TargetProfile::Executor,
        loadstring_canary: true,
        lph_collapse: true,
        line_info: false,
        strip_source_names: true,
        poly_stream: PolyStream::Aggressive,
        optimization: 2,
        static_env,
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

#[test]
fn env_introspection_detects_getfenv_setfenv_only() {
    assert_eq!(
        pipeline::env_introspection("local e = getfenv(1)\nreturn e\n").unwrap(),
        vec!["getfenv"]
    );
    assert_eq!(
        pipeline::env_introspection("setfenv(1, {})\n").unwrap(),
        vec!["setfenv"]
    );
    assert_eq!(
        pipeline::env_introspection("local a = getfenv(1)\nsetfenv(2, {})\nreturn a\n").unwrap(),
        vec!["getfenv", "setfenv"]
    );
    assert!(
        pipeline::env_introspection("local x = 1\nlocal t = {a = 2}\nreturn x + t.a\n")
            .unwrap()
            .is_empty()
    );
    assert!(
        pipeline::env_introspection(
            "local s = \"getfenv\"\nlocal t = {}\nt.setfenv = 1\nreturn s, t\n"
        )
        .unwrap()
        .is_empty(),
        "string contents and field names must not trigger detection"
    );
}

#[test]
fn static_env_does_not_change_the_artifact_for_a_clean_script() {
    let src = "local function add(a, b)\n  return a + b\nend\nreturn add(2, 3)\n";
    let input = tmp("in");
    std::fs::write(&input, src).unwrap();
    let off = tmp("off");
    let on = tmp("on");
    pipeline::run(&input, &off, &executor_cfg(0x1234, false)).unwrap();
    pipeline::run(&input, &on, &executor_cfg(0x1234, true)).unwrap();
    let a = std::fs::read(&off).unwrap();
    let b = std::fs::read(&on).unwrap();
    assert_eq!(a, b, "static-env is audit/warning only in this branch; it must not change the generated artifact");
    for p in [input, off, on] {
        let _ = std::fs::remove_file(p);
    }
}
