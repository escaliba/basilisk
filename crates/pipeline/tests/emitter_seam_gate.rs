use pipeline::{
    Config, FrameConstReuseMode, HotCallbackPolicy, Mode, NoticeConfig, PolyStream, SensitiveOpts,
    SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basil_seam_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn gate_rejects_malformed_token_adjacency() {
    for bad in [
        "local x=256return x",
        "for i=1,3do end",
        "local a=7 return (5or a)",
        "local a=7 return (a and 9or a)",
        "local a=7 return (7if or a)",
    ] {
        assert!(
            pipeline::luau_compile_gate(bad).is_err(),
            "gate must reject malformed: {bad:?}"
        );
    }
}

#[test]
fn gate_accepts_valid_and_does_not_flag_strings_or_comments() {
    for ok in [
        "local x=256 return x",
        "for i=1,3 do end",
        "local a=(1 + 2) % 256 return a",
        "local a=0xFF+1e3 local b=0b1010 local c=1_000 return a+b+c",
        "local s=\"256return glued in a string\" return s",
        "-- 256return in a comment\nreturn 1",
        "local t={} t[1]=5 return t[1]",
    ] {
        assert!(
            pipeline::luau_compile_gate(ok).is_ok(),
            "gate must accept valid: {ok:?}"
        );
    }
}

fn stage2_like(seed: u64) -> Config {
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
        profile: TargetProfile::Executor,
        loadstring_canary: true,
        lph_collapse: true,
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
        shell_family: Some(pipeline::ShellFamily::SetMeta),
        notices: NoticeConfig {
            enabled: false,
            custom: Vec::new(),
            label: None,
        },
        stateful_recovery: false,
        stateful_framing: false,
        property_key_rename: pipeline::PropKeyMode::Off,
        semantic_family: true,
        instruction_family: true,
        state_family: false,
        microir: false,
        semgroup: true,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

const SRC: &str = "local p = BASIL_ENCSTR(\"product-disabled-256\")\nlocal function step(a, b)\n  local acc = 0\n  for i = 1, 256 do\n    if i % 3 == 0 then acc = acc + i\n    elseif i % 5 == 0 then acc = acc - i\n    else acc = acc + (a % 7) end\n  end\n  return acc + b\nend\nlocal r = step(9, 7)\nprint(p, r)\n";

fn build(seed: u64) -> Result<String, String> {
    let i = tmp("in");
    let o = tmp("out");
    std::fs::write(&i, SRC).unwrap();
    let c = stage2_like(seed);
    let (ic, oc) = (i.clone(), o.clone());
    let r = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&ic, &oc, &c).map_err(|e| format!("{e:#}")))
        .unwrap()
        .join()
        .unwrap();
    let out = r.map(|_| std::fs::read_to_string(&o).unwrap());
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

#[test]
fn virtualized_builds_pass_gate_and_are_deterministic() {
    for seed in 0..8u64 {
        let a = build(seed).unwrap_or_else(|e| panic!("plain seed {seed}: {e}"));
        let b = build(seed).unwrap_or_else(|e| panic!("plain seed {seed} (repeat): {e}"));
        assert_eq!(
            a, b,
            "same seed/config must be byte-deterministic (seed {seed})"
        );
    }
}
