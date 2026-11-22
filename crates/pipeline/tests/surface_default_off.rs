use pipeline::{
    Config, HotCallbackPolicy, Mode, Optimizer, PolyStream, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

const SRC: &str = "local s = 0\nfor i = 1, 500 do s = (s + i * 7 - 3) % 100003 end\nprint(s)\n";

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_surfoff_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn cfg(seed: u64) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: false,
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

fn build(src: &str, seed: u64, surface: pipeline::SurfaceConfig) -> String {
    let i = tmp("in");
    let o = tmp("out");
    std::fs::write(&i, src).unwrap();
    let (a, b, c) = (i.clone(), o.clone(), cfg(seed));
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let mut stats = None;
            pipeline::run_capturing_stats_optimized(
                &a,
                &b,
                &c,
                Optimizer::Off,
                None,
                &mut stats,
                false,
                &surface,
            )
            .expect("build succeeds");
        })
        .unwrap()
        .join()
        .unwrap();
    let out = std::fs::read_to_string(&o).unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn plain_build(src: &str, seed: u64) -> String {
    let i = tmp("pin");
    let o = tmp("pout");
    std::fs::write(&i, src).unwrap();
    let (a, b, c) = (i.clone(), o.clone(), cfg(seed));
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&a, &b, &c).expect("plain build succeeds"))
        .unwrap()
        .join()
        .unwrap();
    let out = std::fs::read_to_string(&o).unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

#[test]
fn default_off_surface_is_byte_identical_to_plain_build() {
    let off = build(SRC, 42, pipeline::SurfaceConfig::default());
    let plain = plain_build(SRC, 42);
    assert_eq!(
        off, plain,
        "a default-off SurfaceConfig build must be byte-identical to a plain build"
    );
}
