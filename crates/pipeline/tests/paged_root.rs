use std::path::PathBuf;

use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    match std::process::Command::new("luau").arg("--help").output() {
        Ok(_) => Some("luau".to_string()),
        Err(_) => None,
    }
}

fn cfg(profile: TargetProfile, poly: PolyStream) -> Config {
    Config {
        seed: 0x_9A5E_1207,
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
        line_info: false,
        strip_source_names: false,
        poly_stream: poly,
        optimization: 0,
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

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("basil_paged_{}_{name}", std::process::id()))
}

fn multipage_source() -> String {
    let mut s =
        String::from("local acc = 0\nlocal function step(x) return (x * 3 + 7) % 1000 end\n");
    for i in 0..1500 {
        s.push_str(&format!("acc = acc + step({}) - {}\n", i % 131, i % 17));
        if i % 200 == 0 {
            s.push_str(&format!(
                "if acc > {} then acc = acc - {} end\n",
                i * 3,
                i % 29
            ));
        }
    }
    s.push_str("for k = 1, 40 do acc = acc + k end\n");
    s.push_str("print(acc)\n");
    s
}

fn run(luau: &str, path: &PathBuf) -> String {
    let out = std::process::Command::new(luau)
        .arg(path)
        .output()
        .expect("luau run");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn multipage_root_raw_equals_virt() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping");
        return;
    };
    let run_body = move || {
        let src = multipage_source();
        let src_path = tmp("in.luau");
        std::fs::write(&src_path, &src).unwrap();
        let raw = run(&luau, &src_path);
        assert!(!raw.is_empty(), "raw script produced output");

        for (profile, poly) in [
            (TargetProfile::CliTest, PolyStream::Off),
            (TargetProfile::CliTest, PolyStream::Aggressive),
            (TargetProfile::CliTest, PolyStream::Conservative),
        ] {
            let out_path = tmp("out.luau");
            pipeline::run(&src_path, &out_path, &cfg(profile, poly)).expect("virtualize");
            let virt = run(&luau, &out_path);
            assert_eq!(
                raw, virt,
                "multi-page root raw==virt must hold ({profile:?}, {poly:?})"
            );
            let _ = std::fs::remove_file(&out_path);
        }
        let _ = std::fs::remove_file(&src_path);
    };
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(run_body)
        .unwrap()
        .join()
        .unwrap();
}
