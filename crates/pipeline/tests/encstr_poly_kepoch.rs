use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

fn unique_tmp(prefix: &str) -> PathBuf {
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
    Command::new("luau")
        .arg("--help")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn cfg(seed: u64) -> Config {
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
        surface: false,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile: TargetProfile::CliTest,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: true,
        strip_source_names: false,
        poly_stream: PolyStream::Aggressive,
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

fn build(body: &str, seed: u64) -> String {
    let src = format!("{body}\n");
    let output = unique_tmp("encstr_poly_out");
    let out = output.clone();
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let tmp_in = unique_tmp("encstr_poly_in");
            std::fs::write(&tmp_in, src.as_bytes()).unwrap();
            pipeline::run(&tmp_in, &out, &cfg(seed))
                .unwrap_or_else(|e| panic!("build seed {seed}: {e:#}"));
            let _ = std::fs::remove_file(&tmp_in);
        })
        .unwrap()
        .join()
        .unwrap();
    let s = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    s
}

fn run(luau: &str, art: &str) -> String {
    let p = unique_tmp("encstr_poly_run");
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

fn seeds() -> Vec<u64> {
    let mut v: Vec<u64> = (0u64..48).collect();
    v.push(3190741035353583814);
    v.push(8888888888888888888);
    v
}

#[test]
fn encstr_in_concat_survives_poly_kepoch_all_seeds() {
    let Some(luau) = find_luau() else { return };
    let body = "local ai = \"ProductName\"\nlocal t = {}\nt.product_disabled = ai .. BASIL_ENCSTR\" is currently disabled.\"\nprint(t.product_disabled)";
    let want = "ProductName is currently disabled.";
    for s in seeds() {
        let art = build(body, s);
        assert!(
            !art.contains("is currently disabled"),
            "seed {s}: plaintext enc-string must not ship"
        );
        let got = run(&luau, &art);
        assert_eq!(got, want, "seed {s}: enc-string concat corrupted under poly-stream (KEPOCH inner-proto regression)");
    }
}

#[test]
fn standalone_encstr_survives_poly_kepoch_all_seeds() {
    let Some(luau) = find_luau() else { return };
    let body = "local s = BASIL_ENCSTR\"sealed-payload\"\nprint(s)";
    for s in seeds() {
        let art = build(body, s);
        let got = run(&luau, &art);
        assert_eq!(
            got, "sealed-payload",
            "seed {s}: standalone enc-string returned wrong value under poly-stream"
        );
    }
}
