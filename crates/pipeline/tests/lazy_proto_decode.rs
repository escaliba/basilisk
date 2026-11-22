use std::path::{Path, PathBuf};
use std::process::Command;

use pipeline::{Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

const SEED: u64 = 0x_9017_57EE;

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

fn cfg(profile: TargetProfile, poly: PolyStream) -> Config {
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
        profile,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: true,
        strip_source_names: false,
        poly_stream: poly,
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

const NESTED_SRC: &str = "local function fib(n)\n\
\tif n < 2 then return n end\n\
\treturn fib(n - 1) + fib(n - 2)\n\
end\n\
local function adder(base)\n\
\treturn function(...)\n\
\t\tlocal s = base\n\
\t\tfor _, v in ipairs({ ... }) do s = s + v end\n\
\t\treturn s\n\
\tend\n\
end\n\
local function deferred(x)\n\
\treturn x * x + fib(6)\n\
end\n\
local add10 = adder(10)\n\
local acc = 0\n\
for i = 1, 8 do acc = acc + fib(i % 12) end\n\
acc = acc + add10(1, 2, 3, 4)\n\
acc = acc + deferred(5)\n\
print(\"RESULT\", acc)\n";

fn build(input: &Path, cfg: &Config) -> (String, pipeline::BuildStats) {
    let output = unique_tmp("lazy_out");
    let mut stats = None;
    pipeline::run_capturing_stats(input, &output, cfg, None, &mut stats).expect("virtualize");
    let s = std::fs::read_to_string(&output).expect("read output");
    let _ = std::fs::remove_file(&output);
    (s, stats.unwrap())
}

#[test]
fn deferral_metric_partitions_instructions_and_defers_child_protos() {
    let input = unique_tmp("lazy_in");
    std::fs::write(&input, NESTED_SRC).unwrap();
    let (_art, stats) = build(
        &input,
        &cfg(TargetProfile::Executor, PolyStream::Aggressive),
    );
    assert!(
        stats.protos >= 4,
        "fixture must have several child protos: {}",
        stats.protos
    );
    assert_eq!(
        stats.root_proto_instructions + stats.deferred_instructions,
        stats.instructions,
        "root + deferred must partition every instruction: {stats:?}"
    );
    assert!(
        stats.root_proto_instructions > 0,
        "the root chunk is always decoded at boot: {stats:?}"
    );
    assert!(
        stats.deferred_instructions > 0,
        "child-proto instructions must be deferred off the boot path: {stats:?}"
    );
    let _ = std::fs::remove_file(&input);
}

#[test]
fn lazy_decode_preserves_nested_recursive_closure_and_vararg_semantics() {
    let Some(luau) = find_luau() else { return };
    let input = unique_tmp("lazy_in");
    std::fs::write(&input, NESTED_SRC).unwrap();
    let raw = Command::new(&luau)
        .arg(&input)
        .output()
        .expect("spawn luau");
    let raw_out = String::from_utf8_lossy(&raw.stdout).into_owned();
    assert!(raw_out.contains("RESULT"), "raw fixture runs: {raw_out}");

    let output = unique_tmp("lazy_run");
    pipeline::run(
        &input,
        &output,
        &cfg(TargetProfile::CliTest, PolyStream::Off),
    )
    .expect("virtualize");
    let virt = Command::new(&luau)
        .arg(&output)
        .output()
        .expect("spawn luau");
    let virt_out = String::from_utf8_lossy(&virt.stdout).into_owned();
    assert_eq!(
        virt_out, raw_out,
        "lazy-decoded program must match the raw program exactly"
    );
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&input);
}

#[test]
fn same_seed_build_is_deterministic() {
    let input = unique_tmp("lazy_in");
    std::fs::write(&input, NESTED_SRC).unwrap();
    let (a, _) = build(
        &input,
        &cfg(TargetProfile::Executor, PolyStream::Aggressive),
    );
    let (b, _) = build(
        &input,
        &cfg(TargetProfile::Executor, PolyStream::Aggressive),
    );
    assert_eq!(a, b, "same seed must produce a byte-identical artifact");
    let _ = std::fs::remove_file(&input);
}
