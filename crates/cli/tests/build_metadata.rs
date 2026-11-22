use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_md_{}_{}_{}.{ext}",
        std::process::id(),
        nanos,
        n
    ))
}

fn build_meta(seed: u64) -> (String, serde_json::Value) {
    let inp = tmp("luau");
    let out = tmp("luau");
    let meta = tmp("json");
    std::fs::write(&inp, "local x = 1 local y = 2 print(x + y)\n").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg(seed.to_string());
    cmd.arg("--emit-build-metadata").arg(&meta);
    cmd.env("BASIL_DIRECT_WRITES", "1");
    let o = cmd.output().expect("spawn basilisk");
    assert!(
        o.status.success(),
        "seed {seed}: build failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let art = std::fs::read_to_string(&out).unwrap();
    let m: serde_json::Value = serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
    let _ = std::fs::remove_file(&inp);
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&meta);
    (art, m)
}

const BOUNDARY_SEEDS: &[u64] = &[
    0,
    1,
    1 << 31,
    1 << 32,
    (1u64 << 63) - 1,
    1 << 63,
    u64::MAX,
    13345698180402984039,
];

#[test]
fn build_seed_is_a_lossless_decimal_string() {
    for &seed in BOUNDARY_SEEDS {
        let (_art, m) = build_meta(seed);
        let s = m["build_seed"]
            .as_str()
            .unwrap_or_else(|| panic!("seed {seed}: build_seed must be a JSON string"));
        assert_eq!(s, seed.to_string(), "seed {seed}: decimal-string mismatch");
        assert_eq!(
            s.parse::<u64>().unwrap(),
            seed,
            "seed {seed}: decimal string does not round-trip losslessly"
        );
    }
}

#[test]
fn format_version_is_present_and_current() {
    let (_art, m) = build_meta(7);
    assert_eq!(
        m["format_version"],
        serde_json::json!(2u64),
        "format_version must be the current v2"
    );
}
