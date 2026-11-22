use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);

const NSA: &str = "protected build artifact; see the project license";

const SRC: &str = "local t = {}\n\
for i = 1, 40 do t[i] = (i * 2654435761) % 4294967296 end\n\
local s = 0\n\
for i = 1, #t do s = (s + t[i] * 65536) % 4294967296 end\n\
print(\"RESULT:\" .. tostring(s))\n";

fn find_luau() -> Option<String> {
    Command::new("luau")
        .arg("--help")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_cd_{}_{}_{}.{ext}",
        std::process::id(),
        nanos,
        n
    ))
}

fn build(seed: u64) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, SRC).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_basilisk"))
        .args([
            inp.to_str().unwrap(),
            out.to_str().unwrap(),
            "--no-interactive",
            "--seed",
        ])
        .arg(seed.to_string())
        .args([
            "--opaque",
            "--fuse",
            "--lph-collapse",
            "--poly-stream",
            "aggressive",
            "--optimization",
            "2",
            "--experimental-semantic-family",
        ])
        .output()
        .expect("spawn basilisk");
    assert!(
        o.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let art = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_file(&inp);
    let _ = std::fs::remove_file(&out);
    art
}

fn marker(out: &str) -> Option<String> {
    out.lines()
        .find(|l| l.starts_with("RESULT:"))
        .map(|s| s.to_string())
}

fn run_luau(luau: &str, body: &str) -> String {
    let f = tmp("luau");
    std::fs::write(&f, body).unwrap();
    let o = Command::new(luau).arg(&f).output().expect("spawn luau");
    let _ = std::fs::remove_file(&f);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn count(h: &str, needle: &str) -> usize {
    h.matches(needle).count()
}

#[test]
fn common_runtime_constants_are_diversified_away() {
    let art = build(305419896);
    assert_eq!(count(&art, "4294967296"), 0, "2^32 decimal literal remains");
    assert_eq!(count(&art, "0x100000000"), 0, "2^32 hex literal remains");
    assert_eq!(count(&art, "65536"), 0, "65536 literal remains");
}

#[test]
fn diversified_artifact_is_semantically_identical() {
    let Some(luau) = find_luau() else { return };
    let oracle = marker(&run_luau(&luau, SRC)).expect("oracle RESULT");
    let art = build(305419896);
    let got = marker(&run_luau(&luau, &art)).expect("artifact RESULT");
    assert_eq!(got, oracle, "semantic mismatch");
}

#[test]
fn same_seed_is_byte_identical() {
    assert_eq!(build(777), build(777));
}

#[test]
fn different_seeds_vary_the_decomposition() {
    let distinct: std::collections::HashSet<String> = (1u64..=24).map(build).collect();
    assert!(distinct.len() > 1, "seeds should vary the artifact");
}

#[test]
fn baked_notice_ships_as_a_string_constant_and_runtime_is_unaffected() {
    let Some(luau) = find_luau() else { return };
    let art = build(42);
    assert!(art.contains(NSA), "baked notice present");
    let at = art.find(NSA).unwrap();
    let line_start = art[..at].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let prefix = &art[line_start..at];
    assert!(
        !prefix.trim_start().starts_with("--"),
        "notice is not a comment"
    );
    assert!(
        prefix.contains('"') || prefix.contains("[==["),
        "notice is a quoted string constant"
    );
    let got = marker(&run_luau(&luau, &art)).expect("artifact RESULT");
    assert_eq!(
        got,
        marker(&run_luau(&luau, SRC)).unwrap(),
        "notice does not perturb runtime"
    );
}
