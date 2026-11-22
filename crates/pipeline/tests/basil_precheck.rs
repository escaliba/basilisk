use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_pc_{p}_{}_{}.luau",
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

fn build(body: &str, seed: u64) -> Result<String, String> {
    let s = format!("{body}\n");
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_with(&s, seed, true, true, true, true, true, false, false)
                .map_err(|e| format!("{e:#}"))
        })
        .unwrap()
        .join()
        .unwrap()
}

fn run(luau: &str, art: &str, tag: &str) -> String {
    let p = tmp(tag);
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

#[test]
fn p01_correct_precheck_materializes() {
    let Some(luau) = find_luau() else { return };
    let art = build(
        "BASIL_PRECHECK(function() return 42 end, 42)\nprint(\"pc-ran-ok\")",
        305419896,
    )
    .expect("build");
    assert!(!art.contains("BASIL_PRECHECK"), "marker must not survive");
    assert_eq!(
        run(&luau, &art, "ok"),
        "pc-ran-ok",
        "a correct precheck leaves the genkey intact"
    );
}

#[test]
fn p02_wrong_precheck_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let art = build(
        "BASIL_PRECHECK(function() return 42 end, 99)\nprint(\"pc-ran-bad\")",
        305419896,
    )
    .expect("build");
    assert!(
        !run(&luau, &art, "bad").contains("pc-ran-bad"),
        "a wrong precheck must corrupt the genkey and fail closed"
    );
}

#[test]
fn p03_multiple_prechecks_compose() {
    let Some(luau) = find_luau() else { return };
    let ok = "BASIL_PRECHECK(function() return 3 end, 3)\nBASIL_PRECHECK(function() return 8 end, 8)\nprint(\"pc-multi-ok\")";
    assert_eq!(
        run(&luau, &build(ok, 305419896).expect("build"), "m1"),
        "pc-multi-ok"
    );
    let bad = "BASIL_PRECHECK(function() return 3 end, 3)\nBASIL_PRECHECK(function() return 8 end, 9)\nprint(\"pc-multi-bad\")";
    assert!(
        !run(&luau, &build(bad, 305419896).expect("build"), "m2").contains("pc-multi-bad"),
        "one wrong precheck fails closed"
    );
}

#[test]
fn p04_missing_environment_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let art = build(
        "BASIL_PRECHECK(function() return (getgenv and 1) or 0 end, 1)\nprint(\"pc-env-ok\")",
        305419896,
    )
    .expect("build");
    assert!(
        !run(&luau, &art, "e2").contains("pc-env-ok"),
        "an environment without getgenv fails closed"
    );
}

#[test]
fn p05_integer_list_expected() {
    let Some(luau) = find_luau() else { return };
    let art = build(
        "BASIL_PRECHECK(function() return 3, 8 end, { 3, 8 })\nprint(\"pc-list-ok\")",
        305419896,
    )
    .expect("build");
    assert_eq!(run(&luau, &art, "l1"), "pc-list-ok");
    let bad = build(
        "BASIL_PRECHECK(function() return 3, 8 end, { 3, 9 })\nprint(\"pc-list-bad\")",
        305419896,
    )
    .expect("build");
    assert!(
        !run(&luau, &bad, "l2").contains("pc-list-bad"),
        "wrong list element fails closed"
    );
}

#[test]
fn p06_load_bearing_not_a_branch() {
    let with = build(
        "BASIL_PRECHECK(function() return 5 end, 5)\nprint(\"x\")",
        42,
    )
    .expect("build");
    let without = build("print(\"x\")", 42).expect("build");
    assert!(
        !with.contains("BASIL_CRASH"),
        "precheck must not lower to a cleartext crash-branch"
    );
    assert_ne!(
        with, without,
        "the precheck must fold into the genkey derivation (change the build), not be a no-op"
    );
}

#[test]
fn p07_callback_with_params_rejected() {
    let e = build("BASIL_PRECHECK(function(x) return x end, 1)\nprint(1)", 42).unwrap_err();
    assert!(e.contains("no parameters"), "got: {e}");
}

#[test]
fn p08_non_integer_expected_rejected() {
    let e = build(
        "BASIL_PRECHECK(function() return 1 end, \"x\")\nprint(1)",
        42,
    )
    .unwrap_err();
    assert!(e.contains("integer"), "got: {e}");
}

#[test]
fn p09_macro_inside_callback_rejected() {
    let e = build(
        "BASIL_PRECHECK(function() BASIL_CRASH() return 1 end, 1)\nprint(1)",
        42,
    )
    .unwrap_err();
    assert!(e.contains("runs natively before the VM"), "got: {e}");
}

#[test]
fn p10_no_precheck_still_builds_and_runs() {
    let Some(luau) = find_luau() else { return };
    let art = build("print(\"no-precheck\")", 305419896).expect("build");
    assert_eq!(run(&luau, &art, "np"), "no-precheck");
}
