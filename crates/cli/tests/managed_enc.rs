use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);
const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const WRONG: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_menc_{}_{}_{}.{ext}",
        std::process::id(),
        nanos,
        n
    ))
}

fn find_luau() -> Option<String> {
    if let Ok(b) = std::env::var("LUAU_BIN") {
        return Some(b);
    }
    Command::new("luau")
        .arg("--help")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn build(src: &str, flags: &[&str]) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, src).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg("7");
    cmd.args(flags).env("BASIL_DIRECT_WRITES", "1");
    let o = cmd.output().expect("spawn basilisk");
    let ok = o.status.success();
    let stderr = String::from_utf8_lossy(&o.stderr).to_string();
    let _ = std::fs::remove_file(&inp);
    if !ok {
        let _ = std::fs::remove_file(&out);
        return format!("BUILD_ERR {stderr}");
    }
    let art = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_file(&out);
    art
}

fn run(luau: &str, preamble: &str, artifact: &str) -> String {
    let f = tmp("luau");
    std::fs::write(&f, format!("{preamble}\n{artifact}")).unwrap();
    let o = Command::new(luau).arg(&f).output().expect("spawn luau");
    let _ = std::fs::remove_file(&f);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
    .trim()
    .to_string()
}

const REFERENCE: &str = "local secretA = BASIL_ENCSTR(\"https://api.site/x\")\n\
     local secretB = BASIL_ENCSTR(\"hello world\")\n\
     local protectedA = BASIL_ENCFUNC(function() return \"A\" end)\n\
     local protectedB = BASIL_ENCFUNC(function() return \"B\" end)\n\
     print(secretA, secretB, protectedA(), protectedB())\n";

#[test]
fn managed_encstr_one_arg_compiles_and_runs() {
    let Some(luau) = find_luau() else { return };
    let art = build("local s = BASIL_ENCSTR(\"hello world\")\nprint(s)\n", &[]);
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert_eq!(run(&luau, "", &art), "hello world");
}

#[test]
fn managed_encfunc_one_arg_compiles_and_runs() {
    let Some(luau) = find_luau() else { return };
    let art = build(
        "local f = BASIL_ENCFUNC(function(a, b) return a + b end)\nprint(f(40, 2))\n",
        &[],
    );
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert_eq!(run(&luau, "", &art), "42");
}

#[test]
fn managed_reference_fixture_runs() {
    let Some(luau) = find_luau() else { return };
    let art = build(REFERENCE, &[]);
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert_eq!(
        run(&luau, "", &art),
        "https://api.site/x\thello world\tA\tB"
    );
}

#[test]
fn external_three_arg_encfunc_unchanged() {
    let Some(luau) = find_luau() else { return };
    let src = format!(
        "local rk = BASILISK_RUNTIME_KEY\nlocal f = BASIL_ENCFUNC(function(a, b) return a + b end, \"{KEY}\", rk)\nprint(f(40, 2))\n"
    );
    let art = build(&src, &[]);
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert_eq!(
        run(&luau, &format!("BASILISK_RUNTIME_KEY = \"{KEY}\""), &art),
        "42"
    );
    let wrong = run(&luau, &format!("BASILISK_RUNTIME_KEY = \"{WRONG}\""), &art);
    assert!(
        !wrong.contains("42"),
        "wrong external key must fail closed: {wrong}"
    );
}

#[test]
fn external_three_arg_encstr_unchanged() {
    let Some(luau) = find_luau() else { return };
    let src = format!(
        "local rk = BASILISK_RUNTIME_KEY\nlocal s = BASIL_ENCSTR(\"hello world\", \"{KEY}\", rk)\nprint(s)\n"
    );
    let art = build(&src, &[]);
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert_eq!(
        run(&luau, &format!("BASILISK_RUNTIME_KEY = \"{KEY}\""), &art),
        "hello world"
    );
}

#[test]
fn strict_arity_rejected_at_build() {
    let two_fn = build(
        "local f = BASIL_ENCFUNC(function() end, \"k\")\nprint(f)\n",
        &[],
    );
    assert!(
        two_fn.starts_with("BUILD_ERR"),
        "two-arg ENCFUNC must fail to build: {two_fn}"
    );
    let two_str = build("local s = BASIL_ENCSTR(\"a\", \"b\")\nprint(s)\n", &[]);
    assert!(
        two_str.starts_with("BUILD_ERR"),
        "two-arg ENCSTR must fail to build: {two_str}"
    );
}

#[test]
fn managed_plaintext_and_value_absent_from_artifact() {
    let art = build(
        "local s = BASIL_ENCSTR(\"MANAGED-SECRET-MARKER-9Z\")\nlocal f = BASIL_ENCFUNC(function() return \"FUNC-BODY-MARKER-7Q\" end)\nprint(s, f())\n",
        &[],
    );
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert!(
        !art.contains("MANAGED-SECRET-MARKER-9Z"),
        "managed string plaintext leaked"
    );
    assert!(
        !art.contains("FUNC-BODY-MARKER-7Q"),
        "managed function body plaintext leaked"
    );
}

#[test]
fn managed_build_is_deterministic_for_a_seed() {
    let a = build(REFERENCE, &[]);
    let b = build(REFERENCE, &[]);
    assert!(!a.starts_with("BUILD_ERR"), "{a}");
    assert_eq!(
        a, b,
        "same seed must produce a byte-identical managed artifact"
    );
}
