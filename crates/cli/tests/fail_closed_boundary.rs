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
        "basil_fc_{}_{}_{}.{ext}",
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

fn src() -> String {
    format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(fn) return fn end end\n\
         local rk = BASILISK_RUNTIME_KEY\n\
         print(\"START\")\n\
         local f = BASIL_ENCFUNC(function(a, b) print(\"SIDEEFFECT\") return a + b end, \"{KEY}\", rk)\n\
         local r = f(40, 2)\n\
         print(\"RESULT:\" .. tostring(r))\n"
    )
}

fn build(flags: &[&str]) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, src()).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg("7");
    cmd.args(flags).env("BASIL_DIRECT_WRITES", "1");
    let o = cmd.output().expect("spawn basilisk");
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
}

fn assert_clean_fail_closed(out: &str, ctx: &str) {
    assert!(
        !out.contains("SIDEEFFECT"),
        "{ctx}: sealed body side effect ran: {out}"
    );
    assert!(
        !out.contains("RESULT:42"),
        "{ctx}: sealed body materialized a result: {out}"
    );
    let low = out.to_lowercase();
    for bad in [
        "attempt to",
        "stack traceback",
        "too short",
        "out of range",
        "overflow",
        "invalid argument",
    ] {
        assert!(
            !low.contains(bad),
            "{ctx}: host parser/runtime error leaked (not clean fail-closed): {out}"
        );
    }
}

#[test]
fn encfunc_correct_key_materializes_with_side_effect() {
    let Some(luau) = find_luau() else { return };
    let art = build(&["--vm-traps", "--experimental-semantic-family"]);
    let out = run(&luau, &format!("BASILISK_RUNTIME_KEY = \"{KEY}\""), &art);
    assert!(
        out.contains("START") && out.contains("SIDEEFFECT") && out.contains("RESULT:42"),
        "correct key must run the body: {out}"
    );
}

#[test]
fn encfunc_wrong_key_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let art = build(&["--vm-traps", "--experimental-semantic-family"]);
    let out = run(&luau, &format!("BASILISK_RUNTIME_KEY = \"{WRONG}\""), &art);
    assert!(
        out.contains("START"),
        "code before the sealed call still runs: {out}"
    );
    assert_clean_fail_closed(&out, "encfunc wrong key");
}

#[test]
fn encfunc_missing_key_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let art = build(&["--vm-traps", "--experimental-semantic-family"]);
    let out = run(&luau, "", &art);
    assert_clean_fail_closed(&out, "encfunc missing key");
}

#[test]
fn encfunc_tampered_blob_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let art = build(&["--vm-traps", "--experimental-semantic-family"]);
    let Some(p) = art.find("[==[").map(|i| i + 4) else {
        return;
    };
    let mut b = art.into_bytes();
    b[p] = if b[p] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8_lossy(&b).to_string();
    let out = run(
        &luau,
        &format!("BASILISK_RUNTIME_KEY = \"{KEY}\""),
        &tampered,
    );
    assert_clean_fail_closed(&out, "encfunc tampered blob");
}
