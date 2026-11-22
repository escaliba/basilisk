use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);
const COMPILE_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_rl_{}_{}_{}.{ext}",
        std::process::id(),
        nanos,
        n
    ))
}

#[test]
fn release_encfunc_artifact_leaks_nothing() {
    let inp = tmp("luau");
    let out = tmp("luau");
    let src = format!(
        "local rk = BASILISK_RUNTIME_KEY\n\
         local f = BASIL_ENCFUNC(function() return \"sealed-marker-zzz\" end, \"{COMPILE_KEY}\", rk)\n\
         print(f())\n"
    );
    std::fs::write(&inp, src).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_basilisk"))
        .arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg("424242")
        .arg("--require-external-key")
        .env("BASIL_DIRECT_WRITES", "1")
        .output()
        .expect("spawn basilisk");
    assert!(
        o.status.success(),
        "release build failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let art = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_file(&inp);
    let _ = std::fs::remove_file(&out);

    for (tok, label) in [
        (COMPILE_KEY.to_string(), "compile key hex"),
        (COMPILE_KEY.to_ascii_uppercase(), "compile key hex upper"),
    ] {
        assert!(!art.contains(&tok), "leak ({label})");
    }
    assert!(
        !art.contains("sealed-marker-zzz"),
        "protected body plaintext leaked"
    );
}
