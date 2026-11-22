use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);
const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

const PROD_FLAGS: &[&str] = &[
    "--opaque",
    "--fuse",
    "--lph-collapse",
    "--strip-source-names",
    "--poly-stream",
    "aggressive",
    "--optimization",
    "2",
    "--experimental-frame-const-reuse",
    "all",
    "--experimental-semgroup",
    "--experimental-semantic-family",
    "--experimental-instruction-family",
    "--vm-traps",
];

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_fid_{}_{}_{}.{ext}",
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

fn build(src: &str, seed: u64, flags: &[&str]) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, src).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg(seed.to_string());
    cmd.args(flags);
    cmd.env("BASIL_DIRECT_WRITES", "1");
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
    .trim_end()
    .to_string()
}

fn encrun_src() -> String {
    format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(fn,_,_) return fn end end\n\
         local rk = BASILISK_RUNTIME_KEY\n\
         local f = BASIL_ENCFUNC(function(a,b) local t={{x=\"alpha\",y=\"beta\"}} return \"ok:\"..(a+b)..\":\"..t.x end, \"{KEY}\", rk)\n\
         print(f(40, 2))\n"
    )
}

#[test]
fn encfunc_v2_identity_materializes() {
    let Some(luau) = find_luau() else { return };
    let key_pre = format!("BASILISK_RUNTIME_KEY = \"{KEY}\"");
    for seed in [1u64, 7, 13, 31, 42] {
        let art = build(&encrun_src(), seed, PROD_FLAGS);
        assert_eq!(
            run(&luau, &key_pre, &art),
            "ok:42:alpha",
            "ENCFUNC must materialize under its v2 identity (seed {seed})"
        );
    }
}

#[test]
fn patched_identity_fails_closed_before_parse() {
    let Some(luau) = find_luau() else { return };
    let key_pre = format!("BASILISK_RUNTIME_KEY = \"{KEY}\"");

    let art = build(&encrun_src(), 7, &["--vm-traps"]);
    assert_eq!(
        run(&luau, &key_pre, &art),
        "ok:42:alpha",
        "baseline materializes"
    );
    assert_eq!(
        art.matches("66,83,86,65,50,2,0").count(),
        1,
        "exactly one baked sealed-value identity prefix"
    );
    let patched = art.replacen("66,83,86,65,50,2,0", "66,83,86,65,50,99,0", 1);
    assert_ne!(patched, art, "identity byte flipped");
    let out = run(&luau, &key_pre, &patched);
    assert!(
        !out.contains("ok:42"),
        "mismatched identity must not materialize the sealed body: {out}"
    );
    assert!(
        !out.to_lowercase().contains("attempt to") && !out.contains("stack traceback"),
        "fail-closed must be clean (open fails before parse): {out}"
    );
}

#[test]
fn off_path_has_no_sealed_identity_machinery() {
    let plain = "local s = 0 for i = 1, 5 do s += i end print(s)\n";
    let art = build(plain, 7, PROD_FLAGS);
    assert!(
        !art.contains("66,83,86,65,50"),
        "no BSVA2 sealed-value identity in a build with no sealed values"
    );
}

#[test]
fn deterministic_for_fixed_seed() {
    assert_eq!(
        build(&encrun_src(), 7, PROD_FLAGS),
        build(&encrun_src(), 7, PROD_FLAGS),
        "same input+seed+fmt -> identical artifact"
    );
}
