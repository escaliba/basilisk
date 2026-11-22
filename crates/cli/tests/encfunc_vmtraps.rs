use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);
const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_encvt_{}_{}_{}.{ext}",
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

fn source() -> String {
    let mut leaf = String::from("local s = a + b\n");
    for i in 1..40 {
        leaf.push_str(&format!("s = s + {i} * a - (b % {})\n", i + 1));
    }
    leaf.push_str("local ok, r = pcall(add, s, b)\nif ok then s = s + r end\nreturn s\n");
    format!(
        "if not BASIL_OBFUSCATED then\n\
         BASIL_ENCFUNC = function(fn, _, _) return fn end\n\
         end\n\
         local rk = BASILISK_RUNTIME_KEY\n\
         local probe = BASIL_ENCFUNC(function() return 42 end, \"{KEY}\", rk)\n\
         print(\"RG-PROBE\", probe())\n\
         local realish = BASIL_ENCFUNC(function(a, b, add)\n{leaf}end, \"{KEY}\", rk)\n\
         print(\"RG-REAL\", realish(3, 5, function(x, y) return x + y end))\n"
    )
}

fn build(src: &str, seed: u64, vm_traps: bool) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, src).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg(seed.to_string());
    if vm_traps {
        cmd.arg("--vm-traps");
    }
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

fn run(luau: &str, artifact: &str, key: Option<&str>) -> String {
    let f = tmp("luau");
    let mut full = String::new();
    if let Some(k) = key {
        full.push_str(&format!("BASILISK_RUNTIME_KEY = \"{k}\"\n"));
    }
    full.push_str(artifact);
    std::fs::write(&f, full).unwrap();
    let o = Command::new(luau).arg(&f).output().expect("spawn luau");
    let _ = std::fs::remove_file(&f);
    String::from_utf8_lossy(&o.stdout).trim_end().to_string()
}

const EXPECT: &str = "RG-PROBE\t42\nRG-REAL\t4343";

#[test]
fn encfunc_nontrivial_leaf_with_vm_traps_known_failing_seeds() {
    let Some(luau) = find_luau() else { return };
    for seed in [31u64, 37] {
        let art = build(&source(), seed, true);
        assert_eq!(
            run(&luau, &art, Some(KEY)),
            EXPECT,
            "seed {seed} must materialize under vm_traps"
        );
    }
}

#[test]
fn encfunc_nontrivial_leaf_with_vm_traps_seed_sweep() {
    let Some(luau) = find_luau() else { return };
    for seed in 1u64..40 {
        let art = build(&source(), seed, true);
        assert_eq!(
            run(&luau, &art, Some(KEY)),
            EXPECT,
            "seed {seed} must materialize under vm_traps"
        );
    }
}

#[test]
fn encfunc_vm_traps_wrong_key_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let art = build(&source(), 31, true);
    let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let out = run(&luau, &art, Some(wrong));
    assert!(
        !out.contains("RG-REAL"),
        "wrong key must not materialize the sealed body: {out}"
    );
    assert!(
        !out.contains("unpack"),
        "wrong key must fail closed before deserialize, not crash: {out}"
    );
}

fn source_nested() -> String {
    format!(
        "if not BASIL_OBFUSCATED then\n\
         BASIL_ENCFUNC = function(fn, _, _) return fn end\n\
         end\n\
         local rk = BASILISK_RUNTIME_KEY\n\
         local f = BASIL_ENCFUNC(function(a, b)\n\
           local function helper(x) return x * 3 + 1 end\n\
           local s = 0\n\
           for i = 1, 30 do s = s + helper(a + i) - b end\n\
           return s\n\
         end, \"{KEY}\", rk)\n\
         print(\"RG-NEST\", f(4, 2))\n"
    )
}

#[test]
fn encfunc_nested_child_proto_with_vm_traps() {
    let Some(luau) = find_luau() else { return };
    for seed in [31u64, 37, 7, 13, 50] {
        let art = build(&source_nested(), seed, true);
        assert_eq!(
            run(&luau, &art, Some(KEY)),
            "RG-NEST\t1725",
            "nested seed {seed}"
        );
    }
}

#[test]
fn encfunc_baseline_no_vm_traps_unaffected() {
    let Some(luau) = find_luau() else { return };
    for seed in [31u64, 37, 7] {
        let art = build(&source(), seed, false);
        assert_eq!(run(&luau, &art, Some(KEY)), EXPECT, "baseline seed {seed}");
    }
}
