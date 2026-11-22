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
        "basil_vt_{}_{}_{}.{ext}",
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

fn build(src: &str, args: &[&str]) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, src).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp).arg(&out).arg("--no-interactive");
    for a in args {
        cmd.arg(a);
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

fn run(luau: &str, artifact: &str) -> String {
    let f = tmp("luau");
    std::fs::write(&f, artifact).unwrap();
    let o = Command::new(luau).arg(&f).output().expect("spawn luau");
    let _ = std::fs::remove_file(&f);
    String::from_utf8_lossy(&o.stdout).trim_end().to_string()
}

const CORPUS: &str = r#"
local function fib(n) if n < 2 then return n end return fib(n-1)+fib(n-2) end
local function mk(s) local c=s return function() c=c+1 return c end end
local mt={} mt.__index=function(_,k) return "idx:"..tostring(k) end
local function runit()
	local o={}
	for i=1,10 do o[#o+1]=fib(i) end
	local c=mk(100) for _=1,3 do o[#o+1]=c() end
	local obj=setmetatable({},mt) o[#o+1]=obj.zz
	local co=coroutine.wrap(function() for i=1,3 do coroutine.yield(i*i) end end)
	for _=1,3 do o[#o+1]=co() end
	return table.concat(o,",")
end
print(runit())
"#;

const EXPECT: &str = "1,1,2,3,5,8,13,21,34,55,101,102,103,idx:zz,1,4,9";

fn big_program() -> String {
    let mut s = String::from("local acc = 0\n");
    for i in 1..=1400 {
        s.push_str(&format!("acc = acc + {i} * 2 - {i}\n"));
    }
    s.push_str("print(acc)\n");
    s
}

#[test]
fn traps_on_preserves_behavior() {
    let Some(luau) = find_luau() else { return };
    let art = build(CORPUS, &["--vm-traps", "--seed", "777"]);
    assert_eq!(
        run(&luau, &art),
        EXPECT,
        "traps ON must not change program behavior"
    );
}

#[test]
fn traps_off_preserves_behavior() {
    let Some(luau) = find_luau() else { return };
    let art = build(CORPUS, &["--seed", "777"]);
    assert_eq!(run(&luau, &art), EXPECT);
}

#[test]
fn traps_change_the_artifact() {
    let on = build(CORPUS, &["--vm-traps", "--seed", "777"]);
    let off = build(CORPUS, &["--seed", "777"]);
    assert_ne!(
        on, off,
        "same seed: enabling traps must alter the emitted artifact"
    );
}

#[test]
fn off_build_carries_no_trap_code() {
    let off = build(CORPUS, &["--no-minify", "--seed", "777"]);
    assert!(
        !off.contains("_tmix"),
        "OFF build must not emit the trap diffuser"
    );
    assert!(
        !off.contains("proto[28]"),
        "OFF build must not carry the expected-chain slot"
    );
}

#[test]
fn page_chain_is_load_bearing() {
    let Some(luau) = find_luau() else { return };
    let art = build(CORPUS, &["--vm-traps", "--no-minify", "--seed", "777"]);
    assert_eq!(run(&luau, &art), EXPECT, "baseline must run");
    let tampered = art.replace(
        "(_tmix(bxor(acc, pd)) + k)",
        "(_tmix(bxor(acc, pd)) + k + 1)",
    );
    assert_ne!(tampered, art, "tamper substitution must apply");
    assert_eq!(
        run(&luau, &tampered),
        "",
        "divergent page chain must fail closed (no output)"
    );
}

#[test]
fn frame_canary_is_load_bearing() {
    let Some(luau) = find_luau() else { return };
    let art = build(CORPUS, &["--vm-traps", "--no-minify", "--seed", "777"]);
    let tampered = art.replace(
        "local _tv = { _tcan(proto[5]) }",
        "local _tv = { _tcan(proto[5]) + 1 }",
    );
    assert_ne!(tampered, art, "canary tamper substitution must apply");
    assert_eq!(
        run(&luau, &tampered),
        "",
        "corrupted frame canary must fail closed"
    );
}

#[test]
fn multipage_root_with_traps_is_correct() {
    let Some(luau) = find_luau() else { return };
    let prog = big_program();
    let art = build(&prog, &["--vm-traps", "--seed", "777"]);
    let plain = {
        let f = tmp("luau");
        std::fs::write(&f, &prog).unwrap();
        let o = Command::new(&luau).arg(&f).output().unwrap();
        let _ = std::fs::remove_file(&f);
        String::from_utf8_lossy(&o.stdout).trim_end().to_string()
    };
    assert_eq!(
        run(&luau, &art),
        plain,
        "multi-page root cross-page chain must stay correct"
    );
}

#[test]
fn per_build_diversity_of_trap_constants() {
    let a = build(CORPUS, &["--vm-traps", "--no-minify", "--seed", "111"]);
    let b = build(CORPUS, &["--vm-traps", "--no-minify", "--seed", "222"]);
    let grab = |s: &str| -> String {
        s.lines()
            .find(|l| l.contains("local a = bxor(x, lrotate(x,"))
            .unwrap_or("")
            .to_string()
    };
    assert_ne!(
        grab(&a),
        grab(&b),
        "trap diffuser shape must vary per build seed"
    );
}
