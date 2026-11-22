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
    "--experimental-ablate-fragment",
    "--hot-callback-policy",
    "report",
    "--vm-traps",
];

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_esf_{}_{}_{}.{ext}",
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

fn build(src: &str, seed: u64) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, src).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg(seed.to_string());
    cmd.args(PROD_FLAGS);
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

fn run(luau: &str, artifact: &str) -> String {
    run_key(luau, artifact, KEY)
}

fn run_key(luau: &str, artifact: &str, rt_key: &str) -> String {
    let f = tmp("luau");
    std::fs::write(
        &f,
        format!("BASILISK_RUNTIME_KEY = \"{rt_key}\"\n{artifact}"),
    )
    .unwrap();
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

fn handoff_src() -> String {
    format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(fn, _, _) return fn end end\n\
         local rk = BASILISK_RUNTIME_KEY\n\
         local log = function(n) print(\"RG-ENC/\"..n) end\n\
         local ax = BASIL_ENCFUNC(function(ax, ay, az, aA, aB, aC, aD)\n\
           aD(3)\n\
           if aA == nil or aA.wrapped == nil then\n\
             aC(az, ax, ay)\n\
             return {{ran = true}}\n\
           end\n\
           local d = aB(aA.execKey, aA.account, aA.license, aA.token, aA.sha, aA.wrapped)\n\
           if not d then aD(98) return {{ran = false}} end\n\
           aD(4)\n\
           aC(az, ax, ay, {{slot = aA.slot, key = d}})\n\
           d = nil\n\
           return {{ran = true}}\n\
         end, \"{KEY}\", rk)\n\
         log(2)\n\
         local r = ax(1, 2, 3, nil, function() end, function() end, log)\n\
         print(\"AX\", type(r), r and r.ran)\n"
    )
}

const HANDOFF_EXPECT: &str = "RG-ENC/2\nRG-ENC/3\nAX\ttable\ttrue";

#[test]
fn encfunc_handoff_exact_shape_known_failing_seeds() {
    let Some(luau) = find_luau() else { return };

    for seed in [1u64, 7, 13, 31, 42, 37, 50, 1337] {
        let art = build(&handoff_src(), seed);
        assert_eq!(
            run(&luau, &art),
            HANDOFF_EXPECT,
            "handoff seed {seed} must materialize under prod transforms"
        );
    }
}

#[test]
fn encfunc_handoff_seed_sweep() {
    let Some(luau) = find_luau() else { return };
    for seed in 1u64..=60 {
        let art = build(&handoff_src(), seed);
        assert_eq!(run(&luau, &art), HANDOFF_EXPECT, "handoff seed {seed}");
    }
}

#[test]
fn encfunc_handoff_wrong_key_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    for seed in [1u64, 7, 13, 42] {
        let art = build(&handoff_src(), seed);
        let out = run_key(&luau, &art, wrong);

        assert!(
            !out.contains("AX\ttable\ttrue"),
            "wrong key must not materialize the sealed body (seed {seed}): {out}"
        );
        assert!(
            !out.contains("RG-ENC/3"),
            "wrong key must not reach inside the sealed body (seed {seed}): {out}"
        );
    }
}

#[test]
fn encfunc_build_is_deterministic() {
    for seed in [1u64, 7, 42] {
        assert_eq!(
            build(&handoff_src(), seed),
            build(&handoff_src(), seed),
            "same seed must be byte-identical (seed {seed})"
        );
    }
}

fn arity_src(n: usize) -> String {
    let params: Vec<String> = (1..=n).map(|i| format!("p{i}")).collect();
    let plist = params.join(", ");
    let args: Vec<String> = (1..=n).map(|i| i.to_string()).collect();
    let alist = args.join(", ");
    format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(fn, _, _) return fn end end\n\
         local rk = BASILISK_RUNTIME_KEY\n\
         local f = BASIL_ENCFUNC(function({plist})\n\
           local t = {{a = \"execKey\", b = \"account\", c = \"license\", d = \"token\"}}\n\
           local s = \"\"\n\
           for _, v in pairs(t) do s = s .. tostring(v) end\n\
           return #s\n\
         end, \"{KEY}\", rk)\n\
         print(\"ARITY\", f({alist}))\n"
    )
}

#[test]
fn encfunc_arity_matrix_under_prod_transforms() {
    let Some(luau) = find_luau() else { return };

    for n in [0usize, 1, 2, 4, 7, 8] {
        for seed in [1u64, 7, 13, 42] {
            let art = build(&arity_src(n), seed);
            assert_eq!(run(&luau, &art), "ARITY\t26", "arity {n} seed {seed}");
        }
    }
}

#[test]
fn encfunc_nested_child_proto_under_prod_transforms() {
    let Some(luau) = find_luau() else { return };
    let src = format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(fn, _, _) return fn end end\n\
         local rk = BASILISK_RUNTIME_KEY\n\
         local f = BASIL_ENCFUNC(function(a, b, cb)\n\
           local function helper(x) return x * 3 + 1 end\n\
           local ok, r = pcall(cb, a, b)\n\
           local s = helper(a) + (ok and r or 0)\n\
           return s\n\
         end, \"{KEY}\", rk)\n\
         print(\"NEST\", f(4, 2, function(x, y) return x + y end))\n"
    );

    for seed in [1u64, 7, 13, 42, 37] {
        let art = build(&src, seed);
        assert_eq!(run(&luau, &art), "NEST\t19", "nested seed {seed}");
    }
}
