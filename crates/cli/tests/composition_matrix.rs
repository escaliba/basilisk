use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);
const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_cm_{}_{}_{}.{ext}",
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

struct Fixture {
    name: &'static str,
    src: String,
}

struct Combo {
    name: &'static str,
    flags: Vec<&'static str>,
}

fn fixtures() -> Vec<Fixture> {
    let enc_stub = "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(fn) return fn end BASIL_ENCSTR = function(s) return s end BASIL_ENCBUF = function(s) return buffer.fromstring(s) end end\n";
    vec![
        Fixture {
            name: "a_trivial",
            src: "local a, b = 6, 7 local c = a * b - 2 print(\"RESULT:\" .. c)\n".into(),
        },
        Fixture {
            name: "b_const_heavy",
            src: "local w = {\"alpha\",\"beta\",\"gamma\",\"delta\",\"alpha\",\"beta\"} local s = 0 for i = 1, #w do s = s + #w[i] end local ints = 0 for i = 1, 20 do ints = ints + i end local d = 3.5 * 2 + 0.25 print(\"RESULT:\" .. s .. \":\" .. ints .. \":\" .. d)\n".into(),
        },
        Fixture {
            name: "c_control_flow",
            src: "local acc = 0 for i = 1, 30 do if i % 3 == 0 then acc = acc + i elseif i % 2 == 0 then acc = acc - 1 else acc = acc + 2 end end local function early(n) for i = 1, n do if i == 5 then return i * 10 end end return -1 end print(\"RESULT:\" .. acc .. \":\" .. early(9))\n".into(),
        },
        Fixture {
            name: "d_calling",
            src: "local function vsum(...) local s = 0 for _, v in ipairs({...}) do s = s + v end return s, select(\"#\", ...) end local function app(f, a, b) return f(a, b) end local total, n = vsum(1, 2, 3, 4) local m = app(function(x, y) return x * y end, 6, 7) local ok = pcall(function() error(\"boom\") end) print(\"RESULT:\" .. total .. \":\" .. n .. \":\" .. m .. \":\" .. tostring(ok))\n".into(),
        },
        Fixture {
            name: "e_proto_closure",
            src: "local function counter(start) local n = start return function() n = n + 1 return n end end local c = counter(10) local a = c() + c() + c() local function outer(x) local function inner(y) return x + y end return inner(5) end print(\"RESULT:\" .. a .. \":\" .. outer(100))\n".into(),
        },
        Fixture {
            name: "f_table_meta",
            src: "local base = { greet = \"hi\" } local t = setmetatable({ a = 1, b = 2, nested = { x = 10, y = 20 } }, { __index = base }) t.a = t.a + 5 local sum = t.a + t.b + t.nested.x + t.nested.y print(\"RESULT:\" .. sum .. \":\" .. t.greet)\n".into(),
        },
        Fixture {
            name: "g_protected",
            src: format!(
                "{enc_stub}local rk = BASILISK_RUNTIME_KEY local f = BASIL_ENCFUNC(function(a, b) return a + b end, \"{KEY}\", rk) local s = BASIL_ENCSTR(\"secret-template\") local bf = BASIL_ENCBUF(\"\\1\\2\\3\\255\") print(\"RESULT:\" .. f(40, 2) .. \":\" .. s .. \":\" .. buffer.len(bf))\n"
            ),
        },
        Fixture {
            name: "h_sentinel_like",
            src: format!(
                "{enc_stub}local rk = BASILISK_RUNTIME_KEY\n\
                 local handoff = BASIL_ENCFUNC(function(p1, p2, p3, cb, validate, log, finish)\n\
                 \tlocal cfg = {{ execKey = \"K-7731\", account = \"acc-55\", license = \"LIC-9F3A\", token = \"tok_x\", slot = 3 }}\n\
                 \tlocal function derive(k) local h = 0 for i = 1, #k do h = (h * 31 + string.byte(k, i)) % 1000000007 end return h end\n\
                 \tlog(1)\n\
                 \tlocal ok, res = pcall(validate, cfg.execKey, cfg.token)\n\
                 \tif not ok or not res then finish(0) return {{ ran = false, h = 0, slot = 0 }} end\n\
                 \tlocal total = 0\n\
                 \tfor _, key in ipairs({{ cfg.execKey, cfg.account, cfg.license, cfg.token }}) do total = total + derive(key) end\n\
                 \tcb(p1, p2, p3, cfg.slot)\n\
                 \tfinish(total % 997)\n\
                 \treturn {{ ran = true, h = total % 997, slot = cfg.slot }}\n\
                 end, \"{KEY}\", rk)\n\
                 local sink = 0\n\
                 local r = handoff(1, 2, 3, function(a, b, c, slot) sink = a + b + c + slot end, function(k, t) return #k > 0 and #t > 0 end, function(n) sink = sink + n end, function(n) sink = sink + n * 1000 end)\n\
                 print(\"RESULT:\" .. tostring(r.ran) .. \":\" .. r.h .. \":\" .. r.slot .. \":\" .. sink)\n"
            ),
        },
    ]
}

const PROD_STACK: &[&str] = &[
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
    "--vm-traps",
];

fn combos() -> Vec<Combo> {
    vec![
        Combo {
            name: "baseline",
            flags: vec![],
        },
        Combo {
            name: "prod_stack",
            flags: PROD_STACK.to_vec(),
        },
        Combo {
            name: "vm_traps",
            flags: vec!["--vm-traps"],
        },
        Combo {
            name: "sem_family",
            flags: vec!["--experimental-semantic-family"],
        },
        Combo {
            name: "instr_family",
            flags: vec!["--experimental-instruction-family"],
        },
        Combo {
            name: "sem_x_instr",
            flags: vec![
                "--experimental-semantic-family",
                "--experimental-instruction-family",
            ],
        },
        Combo {
            name: "framing",
            flags: vec!["--experimental-stateful-framing"],
        },
        Combo {
            name: "d1_x_sem",
            flags: vec![
                "--experimental-stateful-recovery",
                "--experimental-semantic-family",
            ],
        },
        Combo {
            name: "frame_const_reuse",
            flags: vec!["--experimental-frame-const-reuse", "all"],
        },
        Combo {
            name: "poly_aggressive",
            flags: vec!["--poly-stream", "aggressive"],
        },
    ]
}

fn result_marker(out: &str) -> Option<String> {
    out.lines()
        .find(|l| l.starts_with("RESULT:"))
        .map(|l| l.to_string())
}

fn oracle(luau: &str, fx: &Fixture) -> String {
    let f = tmp("luau");
    std::fs::write(&f, format!("BASILISK_RUNTIME_KEY = \"{KEY}\"\n{}", fx.src)).unwrap();
    let o = Command::new(luau).arg(&f).output().expect("spawn luau");
    let _ = std::fs::remove_file(&f);
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    result_marker(&out).unwrap_or_else(|| {
        panic!(
            "fixture {} has no RESULT under the unobfuscated oracle: {out}",
            fx.name
        )
    })
}

fn build(fx: &Fixture, combo: &Combo, seed: u64) -> String {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, &fx.src).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg(seed.to_string());
    cmd.args(&combo.flags);
    cmd.env("BASIL_DIRECT_WRITES", "1");
    let o = cmd.output().expect("spawn basilisk");
    assert!(
        o.status.success(),
        "{} / {} / seed {seed}: build failed: {}",
        fx.name,
        combo.name,
        String::from_utf8_lossy(&o.stderr)
    );
    let art = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_file(&inp);
    let _ = std::fs::remove_file(&out);
    art
}

fn run(luau: &str, artifact: &str) -> String {
    let pre = format!("BASILISK_RUNTIME_KEY = \"{KEY}\"\n");
    let f = tmp("luau");
    std::fs::write(&f, format!("{pre}{artifact}")).unwrap();
    let o = Command::new(luau).arg(&f).output().expect("spawn luau");
    let _ = std::fs::remove_file(&f);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn repro(fx: &Fixture, combo: &Combo, seed: u64) -> String {
    format!(
        "fixture={} combo={} seed={}\n  repro: BASIL_DIRECT_WRITES=1 basilisk <{}> out.luau --no-interactive --seed {} {}",
        fx.name, combo.name, seed,
        fx.name, seed, combo.flags.join(" "),
    )
}

fn fast_seeds() -> Vec<u64> {
    vec![1, 7, 13, 31, 37, 42, 50, 1337]
}

fn seed_tier() -> Vec<u64> {
    if std::env::var("BASIL_COMPOSITION_DEEP").is_ok() {
        (1..=256).collect()
    } else if std::env::var("BASIL_COMPOSITION_PREMERGE").is_ok() {
        (1..=64).collect()
    } else {
        fast_seeds()
    }
}

fn check(luau: &str, fx: &Fixture, combo: &Combo, seed: u64, oracle: &str) {
    let art = build(fx, combo, seed);
    let out = run(luau, &art);
    let got = result_marker(&out);
    assert_eq!(
        got.as_deref(),
        Some(oracle),
        "semantic mismatch\n{}\n  expected {oracle}\n  actual   {got:?}\n  raw: {}",
        repro(fx, combo, seed),
        out.trim_end()
    );
}

#[test]
fn composition_semantic_matrix() {
    let Some(luau) = find_luau() else { return };
    let start = Instant::now();
    let fxs = fixtures();
    let cbs = combos();
    let seeds = seed_tier();
    let full = std::env::var("BASIL_COMPOSITION_PREMERGE").is_ok()
        || std::env::var("BASIL_COMPOSITION_DEEP").is_ok();
    let protected = ["g_protected", "h_sentinel_like"];
    let baseline_combos = ["baseline", "prod_stack"];

    let dangerous = [
        "prod_stack",
        "vm_traps",
        "sem_family",
        "instr_family",
        "sem_x_instr",
        "framing",
        "d1_x_sem",
        "frame_const_reuse",
    ];
    let mut cases = 0u32;

    for fx in &fxs {
        let oracle = oracle(&luau, fx);
        for cb in &cbs {
            let run_it = baseline_combos.contains(&cb.name)
                || (protected.contains(&fx.name) && dangerous.contains(&cb.name));
            if !run_it {
                continue;
            }
            let case_seeds: Vec<u64> = if full {
                seeds.clone()
            } else if protected.contains(&fx.name) {
                fast_seeds()
            } else {
                vec![7, 31]
            };
            for &seed in &case_seeds {
                check(&luau, fx, cb, seed, &oracle);
                cases += 1;
            }
        }
    }
    eprintln!(
        "composition_semantic_matrix: {cases} cases in {:?} (tier={})",
        start.elapsed(),
        if full { "full" } else { "fast" }
    );
}

mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 24, failure_persistence: None, ..ProptestConfig::default() })]
        #[test]
        fn prop_feature_vectors_preserve_torture_semantics(
            vmt in any::<bool>(), sem in any::<bool>(), instr in any::<bool>(),
            framing in any::<bool>(), fcr in any::<bool>(), poly in any::<bool>(),
            seed in 1u64..=256,
        ) {
            if std::env::var("BASIL_COMPOSITION_PROPTEST").is_err() {
                return Ok(());
            }
            let Some(luau) = find_luau() else { return Ok(()); };
            let mut flags: Vec<&'static str> = Vec::new();
            if vmt { flags.push("--vm-traps"); }
            if sem { flags.push("--experimental-semantic-family"); }
            if instr { flags.push("--experimental-instruction-family"); }
            if framing { flags.push("--experimental-stateful-framing"); }
            if fcr { flags.push("--experimental-frame-const-reuse"); flags.push("all"); }
            if poly { flags.push("--poly-stream"); flags.push("aggressive"); }
            let combo = Combo { name: "proptest", flags };
            let fxs = fixtures();
            let torture = fxs.iter().find(|f| f.name == "h_sentinel_like").unwrap();
            let want = oracle(&luau, torture);
            let art = build(torture, &combo, seed);
            let got = result_marker(&run(&luau, &art));
            prop_assert_eq!(
                got.as_deref(), Some(want.as_str()),
                "PROPTEST FAILURE (promote to the deterministic matrix): fixture=h_sentinel_like seed={} flags={:?}",
                seed, combo.flags
            );
        }
    }
}
