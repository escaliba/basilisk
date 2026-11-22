use std::path::{Path, PathBuf};
use std::process::Command;

const KNOWN_DIVERGENCES: &[&str] = &["setfenv.luau"];

#[derive(Debug, PartialEq)]
struct Run {
    stdout: String,
    code: Option<i32>,
}

fn run_luau(bin: &str, path: &Path) -> Run {
    let output = Command::new(bin)
        .arg(path)
        .output()
        .expect("failed to spawn luau");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        code: output.status.code(),
    }
}

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    match Command::new("luau").arg("--help").output() {
        Ok(_) => Some("luau".to_string()),
        Err(_) => None,
    }
}

fn corpus_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading corpus dir {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "luau"))
        .collect();
    files.sort();
    files
}

const FLATTEN_SEED: u64 = 0x_B451_115C;

#[test]
fn corpus_virtualizes() {
    run_corpus("virtualize", |s| {
        pipeline::virtualize_with(
            s,
            FLATTEN_SEED,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
        )
    });
}

#[test]
fn corpus_virtualizes_flattened() {
    run_corpus("virtualize+flatten", |s| {
        pipeline::virtualize_with(
            s,
            FLATTEN_SEED,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
        )
    });
}

#[test]
fn corpus_virtualizes_opaque() {
    run_corpus("virtualize+opaque", |s| {
        pipeline::virtualize_with(
            s,
            FLATTEN_SEED,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
        )
    });
}

#[test]
fn corpus_virtualizes_junk() {
    run_corpus("virtualize+junk", |s| {
        pipeline::virtualize_with(
            s,
            FLATTEN_SEED,
            false,
            true,
            false,
            false,
            true,
            false,
            false,
        )
    });
}

#[test]
fn corpus_virtualizes_fused() {
    run_corpus("virtualize+fuse", |s| {
        pipeline::virtualize_with(
            s,
            FLATTEN_SEED,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
        )
    });
}

#[test]
fn corpus_virtualizes_all_passes() {
    run_corpus("virtualize+flatten+junk+opaque+fuse", |s| {
        pipeline::virtualize_with(s, FLATTEN_SEED, true, true, true, true, true, false, false)
    });
}

#[test]
fn corpus_unminified() {
    run_corpus("virtualize+all+no-minify", |s| {
        pipeline::virtualize_with(s, FLATTEN_SEED, true, true, true, true, false, false, false)
    });
}

#[test]
fn corpus_strip_source_names() {
    run_corpus("virtualize+all+strip-source-names", |s| {
        pipeline::virtualize_full_line(
            s,
            FLATTEN_SEED,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
            false,
            pipeline::SensitiveOpts::default(),
            pipeline::TargetProfile::CliTest,
            false,
            false,
            true,
            true,
        )
    });
}

fn build_strip(src: &str, seed: u64, strip: bool) -> String {
    pipeline::virtualize_full_line(
        src,
        seed,
        true,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        pipeline::TargetProfile::CliTest,
        false,
        false,
        true,
        strip,
    )
    .unwrap()
}

#[test]
fn strip_source_names_removes_native_local_names() {
    let src = "\
if not BASIL_OBFUSCATED then function BASIL_NO_VIRTUALIZE(f) return f end end
local run = BASIL_NO_VIRTUALIZE(function(secretParamXyz)
    local hiddenLocalXyz = secretParamXyz + 1
    return hiddenLocalXyz
end)
print(run(1))
";
    let with = build_strip(src, 0x51D, true);
    let without = build_strip(src, 0x51D, false);
    assert!(
        !with.contains("secretParamXyz") && !with.contains("hiddenLocalXyz"),
        "strip on must remove native local/param names from the emitted native body"
    );
    assert!(
        without.contains("secretParamXyz") && without.contains("hiddenLocalXyz"),
        "strip off must preserve native names — proves the sanitizer is the thing removing them"
    );
}

#[test]
fn strip_source_names_is_artifact_neutral_for_fully_virtualized_code() {
    let src = "local secretLocalAbc = 5\nlocal function fooBarBaz(x) return x + secretLocalAbc end\nprint(fooBarBaz(1))\n";
    let with = build_strip(src, 0xA11CE, true);
    let without = build_strip(src, 0xA11CE, false);
    assert_eq!(
        with, without,
        "virtualized code discards local names via register allocation; strip is a no-op on bytes"
    );
    assert!(
        !with.contains("secretLocalAbc") && !with.contains("fooBarBaz"),
        "and the names are absent either way"
    );
}

const IDENTIFIER_LEAK_FIXTURE: &str = "\
if not BASIL_OBFUSCATED then
    function BASIL_NO_VIRTUALIZE(f) return f end
end

local internalAuthState = { count = 0 }

local decryptSessionTicket = BASIL_NO_VIRTUALIZE(function(nativeSecretSeed)
    local nativeHiddenAcc = nativeSecretSeed * 3
    return nativeHiddenAcc + 1
end)

local function validateWhitelistToken(secretUserId)
    internalAuthState.count = internalAuthState.count + 1
    local whitelistDecision = (secretUserId % 2 == 0)
    return whitelistDecision
end

local publicApi = {}

function publicApi.run()
    local ticketSum = decryptSessionTicket(5)
    local allowed = validateWhitelistToken(42)
    return { ticketSum = ticketSum, allowed = allowed, authCount = internalAuthState.count }
end

local result = publicApi.run()
print(result.ticketSum, tostring(result.allowed), result.authCount)
";

fn executor_artifact(strip: bool) -> String {
    pipeline::virtualize_full_line(
        IDENTIFIER_LEAK_FIXTURE,
        FLATTEN_SEED,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        pipeline::TargetProfile::Executor,
        false,
        false,
        false,
        strip,
    )
    .unwrap()
}

#[test]
fn executor_release_artifact_leaks_no_source_identifiers() {
    let artifact = executor_artifact(true);
    let sensitive = [
        "internalAuthState",
        "decryptSessionTicket",
        "nativeSecretSeed",
        "nativeHiddenAcc",
        "validateWhitelistToken",
        "secretUserId",
        "whitelistDecision",
        "publicApi",
        "ticketSum",
    ];
    for id in sensitive {
        assert!(
            !artifact.contains(id),
            "executor release artifact leaked source identifier `{id}`"
        );
    }
    let unstripped = executor_artifact(false);
    assert!(
        unstripped.contains("nativeSecretSeed") && unstripped.contains("nativeHiddenAcc"),
        "native local names must leak with strip off, else this guard is vacuous"
    );
}

const SEEDS: &[u64] = &[
    FLATTEN_SEED,
    0x1,
    0xDEAD_BEEF,
    0x0F0F_0F0F_0F0F_0F0F,
    0xA5A5_5A5A,
];

#[test]
fn corpus_multi_seed_all_paths() {
    for &seed in SEEDS {
        for compress in [false, true] {
            for (name, flatten, junk, opaque, fuse) in [
                ("plain", false, false, false, false),
                ("flatten", true, false, false, false),
                ("opaque", false, false, true, false),
                ("junk", false, true, false, false),
                ("fuse", false, false, false, true),
                ("all", true, true, true, true),
            ] {
                run_corpus(
                    &format!("seed={seed:#018x} {name} compress={compress}"),
                    |s| {
                        pipeline::virtualize_with(
                            s, seed, flatten, junk, opaque, fuse, true, compress, false,
                        )
                    },
                );
            }
        }
    }
}

#[test]
fn corpus_lph_collapse() {
    for &seed in SEEDS {
        run_corpus(&format!("lph-collapse seed={seed:#018x}"), |s| {
            pipeline::virtualize_full_prof(
                s,
                seed,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Off,
                false,
                pipeline::SensitiveOpts::default(),
                pipeline::TargetProfile::CliTest,
                false,
                true,
            )
        });
    }
}

#[test]
fn corpus_multi_seed_hard_dispatch() {
    for &seed in SEEDS {
        for compress in [false, true] {
            run_corpus(
                &format!("seed={seed:#018x} all hard_dispatch compress={compress}"),
                |s| {
                    pipeline::virtualize_full(
                        s,
                        seed,
                        true,
                        true,
                        true,
                        true,
                        true,
                        compress,
                        false,
                        true,
                        false,
                        pipeline::SurfaceVolume::Off,
                    )
                },
            );
        }
    }
}

#[test]
fn corpus_multi_seed_lura_surface() {
    for &seed in SEEDS {
        for compress in [false, true] {
            run_corpus(
                &format!("seed={seed:#018x} all hard_dispatch lura_surface compress={compress}"),
                |s| {
                    pipeline::virtualize_full(
                        s,
                        seed,
                        true,
                        true,
                        true,
                        true,
                        true,
                        compress,
                        false,
                        true,
                        true,
                        pipeline::SurfaceVolume::Off,
                    )
                },
            );
        }
    }
}

#[test]
fn corpus_multi_seed_basil_heavy() {
    for &seed in SEEDS {
        for compress in [false, true] {
            run_corpus(
                &format!("seed={seed:#018x} basil_heavy small compress={compress}"),
                |s| {
                    pipeline::virtualize_full(
                        s,
                        seed,
                        true,
                        true,
                        true,
                        true,
                        true,
                        compress,
                        false,
                        true,
                        false,
                        pipeline::SurfaceVolume::Small,
                    )
                },
            );
        }
    }
}

#[test]
fn return_value_propagates_through_the_vm() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping return-value test");
        return;
    };
    let source =
        "local t = {}\nfor i = 1, 3 do t[i] = i * i end\nreturn 42, \"hello\", true, t[2] + t[3]\n";
    let orig = capture_chunk_return(&luau, source, "rv_orig");
    assert!(
        orig.starts_with("4:"),
        "mechanism sanity: expected 4 returned values, got {orig:?}"
    );
    for compress in [false, true] {
        let obf = pipeline::virtualize_with(
            source,
            FLATTEN_SEED,
            true,
            true,
            true,
            true,
            true,
            compress,
            false,
        )
        .expect("virtualize value-returning script");
        let got = capture_chunk_return(&luau, &obf, "rv_obf");
        assert_eq!(
            orig, got,
            "compress={compress}: virtualized chunk must return the same values"
        );
    }
}

#[test]
fn large_payload_compress_round_trips() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping large compress round-trip");
        return;
    };

    let mut src = String::from("local fns = {}\n");
    for i in 0..800 {
        src.push_str(&format!(
            "fns[{}] = function(x)\nlocal t = {{a = x, b = x + {i}, name = \"key_{i}\"}}\nlocal s = 0\nfor j = 1, 8 do s = s + t.a * j - t.b end\nreturn s\nend\n",
            i + 1
        ));
    }
    src.push_str("local total = 0\n");
    for i in 0..800 {
        src.push_str(&format!("total = total + fns[{}]({i})\n", i + 1));
    }
    src.push_str("print(total)\n");
    let obf = pipeline::virtualize_with(
        &src,
        FLATTEN_SEED,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
    )
    .expect("virtualize large script with --compress");
    let orig_tmp = std::env::temp_dir().join("basilisk_large_orig.luau");
    let obf_tmp = std::env::temp_dir().join("basilisk_large_compress.luau");
    std::fs::write(&orig_tmp, &src).unwrap();
    std::fs::write(&obf_tmp, &obf).unwrap();
    assert_eq!(
        run_luau(&luau, &orig_tmp),
        run_luau(&luau, &obf_tmp),
        "large --compress build must match the original (forces width-bumps + freeze)"
    );
}

#[test]
fn compress_guard_selects_smaller_and_kept_compressed_decodes() {
    let src = "print(\"hi\")\n";
    let mut winning: Option<(u64, String)> = None;
    for seed in 1u64..=96 {
        let raw =
            pipeline::virtualize_with(src, seed, false, false, false, false, true, false, false)
                .unwrap();
        let with =
            pipeline::virtualize_with(src, seed, false, false, false, false, true, true, false)
                .unwrap();
        assert!(
            with.len() <= raw.len(),
            "seed={seed}: --compress must never inflate past the compress-off artifact"
        );
        assert!(
            with == raw || with.len() < raw.len(),
            "seed={seed}: --compress is either the raw fallback (byte-identical) or a strictly-smaller compressed artifact"
        );
        if with.len() < raw.len() && winning.is_none() {
            winning = Some((seed, with));
        }
    }
    let Some(luau) = find_luau() else {
        println!(
            "luau not found; skipping compressed-decode check (guard invariant already verified)"
        );
        return;
    };
    match winning {
        Some((seed, artifact)) => {
            let src_tmp = unique_tmp("cg_src");
            let art_tmp = unique_tmp("cg_art");
            std::fs::write(&src_tmp, src).unwrap();
            std::fs::write(&art_tmp, &artifact).unwrap();
            assert_eq!(
                run_luau(&luau, &src_tmp),
                run_luau(&luau, &art_tmp),
                "seed={seed}: the kept-compressed artifact must still decode to the original behavior"
            );
        }
        None => println!("no compressed win in seed range; guard invariant verified, decode path not exercised this run"),
    }
}

#[test]
fn compress_guard_raw_fallback_is_byte_identical_to_compress_off() {
    let mut src = String::from("local t = {}\n");
    for i in 0..600 {
        src.push_str(&format!("t[{}] = {i} + {}\n", i + 1, i * 3));
    }
    src.push_str("print(#t)\n");
    for seed in [0x1234_5678u64, 0xCAFE_BABE, 7] {
        let raw =
            pipeline::virtualize_with(&src, seed, true, false, true, true, true, false, false)
                .unwrap();
        let with =
            pipeline::virtualize_with(&src, seed, true, false, true, true, true, true, false)
                .unwrap();
        assert_eq!(with, raw, "seed={seed:#x}: this inflating payload must fall back to a byte-identical compress-off artifact");
    }
}

fn capture_chunk_return(luau: &str, code: &str, tag: &str) -> String {
    let wrapper = format!(
        "local f = assert(loadstring({}))\nlocal r = table.pack(f())\nlocal p = {{}}\nfor i = 1, r.n do p[i] = tostring(r[i]) end\nprint(r.n .. \":\" .. table.concat(p, \"|\"))\n",
        luau_quote(code)
    );
    let tmp = std::env::temp_dir().join(format!("basilisk_{tag}.luau"));
    std::fs::write(&tmp, wrapper).unwrap();
    let out = Command::new(luau)
        .arg(&tmp)
        .output()
        .expect("run luau wrapper");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn luau_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2 + 2);
    out.push('"');
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03}")),
        }
    }
    out.push('"');
    out
}

fn run_code(luau: &str, code: &str, tag: &str) -> Run {
    let tmp = std::env::temp_dir().join(format!("basilisk_{tag}.luau"));
    std::fs::write(&tmp, code).unwrap();
    run_luau(luau, &tmp)
}

#[test]
fn constant_cache_still_fails_closed_on_tamper() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping tamper test");
        return;
    };

    let src = "local t = 0\nfor i = 1, 5 do t = t + 7 end\nprint(t)\n";
    let obf = pipeline::virtualize_with(
        src,
        FLATTEN_SEED,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
    )
    .expect("virtualize");
    assert_eq!(
        run_code(&luau, &obf, "cache_clean").stdout.trim(),
        "35",
        "clean cached build must compute 35"
    );

    let open = obf.find("[==[").expect("payload open") + 4;
    let close = obf[open..].find("]==]").expect("payload close") + open;
    let mid = (open + close) / 2;
    let mut bytes = obf.into_bytes();
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();

    let out = run_code(&luau, &tampered, "cache_tampered");
    assert_ne!(
        out.stdout.trim(),
        "35",
        "tampered payload must fail closed — the cache must not serve unverified plaintext"
    );
}

#[test]
fn flat_block_memo_fails_closed_on_tamper() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping memo tamper test");
        return;
    };

    let src = "local function f(x)\n\tlocal r=0\n\tif x%2==0 then r=r+1 else r=r+3 end\n\tif x%3==0 then r=r+5 else r=r+7 end\n\tif x%5==0 then r=r+11 else r=r+13 end\n\tif x%7==0 then r=r+17 else r=r+19 end\n\tif x%11==0 then r=r+23 else r=r+29 end\n\treturn r\nend\nlocal s=0\nfor i=1,50 do s=s+f(i) end\nprint(s)\n";
    let clean = pipeline::virtualize_with(
        src,
        FLATTEN_SEED,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
    )
    .expect("virtualize");
    let expected = run_code(&luau, &clean, "memo_clean")
        .stdout
        .trim()
        .to_string();
    let raw = run_code(&luau, src, "memo_raw").stdout.trim().to_string();
    assert_eq!(
        expected, raw,
        "clean flattened build with the block-id memo must match the raw run"
    );

    let open = clean.find("[==[").expect("payload open") + 4;
    let close = clean[open..].find("]==]").expect("payload close") + open;
    let mid = (open + close) / 2;
    let mut bytes = clean.into_bytes();
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    let out = run_code(&luau, &tampered, "memo_tampered");
    assert_ne!(
        out.stdout.trim(),
        expected,
        "tampered flattened payload must fail closed — the block-id memo must not serve an unverified routing token"
    );
}

#[test]
fn env_log_hook_fails_closed() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping env-log hook test");
        return;
    };
    let src = "local t = 0\nfor i = 1, 5 do t = t + 7 end\nprint(t)\n";
    for compress in [false, true] {
        let obf = pipeline::virtualize_with(
            src,
            FLATTEN_SEED,
            true,
            true,
            true,
            true,
            true,
            compress,
            false,
        )
        .expect("virtualize");
        assert_eq!(
            run_code(&luau, &obf, "envlog_clean").stdout.trim(),
            "35",
            "unhooked build must compute 35"
        );
        let hooked = format!("local _p = print\nprint = function(...) return _p(...) end\n{obf}");
        assert_ne!(
            run_code(&luau, &hooked, "envlog_hooked").stdout.trim(),
            "35",
            "a hooked print must derive a wrong key and fail closed (compress={compress})"
        );
    }
}

#[test]
fn crash_fires_and_does_not_recover() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping crash-fire test");
        return;
    };
    let src = "BASIL_CRASH()\nprint(\"RECOVERED\")\n";
    let obf = pipeline::virtualize_with(
        src,
        FLATTEN_SEED,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .expect("virtualize");
    let tmp = std::env::temp_dir().join("basilisk_crash_fire.luau");
    std::fs::write(&tmp, &obf).unwrap();

    let mut child = Command::new(&luau)
        .arg(&tmp)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn luau");
    let mut waited_ms = 0;
    let exited_on_its_own = loop {
        match child.try_wait().unwrap() {
            Some(_) => break true,
            None if waited_ms >= 2000 => break false,
            None => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                waited_ms += 100;
            }
        }
    };
    if !exited_on_its_own {
        let _ = child.kill();
    }
    let stdout = String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned();
    assert!(
        exited_on_its_own,
        "a firing BASIL_CRASH must terminate fail-closed, not hang; see docs/BASIL_CRASH.md"
    );
    assert!(
        !stdout.contains("RECOVERED"),
        "the crash must prevent post-crash code from running"
    );
}

#[test]
fn integrity_poison_denies_recovery_even_if_dead_is_stubbed() {
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping integrity-poison test");
        return;
    };
    let run = |src: &str, name: &str| -> String {
        let p = std::env::temp_dir().join(format!("basilisk_{name}.luau"));
        std::fs::write(&p, src).unwrap();
        run_luau(&luau, &p).stdout
    };
    let src =
        "local a = \"ALPHA_MARKER_AAAA\"\nlocal b = \"BETA_MARKER_BBBB\"\nprint(a)\nprint(b)\n";
    let obf = pipeline::virtualize_with(
        src,
        FLATTEN_SEED,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
    .expect("virtualize");
    let clean = run(&obf, "poison_clean");
    assert!(
        clean.contains("ALPHA_MARKER_AAAA") && clean.contains("BETA_MARKER_BBBB"),
        "clean build must run"
    );

    let mut attack = obf.replace("dead = true", "dead = false");
    assert_ne!(
        attack, obf,
        "the dead flag must have been present to neutralize"
    );
    let open = attack.find("[==[").expect("payload block") + 4;
    let close = attack[open..].find("]==]").expect("payload close") + open;
    let mut i = (open + close) / 2;
    while !attack.as_bytes()[i].is_ascii_alphanumeric() {
        i += 1;
    }
    let c = if attack.as_bytes()[i] == b'Q' {
        b'R'
    } else {
        b'Q'
    };
    unsafe {
        attack.as_bytes_mut()[i] = c;
    }
    let recovered = run(&attack, "poison_attack");
    assert!(
        !(recovered.contains("ALPHA_MARKER_AAAA") && recovered.contains("BETA_MARKER_BBBB")),
        "stubbing `dead` must NOT recover a tampered build — the accumulator poison cascades"
    );
}

fn run_corpus(label: &str, build: impl Fn(&str) -> anyhow::Result<String>) {
    let files = corpus_files();
    assert!(!files.is_empty(), "no corpus files found");
    let Some(luau) = find_luau() else {
        println!("luau not found; skipping {label} behavioral tests (set LUAU_BIN)");
        return;
    };

    let mut failures: Vec<String> = Vec::new();
    println!("\n== Basilisk {label} corpus ==");

    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let known = KNOWN_DIVERGENCES.contains(&name.as_str());
        let source = std::fs::read_to_string(file).unwrap();

        let produced_src = match build(&source) {
            Ok(v) => v,
            Err(e) => {
                println!("  {name:28} compile:FAIL");
                failures.push(format!("[{name}] {label} failed: {e}"));
                continue;
            }
        };
        let original = run_luau(&luau, file);
        let tmp = std::env::temp_dir().join(format!("basilisk_{}_{name}", label.replace('+', "_")));
        std::fs::write(&tmp, &produced_src).unwrap();
        let produced = run_luau(&luau, &tmp);
        let matches = original == produced;

        if known {
            println!(
                "  {name:28} behavioral:{} (known divergence)",
                if matches { "ok" } else { "diverges" }
            );
            continue;
        }
        println!(
            "  {name:28} behavioral:{}",
            if matches { "ok" } else { "FAIL" }
        );
        if !matches {
            failures.push(format!(
                "[{name}] behavioral mismatch\n--- original ---\n{original:?}\n--- produced ---\n{produced:?}"
            ));
        }
    }

    println!(
        "== {} script(s), {} known divergence(s), {} failure(s) ==\n",
        files.len(),
        KNOWN_DIVERGENCES.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{label} failures:\n\n{}",
        failures.join("\n\n")
    );
}

const ENCFUNC_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn enc_external(body: &str) -> String {
    format!(
        "if not BASIL_OBFUSCATED then\n\
         BASIL_ENCFUNC = function(fn, _, _) return fn end\n\
         BASIL_HASH = function(s) return s end\n\
         BASIL_OPAQUE = function(v) return v end\n\
         BASIL_CRASH = function() end\n\
         end\n\
         local rk = BASILISK_RUNTIME_KEY\n{body}\n"
    )
}

fn run_injected(luau: &str, name: &str, content: &str, key: Option<&str>) -> Run {
    let mut full = String::new();
    if let Some(k) = key {
        full.push_str(&format!("BASILISK_RUNTIME_KEY = \"{k}\"\n"));
    }
    full.push_str(content);
    let p = std::env::temp_dir().join(name);
    std::fs::write(&p, full).unwrap();
    run_luau(luau, &p)
}

fn enc_samples() -> Vec<(&'static str, String)> {
    let k = ENCFUNC_KEY;
    vec![
        ("basic", format!("local f = BASIL_ENCFUNC(function(u) return \"OK:\" .. tostring(u) end, \"{k}\", rk)\nprint(f(99))")),
        ("multret", format!("local f = BASIL_ENCFUNC(function(a, b) return a + b, a - b, a * b end, \"{k}\", rk)\nprint(f(10, 3))")),
        ("varargs", format!("local f = BASIL_ENCFUNC(function(...) return select(\"#\", ...) end, \"{k}\", rk)\nprint(f(10, 20, 30))")),
        ("hash_inside", format!("local f = BASIL_ENCFUNC(function(n) if BASIL_HASH(n) == BASIL_HASH(\"admin\") then return \"granted\" end return \"denied\" end, \"{k}\", rk)\nprint(f(\"admin\"))\nprint(f(\"guest\"))")),
        ("opaque_inside", format!("local f = BASIL_ENCFUNC(function(n) if BASIL_OPAQUE(true) and n > 0 then return \"pos\" end return \"nonpos\" end, \"{k}\", rk)\nprint(f(5))\nprint(f(-1))")),
        ("crash_inside", format!("local f = BASIL_ENCFUNC(function(n) if n < 0 then BASIL_CRASH() end return n * 2 end, \"{k}\", rk)\nprint(f(21))")),
        ("multiple", format!("local a = BASIL_ENCFUNC(function(x, y) return x + y end, \"{k}\", rk)\nlocal b = BASIL_ENCFUNC(function(x, y) return x * y end, \"{k}\", rk)\nprint(a(4, 5))\nprint(b(4, 5))")),
    ]
}

#[test]
fn encfunc_external_key_pass_raw_eq_virt() {
    let Some(luau) = find_luau() else { return };
    for (name, body) in enc_samples() {
        let src = enc_external(&body);
        let raw = run_injected(&luau, "basil_ef_raw.luau", &src, Some(ENCFUNC_KEY));
        let obf =
            pipeline::virtualize_with(&src, 305419896, true, true, true, true, true, false, false)
                .unwrap();
        let virt = run_injected(&luau, "basil_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
        assert!(
            !raw.stdout.trim().is_empty(),
            "[{name}] raw produced no output (sample/setup broken)"
        );
        assert_eq!(
            raw.stdout, virt.stdout,
            "[{name}] raw != virt with injected key"
        );
        assert!(
            !obf.contains(ENCFUNC_KEY),
            "[{name}] compile/runtime key must not be embedded"
        );
    }
}

#[test]
fn encfunc_external_key_lph_raw_eq_virt() {
    let Some(luau) = find_luau() else { return };
    for (name, body) in enc_samples() {
        let src = enc_external(&body);
        let raw = run_injected(&luau, "basil_eflph_raw.luau", &src, Some(ENCFUNC_KEY));
        let obf = pipeline::virtualize_full_prof(
            &src,
            305419896,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
            false,
            pipeline::SensitiveOpts::default(),
            pipeline::TargetProfile::CliTest,
            false,
            true,
        )
        .unwrap();
        let virt = run_injected(&luau, "basil_eflph_virt.luau", &obf, Some(ENCFUNC_KEY));
        assert!(
            !raw.stdout.trim().is_empty(),
            "[{name}] raw produced no output"
        );
        assert_eq!(
            raw.stdout, virt.stdout,
            "[{name}] lph raw != virt with injected key"
        );
        assert!(
            !obf.contains(ENCFUNC_KEY),
            "[{name}] lph must not embed the compile/runtime key"
        );
    }
}

#[test]
fn encfunc_external_key_flag_matrix() {
    let Some(luau) = find_luau() else { return };
    let src = enc_external(&format!("local f = BASIL_ENCFUNC(function(u) return \"OK:\" .. tostring(u) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(1337))"));
    let raw = run_injected(&luau, "basil_efm_raw.luau", &src, Some(ENCFUNC_KEY));
    let combos: &[(bool, bool, bool, pipeline::SurfaceVolume)] = &[
        (true, false, false, pipeline::SurfaceVolume::Off),
        (false, true, false, pipeline::SurfaceVolume::Off),
        (false, true, true, pipeline::SurfaceVolume::Off),
        (false, false, false, pipeline::SurfaceVolume::Medium),
    ];
    for (i, &(compress, hard, surface, heavy)) in combos.iter().enumerate() {
        let obf = pipeline::virtualize_full(
            &src, 305419896, true, true, true, true, true, compress, false, hard, surface, heavy,
        )
        .unwrap();
        let virt = run_injected(&luau, "basil_efm_virt.luau", &obf, Some(ENCFUNC_KEY));
        assert_eq!(raw.stdout, virt.stdout, "flag combo {i} raw != virt");
    }
}

#[test]
fn encfunc_external_key_fail_closed() {
    let Some(luau) = find_luau() else { return };
    let src = enc_external(&format!(
        "print(\"start\")\nlocal f = BASIL_ENCFUNC(function(u) return \"SECRET:\" .. tostring(u) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(99))\nprint(\"done\")"
    ));
    let obf = pipeline::virtualize_with(&src, 42, false, false, false, false, true, false, false)
        .unwrap();
    let ok = run_injected(&luau, "basil_ef_ok.luau", &obf, Some(ENCFUNC_KEY));
    assert!(
        ok.stdout.contains("SECRET:99"),
        "correct key must materialize, got {:?}",
        ok.stdout
    );
    let none = run_injected(&luau, "basil_ef_none.luau", &obf, None);
    assert!(
        !none.stdout.contains("SECRET") && !none.stdout.contains("done"),
        "missing key must fail closed, got {:?}",
        none.stdout
    );
    let wrong = run_injected(
        &luau,
        "basil_ef_wrong.luau",
        &obf,
        Some("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"),
    );
    assert!(
        !wrong.stdout.contains("SECRET") && !wrong.stdout.contains("done"),
        "wrong key must fail closed, got {:?}",
        wrong.stdout
    );
    let mut nm = pipeline::virtualize_full(
        &src,
        42,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    let at = nm.find("BLOBS").expect("BLOBS present");
    let open = nm[at..].find("[==[").expect("blob bracket") + at + 4;
    let mut bytes = nm.into_bytes();
    bytes[open] = if bytes[open] == b'A' { b'B' } else { b'A' };
    nm = String::from_utf8(bytes).unwrap();
    let tr = run_injected(&luau, "basil_ef_tamper.luau", &nm, Some(ENCFUNC_KEY));
    assert!(
        !tr.stdout.contains("SECRET") && !tr.stdout.contains("done"),
        "tampered blob must fail closed, got {:?}",
        tr.stdout
    );
}

const M42_SAMPLE: &str = "local marker = \"hydroxide\"\n\
local svc = { Players = \"PlayersService\" }\n\
local function getService(n) return svc[n] or (\"Invalid Service: \" .. n) end\n\
print(marker, getService(\"Players\"), getService(\"Nope\"))\n\
print(\"yeah its working\", \"nah not ready\", \"LocalPlayer\", \"BasePart\")\n\
local s = 0\n\
for i = 1, 25 do s = s + i * 3 end\n\
print(s)\n";

fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

#[test]
fn m42_packer_round_trips_through_luau_many_seeds() {
    let Some(luau) = find_luau() else { return };
    let raw = {
        let p = std::env::temp_dir().join("basil_m42_raw.luau");
        std::fs::write(&p, M42_SAMPLE).unwrap();
        run_luau(&luau, &p)
    };
    assert!(
        !raw.stdout.trim().is_empty(),
        "raw sample produced no output"
    );
    for seed in 0u64..24 {
        for compress in [false, true] {
            let obf = pipeline::virtualize_full(
                M42_SAMPLE,
                seed,
                true,
                true,
                true,
                true,
                true,
                compress,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Off,
            )
            .unwrap();
            let p = std::env::temp_dir().join("basil_m42_virt.luau");
            std::fs::write(&p, &obf).unwrap();
            let virt = run_luau(&luau, &p);
            assert_eq!(
                raw.stdout, virt.stdout,
                "seed={seed} compress={compress} packer must decode to identical bytes"
            );

            for bad in [
                "loadstring",
                "HttpService",
                "HttpGet",
                "GetAsync",
                "PostAsync",
                "http://",
                "https://",
            ] {
                assert!(
                    !obf.contains(bad),
                    "seed={seed}: forbidden API {bad:?} in output"
                );
            }
        }
    }
    for seed in [3u64, 17, 0xC0FFEE, 0x9E3779B9] {
        let obf = pipeline::virtualize_full(
            M42_SAMPLE,
            seed,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            pipeline::SurfaceVolume::Small,
        )
        .unwrap();
        let p = std::env::temp_dir().join("basil_m42_heavy.luau");
        std::fs::write(&p, &obf).unwrap();
        let virt = run_luau(&luau, &p);
        assert_eq!(
            raw.stdout, virt.stdout,
            "heavy seed={seed} packer must decode to identical bytes"
        );
    }
}

#[test]
fn m42_static_shape_friction() {
    let gen = |seed: u64, heavy: pipeline::SurfaceVolume| {
        pipeline::virtualize_full(
            M42_SAMPLE, seed, true, false, false, false, false, false, false, false, false, heavy,
        )
        .unwrap()
    };
    assert_eq!(
        gen(12345, pipeline::SurfaceVolume::Off),
        gen(12345, pipeline::SurfaceVolume::Off),
        "same seed must be deterministic"
    );

    let seeds: Vec<u64> = (0u64..20).collect();
    let outs: Vec<String> = seeds
        .iter()
        .map(|&s| gen(s, pipeline::SurfaceVolume::Off))
        .collect();
    let distinct: std::collections::HashSet<&String> = outs.iter().collect();
    assert!(
        distinct.len() >= seeds.len() - 1,
        "different seeds must produce different shapes ({}/{})",
        distinct.len(),
        seeds.len()
    );
    let blob_counts: std::collections::HashSet<usize> =
        outs.iter().map(|o| count(o, "[==[")).collect();
    assert!(
        blob_counts.len() >= 2,
        "chunk-literal count must vary across seeds (signature friction), got {blob_counts:?}"
    );
    assert!(
        blob_counts.iter().any(|&c| c >= 3),
        "some build must split the payload into multiple chunks"
    );
    for o in &outs {
        for bad in [
            "loadstring",
            "HttpService",
            "HttpGet",
            "http://",
            "https://",
        ] {
            assert!(
                !o.contains(bad),
                "forbidden API {bad:?} in unminified output"
            );
        }
    }
}

#[test]
fn m42_heavy_surface_is_present_and_inert() {
    let seed = 0xBADC0DE;
    let plain = pipeline::virtualize_full(
        M42_SAMPLE,
        seed,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    let heavy = pipeline::virtualize_full(
        M42_SAMPLE,
        seed,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Small,
    )
    .unwrap();
    assert!(
        heavy.len() > plain.len(),
        "heavy must still add surface volume ({} vs {})",
        heavy.len(),
        plain.len()
    );
    assert_eq!(
        count(&heavy, "[==["),
        count(&plain, "[==["),
        "the packer decoys were removed in 8d7ee46; heavy must no longer add long-bracket siblings"
    );
    for marker in [
        "hydroxide",
        "Invalid Service",
        "yeah its working",
        "nah not ready",
        "LocalPlayer",
        "BasePart",
    ] {
        assert!(
            !plain.contains(marker),
            "plain build leaked constant {marker:?}"
        );
        assert!(
            !heavy.contains(marker),
            "heavy build leaked constant {marker:?}"
        );
    }
}

const C1_IMPORTANT: &[&str] = &[
    "hydroxide",
    "Invalid Service:",
    "yeah its working",
    "nah not ready",
    "Players",
    "LocalPlayer",
    "TestPart",
    "BasePart",
    "SetAttribute",
    "GetAttribute",
    "VectorToWorldSpace",
];

fn c1_sample() -> String {
    let mut s = String::from("local names = {");
    for (i, n) in C1_IMPORTANT.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("\"{n}\""));
    }
    s.push_str("}\nlocal total = 0\nfor _, v in ipairs(names) do total = total + #v end\n");
    s.push_str("print(total, #names, names[1], names[5])\n");
    s
}

#[test]
fn c1_raw_eq_virt_and_important_strings_absent() {
    let Some(luau) = find_luau() else { return };
    let src = c1_sample();
    let raw = {
        let p = std::env::temp_dir().join("basil_c1_raw.luau");
        std::fs::write(&p, &src).unwrap();
        run_luau(&luau, &p)
    };
    assert!(
        !raw.stdout.trim().is_empty(),
        "c1 sample produced no output"
    );
    let combos: &[(bool, bool, bool, pipeline::SurfaceVolume)] = &[
        (false, false, false, pipeline::SurfaceVolume::Off),
        (true, false, false, pipeline::SurfaceVolume::Off),
        (false, true, true, pipeline::SurfaceVolume::Off),
        (false, false, false, pipeline::SurfaceVolume::Small),
    ];
    for &seed in SEEDS {
        for &(compress, hard, surface, heavy) in combos {
            let obf = pipeline::virtualize_full(
                &src, seed, true, true, true, true, true, compress, false, hard, surface, heavy,
            )
            .unwrap();
            let p = std::env::temp_dir().join("basil_c1_virt.luau");
            std::fs::write(&p, &obf).unwrap();
            let virt = run_luau(&luau, &p);
            assert_eq!(
                raw.stdout, virt.stdout,
                "seed={seed:#x} compress={compress} heavy={heavy:?}: C1 must not change behavior"
            );
            for s in C1_IMPORTANT {
                assert!(
                    !obf.contains(s),
                    "important string {s:?} leaked as plaintext (seed={seed:#x})"
                );
            }
        }
    }
}

#[test]
fn c1_constant_ciphertext_varies_by_seed() {
    let src = c1_sample();
    let a = pipeline::virtualize_with(&src, 0x1111, true, false, false, false, false, false, false)
        .unwrap();
    let b = pipeline::virtualize_with(&src, 0x2222, true, false, false, false, false, false, false)
        .unwrap();
    assert_ne!(a, b, "different seeds must produce different artifacts");
}

const C2_SAMPLE: &str =
    "local cfg = { Greeting = \"yeah its working\", Service = \"hydroxide\" }\n\
local function pick(t) return t.Greeting .. \"|\" .. t.Service end\n\
print(pick(cfg), \"VectorToWorldSpace\", \"LocalPlayer\", \"SetAttribute\")\n";

#[test]
fn c2_value_and_field_fragmentation_raw_eq_virt() {
    let Some(luau) = find_luau() else { return };
    let raw = {
        let p = std::env::temp_dir().join("basil_c2_raw.luau");
        std::fs::write(&p, C2_SAMPLE).unwrap();
        run_luau(&luau, &p)
    };
    assert!(
        raw.stdout.contains("yeah its working|hydroxide"),
        "c2 sample sanity: {:?}",
        raw.stdout
    );
    let targets = [
        "yeah its working",
        "hydroxide",
        "VectorToWorldSpace",
        "LocalPlayer",
        "Greeting",
        "Service",
    ];
    let combos: &[(bool, bool, bool, pipeline::SurfaceVolume)] = &[
        (false, false, false, pipeline::SurfaceVolume::Off),
        (true, false, false, pipeline::SurfaceVolume::Off),
        (false, true, true, pipeline::SurfaceVolume::Off),
        (false, false, false, pipeline::SurfaceVolume::Small),
    ];
    for &seed in SEEDS {
        for &(compress, hard, surface, heavy) in combos {
            let obf = pipeline::virtualize_full(
                C2_SAMPLE, seed, true, true, true, true, true, compress, false, hard, surface,
                heavy,
            )
            .unwrap();
            let p = std::env::temp_dir().join("basil_c2_virt.luau");
            std::fs::write(&p, &obf).unwrap();
            let virt = run_luau(&luau, &p);
            assert_eq!(
                raw.stdout, virt.stdout,
                "seed={seed:#x} compress={compress} heavy={heavy:?}: C2 must not change behavior"
            );
            for t in targets {
                assert!(
                    !obf.contains(t),
                    "fragmented target {t:?} must not survive whole (seed={seed:#x})"
                );
            }
            for bad in [
                "loadstring",
                "HttpService",
                "HttpGet",
                "http://",
                "https://",
            ] {
                assert!(!obf.contains(bad), "seed={seed:#x}: forbidden API {bad:?}");
            }
        }
    }
}

#[test]
fn c2_fragmentation_actually_splits_high_value_strings() {
    let src = "return \"VectorToWorldSpace\", \"hi\"\n";
    let mut m = frontend::macros::expand(frontend::lower_str(src).unwrap(), 0xC2).unwrap();
    passes::fragment_strings(&mut m, 0xC2, false);
    let out = ir::emit(&m);
    assert!(
        !out.contains("VectorToWorldSpace"),
        "high-value string must be fragmented: {out}"
    );
    assert!(
        out.contains("concat(") || out.contains(".."),
        "fragments must be reassembled at runtime: {out}"
    );
    assert!(out.contains("\"hi\""), "tiny string stays whole: {out}");
}

const C3_SAMPLE: &str = "local calls = 0\n\
local function makeObj(tag)\n\
  local o = { tag = tag }\n\
  function o:GetAttribute(k) return self.tag .. \":attr:\" .. k end\n\
  function o:SetAttribute(k, v) self[k] = v; return \"set:\" .. k end\n\
  function o:IsA(c) return c == \"BasePart\" end\n\
  function o:GetFullName() return self.tag .. \".Full\" end\n\
  function o:Dot(x) return \"dot:\" .. tostring(x) end\n\
  function o:Cross(x) return \"cross:\" .. tostring(x) end\n\
  function o:Inverse() return \"inv\" end\n\
  function o:VectorToWorldSpace(v) return \"vtws:\" .. tostring(v) end\n\
  function o:plainMethod() return \"plain:\" .. self.tag end\n\
  return o\n\
end\n\
game = { GetService = function(self, name) return \"svc:\" .. name end }\n\
Instance = { new = function(t) return \"inst:\" .. t end }\n\
Vector3 = { new = function(x) return \"v3:\" .. tostring(x) end }\n\
CFrame = { new = function(x) return \"cf:\" .. tostring(x) end, Angles = function(a) return \"ang:\" .. tostring(a) end }\n\
typeof = function(x) return \"ty:\" .. type(x) end\n\
local obj = makeObj(\"P\")\n\
local function getObj() calls = calls + 1; return obj end\n\
print(game:GetService(\"Players\"))\n\
print(obj:GetAttribute(\"foo\"), obj:SetAttribute(\"bar\", 7), obj.bar)\n\
print(obj:IsA(\"BasePart\"), obj:IsA(\"Model\"))\n\
print(obj:GetFullName())\n\
print(obj:Dot(3), obj:Cross(4), obj:Inverse(), obj:VectorToWorldSpace(9))\n\
print(Instance.new(\"Part\"), Vector3.new(5), CFrame.new(1), CFrame.Angles(2))\n\
print(typeof(\"hi\"), typeof(5), typeof({}))\n\
print(obj:plainMethod())\n\
print(getObj():GetAttribute(\"once\"))\n\
print(\"calls=\" .. calls)\n";

#[test]
fn c3_intrinsic_lowering_raw_eq_virt() {
    let Some(luau) = find_luau() else { return };
    let raw = {
        let p = std::env::temp_dir().join("basil_c3_raw.luau");
        std::fs::write(&p, C3_SAMPLE).unwrap();
        run_luau(&luau, &p)
    };
    assert!(
        raw.stdout.contains("svc:Players"),
        "c3 sanity (namecall): {:?}",
        raw.stdout
    );
    assert!(
        raw.stdout.contains("inst:Part"),
        "c3 sanity (lib): {:?}",
        raw.stdout
    );
    assert!(
        raw.stdout.contains("calls=1"),
        "c3 sanity (receiver once): {:?}",
        raw.stdout
    );
    let combos: &[(bool, bool, bool, pipeline::SurfaceVolume)] = &[
        (false, false, false, pipeline::SurfaceVolume::Off),
        (true, false, false, pipeline::SurfaceVolume::Off),
        (false, true, true, pipeline::SurfaceVolume::Off),
        (false, false, false, pipeline::SurfaceVolume::Small),
    ];
    for &seed in SEEDS {
        for &(compress, hard, surface, heavy) in combos {
            let obf = pipeline::virtualize_full(
                C3_SAMPLE, seed, true, true, true, true, true, compress, false, hard, surface,
                heavy,
            )
            .unwrap();
            let p = std::env::temp_dir().join("basil_c3_virt.luau");
            std::fs::write(&p, &obf).unwrap();
            let virt = run_luau(&luau, &p);
            assert_eq!(raw.stdout, virt.stdout, "seed={seed:#x} compress={compress} hard={hard} heavy={heavy:?}: C3 must not change behavior");
            for bad in [
                "loadstring",
                "HttpService",
                "HttpGet",
                "http://",
                "https://",
            ] {
                assert!(!obf.contains(bad), "seed={seed:#x}: forbidden API {bad:?}");
            }
        }
    }
}

#[test]
fn c3_catalog_has_no_plaintext_api_names() {
    let src = "local p = game:GetService(\"X\")\nreturn p:GetFullName(), Instance.new(\"Y\"), typeof(p)\n";
    let obf = pipeline::virtualize_with(src, 0xC3C3, true, true, true, true, false, false, false)
        .unwrap();
    for name in [
        "GetService",
        "GetFullName",
        "VectorToWorldSpace",
        "Instance",
        "typeof",
    ] {
        assert!(
            !obf.contains(name),
            "intrinsic name {name:?} must not appear as plaintext in the catalog/artifact"
        );
    }
}

const C2_1_SAMPLE: &str = "local m = {\n\
  \"hydroxide\", \"Invalid Service:\", \"yeah its working\", \"nah not ready\",\n\
  \"cant find that\", \"data broken\", \"took too long\", \"starting up\",\n\
  \"player:\", \"calculated:\", \"modified stuff:\",\n\
  \"Players\", \"LocalPlayer\", \"TestPart\", \"BasePart\",\n\
  \"SetAttribute\", \"GetAttribute\", \"VectorToWorldSpace\",\n\
}\n\
local acc = \"\"\n\
for i = 1, #m do acc = acc .. i .. \":\" .. m[i] .. \"|\" end\n\
print(acc, #acc)\n";

#[test]
fn c2_1_hardened_fragmentation_raw_eq_virt_and_targets_absent() {
    let Some(luau) = find_luau() else { return };
    let raw = {
        let p = std::env::temp_dir().join("basil_c21_raw.luau");
        std::fs::write(&p, C2_1_SAMPLE).unwrap();
        run_luau(&luau, &p)
    };
    assert!(
        raw.stdout.contains("1:hydroxide|"),
        "c2.1 sanity: {:?}",
        raw.stdout
    );
    let targets = [
        "hydroxide",
        "Invalid Service:",
        "yeah its working",
        "nah not ready",
        "cant find that",
        "data broken",
        "took too long",
        "starting up",
        "player:",
        "calculated:",
        "modified stuff:",
        "Players",
        "LocalPlayer",
        "TestPart",
        "BasePart",
        "SetAttribute",
        "GetAttribute",
        "VectorToWorldSpace",
    ];
    let combos: &[(bool, bool, bool, pipeline::SurfaceVolume)] = &[
        (false, false, false, pipeline::SurfaceVolume::Off),
        (true, false, false, pipeline::SurfaceVolume::Off),
        (false, false, false, pipeline::SurfaceVolume::Small),
    ];
    for &seed in SEEDS {
        for &(compress, hard, surface, heavy) in combos {
            let obf = pipeline::virtualize_full(
                C2_1_SAMPLE,
                seed,
                true,
                true,
                true,
                true,
                true,
                compress,
                false,
                hard,
                surface,
                heavy,
            )
            .unwrap();
            let p = std::env::temp_dir().join("basil_c21_virt.luau");
            std::fs::write(&p, &obf).unwrap();
            let virt = run_luau(&luau, &p);
            assert_eq!(
                raw.stdout, virt.stdout,
                "seed={seed:#x} heavy={heavy:?}: C2.1 must not change behavior"
            );
            for t in targets {
                assert!(
                    !obf.contains(t),
                    "target {t:?} must be absent (seed={seed:#x} heavy={heavy:?})"
                );
            }
        }
    }
}

#[test]
fn c2_1_fragment_shapes_vary_by_seed() {
    let a = pipeline::virtualize_with(C2_1_SAMPLE, 1, true, true, true, true, true, false, false)
        .unwrap();
    let b = pipeline::virtualize_with(C2_1_SAMPLE, 2, true, true, true, true, true, false, false)
        .unwrap();
    let c = pipeline::virtualize_with(C2_1_SAMPLE, 3, true, true, true, true, true, false, false)
        .unwrap();
    assert!(
        a != b && b != c && a != c,
        "different seeds must produce different fragmentation"
    );
}

#[test]
fn c4_strings_are_not_cached_numbers_are() {
    let vm = pipeline::virtualize_with(
        "local s = \"abcdefghij\"\nreturn s, 12345\n",
        7,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
    )
    .unwrap();
    assert!(
        vm.contains("return sub(plain, 10)"),
        "string path must be decrypt-use-discard (no kc store)"
    );
    assert!(
        vm.contains("kc[i] = (unpacks(sD, plain, 10))"),
        "number path must keep the cached fast path"
    );
}

#[test]
fn c4_repeated_access_and_string_table_keys_raw_eq_virt() {
    let Some(luau) = find_luau() else { return };
    let src = "local keys = { \"alpha\", \"betaval\", \"gammakey\", \"deltaword\" }\n\
local t = {}\n\
for i = 1, #keys do t[keys[i]] = i * 10 end\n\
local sum = 0\n\
for _ = 1, 3 do for i = 1, #keys do sum = sum + t[keys[i]] end end\n\
local msg = \"the quick brown fox\"\n\
local acc = \"\"\n\
for _ = 1, 4 do acc = acc .. msg .. \"|\" end\n\
print(sum, t[\"alpha\"], t.gammakey, #acc, acc:sub(1, 19) == msg)\n";
    let raw = {
        let p = std::env::temp_dir().join("basil_c4_raw.luau");
        std::fs::write(&p, src).unwrap();
        run_luau(&luau, &p)
    };
    assert!(raw.stdout.contains("300"), "c4 sanity: {:?}", raw.stdout);
    let combos: &[(bool, bool, bool, pipeline::SurfaceVolume)] = &[
        (false, false, false, pipeline::SurfaceVolume::Off),
        (true, false, false, pipeline::SurfaceVolume::Off),
        (false, true, true, pipeline::SurfaceVolume::Off),
        (false, false, false, pipeline::SurfaceVolume::Small),
    ];
    for &seed in SEEDS {
        for &(compress, hard, surface, heavy) in combos {
            let obf = pipeline::virtualize_full(
                src, seed, true, true, true, true, true, compress, false, hard, surface, heavy,
            )
            .unwrap();
            let p = std::env::temp_dir().join("basil_c4_virt.luau");
            std::fs::write(&p, &obf).unwrap();
            let virt = run_luau(&luau, &p);
            assert_eq!(
                raw.stdout, virt.stdout,
                "seed={seed:#x} compress={compress} heavy={heavy:?}: C4 must not change behavior"
            );
        }
    }
}

const M5_SEED: u64 = 1234567890123456;

fn enc_seed_external(body: &str) -> String {
    format!(
        "if not BASIL_OBFUSCATED then\n\
         BASIL_ENCFUNC_SEED = function(fn, _, _) return fn end\n\
         BASIL_HASH = function(s) return s end\n\
         BASIL_OPAQUE = function(v) return v end\n\
         BASIL_CRASH = function() end\n\
         end\n\
         local rs = BASILISK_RUNTIME_SEED\n{body}\n"
    )
}

fn run_injected_seed(luau: &str, name: &str, content: &str, seed: Option<u64>) -> Run {
    let mut full = String::new();
    if let Some(s) = seed {
        full.push_str(&format!("BASILISK_RUNTIME_SEED = {s}\n"));
    }
    full.push_str(content);
    let p = std::env::temp_dir().join(name);
    std::fs::write(&p, full).unwrap();
    run_luau(luau, &p)
}

fn enc_seed_samples() -> Vec<(&'static str, String)> {
    vec![
        ("basic", format!("local f = BASIL_ENCFUNC_SEED(function(u) return \"OK:\" .. tostring(u) end, {M5_SEED}, rs)\nprint(f(99))")),
        ("multret", format!("local f = BASIL_ENCFUNC_SEED(function(a, b) return a + b, a - b end, {M5_SEED}, rs)\nprint(f(10, 3))")),
        ("varargs", format!("local f = BASIL_ENCFUNC_SEED(function(...) return select(\"#\", ...) end, {M5_SEED}, rs)\nprint(f(1, 2, 3, 4))")),
        ("hash_inside", format!("local f = BASIL_ENCFUNC_SEED(function(n) if BASIL_HASH(n) == BASIL_HASH(\"admin\") then return \"granted\" end return \"denied\" end, {M5_SEED}, rs)\nprint(f(\"admin\"), f(\"guest\"))")),
        ("zero_seed", "local f = BASIL_ENCFUNC_SEED(function(u) return \"Z:\" .. tostring(u) end, 0, rs)\nprint(f(7))".to_string()),
        ("multiple", format!("local a = BASIL_ENCFUNC_SEED(function(x) return x + 1 end, {M5_SEED}, rs)\nlocal b = BASIL_ENCFUNC_SEED(function(x) return x * 2 end, 42, rs2)\nprint(a(10), b(10))")),
    ]
}

#[test]
fn m5_encfunc_seed_pass_raw_eq_virt() {
    let Some(luau) = find_luau() else { return };
    for (name, body) in enc_seed_samples() {
        let runtime_seed = if name == "zero_seed" { 0 } else { M5_SEED };
        let extra = if name == "multiple" {
            "local rs2 = BASILISK_RUNTIME_SEED2\n"
        } else {
            ""
        };
        let src = enc_seed_external(&format!("{extra}{body}"));
        let inject = |nm: &str, c: &str| {
            let mut full = format!("BASILISK_RUNTIME_SEED = {runtime_seed}\n");
            if name == "multiple" {
                full.push_str("BASILISK_RUNTIME_SEED2 = 42\n");
            }
            full.push_str(c);
            let p = std::env::temp_dir().join(nm);
            std::fs::write(&p, full).unwrap();
            run_luau(&luau, &p)
        };
        let raw = inject("basil_es_raw.luau", &src);
        let obf =
            pipeline::virtualize_with(&src, 305419896, true, true, true, true, true, false, false)
                .unwrap();
        let virt = inject("basil_es_virt.luau", &obf);
        assert!(
            !raw.stdout.trim().is_empty(),
            "[{name}] raw produced no output"
        );
        assert_eq!(
            raw.stdout, virt.stdout,
            "[{name}] raw != virt (Rust KDF must match Luau KDF)"
        );
        assert!(
            !obf.contains(&M5_SEED.to_string()),
            "[{name}] compile seed must not be embedded as a literal"
        );
        assert!(
            !obf.contains("BASIL_ENCFUNC_SEED"),
            "[{name}] macro marker must not ship"
        );
    }
}

#[test]
fn m5_encfunc_seed_fail_closed() {
    let Some(luau) = find_luau() else { return };
    let src = enc_seed_external(&format!(
        "print(\"start\")\nlocal f = BASIL_ENCFUNC_SEED(function(u) return \"SECRET:\" .. tostring(u) end, {M5_SEED}, rs)\nprint(f(99))\nprint(\"done\")"
    ));
    let obf = pipeline::virtualize_with(&src, 42, false, false, false, false, true, false, false)
        .unwrap();
    let ok = run_injected_seed(&luau, "basil_es_ok.luau", &obf, Some(M5_SEED));
    assert!(
        ok.stdout.contains("SECRET:99"),
        "correct seed must materialize, got {:?}",
        ok.stdout
    );
    let none = run_injected_seed(&luau, "basil_es_none.luau", &obf, None);
    assert!(
        !none.stdout.contains("SECRET") && !none.stdout.contains("done"),
        "missing seed must fail closed, got {:?}",
        none.stdout
    );
    let wrong = run_injected_seed(&luau, "basil_es_wrong.luau", &obf, Some(M5_SEED + 1));
    assert!(
        !wrong.stdout.contains("SECRET") && !wrong.stdout.contains("done"),
        "wrong seed must fail closed, got {:?}",
        wrong.stdout
    );
    let mut nm = pipeline::virtualize_full(
        &src,
        42,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    let at = nm.find("BLOBS").expect("BLOBS present");
    let open = nm[at..].find("[==[").expect("blob bracket") + at + 4;
    let mut bytes = nm.into_bytes();
    bytes[open] = if bytes[open] == b'A' { b'B' } else { b'A' };
    nm = String::from_utf8(bytes).unwrap();
    let tr = run_injected_seed(&luau, "basil_es_tamper.luau", &nm, Some(M5_SEED));
    assert!(
        !tr.stdout.contains("SECRET") && !tr.stdout.contains("done"),
        "tampered blob must fail closed, got {:?}",
        tr.stdout
    );
}

#[test]
fn m5_encfunc_seed_deterministic_and_seed_changes_blob() {
    let body = format!(
        "local f = BASIL_ENCFUNC_SEED(function(u) return u end, {M5_SEED}, rs)\nprint(f(1))"
    );
    let a = pipeline::virtualize_with(
        &enc_seed_external(&body),
        7,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
    .unwrap();
    let b = pipeline::virtualize_with(
        &enc_seed_external(&body),
        7,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
    .unwrap();
    assert_eq!(a, b, "same seed + source must be deterministic");
    let diff = pipeline::virtualize_with(
        &enc_seed_external(&format!(
            "local f = BASIL_ENCFUNC_SEED(function(u) return u end, {}, rs)\nprint(f(1))",
            M5_SEED + 1
        )),
        7,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
    .unwrap();
    assert_ne!(
        a, diff,
        "different compile seed must change the sealed blob"
    );
}

fn run_with_g(luau: &str, name: &str, content: &str, g_fields: &str) -> Run {
    let full = format!("_G = setmetatable({{{g_fields}}}, {{__index = getfenv()}})\n{content}");
    let p = std::env::temp_dir().join(name);
    std::fs::write(&p, full).unwrap();
    run_luau(luau, &p)
}

fn m6_example(name: &str) -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m6");
    let path = dir.join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read tracked fixture {}: {e}", path.display()))
}

#[test]
fn m6_server_key_pattern_builds_and_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let src = m6_example("encfunc_server_key_pattern.luau");
    let obf =
        pipeline::virtualize_with(&src, 305419896, true, false, true, true, true, false, false)
            .unwrap();
    let k = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let ok = run_with_g(
        &luau,
        "basil_m6_k_ok.luau",
        &obf,
        &format!("BASILISK_RUNTIME_KEY = \"{k}\", SESSION_ID = 1"),
    );
    assert!(
        ok.stdout.contains("welcome:player1"),
        "correct key must unlock, got {:?}",
        ok.stdout
    );
    let miss = run_with_g(&luau, "basil_m6_k_miss.luau", &obf, "SESSION_ID = 1");
    assert!(
        !miss.stdout.contains("welcome"),
        "missing key must fail closed, got {:?}",
        miss.stdout
    );
    let wrong = run_with_g(&luau, "basil_m6_k_wrong.luau", &obf, "BASILISK_RUNTIME_KEY = \"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\", SESSION_ID = 1");
    assert!(
        !wrong.stdout.contains("welcome"),
        "wrong key must fail closed, got {:?}",
        wrong.stdout
    );
    assert!(!obf.contains(k), "compile key must not ship");
}

#[test]
fn m6_seed_server_pattern_builds_and_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let src = m6_example("encfunc_seed_server_pattern.luau");
    let obf =
        pipeline::virtualize_with(&src, 305419896, true, false, true, true, true, false, false)
            .unwrap();
    let ok = run_with_g(
        &luau,
        "basil_m6_s_ok.luau",
        &obf,
        "BASILISK_RUNTIME_SEED = 8675309424242, SESSION_ID = 1",
    );
    assert!(
        ok.stdout.contains("welcome:player1"),
        "correct seed must unlock, got {:?}",
        ok.stdout
    );
    let miss = run_with_g(&luau, "basil_m6_s_miss.luau", &obf, "SESSION_ID = 1");
    assert!(
        !miss.stdout.contains("welcome"),
        "missing seed must fail closed, got {:?}",
        miss.stdout
    );
    let wrong = run_with_g(
        &luau,
        "basil_m6_s_wrong.luau",
        &obf,
        "BASILISK_RUNTIME_SEED = 111, SESSION_ID = 1",
    );
    assert!(
        !wrong.stdout.contains("welcome"),
        "wrong seed must fail closed, got {:?}",
        wrong.stdout
    );
    assert!(
        !obf.contains("8675309424242"),
        "compile seed must not ship as a literal"
    );
}

#[test]
fn e1_digest_verify_is_wired_before_materialization() {
    let src = enc_external(&format!(
        "local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", rk)\nprint(f(1))"
    ));
    let vm = pipeline::virtualize_full(
        &src,
        7,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    assert!(
        vm.contains("ad = SVAD .. char("),
        "ENCFUNC AD must be built from the baked v2 format-identity prefix (SVAD) — E1 format"
    );
    assert!(
        vm.contains("local SVAD = char("),
        "the baked v2 format-identity constant (SVAD) must be present"
    );
    assert!(
        vm.contains("deserialize(sub(pt, 5))"),
        "deserialize must skip the 4-byte authenticated digest prefix"
    );
    assert!(
        vm.contains("_pdg(proto[1]) ~= want"),
        "materialization must verify the inner-proto digest"
    );
    assert!(
        vm.contains("_eKids(proto)"),
        "child protos must be sealed (decoded + digest pinned) before the closure is built"
    );
    let chk = vm.find("_pdg(proto[1]) ~= want").unwrap();
    let kids = vm.find("_eKids(proto)").unwrap();
    let mk = vm.find("makeClosure(proto, {})").unwrap();
    assert!(chk < kids, "root digest verify must precede child sealing");
    assert!(kids < mk, "child sealing must precede makeClosure");
}

#[test]
fn e1_encfunc_and_seed_unlock_with_digest_and_fail_closed_wrong() {
    let Some(luau) = find_luau() else { return };
    let ksrc = enc_external(&format!(
        "local f = BASIL_ENCFUNC(function(u) return \"K:\" .. tostring(u) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(42))"
    ));
    let kobf =
        pipeline::virtualize_with(&ksrc, 305419896, true, true, true, true, true, false, false)
            .unwrap();
    let kok = run_injected(&luau, "basil_e1_k_ok.luau", &kobf, Some(ENCFUNC_KEY));
    assert!(
        kok.stdout.contains("K:42"),
        "ENCFUNC correct key must unlock with E1, got {:?}",
        kok.stdout
    );
    let kbad = run_injected(
        &luau,
        "basil_e1_k_bad.luau",
        &kobf,
        Some("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"),
    );
    assert!(
        !kbad.stdout.contains("K:42"),
        "ENCFUNC wrong key must fail closed, got {:?}",
        kbad.stdout
    );
    let ssrc = enc_seed_external(&format!(
        "local f = BASIL_ENCFUNC_SEED(function(u) return \"S:\" .. tostring(u) end, {M5_SEED}, rs)\nprint(f(42))"
    ));
    let sobf =
        pipeline::virtualize_with(&ssrc, 305419896, true, true, true, true, true, false, false)
            .unwrap();
    let sok = run_injected_seed(&luau, "basil_e1_s_ok.luau", &sobf, Some(M5_SEED));
    assert!(
        sok.stdout.contains("S:42"),
        "ENCFUNC_SEED correct seed must unlock with E1, got {:?}",
        sok.stdout
    );
    let sbad = run_injected_seed(&luau, "basil_e1_s_bad.luau", &sobf, Some(M5_SEED + 1));
    assert!(
        !sbad.stdout.contains("S:42"),
        "ENCFUNC_SEED wrong seed must fail closed, got {:?}",
        sbad.stdout
    );
}

fn agg(src: &str, seed: u64) -> String {
    pipeline::virtualize_full_opt(
        src,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        true,
    )
    .unwrap()
}

#[test]
fn corpus_virtualizes_aggressive() {
    run_corpus("virtualize+all+aggressive", |s| {
        pipeline::virtualize_full_opt(
            s,
            FLATTEN_SEED,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
            true,
        )
    });
}

#[test]
fn o1_default_mode_is_byte_identical() {
    let src = "local x = 2 + 3\nif false then print('dead') end\nprint(x)\n";
    for &seed in &[7u64, 305419896, 0xDEADBEEF] {
        let base = pipeline::virtualize_full(
            src,
            seed,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
        )
        .unwrap();
        let off = pipeline::virtualize_full_opt(
            src,
            seed,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
            false,
        )
        .unwrap();
        assert_eq!(
            base, off,
            "default (aggressive=off) must be byte-identical to virtualize_full"
        );
    }
}

#[test]
fn o1_folds_literals_and_picks_branch_behaviorally() {
    let Some(luau) = find_luau() else { return };
    let src = "local x = 2 + 3 * 4\nif 1 == 1 then print(x) else print(999) end\nif (10 - 4) > 5 then print('hi') end\n";
    let rp = std::env::temp_dir().join("basil_o1_fold_raw.luau");
    std::fs::write(&rp, src).unwrap();
    let raw = run_luau(&luau, &rp);
    let ap = std::env::temp_dir().join("basil_o1_fold_agg.luau");
    std::fs::write(&ap, agg(src, 305419896)).unwrap();
    let virt = run_luau(&luau, &ap);
    assert_eq!(
        raw.stdout, virt.stdout,
        "aggressive fold must preserve behavior"
    );
    assert!(
        virt.stdout.contains("14") && virt.stdout.contains("hi") && !virt.stdout.contains("999")
    );
}

#[test]
fn o1_removes_dead_branch_and_shrinks_payload() {
    let mut dead = String::from("if 1 == 2 then\n");
    for i in 0..60 {
        dead.push_str(&format!("print('dead_branch_unique_constant_{i}')\n"));
    }
    dead.push_str("end\nprint('LIVE')\n");
    let cfg = |aggressive: bool| {
        pipeline::virtualize_full_opt(
            &dead,
            305419896,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
            aggressive,
        )
        .unwrap()
    };
    let kept = cfg(false);
    let pruned = cfg(true);
    assert!(
        pruned.len() + 500 < kept.len(),
        "aggressive must drop the dead branch (pruned {} vs kept {})",
        pruned.len(),
        kept.len()
    );
    if let Some(luau) = find_luau() {
        let p = std::env::temp_dir().join("basil_o1_dead.luau");
        std::fs::write(&p, &pruned).unwrap();
        let out = run_luau(&luau, &p);
        assert!(
            out.stdout.contains("LIVE") && !out.stdout.contains("dead_branch"),
            "live code must survive, dead must be gone: {:?}",
            out.stdout
        );
    }
}

#[test]
fn o1_preserves_side_effecting_condition_and_call() {
    let Some(luau) = find_luau() else { return };

    let src = "local n = 0\nlocal function f() n = n + 1 return false end\nif f() then print('A') else print('B') end\nif true then n = n + 10 end\nprint(n)\n";
    let rp = std::env::temp_dir().join("basil_o1_se_raw.luau");
    std::fs::write(&rp, src).unwrap();
    let raw = run_luau(&luau, &rp);
    let ap = std::env::temp_dir().join("basil_o1_se_agg.luau");
    std::fs::write(&ap, agg(src, 7)).unwrap();
    let virt = run_luau(&luau, &ap);
    assert_eq!(
        raw.stdout, virt.stdout,
        "side-effecting condition must be preserved identically"
    );
    assert!(
        virt.stdout.contains("B"),
        "false branch taken: {:?}",
        virt.stdout
    );
    assert!(
        virt.stdout.trim_end().ends_with("11"),
        "call ran once + true-branch kept: {:?}",
        virt.stdout
    );
}

#[test]
fn m8_basil_line_returns_compile_time_line() {
    let Some(luau) = find_luau() else { return };

    let src = "print(BASIL_LINE())\nlocal a = 1\nprint(\"L\", BASIL_LINE())\nlocal t = { ln = BASIL_LINE() }\nprint(t.ln)\n";
    let obf = pipeline::virtualize_with(src, 305419896, true, true, true, true, true, false, false)
        .unwrap();
    assert!(!obf.contains("BASIL_LINE"), "no macro marker may ship");
    let p = std::env::temp_dir().join("basil_m8_line.luau");
    std::fs::write(&p, &obf).unwrap();
    let out = run_luau(&luau, &p);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(
        lines,
        vec!["1", "L\t3", "4"],
        "compile-time line numbers: {:?}",
        out.stdout
    );
}

#[test]
fn m8_basil_line_survives_aggressive_optimization() {
    let Some(luau) = find_luau() else { return };

    let src = "local a = 2 + 3\nprint(BASIL_LINE())\n";
    let obf = pipeline::virtualize_full_opt(
        src,
        7,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        true,
    )
    .unwrap();
    let p = std::env::temp_dir().join("basil_m8_agg.luau");
    std::fs::write(&p, &obf).unwrap();
    assert_eq!(
        run_luau(&luau, &p).stdout.trim_end(),
        "2",
        "BASIL_LINE under aggressive"
    );
}

#[test]
fn m8_basil_line_works_inside_encfunc_body() {
    let Some(luau) = find_luau() else { return };

    let src = enc_external(
        "local f = BASIL_ENCFUNC(function() return BASIL_LINE() end, \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\", rk)\nprint(f())",
    );
    let obf =
        pipeline::virtualize_with(&src, 305419896, true, true, true, true, true, false, false)
            .unwrap();
    assert!(!obf.contains("BASIL_LINE"), "no marker inside ENCFUNC path");
    let out = run_injected(&luau, "basil_m8_enc.luau", &obf, Some(ENCFUNC_KEY));
    let n: i64 = out.stdout.trim_end().parse().unwrap_or(0);
    assert!(
        n > 0,
        "BASIL_LINE inside ENCFUNC must return a source line, got {:?}",
        out.stdout
    );
}

#[test]
fn m8_macro_free_build_is_byte_identical_and_no_marker() {
    let src = "local x = 0\nfor i = 1, 5 do x = x + i end\nprint(x)\n";
    let a =
        pipeline::virtualize_with(src, 424242, true, true, true, true, true, false, false).unwrap();
    let b =
        pipeline::virtualize_with(src, 424242, true, true, true, true, true, false, false).unwrap();
    assert_eq!(a, b, "deterministic");
    assert!(!a.contains("BASIL_LINE"), "no marker in a macro-free build");
    assert!(
        !a.contains("debug.info"),
        "M8 must not add a runtime debug dependency"
    );
}

fn virt_line_info(src: &str, seed: u64, line_info: bool) -> String {
    pipeline::virtualize_full_line(
        src,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        pipeline::TargetProfile::CliTest,
        false,
        false,
        line_info,
        false,
    )
    .unwrap()
}

#[test]
fn line_info_mode_toggles_basil_line_end_to_end() {
    let Some(luau) = find_luau() else { return };
    let src = "print(BASIL_LINE())\nlocal a = 1\nprint(\"L\", BASIL_LINE())\nlocal t = { ln = BASIL_LINE() }\nprint(t.ln)\n";
    let run = |line_info: bool| {
        let obf = virt_line_info(src, 305419896, line_info);
        assert!(!obf.contains("BASIL_LINE"), "no macro marker may ship");
        let p = std::env::temp_dir().join(format!("basil_lineinfo_{line_info}.luau"));
        std::fs::write(&p, &obf).unwrap();
        run_luau(&luau, &p)
            .stdout
            .lines()
            .map(String::from)
            .collect::<Vec<String>>()
    };
    assert_eq!(
        run(true),
        vec!["1", "L\t3", "4"],
        "on: real compile-time source lines"
    );
    assert_eq!(
        run(false),
        vec!["0", "L\t0", "0"],
        "off: 0 sentinel, no source-line leak"
    );
}

#[test]
fn line_info_off_preserves_program_behavior() {
    let Some(luau) = find_luau() else { return };
    let src = "local function f(n) local s = 0 for i = 1, n do s = s + i * i end return s end\nlocal t = setmetatable({}, { __index = function(_, k) return k .. \"!\" end })\nlocal a, b = f(6), t.hi\nprint(a, b, #\"abc\", -a, not false)\n";
    let raw = run_code(&luau, src, "li_raw");
    for &line_info in &[true, false] {
        let obf = virt_line_info(src, 99, line_info);
        let virt = run_code(&luau, &obf, "li_virt");
        assert_eq!(
            raw.stdout, virt.stdout,
            "line_info={line_info}: behavior must match raw"
        );
        assert_eq!(
            raw.code, virt.code,
            "line_info={line_info}: exit code must match raw"
        );
    }
}

#[test]
fn line_info_off_leaks_no_source_line() {
    let src = "local a = 1\nlocal b = 2\nlocal c = BASIL_LINE()\nprint(a + b + c)\n";
    let off = virt_line_info(src, 7, false);
    assert!(!off.contains("BASIL_LINE"), "no macro marker may ship");
    assert!(
        !off.contains("debug.info") && !off.contains("debug.traceback"),
        "off must not add a debug dependency"
    );
}

fn c11_roundtrip(label: &str, src: &str, seed: u64, hard: bool) {
    let Some(luau) = find_luau() else { return };
    let obf = pipeline::virtualize_full_opt(
        src,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        hard,
        false,
        pipeline::SurfaceVolume::Off,
        false,
    )
    .unwrap();
    let rp = std::env::temp_dir().join(format!("basil_c11_raw_{label}.luau"));
    std::fs::write(&rp, src).unwrap();
    let raw = run_luau(&luau, &rp);
    let vp = std::env::temp_dir().join(format!("basil_c11_virt_{label}.luau"));
    std::fs::write(&vp, &obf).unwrap();
    let virt = run_luau(&luau, &vp);
    assert_eq!(
        raw.stdout, virt.stdout,
        "[{label}] C1.1 raw==virt (seed {seed:#x}, hard={hard})"
    );
}

#[test]
fn c11_same_literal_multiple_pcs() {
    c11_roundtrip("duplit", "local a = \"DUP\"\nprint(a)\nlocal b = \"DUP\"\nprint(b)\nprint(\"DUP\")\nprint(7 + 5)\nprint(7 + 5)\n", 305419896, false);
}

#[test]
fn c11_repeated_access_in_loop() {
    c11_roundtrip("loop", "local s = 0\nfor i = 1, 10 do s = s + 5 end\nprint(s)\nfor i = 1, 3 do print(\"LOOP\") end\n", 0xBEEF, false);
}

#[test]
fn c11_constants_as_table_keys() {
    c11_roundtrip("tblkeys", "local t = {}\nt[\"alpha\"] = 1\nt.beta = 2\nt[\"alpha\"] = t[\"alpha\"] + 10\nprint(t.alpha, t.beta)\nfor k, v in pairs(t) do print(k, v) end\n", 12345, false);
}

#[test]
fn c11_c21_fragmented_string() {
    c11_roundtrip("frag", "local x = \"this_is_a_long_fragmented_secret_string_value\"\nprint(x)\nprint(#x)\nprint(x == \"this_is_a_long_fragmented_secret_string_value\")\n", 777, false);
}

#[test]
fn c11_superop_fuse_hard_dispatch_combo() {
    let src = "local t = { a = 1, b = 2, c = 3 }\nlocal sum = 0\nfor i = 1, 5 do sum = sum + t.a + t.b * 2 end\nprint(sum)\nprint(t.a, t.b, t.c)\nprint(\"const_heavy_\" .. tostring(sum))\n";
    c11_roundtrip("super_hard", src, 0xC0FFEE, true);
}

#[test]
fn c11_different_seeds_differ() {
    let src = "local x = \"seed_sensitive\"\nprint(x .. \"_\" .. tostring(40 + 2))\n";
    let a =
        pipeline::virtualize_with(src, 111, true, true, true, true, true, false, false).unwrap();
    let b =
        pipeline::virtualize_with(src, 222, true, true, true, true, true, false, false).unwrap();
    assert_ne!(
        a, b,
        "different seeds must produce different C1.1 artifacts"
    );
}

#[test]
fn c11_vm_wires_use_site_tokens() {
    let vm = pipeline::virtualize_full(
        "local a = \"x\"\nprint(a, 1 + 2)",
        7,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    assert!(
        vm.contains("local function ktoks(code)"),
        "VM must define the use-site token scan"
    );
    assert!(
        vm.contains("local function ksite("),
        "VM must define the use-site token function"
    );
    assert!(vm.contains("proto[10]"), "tokens must memoize per proto");
    assert!(
        vm.contains("ktok and ktok[i] or 0"),
        "kget nonce must fold the use-site token"
    );
}

#[test]
fn c11_target_string_absent_from_artifact() {
    let obf = pipeline::virtualize_with(
        "local secret = \"C11_TARGET_SECRET_LITERAL\"\nprint(#secret)",
        305419896,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        !obf.contains("C11_TARGET_SECRET_LITERAL"),
        "user string must not appear plaintext"
    );
}

const H1_SRC: &str = r#"
local mt = {}
mt.__index = function(t, k) return "idx:" .. tostring(k) end
mt.__newindex = function(t, k, v) rawset(t, "_" .. k, v) end
mt.__add = function(a, b) return rawget(a, "v") + (type(b) == "table" and rawget(b, "v") or b) end
mt.__eq = function(a, b) return rawget(a, "v") == rawget(b, "v") end
local function obj(v) return setmetatable({ v = v }, mt) end
local x = obj(3)
local y = obj(4)
print(x + y)
print(x.missing)
x.dyn = 99
print(rawget(x, "_dyn"))
print(obj(5) == obj(5), obj(5) == obj(6))
local lib = {}
function lib.greet(self, n) return "hi " .. n end
print(lib:greet("bob"))
GLOB = 7
print(GLOB + 1)
local arr = { 10, 20, 30 }
local s, p = 0, 1
for i = 1, #arr do s = s + arr[i] p = p * arr[i] end
print(s, p, s < p, s > p, s == 60)
if x then print("truthy") end
if not nil then print("not-nil") end
"#;

fn h1_behaves(label: &str, hard: bool, surface: bool, heavy: pipeline::SurfaceVolume) {
    let Some(luau) = find_luau() else { return };
    let obf = pipeline::virtualize_full_opt(
        H1_SRC, 0x4831, true, true, true, true, true, false, false, hard, surface, heavy, false,
    )
    .unwrap();
    let raw = run_code(&luau, H1_SRC, &format!("h1_raw_{label}"));
    let virt = run_code(&luau, &obf, &format!("h1_virt_{label}"));
    assert_eq!(
        raw.stdout, virt.stdout,
        "[{label}] H1 metamethod/control-flow raw==virt"
    );
    assert_eq!(raw.code, virt.code, "[{label}] H1 exit code");
}

#[test]
fn h1_indirected_handlers_preserve_metamethods_and_control_flow() {
    h1_behaves("plain", false, false, pipeline::SurfaceVolume::Off);
    h1_behaves("hard", true, false, pipeline::SurfaceVolume::Off);
    h1_behaves("surface", false, true, pipeline::SurfaceVolume::Off);
    h1_behaves(
        "hard_surface_heavy",
        true,
        true,
        pipeline::SurfaceVolume::Medium,
    );
}

const HANDLER_COV_SRC: &str = r##"
local mt = { __index = function(t, k) return "idx:" .. tostring(k) end, __newindex = function(t, k, v) rawset(t, "s" .. k, v * 2) end, __add = function(p, q) return rawget(p, "v") + (type(q) == "table" and rawget(q, "v") or q) end, __eq = function(p, q) return rawget(p, "v") == rawget(q, "v") end }
local function obj(v) return setmetatable({ v = v }, mt) end
local out = {}
local function push(x) out[#out + 1] = tostring(x) end
local o = obj(10)
o.dyn = 5
push(o.missing) push(rawget(o, "sdyn")) push(obj(2) + obj(3)) push(obj(4) + 6) push(obj(5) == obj(5)) push(obj(5) == obj(6))
G = 100
push(G + 1) push(-G) push(not false) push(#"abcde") push(not nil)
local a, b = 7, 3
push(a + b) push(a - b) push(a * b) push(a % b) push(a // b) push(a ^ 2) push(a .. b)
push(a + 2) push(a * 3 % 4) push("x" .. a) push(a - 1 == 6)
push(a < b) push(a <= b) push(a == 7) push(a ~= b) push(a > b) push(a >= 7)
local function mk() local n = 0 local function inc(d) n = n + d return n end local function get() return n end return inc, get end
local inc, get = mk()
inc(3) inc(4)
push(get())
local function va(...) local t = { ... } local s = 0 for i = 1, #t do s = s + t[i] end return s, select("#", ...) end
local sum, cnt = va(1, 2, 3, 4)
push(sum) push(cnt)
local function fib(x) if x < 2 then return x end return fib(x - 1) + fib(x - 2) end
push(fib(10))
local grid = {}
for i = 1, 6 do grid[i] = i * i end
local ac = 0
for _, v in ipairs(grid) do ac = ac + v end
push(ac)
local kc = 0
for k, v in pairs({ x = 1, y = 2, z = 3 }) do kc = kc + v end
push(kc)
local j = 0
repeat j = j + 1 until j >= 4
push(j)
local w = 0
while w < 5 do w = w + 1 end
push(w)
local lib = {}
function lib:scale(f) self.v = (self.v or 1) * f return self.v end
push(lib:scale(3)) push(lib:scale(2))
local nested = { { 1, 2 }, { 3, 4, 5 } }
local flat = 0
for i = 1, #nested do for k = 1, #nested[i] do flat = flat + nested[i][k] end end
push(flat)
print(table.concat(out, "|"))
"##;

#[test]
fn handler_variant_coverage_raw_equals_virt_across_seeds() {
    let Some(luau) = find_luau() else { return };
    let raw = run_code(&luau, HANDLER_COV_SRC, "hcov_raw");
    for seed in 0..32u64 {
        let obf = pipeline::virtualize_full_opt(
            HANDLER_COV_SRC,
            seed,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
            false,
        )
        .unwrap();
        let virt = run_code(&luau, &obf, &format!("hcov_{seed}"));
        assert_eq!(
            raw.stdout, virt.stdout,
            "seed {seed}: handler-variant raw==virt stdout"
        );
        assert_eq!(
            raw.code, virt.code,
            "seed {seed}: handler-variant exit code"
        );
    }
}

#[test]
fn h1_dispatch_omits_clean_register_patterns() {
    let vm = pipeline::virtualize_full(
        H1_SRC,
        0x4831,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    for clean in [
        "R[a] = R[inst[KB]]",
        "R[a] = genv[",
        "R[a + 1] = R[inst[KB]]",
        "R[a][R[inst[KB]]]",
        "if R[a] then",
        "if not R[a] then",
        "R[a] = R[inst[KB]][R[inst[KC]]]",
    ] {
        assert!(
            !vm.contains(clean),
            "no-minify dispatch must not contain the clean pattern `{clean}`"
        );
    }
    assert!(
        vm.contains("local function rg"),
        "VM must define the read-indirection helper"
    );
    assert!(
        vm.contains("local function rs"),
        "VM must define the write-indirection helper"
    );
    assert!(
        vm.contains("rs(R, a,"),
        "high-value sets must route through rs"
    );
    assert!(
        vm.contains("rg(R, inst[KB])"),
        "high-value reads must route through rg"
    );
}

#[test]
fn h1_different_seeds_produce_different_handler_bodies() {
    let mk = |seed: u64| {
        pipeline::virtualize_full(
            H1_SRC,
            seed,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
        )
        .unwrap()
    };
    let a = mk(0x1111);
    let b = mk(0x2222);
    assert_ne!(
        a, b,
        "different seeds must produce visibly different (no-minify) handler bodies"
    );
    assert!(
        a.contains("local function rg") && b.contains("local function rg"),
        "both keep H1 indirection"
    );
}

#[test]
fn h1_deterministic_same_source_and_seed() {
    let mk = || {
        pipeline::virtualize_full_opt(
            H1_SRC,
            0x9ABC,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            pipeline::SurfaceVolume::Medium,
            false,
        )
        .unwrap()
    };
    assert_eq!(
        mk(),
        mk(),
        "H1 must be fully deterministic for a fixed source+seed"
    );
}

#[test]
fn h1_introduces_no_forbidden_apis() {
    let obf = pipeline::virtualize_full_opt(
        H1_SRC,
        0x4831,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        pipeline::SurfaceVolume::Medium,
        false,
    )
    .unwrap();
    for bad in [
        "loadstring",
        "HttpService",
        "HttpGet",
        "debug.getinfo",
        "debug.traceback",
        "debug.info",
    ] {
        assert!(!obf.contains(bad), "H1 artifact must not reference `{bad}`");
    }
}

const H2_SRC: &str = r#"
local n = setmetatable({}, {
  __add = function(a, b) return rawget(a, "v") + rawget(b, "v") end,
  __sub = function(a, b) return rawget(a, "v") - rawget(b, "v") end,
  __mul = function(a, b) return rawget(a, "v") * rawget(b, "v") end,
  __concat = function(a, b) return rawget(a, "v") .. tostring(b) end,
  __eq = function(a, b) return rawget(a, "v") == rawget(b, "v") end,
  __lt = function(a, b) return rawget(a, "v") < rawget(b, "v") end,
  __le = function(a, b) return rawget(a, "v") <= rawget(b, "v") end,
  __len = function(t) return rawget(t, "v") end,
  __unm = function(t) return -rawget(t, "v") end,
})
local mt = getmetatable(n)
local function obj(v) local o = setmetatable({}, mt) rawset(o, "v", v) return o end
local x, y = obj(10), obj(3)
print(x + y, x - y, x * y, -x, #x)
print(x .. "!", obj(5) == obj(5), obj(5) == obj(6), obj(2) < obj(9), obj(9) <= obj(9))
local s, p = 0, 1
for i = 1, 6 do s = s + i * 2 p = p * (i % 4 + 1) end
print(s, p, s > p, s == 42)
local idx = 0
local proxy = setmetatable({}, { __index = function(t, k) idx = idx + 1 return k .. "!" end })
print(proxy.foo, proxy["bar"], idx)
local api = setmetatable({}, { __index = function(t, k) idx = idx + 1 return function(self, m) return m * 2 end end })
print(api:scale(21), idx)
GLOB = s + p
print(GLOB)
if x then print("truthy-obj") end
if not (s == 0) then print("nz") end
"#;

fn h2_behaves(label: &str, hard: bool, surface: bool, heavy: pipeline::SurfaceVolume) {
    let Some(luau) = find_luau() else { return };
    let obf = pipeline::virtualize_full_opt(
        H2_SRC, 0x4832, true, true, true, true, true, false, false, hard, surface, heavy, false,
    )
    .unwrap();
    let raw = run_code(&luau, H2_SRC, &format!("h2_raw_{label}"));
    let virt = run_code(&luau, &obf, &format!("h2_virt_{label}"));
    assert_eq!(
        raw.stdout, virt.stdout,
        "[{label}] H2 metamethod/eval-once raw==virt"
    );
    assert_eq!(raw.code, virt.code, "[{label}] H2 exit code");
}

#[test]
fn h2_preserves_metamethods_and_eval_order() {
    h2_behaves("plain", false, false, pipeline::SurfaceVolume::Off);
    h2_behaves("hard", true, false, pipeline::SurfaceVolume::Off);
    h2_behaves("surface", false, true, pipeline::SurfaceVolume::Off);
    h2_behaves(
        "hard_surface_heavy",
        true,
        true,
        pipeline::SurfaceVolume::Medium,
    );
}

fn h2_vm(seed: u64) -> String {
    pipeline::virtualize_full(
        H2_SRC,
        seed,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap()
}

#[test]
fn h2_operator_thunks_hide_visible_ops() {
    let vm = h2_vm(0x4832);
    for clean in [
        "rg(R, inst.b) + rg(R, inst.c)",
        "rg(R, inst.b) - rg(R, inst.c)",
        "rg(R, inst.b) * rg(R, inst.c)",
        "rg(R, inst.b) .. rg(R, inst.c)",
        "rg(R, inst.b) < rg(R, inst.c)",
        "rg(R, inst.b) == rg(R, inst.c)",
    ] {
        assert!(
            !vm.contains(clean),
            "operator must not appear inline in a handler: `{clean}`"
        );
    }
}

#[test]
fn h2_branch_predicates_hide_direct_jump_conditions() {
    let vm = h2_vm(0x4832);
    assert!(
        !vm.contains("if not rg(R, a) then"),
        "JMPIFNOT must route through a predicate helper"
    );
    assert!(
        !vm.contains("if rg(R, a) then"),
        "JMPIF must route through a predicate helper"
    );
    assert!(
        vm.contains("local function or1a(m, x)"),
        "VM must define the unary/predicate route shard"
    );
}

#[test]
fn h2_route_helpers_hide_global_table_self_shapes() {
    let vm = h2_vm(0x4832);
    assert!(!vm.contains("rg(genv,"), "GETGLOBAL must route through h_g");
    assert!(
        !vm.contains("rg(rg(R,"),
        "GETTABLE/SELF must not nest the index inline"
    );
    assert!(
        !vm.contains("rs(R, a + 1, rg(R, inst.b))"),
        "SELF must not expose the method/self pair shape"
    );
    assert!(
        vm.contains("local function h_g(k)"),
        "VM must define the global route helper"
    );
    assert!(
        vm.contains("local function h_self(o, k)"),
        "VM must define the self route helper"
    );
}

#[test]
fn h2_generic_alu_and_no_one_helper_per_operator() {
    let vm = h2_vm(0x4832);
    assert!(
        vm.contains("local function or2a(m, x, y)"),
        "generic binary route shard or2a must exist"
    );
    assert!(
        vm.contains("local function or2b(m, x, y)"),
        "generic binary route shard or2b must exist"
    );
    for one_op in [
        "(x, y)\nreturn x + y\nend",
        "(x, y)\nreturn x - y\nend",
        "(x, y)\nreturn x < y\nend",
    ] {
        assert!(
            !vm.contains(one_op),
            "no single-operator helper may exist: `{one_op}`"
        );
    }
    let has_token_call = vm.lines().any(|l| {
        (l.contains("or2a(") || l.contains("or2b("))
            && !l.contains("local function")
            && l.matches(|c: char| c.is_ascii_digit()).count() >= 6
    });
    assert!(
        has_token_call,
        "binary handlers must call a route shard with a numeric token"
    );
}

fn route_tokens_of(vm: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for (i, _) in vm.match_indices("r == ") {
        let tail: String = vm[i + 5..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(v) = tail.parse::<u64>() {
            out.push(v);
        }
    }
    out.sort_unstable();
    out
}

#[test]
fn h2_route_tokens_seeded() {
    let a = h2_vm(0x1111);
    let b = h2_vm(0x2222);
    let ta = route_tokens_of(&a);
    let tb = route_tokens_of(&b);
    assert!(
        ta.len() >= 6 && tb.len() >= 6,
        "expected route tokens in both builds"
    );
    assert_ne!(
        ta, tb,
        "different seeds must produce different route tokens"
    );
    assert_eq!(
        route_tokens_of(&h2_vm(0x1111)),
        ta,
        "same seed must produce the same route tokens"
    );
}

#[test]
fn h2_seed_variation_and_determinism() {
    assert_eq!(
        h2_vm(0x9ABC),
        h2_vm(0x9ABC),
        "same source+seed must be byte-identical"
    );
    assert_ne!(
        h2_vm(0x9ABC),
        h2_vm(0xDEF0),
        "different seeds must change handler bodies/helpers"
    );
}

#[test]
fn h2_h1_not_regressed() {
    let vm = h2_vm(0x4832);
    for clean in [
        "R[a] = R[inst.b]",
        "R[a] = genv[",
        "if not R[a] then",
        "R[a + 1] = R[inst.b]",
    ] {
        assert!(
            !vm.contains(clean),
            "H1 clean pattern must stay absent: `{clean}`"
        );
    }
}

#[test]
fn h2_introduces_no_forbidden_apis() {
    let obf = pipeline::virtualize_full_opt(
        H2_SRC,
        0x4832,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        pipeline::SurfaceVolume::Medium,
        false,
    )
    .unwrap();
    for bad in [
        "loadstring",
        "HttpService",
        "HttpGet",
        "debug.getinfo",
        "debug.traceback",
        "debug.info",
    ] {
        assert!(!obf.contains(bad), "H2 artifact must not reference `{bad}`");
    }
}

const H3_SRC: &str = r#"
local mt = {
  __add = function(a, b) return rawget(a, "v") + rawget(b, "v") end,
  __sub = function(a, b) return rawget(a, "v") - rawget(b, "v") end,
  __mul = function(a, b) return rawget(a, "v") * rawget(b, "v") end,
  __div = function(a, b) return rawget(a, "v") / rawget(b, "v") end,
  __mod = function(a, b) return rawget(a, "v") % rawget(b, "v") end,
  __pow = function(a, b) return rawget(a, "v") ^ rawget(b, "v") end,
  __idiv = function(a, b) return rawget(a, "v") // rawget(b, "v") end,
  __concat = function(a, b) return rawget(a, "v") .. tostring(b) end,
  __eq = function(a, b) return rawget(a, "v") == rawget(b, "v") end,
  __lt = function(a, b) return rawget(a, "v") < rawget(b, "v") end,
  __le = function(a, b) return rawget(a, "v") <= rawget(b, "v") end,
  __len = function(t) return rawget(t, "v") end,
  __unm = function(t) return -rawget(t, "v") end,
}
local function obj(v) local o = setmetatable({}, mt) rawset(o, "v", v) return o end
local a, b = obj(20), obj(6)
print(a + b, a - b, a * b, a / b, a % b, a // b)
print(a ^ obj(2), a .. "!", #a, -a)
print(obj(5) == obj(5), obj(5) == obj(6), obj(2) < obj(9), obj(9) <= obj(9))
local s, p = 0, 1
for i = 1, 7 do s = s + i * 3 - (i % 2) p = p * (i % 5 + 1) end
print(s, p, s > p, s == 70)
local idx = 0
local proxy = setmetatable({}, {
  __index = function(t, k) idx = idx + 1 return k .. "!" end,
  __newindex = function(t, k, v) idx = idx + 1 rawset(t, "_" .. k, v) end,
})
print(proxy.foo, proxy["bar"], idx)
proxy.set = 9
print(rawget(proxy, "_set"), idx)
local api = setmetatable({}, { __index = function(t, k) idx = idx + 1 return function(self, m) return m * 2 end end })
print(api:scale(21), idx)
GLOB = s + p
print(GLOB)
if a then print("truthy") end
if not (s == 0) then print("nz") end
"#;

fn h3_behaves(label: &str, hard: bool, surface: bool, heavy: pipeline::SurfaceVolume) {
    let Some(luau) = find_luau() else { return };
    let obf = pipeline::virtualize_full_opt(
        H3_SRC, 0x4833, true, true, true, true, true, false, false, hard, surface, heavy, false,
    )
    .unwrap();
    let raw = run_code(&luau, H3_SRC, &format!("h3_raw_{label}"));
    let virt = run_code(&luau, &obf, &format!("h3_virt_{label}"));
    assert_eq!(
        raw.stdout, virt.stdout,
        "[{label}] H3 metamethod/eval-once raw==virt"
    );
    assert_eq!(raw.code, virt.code, "[{label}] H3 exit code");
}

#[test]
fn h3_preserves_metamethods_and_eval_order() {
    h3_behaves("plain", false, false, pipeline::SurfaceVolume::Off);
    h3_behaves("hard", true, false, pipeline::SurfaceVolume::Off);
    h3_behaves("surface", false, true, pipeline::SurfaceVolume::Off);
    h3_behaves(
        "hard_surface_heavy",
        true,
        true,
        pipeline::SurfaceVolume::Medium,
    );
}

fn h3_vm(seed: u64) -> String {
    pipeline::virtualize_full(
        H3_SRC,
        seed,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap()
}

fn shard_region<'a>(vm: &'a str, name: &str) -> &'a str {
    let start = vm
        .find(&format!("local function {name}("))
        .expect("shard def");
    let rest = &vm[start + 10..];
    let end = rest
        .find("local function ")
        .map(|e| start + 10 + e)
        .unwrap_or(vm.len());
    &vm[start..end]
}

fn decode_rot(region: &str) -> u32 {
    let i = region.find("bxor(lrotate(m, ").expect("decode line") + "bxor(lrotate(m, ".len();
    region[i..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap()
}

fn decode_key_token(region: &str) -> String {
    let i = region.find("bxor(lrotate(m, ").expect("decode line");
    let j = region[i..].find("), ").expect("decode key") + i + 3;
    region[j..]
        .chars()
        .take_while(|&c| c != ')' && c != '\n')
        .collect::<String>()
        .trim()
        .to_string()
}

fn callsite_first_args(vm: &str, name: &str) -> Vec<u32> {
    let needle = format!("{name}(");
    let mut out = Vec::new();
    for (i, _) in vm.match_indices(&needle) {
        let tail = &vm[i + needle.len()..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(v) = digits.parse::<u32>() {
            out.push(v);
        }
    }
    out
}

#[test]
fn h3_callsite_tokens_are_masked_and_not_clear_arm_selectors() {
    let vm = h3_vm(0x4833);
    for shard in ["or2a", "or2b", "or1a"] {
        let region = shard_region(&vm, shard);
        assert_eq!(
            decode_key_token(region),
            "RSALT",
            "{shard} decode key must be the runtime RSALT"
        );
        let _ = decode_rot(region);
        let arms: std::collections::HashSet<u32> = route_tokens_of(region)
            .into_iter()
            .map(|t| t as u32)
            .collect();
        let callsites = callsite_first_args(&vm, shard);
        assert!(!callsites.is_empty(), "{shard} must have call sites");
        for lit in callsites {
            assert!(
                !arms.contains(&lit),
                "{shard}: callsite literal {lit} must NOT be a clear arm selector"
            );
        }
    }
}

#[test]
fn h3_basic_token_fold_mapper_fails() {
    let vm = h3_vm(0x4833);
    let arms: std::collections::HashSet<u32> =
        route_tokens_of(&vm).into_iter().map(|t| t as u32).collect();
    let mut callsites = Vec::new();
    for shard in ["or2a", "or2b", "or1a"] {
        callsites.extend(callsite_first_args(&vm, shard));
    }
    let matched = callsites.iter().filter(|c| arms.contains(c)).count();
    assert_eq!(
        matched, 0,
        "no masked callsite literal may directly match a helper-arm selector"
    );
}

#[test]
fn h3_no_single_clear_token_map_and_blurred_categories() {
    let vm = h3_vm(0x4833);
    let (a, b) = (shard_region(&vm, "or2a"), shard_region(&vm, "or2b"));
    let count = |r: &str, op: &str| r.matches(&format!("return x {op} y")).count();
    let arith_a = ["+", "-", "*", "/", "%", "^", "//", ".."]
        .iter()
        .map(|o| count(a, o))
        .sum::<usize>();
    let arith_b = ["+", "-", "*", "/", "%", "^", "//", ".."]
        .iter()
        .map(|o| count(b, o))
        .sum::<usize>();
    assert!(
        arith_a > 0 && arith_b > 0,
        "arithmetic must be split across both binary shards"
    );
    assert!(
        arith_a < 8 || arith_b < 8,
        "no single shard may hold every arithmetic operator"
    );
}

#[test]
fn h3_route_decode_is_cheap_no_per_op_decrypt() {
    let vm = h3_vm(0x4833);
    for shard in ["or2a", "or2b", "or1a"] {
        let region = shard_region(&vm, shard);
        assert!(
            region.contains("bxor(lrotate(m,"),
            "{shard} must decode via a cheap rotate+xor"
        );
        assert!(
            !region.contains("streamXor"),
            "{shard} must not run a stream cipher per op"
        );
        assert!(
            !region.contains("chachaBlock"),
            "{shard} must not run chacha per op"
        );
        assert!(
            !region.contains("kget("),
            "{shard} must not decrypt a constant per op"
        );
    }
}

#[test]
fn h3_helper_inline_not_enough() {
    let vm = h3_vm(0x4833);
    for clean in [
        "rg(R, inst.b) + rg(R, inst.c)",
        "rg(R, inst.b) < rg(R, inst.c)",
        "rg(R, inst.b) .. rg(R, inst.c)",
        "if not rg(R, a) then",
        "if rg(R, a) then",
        "rg(genv,",
        "rg(rg(R,",
    ] {
        assert!(
            !vm.contains(clean),
            "no local operator/branch/access shape may remain: `{clean}`"
        );
    }
}

#[test]
fn h3_seed_variation_and_determinism() {
    assert_eq!(
        h3_vm(0x55AA),
        h3_vm(0x55AA),
        "same source+seed must be byte-identical"
    );
    let a = h3_vm(0x55AA);
    let b = h3_vm(0x66BB);
    assert_ne!(a, b, "different seeds must change shards/masks/arms/decoys");
    assert_ne!(
        callsite_first_args(&a, "or2a"),
        callsite_first_args(&b, "or2a"),
        "route masks must be seeded"
    );
}

#[test]
fn h3_h2_not_regressed() {
    let vm = h3_vm(0x4833);
    for one_op in ["(x, y)\nreturn x + y\nend", "(x, y)\nreturn x < y\nend"] {
        assert!(
            !vm.contains(one_op),
            "no single-operator helper may exist: `{one_op}`"
        );
    }
}

#[test]
fn h3_introduces_no_forbidden_apis() {
    let obf = pipeline::virtualize_full_opt(
        H3_SRC,
        0x4833,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        pipeline::SurfaceVolume::Medium,
        false,
    )
    .unwrap();
    for bad in [
        "loadstring",
        "HttpService",
        "HttpGet",
        "debug.getinfo",
        "debug.traceback",
        "debug.info",
    ] {
        assert!(!obf.contains(bad), "H3 artifact must not reference `{bad}`");
    }
}

fn rsalt_derivation(vm: &str) -> &str {
    let i = vm.find("RSALT = ").expect("RSALT derivation");
    let rest = &vm[i..];
    &rest[..rest.find('\n').unwrap_or(rest.len())]
}

#[test]
fn h4_no_source_only_route_decode() {
    let vm = h3_vm(0x4833);
    for shard in ["or2a", "or2b", "or1a"] {
        let key = decode_key_token(shard_region(&vm, shard));
        assert_eq!(
            key, "RSALT",
            "{shard} decode key must be the runtime RSALT, not a source literal"
        );
        assert!(
            key.parse::<u32>().is_err(),
            "{shard} decode key must not be a source-readable number"
        );
    }
}

#[test]
fn h4_route_material_is_protected() {
    let vm = h3_vm(0x4833);
    let deriv = rsalt_derivation(&vm);
    assert!(
        deriv.contains("genkey["),
        "RSALT must be derived from the gen-key: `{deriv}`"
    );
    for shard in ["or2a", "or2b", "or1a"] {
        assert!(
            shard_region(&vm, shard).contains(", RSALT)"),
            "{shard} must fold the protected RSALT"
        );
    }
}

#[test]
fn h4_h3_mapper_fails() {
    let vm = h3_vm(0x4833);
    let mut recovered = 0usize;
    for shard in ["or2a", "or2b", "or1a"] {
        let region = shard_region(&vm, shard);
        let rot = decode_rot(region);
        let Ok(key) = decode_key_token(region).parse::<u32>() else {
            continue;
        };
        let arms: std::collections::HashSet<u32> = route_tokens_of(region)
            .into_iter()
            .map(|t| t as u32)
            .collect();
        for lit in callsite_first_args(&vm, shard) {
            if arms.contains(&(lit.rotate_left(rot) ^ key)) {
                recovered += 1;
            }
        }
    }
    assert_eq!(
        recovered, 0,
        "the H3 source-only mapper must recover no operator routes after H4"
    );
}

#[test]
fn h4_route_cache_works() {
    let vm = h3_vm(0x4833);
    assert_eq!(
        vm.matches("RSALT = bxor").count(),
        1,
        "RSALT must be derived exactly once"
    );
    for shard in ["or2a", "or2b", "or1a"] {
        let region = shard_region(&vm, shard);
        assert!(
            !region.contains("genkey"),
            "{shard} must not re-derive the salt from the gen-key per op"
        );
        assert!(
            region.contains("bxor(lrotate(m,"),
            "{shard} decode must be a cheap rotate+xor"
        );
        for heavy in ["chachaBlock", "streamXor", "kget(", "deriveGenKey"] {
            assert!(
                !region.contains(heavy),
                "{shard} must not run `{heavy}` per op"
            );
        }
    }
}

fn h4_behaves(label: &str, seed: u64, hard: bool, surface: bool, heavy: pipeline::SurfaceVolume) {
    let Some(luau) = find_luau() else { return };
    let obf = pipeline::virtualize_full_opt(
        H3_SRC, seed, true, true, true, true, true, false, false, hard, surface, heavy, false,
    )
    .unwrap();
    let raw = run_code(&luau, H3_SRC, &format!("h4_raw_{label}"));
    let virt = run_code(&luau, &obf, &format!("h4_virt_{label}"));
    assert_eq!(
        raw.stdout, virt.stdout,
        "[{label}] H4 metamethod/eval-once raw==virt"
    );
    assert_eq!(raw.code, virt.code, "[{label}] H4 exit code");
}

#[test]
fn h4_preserves_metamethods_and_eval_order() {
    h4_behaves("plain", 0xF4A1, false, false, pipeline::SurfaceVolume::Off);
    h4_behaves("hard", 0xF4A1, true, false, pipeline::SurfaceVolume::Off);
    h4_behaves("surface", 0xF4A1, false, true, pipeline::SurfaceVolume::Off);
    h4_behaves(
        "hard_surface_heavy",
        0xF4A1,
        true,
        true,
        pipeline::SurfaceVolume::Large,
    );
}

#[test]
fn h4_c1_1_compatibility() {
    let Some(luau) = find_luau() else { return };
    let src = "local s, n = \"alpha\", 0\nfor i = 1, 12 do n = n + i * 3 - (i % 2) s = s .. tostring(i % 4) end\nprint(s, n, n > 100, s == \"alpha\")\nprint((\"k\"):rep(3), #s, -n)";
    let obf = pipeline::virtualize_full(
        src,
        0x5151,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    assert!(
        obf.contains("ktok") && obf.contains("kget("),
        "C1.1 site-token constant accessor must be intact"
    );
    let raw = run_code(&luau, src, "h4_c11_raw");
    let virt = run_code(&luau, &obf, "h4_c11_virt");
    assert_eq!(
        raw.stdout, virt.stdout,
        "constants + routes must coexist and run correctly"
    );
}

#[test]
fn h4_encfunc_inner_proto_compatibility() {
    let Some(luau) = find_luau() else { return };
    let body = format!(
        "local f = BASIL_ENCFUNC(function(a, b) local d = a // b local m = a % b return (a + b) .. \":\" .. (a < b and \"lt\" or \"ge\"), d * m - #tostring(a) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(23, 5))"
    );
    let src = enc_external(&body);
    let raw = run_injected(&luau, "h4_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0x6262, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "h4_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(
        !raw.stdout.trim().is_empty(),
        "raw produced no output (setup broken)"
    );
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC inner-proto arithmetic/compare/concat must route correctly"
    );
    assert!(
        !obf.contains(ENCFUNC_KEY),
        "compile/runtime key must not be embedded"
    );
}

#[test]
fn h4_seed_variation() {
    assert_eq!(
        h3_vm(0x77CC),
        h3_vm(0x77CC),
        "same source+seed must be byte-identical"
    );
    let (a, b) = (h3_vm(0x77CC), h3_vm(0x88DD));
    assert_ne!(
        a, b,
        "different seeds must change route material/slots/masks/shard layout/decoys"
    );

    assert_ne!(
        callsite_first_args(&a, "or2a"),
        callsite_first_args(&b, "or2a"),
        "route masks must vary across seeds"
    );
}

#[test]
fn h4_no_forbidden_apis() {
    for &heavy in &[
        pipeline::SurfaceVolume::Off,
        pipeline::SurfaceVolume::Medium,
    ] {
        let obf = pipeline::virtualize_full_opt(
            H3_SRC, 0x4833, true, true, true, true, true, false, false, true, true, heavy, false,
        )
        .unwrap();
        for bad in [
            "loadstring",
            "load(",
            "HttpService",
            "HttpGet",
            "debug.getinfo",
            "debug.traceback",
            "debug.info",
            "BASIL_",
        ] {
            assert!(
                !obf.contains(bad),
                "H4 artifact must not reference `{bad}` (heavy={heavy:?})"
            );
        }
        let hex64 = obf
            .as_bytes()
            .windows(64)
            .filter(|w| w.iter().all(|c| c.is_ascii_hexdigit()))
            .count();
        assert_eq!(
            hex64, 0,
            "H4 artifact must carry no 64-hex key material (heavy={heavy:?})"
        );
    }
}

#[test]
fn h4_perf_guard() {
    let vm = h3_vm(0x4833);
    let deriv = rsalt_derivation(&vm);
    assert!(
        deriv.contains("bxor") && deriv.contains("lrotate"),
        "RSALT fold must be cheap bit ops"
    );
    assert_eq!(
        vm.matches("genkey = deriveGenKey").count(),
        1,
        "the gen-key (and thus RSALT) is derived once"
    );
    for shard in ["or2a", "or2b", "or1a"] {
        assert!(
            !shard_region(&vm, shard).contains("genkey"),
            "{shard} must not touch the gen-key per op"
        );
    }
}

fn c12_vm(seed: u64) -> String {
    pipeline::virtualize_full(
        "local x = 1 + 2 print(x)",
        seed,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap()
}

#[test]
fn c1_2_missing_debug_still_runs() {
    let Some(luau) = find_luau() else { return };
    let src = "local s = \"c12-\" .. tostring(40 + 2)\nprint(s, 7 * 6)";
    let obf = pipeline::virtualize_full_opt(
        src,
        0x_C12A,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
    )
    .unwrap();
    let raw = run_code(&luau, src, "c12_md_raw");
    let virt = run_code(&luau, &format!("debug = nil\n{obf}"), "c12_md_virt");
    assert_eq!(
        raw.stdout, virt.stdout,
        "VM must run correctly with debug absent (debug not load-bearing)"
    );
}

#[test]
fn c1_2_wrong_probe_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let src = "print(\"c12secret-\" .. tostring(1234 + 1))";
    let obf = pipeline::virtualize_full_opt(
        src,
        0x_C12B,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
    )
    .unwrap();
    let correct = run_code(&luau, src, "c12_fc_raw");
    assert!(correct.stdout.contains("c12secret-1235"), "raw sanity");
    let hook = "local _t = tostring\ntostring = function(x) local r = _t(x) if r == \"0.30000000000000004\" then return \"0.3\" end return r end\n";
    let tampered = run_code(&luau, &format!("{hook}{obf}"), "c12_fc_virt");
    assert_ne!(
        correct.stdout, tampered.stdout,
        "a mis-modelled number-format host must NOT yield correct output"
    );
    assert!(
        !tampered.stdout.contains("c12secret-1235"),
        "the secret constant must not decrypt under a wrong env fingerprint"
    );
}

#[test]
fn c1_2_number_format_fingerprint_present() {
    let vm = c12_vm(0x_C12C);
    let probe = &vm[vm.find("envProbe").expect("envProbe")..];
    let probe = &probe[..probe.find("\nend").map(|e| e + 4).unwrap_or(probe.len())];
    for expr in ["0.1+0.2", "1/3", "2^53", "2^63", "0/0"] {
        assert!(
            probe.contains(expr),
            "envProbe must fold the number-format probe `{expr}`"
        );
    }
}

#[test]
fn c1_2_behavior_error_fingerprint_present() {
    let vm = c12_vm(0x_C12D);
    let probe = &vm[vm.find("envProbe").expect("envProbe")..];
    let probe = &probe[..probe
        .find("\nreturn p\nend")
        .map(|e| e + 12)
        .unwrap_or(probe.len())];
    for body in ["return nil + nil", "return ({}) < ({})"] {
        assert!(
            probe.contains(body),
            "envProbe must fold the error-shape probe `{body}`"
        );
    }
    assert!(
        probe.contains("pcall") || probe.contains("pc("),
        "error probes must run under pcall"
    );
}

#[test]
fn c1_2_static_predictability_audit() {
    let vm = c12_vm(0x_C12E);
    let probe = &vm[vm.find("envProbe").expect("envProbe")..];
    let probe = &probe[..probe
        .find("\nreturn p\nend")
        .map(|e| e + 12)
        .unwrap_or(probe.len())];
    let distinct_num = ["1/0", "-1/0", "0/0", "0.1+0.2", "1/3", "2^53", "2^63"]
        .iter()
        .filter(|e| probe.contains(**e))
        .count();
    assert!(
        distinct_num >= 5,
        "the env hash must fold many distinct number-format inputs, not one constant"
    );
    assert!(
        probe.contains("if nf then"),
        "the debug.info fold must be optional (guarded), not load-bearing"
    );
}

#[test]
fn c1_2_no_forbidden_apis() {
    for &heavy in &[
        pipeline::SurfaceVolume::Off,
        pipeline::SurfaceVolume::Medium,
    ] {
        let obf = pipeline::virtualize_full_opt(
            "local a = 5 print(a * a)",
            0x_C12F,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            heavy,
            false,
        )
        .unwrap();
        for bad in [
            "loadstring",
            "load(",
            "HttpService",
            "HttpGet",
            "debug.getinfo",
            "debug.traceback",
            "debug.info",
        ] {
            assert!(
                !obf.contains(bad),
                "C1.2 artifact must not reference `{bad}` (heavy={heavy:?})"
            );
        }
    }
}

fn s1_src(body: &str) -> String {
    format!("{body}\n")
}

#[test]
fn s1_encfunc_external_key_tier3() {
    let src = enc_external(&format!(
        "local f = BASIL_ENCFUNC(function() return \"secret\" end, \"{ENCFUNC_KEY}\", rk)\nprint(f())"
    ));
    let report = pipeline::sensitive_audit(&src).unwrap();
    let tier3 = report.split("Tier 3").nth(1).unwrap_or("");
    assert!(
        tier3.contains("BASIL_ENCFUNC"),
        "ENCFUNC with an external key must be Tier 3"
    );
}

#[test]
fn s1_require_external_key_validates_encfunc_only() {
    let bad = format!(
        "local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", \"{ENCFUNC_KEY}\")\nprint(f(1))"
    );
    let opts = pipeline::SensitiveOpts {
        audit: false,
        strict: false,
        require_external: true,
    };
    let r = pipeline::virtualize_full_sens(
        &bad,
        1,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        opts,
    );
    assert!(
        r.is_err(),
        "--require-external-key must reject an artifact-derived ENCFUNC runtime key"
    );
    let encval = s1_src("local s = \"hi\"\nlocal n = 123\nprint(s, n)");
    let ok = pipeline::virtualize_full_sens(
        &encval,
        1,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        opts,
    );
    assert!(
        ok.is_ok(),
        "--require-external-key must not touch one-arg ENCSTR/ENCNUM"
    );
}

#[test]
fn s1_encfunc_literal_deckey_rejected() {
    let src = format!(
        "local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", \"{ENCFUNC_KEY}\")\nprint(f(1))"
    );
    assert!(
        pipeline::virtualize_with(&src, 1, false, false, false, false, true, false, false).is_err(),
        "ENCFUNC literal runtime key must be rejected"
    );
}

#[test]
fn s1_encfunc_const_alias_deckey_rejected() {
    let src = format!(
        "local k = \"{ENCFUNC_KEY}\"\nlocal f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", k)\nprint(f(1))"
    );
    assert!(
        pipeline::virtualize_with(&src, 1, false, false, false, false, true, false, false).is_err(),
        "ENCFUNC local-constant-alias runtime key must be rejected"
    );
}

#[test]
fn s1_encfunc_const_concat_deckey_rejected() {
    let half = &ENCFUNC_KEY[..32];
    let src = format!(
        "local k = \"{half}\" .. \"{half}\"\nlocal f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", k)\nprint(f(1))"
    );
    assert!(
        pipeline::virtualize_with(&src, 1, false, false, false, false, true, false, false).is_err(),
        "ENCFUNC static-concat runtime key must be rejected"
    );
}

#[test]
fn s1_encfunc_wrong_key_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let src = enc_external(&format!(
        "local f = BASIL_ENCFUNC(function() return \"PLAINTEXT-BODY\" end, \"{ENCFUNC_KEY}\", rk)\n\
         local ok, v = pcall(f)\nif ok then print(v) else print(\"failed-closed\") end"
    ));
    let obf = pipeline::virtualize_with(&src, 0x530B, true, true, true, true, true, false, false)
        .unwrap();
    let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let out = run_injected(&luau, "s1_encfunc_wrongkey.luau", &obf, Some(wrong));
    assert!(
        !out.stdout.contains("PLAINTEXT-BODY"),
        "wrong ENCFUNC key must not yield the sealed body (fail closed)"
    );
}

#[test]
fn s1_encfunc_compile_key_not_emitted() {
    let src = enc_external(&format!(
        "local f = BASIL_ENCFUNC(function(u) return \"OK:\" .. tostring(u) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(7))"
    ));
    let obf = pipeline::virtualize_with(&src, 0x5308, true, true, true, true, true, false, false)
        .unwrap();
    assert!(
        !obf.contains(ENCFUNC_KEY),
        "ENCFUNC compile key must never appear in the artifact"
    );
}

#[test]
fn s1_audit_tiers_report() {
    let leak = "deadbeefcafe0001deadbeefcafe0002deadbeefcafe0003deadbeefcafe0004";
    let src = enc_external(&format!(
        "local pub = \"hello world\"\nlocal note = \"{leak}\"\nlocal t = \"marked\"\n\
         local f = BASIL_ENCFUNC(function() return \"x\" end, \"{ENCFUNC_KEY}\", rk)\nprint(pub, note, t, f())"
    ));
    let report = pipeline::sensitive_audit(&src).unwrap();
    for tier in ["Tier 0", "Tier 1", "Tier 2", "Tier 3"] {
        assert!(report.contains(tier), "report lists {tier}");
    }
    assert!(
        report.contains("64-hex token"),
        "Tier 1 must flag the bare secret-looking literal"
    );
    let tier1 = report
        .split("Tier 1")
        .nth(1)
        .unwrap_or("")
        .split("Tier 2")
        .next()
        .unwrap_or("");
    assert!(
        tier1.contains("secret-looking literal"),
        "Tier 1 must carry the ordinary secret-looking literal"
    );
    let tier3 = report.split("Tier 3").nth(1).unwrap_or("");
    assert!(tier3.contains("BASIL_ENCFUNC"), "ENCFUNC must be in Tier 3");
}

#[test]
fn s1_high_confidence_secret_heuristic() {
    let webhook = "https://discord.com/api/webhooks/123456789/abcDEFghiJKLmnoPQRstuVWXyz";
    let src = format!("local w = \"{webhook}\"\nprint(w)");
    let report = pipeline::sensitive_audit(&src).unwrap();
    assert!(
        report.contains("discord webhook URL") || report.contains("URL with credential marker"),
        "webhook-like literal must be flagged in the audit"
    );
    let opts = pipeline::SensitiveOpts {
        audit: false,
        strict: true,
        require_external: false,
    };
    let r = pipeline::virtualize_full_sens(
        &src,
        1,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        opts,
    );
    assert!(r.is_err(), "--sensitive-strict must error on a high-confidence secret that is not external-key protected");
}

#[test]
fn s1_no_generated_network_client() {
    let src = s1_src("local s = \"x\"\nlocal n = 7\nprint(s, n)");
    let obf = pipeline::virtualize_with(&src, 0x5309, true, true, true, true, true, false, false)
        .unwrap();
    for bad in [
        "HttpService",
        "HttpGet",
        "HttpPost",
        "PostAsync",
        "GetAsync",
        "RequestAsync",
        "socket",
        "loadstring",
    ] {
        assert!(
            !obf.contains(bad),
            "S1 artifact must not reference network/loader API `{bad}`"
        );
    }
}

#[test]
fn s1_preserve_existing_encfunc() {
    let Some(luau) = find_luau() else { return };
    let src = enc_external(&format!(
        "local f = BASIL_ENCFUNC(function(a, b) return a + b, a .. tostring(b) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(3, 4))"
    ));
    let raw = run_injected(&luau, "s1_pef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0x530A, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "s1_pef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(!raw.stdout.trim().is_empty(), "raw sanity");
    assert_eq!(
        raw.stdout, virt.stdout,
        "existing ENCFUNC behavior must be preserved"
    );
}

#[test]
fn f1_constants_roundtrip() {
    let Some(luau) = find_luau() else { return };
    let src = "local s = { \"alpha\", \"beta gamma\", \"\", \"\\0\\255mixed\" }\n\
local n = { 0, -7, 3.14159, 1000000, -2.5, 2^31 }\n\
local b = { true, false }\n\
local z = nil\n\
local acc = \"\"\n\
for i = 1, #s do acc = acc .. s[i] .. \"|\" end\n\
local sum = 0 for _, v in ipairs(n) do sum = sum + v end\n\
print(acc, sum, b[1], b[2], z == nil, #s)\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("f1_rt_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    let obf =
        pipeline::virtualize_with(src, 0xF101, true, true, true, true, true, false, false).unwrap();
    let virt = run_luau(&luau, &{
        let p = std::env::temp_dir().join("f1_rt_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert!(!raw.stdout.trim().is_empty(), "raw sanity");
    assert_eq!(
        raw.stdout, virt.stdout,
        "all constant kinds must round-trip under the F1 keyed lane"
    );
}

#[test]
fn f1_c1_1_site_tokens_preserved() {
    let Some(luau) = find_luau() else { return };
    let src = "local k = { \"shared_one\", \"shared_two\" }\n\
local t = {}\n\
for i = 1, #k do t[k[i]] = i end\n\
local s = \"\"\n\
for _ = 1, 3 do for i = 1, #k do s = s .. k[i] .. tostring(t[k[i]]) end end\n\
print(s, t.shared_one, t[\"shared_two\"])\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("f1_site_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    let obf = pipeline::virtualize_with(src, 0xF103, true, true, true, true, false, false, false)
        .unwrap();
    assert!(
        obf.contains("ktoks") && obf.contains("ksite"),
        "C1.1 site-token machinery must remain in the VM"
    );
    let virt = run_luau(&luau, &{
        let p = std::env::temp_dir().join("f1_site_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, virt.stdout,
        "shared/looped/table-key constants stay exact under F1 site tokens"
    );
}

#[test]
fn f1_c4_string_no_cache_preserved() {
    let vm = pipeline::virtualize_with(
        "local s = \"abcdefghij\"\nreturn s, 12345\n",
        0xF104,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
    )
    .unwrap();
    assert!(
        vm.contains("return sub(plain, 10)"),
        "string path must be decrypt-use-discard at the F1 body offset"
    );
    assert!(
        vm.contains("kc[i] = (unpacks(sD, plain, 10))"),
        "number path must keep the cached fast path"
    );
}

#[test]
fn f1_h4_rsalt_still_deterministic() {
    let src = "local a = \"determinism\" local b = 4242 print(a, b)\n";
    let v1 =
        pipeline::virtualize_with(src, 0xF105, true, true, true, true, true, false, false).unwrap();
    let v2 =
        pipeline::virtualize_with(src, 0xF105, true, true, true, true, true, false, false).unwrap();
    assert_eq!(
        v1, v2,
        "same seed must produce a byte-identical VM (RSALT + wide env key deterministic)"
    );
    let v3 =
        pipeline::virtualize_with(src, 0xF106, true, true, true, true, true, false, false).unwrap();
    assert_ne!(v1, v3, "a different seed must change the build");
}

#[test]
fn f1_s1_encfunc_unchanged() {
    let Some(luau) = find_luau() else { return };
    let src = enc_external(&format!(
        "local f = BASIL_ENCFUNC(function(x) return \"unlocked:\" .. tostring(x) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(7))"
    ));
    let raw = run_injected(&luau, "f1_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0xF107, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "f1_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("unlocked:7"), "raw sanity");
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external-key round-trip preserved under F1"
    );
    assert!(
        !obf.contains(ENCFUNC_KEY),
        "ENCFUNC compile key must be absent"
    );
    assert!(
        !obf.contains("unlocked:"),
        "the sealed ENCFUNC body must be absent from the artifact"
    );
    let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let bad = run_injected(&luau, "f1_ef_bad.luau", &obf, Some(wrong));
    assert!(
        !bad.stdout.contains("unlocked:7"),
        "wrong external key must fail closed"
    );
}

#[test]
fn f1_static_audit_no_plaintext_regression() {
    let src =
        "local secret = \"recognizable_marker_string\"\nlocal pin = 8675309\nprint(secret, pin)\n";
    let obf =
        pipeline::virtualize_with(src, 0xF108, true, true, true, true, true, false, false).unwrap();
    assert!(
        !obf.contains("recognizable_marker_string"),
        "plaintext string constant must not appear"
    );
    assert!(
        !obf.contains("8675309"),
        "plaintext numeric constant must not appear"
    );
    assert!(!obf.contains("BASIL_"), "no BASIL_ markers in the artifact");
    assert_eq!(obf.matches("loadstring").count(), 0, "no loadstring");
}

#[test]
fn f1_size_perf_benchmark() {
    let mut src = String::from("local t = {}\n");
    for i in 0..200 {
        src.push_str(&format!("t[{i}] = \"const_string_number_{i}\"\n"));
    }
    src.push_str("local n = 0 for i = 0, 199 do n = n + #t[i] end print(n)\n");
    let obf = pipeline::virtualize_with(&src, 0xF109, true, true, true, true, true, false, false)
        .unwrap();
    let kb = obf.len() / 1024;
    println!(
        "f1_size_perf_benchmark: 200-constant polished build = {} bytes ({} KiB)",
        obf.len(),
        kb
    );
    assert!(
        obf.len() > 0 && kb < 4096,
        "constant-heavy polished build size within bound (got {kb} KiB)"
    );
}

const T0_OLD_SIGNATURE: &str =
    "ps'_Dka&hGE`>2^.N:Z<rC6[Y@q+tj=7MLX?J3bBFoQUm!w(V8K*cue%v59IOg$lH4Wn)Tdx;#/,P0i-fAS1R";
const T0_CANONICAL: &str =
    "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghijklmnopqrstuvwx";

fn t0_heavy(src: &str, seed: u64) -> String {
    pipeline::virtualize_full(
        src,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Medium,
    )
    .unwrap()
}

#[test]
fn t0_payload_roundtrip() {
    let Some(luau) = find_luau() else { return };
    let src = "local s = {} for i = 1, 40 do s[i] = \"konst_\" .. i end\nlocal n = 0 for i = 1, 40 do n = n + #s[i] end\nprint(n, s[1], s[40], -3.5 + 1)\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("t0_rt_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    let pol = pipeline::virtualize_with(src, 0x7_0001, true, true, true, true, true, false, false)
        .unwrap();
    let hv = t0_heavy(src, 0x7_0001);
    let vp = run_luau(&luau, &{
        let p = std::env::temp_dir().join("t0_rt_pol.luau");
        std::fs::write(&p, &pol).unwrap();
        p
    });
    let vh = run_luau(&luau, &{
        let p = std::env::temp_dir().join("t0_rt_hv.luau");
        std::fs::write(&p, &hv).unwrap();
        p
    });
    assert!(!raw.stdout.trim().is_empty(), "raw sanity");
    assert_eq!(
        raw.stdout, vp.stdout,
        "polished payload must round-trip through the per-build alphabet"
    );
    assert_eq!(
        raw.stdout, vh.stdout,
        "heavy payload must round-trip through the per-build alphabet"
    );
}

#[test]
fn t0_loader_reconstructs_alphabet() {
    let Some(luau) = find_luau() else { return };
    let src = "local msg = \"reconstruct-alphabet-and-decode\"\nlocal acc = \"\" for _ = 1, 3 do acc = acc .. msg .. \"|\" end\nprint(acc, #acc)\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("t0_lr_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    let hv = t0_heavy(src, 0x7_0002);
    assert!(
        hv.contains("while true do"),
        "heavy reconstruction should use a state-machine loop"
    );
    let vh = run_luau(&luau, &{
        let p = std::env::temp_dir().join("t0_lr_hv.luau");
        std::fs::write(&p, &hv).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, vh.stdout,
        "heavy state-machine reconstruction must decode the payload correctly"
    );
}

#[test]
fn t0_beautified_output_no_clean_alphabet() {
    let src = "local a = \"alpha\" local b = 7 print(a, b)\n";
    for seed in [305419896u64, 0x7_0003] {
        let pol = pipeline::virtualize_with(src, seed, true, true, true, true, true, false, false)
            .unwrap();
        let hv = t0_heavy(src, seed);
        for (label, out) in [("polished", &pol), ("heavy", &hv)] {
            assert!(
                !out.contains(T0_OLD_SIGNATURE),
                "{label} (seed={seed}) must not contain the old alphabet signature"
            );
            assert!(
                !out.contains(T0_CANONICAL),
                "{label} (seed={seed}) must not contain the canonical alphabet"
            );
        }
    }
}

#[test]
fn t0_static_audit_no_old_alphabet() {
    let src = "local t = {} t[\"key\"] = \"value\" print(t.key, 1234)\n";
    let pol = pipeline::virtualize_with(src, 305419896, true, true, true, true, true, false, false)
        .unwrap();
    let hv = t0_heavy(src, 305419896);
    for out in [&pol, &hv] {
        assert!(
            !out.contains(T0_CANONICAL),
            "canonical alphabet must be absent"
        );
        assert!(
            !out.contains(T0_OLD_SIGNATURE),
            "old per-build signature must be absent"
        );
        assert!(!out.contains("BASIL_"), "no BASIL_ markers");
        assert_eq!(out.matches("loadstring").count(), 0, "no loadstring");
    }
}

#[test]
fn t0_executor_samples_still_run() {
    let Some(luau) = find_luau() else { return };
    let src = "local names = { \"run\", \"copy\", \"hash\", \"encstr\" }\n\
local nums = { 1337, -7, 3.14159, 0 }\n\
local out = {}\n\
for i = 1, #names do out[i] = names[i] .. \"=\" .. tostring(nums[i]) end\n\
print(table.concat(out, \", \"), #names)\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("t0_ex_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    for (tag, out) in [
        (
            "pol",
            pipeline::virtualize_with(src, 0x7_0004, true, true, true, true, true, false, false)
                .unwrap(),
        ),
        ("hv", t0_heavy(src, 0x7_0004)),
    ] {
        let v = run_luau(&luau, &{
            let p = std::env::temp_dir().join(format!("t0_ex_{tag}.luau"));
            std::fs::write(&p, &out).unwrap();
            p
        });
        assert_eq!(
            raw.stdout, v.stdout,
            "{tag} build must run correctly under the T0 packer"
        );
    }
}

fn c31_icat_d_line(out: &str) -> String {
    out.lines()
        .find(|l| l.starts_with("local ICAT_D="))
        .unwrap_or("")
        .to_string()
}

fn strip_payload_carriers(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find("[==[") {
        out.push_str(&rest[..p]);
        rest = &rest[p + 4..];
        if let Some(e) = rest.find("]==]") {
            rest = &rest[e + 4..];
        } else {
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

#[test]
fn c31_no_plain_icat_catalog() {
    let full = pipeline::virtualize_with(
        C3_SAMPLE, 0xC31A, true, true, true, true, false, false, false,
    )
    .unwrap();
    let obf = strip_payload_carriers(&full);
    for name in [
        "GetService",
        "GetFullName",
        "GetAttribute",
        "SetAttribute",
        "VectorToWorldSpace",
        "Instance",
        "Vector3",
        "CFrame",
        "typeof",
        "IsA",
    ] {
        assert!(
            !obf.contains(name),
            "intrinsic name {name:?} must not appear plaintext in code"
        );
    }
    let d = c31_icat_d_line(&full);
    assert!(!d.is_empty(), "ICAT_D present");
    assert!(
        !d.contains("[0]=") && !d.contains("[1]="),
        "no stable id-keyed catalog table"
    );
}

#[test]
fn c31_catalog_order_seeded() {
    let a1 = pipeline::virtualize_with(
        C3_SAMPLE, 0xAAA1, true, true, true, true, false, false, false,
    )
    .unwrap();
    let a2 = pipeline::virtualize_with(
        C3_SAMPLE, 0xAAA1, true, true, true, true, false, false, false,
    )
    .unwrap();
    let b = pipeline::virtualize_with(
        C3_SAMPLE, 0xBBB2, true, true, true, true, false, false, false,
    )
    .unwrap();
    assert_eq!(
        c31_icat_d_line(&a1),
        c31_icat_d_line(&a2),
        "same seed must give the same ICAT layout"
    );
    assert_ne!(
        c31_icat_d_line(&a1),
        c31_icat_d_line(&b),
        "different seeds must change the ICAT data/order"
    );
    let pa = a1
        .lines()
        .find(|l| l.starts_with("local ICAT_P="))
        .unwrap_or("")
        .to_string();
    let pb = b
        .lines()
        .find(|l| l.starts_with("local ICAT_P="))
        .unwrap_or("")
        .to_string();
    assert_ne!(
        pa, pb,
        "the per-build id→slot remap (ICAT_P) must differ across seeds"
    );
}

#[test]
fn c31_no_adjacent_api_fragments() {
    let obf = pipeline::virtualize_with(
        C3_SAMPLE, 0xC31F, true, true, true, true, false, false, false,
    )
    .unwrap();
    for frag in [
        "\"Get\"",
        "\"Attribute\"",
        "\"Service\"",
        "\"Full\" .. \"Name\"",
        "\"Get\"..\"",
        "Get\" .. \"",
        "Vector\" .. \"3",
    ] {
        assert!(
            !obf.contains(frag),
            "adjacent API fragment {frag:?} must not appear"
        );
    }
}

#[test]
fn c31_no_universal_concat_signature() {
    let obf = pipeline::virtualize_with(
        C3_SAMPLE, 0xC312, true, true, true, true, false, false, false,
    )
    .unwrap();
    assert!(
        obf.contains("m==0") && obf.contains("m==1"),
        "resolver must branch on a per-entry method tag"
    );
    assert!(
        !obf.contains("for i=1,#e do t[i]=char(bxor(e[i],band("),
        "old universal xor+concat decode must be gone"
    );
}

#[test]
fn c31_resolver_roundtrip() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_rr_raw.luau");
        std::fs::write(&p, C3_SAMPLE).unwrap();
        p
    });
    for seed in [0xC31u64, 0x5151, 305419896] {
        let obf =
            pipeline::virtualize_with(C3_SAMPLE, seed, true, true, true, true, true, false, false)
                .unwrap();
        let v = run_luau(&luau, &{
            let p = std::env::temp_dir().join("c31_rr_virt.luau");
            std::fs::write(&p, &obf).unwrap();
            p
        });
        assert_eq!(
            raw.stdout, v.stdout,
            "all ICAT-resolved APIs must resolve correctly (seed={seed:#x})"
        );
    }
}

#[test]
fn c31_roblox_api_roundtrip() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_rapi_raw.luau");
        std::fs::write(&p, C3_SAMPLE).unwrap();
        p
    });
    let obf = pipeline::virtualize_with(
        C3_SAMPLE, 0xC31B, true, true, true, true, true, false, false,
    )
    .unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_rapi_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    for marker in ["svc:Players", "inst:Part", "v3:5", "cf:1", "ang:2", ".Full"] {
        assert!(
            v.stdout.contains(marker),
            "Roblox intrinsic result {marker:?} must survive (got {:?})",
            v.stdout
        );
    }
    assert_eq!(
        raw.stdout, v.stdout,
        "Vector3/CFrame/Instance/typeof/IsA/GetFullName/Dot/Cross/Inverse/VTWS must round-trip"
    );
}

#[test]
fn c31_executor_api_roundtrip() {
    let Some(luau) = find_luau() else { return };
    let src = "getgenv = function() return { flag = true } end\n\
request = function(o) return { Body = \"ok:\" .. o.Url } end\n\
identifyexecutor = function() return \"TestExec\", \"1.0\" end\n\
local g = getgenv()\nlocal r = request({ Url = \"X\" })\nlocal n, ver = identifyexecutor()\n\
print(g.flag, r.Body, n, ver)\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_ex_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    let obf =
        pipeline::virtualize_with(src, 0xC31E, true, true, true, true, true, false, false).unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_ex_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "executor-style global access must still work under C3.1"
    );
}

#[test]
fn c31_namecall_preserved() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_nc_raw.luau");
        std::fs::write(&p, C3_SAMPLE).unwrap();
        p
    });
    assert!(raw.stdout.contains("calls=1"), "raw receiver-once sanity");
    let obf = pipeline::virtualize_with(
        C3_SAMPLE, 0xC31C, true, true, true, true, true, false, false,
    )
    .unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_nc_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "namecall method handling must remain correct (incl. receiver-once)"
    );
    assert!(
        v.stdout.contains("calls=1"),
        "receiver evaluated exactly once under C3.1"
    );
}

#[test]
fn c31_heavy_decoys_present() {
    let Some(luau) = find_luau() else { return };
    let normal = pipeline::virtualize_with(
        C3_SAMPLE, 0xC31D, true, true, true, true, false, false, false,
    )
    .unwrap();
    let heavy = pipeline::virtualize_full(
        C3_SAMPLE,
        0xC31D,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Medium,
    )
    .unwrap();
    assert!(
        c31_icat_d_line(&heavy).len() > c31_icat_d_line(&normal).len(),
        "heavy ICAT_D must carry more entries (decoys) than normal"
    );
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_hd_raw.luau");
        std::fs::write(&p, C3_SAMPLE).unwrap();
        p
    });
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_hd_virt.luau");
        std::fs::write(&p, &heavy).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "decoy catalog entries must not affect runtime behavior"
    );
}

#[test]
fn c31_all_three_decode_methods_exercised() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_m3_raw.luau");
        std::fs::write(&p, C3_SAMPLE).unwrap();
        p
    });
    let mut seen = [false; 3];
    for seed in 0u64..24 {
        let un = pipeline::virtualize_with(
            C3_SAMPLE, seed, true, false, false, false, false, false, false,
        )
        .unwrap();
        let d = c31_icat_d_line(&un);
        for (m, pat) in ["{0,", "{1,", "{2,"].iter().enumerate() {
            if d.contains(pat) {
                seen[m] = true;
                let obf = pipeline::virtualize_with(
                    C3_SAMPLE, seed, true, true, true, true, true, false, false,
                )
                .unwrap();
                let v = run_luau(&luau, &{
                    let p = std::env::temp_dir().join("c31_m3_virt.luau");
                    std::fs::write(&p, &obf).unwrap();
                    p
                });
                assert_eq!(
                    raw.stdout, v.stdout,
                    "build using method m{m} (seed {seed}) must round-trip"
                );
            }
        }
    }
    assert!(
        seen[0] && seen[1] && seen[2],
        "all three decode methods must be exercised across seeds: {seen:?}"
    );
}

#[test]
fn c31_normal_size_reasonable() {
    let obf = pipeline::virtualize_with(
        C3_SAMPLE, 0xC315, true, true, true, true, false, false, false,
    )
    .unwrap();
    let d = c31_icat_d_line(&obf);
    assert!(
        d.len() < 4096,
        "normal ICAT_D must stay modest (got {} bytes)",
        d.len()
    );
}

#[test]
fn c31_s1_f1_t0_preserved() {
    let Some(luau) = find_luau() else { return };
    let src = "typeof = function(x) return \"ty:\" .. type(x) end\n\
local tag = \"combined-marker\"\nlocal lim = 4242\nprint(tag, lim, typeof(5))\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_comb_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    let obf = pipeline::virtualize_with(
        src,
        0x305419896u64 as u64 & 0xFFFFFFFF,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c31_comb_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "S1+F1+C3.1+T0 combined build must run correctly"
    );
    assert!(
        !obf.contains("combined-marker"),
        "constant plaintext must not leak (S1/F1)"
    );
    assert!(
        !obf.contains("typeof"),
        "intrinsic name must not leak (C3.1)"
    );
    assert!(
        !obf.contains(T0_CANONICAL),
        "canonical packer alphabet must not appear (T0)"
    );
}

const C22_SAMPLE: &str =
    "local labels = { \"basilisk test panel ready\", \"Invalid Service:\", \"took too long\" }\n\
local url = \"https://basil-key-worker.heroin-9c6.workers.dev/basil-key\"\n\
local rich = \"<b>ok</b> & done\\\"q\\\"\"\n\
local empty = \"\"\n\
local dup1 = \"shared duplicate string value\"\n\
local dup2 = \"shared duplicate string value\"\n\
local t = {}\n\
t[\"configuration key name\"] = \"configuration value here\"\n\
local acc = \"\"\n\
for i = 1, #labels do acc = acc .. labels[i] .. \"|\" end\n\
print(acc, #url, rich, #empty, dup1 == dup2, t[\"configuration key name\"], url)\n";

#[test]
fn c22_string_roundtrip() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c22_rt_raw.luau");
        std::fs::write(&p, C22_SAMPLE).unwrap();
        p
    });
    assert!(
        raw.stdout.contains("basilisk test panel ready"),
        "raw sanity"
    );
    for (tag, heavy) in [("pol", false), ("hv", true)] {
        let obf = if heavy {
            pipeline::virtualize_full(
                C22_SAMPLE,
                0x2201,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Medium,
            )
            .unwrap()
        } else {
            pipeline::virtualize_with(
                C22_SAMPLE, 0x2201, true, true, true, true, true, false, false,
            )
            .unwrap()
        };
        let v = run_luau(&luau, &{
            let p = std::env::temp_dir().join(format!("c22_rt_{tag}.luau"));
            std::fs::write(&p, &obf).unwrap();
            p
        });
        assert_eq!(
            raw.stdout, v.stdout,
            "{tag}: long/short/escape/empty/dup/table-key strings must round-trip"
        );
    }
}

#[test]
fn c22_encstr_roundtrip() {
    let Some(luau) = find_luau() else { return };
    let src = s1_src("local s = \"a reasonably long protected constant string\"\nprint(s, #s)");
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c22_en_raw.luau");
        std::fs::write(&p, &src).unwrap();
        p
    });
    let obf = pipeline::virtualize_with(&src, 0x2202, true, true, true, true, true, false, false)
        .unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c22_en_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert!(
        raw.stdout.contains("protected constant string"),
        "raw sanity"
    );
    assert_eq!(
        raw.stdout, v.stdout,
        "an ordinary string constant must still round-trip under C2.2"
    );
}

#[test]
fn c22_c4_no_cache_preserved() {
    let vm = pipeline::virtualize_with(
        "local s = \"abcdefghij\"\nreturn s, 12345\n",
        0x2203,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
    )
    .unwrap();
    assert!(
        vm.contains("return sub(plain, 10)"),
        "string path must stay decrypt-use-discard"
    );
    assert!(
        vm.contains("kc[i] = (unpacks(sD, plain, 10))"),
        "number path must keep the cached fast path"
    );
}

#[test]
fn c22_no_plaintext_regression() {
    for (tag, heavy) in [("pol", false), ("hv", true)] {
        let obf = if heavy {
            pipeline::virtualize_full(
                C22_SAMPLE,
                0x2204,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Medium,
            )
            .unwrap()
        } else {
            pipeline::virtualize_with(
                C22_SAMPLE, 0x2204, true, true, true, true, true, false, false,
            )
            .unwrap()
        };
        for s in [
            "basilisk test panel ready",
            "configuration value here",
            "configuration key name",
            "shared duplicate string value",
            "basil-key-worker.heroin",
            "workers.dev",
        ] {
            assert!(
                !obf.contains(s),
                "{tag}: protected string {s:?} must not appear plaintext"
            );
        }
        assert!(!obf.contains("BASIL_"), "{tag}: no BASIL_ markers");
    }
}

#[test]
fn c22_s1_f1_t0_c31_preserved() {
    let Some(luau) = find_luau() else { return };
    let src = "typeof = function(x) return \"ty:\" .. type(x) end\n\
local secret = \"combined-c22-secret-marker\"\n\
local url = \"https://endpoint.example.test/v1/resource/path\"\n\
print(secret, #url, typeof(5), url:sub(1, 8))\n";
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c22_comb_raw.luau");
        std::fs::write(&p, src).unwrap();
        p
    });
    let obf =
        pipeline::virtualize_with(src, 0xC22F, true, true, true, true, true, false, false).unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("c22_comb_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "combined S1+F1+T0+C3.1+C2.2 build must run correctly"
    );
    assert!(
        !obf.contains("combined-c22-secret-marker"),
        "ENCSTR plaintext must not leak"
    );
    assert!(
        !obf.contains("endpoint.example.test"),
        "URL must not appear plaintext"
    );
    assert!(
        !obf.contains("typeof"),
        "intrinsic name must not leak (C3.1)"
    );
    assert!(
        !obf.contains(T0_CANONICAL),
        "canonical packer alphabet must not appear (T0)"
    );
}

const AT2_SAMPLE_SRC: &str = "local msg = \"a small sample script\"\nlocal n = 0\nfor i = 1, 5 do n = n + i end\nprint(msg, n)\n";

#[test]
fn at2_no_infinite_task_wait_loop() {
    for heavy in [false, true] {
        let obf = if heavy {
            pipeline::virtualize_full(
                AT2_SAMPLE_SRC,
                0x7303,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Medium,
            )
            .unwrap()
        } else {
            pipeline::virtualize_with(
                AT2_SAMPLE_SRC,
                0x7303,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
            )
            .unwrap()
        };
        assert_eq!(
            obf.matches("task.wait").count(),
            0,
            "no task.wait anti-tamper spin (heavy={heavy})"
        );
        assert!(
            !obf.contains("while true do end"),
            "no empty infinite-loop anti-tamper response (heavy={heavy})"
        );
    }
}

#[test]
fn at2_wrong_trap_value_fails_closed() {
    let vm = pipeline::virtualize_with(
        AT2_SAMPLE_SRC,
        0x7304,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
    )
    .unwrap();
    assert!(
        vm.contains("dead = true"),
        "VM must carry the fail-closed poison path"
    );
    assert_eq!(
        vm.matches("task.wait").count(),
        0,
        "fail-closed path must not be a spin loop"
    );
}

fn prof_build(src: &str, seed: u64, profile: pipeline::TargetProfile, _wm: bool) -> String {
    pipeline::virtualize_full_prof(
        src,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        profile,
        false,
        false,
    )
    .unwrap()
}

fn lc1_build(src: &str, seed: u64, profile: pipeline::TargetProfile) -> String {
    pipeline::virtualize_full_prof(
        src,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        profile,
        true,
        false,
    )
    .unwrap()
}

const AT2_SRC: &str = "local s = \"at2 sample constant\" local n = 4242 print(\"OUT\", s, n)\n";

#[test]
fn at2_target_profile_cli_skips_roblox_traps() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("at2_cli_raw.luau");
        std::fs::write(&p, AT2_SRC).unwrap();
        p
    });
    let obf = prof_build(AT2_SRC, 0x4201, pipeline::TargetProfile::CliTest, false);
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("at2_cli_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "cli-test profile must run on the CLI unchanged"
    );
}

#[test]
fn at2_target_profile_executor_emits_datatype_traps() {
    let Some(luau) = find_luau() else { return };
    let cli = prof_build(AT2_SRC, 0x4202, pipeline::TargetProfile::CliTest, false);
    let exec = prof_build(AT2_SRC, 0x4202, pipeline::TargetProfile::Executor, false);
    assert_ne!(cli, exec, "executor profile must emit extra trap material");
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("at2_exec.luau");
        std::fs::write(&p, &exec).unwrap();
        p
    });
    assert_eq!(
        v.stdout.matches("OUT").count(),
        0,
        "executor build must fail closed on the non-conforming CLI env"
    );
}

#[test]
fn at2_target_profile_deterministic_same_seed() {
    assert_eq!(
        prof_build(AT2_SRC, 0x4203, pipeline::TargetProfile::Executor, true),
        prof_build(AT2_SRC, 0x4203, pipeline::TargetProfile::Executor, true),
        "same seed + profile + settings must be deterministic"
    );
}

#[test]
fn at2_target_profile_changes_trap_set() {
    use pipeline::TargetProfile as P;
    let mut set = std::collections::HashSet::new();
    for p in [
        P::CliTest,
        P::Executor,
        P::Studio,
        P::RobloxClient,
        P::RobloxServer,
    ] {
        set.insert(prof_build(AT2_SRC, 0x4204, p, false));
    }
    assert_eq!(
        set.len(),
        5,
        "each profile must produce a distinct trap set / build"
    );
}

#[test]
fn at2_no_infinite_task_wait_loop_profiles() {
    use pipeline::TargetProfile as P;
    for p in [P::CliTest, P::Executor, P::Studio, P::RobloxServer] {
        let obf = prof_build(AT2_SRC, 0x4205, p, true);
        assert_eq!(
            obf.matches("task.wait").count(),
            0,
            "no task.wait spin ({p:?})"
        );
        assert!(
            !obf.contains("while true do end"),
            "no empty infinite loop ({p:?})"
        );
    }
}

fn prof_build_unmin(src: &str, seed: u64, profile: pipeline::TargetProfile) -> String {
    pipeline::virtualize_full_prof(
        src,
        seed,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        profile,
        false,
        false,
    )
    .unwrap()
}

#[test]
fn at2_executor_does_not_use_global_players() {
    let vm = prof_build_unmin(AT2_SRC, 0x4301, pipeline::TargetProfile::Executor);
    assert!(
        vm.contains("local _pl ="),
        "Players must be resolved via a GetService local (_pl), not the global"
    );
}

#[test]
fn at2_executor_profile_players_service_resolution() {
    assert!(
        !prof_build_unmin(AT2_SRC, 0x4302, pipeline::TargetProfile::CliTest)
            .contains("local _pl ="),
        "cli-test resolves no Players"
    );
    assert!(
        prof_build_unmin(AT2_SRC, 0x4302, pipeline::TargetProfile::Executor)
            .contains("local _pl ="),
        "executor resolves Players via GetService"
    );
}

const SIG1_SRC: &str =
    "local s = \"sig1 sample text\" local n = 918273 local t = { 7, 8, 9 } local a = 0\nfor i = 1, 15 do a = a + i * n end\nprint(\"OUT\", a, s, t[2])\n";

const SIG1_MAGIC: &[&str] = &[
    "2654435769",
    "9e3779b9",
    "811c9dc5",
    "6a09e667",
    "bb67ae85",
    "7f4a7c15",
    "bf58476d",
    "1ce4e5b9",
    "94d049bb",
    "133111eb",
    "ec461848",
    "b780f2d9",
    "ce96985a",
    "dbce659b",
    "61707865",
    "3320646e",
    "79622d32",
    "6b206574",
    "636f6e73",
    "6e6f726d",
    "74763031",
];

fn sig1_cli(seed: u64) -> String {
    pipeline::virtualize_full(
        SIG1_SRC,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap()
    .to_lowercase()
}

fn stable_across_seeds(f: &dyn Fn(u64) -> String, needle: &str) -> bool {
    (1u64..=5).all(|s| f(s).contains(needle))
}

fn universal_large_consts(f: &dyn Fn(u64) -> String) -> Vec<String> {
    fn toks(s: &str) -> std::collections::BTreeSet<String> {
        let b = s.as_bytes();
        let mut out = std::collections::BTreeSet::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'0' && i + 1 < b.len() && b[i + 1] == b'x' {
                let mut j = i + 2;
                while j < b.len() && b[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j - (i + 2) >= 7 {
                    out.insert(s[i..j].to_string());
                }
                i = j.max(i + 1);
            } else if b[i].is_ascii_digit() {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j - i >= 7 {
                    out.insert(s[i..j].to_string());
                }
                i = j;
            } else {
                i += 1;
            }
        }
        out
    }
    let builds: Vec<std::collections::BTreeSet<String>> = (1u64..=5).map(|s| toks(&f(s))).collect();
    let whitelist = ["16777216", "0x100000000"];
    builds[0]
        .iter()
        .filter(|t| !whitelist.contains(&t.as_str()) && builds.iter().all(|set| set.contains(*t)))
        .cloned()
        .collect()
}

#[test]
fn sig1_no_plain_golden_ratio_decimal() {
    assert!(
        !stable_across_seeds(&sig1_cli, "2654435769"),
        "golden-ratio decimal must not be a stable anchor"
    );
}

#[test]
fn sig1_no_plain_golden_ratio_hex() {
    assert!(
        !stable_across_seeds(&sig1_cli, "9e3779b9"),
        "golden-ratio hex must not be a stable anchor"
    );
}

#[test]
fn sig1_magic_constants_are_derived() {
    let leaked: Vec<&str> = SIG1_MAGIC
        .iter()
        .copied()
        .filter(|m| stable_across_seeds(&sig1_cli, m))
        .collect();
    assert!(
        leaked.is_empty(),
        "magic constants still ship as stable anchors: {leaked:?}"
    );
}

#[test]
fn sig1_stable_intersection_audit_runs() {
    let universal = universal_large_consts(&sig1_cli);
    for m in SIG1_MAGIC {
        assert!(
            !universal.iter().any(|u| u.to_lowercase().contains(m)),
            "magic constant {m} is a universal anchor"
        );
    }
}

#[test]
fn sig1_no_new_static_alphabet_signature() {
    let universal = universal_large_consts(&sig1_cli);
    assert!(
        universal.is_empty(),
        "a new constant became a universal static signature: {universal:?}"
    );
}

#[test]
fn sig1_seed_changes_helper_constants() {
    assert_ne!(
        sig1_cli(0x5151_0001),
        sig1_cli(0x5151_0002),
        "helper constants must vary per build"
    );
}

#[test]
fn sig1_same_seed_deterministic() {
    assert_eq!(
        sig1_cli(0x515A_BCDE),
        sig1_cli(0x515A_BCDE),
        "same seed must be byte-identical"
    );
}

#[test]
fn sig1_no_behavior_change_cli_test() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig1_raw.luau");
        std::fs::write(&p, SIG1_SRC).unwrap();
        p
    });
    let obf = pipeline::virtualize_full(
        SIG1_SRC,
        0x51C1,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig1_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "cli-test SIG1 build must run identically (raw == virt)"
    );
}

#[test]
fn sig1_no_behavior_change_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let cli = prof_build(SIG1_SRC, 0x51E0, pipeline::TargetProfile::CliTest, false);
    let exec = prof_build(SIG1_SRC, 0x51E0, pipeline::TargetProfile::Executor, false);
    assert_ne!(
        cli, exec,
        "executor profile must still emit its extra trap material"
    );
    assert!(
        !exec.to_lowercase().contains("9e3779b9"),
        "executor build must not ship the golden ratio"
    );
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig1_exec.luau");
        std::fs::write(&p, &exec).unwrap();
        p
    });
    assert_eq!(
        v.stdout.matches("OUT").count(),
        0,
        "executor build must fail closed on the non-conforming CLI"
    );
}

#[test]
fn sig1_preserves_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return \"OK:\" .. tostring(u) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(2024))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "sig1_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf =
        pipeline::virtualize_with(&src, 305419896, true, true, true, true, true, false, false)
            .unwrap();
    let virt = run_injected(&luau, "sig1_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert_eq!(raw.stdout, virt.stdout, "ENCFUNC raw != virt after SIG1");
    let lower = obf.to_lowercase();
    assert!(
        lower.contains("3c6ef372"),
        "standard SHA-256 IV is whitelisted and must remain in ENCFUNC builds"
    );
    assert!(
        !lower.contains("9e3779b9"),
        "golden ratio must still be derived even in ENCFUNC builds"
    );
}

fn sig11_exec(seed: u64) -> String {
    prof_build(SIG1_SRC, seed, pipeline::TargetProfile::Executor, false).to_lowercase()
}

fn magic_exprs(s: &str) -> std::collections::BTreeSet<String> {
    let b = s.as_bytes();
    let is_c = |c: u8| c.is_ascii_digit() || c == b'+' || c == b'-';
    let mut out = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < b.len() {
        if is_c(b[i]) {
            let start = i;
            while i < b.len() && is_c(b[i]) {
                i += 1;
            }
            let tok = &s[start..i];
            if tok.len() >= 12
                && (tok.contains('+') || tok.contains('-'))
                && tok.bytes().filter(u8::is_ascii_digit).count() >= 10
            {
                out.insert(tok.to_string());
            }
        } else {
            i += 1;
        }
    }
    let read_hex0x = |b: &[u8], p: usize| -> Option<usize> {
        if p + 2 <= b.len() && b[p] == b'0' && (b[p + 1] == b'x' || b[p + 1] == b'X') {
            let s0 = p + 2;
            let mut q = s0;
            while q < b.len() && b[q].is_ascii_hexdigit() {
                q += 1;
            }
            if q - s0 >= 6 {
                return Some(q);
            }
        }
        None
    };
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'(' {
            if let Some(j) = read_hex0x(b, i + 1) {
                let mut k = j;
                if k < b.len() && b[k] == b',' {
                    k += 1;
                    while k < b.len() && b[k] == b' ' {
                        k += 1;
                    }
                    if let Some(m) = read_hex0x(b, k) {
                        if m < b.len() && b[m] == b')' {
                            out.insert(s[i..=m].to_string());
                            i = m + 1;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    out
}

#[test]
fn sig11_no_string_2987342059_minus_332906290() {
    for s in 1u64..=5 {
        assert!(
            !sig1_cli(s).contains("2987342059-332906290"),
            "seed {s} cli leaks the old derived anchor"
        );
        assert!(
            !sig11_exec(s).contains("2987342059-332906290"),
            "seed {s} exec leaks the old derived anchor"
        );
    }
}

#[test]
fn sig11_no_raw_golden_ratio_decimal() {
    assert!(!stable_across_seeds(&sig1_cli, "2654435769"));
    assert!(!stable_across_seeds(&sig11_exec, "2654435769"));
}

#[test]
fn sig11_no_raw_golden_ratio_hex() {
    assert!(!stable_across_seeds(&sig1_cli, "9e3779b9"));
    assert!(!stable_across_seeds(&sig11_exec, "9e3779b9"));
}

#[test]
fn sig11_no_stable_derived_expression_intersection() {
    let sets: Vec<_> = (1u64..=5).map(|s| magic_exprs(&sig1_cli(s))).collect();
    let universal: Vec<_> = sets[0]
        .iter()
        .filter(|e| sets.iter().all(|set| set.contains(*e)))
        .collect();
    assert!(
        universal.is_empty(),
        "derived expressions became universal anchors: {universal:?}"
    );
}

#[test]
fn sig11_polished_executor_do_not_share_magic_derivation_pairs() {
    for s in 1u64..=3 {
        let a = magic_exprs(&sig1_cli(s));
        let b = magic_exprs(&sig11_exec(s));
        let shared: Vec<_> = a.intersection(&b).collect();
        assert!(
            shared.is_empty(),
            "seed {s}: cli & executor share derived magic expressions: {shared:?}"
        );
    }
}

#[test]
fn sig11_no_repeated_golden_ratio_expression_across_profiles() {
    let shared: Vec<_> = magic_exprs(&sig1_cli(2))
        .intersection(&magic_exprs(&sig11_exec(2)))
        .cloned()
        .collect();
    assert!(
        shared.is_empty(),
        "cli/executor (seed 2) must not share any derived magic expression: {shared:?}"
    );
}

#[test]
fn sig11_expression_intersection_audit_runs() {
    let n = magic_exprs(&sig1_cli(1)).len();
    assert!(
        n >= 5,
        "expected several derived expressions to audit, found {n}"
    );
}

#[test]
fn sig11_no_new_global_large_expression_anchor() {
    let mut sets: Vec<std::collections::BTreeSet<String>> = Vec::new();
    for s in 1u64..=3 {
        sets.push(magic_exprs(&sig1_cli(s)));
        sets.push(magic_exprs(&sig11_exec(s)));
    }
    let universal: Vec<_> = sets[0]
        .iter()
        .filter(|e| sets.iter().all(|set| set.contains(*e)))
        .collect();
    assert!(
        universal.is_empty(),
        "a derived expression is a global anchor: {universal:?}"
    );
}

#[test]
fn sig11_same_seed_same_config_deterministic() {
    assert_eq!(
        sig1_cli(0x5151_ABCD),
        sig1_cli(0x5151_ABCD),
        "same seed + config must be byte-identical"
    );
    assert_eq!(
        sig11_exec(0x5151_ABCD),
        sig11_exec(0x5151_ABCD),
        "same seed + config (executor) must be byte-identical"
    );
}

#[test]
fn sig11_different_profile_changes_magic_derivation_expressions() {
    assert_ne!(
        magic_exprs(&sig1_cli(9)),
        magic_exprs(&sig11_exec(9)),
        "profile change must vary the derived expressions"
    );
}

#[test]
fn sig11_values_remain_bit_exact() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig11_raw.luau");
        std::fs::write(&p, SIG1_SRC).unwrap();
        p
    });
    let obf = pipeline::virtualize_full(
        SIG1_SRC,
        0x5B17,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig11_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(
        raw.stdout, v.stdout,
        "derived constants must round-trip (raw == virt)"
    );
}

#[test]
fn sig11_no_behavior_change_cli_test() {
    let Some(luau) = find_luau() else { return };
    let raw = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig11_nc_raw.luau");
        std::fs::write(&p, SIG1_SRC).unwrap();
        p
    });
    let obf = pipeline::virtualize_full(
        SIG1_SRC,
        0x5B18,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig11_nc_virt.luau");
        std::fs::write(&p, &obf).unwrap();
        p
    });
    assert_eq!(raw.stdout, v.stdout, "cli-test behavior unchanged");
}

#[test]
fn sig11_no_behavior_change_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let cli = prof_build(SIG1_SRC, 0x5B19, pipeline::TargetProfile::CliTest, false);
    let exec = prof_build(SIG1_SRC, 0x5B19, pipeline::TargetProfile::Executor, false);
    assert_ne!(cli, exec, "executor profile still differs from cli-test");
    let v = run_luau(&luau, &{
        let p = std::env::temp_dir().join("sig11_exec.luau");
        std::fs::write(&p, &exec).unwrap();
        p
    });
    assert_eq!(
        v.stdout.matches("OUT").count(),
        0,
        "executor build fails closed on the non-conforming CLI"
    );
}

#[test]
fn sig11_preserves_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return \"OK:\" .. tostring(u) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(3))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "sig11_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf =
        pipeline::virtualize_with(&src, 305419896, true, true, true, true, true, false, false)
            .unwrap();
    let virt = run_injected(&luau, "sig11_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert_eq!(raw.stdout, virt.stdout, "ENCFUNC external key still works");
    assert!(
        !obf.to_lowercase().contains("9e3779b9"),
        "golden ratio still derived in ENCFUNC builds"
    );
}

const LC1_SRC: &str = "print(\"CANARYPROG\", 6 * 7)\n";
const LC1_ART_ROW: &str = ",@@&@&&&@@@&&&";

fn max_str_lit_len(s: &str) -> usize {
    let (mut best, mut cur, mut in_str, mut prev_bs) = (0usize, 0usize, false, false);
    for c in s.chars() {
        if in_str {
            if c == '"' && !prev_bs {
                best = best.max(cur);
                cur = 0;
                in_str = false;
            } else {
                cur += 1;
                prev_bs = c == '\\' && !prev_bs;
            }
        } else if c == '"' {
            in_str = true;
            cur = 0;
            prev_bs = false;
        }
    }
    best
}

fn lc1_run_hooked(build: &str, block: bool) -> Option<String> {
    let luau = find_luau()?;
    let mut lvl = 4usize;
    while build.contains(&format!("]{}]", "=".repeat(lvl))) {
        lvl += 1;
    }
    let (op, cl) = (
        format!("[{}[", "=".repeat(lvl)),
        format!("]{}]", "=".repeat(lvl)),
    );
    let act = if block {
        "if caps>=2 then return nil end return real(s,...)"
    } else {
        "return real(s,...)"
    };
    let harness = format!(
        "local caps=0 local canary local real=loadstring\ngetfenv().loadstring=function(s,...) caps=caps+1 local t=tostring(s) if t:find(\"zxq7f3a90b5e4d28\",1,true) then canary=t end {act} end\nlocal f=loadstring({op}\n{build}\n{cl})\nlocal ok=false if f then ok=pcall(f) end\nlocal code=\"\" if canary then code=canary:match(\"%]%](.*)$\") or \"\" end\nlocal hw=code:find(\"return%s*%(function\")~=nil\nlocal ns=code:find(\"return%s*%(%d+%+%d+%+%d+%)\")~=nil\nlocal cancel=code:find(\"%)%s*%-%s*[%a_]\")~=nil\nlocal hastab=(code:find(\"{{\")~=nil) and (code:find(\"%[\")~=nil)\nlocal shape=\"S\" if code:find(\"setmetatable\") then shape=\"A\" elseif code:find(\"pcall\") then shape=\"P\" elseif code:find(\"for \") then shape=\"L\" elseif code:find(\"return function\") then shape=\"C\" elseif code:find(\"%[%d+%]=function\") then shape=\"N\" end\nlocal ch=0 local cn=0 if canary then cn=#canary for i=1,#canary do ch=(ch*31+string.byte(canary,i))%2147483647 end end\nprint(\"LC1_NCAP=\"..caps)\nprint(\"LC1_ARTCAP=\"..tostring(canary~=nil))\nprint(\"LC1_HASWRAP=\"..tostring(hw))\nprint(\"LC1_NAKEDSUM=\"..tostring(ns))\nprint(\"LC1_CANCEL=\"..tostring(cancel))\nprint(\"LC1_HASTABLE=\"..tostring(hastab))\nprint(\"LC1_SHAPE=\"..shape)\nprint(\"LC1_CANHASH=\"..ch)\nprint(\"LC1_CANLEN=\"..cn)\nprint(\"LC1_RANOK=\"..tostring(ok))\n"
    );
    let p = unique_tmp("lc1_hook");
    std::fs::write(&p, harness).unwrap();
    Some(run_luau(&luau, &p).stdout)
}

#[test]
fn lc1_raw_art_row_absent() {
    assert!(
        !lc1_build(LC1_SRC, 0x1C01, pipeline::TargetProfile::CliTest).contains(LC1_ART_ROW),
        "no plaintext art row in the raw artifact"
    );
}

#[test]
fn lc1_raw_art_absent() {
    let o = lc1_build(LC1_SRC, 0x1C02, pipeline::TargetProfile::CliTest);
    assert!(!o.contains(LC1_ART_ROW), "no art row");
    assert!(
        !o.contains("--[["),
        "no plaintext `--[[` art comment in the raw artifact"
    );
    assert!(
        !o.contains("github.com/escaliba/basilisk") && !o.contains('\u{1F40D}'),
        "no attribution/emoji in the raw artifact"
    );
}

#[test]
fn lc1_clean_run_emits_no_attribution() {
    let Some(luau) = find_luau() else { return };
    let o = lc1_build(LC1_SRC, 0x1C03, pipeline::TargetProfile::CliTest);
    let p = unique_tmp("lc1_clean");
    std::fs::write(&p, &o).unwrap();
    let run = run_luau(&luau, &p);
    assert!(
        run.stdout.contains("CANARYPROG"),
        "clean run executes ({:?})",
        run.stdout
    );
    assert!(
        !run.stdout.contains(LC1_ART_ROW) && !run.stdout.contains("github.com/escaliba/basilisk"),
        "clean run prints no attribution"
    );
}

#[test]
fn lc1_hook_dump_has_second_capture() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1C05, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    assert!(
        out.contains("LC1_NCAP=2"),
        "hook sees two captures: outer file + canary ({out:?})"
    );
}

#[test]
fn lc1_second_capture_is_small() {
    let o = lc1_build(LC1_SRC, 0x1C06, pipeline::TargetProfile::CliTest);
    assert!(
        max_str_lit_len(&o) < 4096,
        "the canary blob is small (~1.8 KB), not a giant source string"
    );
}

#[test]
fn lc1_no_full_vm_source_stage() {
    let o = lc1_build(LC1_SRC, 0x1C08, pipeline::TargetProfile::CliTest);
    assert!(
        o.starts_with("return(function"),
        "normal inline VM shape, not a source-stage wrapper"
    );
    assert!(
        max_str_lit_len(&o) < 4096,
        "no giant inner-VM source string"
    );
}

#[test]
fn lc1_no_second_full_source_base85_layer() {
    let off = prof_build(LC1_SRC, 0x1C09, pipeline::TargetProfile::CliTest, false);
    let on = lc1_build(LC1_SRC, 0x1C09, pipeline::TargetProfile::CliTest);
    assert!(
        on.len() < off.len() + 8192,
        "overhead is ~the art layer, not a whole-VM re-encode"
    );
}

#[test]
fn lc1_no_giant_source_string() {
    assert!(
        max_str_lit_len(&lc1_build(
            LC1_SRC,
            0x1C0A,
            pipeline::TargetProfile::CliTest
        )) < 4096,
        "no giant source string literal"
    );
}

#[test]
fn lc1_canary_is_load_bearing() {
    let Some(luau) = find_luau() else { return };
    let o = lc1_build(LC1_SRC, 0x1C0B, pipeline::TargetProfile::CliTest);
    let p = unique_tmp("lc1_lb");
    std::fs::write(&p, &o).unwrap();
    assert!(
        run_luau(&luau, &p).stdout.contains("CANARYPROG"),
        "canary salt folds into a working key"
    );
}

#[test]
fn lc1_canary_block_or_bad_return_poisons() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1C0C, pipeline::TargetProfile::CliTest),
        true,
    ) else {
        return;
    };
    assert!(
        !out.contains("CANARYPROG"),
        "a blocked canary fails closed (no program output) ({out:?})"
    );
}

#[test]
fn lc1_normal_hook_forwarding_still_executes() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1C0D, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    assert!(
        out.contains("CANARYPROG"),
        "a log+forward hook still runs the program ({out:?})"
    );
}

#[test]
fn lc1_output_has_no_foreign_obfuscator_markers() {
    let o = lc1_build(LC1_SRC, 0x1C0E, pipeline::TargetProfile::CliTest);
    assert!(
        !o.contains("Luraph") && !o.to_lowercase().contains("trollface"),
        "output carries no foreign-obfuscator markers"
    );
}

#[test]
fn lc1_size_overhead_under_7kb() {
    let off = prof_build(LC1_SRC, 0x1C0F, pipeline::TargetProfile::CliTest, false);
    let on = lc1_build(LC1_SRC, 0x1C0F, pipeline::TargetProfile::CliTest);
    let overhead = on.len().saturating_sub(off.len());
    assert!(
        overhead < 7168,
        "LC1 overhead {overhead} B must be under 7 KB (art + wrapper via streaming carrier)"
    );
}

#[test]
fn lc1_same_seed_deterministic() {
    assert_eq!(
        lc1_build(LC1_SRC, 0x1C10, pipeline::TargetProfile::CliTest),
        lc1_build(LC1_SRC, 0x1C10, pipeline::TargetProfile::CliTest),
        "same seed → byte-identical"
    );
}

#[test]
fn lc1_different_seed_changes_canary_blob() {
    assert_ne!(
        lc1_build(LC1_SRC, 0x1C11, pipeline::TargetProfile::CliTest),
        lc1_build(LC1_SRC, 0x1C12, pipeline::TargetProfile::CliTest),
        "different seed → different canary blob/alphabet (and key)"
    );
}

#[test]
fn lc1_preserves_sig11() {
    let o = lc1_build(LC1_SRC, 0x1C13, pipeline::TargetProfile::CliTest);
    assert!(
        !o.contains("2987342059-332906290")
            && !o.contains("2654435769")
            && !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio anchor"
    );
}

#[test]
fn lc1_preserves_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return \"OK:\" .. tostring(u) end, \"{ENCFUNC_KEY}\", rk)\nprint(f(3))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "lc1_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_full_prof(
        &src,
        0x1C15,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        pipeline::TargetProfile::CliTest,
        true,
        false,
    )
    .unwrap();
    let virt = run_injected(&luau, "lc1_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external key still works with LC1 on"
    );
}

fn lc1_marker(out: &str, key: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.strip_prefix(key).map(str::to_string))
}

#[test]
fn lc1_no_naked_constant_return() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1A01, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    assert_eq!(
        lc1_marker(&out, "LC1_HASWRAP=").as_deref(),
        Some("true"),
        "the canary chunk returns a function wrapper, not a naked constant ({out:?})"
    );
}

#[test]
fn lc1_no_simple_number_plus_number_plus_number_return() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1A02, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    assert_eq!(
        lc1_marker(&out, "LC1_NAKEDSUM=").as_deref(),
        Some("false"),
        "no `return (N+N+N)` split-constant tell ({out:?})"
    );
}

#[test]
fn lc1_canary_wrapper_result_bit_exact() {
    let Some(luau) = find_luau() else { return };
    let o = lc1_build(LC1_SRC, 0x1A03, pipeline::TargetProfile::CliTest);
    let p = unique_tmp("lc1a_exact");
    std::fs::write(&p, &o).unwrap();
    assert!(
        run_luau(&luau, &p).stdout.contains("CANARYPROG"),
        "wrapper folds to the exact salt → correct key"
    );
}

#[test]
fn lc1_canary_wrapper_varies_by_seed() {
    let Some(a) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1A04, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    let Some(b) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1A05, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    let ha = lc1_marker(&a, "LC1_CANHASH=");
    assert!(
        ha.is_some() && ha != lc1_marker(&b, "LC1_CANHASH="),
        "the canary wrapper text varies per seed"
    );
}

#[test]
fn lc1_blocked_canary_still_poisons() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1A07, pipeline::TargetProfile::CliTest),
        true,
    ) else {
        return;
    };
    assert!(
        !out.contains("CANARYPROG"),
        "a blocked wrapped canary still fails closed ({out:?})"
    );
}

#[test]
fn lc1_size_still_under_7kb() {
    let seeds = [
        0x1A08u64, 0x1A09, 0x1A0A, 0x1A0B, 0x2201, 0x3301, 0x4401, 0x5501,
    ];
    let mut deltas: Vec<usize> = seeds
        .iter()
        .map(|&s| {
            let off = prof_build(LC1_SRC, s, pipeline::TargetProfile::CliTest, false);
            let on = lc1_build(LC1_SRC, s, pipeline::TargetProfile::CliTest);
            on.len().saturating_sub(off.len())
        })
        .collect();
    deltas.sort_unstable();
    let median = deltas[deltas.len() / 2];
    assert!(
        median < 7168,
        "median streaming-carrier wrapper overhead {median} exceeds 7 KB across seeds ({deltas:?})"
    );
}

#[test]
fn lc1_no_direct_plus_minus_same_var() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1B01, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    assert_eq!(
        lc1_marker(&out, "LC1_CANCEL=").as_deref(),
        Some("false"),
        "no `(...)-var` cancellation tell (the LC1A wart) ({out:?})"
    );
}

#[test]
fn lc1_no_obvious_constant_sum_return() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1B02, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    assert_eq!(
        lc1_marker(&out, "LC1_NAKEDSUM=").as_deref(),
        Some("false"),
        "no naked constant-sum return"
    );
    assert_eq!(
        lc1_marker(&out, "LC1_HASWRAP=").as_deref(),
        Some("true"),
        "returns a wrapper, not a constant"
    );
}

#[test]
fn lc1_no_single_arithmetic_return_wrapper() {
    let Some(out) = lc1_run_hooked(
        &lc1_build(LC1_SRC, 0x1B03, pipeline::TargetProfile::CliTest),
        false,
    ) else {
        return;
    };
    assert_eq!(
        lc1_marker(&out, "LC1_HASWRAP=").as_deref(),
        Some("true"),
        "the salt rides a function wrapper, not one-line arithmetic ({out:?})"
    );
    assert_eq!(
        lc1_marker(&out, "LC1_NAKEDSUM=").as_deref(),
        Some("false"),
        "not a naked constant sum"
    );
}

#[test]
fn lc1_wrapper_uses_table_or_env_indirection() {
    if find_luau().is_none() {
        return;
    }
    let any_table = (0u64..14)
        .filter_map(|s| {
            lc1_run_hooked(
                &lc1_build(LC1_SRC, 0x1B10 + s, pipeline::TargetProfile::CliTest),
                false,
            )
        })
        .any(|o| lc1_marker(&o, "LC1_HASTABLE=").as_deref() == Some("true"));
    assert!(
        any_table,
        "at least one wrapper variant reads a value from a table/env via a generated key"
    );
}

fn lc1_shape(seed: u64) -> Option<String> {
    let out = lc1_run_hooked(
        &lc1_build(LC1_SRC, seed, pipeline::TargetProfile::CliTest),
        false,
    )?;
    lc1_marker(&out, "LC1_SHAPE=")
}

#[test]
fn lc1_wrapper_has_multiple_variants() {
    if find_luau().is_none() {
        return;
    }
    let shapes: std::collections::HashSet<String> =
        (0u64..16).filter_map(|s| lc1_shape(0x1C00 + s)).collect();
    assert!(
        shapes.len() >= 4,
        "expected >=4 distinct wrapper shapes across seeds, got {shapes:?}"
    );
}

#[test]
fn lc1_wrapper_variant_changes_by_seed() {
    if find_luau().is_none() {
        return;
    }
    let shapes: std::collections::HashSet<String> =
        (0u64..8).filter_map(|s| lc1_shape(0x1D00 + s)).collect();
    assert!(
        shapes.len() >= 2,
        "the wrapper variant varies by seed, got {shapes:?}"
    );
}

#[test]
fn lc1_all_wrapper_variants_return_exact_salt() {
    let Some(luau) = find_luau() else { return };
    for s in 0u64..12 {
        let o = lc1_build(LC1_SRC, 0x1E00 + s, pipeline::TargetProfile::CliTest);
        let p = unique_tmp("lc1c_exact");
        std::fs::write(&p, &o).unwrap();
        assert!(
            run_luau(&luau, &p).stdout.contains("CANARYPROG"),
            "seed offset {s}: wrapper must fold to the exact salt"
        );
    }
}

#[test]
fn lc1_no_naked_constant_return_in_any_variant() {
    if find_luau().is_none() {
        return;
    }
    for s in 0u64..12 {
        let out = lc1_run_hooked(
            &lc1_build(LC1_SRC, 0x1F00 + s, pipeline::TargetProfile::CliTest),
            false,
        )
        .unwrap();
        assert_eq!(
            lc1_marker(&out, "LC1_HASWRAP=").as_deref(),
            Some("true"),
            "seed offset {s}: wrapper present"
        );
        assert_eq!(
            lc1_marker(&out, "LC1_NAKEDSUM=").as_deref(),
            Some("false"),
            "seed offset {s}: no naked constant sum"
        );
        assert_eq!(
            lc1_marker(&out, "LC1_CANCEL=").as_deref(),
            Some("false"),
            "seed offset {s}: no cancellation"
        );
    }
}

fn typed_raw_eq_virt(src: &str) -> Option<(String, String)> {
    let luau = find_luau()?;
    let rp = unique_tmp("typed_raw");
    std::fs::write(&rp, src).unwrap();
    let raw = run_luau(&luau, &rp).stdout;
    let obf =
        pipeline::virtualize_with(src, 0x7DEF, true, true, true, true, true, false, false).ok()?;
    let vp = unique_tmp("typed_virt");
    std::fs::write(&vp, &obf).unwrap();
    let virt = run_luau(&luau, &vp).stdout;
    Some((raw, virt))
}

#[test]
fn typed_luau_locals() {
    let Some((raw, virt)) = typed_raw_eq_virt("local x: number = 5\nlocal s: string = \"hi\"\nlocal b: boolean = true\nlocal t: { number } = { 1, 2, 3 }\nprint(x + t[1], s, tostring(b))") else { return };
    assert!(raw.contains("hi"), "typed locals run raw");
    assert_eq!(raw, virt, "typed locals: virtualized behavior matches raw");
}

#[test]
fn typed_luau_functions() {
    let Some((raw, virt)) = typed_raw_eq_virt("local function f(x: string, y: number): boolean return #x > y end\nlocal function sum(...: number): number local t = { ... } local s = 0 for i = 1, #t do s = s + t[i] end return s end\nprint(f(\"hello\", 3), f(\"ab\", 5), sum(1, 2, 3, 4))") else { return };
    assert!(!raw.trim().is_empty(), "typed functions run raw");
    assert_eq!(
        raw, virt,
        "typed function params/returns/variadic: behavior matches"
    );
}

#[test]
fn typed_luau_type_aliases() {
    let Some((raw, virt)) = typed_raw_eq_virt("type Point = { x: number, y: number }\ntype Name = string\nlocal p: Point = { x = 10, y = 20 }\nlocal n: Name = \"pt\"\nprint(p.x + p.y, n)") else { return };
    assert!(raw.contains("30"), "type alias program runs raw");
    assert_eq!(raw, virt, "type aliases dropped, behavior matches");
}

#[test]
fn typed_luau_export_type_aliases() {
    let Some((raw, virt)) = typed_raw_eq_virt("export type Vec = { [number]: number }\nexport type Handler = (number) -> number\nlocal v: Vec = { 1, 2, 3 }\nprint(v[1] + v[2] + v[3])") else { return };
    assert!(raw.contains("6"), "export type program runs raw");
    assert_eq!(raw, virt, "export type aliases dropped, behavior matches");
}

#[test]
fn typed_luau_casts() {
    let Some((raw, virt)) = typed_raw_eq_virt("local x = (5 :: any) + (3 :: number)\nlocal s = (\"hi\" :: string)\nlocal t = ({ 1, 2 } :: { number })\nprint(x, s, t[2])") else { return };
    assert!(raw.contains("8"), "casts run raw");
    assert_eq!(
        raw, virt,
        "`::` casts erased to the inner expression, behavior matches"
    );
}

#[test]
fn typed_luau_typeof() {
    let Some((raw, virt)) = typed_raw_eq_virt("local n = 5\nlocal z: typeof(n) = n * 2\nlocal m: { [string]: typeof(n) } = { a = 1 }\nprint(z, m.a)") else { return };
    assert!(raw.contains("10"), "typeof-type program runs raw");
    assert_eq!(
        raw, virt,
        "typeof(...) type expressions erased, behavior matches"
    );
}

#[test]
fn typed_luau_generics_if_supported() {
    let Some((raw, virt)) = typed_raw_eq_virt("type Id<T> = T\ntype Pair<A, B> = { first: A, second: B }\nlocal a: Id<number> = 9\nlocal p: Pair<number, string> = { first = 1, second = \"x\" }\nlocal function g<T>(v: T): T return v end\nprint(a, p.first, p.second, g(42))") else { return };
    assert!(
        raw.contains("42"),
        "generic type params run raw (full_moon luau supports them)"
    );
    assert_eq!(
        raw, virt,
        "generic type params/args erased, behavior matches"
    );
}

#[test]
fn typed_luau_with_a_string_constant() {
    let Some(luau) = find_luau() else { return };
    let src = "local s: string = \"typed_secret\"\nlocal n: number = 7\nprint(\"ES\", s, n)";
    let obf =
        pipeline::virtualize_with(src, 0x7E5, true, false, true, true, true, false, false).unwrap();
    assert!(
        !obf.contains("typed_secret"),
        "ENCSTR plaintext must not ship even with a type annotation"
    );
    let p = unique_tmp("typed_encstr");
    std::fs::write(&p, &obf).unwrap();
    assert_eq!(
        run_luau(&luau, &p).stdout.trim(),
        "ES\ttyped_secret\t7",
        "typed ENCSTR decrypts correctly"
    );
}

#[test]
fn typed_luau_with_BASIL_ENCFUNC() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u: number): number return u * 2 end, \"{ENCFUNC_KEY}\", rk)\nprint(f(21))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "typed_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0x7EF7, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "typed_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("42"), "typed ENCFUNC body runs raw");
    assert_eq!(
        raw.stdout, virt.stdout,
        "typed params/return inside ENCFUNC behave identically"
    );
}

#[test]
fn typed_luau_runtime_behavior_matches_untyped() {
    let Some(luau) = find_luau() else { return };
    let typed = "type N = number\nlocal function f(a: N, b: N): N return a + b end\nlocal x: number = f(2, 3) + (10 :: any)\nlocal t: { string } = { \"p\", \"q\" }\nprint(x, t[1] .. t[2])";
    let untyped = "local function f(a, b) return a + b end\nlocal x = f(2, 3) + 10\nlocal t = { \"p\", \"q\" }\nprint(x, t[1] .. t[2])";
    let obf = pipeline::virtualize_with(typed, 0x7A11, true, true, true, true, true, false, false)
        .unwrap();
    let vp = unique_tmp("typed_match_virt");
    std::fs::write(&vp, &obf).unwrap();
    let up = unique_tmp("typed_match_untyped");
    std::fs::write(&up, untyped).unwrap();
    assert_eq!(
        run_luau(&luau, &vp).stdout,
        run_luau(&luau, &up).stdout,
        "typed (virtualized) output equals the untyped twin"
    );
}

const B1A_SRC: &str = "local function add(a,b) return a+b end\nlocal function fib(n) if n<2 then return n end return fib(n-1)+fib(n-2) end\nlocal t={} for i=1,6 do t[i]=add(i,i*2) end\nlocal s=0 for i=1,#t do s=s+t[i] end\nprint(\"B1A\", s, fib(9), (\"ab\"):rep(3))";

fn b1a_virt_stdout(src: &str, seed: u64) -> Option<String> {
    let luau = find_luau()?;
    let obf =
        pipeline::virtualize_with(src, seed, true, true, true, true, true, false, false).ok()?;
    let p = unique_tmp("b1a");
    std::fs::write(&p, &obf).unwrap();
    Some(run_luau(&luau, &p).stdout)
}

#[test]
fn byte1a_opcode_stream_mask_differs_by_pc() {
    let mk = bytecode::crypt::opmask_key(0xB1A01);
    let esk = t_esk(0xB1A01, mk);
    let masks: Vec<u8> = (1..=64u32)
        .map(|pc| bytecode::crypt::opmask_byte(mk, &esk, 0, pc))
        .collect();
    let distinct: std::collections::HashSet<u8> = masks.iter().copied().collect();
    assert!(
        distinct.len() >= 32,
        "mask must vary widely across pc, got {} distinct",
        distinct.len()
    );
    let adj = masks.windows(2).filter(|w| w[0] != w[1]).count();
    assert!(
        adj >= 60,
        "adjacent pcs should almost always differ, got {adj}/63"
    );
}

#[test]
fn byte1a_same_logical_opcode_different_positions_different_encoded_bytes() {
    let mk = bytecode::crypt::opmask_key(0xB1A02);
    let esk = t_esk(0xB1A02, mk);
    let x: u8 = 7;
    let enc: std::collections::HashSet<u8> = (1..=64u32)
        .map(|pc| x ^ bytecode::crypt::opmask_byte(mk, &esk, 3, pc))
        .collect();
    assert!(
        enc.len() >= 32,
        "same logical op at different pcs serializes to many distinct bytes, got {}",
        enc.len()
    );
}

#[test]
fn byte1a_different_seed_different_opcode_stream() {
    assert_ne!(
        bytecode::crypt::opmask_key(1),
        bytecode::crypt::opmask_key(2),
        "mask key varies by seed"
    );
    let seq = |seed: u64| -> Vec<u8> {
        let mk = bytecode::crypt::opmask_key(seed);
        let esk = t_esk(seed, mk);
        (1..=32u32)
            .map(|pc| bytecode::crypt::opmask_byte(mk, &esk, 0, pc))
            .collect()
    };
    assert_ne!(seq(11), seq(22), "mask sequence varies by seed");
    let a =
        pipeline::virtualize_with(B1A_SRC, 11, true, true, true, true, true, false, false).unwrap();
    let b =
        pipeline::virtualize_with(B1A_SRC, 22, true, true, true, true, true, false, false).unwrap();
    assert_ne!(a, b, "same script, different seed → different artifact");
}

#[test]
fn byte1a_runtime_behavior_equivalence() {
    let Some(luau) = find_luau() else { return };
    let rp = unique_tmp("b1a_raw");
    std::fs::write(&rp, B1A_SRC).unwrap();
    let raw = run_luau(&luau, &rp).stdout;
    assert!(raw.contains("B1A"), "raw runs");
    assert_eq!(
        Some(raw),
        b1a_virt_stdout(B1A_SRC, 0xB1A03),
        "masked build behaves identically to raw"
    );
}

#[test]
fn byte1a_with_f1_constants() {
    let Some(luau) = find_luau() else { return };
    let src = "local a = \"alpha\"\nlocal b = 1234\nlocal c = { x = \"nested\", y = 3.5 }\nprint(a, b, c.x, c.y)";
    let rp = unique_tmp("b1a_f1_raw");
    std::fs::write(&rp, src).unwrap();
    assert_eq!(
        Some(run_luau(&luau, &rp).stdout),
        b1a_virt_stdout(src, 0xB1A04),
        "F1 constants decrypt correctly under opcode masking"
    );
}

#[test]
fn byte1a_with_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return u * 3 end, \"{ENCFUNC_KEY}\", rk)\nprint(f(14))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "b1a_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0xB1A05, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "b1a_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("42"), "encfunc raw runs");
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external key still works under opcode masking"
    );
}

#[test]
fn byte1a_with_at2_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"AT2PROG\")",
        0xB1A08,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("b1a_at2");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("AT2PROG"),
        "executor profile still fails closed on the CLI under opcode masking"
    );
}

#[test]
fn byte1a_no_raw_marker_regressions() {
    let o = pipeline::virtualize_with(
        "local s = \"x\" print(s)",
        0xB1A09,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    for m in [
        ",@@&@&&&@@@&&&",
        "github.com/escaliba/basilisk",
        "loadstring",
        "2654435769",
        "2987342059-332906290",
    ] {
        assert!(!o.contains(m), "no {m} in the masked artifact");
    }
    assert!(
        !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio literal"
    );
}

#[test]
fn byte1a_perf_budget() {
    let o = pipeline::virtualize_with(
        "print(1 + 2)",
        0xB1A0A,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        o.len() < 31_000,
        "no size blowup from opcode masking (got {} bytes)",
        o.len()
    );
}

const B1B_SRC: &str = "local function outer(tag)\n  local function inner(n) return tag .. \":\" .. tostring(n) end\n  return inner\nend\nlocal A = \"aa\"\nlocal B = 77\nlocal f = outer(\"Z\")\nprint(\"B1B\", A, B, f(1), f(2), (outer(\"Q\"))(3))";

fn proto_of(src: &str) -> bytecode::proto::Proto {
    let m = frontend::lower_str(src).unwrap();
    let m = frontend::macros::expand(m, 0).unwrap();
    bytecode::compile(&m).unwrap()
}

fn b1b_raw_eq_virt(src: &str, seed: u64) -> Option<(String, String)> {
    let luau = find_luau()?;
    let rp = unique_tmp("b1b_raw");
    std::fs::write(&rp, src).unwrap();
    let raw = run_luau(&luau, &rp).stdout;
    let obf =
        pipeline::virtualize_with(src, seed, true, true, true, true, true, false, false).ok()?;
    let vp = unique_tmp("b1b_virt");
    std::fs::write(&vp, &obf).unwrap();
    Some((raw, run_luau(&luau, &vp).stdout))
}

#[test]
fn byte1b_constant_pool_order_differs_by_seed() {
    let p = proto_of("local a='aa' local b='bb' local c='cc' local d=11 local e=22 local f=33 print(a,b,c,d,e,f)");
    assert!(
        p.consts.len() >= 6,
        "sample has enough constants ({} found)",
        p.consts.len()
    );
    let orders: std::collections::HashSet<String> = (1u64..=6)
        .map(|s| format!("{:?}", passes::shuffle_structure(&p, s).consts))
        .collect();
    assert!(
        orders.len() >= 2,
        "constant-pool order must vary across seeds, got {} distinct",
        orders.len()
    );
    for s in 1u64..=6 {
        assert_eq!(
            passes::shuffle_structure(&p, s).consts.len(),
            p.consts.len(),
            "shuffle preserves the pool (no add/drop)"
        );
    }
}

#[test]
fn byte1b_constant_indices_rewritten_correctly() {
    let Some(luau) = find_luau() else { return };
    let src = "print(\"K1\", \"K2\", \"K3\", 111, 222, 333, \"K4\")";
    let rp = unique_tmp("b1b_ci_raw");
    std::fs::write(&rp, src).unwrap();
    let raw = run_luau(&luau, &rp).stdout;
    let obf =
        pipeline::virtualize_with(src, 7, true, false, true, true, true, false, false).unwrap();
    let vp = unique_tmp("b1b_ci_virt");
    std::fs::write(&vp, &obf).unwrap();
    assert_eq!(
        raw,
        run_luau(&luau, &vp).stdout,
        "const indices rewritten to the correct constants"
    );
}

#[test]
fn byte1b_proto_order_differs_by_seed() {
    let p = proto_of("local function a() return 1 end local function b() return 2 end local function c() return 3 end local function d() return 4 end local function e() return 5 end print(a(),b(),c(),d(),e())");
    assert!(
        p.protos.len() >= 5,
        "sample has enough child protos ({} found)",
        p.protos.len()
    );
    let orders: std::collections::HashSet<String> = (1u64..=6)
        .map(|s| format!("{:?}", passes::shuffle_structure(&p, s).protos))
        .collect();
    assert!(
        orders.len() >= 2,
        "child-proto order must vary across seeds, got {} distinct",
        orders.len()
    );
}

#[test]
fn byte1b_proto_refs_rewritten_correctly() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1B_SRC, 0xB1B01) else {
        return;
    };
    assert!(raw.contains("Z:1"), "nested closures run raw");
    assert_eq!(
        raw, virt,
        "Closure proto refs rewritten correctly under shuffle"
    );
}

#[test]
fn byte1b_runtime_behavior_equivalence() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1B_SRC, 0xB1B02) else {
        return;
    };
    assert!(!raw.trim().is_empty(), "raw runs");
    assert_eq!(raw, virt, "shuffled build behaves identically to raw");
}

#[test]
fn byte1b_with_f1_constants() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local a = \"alpha\"\nlocal b = 1234\nlocal c = { x = \"nested\", y = 3.5, z = \"deep\" }\nprint(a, b, c.x, c.y, c.z)", 0xB1B03) else { return };
    assert_eq!(
        raw, virt,
        "F1 constants decrypt correctly under const-pool shuffle"
    );
}

#[test]
fn byte1b_with_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return u + 100 end, \"{ENCFUNC_KEY}\", rk)\nprint(f(23))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "b1b_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0xB1B04, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "b1b_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("123"), "encfunc raw runs");
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external key + inner-proto shuffle still works"
    );
}

#[test]
fn byte1b_with_at2_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"AT2PROG\")",
        0xB1B07,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("b1b_at2");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("AT2PROG"),
        "executor profile still fails closed on the CLI under shuffle"
    );
}

#[test]
fn byte1b_same_seed_deterministic() {
    assert_eq!(
        pipeline::virtualize_with(B1B_SRC, 0xB1B08, true, true, true, true, true, false, false)
            .unwrap(),
        pipeline::virtualize_with(B1B_SRC, 0xB1B08, true, true, true, true, true, false, false)
            .unwrap(),
        "same seed → byte-identical (shuffle is deterministic)"
    );
}

#[test]
fn byte1b_no_raw_marker_regressions() {
    let o = pipeline::virtualize_with(
        "local s = \"x\" print(s)",
        0xB1B09,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    for m in [
        ",@@&@&&&@@@&&&",
        "github.com/escaliba/basilisk",
        "loadstring",
        "2654435769",
        "2987342059-332906290",
    ] {
        assert!(!o.contains(m), "no {m} in the shuffled artifact");
    }
    assert!(
        !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio literal"
    );
}

const B1A2_SRC: &str = "local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end\nlocal function make(p) return function(x) return p .. tostring(x * 3 + 1) end end\nlocal t = {}\nfor i = 1, 8 do if i % 2 == 0 then t[i] = \"e\" .. i else t[i] = \"o\" .. i end end\nlocal g = make(\"G\")\nlocal s = 0\nfor i = 1, #t do s = s + #t[i] end\nprint(\"B1A2\", fib(12), g(4), s, t[3], t[8], 3.14159, \"const\")";

#[test]
fn byte1a2_operand_stream_differs_by_seed() {
    assert_ne!(
        bytecode::crypt::opmask_key(1),
        bytecode::crypt::opmask_key(2),
        "mask key varies by seed"
    );
    let seq = |seed: u64| -> Vec<u8> {
        let mk = bytecode::crypt::opmask_key(seed);
        let esk = t_esk(seed, mk);
        (0..16u32)
            .map(|j| bytecode::crypt::opmask2_byte(mk, &esk, 0, 5, 0, j))
            .collect()
    };
    assert_ne!(seq(11), seq(22), "operand mask sequence varies by seed");
    let a = pipeline::virtualize_with(B1A2_SRC, 11, true, true, true, true, true, false, false)
        .unwrap();
    let b = pipeline::virtualize_with(B1A2_SRC, 22, true, true, true, true, true, false, false)
        .unwrap();
    assert_ne!(a, b, "same script, different seed → different artifact");
}

#[test]
fn byte1a2_same_operand_different_pc_differs_when_masked() {
    let mk = bytecode::crypt::opmask_key(0x1A201);
    let esk = t_esk(0x1A201, mk);
    let masks: std::collections::HashSet<u8> = (1..=64u32)
        .map(|pc| bytecode::crypt::opmask2_byte(mk, &esk, 0, pc, 0, 0))
        .collect();
    assert!(
        masks.len() >= 16,
        "operand mask (byte 0) varies across pc, got {} distinct",
        masks.len()
    );
    let slot_varies = (1..=64u32)
        .filter(|&pc| {
            (0..3u32)
                .map(|slot| bytecode::crypt::opmask2_byte(mk, &esk, 0, pc, slot, 0))
                .collect::<std::collections::HashSet<u8>>()
                .len()
                >= 2
        })
        .count();
    assert!(
        slot_varies >= 40,
        "operand slot varies the mask at most positions, got {slot_varies}/64"
    );
}

#[test]
fn byte1a2_runtime_behavior_equivalence() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1A2_SRC, 0x1A202) else {
        return;
    };
    assert!(raw.contains("B1A2"), "raw runs");
    assert_eq!(raw, virt, "operand-masked build behaves identically to raw");
}

#[test]
fn byte1a2_jump_offsets_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end\nlocal s = 0\nfor i = 1, 12 do if i % 3 == 0 then s = s + i else s = s - 1 end end\nprint(fib(13), s)", 0x1A203) else { return };
    assert!(raw.contains("233"), "jump-heavy program runs raw");
    assert_eq!(raw, virt, "jump offsets preserved under operand masking");
}

#[test]
fn byte1a2_constant_refs_preserved_after_byte1b() {
    let Some((raw, virt)) = b1b_raw_eq_virt(
        "print(\"K1\", \"K2\", \"K3\", 111, 222, 333, \"K4\", \"K5\", 4.5)",
        0x1A204,
    ) else {
        return;
    };
    assert!(raw.contains("K5"), "const-heavy program runs raw");
    assert_eq!(
        raw, virt,
        "const refs correct under BYTE1B shuffle + BYTE1A.2 operand masking"
    );
}

#[test]
fn byte1a2_proto_refs_preserved_after_byte1b() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1B_SRC, 0x1A205) else {
        return;
    };
    assert!(raw.contains("Z:1"), "nested closures run raw");
    assert_eq!(
        raw, virt,
        "Closure proto refs correct under BYTE1B shuffle + BYTE1A.2 operand masking"
    );
}

#[test]
fn byte1a2_with_f1_constants() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local a = \"alpha\"\nlocal b = 1234\nlocal c = { x = \"nested\", y = 3.5 }\nprint(a, b, c.x, c.y)", 0x1A206) else { return };
    assert_eq!(
        raw, virt,
        "F1 constants decrypt correctly under operand masking"
    );
}

#[test]
fn byte1a2_with_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return u * 4 end, \"{ENCFUNC_KEY}\", rk)\nprint(f(25))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "b1a2_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0x1A207, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "b1a2_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("100"), "encfunc raw runs");
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external key still works under operand masking"
    );
}

#[test]
fn byte1a2_with_at2_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"AT2PROG\")",
        0x1A20A,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("b1a2_at2");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("AT2PROG"),
        "executor profile still fails closed on the CLI under operand masking"
    );
}

#[test]
fn byte1a2_no_raw_marker_regressions() {
    let o = pipeline::virtualize_with(
        "local s = \"x\" print(s)",
        0x1A20B,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    for m in [
        ",@@&@&&&@@@&&&",
        "github.com/escaliba/basilisk",
        "loadstring",
        "2654435769",
        "2987342059-332906290",
    ] {
        assert!(!o.contains(m), "no {m} in the operand-masked artifact");
    }
    assert!(
        !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio literal"
    );
}

#[test]
fn byte1a2_size_budget() {
    let o = pipeline::virtualize_with(
        "print(1 + 2 + 3 + 4 + 5)",
        0x1A20C,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        o.len() < 31_000,
        "no operand-varint blowup (got {} bytes)",
        o.len()
    );
}

fn count_pads(p: &bytecode::proto::Proto) -> usize {
    p.code
        .iter()
        .filter(|i| i.op == bytecode::opcode::Opcode::Pad)
        .count()
        + p.protos.iter().map(count_pads).sum::<usize>()
}

fn big_proto_src() -> String {
    let mut src: String = (0..50)
        .map(|i| format!("local v{i} = ({i} * 3) + {i}\n"))
        .collect();
    src.push_str("print(v0 + v49)");
    src
}

fn big_proto() -> bytecode::proto::Proto {
    proto_of(&big_proto_src())
}

#[test]
fn byte1c_decoy_instructions_present() {
    let p = big_proto();
    let total: usize = (1u64..=4)
        .map(|s| count_pads(&passes::pad_decoys(&p, s)))
        .sum();
    assert!(total > 0, "pad decoys are inserted into the code");
    assert_eq!(
        count_pads(&p),
        0,
        "the pre-pass proto has no pads (they are added by the pass)"
    );
}

#[test]
fn byte1c_decoys_vary_by_seed() {
    let p = big_proto();
    let a = passes::pad_decoys(&p, 1);
    let b = passes::pad_decoys(&p, 2);
    assert_ne!(a, b, "pad positions/count vary by seed");
    assert_eq!(passes::pad_decoys(&p, 1), a, "same seed deterministic");
}

#[test]
fn byte1c_runtime_behavior_equivalence() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1A2_SRC, 0x1C001) else {
        return;
    };
    assert!(raw.contains("B1A2"), "raw runs");
    assert_eq!(raw, virt, "padded build behaves identically to raw");
}

#[test]
fn byte1c_jump_targets_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end\nlocal s = 0\nfor i = 1, 15 do if i % 4 == 0 then s = s + i else s = s - 1 end end\nwhile s < 0 do s = s + 1 end\nprint(fib(14), s)", 0x1C002) else { return };
    assert!(raw.contains("377"), "jump-heavy program runs raw");
    assert_eq!(
        raw, virt,
        "jump targets valid after pad insertion (fixup correct)"
    );
}

#[test]
fn byte1c_return_vararg_behavior_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local function pack(...) return select(\"#\", ...), ... end\nlocal function multi() return 1, 2, 3 end\nlocal n, a, b, c = pack(10, 20, 30)\nprint(n, a, b, c, multi())", 0x1C003) else { return };
    assert!(!raw.trim().is_empty(), "vararg/return program runs raw");
    assert_eq!(raw, virt, "returns + varargs preserved under pad insertion");
}

#[test]
fn byte1c_closure_upvalue_behavior_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local function counter()\n  local n = 0\n  return function() n = n + 1 return n end\nend\nlocal c = counter()\nprint(c(), c(), c())", 0x1C004) else { return };
    assert!(raw.contains("1"), "closure/upvalue program runs raw");
    assert_eq!(
        raw, virt,
        "closure + upvalue behavior preserved under pad insertion"
    );
}

#[test]
fn byte1c_decoys_are_opcode_masked() {
    let Some((raw, virt)) = b1b_raw_eq_virt(&(big_proto_src()), 0x1C005) else {
        return;
    };
    assert_eq!(
        raw, virt,
        "padded build runs → pad opcode is masked/unmasked correctly"
    );
    let obf = pipeline::virtualize_with(
        &big_proto_src(),
        0x1C005,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        !obf.contains("PAD"),
        "no plaintext PAD marker in the artifact"
    );
}

#[test]
fn byte1c_decoy_operands_are_masked() {
    let Some((raw, virt)) = b1b_raw_eq_virt(&big_proto_src(), 0x1C006) else {
        return;
    };
    assert_eq!(
        raw, virt,
        "padded build runs → pad operands masked/unmasked correctly"
    );
}

#[test]
fn byte1c_with_f1_constants() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local a = \"alpha\"\nlocal b = 1234\nlocal c = { x = \"nested\", y = 3.5 }\nprint(a, b, c.x, c.y)", 0x1C007) else { return };
    assert_eq!(
        raw, virt,
        "F1 constants decrypt correctly with pads present"
    );
}

#[test]
fn byte1c_with_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return u + 7 end, \"{ENCFUNC_KEY}\", rk)\nprint(f(35))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "b1c_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0x1C008, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "b1c_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("42"), "encfunc raw runs");
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external key still works with pads present"
    );
}

#[test]
fn byte1c_with_at2_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"AT2PROG\")",
        0x1C00B,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("b1c_at2");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("AT2PROG"),
        "executor profile still fails closed on the CLI with pads"
    );
}

#[test]
fn byte1c_no_raw_marker_regressions() {
    let o = pipeline::virtualize_with(
        "local s = \"x\" print(s)",
        0x1C00C,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    for m in [
        ",@@&@&&&@@@&&&",
        "github.com/escaliba/basilisk",
        "loadstring",
        "2654435769",
        "2987342059-332906290",
    ] {
        assert!(!o.contains(m), "no {m} in the padded artifact");
    }
    assert!(
        !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio literal"
    );
}

#[test]
fn byte1c_size_budget() {
    let o = pipeline::virtualize_with(
        &big_proto_src(),
        0x1C00D,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        o.len() < 40_000,
        "padded artifact stays modest (got {} bytes)",
        o.len()
    );
}

#[test]
fn byte1c_perf_budget() {
    let p = big_proto();
    let padded = passes::pad_decoys(&p, 3);
    let real = p.code.len();
    let pads = count_pads(&padded);
    assert!(
        pads * 4 <= real.max(1),
        "pad density stays low (~1/16): {pads} pads over {real} real insts"
    );
}

fn opmap(seed: u64, pid: u32) -> [u8; 256] {
    let mp = bytecode::crypt::mapkey(seed);
    bytecode::crypt::proto_opmap(mp, &t_esk(seed, mp), pid)
}

#[test]
fn byte1d_opcode_map_differs_by_proto() {
    let mk = bytecode::crypt::mapkey(0x1D01);
    let esk = t_esk(0x1D01, mk);
    let (p0, p1, p2) = (
        bytecode::crypt::proto_opmap(mk, &esk, 0),
        bytecode::crypt::proto_opmap(mk, &esk, 1),
        bytecode::crypt::proto_opmap(mk, &esk, 2),
    );
    assert_ne!(p0, p1, "proto 0 and 1 have different opcode maps");
    assert_ne!(p1, p2, "proto 1 and 2 have different opcode maps");
    let mut sorted = p0;
    sorted.sort();
    assert!(
        sorted.iter().enumerate().all(|(i, &v)| v as usize == i),
        "each map is a valid permutation of [0,256)"
    );
}

#[test]
fn byte1d_opcode_map_differs_by_seed() {
    assert_ne!(
        opmap(1, 0),
        opmap(2, 0),
        "proto 0's map differs across seeds"
    );
    assert_ne!(
        opmap(0xAAAA, 3),
        opmap(0xBBBB, 3),
        "proto 3's map differs across seeds"
    );
}

#[test]
fn byte1d_same_logical_opcode_differs_across_protos() {
    let mk = bytecode::crypt::mapkey(0x1D03);
    let esk = t_esk(0x1D03, mk);
    let (p0, p1) = (
        bytecode::crypt::proto_opmap(mk, &esk, 0),
        bytecode::crypt::proto_opmap(mk, &esk, 1),
    );
    let diff = (0..256).filter(|&k| p0[k] != p1[k]).count();
    assert!(
        diff >= 200,
        "same logical opcode maps to different serialized bytes across protos, got {diff}/256"
    );
}

#[test]
fn byte1d_same_seed_deterministic() {
    assert_eq!(
        pipeline::virtualize_with(B1A2_SRC, 0x1D04, true, true, true, true, true, false, false)
            .unwrap(),
        pipeline::virtualize_with(B1A2_SRC, 0x1D04, true, true, true, true, true, false, false)
            .unwrap(),
        "same seed → byte-identical"
    );
    assert_eq!(
        opmap(0x1D04, 5),
        opmap(0x1D04, 5),
        "map is deterministic per (seed, pid)"
    );
}

#[test]
fn byte1d_runtime_behavior_equivalence() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1A2_SRC, 0x1D05) else {
        return;
    };
    assert!(raw.contains("B1A2"), "raw runs");
    assert_eq!(
        raw, virt,
        "per-proto-mapped build behaves identically to raw"
    );
}

#[test]
fn byte1d_corpus_equivalence() {
    let src = "local mt = setmetatable({}, { __index = function(_, k) return k .. \"!\" end })\nlocal function acc(...) local s = 0 for i = 1, select(\"#\", ...) do s = s + select(i, ...) end return s end\nlocal function outer() local n = 0 return function() n = n + 1 return n end end\nlocal g = outer()\nprint(mt.hello, acc(1,2,3,4), g(), g(), #\"abc\")";
    let Some((raw, virt)) = b1b_raw_eq_virt(src, 0x1D06) else {
        return;
    };
    assert!(!raw.trim().is_empty(), "multi-feature program runs raw");
    assert_eq!(
        raw, virt,
        "corpus-style behavior equivalent under per-proto maps"
    );
}

#[test]
fn byte1d_with_superops() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local a, b, c = 1, 2, 3\nlocal t = { a + b, b * c, a - c, \"k1\", \"k2\" }\nprint(t[1], t[2], t[3], t[4], t[5])", 0x1D07) else { return };
    assert_eq!(raw, virt, "super-ops correct under per-proto maps");
}

#[test]
fn byte1d_with_synonym_ops() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local x = 0\nfor i = 1, 30 do x = x + i - 1 + (i * 2) end\nlocal t = {} t[1] = x t[2] = x + 1\nprint(x, t[1], t[2])", 0x1D08) else { return };
    assert_eq!(raw, virt, "synonym ops correct under per-proto maps");
}

#[test]
fn byte1d_with_pad_decoys() {
    let p = big_proto();
    assert!(
        (1u64..=4)
            .map(|s| count_pads(&passes::pad_decoys(&p, s)))
            .sum::<usize>()
            > 0,
        "pads present"
    );
    let Some((raw, virt)) = b1b_raw_eq_virt(&big_proto_src(), 0x1D09) else {
        return;
    };
    assert_eq!(raw, virt, "Pad decoys (mapped per-proto) still inert");
}

#[test]
fn byte1d_jump_targets_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end\nlocal s = 0 for i = 1, 12 do if i % 3 == 0 then s = s + i else s = s - 1 end end\nwhile s < 0 do s = s + 1 end\nprint(fib(13), s)", 0x1D0A) else { return };
    assert!(raw.contains("233"), "jump-heavy runs raw");
    assert_eq!(raw, virt, "jump targets preserved under per-proto maps");
}

#[test]
fn byte1d_constant_refs_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt(
        "print(\"K1\", \"K2\", \"K3\", 111, 222, 333, \"K4\", 4.5)",
        0x1D0B,
    ) else {
        return;
    };
    assert!(raw.contains("K4"), "const-heavy runs raw");
    assert_eq!(raw, virt, "const refs correct under per-proto maps");
}

#[test]
fn byte1d_proto_refs_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1B_SRC, 0x1D0C) else {
        return;
    };
    assert!(raw.contains("Z:1"), "nested closures run raw");
    assert_eq!(raw, virt, "Closure proto refs correct under per-proto maps");
}

#[test]
fn byte1d_f1_constant_tags_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local a = \"alpha\"\nlocal b = 1234\nlocal c = { x = \"nested\", y = 3.5, z = \"deep\" }\nprint(a, b, c.x, c.y, c.z)", 0x1D0D) else { return };
    assert_eq!(raw, virt, "F1 constant tags correct under per-proto maps");
}

#[test]
fn byte1d_const_site_tokens_preserved() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local k = \"SITE\"\nlocal s = \"\"\nfor i = 1, 6 do s = s .. k .. tostring(i) end\nprint(s, k, k)", 0x1D0E) else { return };
    assert_eq!(raw, virt, "const-site tokens correct under per-proto maps");
}

#[test]
fn byte1d_with_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return u - 5 end, \"{ENCFUNC_KEY}\", rk)\nprint(f(50))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "b1d_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0x1D0F, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "b1d_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("45"), "encfunc raw runs");
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external key + inner-proto per-proto map still works"
    );
}

#[test]
fn byte1d_with_at2_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"AT2PROG\")",
        0x1D12,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("b1d_at2");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("AT2PROG"),
        "executor profile still fails closed on the CLI under per-proto maps"
    );
}

#[test]
fn byte1d_no_raw_marker_regressions() {
    let o = pipeline::virtualize_with(
        "local s = \"x\" print(s)",
        0x1D13,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    for m in [
        ",@@&@&&&@@@&&&",
        "github.com/escaliba/basilisk",
        "loadstring",
        "2654435769",
        "2987342059-332906290",
    ] {
        assert!(!o.contains(m), "no {m} in the per-proto-mapped artifact");
    }
    assert!(
        !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio literal"
    );
}

#[test]
fn byte1d_size_budget() {
    let o = pipeline::virtualize_with(
        "print(1 + 2 + 3)",
        0x1D14,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        o.len() < 30_000,
        "no payload growth from per-proto maps (got {} bytes)",
        o.len()
    );
}

#[test]
fn byte1d_perf_budget() {
    let p = opmap(0x1D15, 7);
    let mut sorted = p;
    sorted.sort();
    assert!(
        sorted.iter().enumerate().all(|(i, &v)| v as usize == i),
        "map is a bijection → O(1) decode lookup"
    );
}

#[test]
fn att2a_no_stable_env_nonce_string() {
    assert_ne!(
        bytecode::crypt::env_nonce(1),
        bytecode::crypt::env_nonce(2),
        "env nonce varies by seed"
    );
    let old = [0x6e6f_726du32, 0x636f_6e73, 0x7476_3031];
    for s in [1u64, 2, 305419896, 0xDEAD] {
        assert_ne!(
            bytecode::crypt::env_nonce(s),
            old,
            "env nonce is not the fixed normconstv01 (seed {s})"
        );
    }
}

#[test]
fn att2a_no_stable_payload_nonce() {
    assert_ne!(
        bytecode::encoder::payload_salt(1),
        bytecode::encoder::payload_salt(2),
        "payload salt varies by seed"
    );
    let a = pipeline::virtualize_with("print(1)", 1, true, false, false, false, true, false, false)
        .unwrap();
    let b = pipeline::virtualize_with("print(1)", 2, true, false, false, false, true, false, false)
        .unwrap();
    assert_ne!(
        a, b,
        "same source, different seed → different artifact (per-build salt)"
    );
}

#[test]
fn att2a_no_stable_encfunc_nonces() {
    assert_ne!(
        bytecode::encoder::payload_salt(0xA),
        bytecode::encoder::payload_salt(0xB),
        "nonce base varies by seed"
    );
    let body = format!(
        "local f = BASIL_ENCFUNC(function(u) return u end, \"{ENCFUNC_KEY}\", rk)\nprint(f(1))"
    );
    let src = enc_external(&body);
    let a =
        pipeline::virtualize_with(&src, 0xA, true, true, true, true, true, false, false).unwrap();
    let b =
        pipeline::virtualize_with(&src, 0xB, true, true, true, true, true, false, false).unwrap();
    assert_ne!(
        a, b,
        "same ENCFUNC source, different seed → different sealed artifact"
    );
}

#[test]
fn att2a_semantic_opcode_table_varies_by_seed() {
    use bytecode::opcode::Opcode;
    let e1 = bytecode::encoding::Encoding::from_seed(1);
    let e2 = bytecode::encoding::Encoding::from_seed(2);
    let diff = [
        Opcode::Move,
        Opcode::Add,
        Opcode::GetTable,
        Opcode::Call,
        Opcode::Return,
    ]
    .iter()
    .filter(|&&op| e1.concrete(op) != e2.concrete(op))
    .count();
    assert!(
        diff >= 3,
        "concrete opcode numbering varies by seed, got {diff}/5 differing"
    );
}

#[test]
fn att2a_artifact_only_decode_requires_env_model() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"ENVSECRET\")",
        0x2A01,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("att2a_envmodel");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("ENVSECRET"),
        "wrong-env run must not decode the constant"
    );
}

#[test]
fn att2a_wrong_env_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"AT2PROG\")",
        0x2A02,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("att2a_wrongenv");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("AT2PROG"),
        "executor build fails closed on the CLI"
    );
}

#[test]
fn att2a_runtime_behavior_equivalence() {
    let Some((raw, virt)) = b1b_raw_eq_virt(B1A2_SRC, 0x2A03) else {
        return;
    };
    assert!(raw.contains("B1A2"), "raw runs");
    assert_eq!(raw, virt, "seed-derived ENV_NONCE preserves behavior");
}

#[test]
fn att2a_with_f1_constants() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local a = \"alpha\"\nlocal b = 1234\nlocal c = { x = \"nested\", y = 3.5 }\nprint(a, b, c.x, c.y)", 0x2A04) else { return };
    assert_eq!(
        raw, virt,
        "F1 constants decrypt under seed-derived ENV_NONCE"
    );
}

#[test]
fn att2a_with_encfunc_external() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local f = BASIL_ENCFUNC(function(u) return u + 9 end, \"{ENCFUNC_KEY}\", rk)\nprint(f(41))");
    let src = enc_external(&body);
    let raw = run_injected(&luau, "att2a_ef_raw.luau", &src, Some(ENCFUNC_KEY));
    let obf = pipeline::virtualize_with(&src, 0x2A05, true, true, true, true, true, false, false)
        .unwrap();
    let virt = run_injected(&luau, "att2a_ef_virt.luau", &obf, Some(ENCFUNC_KEY));
    assert!(raw.stdout.contains("50"), "encfunc raw runs");
    assert_eq!(
        raw.stdout, virt.stdout,
        "ENCFUNC external key works under seed-derived ENV_NONCE"
    );
}

#[test]
fn att2a_with_at2_executor_profile() {
    let Some(luau) = find_luau() else { return };
    let exec = prof_build(
        "print(\"AT2PROG\")",
        0x2A08,
        pipeline::TargetProfile::Executor,
        false,
    );
    let p = unique_tmp("att2a_at2");
    std::fs::write(&p, &exec).unwrap();
    assert!(
        !run_luau(&luau, &p).stdout.contains("AT2PROG"),
        "executor profile fails closed on the CLI"
    );
}

#[test]
fn att2a_no_raw_marker_regressions() {
    let o = pipeline::virtualize_with(
        "local s = \"x\" print(s)",
        0x2A09,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    for m in [
        ",@@&@&&&@@@&&&",
        "github.com/escaliba/basilisk",
        "loadstring",
        "2654435769",
        "2987342059-332906290",
        "normconstv01",
    ] {
        assert!(!o.contains(m), "no {m} in the artifact");
    }
    assert!(
        !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio literal"
    );
}

#[test]
fn att2a_size_budget() {
    let o = pipeline::virtualize_with(
        "print(1 + 2)",
        0x2A0A,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
    )
    .unwrap();
    assert!(
        o.len() < 30_000,
        "no size growth from seed-derived ENV_NONCE (got {} bytes)",
        o.len()
    );
}

#[test]
fn att2a_perf_budget() {
    assert_eq!(
        pipeline::virtualize_with(B1A2_SRC, 0x2A0B, true, true, true, true, true, false, false)
            .unwrap(),
        pipeline::virtualize_with(B1A2_SRC, 0x2A0B, true, true, true, true, true, false, false)
            .unwrap(),
        "same seed deterministic (seed-derived ENV_NONCE stable per seed)"
    );
}

#[test]
fn no_virtualize_ships_body_as_native_not_virtualized() {
    let src = "local nat = BASIL_NO_VIRTUALIZE(function(x) return \"NVMARK_NATIVE_7f3\" .. tostring(x) end)\nlocal vrt = \"NVMARK_VIRT_7f3\"\nprint(nat(2), vrt)";
    let obf = pipeline::virtualize_with(src, 0x4E0F17, true, true, true, true, true, false, false)
        .unwrap();
    assert!(
        obf.contains("NVMARK_NATIVE_7f3"),
        "NO_VIRTUALIZE body must ship as native plaintext Luau"
    );
    assert!(
        !obf.contains("NVMARK_VIRT_7f3"),
        "a virtualized string must not appear plaintext in the artifact"
    );
    let Some(luau) = find_luau() else { return };
    let p = unique_tmp("no_virt_e2e");
    std::fs::write(&p, &obf).unwrap();
    assert_eq!(
        run_luau(&luau, &p).stdout.trim(),
        "NVMARK_NATIVE_7f32\tNVMARK_VIRT_7f3",
        "native + virtualized parts run correctly"
    );
}

fn t_esk(seed: u64, dom: u32) -> [u32; 8] {
    bytecode::crypt::struct_key(
        &bytecode::crypt::env_fingerprint_digest(seed, pipeline::TargetProfile::CliTest),
        dom,
    )
}

fn att2c_esk(seed: u64, profile: pipeline::TargetProfile) -> ([u32; 8], [u32; 8], [u32; 8]) {
    let d = bytecode::crypt::env_fingerprint_digest(seed, profile);
    let (sj, qk, ej) = bytecode::crypt::struct_domains(seed);
    (
        bytecode::crypt::struct_key(&d, sj),
        bytecode::crypt::struct_key(&d, qk),
        bytecode::crypt::struct_key(&d, ej),
    )
}

#[test]
fn att2b_structural_masks_require_env_fold() {
    let seed = 305419896u64;
    let (mk, mp) = (
        bytecode::crypt::opmask_key(seed),
        bytecode::crypt::mapkey(seed),
    );
    let (sjd, qkd, ejd) = bytecode::crypt::struct_domains(seed);
    let d1 = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let d2 = [8u32, 7, 6, 5, 4, 3, 2, 1];
    let sk = |d: &[u32; 8], dom| bytecode::crypt::struct_key(d, dom);
    assert_ne!(
        bytecode::crypt::proto_opmap(mp, &sk(&d1, qkd), 0),
        bytecode::crypt::proto_opmap(mp, &sk(&d2, qkd), 0),
        "QK requires env struct-key"
    );
    assert!(
        (1u32..=32).any(|pc| bytecode::crypt::opmask_byte(mk, &sk(&d1, sjd), 0, pc)
            != bytecode::crypt::opmask_byte(mk, &sk(&d2, sjd), 0, pc)),
        "Sj requires env struct-key"
    );
    assert!(
        (0u32..8).any(
            |j| bytecode::crypt::opmask2_byte(mk, &sk(&d1, ejd), 0, 1, 0, j)
                != bytecode::crypt::opmask2_byte(mk, &sk(&d2, ejd), 0, 1, 0, j)
        ),
        "eJ requires env struct-key"
    );
    let Some((raw, virt)) =
        b1b_raw_eq_virt("local a = \"x\" local b = 7 print(a, b, a .. b)", 0x2B01)
    else {
        return;
    };
    assert_eq!(raw, virt, "correct env preserves raw==virt");
}

#[test]
fn att2b_artifact_only_decode_without_env_fails() {
    let seed = 305419896u64;
    let (mk, mp) = (
        bytecode::crypt::opmask_key(seed),
        bytecode::crypt::mapkey(seed),
    );
    let (sjd, qkd, ejd) = bytecode::crypt::struct_domains(seed);
    let (sj, qk, ej) = att2c_esk(seed, pipeline::TargetProfile::Executor);
    let z = [0u32; 8];
    let (zsj, zqk, zej) = (
        bytecode::crypt::struct_key(&z, sjd),
        bytecode::crypt::struct_key(&z, qkd),
        bytecode::crypt::struct_key(&z, ejd),
    );
    assert_ne!(
        bytecode::crypt::proto_opmap(mp, &zqk, 0),
        bytecode::crypt::proto_opmap(mp, &qk, 0),
        "baked keys without env struct-key → wrong QK"
    );
    assert!(
        (1u32..=32).any(|pc| bytecode::crypt::opmask_byte(mk, &zsj, 0, pc)
            != bytecode::crypt::opmask_byte(mk, &sj, 0, pc)),
        "baked keys without env struct-key → wrong Sj"
    );
    assert!(
        (0u32..8).any(|j| bytecode::crypt::opmask2_byte(mk, &zej, 0, 1, 0, j)
            != bytecode::crypt::opmask2_byte(mk, &ej, 0, 1, 0, j)),
        "baked keys without env struct-key → wrong eJ"
    );
}

#[test]
fn att2b_correct_env_runtime_equivalence() {
    let Some((raw, virt)) = b1b_raw_eq_virt("local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end\nprint(fib(12), \"str\", 3.5)", 0x2B02) else { return };
    assert!(raw.contains("144"), "raw runs");
    assert_eq!(raw, virt, "intended profile: behavior identical");
}

#[test]
fn att2b_wrong_env_fails_closed_no_hang() {
    let Some(luau) = find_luau() else { return };
    for seed in [0x2B04u64, 0x2B05, 0x2B06] {
        let exec = prof_build(
            "print(\"ATT2B_SECRET\")",
            seed,
            pipeline::TargetProfile::Executor,
            false,
        );
        let p = unique_tmp("att2b_fc");
        std::fs::write(&p, &exec).unwrap();
        let out = run_luau(&luau, &p).stdout;
        assert!(
            !out.contains("ATT2B_SECRET"),
            "wrong-env must not leak payload (seed {seed})"
        );
        assert!(
            !out.contains(",@@&@&&&@@@&&&"),
            "fail-closed, no art reveal (seed {seed})"
        );
    }
}

#[test]
fn att2b_env_nonce_differs_by_seed() {
    assert_ne!(
        bytecode::crypt::env_nonce(1),
        bytecode::crypt::env_nonce(2),
        "ENV_NONCE material differs by seed"
    );
    assert_ne!(
        bytecode::encoder::payload_salt(1),
        bytecode::encoder::payload_salt(2),
        "payload salt differs by seed"
    );
    let old = [0x6e6f_726du32, 0x636f_6e73, 0x7476_3031];
    for s in [1u64, 2, 305419896] {
        assert_ne!(
            bytecode::crypt::env_nonce(s),
            old,
            "no fixed normconstv01 (seed {s})"
        );
    }
}

#[test]
fn att2b_no_marker_regressions() {
    let o = pipeline::virtualize_with(
        "local s = \"x\" print(s)",
        0x2B08,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    for m in [
        ",@@&@&&&@@@&&&",
        "github.com/escaliba/basilisk",
        "loadstring",
        "normconstv01",
        "2654435769",
        "2987342059-332906290",
        "EXPECTED_EFE",
        "EXPECTED_ENVDIG",
    ] {
        assert!(!o.contains(m), "no {m} in the artifact");
    }
    assert!(
        !o.to_lowercase().contains("9e3779b9"),
        "no golden-ratio literal"
    );
}

#[test]
fn att2b_no_expected_efe_leak() {
    for seed in [0x2B0Au64, 0x2B0B] {
        let readable = pipeline::virtualize_with(
            "print(1)", seed, true, false, false, false, false, false, false,
        )
        .unwrap();
        let shipped = pipeline::virtualize_with(
            "print(1)", seed, true, false, false, false, true, false, false,
        )
        .unwrap();
        for m in ["EXPECTED_EFE", "EXPECTED_ENVDIG", "EXPECTED_FOLD"] {
            assert!(!readable.contains(m), "no baked {m} (readable)");
            assert!(!shipped.contains(m), "no baked {m} (shipped)");
        }
    }
}

fn att2b_zero_const_build(seed: u64, profile: pipeline::TargetProfile, _wm: bool) -> String {
    pipeline::virtualize_full_prof(
        "local a = nil\nreturn a",
        seed,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
        false,
        pipeline::SensitiveOpts::default(),
        profile,
        false,
        false,
    )
    .unwrap()
}

#[test]
fn att2b_no_user_constants_silent_fail_closed() {
    let Some(luau) = find_luau() else { return };
    let p = unique_tmp("att2b_zc_off");
    std::fs::write(
        &p,
        &att2b_zero_const_build(0x2B21, pipeline::TargetProfile::Executor, false),
    )
    .unwrap();
    let out = run_luau(&luau, &p).stdout;
    assert!(
        !out.contains(",@@&@&&&@@@&&&"),
        "silent fail-closed, no reveal"
    );
    let cp = unique_tmp("att2b_zc_clean");
    std::fs::write(
        &cp,
        &att2b_zero_const_build(0x2B22, pipeline::TargetProfile::CliTest, false),
    )
    .unwrap();
    assert_eq!(
        run_luau(&luau, &cp).code,
        Some(0),
        "correct env: no-user-constant build still runs cleanly"
    );
}
#[test]
fn att2c_masks_change_on_any_envdig_lane() {
    let seed = 305419896u64;
    let (mk, mp) = (
        bytecode::crypt::opmask_key(seed),
        bytecode::crypt::mapkey(seed),
    );
    let (sjd, qkd, ejd) = bytecode::crypt::struct_domains(seed);
    let base = [
        0x1111_1111u32,
        0x2222_2222,
        0x3333_3333,
        0x4444_4444,
        0x5555_5555,
        0x6666_6666,
        0x7777_7777,
        0x8888_8888,
    ];
    let sk = |d: &[u32; 8], dom| bytecode::crypt::struct_key(d, dom);
    let (bqk, bsj, bej) = (sk(&base, qkd), sk(&base, sjd), sk(&base, ejd));
    for lane in 0..8usize {
        let mut d = base;
        d[lane] ^= 1;
        assert_ne!(
            bytecode::crypt::proto_opmap(mp, &sk(&d, qkd), 0),
            bytecode::crypt::proto_opmap(mp, &bqk, 0),
            "QK changes when ENVDIG lane {lane} changes"
        );
        assert!(
            (1u32..=64).any(|pc| bytecode::crypt::opmask_byte(mk, &sk(&d, sjd), 0, pc)
                != bytecode::crypt::opmask_byte(mk, &bsj, 0, pc)),
            "Sj changes when ENVDIG lane {lane} changes"
        );
        assert!(
            (1u32..=64).any(|pc| (0u32..3).any(|s| bytecode::crypt::opmask2_byte(
                mk,
                &sk(&d, ejd),
                0,
                pc,
                s,
                0
            ) != bytecode::crypt::opmask2_byte(
                mk, &bej, 0, pc, s, 0
            ))),
            "eJ changes when ENVDIG lane {lane} changes"
        );
    }
}

#[test]
fn att2c_no_single_u32_fold_controls_masks() {
    let seed = 305419896u64;
    let (mk, mp) = (
        bytecode::crypt::opmask_key(seed),
        bytecode::crypt::mapkey(seed),
    );
    let (sjd, qkd, ejd) = bytecode::crypt::struct_domains(seed);
    let old_fold = |d: &[u32; 8]| {
        let mut e = 0u32;
        for &w in d.iter() {
            e = e.rotate_left(7) ^ w;
        }
        e
    };
    let d1 = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let x = 0x1234_5678u32;
    let mut d2 = d1;
    d2[6] ^= x;
    d2[7] ^= x.rotate_left(7);
    assert_eq!(
        old_fold(&d1),
        old_fold(&d2),
        "constructed a 32-bit fold collision"
    );
    assert_ne!(d1, d2);
    let sk = |d: &[u32; 8], dom| bytecode::crypt::struct_key(d, dom);
    assert_ne!(
        bytecode::crypt::proto_opmap(mp, &sk(&d1, qkd), 0),
        bytecode::crypt::proto_opmap(mp, &sk(&d2, qkd), 0),
        "QK differs despite equal 32-bit fold"
    );
    assert!(
        (1u32..=64).any(|pc| bytecode::crypt::opmask_byte(mk, &sk(&d1, sjd), 0, pc)
            != bytecode::crypt::opmask_byte(mk, &sk(&d2, sjd), 0, pc)),
        "Sj differs despite equal 32-bit fold"
    );
    assert!(
        (1u32..=64).any(|pc| (0u32..3).any(|s| bytecode::crypt::opmask2_byte(
            mk,
            &sk(&d1, ejd),
            0,
            pc,
            s,
            0
        ) != bytecode::crypt::opmask2_byte(
            mk,
            &sk(&d2, ejd),
            0,
            pc,
            s,
            0
        ))),
        "eJ differs despite equal 32-bit fold"
    );
}

fn count_big_arith_splits(s: &str) -> usize {
    let b = s.as_bytes();
    let mut n = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'(' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j - start >= 5 && j < b.len() && (b[j] == b'+' || b[j] == b'-') {
                n += 1;
            }
        }
        i += 1;
    }
    n
}

#[test]
fn numeric_style_no_large_arithmetic_splits() {
    for seed in [305419896u64, 1, 42] {
        let art = pipeline::virtualize_with(
            "local a = 1 local b = 2 print(a + b, \"x\" .. a, 3.5)",
            seed,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
        )
        .unwrap();
        let splits = count_big_arith_splits(&art);
        assert!(splits <= 4, "large arithmetic-split constants should be largely gone (was ~30), found {splits} at seed {seed}");
        let low = art.to_lowercase();
        for m in [
            "2654435769",
            "9e3779b9",
            "811c9dc5",
            "1634760805",
            "normconstv01",
        ] {
            assert!(
                !low.contains(m),
                "forbidden stable marker {m} returned in artifact (seed {seed})"
            );
        }
    }
}

fn count_adjacent_str_pairs(s: &str) -> usize {
    let b = s.as_bytes();
    let read_str_decl = |from: usize| -> Option<usize> {
        if !s[from..].starts_with("local ") {
            return None;
        }
        let mut j = from + 6;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            j += 1;
        }
        if j >= b.len() || b[j] != b'=' || j + 1 >= b.len() || b[j + 1] != b'"' {
            return None;
        }
        let q0 = j + 2;
        let qe = s[q0..].find('"')?;
        if qe < 40 {
            return None;
        }
        Some(q0 + qe + 1)
    };
    let mut n = 0usize;
    let mut i = 0usize;
    while let Some(p) = s[i..].find("local ") {
        let at = i + p;
        if let Some(after) = read_str_decl(at) {
            if read_str_decl(after).is_some() {
                n += 1;
            }
        }
        i = at + 6;
    }
    n
}

#[test]
fn surface_hardening_numeric_slots_and_data_driven_ksite() {
    let vm = pipeline::virtualize_full(
        "local a = 1 local b = \"x\" local t = {10, 20, 30} print(a, b, t[2], a .. b)",
        0x51AA,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    assert!(
        vm.contains("inst[KOP]"),
        "instruction records use numeric slot KOP"
    );
    assert!(!vm.contains("inst.op"), "no semantic .op field");
    assert!(!vm.contains("inst.ops"), "no semantic .ops field");
    assert!(
        vm.contains("KRULE") && vm.contains("byte(KRULE"),
        "const-site scan is data-driven via KRULE"
    );
    let start = vm
        .find("local function ktoks")
        .expect("ktoks helper present");
    let end = start + vm[start..].find("return tok").unwrap_or(1500);
    assert!(
        !vm[start..end].contains("op == "),
        "const-site scan must not list opcode ids: {}",
        &vm[start..end]
    );
}

#[test]
fn surface_hardening_no_contiguous_alphabet_blob() {
    for wm in [false, true] {
        let art = pipeline::virtualize_full_prof(
            "print(1)",
            0x51AB,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
            false,
            pipeline::SensitiveOpts::default(),
            pipeline::TargetProfile::Executor,
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            count_adjacent_str_pairs(&art),
            0,
            "no contiguous alphabet+blob literal pair (wm={wm})"
        );
        let low = art.to_lowercase();
        for m in [
            "2654435769",
            "9e3779b9",
            "normconstv01",
            "github.com/escaliba/basilisk",
        ] {
            assert!(!low.contains(m), "no forbidden marker {m} (wm={wm})");
        }
    }
}

#[test]
fn sh2_no_payload_bootstrap_numeric_table() {
    for seed in [305419896u64, 7, 42] {
        let art = pipeline::virtualize_full(
            "local a = 1 print(a, \"x\")",
            seed,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            pipeline::SurfaceVolume::Off,
        )
        .unwrap();
        let b = art.as_bytes();
        let mut worst = 0usize;
        let mut i = 0usize;
        while i < b.len() {
            if b[i] == b'{' {
                let mut j = i + 1;
                let mut count = 0usize;
                loop {
                    let start = j;
                    while j < b.len() && (b[j] == b' ' || b[j] == b'\n' || b[j] == b'\t') {
                        j += 1;
                    }
                    let ds = j;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j == ds {
                        j = start;
                        break;
                    }
                    count += 1;
                    while j < b.len() && (b[j] == b' ' || b[j] == b'\n' || b[j] == b'\t') {
                        j += 1;
                    }
                    if j < b.len() && b[j] == b',' {
                        j += 1;
                    } else {
                        break;
                    }
                }
                worst = worst.max(count);
            }
            i += 1;
        }
        assert!(
            worst < 40,
            "no large numeric bootstrap table (seed {seed}): worst run {worst}"
        );
        assert!(
            art.contains("lshift("),
            "payload alphabet reconstructed via bit32 xorshift (seed {seed})"
        );
    }
}

#[test]
fn sh2_upvalue_records_use_numeric_slots() {
    let vm = pipeline::virtualize_full(
        "local function mk(x) return function(y) x = x + y return x end end\nlocal f = mk(10) print(f(1), f(2))",
        0x51C4, true, false, false, false, false, false, false, false, false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap();
    assert!(
        vm.contains("[KIS]") && vm.contains("[KOPEN]") && vm.contains("[KV]"),
        "upvalue/cell records use numeric slots"
    );
    for f in [".inStack", ".index", ".open", ".idx"] {
        assert!(!vm.contains(f), "no semantic upvalue field {f}");
    }
}
