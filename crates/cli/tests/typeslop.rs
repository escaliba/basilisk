use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);

const SRC: &str = "local t = {}\nfor i = 1, 24 do t[i] = i * 3 end\nlocal s = 0\nfor _, v in ipairs(t) do s = s + v end\nprint(\"TS\", s)\n";

const CANARY: &[&str] = &[
    "sentinel-canary-meme-high-iq-required",
    "sentinel-canary-meme-beyond-basilisk",
    "sentinel-canary-meme-stop-doing-reversing",
    "sentinel-canary-meme-he-does-not-afraid",
    "sentinel-canary-meme-used-the-stones",
    "sentinel-canary-meme-why-are-we-still-here",
];

fn tmp(ext: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "basil_ts_{}_{}_{}.{ext}",
        std::process::id(),
        nanos,
        n
    ))
}

fn fullmoon_parses(artifact: String) -> bool {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || full_moon::parse(&artifact).is_ok())
        .unwrap()
        .join()
        .unwrap()
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

fn catalog_file() -> PathBuf {
    let p = tmp("toml");
    let mut s = String::from("version = 1\nstrings = [\n");
    for m in CANARY {
        s.push_str(&format!("  \"{m}\",\n"));
    }
    s.push_str("]\n");
    std::fs::write(&p, s).unwrap();
    p
}

fn build(seed: u64, flags: &[&str], audit: &[(&str, &str)]) -> (String, String) {
    let inp = tmp("luau");
    let out = tmp("luau");
    std::fs::write(&inp, SRC).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--seed")
        .arg(seed.to_string());
    cmd.args(flags).env("BASIL_DIRECT_WRITES", "1");
    for (k, v) in audit {
        cmd.env(k, v);
    }
    let o = cmd.output().expect("spawn basilisk");
    let stderr = String::from_utf8_lossy(&o.stderr).to_string();
    let _ = std::fs::remove_file(&inp);
    if !o.status.success() {
        let _ = std::fs::remove_file(&out);
        return (format!("BUILD_ERR {stderr}"), stderr);
    }
    let art = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_file(&out);
    (art, stderr)
}

fn run(luau: &str, artifact: &str) -> String {
    let f = tmp("luau");
    std::fs::write(&f, artifact).unwrap();
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

fn type_regions(stderr: &str) -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("TYPE_REGION\t") {
            if let Some((region, _alias)) = rest.split_once('\t') {
                *m.entry(region.to_string()).or_insert(0) += 1;
            }
        }
    }
    m
}

fn meme_log(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| l.starts_with("MEME_REGION\t"))
        .map(|l| l.to_string())
        .collect()
}

#[test]
fn off_is_deterministic_and_on_changes_the_artifact() {
    let a = build(7, &[], &[]).0;
    let b = build(7, &[], &[]).0;
    assert!(!a.starts_with("BUILD_ERR"), "{a}");
    assert_eq!(a, b, "types-off must be deterministic");
    let on = build(7, &["--surface-types"], &[]).0;
    assert!(!on.starts_with("BUILD_ERR"), "{on}");
    assert_ne!(a, on, "enabling types must change the artifact");
}

#[test]
fn on_produces_type_syntax_that_runs() {
    let Some(luau) = find_luau() else { return };
    let (art, _) = build(7, &["--surface-types"], &[]);
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert!(
        art.contains("type _Tf"),
        "artifact must contain generated type aliases"
    );
    assert_eq!(run(&luau, &art), "TS\t900");
}

#[test]
fn types_span_at_least_six_regions_under_budget() {
    let (_art, stderr) = build(7, &["--surface-types"], &[("BASIL_TYPE_AUDIT", "1")]);
    let regions = type_regions(&stderr);
    assert!(
        regions.len() >= 6,
        "expected >=6 regions, got {}: {regions:?}",
        regions.len()
    );
    let total: usize = regions.values().sum();
    assert!(
        total <= pipeline::surface::types::MAX_ALIASES,
        "alias cap: {total}"
    );
    let max = *regions.values().max().unwrap();
    assert!(
        max <= pipeline::surface::types::PER_REGION_CAP,
        "per-region cap: {max}"
    );
}

#[test]
fn same_seed_deterministic_different_seed_differs() {
    let a = build(7, &["--surface-types"], &[]).0;
    let b = build(7, &["--surface-types"], &[]).0;
    let c = build(8, &["--surface-types"], &[]).0;
    assert_eq!(a, b, "same seed = identical type structure");
    assert_ne!(a, c, "different seed = different type structure");
}

#[test]
fn output_parses_with_pinned_full_moon() {
    let (art, _) = build(7, &["--surface-types"], &[]);
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert!(
        fullmoon_parses(art.clone()),
        "pinned full_moon 2.2.0 must accept the typed artifact"
    );
}

#[test]
fn types_do_not_change_meme_selection() {
    let cat = catalog_file();
    let cat = cat.to_str().unwrap();
    let without = build(
        7,
        &["--surface-memes", "--surface-meme-catalog", cat],
        &[("BASIL_MEME_AUDIT", "1")],
    )
    .1;
    let with = build(
        7,
        &[
            "--surface-memes",
            "--surface-meme-catalog",
            cat,
            "--surface-types",
        ],
        &[("BASIL_MEME_AUDIT", "1")],
    )
    .1;
    assert!(
        !meme_log(&without).is_empty(),
        "meme audit should emit placements"
    );
    assert_eq!(
        meme_log(&without),
        meme_log(&with),
        "enabling types must not perturb meme placement"
    );
}

#[test]
fn memes_do_not_change_type_structure() {
    let cat = catalog_file();
    let cat = cat.to_str().unwrap();
    let without = build(7, &["--surface-types"], &[("BASIL_TYPE_AUDIT", "1")]).1;
    let with = build(
        7,
        &[
            "--surface-types",
            "--surface-memes",
            "--surface-meme-catalog",
            cat,
        ],
        &[("BASIL_TYPE_AUDIT", "1")],
    )
    .1;
    let log = |s: &str| {
        s.lines()
            .filter(|l| l.starts_with("TYPE_REGION\t"))
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
    };
    assert!(!log(&without).is_empty());
    assert_eq!(
        log(&without),
        log(&with),
        "enabling memes must not perturb type structure"
    );
}

#[test]
fn full_surface_composition_builds_and_runs() {
    let Some(luau) = find_luau() else { return };
    let cat = catalog_file();
    let cat = cat.to_str().unwrap();
    let (art, _) = build(
        20261018,
        &[
            "--surface-types",
            "--surface-memes",
            "--surface-meme-catalog",
            cat,
            "--surface-theme",
            "ascii",
        ],
        &[],
    );
    assert!(!art.starts_with("BUILD_ERR"), "{art}");
    assert!(
        art.contains("type _Tf"),
        "types present under full composition"
    );
    assert_eq!(run(&luau, &art), "TS\t900");
}
