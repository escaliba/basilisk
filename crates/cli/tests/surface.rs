use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
static N: AtomicU64 = AtomicU64::new(0);

fn tmp(ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_surface_{}_{}.{ext}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ))
}

fn find_luau() -> Option<String> {
    if let Ok(b) = std::env::var("LUAU_BIN") {
        return Some(b);
    }
    for c in ["luau", "/opt/homebrew/bin/luau", "/usr/local/bin/luau"] {
        if Command::new(c).arg("--help").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

fn catalog_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/meme_strings.toml")
}

fn try_build(
    src: &str,
    seed: u64,
    flags: &[&str],
    catalog: Option<&str>,
) -> Result<Vec<u8>, String> {
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
    match catalog {
        Some(p) => {
            cmd.env("BASIL_MEME_CATALOG", p);
        }
        None => {
            cmd.env("BASIL_MEME_CATALOG", catalog_path());
        }
    }
    let o = cmd.output().expect("spawn basilisk");
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).to_string());
    }
    Ok(std::fs::read(&out).unwrap())
}

fn build(src: &str, seed: u64, flags: &[&str]) -> Vec<u8> {
    try_build(src, seed, flags, None).unwrap_or_else(|e| panic!("build {flags:?} failed: {e}"))
}

fn run(luau: &str, artifact: &[u8]) -> String {
    let f = tmp("luau");
    let mut full = format!("BASILISK_RUNTIME_KEY = \"{KEY}\"\n").into_bytes();
    full.extend_from_slice(artifact);
    std::fs::write(&f, &full).unwrap();
    let o = Command::new(luau).arg(&f).output().expect("spawn luau");
    let _ = std::fs::remove_file(&f);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn large_src() -> (String, String) {
    let n = 2500i64;
    let mut sum = 0i64;
    let mut s = String::from("local t = {\n");
    for i in 0..n {
        let v = (i * 7 + 3) % 100003;
        sum += v;
        s.push_str(&v.to_string());
        s.push(',');
        if i % 16 == 15 {
            s.push('\n');
        }
    }
    s.push_str("\n}\nlocal s = 0\nfor i = 1, #t do s = s + t[i] end\nprint(\"R:\" .. s)\n");
    (s, format!("R:{sum}"))
}

fn region_audit(src: &str, seed: u64, flags: &[&str]) -> std::collections::HashMap<String, usize> {
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
    cmd.env("BASIL_MEME_AUDIT", "1");
    cmd.env("BASIL_MEME_CATALOG", catalog_path());
    let o = cmd.output().expect("spawn basilisk");
    assert!(
        o.status.success(),
        "audit build failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let mut m = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&o.stderr).lines() {
        if let Some(rest) = line.strip_prefix("MEME_REGION\t") {
            if let Some((region, _)) = rest.split_once('\t') {
                *m.entry(region.to_string()).or_insert(0) += 1;
            }
        }
    }
    m
}

#[test]
fn memes_span_at_least_six_structural_regions_under_25_percent() {
    let (src, _expect) = large_src();
    let combos: Vec<(u64, Vec<&str>)> = vec![
        (20261018, vec!["--surface-memes"]),
        (7, vec!["--basil-heavy", "large", "--surface-memes"]),
    ];
    for (seed, flags) in combos {
        let regions = region_audit(&src, seed, &flags);
        let total: usize = regions.values().sum();
        assert!(
            total >= 12,
            "seed {seed} {flags:?}: expected a woven plan, got {total} ({regions:?})"
        );
        assert!(
            regions.len() >= 6,
            "seed {seed} {flags:?}: memes must span >= 6 structural regions, got {} ({regions:?})",
            regions.len()
        );
        let max = *regions.values().max().unwrap();
        assert!(max * 4 <= total, "seed {seed} {flags:?}: no region may hold > 25% of occurrences ({regions:?} of {total})");
    }
}

#[test]
fn meme_region_placement_is_deterministic() {
    let (src, _e) = large_src();
    assert_eq!(
        region_audit(&src, 20261018, &["--surface-memes"]),
        region_audit(&src, 20261018, &["--surface-memes"])
    );
}

const SRC: &str = "local s = 0 for i = 1, 10 do s = s + i * i end print(\"R:\" .. s)";
const EXPECT: &str = "R:385";

#[test]
fn default_off_is_byte_identical() {
    let a = build(SRC, 123, &[]);
    let b = build(SRC, 123, &[]);
    assert_eq!(a, b, "no-flags build must be deterministic");
    let c = build(SRC, 123, &["--surface-theme", "none"]);
    assert_eq!(a, c, "explicit none must be byte-identical to default-off");
    let on = build(SRC, 123, &["--surface-theme", "ascii"]);
    assert_ne!(a, on, "a surface theme must change the artifact");
}

#[test]
fn composition_matrix_executes() {
    let Some(luau) = find_luau() else {
        return;
    };
    let combos: Vec<Vec<&str>> = vec![
        vec!["--surface-theme", "ascii"],
        vec!["--surface-memes"],
        vec!["--surface-theme", "ascii", "--surface-memes"],
    ];
    for combo in &combos {
        let art = build(SRC, 13, combo);
        assert!(
            run(&luau, &art).contains(EXPECT),
            "combo {combo:?} must execute correctly"
        );
    }
}

#[test]
fn memes_require_a_nonempty_catalog() {
    let missing = tmp("toml");
    let e = try_build(
        SRC,
        1,
        &["--surface-memes"],
        Some(missing.to_str().unwrap()),
    )
    .expect_err("missing catalog must fail the build");
    assert!(
        e.to_lowercase().contains("catalog") || e.to_lowercase().contains("meme"),
        "clear error: {e}"
    );

    let empty = tmp("toml");
    std::fs::write(&empty, "version = 1\nstrings = []\n").unwrap();
    let e2 = try_build(SRC, 1, &["--surface-memes"], Some(empty.to_str().unwrap()))
        .expect_err("empty catalog must fail");
    assert!(
        e2.to_lowercase().contains("empty") || e2.to_lowercase().contains("catalog"),
        "clear error: {e2}"
    );
}

#[test]
fn memes_appear_in_the_artifact() {
    let art = build(SRC, 3, &["--surface-memes"]);
    let text = String::from_utf8_lossy(&art);
    let catalog = std::fs::read_to_string(catalog_path()).unwrap();
    let cat = pipeline::surface::meme::parse(&catalog).unwrap();
    let any = cat.strings.iter().any(|s| text.contains(s));
    assert!(
        any,
        "at least one catalog meme must appear in a memes-enabled artifact"
    );
}

fn meme_payload_separators(text: &str, memes: &[&String]) -> usize {
    let mut n = 0;
    for m in memes {
        let needle = format!("#\"{m}\"");
        for (i, _) in text.match_indices(&needle) {
            let lo = i.saturating_sub(10);
            let hi = (i + needle.len() + 10).min(text.len());
            let win = &text[lo..hi];
            if win.contains("]==]") || win.contains("[==[") {
                n += 1;
            }
        }
    }
    n
}

fn payload_blobs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(a) = rest.find("[==[") {
        let after = &rest[a + 4..];
        if let Some(b) = after.find("]==]") {
            out.push(&after[..b]);
            rest = &after[b + 4..];
        } else {
            break;
        }
    }
    out
}

#[test]
fn memes_are_woven_as_expressions_without_payload_separators_and_run() {
    let luau = find_luau();
    let catalog = std::fs::read_to_string(catalog_path()).unwrap();
    let cat = pipeline::surface::meme::parse(&catalog).unwrap();
    let combos: Vec<(u64, Vec<&str>)> = vec![
        (20261012, vec!["--surface-memes"]),
        (7, vec!["--basil-heavy", "large", "--surface-memes"]),
        (42, vec!["--surface-theme", "ascii", "--surface-memes"]),
        (1337, vec!["--surface-memes"]),
    ];
    for (seed, flags) in combos {
        let selected =
            pipeline::surface::meme::select(&cat, seed, pipeline::surface::DEFAULT_MEME_COUNT);
        let distinct: std::collections::HashSet<&String> = selected.iter().collect();
        let distinctv: Vec<&String> = distinct.iter().copied().collect();

        let art = build(SRC, seed, &flags);
        let text = String::from_utf8_lossy(&art).to_string();

        let total: usize = distinct
            .iter()
            .map(|m| text.matches(&format!("#\"{m}\"")).count())
            .sum();
        assert!(total >= distinct.len(), "seed {seed} {flags:?}: every selected meme must appear as a live carrier (total {total})");
        for m in &distinct {
            assert!(
                text.contains(&format!("#\"{m}\"")),
                "seed {seed} {flags:?}: selected meme {m:?} must be present as a length carrier"
            );
        }

        let seps = meme_payload_separators(&text, &distinctv);
        assert_eq!(seps, 0, "seed {seed} {flags:?}: no meme may sit next to a payload long-bracket boundary ({seps})");

        if let Some(l) = &luau {
            assert!(
                run(l, &art).contains(EXPECT),
                "seed {seed} {flags:?}: woven-meme artifact must run correctly"
            );
        }
    }
}

#[test]
fn memes_do_not_change_payload_chunking_or_bytes() {
    for seed in [1u64, 7, 20261018] {
        let off = build(SRC, seed, &["--basil-heavy", "large"]);
        let on = build(SRC, seed, &["--basil-heavy", "large", "--surface-memes"]);
        let off_t = String::from_utf8_lossy(&off).to_string();
        let on_t = String::from_utf8_lossy(&on).to_string();
        assert_eq!(
            payload_blobs(&off_t),
            payload_blobs(&on_t),
            "seed {seed}: enabling memes must not change payload chunking or payload bytes"
        );
    }
}

#[test]
fn meme_carrier_expressions_preserve_value_under_luau() {
    let Some(luau) = find_luau() else {
        return;
    };
    use pipeline::surface::meme::wrap_expr;
    use pipeline::surface::rng::Rng;
    let memes = [
        "sentinel-canary-meme-high-iq-required",
        "it's a meme",
        "a\\b\"c",
        "\u{4e2d}\u{6587}meme",
    ];
    let inners: [i64; 8] = [0, 1, 8, 60, 255, 512, 1_000_000, 2_743_021_643];
    let mut checks: Vec<String> = Vec::new();
    for (mi, m) in memes.iter().enumerate() {
        let lit = pipeline::surface::meme::luau_str(m);
        for &k in &inners {
            for s in 0..6u64 {
                let mut rng = Rng::new(s ^ (mi as u64).wrapping_mul(0x9E3779B1) ^ (k as u64));
                let e = wrap_expr(&k.to_string(), &lit, m.len(), &mut rng);
                checks.push(format!("if ({e}) ~= {k} then bad = bad + 1 end"));
            }
        }
    }
    let snippet = format!(
        "local bad = 0\n{}\nprint(bad == 0 and \"WRAPOK\" or (\"BAD:\" .. bad))\n",
        checks.join("\n")
    );
    let f = tmp("luau");
    std::fs::write(&f, &snippet).unwrap();
    let o = Command::new(&luau).arg(&f).output().expect("luau");
    let _ = std::fs::remove_file(&f);
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        out.contains("WRAPOK"),
        "every meme carrier expression must evaluate to its original value under luau: {out}"
    );
}

#[test]
fn memes_are_materially_present_every_selected_meme_appears() {
    let catalog = std::fs::read_to_string(catalog_path()).unwrap();
    let cat = pipeline::surface::meme::parse(&catalog).unwrap();
    for seed in [1u64, 2, 7, 42, 1337] {
        let selected =
            pipeline::surface::meme::select(&cat, seed, pipeline::surface::DEFAULT_MEME_COUNT);
        let distinct_in_catalog = cat
            .strings
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(
            selected.len(),
            distinct_in_catalog.min(pipeline::surface::DEFAULT_MEME_COUNT)
        );
        let art = build(SRC, seed, &["--surface-memes"]);
        let text = String::from_utf8_lossy(&art);
        for m in &selected {
            let marker = format!("#\"{m}\"");
            assert!(
                text.contains(&marker),
                "seed {seed}: selected meme {m:?} must appear as a live length carrier"
            );
        }
        let sites: usize = selected
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .iter()
            .map(|m| text.matches(&format!("#\"{m}\"")).count())
            .sum();
        assert!(
            sites >= 1,
            "seed {seed}: expected live meme sites, saw {sites}"
        );
    }
}

#[test]
fn meme_text_change_same_length_does_not_perturb_vm_structure() {
    let cat_a = tmp("toml");
    let cat_b = tmp("toml");
    std::fs::write(&cat_a, "version = 1\nstrings = [\"AAAAAAAAAA\"]\n").unwrap();
    std::fs::write(&cat_b, "version = 1\nstrings = [\"BBBBBBBBBB\"]\n").unwrap();
    let art_a = try_build(
        SRC,
        20261012,
        &["--surface-memes"],
        Some(cat_a.to_str().unwrap()),
    )
    .unwrap();
    let art_b = try_build(
        SRC,
        20261012,
        &["--surface-memes"],
        Some(cat_b.to_str().unwrap()),
    )
    .unwrap();
    assert_eq!(
        art_a.len(),
        art_b.len(),
        "changing a meme's text (same byte length) must not change artifact size/structure"
    );
    assert_ne!(art_a, art_b, "the meme bytes themselves must differ");
    if let Some(l) = find_luau() {
        assert!(
            run(&l, &art_a).contains(EXPECT),
            "single-meme artifact A must run"
        );
        assert!(
            run(&l, &art_b).contains(EXPECT),
            "single-meme artifact B must run"
        );
    }
}

fn run_cli(flags: &[&str], catalog: Option<&str>) -> (bool, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg("--no-interactive").args(flags);
    cmd.env(
        "BASIL_MEME_CATALOG",
        catalog.map(PathBuf::from).unwrap_or_else(catalog_path),
    );
    let o = cmd.output().expect("spawn basilisk");
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o.status.success(), out)
}

#[test]
fn surface_meme_audit_reports_catalog_stats() {
    let (ok, out) = run_cli(&["--surface-meme-audit"], None);
    assert!(ok, "audit must succeed: {out}");
    for tok in [
        "catalog audit",
        "entries:",
        "unique entries",
        "median (bytes)",
        "total catalog bytes",
    ] {
        assert!(out.contains(tok), "audit output missing {tok:?}: {out}");
    }
}

#[test]
fn surface_meme_preview_uses_the_real_planner() {
    let (ok, out) = run_cli(
        &[
            "--surface-memes",
            "--surface-meme-preview",
            "--seed",
            "20261012",
        ],
        None,
    );
    assert!(ok, "preview must succeed: {out}");
    for tok in [
        "surface meme preview",
        "seed: 20261012",
        "selected distinct:",
        "planned occurrences:",
    ] {
        assert!(out.contains(tok), "preview output missing {tok:?}: {out}");
    }
    let catalog = std::fs::read_to_string(catalog_path()).unwrap();
    let cat = pipeline::surface::meme::parse(&catalog).unwrap();
    let plan = pipeline::surface::SurfaceConfig {
        memes: true,
        ..Default::default()
    }
    .resolve(20261012, Some(&cat))
    .unwrap();
    let pv = pipeline::surface::meme::preview(&plan);
    assert!(
        out.contains(&format!("planned occurrences: {}", pv.total)),
        "preview total must match the planner ({}): {out}",
        pv.total
    );
    let needs_memes = run_cli(&["--surface-meme-preview"], None);
    assert!(
        !needs_memes.0,
        "preview without --surface-memes must fail: {}",
        needs_memes.1
    );
}

fn plan_for_pool(pool: &[String], seed: u64) -> pipeline::surface::SurfacePlan {
    let cat = pipeline::surface::meme::from_strings(pool).unwrap();
    pipeline::surface::SurfaceConfig {
        memes: true,
        meme_strings: Some(pool.to_vec()),
        ..Default::default()
    }
    .resolve(seed, Some(&cat))
    .unwrap()
}

#[test]
fn explicit_pool_is_the_only_selection_source() {
    let pool: Vec<String> = (0..6).map(|i| format!("reqmeme{i:02}")).collect();
    let plan = plan_for_pool(&pool, 20261012);
    assert_eq!(
        plan.memes.len(),
        6,
        "catalog >= 6 selects exactly 6 distinct"
    );
    for m in &plan.memes {
        assert!(
            pool.contains(m),
            "selected meme {m:?} must come only from the request pool"
        );
    }
}

#[test]
fn tiny_explicit_pool_uses_all_three_and_repeats() {
    let pool: Vec<String> = vec!["tinyA".into(), "tinyB".into(), "tinyC".into()];
    let plan = plan_for_pool(&pool, 20261012);
    let mut distinct: Vec<&String> = plan.memes.iter().collect();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 3, "tiny catalog uses all three");
    let pv = pipeline::surface::meme::preview(&plan);
    assert!(
        (24..=30).contains(&pv.total),
        "balanced repeated occurrences 24-30, got {}",
        pv.total
    );
}

#[test]
fn duplicate_pool_entries_dedupe_first_seen() {
    let cat = pipeline::surface::meme::from_strings(&["dup".into(), "dup".into(), "keep".into()])
        .unwrap();
    assert_eq!(cat.strings, vec!["dup", "keep"]);
}

#[test]
fn same_seed_same_pool_is_deterministic() {
    let pool: Vec<String> = (0..6).map(|i| format!("det{i}")).collect();
    assert_eq!(
        plan_for_pool(&pool, 777).memes,
        plan_for_pool(&pool, 777).memes
    );
}

#[test]
fn explicit_catalog_flag_overrides_env_catalog() {
    let flag_cat = tmp("toml");
    let env_cat = tmp("toml");
    std::fs::write(&flag_cat, "version = 1\nstrings = [\"FLAGPOOLTOKEN\"]\n").unwrap();
    std::fs::write(&env_cat, "version = 1\nstrings = [\"ENVPOOLTOKEN\"]\n").unwrap();
    let art = try_build(
        SRC,
        20261012,
        &[
            "--surface-memes",
            "--surface-meme-catalog",
            flag_cat.to_str().unwrap(),
        ],
        Some(env_cat.to_str().unwrap()),
    )
    .unwrap();
    let text = String::from_utf8_lossy(&art);
    assert!(
        text.contains("FLAGPOOLTOKEN"),
        "explicit catalog flag pool must be used"
    );
    assert!(
        !text.contains("ENVPOOLTOKEN"),
        "BASIL_MEME_CATALOG must not override the flag"
    );
}

#[test]
fn explicit_pool_same_length_change_does_not_perturb_structure() {
    let cat_a = tmp("toml");
    let cat_b = tmp("toml");
    std::fs::write(&cat_a, "version = 1\nstrings = [\"CCCCCCCCCC\"]\n").unwrap();
    std::fs::write(&cat_b, "version = 1\nstrings = [\"DDDDDDDDDD\"]\n").unwrap();
    let a = try_build(
        SRC,
        20261012,
        &[
            "--surface-memes",
            "--surface-meme-catalog",
            cat_a.to_str().unwrap(),
        ],
        None,
    )
    .unwrap();
    let b = try_build(
        SRC,
        20261012,
        &[
            "--surface-memes",
            "--surface-meme-catalog",
            cat_b.to_str().unwrap(),
        ],
        None,
    )
    .unwrap();
    assert_eq!(
        a.len(),
        b.len(),
        "same-length meme change must not alter structure"
    );
    assert_ne!(a, b, "the meme bytes must differ");
}

#[test]
fn catalog_flag_without_memes_is_rejected() {
    let cat = tmp("toml");
    std::fs::write(&cat, "version = 1\nstrings = [\"x\"]\n").unwrap();
    let r = try_build(
        SRC,
        1,
        &["--surface-meme-catalog", cat.to_str().unwrap()],
        None,
    );
    assert!(
        r.is_err(),
        "catalog flag without --surface-memes must be rejected"
    );
}

#[test]
fn memes_on_with_missing_default_catalog_fails_closed() {
    let r = try_build(
        SRC,
        1,
        &["--surface-memes"],
        Some("/no/such/meme_catalog.toml"),
    );
    assert!(
        r.is_err(),
        "memes-on with a missing default catalog must fail closed, not silently memes-off"
    );
}
