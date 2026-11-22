use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    std::process::Command::new("luau")
        .arg("--help")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn run_luau(bin: &str, path: &std::path::Path) -> String {
    let out = std::process::Command::new(bin)
        .arg(path)
        .output()
        .expect("spawn luau");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn cfg(seed: u64, d1: bool) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: false,
        junk: false,
        fuse: false,
        minify: false,
        compress: false,
        anti_envlog: false,
        hard_dispatch: false,
        surface: false,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile: TargetProfile::CliTest,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: false,
        strip_source_names: false,
        poly_stream: PolyStream::Off,
        optimization: 0,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: Default::default(),
        hot_callback_policy: HotCallbackPolicy::Report,
        ablate_fragment: false,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
        shell_family: None,
        notices: pipeline::NoticeConfig::default(),
        stateful_recovery: d1,
        stateful_framing: false,
        property_key_rename: pipeline::PropKeyMode::Off,
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let input = tmp("d1_in");
    let output = tmp("d1_out");
    std::fs::write(&input, src).unwrap();
    let (i, o) = (input.clone(), output.clone());
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || pipeline::run(&i, &o, &cfg).unwrap())
        .unwrap()
        .join()
        .unwrap();
    std::fs::read_to_string(&output).unwrap()
}

const SRC: &str = r#"
local function fib(n)
	if n < 2 then return n end
	return fib(n - 1) + fib(n - 2)
end
local function classify(x)
	local tag
	if x > 0 then tag = "pos" else tag = "nonpos" end
	return tag
end
local sum = 0
for i = 1, 5 do sum = sum + i end
local function mk(base) return function(y) return base + y end end
local add10 = mk(10)
local shared = "SHARED"
local function usesShared(b)
	if b then return shared .. "-A" else return shared .. "-B" end
end
print("D1 " .. tostring(fib(6)) .. " " .. classify(-3) .. " " .. classify(7) .. " " .. tostring(sum) .. " " .. tostring(add10(5)) .. " " .. usesShared(true) .. " " .. usesShared(false))
"#;

const KNOWN_DIVERGENCES: &[&str] = &["setfenv.luau"];

const D1_EP: &str = "((i <= (kc[-5] or 0)) and kc[-4] or (bxor(kc[-2] or 0, kc[-1] or 0)))";
const D1_STEP: &str = "kc[-4] = bxor(fmix(kc[-4]), a %";

#[test]
fn d1_negatives_fail_closed() {
    let Some(luau) = find_luau() else {
        return;
    };
    let reference = "D1 8 nonpos pos 15 15 SHARED-A SHARED-B";
    let art = build(SRC, cfg(0x51_a7e, true));
    assert!(art.contains(D1_EP), "D1 ep selector present in artifact");
    assert!(art.contains(D1_STEP), "D1 bstate-step handler present");

    let ce_only = art.replace(D1_EP, "(bxor(kc[-2] or 0, kc[-1] or 0))");
    let p = tmp("d1_neg_ce");
    std::fs::write(&p, &ce_only).unwrap();
    let got = run_luau(&luau, &p);
    assert_ne!(
        got, reference,
        "opening D1 constants with static CE state must fail (got correct output)"
    );

    let no_step = art.replace(D1_STEP, "kc[-4] = kc[-4]; local _ = (a %");
    let p2 = tmp("d1_neg_step");
    std::fs::write(&p2, &no_step).unwrap();
    let got2 = run_luau(&luau, &p2);
    assert_ne!(
        got2, reference,
        "skipping the bstate recurrence must fail (got correct output)"
    );
}

#[test]
fn d1_on_whole_corpus_matches_raw() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping");
        return;
    };
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "luau").unwrap_or(false))
        .filter(|p| !KNOWN_DIVERGENCES.contains(&p.file_name().unwrap().to_str().unwrap()))
        .collect();
    files.sort();
    assert!(files.len() > 20, "corpus present: {}", files.len());
    let mut fails = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let name = f.file_name().unwrap().to_str().unwrap().to_string();
        let raw = run_luau(&luau, f);
        let art = build(&src, cfg(0xD1_C0, true));
        let ap = tmp("d1_corpus");
        std::fs::write(&ap, &art).unwrap();
        let got = run_luau(&luau, &ap);
        if got != raw {
            fails.push(format!("{name}: raw={raw:?} d1={got:?}"));
        }
    }
    assert!(
        fails.is_empty(),
        "D1-ON corpus divergences ({}/{}):\n{}",
        fails.len(),
        files.len(),
        fails.join("\n")
    );
}

#[test]
fn d1_on_artifact_executes_correctly() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping");
        return;
    };
    let raw = tmp("d1_raw");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    assert!(
        reference.contains("D1 8 nonpos pos 15 15 SHARED-A SHARED-B"),
        "raw reference: {reference}"
    );

    let art = build(SRC, cfg(0x51_a7e, true));
    let art_path = tmp("d1_art");
    std::fs::write(&art_path, &art).unwrap();
    let got = run_luau(&luau, &art_path);
    assert_eq!(
        got, reference,
        "D1-ON artifact output must equal raw source output"
    );
}
