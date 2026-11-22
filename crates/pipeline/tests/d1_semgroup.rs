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

fn cfg(seed: u64, d1: bool, semgroup: bool) -> Config {
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
        semgroup,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let input = tmp("sg_in");
    let output = tmp("sg_out");
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

const D1_EP: &str = "((i <= (kc[-5] or 0)) and kc[-4] or (bxor(kc[-2] or 0, kc[-1] or 0)))";
const D1_STEP: &str = "kc[-4] = bxor(fmix(kc[-4]), a %";

const KNOWN_DIVERGENCES: &[&str] = &["setfenv.luau"];

const MULTICONST_SRC: &str = r#"
local function f(n)
	local a = n * 2 + 3 - 1
	local b = n * 2 + 3 - 1
	local s = "x" .. tostring(a) .. "y" .. tostring(b) .. "z"
	local c = n + 100 + 100
	local m = math.floor(n / 2.0)
	if n > 0 then
		return s .. "-pos-" .. tostring(c) .. "-" .. tostring(m)
	else
		return s .. "-neg-" .. tostring(c) .. "-" .. tostring(m)
	end
end
print(f(5))
print(f(-4))
print(f(0))
"#;

const SHARED_SRC: &str = r#"
local shared = "SHARED"
local function usesShared(b)
	local k = 7 * 6 + 1
	if b then return shared .. "-A-" .. tostring(k) else return shared .. "-B-" .. tostring(k) end
end
local function classify(x)
	local t = x * x + x - 2
	if x > 0 then return "pos:" .. tostring(t) else return "nonpos:" .. tostring(t) end
end
print(usesShared(true) .. " " .. usesShared(false) .. " " .. classify(4) .. " " .. classify(-3))
"#;

#[test]
fn sg_d1_artifact_executes_correctly() {
    let Some(luau) = find_luau() else {
        return;
    };
    let raw = tmp("sg_raw");
    std::fs::write(&raw, MULTICONST_SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    assert!(!reference.is_empty(), "raw produced output");

    let art = build(MULTICONST_SRC, cfg(0x5613, true, true));
    let ap = tmp("sg_art");
    std::fs::write(&ap, &art).unwrap();
    assert_eq!(
        run_luau(&luau, &ap),
        reference,
        "D1+semgroup multi-const artifact must equal raw"
    );
}

#[test]
fn sg_d1_is_actually_fusing_and_stays_correct() {
    let Some(luau) = find_luau() else {
        return;
    };
    let raw = tmp("sg_raw2");
    std::fs::write(&raw, MULTICONST_SRC).unwrap();
    let reference = run_luau(&luau, &raw);

    let plain_d1 = build(MULTICONST_SRC, cfg(0x5613, true, false));
    let sg_d1 = build(MULTICONST_SRC, cfg(0x5613, true, true));
    assert_ne!(
        plain_d1, sg_d1,
        "semgroup must change the D1 artifact (fusion active)"
    );

    let p1 = tmp("sg_pd1");
    let p2 = tmp("sg_sgd1");
    std::fs::write(&p1, &plain_d1).unwrap();
    std::fs::write(&p2, &sg_d1).unwrap();
    assert_eq!(run_luau(&luau, &p1), reference, "plain D1 correct");
    assert_eq!(run_luau(&luau, &p2), reference, "D1+semgroup correct");
}

#[test]
fn sg_d1_shared_plaintext_no_state_confusion() {
    let Some(luau) = find_luau() else {
        return;
    };
    let raw = tmp("sg_shraw");
    std::fs::write(&raw, SHARED_SRC).unwrap();
    let reference = run_luau(&luau, &raw);

    let art = build(SHARED_SRC, cfg(0x9ac1, true, true));
    let ap = tmp("sg_shart");
    std::fs::write(&ap, &art).unwrap();
    assert_eq!(
        run_luau(&luau, &ap),
        reference,
        "same plaintext across branches must not confuse D1 state under fusion"
    );
}

#[test]
fn sg_d1_negatives_fail_closed() {
    let Some(luau) = find_luau() else {
        return;
    };
    let raw = tmp("sg_negraw");
    std::fs::write(&raw, MULTICONST_SRC).unwrap();
    let reference = run_luau(&luau, &raw);

    let art = build(MULTICONST_SRC, cfg(0x51_a7e, true, true));
    assert!(
        art.contains(D1_EP),
        "D1 ep selector present with semgroup on"
    );
    assert!(
        art.contains(D1_STEP),
        "D1 bstate-step present with semgroup on"
    );

    let ce_only = art.replace(D1_EP, "(bxor(kc[-2] or 0, kc[-1] or 0))");
    let p = tmp("sg_neg_ce");
    std::fs::write(&p, &ce_only).unwrap();
    assert_ne!(
        run_luau(&luau, &p),
        reference,
        "CE-open of fused-group D1 constants must fail closed"
    );

    let no_step = art.replace(D1_STEP, "kc[-4] = kc[-4]; local _ = (a %");
    let p2 = tmp("sg_neg_step");
    std::fs::write(&p2, &no_step).unwrap();
    assert_ne!(
        run_luau(&luau, &p2),
        reference,
        "skipping the bstate recurrence must fail with semgroup on"
    );
}

const EXPANDED_SRC: &str = r#"
local G = 0
local base = 7
local flag = true
local function build(n)
	local acc = base
	local t = {}
	t[1] = n * 2
	t[2] = n + base
	t[3] = t[1] + t[2]
	G = G + t[3]
	acc = acc + t[3]
	local ok = flag and (n > 0)
	local o = {}
	o.x = n
	o.y = n * n
	o.z = o.x + o.y
	if ok then return t[3] + o.z + G + acc else return o.z - G end
end
print(build(5), build(-3), build(10), build(0))
"#;

#[test]
fn sg_expanded_ops_execute_correctly() {
    let Some(luau) = find_luau() else {
        return;
    };
    let raw = tmp("sg_exraw");
    std::fs::write(&raw, EXPANDED_SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    assert!(!reference.is_empty());
    for (name, c) in [
        ("d1", cfg(0x3f21, true, true)),
        ("standalone", cfg(0x3f21, false, true)),
    ] {
        let art = build(EXPANDED_SRC, c);
        let ap = tmp("sg_exart");
        std::fs::write(&ap, &art).unwrap();
        assert_eq!(
            run_luau(&luau, &ap),
            reference,
            "{name}: expanded-op fusion must equal raw"
        );
    }
}

#[test]
fn sg_expanded_d1_negatives_fail_closed() {
    let Some(luau) = find_luau() else {
        return;
    };
    let raw = tmp("sg_exnegraw");
    std::fs::write(&raw, EXPANDED_SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    let art = build(EXPANDED_SRC, cfg(0x77b2, true, true));
    assert!(
        art.contains(D1_EP) && art.contains(D1_STEP),
        "D1 anchors present with expanded fusion"
    );
    let ce_only = art.replace(D1_EP, "(bxor(kc[-2] or 0, kc[-1] or 0))");
    let p = tmp("sg_exneg");
    std::fs::write(&p, &ce_only).unwrap();
    assert_ne!(
        run_luau(&luau, &p),
        reference,
        "CE-open must fail closed with expanded fusion"
    );
}

#[test]
fn sg_d1_whole_corpus_matches_raw() {
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
        let art = build(&src, cfg(0xD1_56, true, true));
        let ap = tmp("sg_d1c");
        std::fs::write(&ap, &art).unwrap();
        let got = run_luau(&luau, &ap);
        if got != raw {
            fails.push(format!("{name}: raw={raw:?} d1+sg={got:?}"));
        }
    }
    assert!(
        fails.is_empty(),
        "D1+semgroup corpus divergences ({}/{}):\n{}",
        fails.len(),
        files.len(),
        fails.join("\n")
    );
}

#[test]
fn sg_standalone_whole_corpus_matches_raw() {
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
    let mut fails = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let name = f.file_name().unwrap().to_str().unwrap().to_string();
        let raw = run_luau(&luau, f);
        let art = build(&src, cfg(0x5C_a1, false, true));
        let ap = tmp("sg_sac");
        std::fs::write(&ap, &art).unwrap();
        let got = run_luau(&luau, &ap);
        if got != raw {
            fails.push(format!("{name}: raw={raw:?} sg={got:?}"));
        }
    }
    assert!(
        fails.is_empty(),
        "standalone semgroup corpus divergences ({}/{}):\n{}",
        fails.len(),
        files.len(),
        fails.join("\n")
    );
}

const KOP_SRC: &str = r#"
local function f(a, b)
	local x = a + 1
	x = x * 3
	x = x - 2
	local y = x
	local eq = (y == b)
	local t = {}
	t.k = y
	local s = "v=" .. tostring(y) .. ":" .. tostring(eq)
	return s, t.k
end
print(f(10, 4))
print(f(-3, -3))
print(f(0, 33))
"#;

#[test]
fn non_d1_semgroup_families_builds_without_panic() {
    let mut c = cfg(0x50f7, false, true);
    c.semantic_family = true;
    c.instruction_family = true;
    let art = build(KOP_SRC, c);
    assert!(
        !art.is_empty(),
        "non-D1 semgroup+families build must succeed on compound-K-op source"
    );

    let Some(luau) = find_luau() else {
        return;
    };
    let raw = tmp("sg_kop_raw");
    std::fs::write(&raw, KOP_SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    let ap = tmp("sg_kop_art");
    std::fs::write(&ap, &art).unwrap();
    assert_eq!(
        run_luau(&luau, &ap),
        reference,
        "non-D1 semgroup+families artifact must equal raw"
    );
}
