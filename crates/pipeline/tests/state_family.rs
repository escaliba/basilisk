use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, PropKeyMode, SensitiveOpts, StringFragMode,
    SurfaceVolume, TargetProfile,
};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
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
        .expect("luau");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim()
    .to_string()
}

fn cfg(
    seed: u64,
    minify: bool,
    state_family: bool,
    semantic_family: bool,
    instruction_family: bool,
) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: false,
        junk: false,
        fuse: false,
        minify,
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
        ablate_fragment: true,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
        shell_family: None,
        notices: pipeline::NoticeConfig::default(),
        stateful_recovery: true,
        stateful_framing: false,
        property_key_rename: PropKeyMode::Off,
        semantic_family,
        instruction_family,
        state_family,
        microir: false,
        semgroup: false,
        string_frag_mode: StringFragMode::Full,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let i = tmp("sf_in");
    let o = tmp("sf_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).unwrap())
        .unwrap()
        .join()
        .unwrap();
    std::fs::read_to_string(&o).unwrap()
}

const SRC: &str = r#"
local function outer(n)
	local acc = 0
	local function middle(x)
		local function inner(y) return y * y + x end
		for i = 1, x do acc = acc + inner(i) end
		return acc
	end
	return middle(n) + middle(n + 1)
end
local co = coroutine.wrap(function() for k = 1, 5 do coroutine.yield(k * k) end end)
local s = 0
for i = 1, 15 do
	if i % 3 == 0 then s = s + outer(i % 4 + 1)
	elseif i % 2 == 0 then s = s - i
	else s = s + co() end
end
print("SF", outer(3), s)
"#;

const LINEAGE_EP_B: &str = "bxor(fmix(kc[-4]), kc[-10] or 0)";
const LINEAGE_SLOT: &str = "kc[-10] = proto[20]";
const D1_STEP: &str = "kc[-4] = bxor(fmix(kc[-4]), a %";
const FAMILY_A_EP: &str = "and kc[-4] or";

const STATE_A_SEED: u64 = 2;
const STATE_B_SEED: u64 = 1;

#[test]
fn both_families_reachable_and_off_is_family_a() {
    let a = build(SRC, cfg(STATE_A_SEED, false, true, false, false));
    let b = build(SRC, cfg(STATE_B_SEED, false, true, false, false));
    assert!(
        !a.contains(LINEAGE_EP_B),
        "FAMILY A never folds the proto-tree lineage into ep"
    );
    assert!(
        !a.contains(LINEAGE_SLOT),
        "FAMILY A never binds the lineage slot"
    );
    assert!(
        b.contains(LINEAGE_EP_B),
        "FAMILY B folds the proto-tree lineage into ep"
    );
    assert!(
        b.contains(LINEAGE_SLOT),
        "FAMILY B binds the lineage slot at frame init"
    );

    let off = build(SRC, cfg(STATE_B_SEED, false, false, false, false));
    assert!(
        !off.contains(LINEAGE_EP_B),
        "OFF must never fold the lineage even for a FAMILY-B-bit seed"
    );
    assert!(
        !off.contains(LINEAGE_SLOT),
        "OFF must never bind the lineage slot even for a FAMILY-B-bit seed"
    );
}

#[test]
fn cfg_state_model_leaves_the_forward_recurrence_untouched() {
    let b = build(SRC, cfg(STATE_B_SEED, false, true, false, false));
    assert!(
        b.contains(D1_STEP),
        "FAMILY B keeps the identical intra-proto CFG bstate recurrence"
    );
    assert!(
        b.contains(FAMILY_A_EP) == false || b.contains(LINEAGE_EP_B),
        "FAMILY B replaces the ep read with the composite form"
    );
}

#[test]
fn cfg_only_state_model_fails_closed_on_family_b() {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("sf_raw");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);

    let b = build(SRC, cfg(STATE_B_SEED, false, true, false, false));
    assert!(b.contains(LINEAGE_EP_B), "family B artifact folds lineage");

    let unpatched = tmp("sf_b_ok");
    std::fs::write(&unpatched, &b).unwrap();
    assert_eq!(
        run_luau(&luau, &unpatched),
        reference,
        "unpatched FAMILY B artifact runs correctly"
    );

    let cfg_only = b.replace(LINEAGE_EP_B, "kc[-4]");
    let patched = tmp("sf_b_cfgonly");
    std::fs::write(&patched, &cfg_only).unwrap();
    assert_ne!(
        run_luau(&luau, &patched),
        reference,
        "a CFG-only state model (dropping the proto-tree lineage) must fail closed on a FAMILY B build"
    );
}

#[test]
fn behaviour_matches_plain_for_both_families() {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("sf_raw2");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    assert!(
        reference.starts_with("SF"),
        "raw reference sane: {reference}"
    );
    for seed in [STATE_A_SEED, STATE_B_SEED, 3u64, 4, 5, 6, 7, 42, 305419896] {
        let art = build(SRC, cfg(seed, true, true, false, false));
        let p = tmp("sf_art");
        std::fs::write(&p, &art).unwrap();
        assert_eq!(
            run_luau(&luau, &p),
            reference,
            "seed {seed}: state family must match plain Luau"
        );
    }
}

#[test]
fn stacks_with_const_section_and_instruction_families() {
    let Some(luau) = find_luau() else { return };
    let raw = tmp("sf_raw3");
    std::fs::write(&raw, SRC).unwrap();
    let reference = run_luau(&luau, &raw);
    for seed in [38u64, 67, 130] {
        let art = build(SRC, cfg(seed, true, true, true, true));
        let p = tmp("sf_stack");
        std::fs::write(&p, &art).unwrap();
        assert_eq!(
            run_luau(&luau, &p),
            reference,
            "seed {seed}: state + const-section + instruction families compose"
        );
    }
}

#[test]
fn family_b_specific_logic_is_bounded() {
    let b = build(SRC, cfg(STATE_B_SEED, false, true, false, false));
    let accessors = b.matches("streamXor(pkey").count();
    assert!(accessors >= 3, "several D1 accessors present: {accessors}");
    assert_eq!(
        b.matches(LINEAGE_EP_B).count(),
        accessors,
        "the whole family-B state delta is one composite ep read per accessor"
    );
    assert_eq!(
        b.matches(LINEAGE_SLOT).count(),
        1,
        "the lineage is bound exactly once, at frame init"
    );
}

#[test]
fn off_is_deterministic_and_default() {
    let a = build(SRC, cfg(9, true, false, false, false));
    let b = build(SRC, cfg(9, true, false, false, false));
    assert_eq!(a, b, "OFF deterministic");
    assert_eq!(cfg(0, true, false, false, false).state_family, false);

    let on_a = build(SRC, cfg(STATE_A_SEED, true, true, false, false));
    let off_a = build(SRC, cfg(STATE_A_SEED, true, false, false, false));
    assert_eq!(
        on_a, off_a,
        "ON with a FAMILY-A-bit seed is byte-identical to OFF"
    );

    let on_b = build(SRC, cfg(STATE_B_SEED, true, true, false, false));
    let off_b = build(SRC, cfg(STATE_B_SEED, true, false, false, false));
    assert_ne!(
        on_b, off_b,
        "ON with a FAMILY-B-bit seed changes the artifact"
    );
}
