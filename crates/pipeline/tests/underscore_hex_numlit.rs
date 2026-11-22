use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

const FIXTURE: &str = "\
local zero = 0
local pos = 4095
local neg = -4096
local mask = bit32.band(0xFFFF, 0xF0F0)
local wide = bit32.bxor(0x7FFFFFFF, 0x0)
local t = { [16] = \"key16\", [0] = \"key0\" }
local acc = 0
for i = 1, 40 do acc = acc + i * 3 - 1 end
print(zero, pos, neg, mask, wide, t[16], t[0], acc)
";

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn require_luau() {
    for tool in ["luau", "luau-compile"] {
        if let Err(e) = std::process::Command::new(tool).arg("--help").output() {
            panic!("`{tool}` is required for underscore-hex numeric-literal tests ({e})");
        }
    }
}

fn cfg(seed: u64, underscore: bool, minify: bool) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: true,
        junk: false,
        fuse: true,
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
        strip_source_names: true,
        poly_stream: PolyStream::Off,
        optimization: 1,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: pipeline::FrameConstReuseMode::Off,
        hot_callback_policy: HotCallbackPolicy::Report,
        ablate_fragment: false,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: underscore,
        shell_family: None,
        notices: pipeline::NoticeConfig::default(),
        stateful_recovery: false,
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

fn build(cfg: Config) -> String {
    let i = tmp("uh_in");
    let o = tmp("uh_out");
    std::fs::write(&i, FIXTURE).unwrap();
    let (a, b) = (i.clone(), o.clone());
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).expect("build succeeds"))
        .unwrap()
        .join()
        .unwrap();
    let out = std::fs::read_to_string(&o).unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn run(artifact: &str) -> String {
    let p = tmp("uh_run");
    std::fs::write(&p, artifact).unwrap();
    let out = std::process::Command::new("luau")
        .arg(&p)
        .output()
        .expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn compiles(artifact: &str) -> bool {
    let p = tmp("uh_cc");
    std::fs::write(&p, artifact).unwrap();
    let st = std::process::Command::new("luau-compile")
        .arg("--binary")
        .arg(&p)
        .output()
        .expect("luau-compile");
    let _ = std::fs::remove_file(&p);
    st.status.success()
}

fn underscore_literals(art: &str) -> Vec<String> {
    let b = art.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'0' && i + 1 < b.len() && b[i + 1] == b'_' {
            let mut j = i + 1;
            while j < b.len() && b[j] == b'_' {
                j += 1;
            }
            if j < b.len() && (b[j] == b'x' || b[j] == b'X') {
                let mut k = j + 1;
                while k < b.len() && b[k] == b'_' {
                    k += 1;
                }
                if k < b.len() && b[k].is_ascii_hexdigit() {
                    while k < b.len() && (b[k].is_ascii_hexdigit() || b[k] == b'_') {
                        k += 1;
                    }
                    out.push(art[i..k].to_string());
                    i = k;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

#[test]
fn the_flag_defaults_off_and_off_output_is_unchanged() {
    let a = build(cfg(42, false, true));
    let b = build(cfg(42, false, true));
    assert_eq!(a, b, "flag-off builds are deterministic");
    assert!(
        underscore_literals(&a).is_empty(),
        "no underscore-hex literal may appear when the flag is off"
    );
}

#[test]
fn a_fixed_seed_is_deterministic_and_different_seeds_vary_the_layout() {
    let a = build(cfg(42, true, true));
    let b = build(cfg(42, true, true));
    assert_eq!(a, b, "a fixed seed must reproduce byte-for-byte");

    let layouts: Vec<Vec<String>> = [1u64, 42, 1337]
        .iter()
        .map(|&s| underscore_literals(&build(cfg(s, true, true))))
        .collect();
    for l in &layouts {
        assert!(!l.is_empty(), "each seed must emit underscore literals");
    }
    assert!(
        layouts[0] != layouts[1] || layouts[1] != layouts[2],
        "different seeds must vary the underscore layout"
    );
}

#[test]
fn generated_literals_compile_and_evaluate_identically_minified_and_not() {
    require_luau();
    for minify in [true, false] {
        for seed in [1u64, 42, 1337] {
            let off = build(cfg(seed, false, minify));
            let on = build(cfg(seed, true, minify));
            assert!(
                !underscore_literals(&on).is_empty(),
                "seed {seed}: literals emitted"
            );
            assert!(
                compiles(&on),
                "seed {seed} minify={minify}: luau-compile must accept it"
            );
            assert_eq!(
                run(&on).trim(),
                run(&off).trim(),
                "seed {seed} minify={minify}: the artifact must behave identically"
            );
        }
    }
}

#[test]
fn zero_boundaries_negatives_table_keys_and_bit32_all_survive() {
    require_luau();
    let out = run(&build(cfg(42, true, true)));
    for want in [
        "0",
        "4095",
        "-4096",
        "61680",
        "2147483647",
        "key16",
        "key0",
        "2420",
    ] {
        assert!(out.contains(want), "expected `{want}` in output: {out}");
    }
}

#[test]
fn emitted_literals_stay_within_the_bounded_shape() {
    for seed in [1u64, 42, 1337] {
        for lit in underscore_literals(&build(cfg(seed, true, true))) {
            let x = lit.find(['x', 'X']).expect("prefix letter");
            let lead = lit[1..x].len();
            let trail = lit[x + 1..].chars().take_while(|&c| c == '_').count();
            assert!(
                (1..=3).contains(&lead),
                "lead underscores out of range in {lit}"
            );
            assert!(
                (1..=5).contains(&trail),
                "trail underscores out of range in {lit}"
            );
            assert!(
                !lit.ends_with('_'),
                "no trailing underscore may be emitted: {lit}"
            );
            let digits: String = lit[x + 1..]
                .chars()
                .skip_while(|&c| c == '_')
                .filter(|c| *c != '_')
                .collect();
            assert!(
                !digits.is_empty(),
                "a literal must have at least one hex digit: {lit}"
            );
            assert!(
                digits.chars().all(|c| c.is_ascii_hexdigit()),
                "integer hexadecimal digits only: {lit}"
            );
        }
    }
}

#[test]
fn the_serialized_payload_is_untouched_by_the_style() {
    let stats = |underscore: bool| {
        let i = tmp("uh_m_in");
        let o = tmp("uh_m_out");
        std::fs::write(&i, FIXTURE).unwrap();
        let c = cfg(42, underscore, true);
        let (a, b) = (i.clone(), o.clone());
        let got = std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(move || {
                let mut got: Option<pipeline::BuildStats> = None;
                pipeline::run_capturing_stats(&a, &b, &c, None, &mut got).expect("build");
                got.expect("stats")
            })
            .unwrap()
            .join()
            .unwrap();
        let _ = std::fs::remove_file(&i);
        let _ = std::fs::remove_file(&o);
        got
    };
    let off = stats(false);
    let on = stats(true);
    assert!(
        off.base85_payload_chars > 0,
        "the fixture must carry a payload"
    );
    assert_eq!(
        (
            off.serialized_total_bytes,
            off.base85_payload_chars,
            off.constants,
            off.instructions
        ),
        (
            on.serialized_total_bytes,
            on.base85_payload_chars,
            on.constants,
            on.instructions
        ),
        "the style renders shell literals only -- the serialized payload must be identical"
    );
}

#[test]
fn a_naive_hex_regex_misses_the_style_but_a_real_parser_does_not() {
    require_luau();
    let on = build(cfg(42, true, true));
    let lits = underscore_literals(&on);
    assert!(!lits.is_empty(), "literals emitted");

    for lit in lits.iter().take(5) {
        assert!(
            !lit.starts_with("0x") && !lit.starts_with("0X"),
            "a naive `0x[0-9a-fA-F]+` scan cannot match `{lit}` -- that is the entire friction claim"
        );
        let digits: String = lit.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let digits = digits.trim_start_matches(['x', 'X']).to_string();
        let value = u64::from_str_radix(digits.trim_start_matches('0'), 16).unwrap_or(0);
        let src = format!("print({lit} == 0x{value:X})\n");
        let p = tmp("uh_eq");
        std::fs::write(&p, &src).unwrap();
        let o = std::process::Command::new("luau").arg(&p).output().unwrap();
        let _ = std::fs::remove_file(&p);
        assert!(
            String::from_utf8_lossy(&o.stdout).trim() == "true",
            "a real Luau parser must fold `{lit}` to the same integer immediately"
        );
    }
}
