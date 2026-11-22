use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn cfg(seed: u64, minify: bool) -> Config {
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
        surface: true,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile: TargetProfile::Executor,
        loadstring_canary: true,
        lph_collapse: true,
        line_info: false,
        strip_source_names: true,
        poly_stream: PolyStream::Aggressive,
        optimization: 2,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: pipeline::FrameConstReuseMode::Off,
        hot_callback_policy: HotCallbackPolicy::Report,
        ablate_fragment: true,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
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

fn build(src: &str, cfg: Config) -> String {
    let i = tmp("slb_in");
    let o = tmp("slb_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    std::thread::Builder::new()
        .stack_size(128 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).expect("build"))
        .unwrap()
        .join()
        .unwrap();
    let out = std::fs::read_to_string(&o).unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn longest_code_literal(art: &str) -> usize {
    let b = art.as_bytes();
    let mut i = 0;
    let mut max = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'[' && i + 1 < b.len() && (b[i + 1] == b'=' || b[i + 1] == b'[') {
            let mut j = i + 1;
            while j < b.len() && b[j] == b'=' {
                j += 1;
            }
            if j < b.len() && b[j] == b'[' {
                let close = format!("]{}]", "=".repeat(j - i - 1));
                if let Some(e) = art[j + 1..].find(&close) {
                    let body = &art[j + 1..j + 1 + e];
                    if body.contains(' ') || body.contains('\n') || body.contains('\t') {
                        max = max.max(body.len());
                    }
                    i = j + 1 + e + close.len();
                    continue;
                }
            }
        }
        if c == b'"' || c == b'\'' {
            let mut j = i + 1;
            while j < b.len() && b[j] != c {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            let body = &art[i + 1..j.min(b.len())];
            if body.contains(' ')
                || body.contains('\\') && (body.contains('n') || body.contains('t'))
            {
                max = max.max(body.len());
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    max
}

#[test]
fn no_code_scaffold_literal_exceeds_96_bytes() {
    for seed in [1u64, 7, 42, 999, 305419896, 2, 88, 13, 55, 100] {
        let art = build("return 0", cfg(seed, true));
        let m = longest_code_literal(&art);
        assert!(
            m <= 96,
            "seed {seed}: a code-scaffold string literal of {m} bytes exceeds the 96-byte budget"
        );
    }
}

fn largest_numeric_table(art: &str) -> usize {
    let b = art.as_bytes();
    let mut i = 0;
    let mut max = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if let Some(rel) = art[i + 1..].find('}') {
                let body = &art[i + 1..i + 1 + rel];
                if !body.trim().is_empty()
                    && body.bytes().all(|ch| {
                        ch.is_ascii_hexdigit()
                            || matches!(ch, b',' | b'x' | b'X' | b' ' | b'\n' | b'\t')
                    })
                {
                    let entries = body.split(',').filter(|s| !s.trim().is_empty()).count();
                    max = max.max(entries);
                }
            }
        }
        i += 1;
    }
    max
}

fn longest_numeric_line_run(art: &str) -> usize {
    let mut run = 0usize;
    let mut max = 0usize;
    for line in art.lines() {
        let t = line.trim().trim_end_matches(',');
        if !t.is_empty()
            && (t.bytes().all(|c| c.is_ascii_digit()) || t.starts_with("0x") || t.starts_with("0X"))
        {
            run += 1;
            max = max.max(run);
        } else {
            run = 0;
        }
    }
    max
}

#[test]
fn no_non_payload_numeric_carrier_table_exceeds_16_entries() {
    for seed in [1u64, 7, 42, 999, 305419896, 2, 88, 13, 55, 100] {
        for minify in [true, false] {
            let art = build("return 0", cfg(seed, minify));
            let m = largest_numeric_table(&art);
            assert!(m <= 16, "seed {seed} (minify={minify}): a numeric carrier table of {m} entries exceeds the 16-entry budget");
            let r = longest_numeric_line_run(&art);
            assert!(
                r <= 16,
                "seed {seed} (minify={minify}): a run of {r} standalone numeric lines exceeds 16"
            );
        }
    }
}

#[test]
fn reveal_data_is_word_carried_not_a_reverse_base85_island() {
    for seed in [1u64, 7, 42, 305419896, 88] {
        let art = build("return 0", cfg(seed, false));
        assert!(
            art.contains("writeu32") || art.contains("16777216"),
            "seed {seed}: word-carrier reconstruction (buffer writeu32 or arithmetic word split) absent"
        );
        assert!(
            !art.contains("string.reverse"),
            "seed {seed}: carrier string.reverse survives"
        );
        assert!(
            !art.contains(".reverse("),
            "seed {seed}: a reverse-and-concatenate carrier survives"
        );
    }
}
