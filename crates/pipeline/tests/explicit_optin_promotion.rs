use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pipeline::{
    Config, FrameConstReuseMode, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

const ACCEPTED_RC: &str = "bea9c4bac14cb744754352659d4f64be89c5cc947ee903355bc9dcee65bff056";
const ACCEPTED_PROTOS: usize = 978;
const ACCEPTED_NATIVES: usize = 3;
const ACCEPTED_INSTRUCTIONS: usize = 88_938;
const ACCEPTED_SERIALIZED_BYTES: usize = 802_685;

fn tmp(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{prefix}_{}_{}.luau",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_crates() -> PathBuf {
    crate_root().join("..")
}

fn annotated_fixture() -> PathBuf {
    crate_root().join("tests/fixtures/explicit_optin/infinite_yield_annotated.lua")
}

fn p1j_config(seed: u64, explicit_optin: bool) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: true,
        junk: false,
        fuse: true,
        minify: true,
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
        frame_const_reuse: FrameConstReuseMode::All,
        hot_callback_policy: HotCallbackPolicy::Report,
        ablate_fragment: true,
        hot_light: false,
        explicit_optin,
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
    let input = tmp("optin_in");
    let output = tmp("optin_out");
    std::fs::write(&input, src).expect("write input");
    let (i, o) = (input.clone(), output.clone());
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&i, &o, &cfg).expect("build succeeds"))
        .expect("spawn")
        .join()
        .expect("build thread");
    let out = std::fs::read_to_string(&output).expect("read artifact");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    out
}

fn build_with_stats(src: &str, cfg: Config) -> (String, pipeline::BuildStats) {
    let input = tmp("optin_in");
    let output = tmp("optin_out");
    std::fs::write(&input, src).expect("write input");
    let (i, o) = (input.clone(), output.clone());
    let stats = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let mut stats = None;
            pipeline::run_capturing_stats(&i, &o, &cfg, None, &mut stats).expect("build succeeds");
            stats.expect("stats collected")
        })
        .expect("spawn")
        .join()
        .expect("build thread");
    let out = std::fs::read_to_string(&output).expect("read artifact");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    (out, stats)
}

fn build_err(src: &str, cfg: Config) -> String {
    let input = tmp("optin_in");
    let output = tmp("optin_out");
    std::fs::write(&input, src).expect("write input");
    let (i, o) = (input.clone(), output.clone());
    let e = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::run(&i, &o, &cfg)
                .map(|_| ())
                .unwrap_err()
                .to_string()
        })
        .expect("spawn")
        .join()
        .expect("build thread");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    e
}

const ANNOTATED: &str = "\
local topPick = nil
Matches = function(name, str)
\tstr = str:gsub('%W', '%%%1')
\treturn name:lower():find(str:lower()) and true
end
local function Scan(query)
\ttopPick = nil
\tfor _, entry in pairs(Registry()) do
\t\tif Matches(entry.Text, query) then
\t\t\tif topPick == nil then topPick = entry.Text end
\t\tend
\tend
end
BASIL_PRIVATE_SCAN(Scan, topPick, Matches)
Lookup = function(tbl, want)
\tfor _, x in pairs(tbl) do if x == want then return true end end
\treturn false
end
BASIL_NATIVE_LEAF(Lookup)
Twin = function(tbl, want)
\tfor _, x in pairs(tbl) do if x == want then return true end end
\treturn false
end
Resolve = function(name)
\tfor k, v in pairs(Commands()) do if k == name then return v end end
\treturn nil
end
local function Consume()
\tif topPick ~= nil then Complete(topPick) end
end
return Scan, Lookup, Twin, Resolve, Consume
";

fn unannotated() -> String {
    ANNOTATED
        .lines()
        .filter(|l| !l.trim_start().starts_with("BASIL_"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn production_contains_no_fixed_p1j_selector_constants() {
    let root = workspace_crates();
    let mut offenders = Vec::new();
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    for f in files {
        let rel = f
            .strip_prefix(workspace_crates())
            .unwrap_or(&f)
            .to_path_buf();
        if rel.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let src = std::fs::read_to_string(&f).expect("read source");
        let prod = match src.find("\n#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src[..],
        };
        for (n, line) in prod.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("\"topCommand\"") {
                offenders.push(format!("{}:{}: {}", rel.display(), n + 1, line.trim()));
            }
            for id in ["220", "296", "219", "230"] {
                if code.split(|c: char| !c.is_ascii_digit()).any(|t| t == id) {
                    offenders.push(format!("{}:{}: {}", rel.display(), n + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "production Rust must not carry the retired P1-J selectors:\n{}",
        offenders.join("\n")
    );
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn an_annotated_source_produces_exactly_three_natives() {
    let (art, stats) = build_with_stats(ANNOTATED, p1j_config(0x51E4_3D77_0011_A2B3, true));
    assert_eq!(
        stats.natives, 3,
        "two markers admit exactly three natives: the scan helper, the matcher and the leaf"
    );
    assert!(
        art.contains("gsub"),
        "the marked matcher body is emitted natively: no gsub found"
    );
    assert!(
        art.contains("Registry()"),
        "the marked scan body is emitted natively: no Registry call found"
    );

    let (_, plain) = build_with_stats(&unannotated(), p1j_config(0x51E4_3D77_0011_A2B3, true));
    assert_eq!(
        plain.natives, 0,
        "the same source without markers admits nothing"
    );
}

#[test]
fn an_unmarked_eligible_helper_stays_virtualized() {
    let art = build(ANNOTATED, p1j_config(0x51E4_3D77_0011_A2B3, true));
    assert!(
        !art.contains("Twin"),
        "the unmarked twin helper must not be published: {}",
        &art[..0]
    );
    assert!(
        !art.contains("Commands()"),
        "the unmarked Resolve helper must stay virtualized (no plaintext Commands call)"
    );
}

#[test]
fn the_command_resolver_stays_virtualized() {
    let art = build(ANNOTATED, p1j_config(0x51E4_3D77_0011_A2B3, true));
    for leak in ["Resolve", "Commands", "Complete", "topPick"] {
        assert!(
            !art.contains(leak),
            "`{leak}` must not appear in the artifact"
        );
    }
}

#[test]
fn markers_without_the_gate_fail_rather_than_being_ignored() {
    let e = build_err(ANNOTATED, p1j_config(0x51E4_3D77_0011_A2B3, false));
    assert!(
        e.contains("refusing to silently ignore"),
        "an unannotated build path must refuse marked sources: {e}"
    );
}

#[test]
fn a_malformed_marker_fails_the_build_before_any_transform() {
    let bad = ANNOTATED.replace("BASIL_NATIVE_LEAF(Lookup)", "BASIL_NATIVE_LEAF(\"Lookup\")");
    let e = build_err(&bad, p1j_config(0x51E4_3D77_0011_A2B3, true));
    assert!(e.contains("bare function/variable names"), "{e}");
}

#[test]
fn annotated_fixture_is_reproducible() {
    let fixture = annotated_fixture();
    let src = std::fs::read_to_string(&fixture)
        .unwrap_or_else(|e| panic!("read tracked fixture {}: {e}", fixture.display()));
    assert_eq!(
        src.matches("BASIL_PRIVATE_SCAN(IndexContents, topCommand, Match)")
            .count(),
        1,
        "the tracked fixture must carry exactly one private-scan marker"
    );
    assert_eq!(
        src.matches("BASIL_NATIVE_LEAF(FindInTable)").count(),
        1,
        "the tracked fixture must carry exactly one native-leaf marker"
    );
    assert_eq!(
        src.matches("BASIL_").count(),
        2,
        "the tracked fixture adds the two markers and nothing else"
    );

    let output = tmp("iy_rc");
    let cfg = p1j_config(17906244878785717735, true);
    let (i, o) = (fixture.clone(), output.clone());
    let stats = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let mut stats = None;
            pipeline::run_capturing_stats(&i, &o, &cfg, None, &mut stats).expect("build");
            stats.expect("stats collected")
        })
        .expect("spawn")
        .join()
        .expect("build thread");

    let art = std::fs::read(&output).expect("read artifact");
    let _ = std::fs::remove_file(&output);

    let digest = sha256_hex(&art);
    assert_eq!(
        stats.protos, ACCEPTED_PROTOS,
        "program proto count must be unchanged"
    );
    assert_eq!(
        stats.natives, ACCEPTED_NATIVES,
        "native-escape selection must be unchanged"
    );
    assert_eq!(
        stats.instructions, ACCEPTED_INSTRUCTIONS,
        "program instruction count must be unchanged"
    );
    assert_eq!(
        stats.serialized_total_bytes, ACCEPTED_SERIALIZED_BYTES,
        "serialized payload must be unchanged"
    );
    assert_eq!(
        digest, ACCEPTED_RC,
        "artifact sha changed to {digest} (VM-template-only change updates this golden)"
    );

    let text = String::from_utf8_lossy(&art);

    for present in [
        "IsA(",
        "CanvasPosition",
        "AbsoluteContentSize",
        "GetChildren",
        "%W",
        "pairs(",
    ] {
        assert!(
            text.contains(present),
            "the three marked native bodies must be emitted in cleartext; `{present}` missing"
        );
    }

    for leak in [
        "BASIL_PRIVATE_SCAN",
        "BASIL_NATIVE_LEAF",
        "BASIL_",
        "topCommand",
        "_basil_",
        "findCmd",
    ] {
        assert!(
            !text.contains(leak),
            "`{leak}` must not survive into the artifact"
        );
    }

    for protected in [
        "customAlias",
        "ALIAS",
        "IndexContents",
        "FindInTable",
        "cmdBar",
    ] {
        assert!(
            !text.contains(protected),
            "`{protected}` belongs to a virtualized body or a source local and must not appear"
        );
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut msg = bytes.to_vec();
    let bitlen = (bytes.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].into_iter().enumerate() {
            h[i] = h[i].wrapping_add(v);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[test]
fn unannotated_and_annotated_sources_agree_when_no_transform_applies() {
    let plain = unannotated();
    let a = build(&plain, p1j_config(0x77AA_1122_3344_5566, false));
    let b = build(&plain, p1j_config(0x77AA_1122_3344_5566, true));
    assert_eq!(
        a, b,
        "enabling the gate on a source with no markers must be byte-identical: the gate alone \
         draws no randomness and shifts no stable id"
    );
}
