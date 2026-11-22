use std::collections::BTreeSet;
use std::collections::HashSet;

const SAMPLE: &str = "local function greet(name)\n\
  local parts = { \"hello\", \"world\", name }\n\
  local out = \"\"\n\
  for i = 1, #parts do out = out .. parts[i] .. tostring(i * 7) end\n\
  return out\n\
end\n\
return greet(\"basilisk\")\n";

const NEUTRAL: &str = "local t = {}\n\
for i = 1, 12 do t[i] = i * i - 3 end\n\
local s = 0\n\
for i = 1, #t do s = s + t[i] end\n\
return s\n";

fn build_min(src: &str, seed: u64) -> String {
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
        pipeline::SurfaceVolume::Off,
    )
    .unwrap()
}

fn build_unmin(src: &str, seed: u64) -> String {
    pipeline::virtualize_full(
        src,
        seed,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap()
}

fn build_compress(src: &str, seed: u64) -> String {
    pipeline::virtualize_full(
        src,
        seed,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        pipeline::SurfaceVolume::Off,
    )
    .unwrap()
}

fn build_heavy(src: &str, seed: u64) -> String {
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

fn build_exec_wm(src: &str, seed: u64) -> String {
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
        pipeline::TargetProfile::Executor,
        true,
        false,
    )
    .unwrap()
}

fn strip_payload(s: &str) -> String {
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

fn code_no_strings(s: &str) -> String {
    let s = strip_payload(s);
    let b = s.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}

fn normalize_idents(s: &str) -> String {
    let s = strip_payload(s);
    let b = s.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push('S');
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_') {
                i += 1;
            }
            out.push_str(&s[start..i]);
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push('I');
        } else if c.is_ascii_whitespace() {
            i += 1;
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}

fn ngrams(s: &str, n: usize) -> HashSet<&str> {
    let mut set = HashSet::new();
    if s.len() >= n {
        for i in 0..=s.len() - n {
            set.insert(&s[i..i + n]);
        }
    }
    set
}

fn jaccard(a: &str, b: &str, n: usize) -> f64 {
    let (sa, sb) = (ngrams(a, n), ngrams(b, n));
    let uni = sa.union(&sb).count();
    if uni == 0 {
        return 1.0;
    }
    sa.intersection(&sb).count() as f64 / uni as f64
}

fn normalize_full(s: &str) -> String {
    let s = strip_payload(s);
    let b = s.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push('S');
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_') {
                i += 1;
            }
            out.push('N');
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push('I');
        } else if c.is_ascii_whitespace() {
            i += 1;
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}

fn dispatch_region(s: &str) -> &str {
    if let Some(a) = s.find("code[pc]") {
        let end = s[a..]
            .find("SK_SJ = structKey")
            .map(|e| a + e)
            .unwrap_or(s.len());
        &s[a..end]
    } else {
        s
    }
}

fn numeric_table_keys(s: &str) -> BTreeSet<u32> {
    let b = s.as_bytes();
    let mut keys = BTreeSet::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'[' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > start && j < b.len() && b[j] == b']' {
                let mut k = j + 1;
                while k < b.len() && b[k] == b' ' {
                    k += 1;
                }
                if k < b.len() && b[k] == b'=' && !(k + 1 < b.len() && b[k + 1] == b'=') {
                    if let Ok(v) = s[start..j].parse::<u32>() {
                        keys.insert(v);
                    }
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    keys
}

fn first_number_after(s: &str, anchor: &str) -> Option<u32> {
    let p = s.find(anchor)? + anchor.len();
    let b = s.as_bytes();
    let mut i = p;
    while i < b.len() && !b[i].is_ascii_digit() {
        if b[i] == b'\n' {
            return None;
        }
        i += 1;
    }
    let start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    s[start..i].parse().ok()
}

#[test]
fn deobf_no_toolchain_pass_or_attribution_anchors() {
    let word_anchors: &[&str] = &[
        "basilisk",
        "vmgen",
        "normconstv01",
        "github.com/escaliba/basilisk",
        "basil_",
        "flatten",
        "opaque",
        "synonymize",
        "pad_decoys",
        "shuffle_structure",
        "obfuscated by",
        "protected by",
        "powered by",
        "obfuscator",
        "github.com",
    ];
    let builds: &[(&str, String)] = &[
        ("default", build_min(NEUTRAL, 0xA11CE)),
        ("compress", build_compress(NEUTRAL, 0xA11CE)),
        ("basil-heavy", build_heavy(NEUTRAL, 0xA11CE)),
        ("executor+wm", build_exec_wm(NEUTRAL, 0xA11CE)),
    ];
    for (name, full) in builds {
        let code = strip_payload(full).to_lowercase();
        for a in word_anchors {
            assert!(
                !code.contains(a),
                "profile {name}: deobfuscator anchor {a:?} must not appear in generated code"
            );
        }
    }
}

#[test]
fn deobf_no_in_band_cipher_magic_constants() {
    let magic: &[&str] = &[
        "2654435769",
        "9e3779b9",
        "811c9dc5",
        "61707865",
        "3320646e",
        "79622d32",
        "6b206574",
        "35184372088832",
    ];
    for seed in [1u64, 2, 3] {
        for full in [
            build_min(NEUTRAL, seed),
            build_compress(NEUTRAL, seed),
            build_exec_wm(NEUTRAL, seed),
        ] {
            let code = code_no_strings(&full).to_lowercase();
            for m in magic {
                assert!(!code.contains(m), "in-band cipher/signature magic {m:?} must not appear as a numeric literal (seed {seed})");
            }
        }
    }
}

#[test]
fn deobf_constants_resolved_per_access_not_materialized() {
    let un = build_unmin(SAMPLE, 0xC0FFEE);
    assert!(
        un.contains("kget"),
        "per-access constant accessor (kget) must be present"
    );
    let cap = first_number_after(&un, "KCAP").expect("KCAP bound present");
    assert!(
        cap >= 1 && cap <= 32,
        "kget cache must stay small/bounded (KCAP={cap})"
    );
    for pool in ["#_cs do", "#consts do", "#_cs)", "#consts)"] {
        assert!(
            !un.contains(pool),
            "no decode-all loop may iterate the constant pool ({pool:?})"
        );
    }
    for seed in [1u64, 77, 909] {
        let code = strip_payload(&build_min(SAMPLE, seed));
        for c in ["hello", "world", "basilisk"] {
            assert!(
                !code.contains(c),
                "source constant {c:?} must not appear as one plaintext table entry (seed {seed})"
            );
        }
    }
}

#[test]
fn deobf_constant_access_seam_is_not_a_single_helper() {
    let un = build_unmin(SAMPLE, 0x5EA33);
    for name in ["function kg1", "function kg2", "function kg3"] {
        assert!(
            un.contains(name),
            "constant accessor {name} must exist (>= 3 shapes)"
        );
    }
    assert!(
        un.matches("streamXor(pkey").count() >= 3,
        "each accessor must decrypt independently, not forward to one helper"
    );
    assert!(
        un.matches("keyedTag(pkey").count() >= 3,
        "each accessor must run its own keyed-tag check"
    );
    for name in ["kg1(", "kg2(", "kg3("] {
        assert_eq!(
            un.matches(name).count(),
            1,
            "{name} must appear only as its own definition (no accessor forwards to another)"
        );
    }
    assert!(
        un.contains("kget = kroute(proto[5])"),
        "per-proto accessor selection must be present"
    );
    let kgr_start = un.find("local KGR = {").expect("route table present");
    let kgr = &un[kgr_start..kgr_start + un[kgr_start..].find('}').unwrap()];
    let distinct = ["kg1", "kg2", "kg3"]
        .iter()
        .filter(|n| kgr.contains(**n))
        .count();
    assert!(
        distinct >= 2,
        "route table must distribute across >= 2 accessors: {kgr}"
    );
    let code = strip_payload(&build_min(SAMPLE, 0x5EA33));
    for c in ["hello", "world", "basilisk"] {
        assert!(!code.contains(c), "no plaintext constant {c:?}");
    }
}

fn accessor_skeletons(un: &str) -> Vec<String> {
    let s = un
        .find("local function kg1(consts")
        .expect("kg1 accessor present");
    let e = un[s..].find("local KGR").map(|x| s + x).unwrap_or(un.len());
    un[s..e]
        .split("local function kg")
        .filter(|c| c.contains("streamXor"))
        .map(|c| normalize_full(&format!("local function kg{c}")))
        .collect()
}

#[test]
fn deobf_constant_accessors_are_generated_per_build() {
    let per: BTreeSet<String> = accessor_skeletons(&build_unmin(SAMPLE, 0xACCE55))
        .into_iter()
        .collect();
    assert!(
        per.len() >= 3,
        "at least 3 distinct accessor skeletons per artifact: {}",
        per.len()
    );
    let mut all: BTreeSet<String> = BTreeSet::new();
    let mut sets: Vec<BTreeSet<String>> = Vec::new();
    for seed in 0..20u64 {
        let sk: BTreeSet<String> = accessor_skeletons(&build_unmin(SAMPLE, seed * 131 + 5))
            .into_iter()
            .collect();
        all.extend(sk.iter().cloned());
        sets.push(sk);
    }
    assert!(
        all.len() >= 5,
        "at least 5 distinct accessor skeletons across 20 seeds: {}",
        all.len()
    );
    assert!(
        sets.iter().any(|s| *s != sets[0]),
        "accessor skeleton sets must vary across seeds"
    );
}

fn mean_pairwise_jaccard(builds: &[String], scope: &dyn Fn(&str) -> String) -> f64 {
    let norms: Vec<String> = builds.iter().map(|b| scope(b)).collect();
    let mut sum = 0.0;
    let mut n = 0.0;
    for i in 0..norms.len() {
        for j in i + 1..norms.len() {
            sum += jaccard(&norms[i], &norms[j], 8);
            n += 1.0;
        }
    }
    sum / n
}

#[test]
fn deobf_handler_bodies_vary_across_seeds() {
    let seeds = [101u64, 202, 303];
    let builds: Vec<String> = seeds.iter().map(|&s| build_unmin(SAMPLE, s)).collect();

    let id_norm = mean_pairwise_jaccard(&builds, &|b| normalize_idents(b));
    assert!(
        id_norm < 0.85,
        "per-build material must vary across seeds beyond renaming (masks/slots/keys reach emitted text): mean id-normalized 8-gram Jaccard {id_norm:.3}"
    );

    let whole_full = mean_pairwise_jaccard(&builds, &|b| normalize_full(b));
    assert!(
        whole_full < 0.87,
        "whole-VM fully-abstracted skeleton must improve on the 0.904->0.847 baseline: mean {whole_full:.3}"
    );

    for b in &builds {
        assert!(
            dispatch_region(b).len() > 2000,
            "dispatch region anchors must locate the handler block"
        );
    }
    let region_full = mean_pairwise_jaccard(&builds, &|b| normalize_full(dispatch_region(b)));
    println!("handler-body Jaccard: id_norm={id_norm:.3} whole_full={whole_full:.3} region_full={region_full:.3}");
    assert!(
        region_full < 0.745,
        "the dispatch/handler region a fingerprinter examines must improve on the 0.793->0.720 baseline: mean fully-abstracted 8-gram Jaccard {region_full:.3}"
    );
}

#[test]
fn deobf_operand_slots_vary_and_reach_emitted_text() {
    let seeds = [7u64, 8, 9];
    let keysets: Vec<BTreeSet<u32>> = seeds
        .iter()
        .map(|&s| numeric_table_keys(&build_unmin(SAMPLE, s)))
        .collect();
    for (i, ks) in keysets.iter().enumerate() {
        assert!(
            !ks.is_empty(),
            "numeric operand/record slots must reach emitted VM text (seed {})",
            seeds[i]
        );
    }
    assert!(
        !(keysets[0] == keysets[1] && keysets[1] == keysets[2]),
        "operand/record slot values must vary across seeds (wired and live, not dead like IronBrew's unused shuffle)"
    );
}

#[test]
fn deobf_isa_not_trivially_stock_luau() {
    let all = bytecode::opcode::ALL;
    let fused = [
        "ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK", "IDIVK", "CONCATK", "EQK", "NEK", "LTK",
        "LEK", "GTK", "GEK",
    ];
    let custom = [
        "LOADNATIVE",
        "CRASH",
        "LOADK1",
        "LOADK2",
        "MUL1",
        "MUL2",
        "ADD1",
        "MOVE1",
        "SUB1",
        "GETTABLE1",
        "ENCFUNC",
        "GETGLOBALI",
        "SELFI",
        "GUARD",
        "PAD",
    ];
    let total = all.len();
    let non = all
        .iter()
        .filter(|(_, n)| {
            let n = *n;
            fused.contains(&n) || custom.contains(&n) || n.starts_with("SUPER")
        })
        .count();
    assert!(
        total >= 60,
        "ISA inventory must be substantial ({total} opcodes)"
    );
    let pct = non * 100 / total;
    assert!(
        pct >= 40,
        "a meaningful fraction of the ISA must be fused/split/custom (no 1:1 stock-Luau reduction): {non}/{total} = {pct}%"
    );
}

#[test]
fn deobf_normalized_skeleton_leaks_no_reusable_material() {
    let seeds = [0x5EED1u64, 0x5EED2, 0x5EED3];
    let keysets: Vec<BTreeSet<u32>> = seeds
        .iter()
        .map(|&s| numeric_table_keys(&build_unmin(SAMPLE, s)))
        .collect();
    assert!(
        !(keysets[0] == keysets[1] && keysets[1] == keysets[2]),
        "even with the structural skeleton exposed, per-build numeric material (masks/slots/keys) must vary across seeds so it cannot be reused"
    );
    let code = strip_payload(&build_min(SAMPLE, seeds[0]));
    for c in ["hello", "world", "basilisk"] {
        assert!(
            !code.contains(c),
            "normalization must not expose a clean plaintext constant table ({c:?})"
        );
    }
}

fn patch_set(un: &str, marker: &str) -> BTreeSet<u32> {
    let start = un
        .find(marker)
        .unwrap_or_else(|| panic!("ISHARD block emits {marker}"));
    let body = &un[start + marker.len()..];
    let end = body.find('}').expect("patch set closes");
    body[..end]
        .split(',')
        .filter_map(|e| e.trim().strip_prefix('['))
        .filter_map(|e| e.split(']').next())
        .filter_map(|n| n.trim().parse::<u32>().ok())
        .collect()
}

fn ipok_set(un: &str) -> BTreeSet<u32> {
    patch_set(un, "local IPOK = {")
}

const SOP_SRC: &str = "local t={10,20,30,40}\nlocal s=0\nfor i=1,#t do local x=t[i] s=s+x*2 end\nlocal a=t[1] local b=t[2] local c=a+b\nreturn s+c\n";

#[test]
fn deobf_instr_shard_selfpatch_is_present_and_per_build() {
    let un = build_unmin(SAMPLE, 0x15A0D);
    let code = strip_payload(&un);
    assert!(
        code.contains("local function ipatch("),
        "the cold instruction-shard patch stage is emitted"
    );
    assert!(
        code.contains("ipatch(proto)"),
        "patch runs per-proto for child closures (makeClosure)"
    );
    assert!(
        code.contains("ipatchRange(proto, base + 1, base + count)")
            && code.contains("local function ensurePages"),
        "the lazily-paged root patches per-page via ipatchRange in ensurePages"
    );
    assert!(
        code.contains("local IPOK = {") && code.contains("IPOK[inst[KOP]]"),
        "patch is gated by a per-build patchable-opcode bitmask"
    );
    assert!(
        code.contains("local KS = { KA, KB, KC }") && code.contains("inst[k] = inst[k] -"),
        "the repair adjusts numeric A/B/C slots via a slot loop, not clean fields"
    );

    assert!(
        code.contains("local ISOK = {") && code.contains("ISOK[inst[KOP]]"),
        "sidecar patch is gated by a per-build super-op mask"
    );
    assert!(
        code.contains("inst[KOPS]") && code.contains("so[j] = so[j] -"),
        "sidecar repair adjusts numeric ops slots via a slot loop, not clean fields"
    );

    assert!(
        code.contains("local CFPOK = {") && code.contains("CFPOK[inst[KOP]]"),
        "control-flow offset patch is gated by a per-build mask"
    );
    assert!(
        code.contains("cfk = bxor("),
        "control-flow patch key derived in the cold ipatch stage"
    );
    for anchor in [
        ".op", ".ops", ".inStack", ".index", ".open", ".idx", "inst.a", "inst.b", "inst.c",
    ] {
        assert!(
            !code.contains(anchor),
            "instruction-shard code must not expose a clean anchor {anchor:?}"
        );
    }
    let seeds = [0x111u64, 0x222, 0x333, 0x444, 0x555];
    let sets: Vec<BTreeSet<u32>> = seeds
        .iter()
        .map(|&s| ipok_set(&build_unmin(SAMPLE, s)))
        .collect();
    for s in &sets {
        assert!(
            !s.is_empty(),
            "a representative program has patchable low-risk instructions"
        );
    }
    assert!(
        sets.iter().any(|s| *s != sets[0]),
        "the patchable-opcode set (concrete values) varies across builds"
    );

    let ssets: Vec<BTreeSet<u32>> = seeds
        .iter()
        .map(|&s| patch_set(&build_unmin(SOP_SRC, s), "local ISOK = {"))
        .collect();
    for s in &ssets {
        assert!(
            !s.is_empty(),
            "a super-op-bearing program has patchable sidecar operands"
        );
    }
    assert!(
        ssets.iter().any(|s| *s != ssets[0]),
        "the super-op sidecar mask (concrete keys) varies across builds"
    );

    let csets: Vec<BTreeSet<u32>> = seeds
        .iter()
        .map(|&s| patch_set(&build_unmin(NEUTRAL, s), "local CFPOK = {"))
        .collect();
    for s in &csets {
        assert!(
            !s.is_empty(),
            "a loop-bearing program has patchable control-flow offset operands"
        );
    }
    assert!(
        csets.iter().any(|s| *s != csets[0]),
        "the control-flow offset mask (concrete keys) varies across builds"
    );
}

#[test]
fn physical_opcode_remap_scatters_dispatch_labels_across_seeds() {
    let seeds = [0x51u64, 0x52, 0x53, 0x54, 0x55];
    let dispatch_labels = |un: &str| -> BTreeSet<u32> {
        let code = strip_payload(un);
        code.match_indices("op == ")
            .filter_map(|(i, _)| code[i + 6..].split(|c: char| !c.is_ascii_digit()).next())
            .filter_map(|s| s.parse::<u32>().ok())
            .collect()
    };
    let labels: Vec<BTreeSet<u32>> = seeds
        .iter()
        .map(|&s| dispatch_labels(&build_unmin(SOP_SRC, s)))
        .collect();
    for l in &labels {
        assert!(
            l.len() > 10,
            "dispatch routes many distinct physical opcodes ({})",
            l.len()
        );
    }
    assert!(
        labels.iter().any(|l| *l != labels[0]),
        "physical dispatch opcode labels vary across builds"
    );

    let supers: Vec<BTreeSet<u32>> = seeds
        .iter()
        .map(|&s| patch_set(&build_unmin(SOP_SRC, s), "local SUPER = {"))
        .collect();
    for s in &supers {
        assert!(
            !s.is_empty(),
            "a super-op-bearing program emits a SUPER table"
        );
    }
    assert!(
        supers.iter().any(|s| *s != supers[0]),
        "super-op physical ids (SUPER keys) vary across builds"
    );
}

fn compile_final(src: &str, seed: u64) -> bytecode::Proto {
    let module = frontend::lower_str(src).unwrap();
    let mut module = frontend::macros::expand(module, seed).unwrap();
    passes::fragment_strings(&mut module, seed, false);
    let mut proto = bytecode::compile(&module).unwrap();
    proto = passes::flatten(&proto, seed);
    proto = passes::junk(&proto, seed);
    proto = passes::opaque(&proto, seed);
    proto = passes::fuse(&proto, seed);
    proto = passes::synonymize(&proto, seed);
    proto = passes::pad_decoys(&proto, seed);
    passes::shuffle_structure(&proto, seed)
}

#[derive(Default)]
struct PatchStats {
    total: usize,
    records: usize,
    a: usize,
    b: usize,
    c: usize,
    set_table: usize,
    set_global: usize,
    set_upval: usize,
    side: usize,
    side_records: usize,
    cf: usize,
    cf_records: usize,
}

fn count_patched(
    p: &bytecode::Proto,
    pid: &mut u32,
    genkey: &[u32; 8],
    seed: u64,
    st: &mut PatchStats,
) {
    use bytecode::opcode::Opcode;
    let this = *pid;
    *pid += 1;
    let ipk =
        bytecode::crypt::instr_patch_key(genkey, this, bytecode::crypt::instr_patch_domain(seed));
    let spk =
        bytecode::crypt::instr_patch_key(genkey, this, bytecode::crypt::sidecar_patch_domain(seed));
    let cfk = bytecode::crypt::instr_patch_key(
        genkey,
        this,
        bytecode::crypt::controlflow_patch_domain(seed),
    );
    for (pc0, inst) in p.code.iter().enumerate() {
        st.total += 1;
        let pc = pc0 as u32 + 1;
        let mut rec = false;
        for slot in 0..3usize {
            if bytecode::opcode::patch_role(inst.op, slot) != bytecode::opcode::OperandRole::None
                && bytecode::crypt::instr_patch_selected(ipk, pc, slot as u32)
            {
                rec = true;
                match slot {
                    0 => st.a += 1,
                    1 => st.b += 1,
                    _ => st.c += 1,
                }
                match inst.op {
                    Opcode::SetTable => st.set_table += 1,
                    Opcode::SetGlobal => st.set_global += 1,
                    Opcode::SetUpval => st.set_upval += 1,
                    _ => {}
                }
            }
        }
        let mut cfrec = false;
        for slot in 0..3usize {
            if bytecode::opcode::patch_cf_role(inst.op, slot) != bytecode::opcode::OperandRole::None
                && bytecode::crypt::instr_patch_selected(
                    cfk,
                    pc,
                    bytecode::crypt::CONTROLFLOW_SLOT_BASE + slot as u32,
                )
            {
                st.cf += 1;
                cfrec = true;
                rec = true;
            }
        }
        if cfrec {
            st.cf_records += 1;
        }
        let mut srec = false;
        if bytecode::superop::is_super(inst.op) {
            for j in 0..inst.ops.len() {
                if bytecode::opcode::patch_sidecar_role(inst.op, j)
                    != bytecode::opcode::OperandRole::None
                    && bytecode::crypt::instr_patch_selected(
                        spk,
                        pc,
                        bytecode::crypt::SIDECAR_SLOT_BASE + j as u32,
                    )
                {
                    st.side += 1;
                    srec = true;
                    rec = true;
                }
            }
        }
        if srec {
            st.side_records += 1;
        }
        if rec {
            st.records += 1;
        }
    }
    for c in &p.protos {
        count_patched(c, pid, genkey, seed, st);
    }
}

#[test]
fn instr_shard_bc_patched_and_bounded_not_whole_stream() {
    let scripts = [SAMPLE, NEUTRAL,
        "local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end\nreturn fib(12)\n",
        "local acc = {}\nfor i = 1, 40 do acc[i] = (i * 3 + 7) % 13 - i end\nlocal s = 0\nfor _, v in ipairs(acc) do s = s + v * 2 - 1 end\nreturn s\n",
        "local t = { a = 1, b = 2 }\nlocal function f(x) return -x + #tostring(x) end\nlocal s = ''\nfor k, v in pairs(t) do s = s .. k .. f(v) end\nreturn s\n",
        "A1=1 A2=2 A3=3 A4=4 A5=5 A6=6 A7=7 A8=8\nA1=A1+A2 A3=A3*A4 A5=A5-A6 A7=A7+A8 A2=A2+A5 A4=A4+A7 A6=A6+A1 A8=A8+A3\nlocal function mk() local n = 0 return function(d) n = n + d end, function() return n end end\nlocal inc, get = mk()\nlocal t = setmetatable({}, { __newindex = function(o, k, v) rawset(o, k, v * 2) end })\nfor i = 1, 6 do inc(i) t['k' .. i] = i t.acc = (t.acc or 0) + i end\nreturn A1+A2+A3+A4+A5+A6+A7+A8 + get() + (rawget(t, 'k3') or 0)\n"];
    let mut g = PatchStats::default();
    for (i, src) in scripts.iter().enumerate() {
        let seed = 0xB0FE + i as u64 * 97;
        let proto = compile_final(src, seed);
        let enc = bytecode::encoding::Encoding::from_seed(seed);
        let genkey = bytecode::encoder::payload_genkey(
            &proto,
            seed,
            &enc,
            false,
            pipeline::TargetProfile::CliTest,
            false,
        );
        let mut pid = 0u32;
        count_patched(&proto, &mut pid, &genkey, seed, &mut g);
    }
    let fields = g.a + g.b + g.c;
    let set_fields = g.set_table + g.set_global + g.set_upval;
    let rec_frac = g.records as f64 / g.total as f64;
    assert!(
        g.b > 0 && g.c > 0,
        "B and C operands still patched (B={}, C={})",
        g.b,
        g.c
    );
    assert!(g.a > 0, "A operands still patched (not weakened): {}", g.a);
    assert!(
        set_fields > 0,
        "SET-family operands are actually patched (SETTABLE={}, SETGLOBAL={}, SETUPVAL={})",
        g.set_table,
        g.set_global,
        g.set_upval
    );
    assert!(
        g.side > 0,
        "super-op sidecar operands are actually patched: {}",
        g.side
    );
    assert!(
        g.cf > 0,
        "control-flow offset operands are actually patched: {}",
        g.cf
    );
    assert!(
        g.records < g.total * 50 / 100,
        "patched records bounded (not full-stream) < 50%: {}/{} = {rec_frac:.3}",
        g.records,
        g.total
    );
    println!("instr-shard fields A={} B={} C={} (total {fields}); SET SETTABLE={} SETGLOBAL={} SETUPVAL={} (total {set_fields}); sidecar fields={} in {} records; CF fields={} in {} records; records {}/{} = {:.1}%", g.a, g.b, g.c, g.set_table, g.set_global, g.set_upval, g.side, g.side_records, g.cf, g.cf_records, g.records, g.total, rec_frac * 100.0);
}

#[test]
fn instr_shard_bc_roles_are_declared_safe_and_control_flow_excluded() {
    use bytecode::opcode::{patch_role, Opcode, OperandRole, ALL};
    let safe = |r: OperandRole| {
        matches!(
            r,
            OperandRole::DstReg
                | OperandRole::SrcReg
                | OperandRole::TableReg
                | OperandRole::ConstIdx
                | OperandRole::UpvalIdx
                | OperandRole::ImmBool
        )
    };
    for (op, name) in ALL {
        for slot in 0..3usize {
            let r = patch_role(*op, slot);
            if r != OperandRole::None {
                assert!(safe(r), "{name} slot {slot} is patchable but role {r:?} is not in the declared-safe set");
            }
        }
    }

    let fully_excluded = [
        Opcode::Jmp,
        Opcode::JmpIf,
        Opcode::JmpIfNot,
        Opcode::Call,
        Opcode::Return,
        Opcode::Vararg,
        Opcode::Closure,
        Opcode::ForPrep,
        Opcode::ForLoop,
        Opcode::TForCall,
        Opcode::TForLoop,
        Opcode::Close,
        Opcode::EncFunc,
        Opcode::Crash,
        Opcode::SetList,
        Opcode::Eq,
        Opcode::Lt,
        Opcode::EqK,
    ];
    for op in fully_excluded {
        for slot in 0..3usize {
            assert_eq!(
                patch_role(op, slot),
                OperandRole::None,
                "control-flow/count/compare op {op:?} slot {slot} must never be patchable"
            );
        }
    }
    let expect = |op: Opcode| (patch_role(op, 0), patch_role(op, 1), patch_role(op, 2));
    use OperandRole::*;
    assert_eq!(
        expect(Opcode::Move),
        (DstReg, SrcReg, None),
        "MOVE: A dst, B src reg, C unused"
    );
    assert_eq!(
        expect(Opcode::LoadK),
        (DstReg, ConstIdx, None),
        "LOADK: B const index"
    );
    assert_eq!(
        expect(Opcode::LoadNil),
        (DstReg, None, None),
        "LOADNIL: A only (B is a count -> excluded)"
    );
    assert_eq!(
        expect(Opcode::NewTable),
        (DstReg, None, None),
        "NEWTABLE: A only (B/C size hints unused)"
    );
    assert_eq!(
        expect(Opcode::GetTable),
        (DstReg, SrcReg, SrcReg),
        "GETTABLE: B/C src regs"
    );
    assert_eq!(
        expect(Opcode::Self_),
        (DstReg, SrcReg, ConstIdx),
        "SELF: B table reg, C method const"
    );
    assert_eq!(
        expect(Opcode::Add),
        (DstReg, SrcReg, SrcReg),
        "ADD: B/C src regs"
    );
    assert_eq!(
        expect(Opcode::AddK),
        (DstReg, None, ConstIdx),
        "ADDK: B unused (R[a] op K[c]), C const"
    );
    assert_eq!(
        expect(Opcode::GetUpval),
        (DstReg, UpvalIdx, None),
        "GETUPVAL: B upvalue index"
    );
    assert_eq!(
        expect(Opcode::LoadBool),
        (DstReg, ImmBool, None),
        "LOADBOOL: B immediate bool"
    );
    assert_eq!(
        expect(Opcode::SetGlobal),
        (SrcReg, ConstIdx, None),
        "SETGLOBAL: A value reg, B global-name const, C unused"
    );
    assert_eq!(
        expect(Opcode::SetUpval),
        (SrcReg, UpvalIdx, None),
        "SETUPVAL: A value reg, B upvalue index, C unused"
    );
    assert_eq!(
        expect(Opcode::SetTable),
        (TableReg, SrcReg, SrcReg),
        "SETTABLE: A table reg, B key reg, C value reg"
    );
    assert_eq!(
        expect(Opcode::SetList),
        (None, None, None),
        "SETLIST stays excluded: B count (0='to top'), C base"
    );
}

#[test]
fn controlflow_selfpatch_role_table_is_pinned_and_disjoint_from_data() {
    use bytecode::opcode::{
        patch_cf_role, patch_role, patch_sidecar_role, Opcode, OperandRole::*, ALL,
    };
    let cf = |op: Opcode| {
        (
            patch_cf_role(op, 0),
            patch_cf_role(op, 1),
            patch_cf_role(op, 2),
        )
    };
    assert_eq!(
        cf(Opcode::Jmp),
        (RelJump, None, None),
        "JMP: A = relative signed offset (pc = pc + a)"
    );
    assert_eq!(
        cf(Opcode::JmpIf),
        (None, RelJump, None),
        "JMPIF: B = offset, A = tested register"
    );
    assert_eq!(
        cf(Opcode::JmpIfNot),
        (None, RelJump, None),
        "JMPIFNOT: B = offset, A = tested register"
    );
    assert_eq!(
        cf(Opcode::ForPrep),
        (None, RelJump, None),
        "FORPREP: B = offset, A = numeric base register"
    );
    assert_eq!(
        cf(Opcode::ForLoop),
        (None, RelJump, None),
        "FORLOOP: B = back-edge offset, A = numeric base register"
    );
    assert_eq!(
        cf(Opcode::TForLoop),
        (None, RelJump, None),
        "TFORLOOP: B = back-edge offset, A = iterator base register"
    );

    let cf_excluded = [
        Opcode::TForCall,
        Opcode::Call,
        Opcode::Return,
        Opcode::Vararg,
        Opcode::Closure,
        Opcode::Close,
        Opcode::SetList,
        Opcode::EncFunc,
        Opcode::Crash,
        Opcode::Eq,
        Opcode::Lt,
        Opcode::EqK,
        Opcode::Move,
        Opcode::LoadK,
        Opcode::Add,
    ];
    for op in cf_excluded {
        for slot in 0..3usize {
            assert_eq!(
                patch_cf_role(op, slot),
                None,
                "{op:?} slot {slot} is not a relative-pc offset and must not be CF-patchable"
            );
        }
    }

    assert_eq!(
        patch_cf_role(Opcode::ForLoop, 0),
        None,
        "FORLOOP slot A (numeric base register) never patched"
    );
    assert_eq!(
        patch_cf_role(Opcode::TForLoop, 0),
        None,
        "TFORLOOP slot A (iterator base register) never patched"
    );
    assert_eq!(
        patch_cf_role(Opcode::JmpIf, 0),
        None,
        "JMPIF slot A (tested register) never patched"
    );
    assert_eq!(
        patch_cf_role(Opcode::Jmp, 1),
        None,
        "JMP slot B (unused) never patched"
    );

    for (op, name) in ALL {
        for slot in 0..3usize {
            let dr = patch_role(*op, slot);
            let cr = patch_cf_role(*op, slot);
            assert!(
                !(dr != None && cr != None),
                "{name} slot {slot}: data and control-flow streams both patch it"
            );
            assert_ne!(
                dr, RelJump,
                "{name} slot {slot}: the data patch_role must never return RelJump"
            );
            if cr != None {
                assert_eq!(
                    cr, RelJump,
                    "{name} slot {slot}: the only control-flow role is RelJump"
                );
            }
        }
        if bytecode::superop::is_super(*op) {
            for i in 0..bytecode::superop::operand_count(*op) {
                assert_ne!(
                    patch_sidecar_role(*op, i),
                    RelJump,
                    "{name} sidecar {i}: sidecars carry no control flow"
                );
            }
        }
    }
}

fn walk_cf_divergence(
    p: &bytecode::Proto,
    pid: &mut u32,
    genkey: &[u32; 8],
    seed: u64,
    checked: &mut usize,
    misled: &mut usize,
) {
    use bytecode::opcode::{patch_cf_role, OperandRole};
    let this = *pid;
    *pid += 1;
    let cfk = bytecode::crypt::instr_patch_key(
        genkey,
        this,
        bytecode::crypt::controlflow_patch_domain(seed),
    );
    for (pc0, inst) in p.code.iter().enumerate() {
        let pc = pc0 as u32 + 1;
        for slot in 0..3usize {
            if patch_cf_role(inst.op, slot) != OperandRole::None {
                *checked += 1;
                let cid = bytecode::crypt::CONTROLFLOW_SLOT_BASE + slot as u32;
                if bytecode::crypt::instr_patch_selected(cfk, pc, cid) {
                    let real = match slot {
                        0 => inst.a,
                        1 => inst.b,
                        _ => inst.c,
                    };
                    let delta = bytecode::crypt::instr_patch_delta(cfk, pc, cid) as i32;
                    let real_target = pc0 as i64 + 1 + real as i64;
                    let rest_target = pc0 as i64 + 1 + (real + delta) as i64;
                    assert_ne!(
                        real_target, rest_target,
                        "a selected control-flow site must move its apparent target"
                    );
                    *misled += 1;
                }
            }
        }
    }
    for c in &p.protos {
        walk_cf_divergence(c, pid, genkey, seed, checked, misled);
    }
}

#[test]
fn at_rest_offsets_diverge_from_targets() {
    let src = "local function f(n)\n\
          local s = 0\n\
          if n % 2 == 0 then s = s + 1 else s = s - 1 end\n\
          local i = 0\n\
          while i < n do s = s + i i = i + 1 if s > 100 then break end end\n\
          repeat s = s - 1 until s <= 0\n\
          for k = 1, n do s = s + k * 2 if k == 3 then return s end end\n\
          local t = { 4, 5, 6 }\n\
          for _, v in ipairs(t) do s = s + v end\n\
          return s\n\
        end\n\
        return f(9)\n";
    let (mut checked, mut misled) = (0usize, 0usize);
    for seed in [0x_C0FF_EE01u64, 0x_C0FF_EE02, 0x_C0FF_EE03] {
        let proto = compile_final(src, seed);
        let enc = bytecode::encoding::Encoding::from_seed(seed);
        let genkey = bytecode::encoder::payload_genkey(
            &proto,
            seed,
            &enc,
            false,
            pipeline::TargetProfile::CliTest,
            false,
        );
        let mut pid = 0u32;
        walk_cf_divergence(&proto, &mut pid, &genkey, seed, &mut checked, &mut misled);
    }
    assert!(
        checked > 0,
        "the CFG-heavy proto has control-flow offset sites"
    );
    assert!(
        misled > 0,
        "at least one at-rest offset diverges from its real target — a naive static CFG is wrong"
    );
    println!("CFG static-dump audit: {misled}/{checked} control-flow offset sites wrong at rest across 3 seeds");
}

#[test]
fn superop_roles_exclude_dangerous() {
    use bytecode::opcode::Opcode::*;
    use bytecode::opcode::{patch_sidecar_role, OperandRole, OperandRole::*};
    use bytecode::superop::{self, CATALOGUE};
    let safe = |r: OperandRole| {
        matches!(
            r,
            DstReg | SrcReg | TableReg | ConstIdx | UpvalIdx | ImmBool
        )
    };
    for (op, _subs) in CATALOGUE {
        let cnt = superop::operand_count(*op);
        for i in 0..cnt {
            let r = patch_sidecar_role(*op, i);
            if r != None {
                assert!(
                    safe(r),
                    "{op:?} sidecar {i}: role {r:?} is not in the declared-safe set"
                );
            }
        }
        assert_eq!(
            patch_sidecar_role(*op, cnt),
            None,
            "{op:?}: out-of-range sidecar index is unpatchable"
        );
    }

    for i in 0..superop::operand_count(Super8) {
        assert_eq!(
            patch_sidecar_role(Super8, i),
            None,
            "Super8 (contains LtK compare) sidecar {i} must be unpatchable"
        );
    }

    assert_eq!(
        patch_sidecar_role(Move, 0),
        None,
        "a non-super opcode has no sidecar role"
    );

    let pin = |op: bytecode::opcode::Opcode, roles: &[OperandRole]| {
        for (i, &want) in roles.iter().enumerate() {
            assert_eq!(patch_sidecar_role(op, i), want, "{op:?} sidecar {i}");
        }
    };
    pin(
        Super0,
        &[
            DstReg, SrcReg, None, DstReg, ConstIdx, None, DstReg, SrcReg, SrcReg,
        ],
    );
    pin(
        Super1,
        &[
            DstReg, ConstIdx, None, DstReg, SrcReg, SrcReg, DstReg, SrcReg, None,
        ],
    );
    pin(
        Super2,
        &[
            DstReg, ConstIdx, None, DstReg, ConstIdx, None, DstReg, SrcReg, None,
        ],
    );
    pin(Super3, &[DstReg, SrcReg, None, DstReg, ConstIdx, None]);
    pin(Super4, &[DstReg, ConstIdx, None, DstReg, SrcReg, SrcReg]);
    pin(Super5, &[DstReg, ConstIdx, None, DstReg, ConstIdx, None]);
    pin(Super6, &[DstReg, SrcReg, SrcReg, DstReg, SrcReg, None]);
    pin(Super7, &[DstReg, SrcReg, None, DstReg, SrcReg, None]);
    pin(
        Super8,
        &[None, None, None, None, None, None, None, None, None],
    );
    pin(Super9, &[DstReg, ConstIdx, None, DstReg, ConstIdx, None]);
}
