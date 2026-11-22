use crate::rng::Rng;

const DOMAIN: u64 = 0x_5041_434B_4552_30;

pub(crate) fn safe_set() -> Vec<u8> {
    (33u8..=126)
        .filter(|c| *c != 34 && *c != 92 && *c != 93)
        .take(85)
        .collect()
}

fn xorshift32(mut x: u32) -> u32 {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}

fn pseed_of(seed: u64) -> u32 {
    (Rng::new(seed ^ (DOMAIN ^ 0x_5053_4545_44)).next() as u32) | 1
}

fn permute_x(pseed: u32) -> Vec<u8> {
    let mut v = safe_set();
    let mut st = pseed;
    for i in (1..85usize).rev() {
        st = xorshift32(st);
        let j = (st % (i as u32 + 1)) as usize;
        v.swap(i, j);
    }
    v
}

pub(crate) fn encode_b85(bytes: &[u8], ab: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(4) * 5);
    for chunk in bytes.chunks(4) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).map_or(0, |&b| b as u32);
        let b2 = chunk.get(2).map_or(0, |&b| b as u32);
        let b3 = chunk.get(3).map_or(0, |&b| b as u32);
        let mut n = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        let mut group = [0u8; 5];
        for slot in group.iter_mut().rev() {
            *slot = ab[(n % 85) as usize];
            n /= 85;
        }
        out.extend(group.iter().map(|&c| c as char));
    }
    out
}

#[cfg(test)]
pub(crate) fn decode_b85(s: &str, ab: &[u8]) -> Vec<u8> {
    let mut rev = [0u64; 256];
    for (i, &c) in ab.iter().enumerate() {
        rev[c as usize] = i as u64;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 5 * 4);
    let mut pos = 0;
    while pos + 5 <= b.len() {
        let n = rev[b[pos] as usize] * 52_200_625
            + rev[b[pos + 1] as usize] * 614_125
            + rev[b[pos + 2] as usize] * 7_225
            + rev[b[pos + 3] as usize] * 85
            + rev[b[pos + 4] as usize];
        out.push((n >> 24 & 255) as u8);
        out.push((n >> 16 & 255) as u8);
        out.push((n >> 8 & 255) as u8);
        out.push((n & 255) as u8);
        pos += 5;
    }
    out
}

#[derive(Clone, Copy)]
enum Coeff {
    Poly,
    Horner,
}
#[derive(Clone, Copy)]
enum Extract {
    DivMod,
    SubDiv,
}
#[derive(Clone, Copy)]
enum LoopKind {
    While,
    For,
}

struct Namer {
    tag: String,
    n: usize,
}
impl Namer {
    fn fresh(&mut self) -> String {
        self.n += 1;
        format!("{}{}", self.tag, self.n)
    }
}

fn make_tag(seed: u64) -> String {
    let mut rng = Rng::new(seed ^ (DOMAIN ^ 0x_5441_47));
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    (0..3)
        .map(|_| letters[rng.below(26) as usize] as char)
        .collect()
}

pub struct Plan {
    seed: u64,
    variant: u8,
    alphabet: Vec<u8>,
    pseed: u32,
    coeff: Coeff,
    extract: Extract,
    loopk: LoopKind,
    chunks: usize,
    shuffle_chunks: bool,
    per_chunk_decode: bool,
    prefix_bytes: usize,
    geo: Geo,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Geo {
    Array,
    SeparateLocals,
    TwoGroups,
}

#[cfg(test)]
pub struct Audit {
    pub variant_id: u8,
    pub canonical_alphabet: bool,
    pub chunk_count: usize,
    pub shuffled: bool,
    pub per_chunk_decode: bool,
    pub alphabet: Vec<u8>,
}

impl Plan {
    pub fn for_seed(seed: u64, heavy: bool) -> Self {
        let mut rng = Rng::new(seed ^ DOMAIN);
        let variant = if heavy {
            5
        } else {
            match rng.below(10) {
                0 => 0,
                1 | 2 | 3 => 1,
                4 | 5 | 6 => 2,
                7 | 8 => 3,
                _ => 4,
            }
        };
        Self::build(variant, seed, heavy)
    }

    #[cfg(test)]
    pub fn variant(v: u8, seed: u64, heavy: bool) -> Self {
        Self::build(v, seed, heavy)
    }

    fn build(variant: u8, seed: u64, heavy: bool) -> Self {
        let mut rng = Rng::new(seed ^ (DOMAIN ^ 0x_4B4E_4F42));
        let pseed = pseed_of(seed);
        let alphabet = permute_x(pseed);
        let coeff = if rng.below(2) == 0 {
            Coeff::Poly
        } else {
            Coeff::Horner
        };
        let extract = if rng.below(2) == 0 {
            Extract::DivMod
        } else {
            Extract::SubDiv
        };
        let loopk = if rng.below(2) == 0 {
            LoopKind::While
        } else {
            LoopKind::For
        };
        let chunks = match variant {
            0 | 1 => 1,
            4 => 2 + rng.below(6) as usize,
            _ => 3 + rng.below(7) as usize,
        };
        let shuffle_chunks = variant == 3 || (variant == 5 && rng.below(2) == 0);
        let per_chunk_decode = chunks > 1 && rng.below(2) == 0;
        let prefix_bytes = if variant == 4 {
            4 + rng.below(9) as usize
        } else {
            0
        };
        let geo = if chunks > 1 && !per_chunk_decode {
            match rng.below(3) {
                0 => Geo::SeparateLocals,
                1 => Geo::TwoGroups,
                _ => Geo::Array,
            }
        } else {
            Geo::Array
        };
        let _ = heavy;
        Plan {
            seed,
            variant,
            alphabet,
            pseed,
            coeff,
            extract,
            loopk,
            chunks,
            shuffle_chunks,
            per_chunk_decode,
            prefix_bytes,
            geo,
        }
    }

    #[cfg(test)]
    pub fn audit(&self) -> Audit {
        Audit {
            variant_id: self.variant,
            canonical_alphabet: self.alphabet == safe_set(),
            chunk_count: self.chunks,
            shuffled: self.shuffle_chunks,
            per_chunk_decode: self.per_chunk_decode,
            alphabet: self.alphabet.clone(),
        }
    }

    pub fn emit(
        &self,
        payload: &[u8],
        wrap: (&str, &str),
        ink: &mut Option<surface::meme::MemeInk>,
    ) -> String {
        let mut namer = Namer {
            tag: make_tag(self.seed),
            n: 0,
        };
        let mut rng = Rng::new(self.seed ^ (DOMAIN ^ 0x_454D_4954));
        let mut parts: Vec<String> = Vec::new();

        let (rm_decls, rm) = emit_rm(&mut namer, self.pseed, ink);
        parts.push(rm_decls);
        let (dec_decls, f) = emit_decoder(&mut namer, &rm, self.coeff, self.extract, self.loopk);
        parts.push(dec_decls);

        let (enc_bytes, prefix_expr) = if self.prefix_bytes > 0 {
            let k = self.prefix_bytes.min(payload.len().saturating_sub(1));
            if k == 0 {
                (payload, None)
            } else {
                let (pre, rest) = payload.split_at(k);
                let pre = pre
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                (rest, Some(format!("char({pre})")))
            }
        } else {
            (payload, None)
        };
        let enc = encode_b85(enc_bytes, &self.alphabet);
        parts.push(self.emit_payload_assign(&mut namer, &mut rng, &f, &enc, prefix_expr, wrap));

        parts.join("\n")
    }

    fn emit_payload_assign(
        &self,
        namer: &mut Namer,
        rng: &mut Rng,
        f: &str,
        enc: &str,
        prefix: Option<String>,
        wrap: (&str, &str),
    ) -> String {
        let groups = enc.len() / 5;
        let n = self.chunks.max(1).min(groups.max(1));
        let chunks = split_groups(enc, n);
        let mut decls: Vec<String> = Vec::new();
        let core_expr;
        if n <= 1 {
            let lit = chunks.first().copied().unwrap_or("");
            if self.variant == 0 {
                core_expr = format!("{f}([==[{lit}]==])");
            } else {
                let c = namer.fresh();
                decls.push(format!("local {c} = [==[{lit}]==]"));
                core_expr = format!("{f}({c})");
            }
        } else if self.geo == Geo::SeparateLocals {
            let names: Vec<String> = (0..n).map(|_| namer.fresh()).collect();
            let mut phys: Vec<usize> = (0..n).collect();
            rng.shuffle(&mut phys);
            for &k in &phys {
                decls.push(format!("local {} = [==[{}]==]", names[k], chunks[k]));
            }
            let logical = (0..n)
                .map(|k| names[k].as_str())
                .collect::<Vec<_>>()
                .join(" .. ");
            core_expr = format!("{f}({logical})");
        } else if self.geo == Geo::TwoGroups {
            let mid = 1 + (n - 1) / 2;
            let a = namer.fresh();
            let b = namer.fresh();
            let lits_a = chunks[..mid]
                .iter()
                .map(|c| format!("[==[{c}]==]"))
                .collect::<Vec<_>>()
                .join(", ");
            let lits_b = chunks[mid..]
                .iter()
                .map(|c| format!("[==[{c}]==]"))
                .collect::<Vec<_>>()
                .join(", ");
            if rng.below(2) == 0 {
                decls.push(format!("local {b} = {{ {lits_b} }}"));
                decls.push(format!("local {a} = {{ {lits_a} }}"));
            } else {
                decls.push(format!("local {a} = {{ {lits_a} }}"));
                decls.push(format!("local {b} = {{ {lits_b} }}"));
            }
            core_expr = format!("{f}(concat({a}) .. concat({b}))");
        } else {
            let arr = namer.fresh();
            if self.shuffle_chunks {
                decls.push(format!("local {arr} = {{}}"));
                let mut order: Vec<usize> = (0..n).collect();
                rng.shuffle(&mut order);
                for &k in &order {
                    decls.push(format!("{arr}[{}] = [==[{}]==]", k + 1, chunks[k]));
                }
            } else {
                let lits = chunks
                    .iter()
                    .map(|c| format!("[==[{c}]==]"))
                    .collect::<Vec<_>>()
                    .join(", ");
                decls.push(format!("local {arr} = {{ {lits} }}"));
            }
            if self.per_chunk_decode {
                let r = namer.fresh();
                let i = namer.fresh();
                decls.push(format!("local {r} = {{}}"));
                decls.push(format!(
                    "for {i} = 1, #{arr} do {r}[{i}] = {f}({arr}[{i}]) end"
                ));
                core_expr = format!("concat({r})");
            } else {
                core_expr = format!("{f}(concat({arr}))");
            }
        }
        let full = match prefix {
            Some(p) => format!("{p} .. {core_expr}"),
            None => core_expr,
        };
        decls.push(format!("local PAYLOAD = {}{}{}", wrap.0, full, wrap.1));
        decls.join("\n")
    }
}

fn split_groups(enc: &str, n: usize) -> Vec<&str> {
    let groups = enc.len() / 5;
    if groups == 0 {
        return vec![enc];
    }
    let n = n.max(1).min(groups);
    let base = groups / n;
    let rem = groups % n;
    let mut out = Vec::with_capacity(n);
    let mut start = 0;
    for k in 0..n {
        let g = base + usize::from(k < rem);
        let end = start + g * 5;
        out.push(&enc[start..end]);
        start = end;
    }
    out
}

fn emit_rm(
    namer: &mut Namer,
    pseed: u32,
    ink: &mut Option<surface::meme::MemeInk>,
) -> (String, String) {
    let rm = namer.fresh();
    let v = namer.fresh();
    let c = namer.fresh();
    let k = namer.fresh();
    let st = namer.fresh();
    let i = namer.fresh();
    let j = namer.fresh();
    let lim = ink
        .as_mut()
        .and_then(|m| m.wrap("PackerDecoder", "85"))
        .unwrap_or_else(|| "85".to_string());
    let hi = ink
        .as_mut()
        .and_then(|m| m.wrap("PackerDecoder", "255"))
        .unwrap_or_else(|| "255".to_string());
    let lim2 = ink
        .as_mut()
        .and_then(|m| m.wrap("PackerDecoder", "85"))
        .unwrap_or_else(|| "85".to_string());
    let decls = format!(
        "local {v} = {{}}\n\
         local {c} = 0\n\
         for {k} = 33, 126 do if {k} ~= 34 and {k} ~= 92 and {k} ~= 93 and {c} < {lim} then {c} = {c} + 1 {v}[{c}] = {k} end end\n\
         local {st} = 0x{pseed:X}\n\
         for {i} = 84, 1, -1 do\n\
         {st} = bxor({st}, lshift({st}, 13))\n\
         {st} = bxor({st}, rshift({st}, 17))\n\
         {st} = bxor({st}, lshift({st}, 5))\n\
         local {j} = {st} % ({i} + 1) + 1\n\
         {v}[{i} + 1], {v}[{j}] = {v}[{j}], {v}[{i} + 1]\n\
         end\n\
         local {rm} = {{}}\n\
         for {k} = 0, {hi} do {rm}[{k}] = 0 end\n\
         for {k} = 1, {lim2} do {rm}[{v}[{k}]] = {k} - 1 end"
    );
    (decls, rm)
}

fn emit_decoder(
    namer: &mut Namer,
    rm: &str,
    coeff: Coeff,
    extract: Extract,
    loopk: LoopKind,
) -> (String, String) {
    let f = namer.fresh();
    let s = namer.fresh();
    let out = namer.fresh();
    let oi = namer.fresh();
    let n = namer.fresh();
    let pos = namer.fresh();

    let read = |off: usize| -> String {
        if off == 0 {
            format!("{rm}[byte({s}, {pos})]")
        } else {
            format!("{rm}[byte({s}, {pos} + {off})]")
        }
    };
    let compute_n = match coeff {
        Coeff::Poly => format!(
            "local {n} = {} * 52200625 + {} * 614125 + {} * 7225 + {} * 85 + {}",
            read(0),
            read(1),
            read(2),
            read(3),
            read(4)
        ),
        Coeff::Horner => format!(
            "local {n} = {}\n{n} = {n} * 85 + {}\n{n} = {n} * 85 + {}\n{n} = {n} * 85 + {}\n{n} = {n} * 85 + {}",
            read(0),
            read(1),
            read(2),
            read(3),
            read(4)
        ),
    };
    let store = match extract {
        Extract::DivMod => format!(
            "{out}[{oi}] = char({n} // 16777216 % 256, {n} // 65536 % 256, {n} // 256 % 256, {n} % 256)"
        ),
        Extract::SubDiv => {
            let b0 = namer.fresh();
            let b1 = namer.fresh();
            let b2 = namer.fresh();
            let b3 = namer.fresh();
            format!(
                "local {b0} = {n} % 256\n{n} = ({n} - {b0}) / 256\nlocal {b1} = {n} % 256\n{n} = ({n} - {b1}) / 256\nlocal {b2} = {n} % 256\nlocal {b3} = ({n} - {b2}) / 256\n{out}[{oi}] = char({b3}, {b2}, {b1}, {b0})"
            )
        }
    };

    let body = match loopk {
        LoopKind::While => {
            let len = namer.fresh();
            format!(
                "local {pos} = 1\nlocal {len} = #{s}\nwhile {pos} + 4 <= {len} do\n{compute_n}\n{pos} = {pos} + 5\n{oi} = {oi} + 1\n{store}\nend"
            )
        }
        LoopKind::For => {
            format!("for {pos} = 1, #{s} - 4, 5 do\n{compute_n}\n{oi} = {oi} + 1\n{store}\nend")
        }
    };

    (
        format!("local function {f}({s})\nlocal {out} = {{}}\nlocal {oi} = 0\n{body}\nreturn concat({out})\nend"),
        f,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_set_matches_canonical_alphabet() {
        assert_eq!(safe_set(), crate::ALPHABET85.to_vec());
        assert_eq!(safe_set().len(), 85);
    }

    fn pad4(b: &[u8]) -> Vec<u8> {
        let mut v = b.to_vec();
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn encode_decode_round_trips_canonical_and_permuted() {
        let samples: Vec<Vec<u8>> = vec![
            (0u8..=255).collect(),
            b"hello world".to_vec(),
            vec![0, 0, 0, 1],
            vec![255; 37],
            (0..1000).map(|i| (i * 7 % 256) as u8).collect(),
        ];
        for seed in [0u64, 1, 0xDEAD_BEEF, 0xA5A5_5A5A, 12345] {
            for ab in [safe_set(), permute_x(pseed_of(seed))] {
                for s in &samples {
                    let enc = encode_b85(s, &ab);
                    assert_eq!(
                        decode_b85(&enc, &ab),
                        pad4(s),
                        "round-trip mismatch seed={seed}"
                    );
                }
            }
        }
    }

    #[test]
    fn deterministic_same_seed() {
        let payload: Vec<u8> = (0..500).map(|i| (i * 31 % 256) as u8).collect();
        for &heavy in &[false, true] {
            for seed in [7u64, 99, 0xFEED_FACE] {
                let a = Plan::for_seed(seed, heavy).emit(&payload, ("", ""), &mut None);
                let b = Plan::for_seed(seed, heavy).emit(&payload, ("", ""), &mut None);
                assert_eq!(a, b, "seed={seed} heavy={heavy} must be deterministic");
            }
        }
    }

    #[test]
    fn different_seeds_differ() {
        let payload: Vec<u8> = (0..500).map(|i| (i * 31 % 256) as u8).collect();
        let mut shapes = std::collections::HashSet::new();
        for seed in 0u64..24 {
            shapes.insert(Plan::for_seed(seed, false).emit(&payload, ("", ""), &mut None));
        }
        assert!(
            shapes.len() >= 20,
            "expected mostly-distinct shapes across 24 seeds, got {}",
            shapes.len()
        );
    }

    #[test]
    fn every_variant_round_trips_via_rust_mirror() {
        let payload: Vec<u8> = (0..733).map(|i| ((i * 13 + 5) % 256) as u8).collect();
        for v in 0u8..=5 {
            for seed in [1u64, 2, 3, 0xBEEF, 0x1234_5678] {
                let plan = Plan::variant(v, seed, v == 5);
                assert_eq!(plan.audit().variant_id, v);
                let k = if plan.prefix_bytes > 0 {
                    plan.prefix_bytes.min(payload.len().saturating_sub(1))
                } else {
                    0
                };
                let (pre, rest) = payload.split_at(k);
                let enc = encode_b85(rest, &plan.alphabet);
                let mut got = pre.to_vec();
                got.extend(decode_b85(&enc, &plan.alphabet));
                got.truncate(payload.len());
                assert_eq!(got, payload, "variant {v} seed {seed} byte mismatch");
            }
        }
    }

    #[test]
    fn no_forbidden_apis_in_emitted_code() {
        let payload: Vec<u8> = (0..600).map(|i| (i % 256) as u8).collect();
        for &heavy in &[false, true] {
            for seed in 0u64..16 {
                let code = Plan::for_seed(seed, heavy).emit(&payload, ("lzwdec(", ")"), &mut None);
                for bad in [
                    "loadstring",
                    "load(",
                    "HttpService",
                    "HttpGet",
                    "GetAsync",
                    "PostAsync",
                    "require",
                    "getfenv",
                    "setfenv",
                    "://",
                ] {
                    assert!(
                        !code.contains(bad),
                        "emitted packer must not contain {bad:?} (seed={seed})"
                    );
                }
            }
        }
    }

    #[test]
    fn exactly_one_alphabet_rebuild_in_every_configuration() {
        let payload: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        for &heavy in &[false, true] {
            for seed in 0u64..40 {
                let code = Plan::for_seed(seed, heavy).emit(&payload, ("", ""), &mut None);
                assert_eq!(
                    code.matches("= 33, 126 do").count(),
                    1,
                    "exactly one real alphabet rebuild; decoy packers were removed 2026-08-05 \
                     (seed={seed} heavy={heavy})"
                );
            }
        }
    }

    #[test]
    fn no_discarded_reference_table_or_decoy_blob_is_emitted() {
        let payload: Vec<u8> = (0..900).map(|i| (i % 251) as u8).collect();
        for &heavy in &[false, true] {
            for seed in 0u64..24 {
                let code = Plan::for_seed(seed, heavy).emit(&payload, ("", ""), &mut None);
                let decoders = code.matches("local function ").count();
                assert_eq!(
                    decoders, 1,
                    "exactly one decoder function; no decoy decoders (seed={seed} heavy={heavy})"
                );
                let blobs: Vec<usize> = code
                    .match_indices("[==[")
                    .map(|(i, _)| code[i + 4..].find("]==]").unwrap_or(0))
                    .collect();
                assert!(
                    blobs.iter().all(|&l| l >= 40),
                    "no short random decoy blob may remain (seed={seed} heavy={heavy}): {blobs:?}"
                );
            }
        }
    }

    #[test]
    fn no_payload_plaintext_leaks_into_the_packer() {
        let marker = b"hydroxide-SECRET-MARKER-string-value";
        let mut payload = marker.to_vec();
        payload.extend((0..400).map(|i| (i % 256) as u8));
        for &heavy in &[false, true] {
            for seed in 0u64..12 {
                let code = Plan::for_seed(seed, heavy).emit(&payload, ("", ""), &mut None);
                assert!(
                    !code.contains("hydroxide"),
                    "packer must not embed plaintext marker (seed={seed} heavy={heavy})"
                );
            }
        }
    }

    #[test]
    fn audit_flags_reflect_variant() {
        for seed in [1u64, 2, 7, 0xABCD, 0x9999] {
            let v3 = Plan::variant(3, seed, false).audit();
            assert!(v3.shuffled, "variant 3 must shuffle chunks (seed={seed})");
            assert!(v3.chunk_count > 1);
            for v in 0u8..=5 {
                let a = Plan::variant(v, seed, v == 5).audit();
                if a.per_chunk_decode {
                    assert!(
                        a.chunk_count > 1,
                        "per-chunk decode requires >1 chunk (v={v} seed={seed})"
                    );
                }
            }
        }
    }

    #[test]
    fn shape_diversity_across_seeds() {
        let seeds: Vec<u64> = (0u64..24).collect();
        let mut alphabets = std::collections::HashSet::new();
        let mut canonical = 0;
        let mut single_chunk = 0;
        for &s in &seeds {
            let a = Plan::for_seed(s, false).audit();
            alphabets.insert(a.alphabet.clone());
            if a.canonical_alphabet {
                canonical += 1;
            }
            if a.chunk_count <= 1 {
                single_chunk += 1;
            }
        }
        assert!(
            canonical < seeds.len(),
            "not every build may use the canonical alphabet"
        );
        assert!(
            single_chunk < seeds.len(),
            "not every build may be a single blob"
        );
        assert!(
            alphabets.len() >= 10,
            "expected many distinct alphabets, got {}",
            alphabets.len()
        );
    }

    #[test]
    fn t0_same_seed_same_alphabet() {
        for &heavy in &[false, true] {
            for seed in [1u64, 305419896, 0xFEED_FACE] {
                assert_eq!(
                    Plan::for_seed(seed, heavy).audit().alphabet,
                    Plan::for_seed(seed, heavy).audit().alphabet,
                    "same seed/settings must yield the same alphabet"
                );
            }
        }
    }

    #[test]
    fn t0_different_seed_different_alphabet() {
        let mut set = std::collections::HashSet::new();
        for seed in 0u64..24 {
            set.insert(Plan::for_seed(seed, false).audit().alphabet);
        }
        assert!(
            set.len() >= 20,
            "expected distinct per-seed alphabets, got {}",
            set.len()
        );

        for seed in 0u64..24 {
            assert_ne!(
                Plan::for_seed(seed, false).audit().alphabet,
                crate::ALPHABET85.to_vec()
            );
            assert_ne!(
                Plan::for_seed(seed, true).audit().alphabet,
                crate::ALPHABET85.to_vec()
            );
        }
    }

    #[test]
    fn t0_transport_decode_matches_encoder() {
        let payload: Vec<u8> = (0..733).map(|i| ((i * 13 + 5) % 256) as u8).collect();
        for &heavy in &[false, true] {
            for seed in [1u64, 2, 305419896, 0xBEEF] {
                let ab = Plan::for_seed(seed, heavy).audit().alphabet;
                let dec = decode_b85(&encode_b85(&payload, &ab), &ab);
                assert_eq!(
                    &dec[..payload.len()],
                    &payload[..],
                    "decode must match the encoder alphabet"
                );
            }
        }
    }

    #[test]
    fn t0_no_static_default_alphabet_literal() {
        let payload: Vec<u8> = (0..600).map(|i| (i % 256) as u8).collect();
        let canon: String = crate::ALPHABET85.iter().map(|&c| c as char).collect();
        for &heavy in &[false, true] {
            for seed in 0u64..16 {
                let code = Plan::for_seed(seed, heavy).emit(&payload, ("", ""), &mut None);
                assert!(
                    !code.contains(&canon),
                    "canonical default alphabet must never appear (seed={seed})"
                );
            }
        }
    }

    #[test]
    fn t0_no_contiguous_85_char_alphabet_literal() {
        let payload: Vec<u8> = (0..600).map(|i| ((i * 7 + 3) % 256) as u8).collect();
        for &heavy in &[false, true] {
            for seed in 0u64..16 {
                let plan = Plan::for_seed(seed, heavy);
                let ab: String = plan.audit().alphabet.iter().map(|&c| c as char).collect();
                let code = plan.emit(&payload, ("", ""), &mut None);
                assert!(
                    !code.contains(&ab),
                    "the per-build alphabet must not appear as a contiguous literal (seed={seed} heavy={heavy})"
                );
            }
        }
    }

    #[test]
    fn t0_normal_and_heavy_outputs_differ() {
        let payload: Vec<u8> = (0..500).map(|i| (i * 31 % 256) as u8).collect();
        for seed in [1u64, 7, 305419896] {
            let n = Plan::for_seed(seed, false).emit(&payload, ("", ""), &mut None);
            let h = Plan::for_seed(seed, true).emit(&payload, ("", ""), &mut None);
            assert_ne!(
                n, h,
                "normal and heavy packer output must differ (seed={seed})"
            );
        }
    }
}
