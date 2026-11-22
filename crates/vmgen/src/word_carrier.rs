use crate::rng::Rng;

const DOMAIN: u64 = 0x_574F_5244_4341_5252;

pub struct Names<'a> {
    pub byte: &'a str,
    pub char: &'a str,
    pub concat: &'a str,
    pub sub: &'a str,
    pub genv: &'a str,
}

fn distinct_alphabet(data: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut set: Vec<u8> = data
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<u8>>()
        .into_iter()
        .collect();
    if set.is_empty() {
        set.push(0);
    }
    for i in (1..set.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        set.swap(i, j);
    }
    set
}

fn bits_for(n: usize) -> u32 {
    let mut b = 1u32;
    while (1usize << b) < n {
        b += 1;
    }
    b.max(1)
}

fn pack_codes_msb(codes: &[u32], bits: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut nb = 0u32;
    for &c in codes {
        acc = (acc << bits) | c as u64;
        nb += bits;
        while nb >= 8 {
            nb -= 8;
            out.push((acc >> nb) as u8);
        }
    }
    if nb > 0 {
        out.push((acc << (8 - nb)) as u8);
    }
    out
}

fn pack_words_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|c| {
            let mut w = 0u32;
            for i in 0..4 {
                w |= (*c.get(i).unwrap_or(&0) as u32) << (8 * i);
            }
            w
        })
        .collect()
}

fn distinct_keys(rng: &mut Rng, count: usize) -> Vec<u64> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let k = 1 + rng.next() % 60000;
        if seen.insert(k) {
            out.push(k);
        }
    }
    out
}

fn word_array(words: &[u32], hex: bool) -> String {
    let mut s = String::from("{");
    for (i, &w) in words.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        if hex {
            s.push_str(&format!("0x{w:X}"));
        } else {
            s.push_str(&w.to_string());
        }
    }
    s.push('}');
    s
}

pub fn emit_expr(data: &[u8], seed: u64, domain: u64, names: &Names) -> String {
    let mut rng = Rng::new(seed ^ DOMAIN ^ domain);
    let use_buffer = rng.next() % 2 == 0;
    let hex = rng.next() % 2 == 0;

    let alpha = distinct_alphabet(data, &mut rng);
    let bits = bits_for(alpha.len());
    let index: std::collections::HashMap<u8, u32> = alpha
        .iter()
        .enumerate()
        .map(|(i, &b)| (b, i as u32))
        .collect();
    let codes: Vec<u32> = data.iter().map(|b| index[b]).collect();

    let aw = pack_words_le(&alpha);

    let (b, c, cc, sub, genv) = (names.byte, names.char, names.concat, names.sub, names.genv);

    let arith_tail = format!(
        "local _t={{}}for _i=1,#_W do local _w=_W[_i] _t[_i]={c}(_w%256,(_w//256)%256,(_w//65536)%256,(_w//16777216))end return {cc}(_t)"
    );
    let w2b_body = if use_buffer {
        format!(
            "local _bf={genv}[{c}(98,117,102,102,101,114)]if _bf and _bf.create then local _bu=_bf.create(#_W*4)for _i=1,#_W do _bf.writeu32(_bu,(_i-1)*4,_W[_i])end return _bf.tostring(_bu)end {arith_tail}"
        )
    } else {
        arith_tail
    };

    let wpb = [10usize, 12, 14][(rng.next() % 3) as usize];
    let aw_concat = aw
        .chunks(wpb)
        .map(|ch| format!("_w2b({})", word_array(ch, hex)))
        .collect::<Vec<_>>()
        .join("..");
    let cpb = (wpb * 32 / bits as usize).max(1);
    let blocks: Vec<(String, usize, usize)> = codes
        .chunks(cpb)
        .enumerate()
        .map(|(i, ch)| {
            (
                word_array(&pack_words_le(&pack_codes_msb(ch, bits)), hex),
                ch.len(),
                i * cpb,
            )
        })
        .collect();
    let n = blocks.len();
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    let keys = distinct_keys(&mut rng, n.max(1));
    let mut brem: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        brem.swap(i, j);
    }
    let mut branches = String::new();
    let mut first = true;
    for &p in &brem {
        let (wl, cn, off) = &blocks[order[p]];
        let nextk = if p + 1 < n { keys[p + 1] } else { 0 };
        let kw = if first { "if" } else { "elseif" };
        first = false;
        branches.push_str(&format!(
            "{kw} _s=={} then _e({wl},{cn},{off}) _s={nextk} ",
            keys[p]
        ));
    }
    let first_key = if n == 0 { 0 } else { keys[0] };

    format!(
        "(function()\nlocal function _w2b(_W){w2b_body} end\nlocal _A={aw_concat}\nlocal _o={{}}\nlocal function _e(_W,_cn,_of)\nlocal _P=_w2b(_W)\nlocal _ac,_nb,_pi=0,0,0\nfor _k=1,_cn do\nwhile _nb<{bits} do _pi=_pi+1 _ac=_ac*256+{b}(_P,_pi) _nb=_nb+8 end\nlocal _sh=2^(_nb-{bits})local _cd=_ac//_sh _ac=_ac-_cd*_sh _nb=_nb-{bits}\n_o[_of+_k]={sub}(_A,_cd+1,_cd+1)\nend\nend\nlocal _s={first_key}\nwhile _s~=0 do\n{branches}end\nend\nreturn {cc}(_o)\nend)()"
    )
}

pub fn mirror(data: &[u8], seed: u64, domain: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed ^ DOMAIN ^ domain);
    let _use_buffer = rng.next() % 2 == 0;
    let _hex = rng.next() % 2 == 0;
    let alpha = distinct_alphabet(data, &mut rng);
    let bits = bits_for(alpha.len());
    let index: std::collections::HashMap<u8, u32> = alpha
        .iter()
        .enumerate()
        .map(|(i, &b)| (b, i as u32))
        .collect();
    let codes: Vec<u32> = data.iter().map(|b| index[b]).collect();
    let packed = pack_codes_msb(&codes, bits);

    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut nb = 0u32;
    let mut pi = 0usize;
    for _ in 0..data.len() {
        while nb < bits {
            acc = acc * 256 + packed[pi] as u64;
            pi += 1;
            nb += 8;
        }
        let sh = 1u64 << (nb - bits);
        let cd = (acc / sh) as usize;
        acc -= cd as u64 * sh;
        nb -= bits;
        out.push(alpha[cd]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn max_string_literal(s: &str) -> usize {
        let b = s.as_bytes();
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
                    if let Some(e) = s[j + 1..].find(&close) {
                        max = max.max(e);
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
                max = max.max(j.saturating_sub(i + 1));
                i = j + 1;
                continue;
            }
            i += 1;
        }
        max
    }

    #[test]
    fn emit_never_produces_a_string_literal_over_96_bytes() {
        let names = Names {
            byte: "byte",
            char: "char",
            concat: "concat",
            sub: "sub",
            genv: "genv",
        };
        let art = b"a run of at-signs @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ and &&&&&&&&&&&&&&&&&&&&&&&& spaces\nand line breaks\n\nsample carrier payload row\n";
        let big: Vec<u8> = (0..3000u32)
            .map(|i| (33 + (i * 7 + 3) % 90) as u8)
            .collect();
        for data in [&art[..], &big[..]] {
            for seed in [1u64, 7, 42, 305419896, 2, 88, 999] {
                let expr = emit_expr(data, seed, 0, &names);
                let m = max_string_literal(&expr);
                assert!(
                    m <= 96,
                    "carrier emitted a {m}-byte string literal (seed {seed}, data {} bytes)",
                    data.len()
                );
            }
        }
    }

    #[test]
    fn mirror_reconstructs_exactly() {
        let samples: [&[u8]; 3] = [
            b"hello world",
            b"--[[art @@@ &&& ;;; ::: ,,, ]]\nreturn 42\n",
            &[0u8, 255, 128, 10, 13, 9, 32, 64, 64, 64, 38, 38],
        ];
        for (di, data) in samples.iter().enumerate() {
            for seed in [1u64, 7, 42, 305419896] {
                assert_eq!(
                    &mirror(data, seed, di as u64),
                    data,
                    "seed {seed} sample {di}"
                );
            }
        }
    }
}
