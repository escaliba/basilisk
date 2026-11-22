use crate::rng::Rng;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Coeff {
    Poly,
    Horner,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Extract {
    DivMod,
    SubDiv,
    Bit32,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LoopKind {
    While,
    For,
}

pub struct Names<'a> {
    pub byte: &'a str,
    pub char: &'a str,
    pub concat: &'a str,
}

pub struct Family {
    coeff: Coeff,
    extract: Extract,
    loopk: LoopKind,
    tag: String,
    n: usize,
}

impl Family {
    pub fn for_domain(seed: u64, domain: u64) -> Self {
        let mut rng = Rng::new(seed ^ domain ^ 0x_434F_4C44_4443_5230);
        let coeff = if rng.below(2) == 0 {
            Coeff::Poly
        } else {
            Coeff::Horner
        };
        let extract = match rng.below(3) {
            0 => Extract::DivMod,
            1 => Extract::SubDiv,
            _ => Extract::Bit32,
        };
        let loopk = if rng.below(2) == 0 {
            LoopKind::While
        } else {
            LoopKind::For
        };
        let letters = b"abcdefghijklmnopqrstuvwxyz";
        let tag: String = (0..2)
            .map(|_| letters[rng.below(26) as usize] as char)
            .collect();
        Family {
            coeff,
            extract,
            loopk,
            tag: format!("_{tag}"),
            n: 0,
        }
    }

    fn fresh(&mut self) -> String {
        self.n += 1;
        format!("{}{}", self.tag, self.n)
    }

    pub fn emit(&mut self, names: &Names, rev: &str, enc: &str) -> (String, String) {
        let out = self.fresh();
        let oi = self.fresh();
        let p = self.fresh();
        let n = self.fresh();
        let byte = names.byte;
        let ch = names.char;
        let read = |off: usize| {
            if off == 0 {
                format!("{rev}[{byte}({enc},{p})]")
            } else {
                format!("{rev}[{byte}({enc},{p}+{off})]")
            }
        };
        let compute = match self.coeff {
            Coeff::Poly => format!(
                "local {n}={}*52200625+{}*614125+{}*7225+{}*85+{}",
                read(0),
                read(1),
                read(2),
                read(3),
                read(4)
            ),
            Coeff::Horner => format!(
                "local {n}={}\n{n}={n}*85+{}\n{n}={n}*85+{}\n{n}={n}*85+{}\n{n}={n}*85+{}",
                read(0),
                read(1),
                read(2),
                read(3),
                read(4)
            ),
        };
        let store = match self.extract {
            Extract::DivMod => {
                format!("{out}[{oi}]={ch}({n}//16777216%256,{n}//65536%256,{n}//256%256,{n}%256)")
            }
            Extract::SubDiv => {
                let b0 = self.fresh();
                let b1 = self.fresh();
                let b2 = self.fresh();
                let b3 = self.fresh();
                format!(
                    "local {b0}={n}%256\n{n}=({n}-{b0})/256\nlocal {b1}={n}%256\n{n}=({n}-{b1})/256\nlocal {b2}={n}%256\nlocal {b3}=({n}-{b2})/256\n{out}[{oi}]={ch}({b3},{b2},{b1},{b0})"
                )
            }
            Extract::Bit32 => {
                format!("{out}[{oi}]={ch}(band(rshift({n},24),255),band(rshift({n},16),255),band(rshift({n},8),255),band({n},255))")
            }
        };
        let stmts = match self.loopk {
            LoopKind::While => format!(
                "local {out}={{}}\nlocal {oi}=0\nlocal {p}=1\nwhile {p}+4<=#{enc} do\n{compute}\n{p}={p}+5\n{oi}={oi}+1\n{store}\nend"
            ),
            LoopKind::For => format!(
                "local {out}={{}}\nlocal {oi}=0\nfor {p}=1,#{enc}-4,5 do\n{compute}\n{oi}={oi}+1\n{store}\nend"
            ),
        };
        (stmts, format!("{}({out})", names.concat))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revmap(alpha: &[u8]) -> [i64; 256] {
        let mut r = [0i64; 256];
        for (i, &c) in alpha.iter().enumerate() {
            r[c as usize] = i as i64;
        }
        r
    }

    fn mirror_decode(f: &Family, alpha: &[u8], enc: &[u8]) -> Vec<u8> {
        let r = revmap(alpha);
        let mut out = Vec::new();
        let mut p = 0usize;
        while p + 5 <= enc.len() {
            let d = |off: usize| r[enc[p + off] as usize];
            let n: i64 = match f.coeff {
                Coeff::Poly => d(0) * 52200625 + d(1) * 614125 + d(2) * 7225 + d(3) * 85 + d(4),
                Coeff::Horner => {
                    let mut n = d(0);
                    n = n * 85 + d(1);
                    n = n * 85 + d(2);
                    n = n * 85 + d(3);
                    n * 85 + d(4)
                }
            };
            match f.extract {
                Extract::DivMod => {
                    out.push((n / 16777216 % 256) as u8);
                    out.push((n / 65536 % 256) as u8);
                    out.push((n / 256 % 256) as u8);
                    out.push((n % 256) as u8);
                }
                Extract::SubDiv => {
                    let b0 = n % 256;
                    let n1 = (n - b0) / 256;
                    let b1 = n1 % 256;
                    let n2 = (n1 - b1) / 256;
                    let b2 = n2 % 256;
                    let b3 = (n2 - b2) / 256;
                    out.push(b3 as u8);
                    out.push(b2 as u8);
                    out.push(b1 as u8);
                    out.push(b0 as u8);
                }
                Extract::Bit32 => {
                    out.push(((n >> 24) & 255) as u8);
                    out.push(((n >> 16) & 255) as u8);
                    out.push(((n >> 8) & 255) as u8);
                    out.push((n & 255) as u8);
                }
            }
            p += 5;
        }
        out
    }

    fn encode(alpha: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let n = ((bytes[i] as u32) << 24)
                | ((*bytes.get(i + 1).unwrap_or(&0) as u32) << 16)
                | ((*bytes.get(i + 2).unwrap_or(&0) as u32) << 8)
                | (*bytes.get(i + 3).unwrap_or(&0) as u32);
            out.push(alpha[(n / 52_200_625 % 85) as usize]);
            out.push(alpha[(n / 614_125 % 85) as usize]);
            out.push(alpha[(n / 7_225 % 85) as usize]);
            out.push(alpha[(n / 85 % 85) as usize]);
            out.push(alpha[(n % 85) as usize]);
            i += 4;
        }
        out
    }

    fn alpha() -> Vec<u8> {
        (33u8..=126)
            .filter(|&c| c != b'"' && c != b'\\')
            .take(85)
            .collect()
    }

    #[test]
    fn every_family_decodes_byte_exact() {
        let a = alpha();

        let mut payload: Vec<u8> = (0..733).map(|i| ((i * 13 + 5) % 256) as u8).collect();
        while payload.len() % 4 != 0 {
            payload.push(b'\n');
        }
        let enc = encode(&a, &payload);
        for seed in [1u64, 2, 7, 20260809, 0xBEEF, 0xC0FFEE] {
            for dom in [0x_574D_3344u64, 0x_4C43_3144] {
                let f = Family::for_domain(seed, dom);
                assert_eq!(
                    mirror_decode(&f, &a, &enc),
                    payload,
                    "seed {seed} dom {dom:#x}"
                );
            }
        }
    }

    #[test]
    fn wm3_and_lc1_domains_usually_pick_distinct_families() {
        let mut same = 0u32;
        let total = 64u32;
        for seed in 0..total as u64 {
            let a = Family::for_domain(seed, 0x_574D_3344);
            let b = Family::for_domain(seed, 0x_4C43_3144);
            if (a.coeff, a.extract, a.loopk) == (b.coeff, b.extract, b.loopk) {
                same += 1;
            }
        }
        assert!(
            same < total / 2,
            "the two cold decoders should usually differ ({same}/{total} identical)"
        );
    }

    #[test]
    fn most_builds_avoid_the_poly_signature() {
        let mut poly = 0u32;
        for seed in 0..64u64 {
            if Family::for_domain(seed, 0x_574D_3344).coeff == Coeff::Poly {
                poly += 1;
            }
        }
        assert!(
            poly < 48,
            "Horner should appear on a healthy fraction of builds ({poly}/64 Poly)"
        );
    }

    #[test]
    fn deterministic_per_seed_domain() {
        for seed in [1u64, 42, 20260809] {
            let mut a = Family::for_domain(seed, 0x_574D_3344);
            let mut b = Family::for_domain(seed, 0x_574D_3344);
            let names = Names {
                byte: "byte",
                char: "char",
                concat: "concat",
            };
            assert_eq!(a.emit(&names, "_r", "_e"), b.emit(&names, "_r", "_e"));
        }
    }
}
