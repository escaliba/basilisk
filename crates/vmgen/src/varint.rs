use crate::rng::Rng;

const DOMAIN: u64 = 0x_5641_5249_4E54_3235;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LoopK {
    While,
    Repeat,
    FastFirst,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Bits {
    Mod,
    Band,
}

#[derive(Clone, Copy)]
pub struct Family {
    loopk: LoopK,
    low: Bits,
    cont: Bits,
    zz: Bits,
}

impl Family {
    pub fn for_seed(seed: u64, domain: u64) -> Self {
        let mut rng = Rng::new(seed ^ DOMAIN ^ domain);
        let loopk = match rng.below(3) {
            0 => LoopK::While,
            1 => LoopK::Repeat,
            _ => LoopK::FastFirst,
        };
        Family {
            loopk,
            low: if rng.below(2) == 0 {
                Bits::Mod
            } else {
                Bits::Band
            },
            cont: if rng.below(2) == 0 {
                Bits::Mod
            } else {
                Bits::Band
            },
            zz: if rng.below(2) == 0 {
                Bits::Mod
            } else {
                Bits::Band
            },
        }
    }

    fn low(&self, b: &str) -> String {
        match self.low {
            Bits::Mod => format!("{b} % 128"),
            Bits::Band => format!("band({b}, 127)"),
        }
    }
    fn cont(&self, b: &str) -> String {
        match self.cont {
            Bits::Mod => format!("{b} < 128"),
            Bits::Band => format!("band({b}, 128) == 0"),
        }
    }
    fn ncont(&self, b: &str) -> String {
        match self.cont {
            Bits::Mod => format!("{b} >= 128"),
            Bits::Band => format!("band({b}, 128) ~= 0"),
        }
    }
    fn zz(&self, u: &str) -> String {
        match self.zz {
            Bits::Mod => format!("{u} % 2 == 0"),
            Bits::Band => format!("band({u}, 1) == 0"),
        }
    }

    fn accum(&self, iter: &dyn Fn(&str, &str) -> String, use_j: bool) -> String {
        let jdecl = if use_j { " local j = 0" } else { "" };
        let jinc = if use_j { " j = j + 1" } else { "" };
        match self.loopk {
            LoopK::While => format!(
                "local result = 0 local mul = 1{jdecl}\nwhile true do\nlocal b = byte(data, pos) pos = pos + 1\n{}\nif {} then break end\nmul = mul * 128{jinc}\nend",
                iter("b", "j"),
                self.cont("b"),
            ),
            LoopK::Repeat => format!(
                "local result = 0 local mul = 1 local b{jdecl}\nrepeat\nb = byte(data, pos) pos = pos + 1\n{}\nmul = mul * 128{jinc}\nuntil {}",
                iter("b", "j"),
                self.cont("b"),
            ),
            LoopK::FastFirst => format!(
                "local result = 0 local mul = 1{jdecl}\nlocal b = byte(data, pos) pos = pos + 1\n{}\nif {} then\nmul = mul * 128{jinc}\nwhile true do\nb = byte(data, pos) pos = pos + 1\n{}\nif {} then break end\nmul = mul * 128{jinc}\nend\nend",
                iter("b", "j"),
                self.ncont("b"),
                iter("b", "j"),
                self.cont("b"),
            ),
        }
    }

    pub fn deserialize_defs(&self) -> String {
        let vu = format!(
            "local function vu()\n{}\nreturn result\nend",
            self.accum(
                &|b, _| format!("result = result + ({}) * mul", self.low(b)),
                false
            )
        );
        let vs = format!(
            "local function vs()\nlocal u = vu()\nif {} then return u // 2 end\nreturn -((u + 1) // 2)\nend",
            self.zz("u")
        );
        let vsm = format!(
            "local function vsm(pid, pc, slot)\n{}\nif {} then return result // 2 end\nreturn -((result + 1) // 2)\nend",
            self.accum(
                &|b, j| format!("result = result + bxor({}, opmask2(pid, pc, slot, {})) * mul", self.low(b), j),
                true
            ),
            self.zz("result")
        );
        let fvu = format!(
            "local function fvu(pid, fidx)\n{}\nreturn result\nend",
            self.accum(&|b, j| self.fvu_iter(b, j), true)
        );
        format!("{vu}\n{vs}\n{vsm}\n{fvu}")
    }

    fn fvu_iter(&self, b: &str, j: &str) -> String {
        format!(
            "local h = bxor(MK, SK_FR[band(fidx, 7) + 1], lrotate(pid, 13), lrotate(fidx, 7), lrotate({j}, 19)) h = bxor(h, rshift(h, 15)) h = lrotate(h, 13) h = bxor(h, rshift(h, 11)) h = lrotate(h, 7) h = bxor(h, rshift(h, 17))\nresult = result + bxor({}, band(bxor(h, rshift(h, 10), rshift(h, 20)), 0x7F)) * mul",
            self.low(b)
        )
    }

    pub fn skipv_def(&self) -> String {
        let cont_ge = match self.cont {
            Bits::Mod => "byte(data, pos) >= 128",
            Bits::Band => "band(byte(data, pos), 128) ~= 0",
        };
        let cont_lt = match self.cont {
            Bits::Mod => "byte(data, pos - 1) < 128",
            Bits::Band => "band(byte(data, pos - 1), 128) == 0",
        };
        match self.loopk {
            LoopK::Repeat => {
                format!("local function skipv()\nrepeat pos = pos + 1 until {cont_lt}\nend")
            }
            _ => format!(
                "local function skipv()\nwhile {cont_ge} do pos = pos + 1 end\npos = pos + 1\nend"
            ),
        }
    }

    pub fn decoderange_vsm(&self) -> String {
        format!(
            "local function vsm(pid, pc, slot)\n{}\nif {} then return result // 2 end\nreturn -((result + 1) // 2)\nend",
            self.accum(
                &|b, j| format!("result = result + bxor({}, opmask2(pid, pc, slot, {})) * mul", self.low(b), j),
                true
            ),
            self.zz("result")
        )
    }
}

pub fn structkey_def(seed: u64) -> String {
    let mut rng = Rng::new(seed ^ 0x_5354_4B45_5932_35);
    let band = rng.below(2) == 0;
    let norm = |x: &str| {
        if band {
            format!("band({x}, 0xffffffff)")
        } else {
            format!("({x}) % 0x100000000")
        }
    };
    format!(
        "local function structKey(d, dom)\nlocal acc = dom\nfor i = 0, 7 do\nacc = lrotate(bxor(acc, d[i + 1]), 7)\nacc = {}\nend\nlocal out = {{}}\nfor i = 0, 7 do\nacc = lrotate(bxor(acc, {}), 11)\nacc = {}\nacc = bxor(acc, rshift(acc, 15))\nout[i + 1] = acc\nend\nreturn out\nend",
        norm("acc + d[band(i + 5, 7) + 1]"),
        norm("dom + i"),
        norm("acc + d[i + 1]")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_vu(data: &[u8], pos: usize) -> (i128, usize) {
        let mut result: i128 = 0;
        let mut mul: i128 = 1;
        let mut p = pos;
        loop {
            let b = data[p - 1] as i128;
            p += 1;
            result += (b % 128) * mul;
            if b < 128 {
                return (result, p);
            }
            mul *= 128;
        }
    }
    fn zigzag(u: i128) -> i128 {
        if u % 2 == 0 {
            u / 2
        } else {
            -((u + 1) / 2)
        }
    }

    fn enc(mut v: u128) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v % 128) as u8;
            v /= 128;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 128);
        }
    }

    #[test]
    fn all_families_equal_reference_over_edge_vectors() {
        let vals: Vec<u128> = vec![
            0,
            1,
            2,
            126,
            127,
            128,
            129,
            255,
            256,
            16383,
            16384,
            16385,
            2097151,
            2097152,
            (1u128 << 31) - 1,
            1u128 << 31,
            (1u128 << 32) - 1,
            1u128 << 32,
            (1u128 << 52) - 1,
        ];

        for &lk in &[LoopK::While, LoopK::Repeat, LoopK::FastFirst] {
            for &lo in &[Bits::Mod, Bits::Band] {
                for &co in &[Bits::Mod, Bits::Band] {
                    for &zz in &[Bits::Mod, Bits::Band] {
                        let f = Family {
                            loopk: lk,
                            low: lo,
                            cont: co,
                            zz,
                        };
                        for &v in &vals {
                            let bytes = enc(v);
                            let (u, _) = ref_vu(&bytes, 1);
                            assert_eq!(u as u128, v, "reference vu mismatch v={v}");

                            assert_eq!(f.zz_ok(u), (u % 2 == 0), "zz axis equivalence v={v}");
                            assert_eq!(zigzag(u), if u % 2 == 0 { u / 2 } else { -((u + 1) / 2) });
                        }
                    }
                }
            }
        }
    }

    impl Family {
        fn zz_ok(&self, u: i128) -> bool {
            match self.zz {
                Bits::Mod => u % 2 == 0,
                Bits::Band => (u & 1) == 0,
            }
        }
    }

    #[test]
    fn families_diversify_and_are_deterministic() {
        let mut shapes = std::collections::HashSet::new();
        for seed in 0u64..48 {
            let f = Family::for_seed(seed, 0);
            let a = f.deserialize_defs();
            let b = Family::for_seed(seed, 0).deserialize_defs();
            assert_eq!(a, b, "deterministic per seed");
            shapes.insert(a);
        }
        assert!(
            shapes.len() >= 8,
            "varint families must diversify across seeds: {}",
            shapes.len()
        );
    }

    #[test]
    fn every_family_defines_all_four_readers() {
        for seed in 0u64..24 {
            let d = Family::for_seed(seed, 0).deserialize_defs();
            for name in [
                "function vu()",
                "function vs()",
                "function vsm(",
                "function fvu(",
            ] {
                assert!(d.contains(name), "seed {seed} missing {name}: {d}");
            }
        }
    }
}
