use crate::rng::Rng;

const DOMAIN: u64 = 0x_4D49_5845_5232_36;

#[derive(Clone, Copy)]
pub struct Family {
    split_init: bool,
    mod_extract: bool,
}

impl Family {
    pub fn for_seed(seed: u64, domain: u64) -> Self {
        let mut rng = Rng::new(seed ^ DOMAIN ^ domain);
        Family {
            split_init: rng.below(2) == 0,
            mod_extract: rng.below(2) == 0,
        }
    }

    pub fn opmask_def(&self) -> String {
        let init = if self.split_init {
            "local h = bxor(MK, SK_SJ[band(i, 7) + 1])\nh = bxor(h, lrotate(pid, 13))"
        } else {
            "local h = bxor(MK, SK_SJ[band(i, 7) + 1], lrotate(pid, 13))"
        };
        let extract = if self.mod_extract {
            "rshift(h, 3) % 256"
        } else {
            "band(rshift(h, 3), 0xFF)"
        };
        format!(
            "local function opmask(pid, i)\n{init}\nh = bxor(h, lrotate(i, 7))\nh = bxor(h, rshift(h, 11))\nh = bxor(lrotate(h, 5), i)\nh = bxor(h, rshift(h, 6))\nreturn {extract}\nend"
        )
    }

    pub fn opmask2_def(&self) -> String {
        let init = if self.split_init {
            "local h = bxor(MK, SK_EJ[band(i + slot, 7) + 1], lrotate(pid, 13))\nh = bxor(h, lrotate(i, 7), lrotate(slot, 3), lrotate(j, 19))"
        } else {
            "local h = bxor(MK, SK_EJ[band(i + slot, 7) + 1], lrotate(pid, 13), lrotate(i, 7), lrotate(slot, 3), lrotate(j, 19))"
        };
        let extract = if self.mod_extract {
            "f % 128"
        } else {
            "band(f, 0x7F)"
        };
        format!(
            "local function opmask2(pid, i, slot, j)\n{init}\nh = bxor(h, rshift(h, 15))\nh = lrotate(h, 13)\nh = bxor(h, rshift(h, 11))\nh = lrotate(h, 7)\nh = bxor(h, rshift(h, 17))\nlocal f = bxor(h, rshift(h, 10), rshift(h, 20))\nreturn {extract}\nend"
        )
    }
}

const SX_BYTETAB: &str = "local BYTETAB = {}\nfor _bi = 0, 255 do\nBYTETAB[_bi] = char(_bi)\nend\nif BYTETAB[0] ~= \"\\0\" or #BYTETAB[0] ~= 1 or BYTETAB[65] ~= \"A\" or BYTETAB[127] ~= \"\\127\" or BYTETAB[200] ~= \"\\200\" or BYTETAB[255] ~= \"\\255\" then\ndead = true\nend";

const SX_REDUCE: &str = "if ki == 0 then\nreturn \"\"\nend\nlocal n = ki\nwhile n > 1 do\nlocal m = 0\nfor i = 1, n - 1, 2 do\nm = m + 1\nout[m] = out[i] .. out[i + 1]\nend\nif n % 2 == 1 then\nm = m + 1\nout[m] = out[n]\nend\nfor i = m + 1, n do\nout[i] = nil\nend\nn = m\nend\nlocal r = out[1]\nout[1] = nil\nreturn r";

const SX_STRING: &str = "local len, out, oi, counter, ki = #data, {}, 0, 0, 0\nwhile oi < len do\nlocal w = chachaBlock(key, nonce, counter)\nfor i = 1, 16 do\nif oi >= len then break end\nlocal word = w[i]\nif oi + 4 <= len then\nlocal d0, d1, d2, d3 = byte(data, oi + 1, oi + 4)\nlocal R = bxor(d0 + d1 * 256 + d2 * 65536 + d3 * 16777216, word)\nki = ki + 1\nout[ki] = BYTETAB[R % 256] .. BYTETAB[(R // 256) % 256] .. BYTETAB[(R // 65536) % 256] .. BYTETAB[R // 16777216]\noi = oi + 4\nelse\nfor b = 0, 3 do\nif oi >= len then break end\noi = oi + 1\nki = ki + 1\nout[ki] = BYTETAB[bxor(byte(data, oi), band(rshift(word, b * 8), 0xFF))]\nend\nend\nend\ncounter = counter + 1\nend";

const SX_STRING_COMPACT: &str = "local len, out, ki, counter = #data, {}, 0, 0\nwhile ki < len do\nlocal w = chachaBlock(key, nonce, counter)\nfor i = 1, 16 do\nif ki >= len then break end\nlocal word = w[i]\nfor b = 0, 3 do\nif ki >= len then break end\nki = ki + 1\nout[ki] = BYTETAB[bxor(byte(data, ki), band(rshift(word, b * 8), 0xFF))]\nend\nend\ncounter = counter + 1\nend";

pub fn streamxor_def(seed: u64) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_5358_4F52_3236);
    if rng.below(2) == 0 {
        format!("{SX_BYTETAB}\nlocal function streamXor(key, nonce, data)\n{SX_STRING}\n{SX_REDUCE}\nend")
    } else {
        format!(
            "local streamXor\nlocal _bf = genv[char(98, 117, 102, 102, 101, 114)]\nif _bf and _bf.create then\nlocal _bc, _bw, _bu, _bt = _bf.create, _bf.writeu32, _bf.writeu8, _bf.tostring\nstreamXor = function(key, nonce, data)\nlocal len = #data\nlocal buf = _bc(len)\nlocal oi, counter = 0, 0\nwhile oi < len do\nlocal w = chachaBlock(key, nonce, counter)\nfor i = 1, 16 do\nif oi >= len then break end\nlocal word = w[i]\nif oi + 4 <= len then\nlocal d0, d1, d2, d3 = byte(data, oi + 1, oi + 4)\nlocal R = bxor(d0 + d1 * 256 + d2 * 65536 + d3 * 16777216, word)\n_bw(buf, oi, R)\noi = oi + 4\nelse\nfor b = 0, 3 do\nif oi >= len then break end\n_bu(buf, oi, bxor(byte(data, oi + 1), band(rshift(word, b * 8), 0xFF)))\noi = oi + 1\nend\nend\nend\ncounter = counter + 1\nend\nreturn _bt(buf)\nend\nelse\n{SX_BYTETAB}\nstreamXor = function(key, nonce, data)\n{SX_STRING_COMPACT}\n{SX_REDUCE}\nend\nend"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_deterministic_and_diverse() {
        let mut shapes = std::collections::HashSet::new();
        for seed in 0u64..48 {
            let f = Family::for_seed(seed, 0);
            let a = format!("{}{}", f.opmask_def(), f.opmask2_def());
            let b = format!(
                "{}{}",
                Family::for_seed(seed, 0).opmask_def(),
                Family::for_seed(seed, 0).opmask2_def()
            );
            assert_eq!(a, b, "deterministic per seed");
            shapes.insert(a);
        }
        assert!(
            shapes.len() >= 3,
            "opmask families must diversify: {}",
            shapes.len()
        );
    }

    #[test]
    fn both_extraction_and_init_forms_occur() {
        let mut mod_e = false;
        let mut band_e = false;
        let mut split = false;
        let mut fused = false;
        for seed in 0u64..64 {
            let d = Family::for_seed(seed, 0).opmask_def();
            if d.contains("rshift(h, 3) % 256") {
                mod_e = true;
            }
            if d.contains("band(rshift(h, 3), 0xFF)") {
                band_e = true;
            }
            if d.contains("local h = bxor(MK, SK_SJ[band(i, 7) + 1])\n") {
                split = true;
            }
            if d.contains("lrotate(pid, 13))\nh = bxor(h, lrotate(i, 7))") {
                fused = true;
            }
        }
        assert!(mod_e && band_e, "both extraction forms occur");
        assert!(split && fused, "both init-grouping forms occur");
    }

    #[test]
    fn every_family_defines_both_masks() {
        for seed in 0u64..16 {
            let f = Family::for_seed(seed, 0);
            assert!(f.opmask_def().contains("function opmask(pid, i)"));
            assert!(f
                .opmask2_def()
                .contains("function opmask2(pid, i, slot, j)"));
        }
    }
}
