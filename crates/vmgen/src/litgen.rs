use crate::rng::Rng;

fn num(n: u32, rng: &mut Rng) -> String {
    if rng.below(2) == 0 {
        format!("0x{n:X}")
    } else {
        format!("{n}")
    }
}

pub fn num_lit(b: u8, rng: &mut Rng) -> String {
    let bv = b as u32;
    match rng.below(4) {
        0 => {
            let k = (rng.below(255) + 1) as u32;
            debug_assert_eq!((bv ^ k) ^ k, bv);
            format!("bxor({}, {})", num(bv ^ k, rng), num(k, rng))
        }
        1 => {
            let x = rng.below(256) as u32;
            let y = (bv + 256 - x) % 256;
            debug_assert_eq!((x + y) % 256, bv);
            format!("({} + {}) % {}", num(x, rng), num(y, rng), num(256, rng))
        }
        2 => {
            let y = rng.below(256) as u32;
            let x = bv + y;
            debug_assert_eq!((x - y) % 256, bv);
            format!("({} - {}) % {}", num(x, rng), num(y, rng), num(256, rng))
        }
        _ => {
            let a = (rng.below(255) + 1) as u32;
            let r = (rng.below(7) + 1) as u32;
            let t = a.rotate_left(r);
            let c = t ^ bv;
            debug_assert_eq!(t ^ c, bv);
            format!(
                "bxor(lrotate({}, {}), {})",
                num(a, rng),
                num(r, rng),
                num(c, rng)
            )
        }
    }
}

fn chunk(s: &[u8], rng: &mut Rng) -> String {
    let parts: Vec<String> = s.iter().map(|&b| num_lit(b, rng)).collect();
    format!("char({})", parts.join(", "))
}

pub fn string_lit(s: &[u8], rng: &mut Rng) -> String {
    if s.len() >= 2 && rng.below(3) == 0 {
        let cut = 1 + rng.below((s.len() - 1) as u64) as usize;
        format!("{} .. {}", chunk(&s[..cut], rng), chunk(&s[cut..], rng))
    } else {
        chunk(s, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_and_shape_formula_holds() {
        for seed in 0..96u64 {
            let mut rng = Rng::new(seed);
            for b in 0..=255u8 {
                let _ = string_lit(&[b], &mut rng);
            }
        }
    }

    #[test]
    fn deterministic_for_same_rng() {
        let a = string_lit(b"Path2D", &mut Rng::new(42));
        let b = string_lit(b"Path2D", &mut Rng::new(42));
        assert_eq!(a, b);
    }

    #[test]
    fn no_plaintext_helper_name_leaks() {
        for seed in 0..64u64 {
            let mut rng = Rng::new(seed);
            for name in [&b"Path2D"[..], b"Vector3", b"GetLength", b"debug", b"print"] {
                let lit = string_lit(name, &mut rng);
                let text = std::str::from_utf8(name).unwrap();
                assert!(
                    !lit.contains(text),
                    "helper name {text:?} leaked as plaintext in {lit:?}"
                );
            }
        }
    }

    #[test]
    fn varies_across_builds() {
        let shapes: std::collections::HashSet<String> = (0..40u64)
            .map(|s| string_lit(b"Vector3", &mut Rng::new(s)))
            .collect();
        assert!(
            shapes.len() > 1,
            "helper literal spelling must vary per build"
        );
    }

    #[test]
    fn breaks_the_single_decimal_bxor_regex() {
        let is_legacy = |lit: &str| {
            lit.starts_with("char(")
                && !lit.contains("0x")
                && !lit.contains(" + ")
                && !lit.contains(" - ")
                && !lit.contains("lrotate")
                && !lit.contains(" .. ")
        };
        let total = 200u64;
        let legacy = (0..total)
            .filter(|&s| is_legacy(&string_lit(b"GetLength", &mut Rng::new(s))))
            .count();
        assert!(
            legacy * 4 < total as usize,
            "too many emissions still match the legacy decimal-bxor regex: {legacy}/{total}"
        );
    }
}
