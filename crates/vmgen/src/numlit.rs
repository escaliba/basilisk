use crate::rng::Rng;

fn group_underscores(digits: &str) -> String {
    let n = digits.len();
    if n <= 4 {
        return digits.to_string();
    }
    let mut out = String::new();
    let first = n % 4;
    let mut idx = 0;
    if first != 0 {
        out.push_str(&digits[..first]);
        idx = first;
    }
    while idx < n {
        if !out.is_empty() {
            out.push('_');
        }
        out.push_str(&digits[idx..idx + 4]);
        idx += 4;
    }
    out
}

pub(crate) fn hex(v: u32, rng: &mut Rng, underscore_hex: bool) -> String {
    if !underscore_hex {
        return format!("0x{v:X}");
    }
    format!("{}{v:X}", hex_prefix(rng, true))
}

fn hex_prefix(rng: &mut Rng, underscore_hex: bool) -> String {
    let x = if rng.next() % 2 == 0 { 'x' } else { 'X' };
    if !underscore_hex {
        return format!("0{x}");
    }
    let lead = 1 + rng.next() % 3;
    let trail = 1 + rng.next() % 5;
    let mut out = String::from("0");
    for _ in 0..lead {
        out.push('_');
    }
    out.push(x);
    for _ in 0..trail {
        out.push('_');
    }
    out
}

fn literal(v: u64, rng: &mut Rng, underscore_hex: bool) -> String {
    if v <= 0xFFFF && rng.next() % 3 == 0 {
        let digits = format!("{v:b}");
        let digits = if rng.next() % 2 == 0 {
            group_underscores(&digits)
        } else {
            digits
        };
        let p = if rng.next() % 2 == 0 { "0b" } else { "0B" };
        return format!("{p}{digits}");
    }
    let digits = if rng.next() % 2 == 0 {
        format!("{v:X}")
    } else {
        format!("{v:x}")
    };
    let digits = if rng.next() % 2 == 0 {
        group_underscores(&digits)
    } else {
        digits
    };
    format!("{}{digits}", hex_prefix(rng, underscore_hex))
}

pub(crate) fn cold_expr(value: u32, rng: &mut Rng, underscore_hex: bool) -> String {
    let v = value as u64;
    if v < 8 {
        return literal(v, rng, underscore_hex);
    }
    match rng.next() % 5 {
        0 => literal(v, rng, underscore_hex),
        1 => {
            let a = 1 + rng.next() % (v - 1);
            format!(
                "({}+{})",
                literal(a, rng, underscore_hex),
                literal(v - a, rng, underscore_hex)
            )
        }
        2 => {
            let d = 1 + rng.next() % 0x4000_0000;
            format!(
                "({}-{})",
                literal(v + d, rng, underscore_hex),
                literal(d, rng, underscore_hex)
            )
        }
        3 => {
            let a = 1 + rng.next() % (v - 2);
            let rem = v - a;
            let b = 1 + rng.next() % (rem - 1);
            format!(
                "({}+{}+{})",
                literal(a, rng, underscore_hex),
                literal(b, rng, underscore_hex),
                literal(rem - b, rng, underscore_hex)
            )
        }
        _ => {
            let c = 1 + rng.next() % (v - 1);
            let r = 1 + rng.next() % 0x4000_0000;
            format!(
                "({}-{}+{})",
                literal((v - c) + r, rng, underscore_hex),
                literal(r, rng, underscore_hex),
                literal(c, rng, underscore_hex)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_operand(t: &str) -> u64 {
        let clean: String = t.chars().filter(|c| *c != '_').collect();
        if let Some(h) = clean
            .strip_prefix("0x")
            .or_else(|| clean.strip_prefix("0X"))
        {
            u64::from_str_radix(h, 16).unwrap()
        } else if let Some(b) = clean
            .strip_prefix("0b")
            .or_else(|| clean.strip_prefix("0B"))
        {
            u64::from_str_radix(b, 2).unwrap()
        } else {
            panic!("non-hex/bin operand emitted: {t:?}")
        }
    }

    fn eval(expr: &str) -> u64 {
        let mut s = expr.trim();
        if s.starts_with('(') && s.ends_with(')') {
            s = &s[1..s.len() - 1];
        }
        let bytes = s.as_bytes();
        let mut acc: i128 = 0;
        let mut op = b'+';
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'+' || c == b'-' {
                op = c;
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && bytes[i] != b'+' && bytes[i] != b'-' {
                i += 1;
            }
            let val = parse_operand(s[start..i].trim()) as i128;
            if op == b'+' {
                acc += val;
            } else {
                acc -= val;
            }
        }
        acc as u64
    }

    #[test]
    fn cold_expr_evaluates_exactly_over_seeds_and_values() {
        for value in [
            0u32,
            1,
            7,
            8,
            42,
            255,
            256,
            65535,
            65536,
            1_000_003,
            0x7FFF_FFFF,
            0xFFFF_FFFF,
        ] {
            for seed in 0..64u64 {
                let mut rng = Rng::new(seed);
                let e = cold_expr(value, &mut rng, false);
                assert_eq!(eval(&e), value as u64, "value {value} seed {seed} expr {e}");
            }
        }
    }

    #[test]
    fn only_supported_nondecimal_forms_emitted() {
        for value in [8u32, 100, 4096, 70000, 0xDEAD_BEEF, 0xFFFF_FFFF] {
            for seed in 0..96u64 {
                let mut rng = Rng::new(seed ^ 0x55);
                let e = cold_expr(value, &mut rng, false);
                for tok in e
                    .split(['(', ')', '+', '-'])
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                {
                    let ok = tok.starts_with("0x")
                        || tok.starts_with("0X")
                        || tok.starts_with("0b")
                        || tok.starts_with("0B");
                    assert!(ok, "non-hex/bin token {tok:?} in {e:?}");
                }
                assert!(
                    !e.contains('*') && !e.contains('/') && !e.contains('%') && !e.contains('^'),
                    "disallowed op in {e:?}"
                );
            }
        }
    }

    #[test]
    fn deterministic_per_seed_and_diverse_across_seeds() {
        let mut a = Rng::new(9);
        let mut b = Rng::new(9);
        assert_eq!(
            cold_expr(123456, &mut a, false),
            cold_expr(123456, &mut b, false),
            "deterministic per seed"
        );
        let mut skel = std::collections::HashSet::new();
        for seed in 0..64u64 {
            let mut rng = Rng::new(seed);
            skel.insert(cold_expr(0xABCDEF, &mut rng, false));
        }
        assert!(
            skel.len() >= 16,
            "cold_expr must diversify across seeds: {} distinct",
            skel.len()
        );
    }

    #[test]
    fn underscore_grouping_preserves_value() {
        assert_eq!(group_underscores("100000000"), "1_0000_0000");
        assert_eq!(group_underscores("deadbeef"), "dead_beef");
        assert_eq!(group_underscores("2a"), "2a");
        assert_eq!(group_underscores("2abc"), "2abc");
    }
}
