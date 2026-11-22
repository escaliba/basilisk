use crate::rng::Rng;
use crate::topology::replace_word_in_code;

const DOMAIN: u64 = 0x_434F_4E53_5444_4956;

const MOD32: u64 = 4294967296;
const MOD16: u64 = 65536;

const ANCHOR: &str = "local genv = getfenv(1)\n";

pub fn apply(src: String, seed: u64) -> String {
    if !src.contains(ANCHOR) {
        return src;
    }
    let mut rng = Rng::new(seed ^ DOMAIN);
    let n32 = name(&mut rng);
    let mut n16 = name(&mut rng);
    while n16 == n32 {
        n16 = name(&mut rng);
    }
    let e32 = decompose(MOD32, &mut rng);
    let e16 = decompose(MOD16, &mut rng);

    let decls = format!("{ANCHOR}local {n32} = {e32}\nlocal {n16} = {e16}\n");
    let mut out = src.replacen(ANCHOR, &decls, 1);
    for form in ["0x100000000", "0x1_0000_0000", "4294967296"] {
        out = replace_word_in_code(&out, form, &n32);
    }
    for form in ["65536", "0x10000", "0x1_0000"] {
        out = replace_word_in_code(&out, form, &n16);
    }
    out
}

fn name(rng: &mut Rng) -> String {
    let a = b"abcdefghijklmnopqrstuvwxyz";
    let mut s = String::from("_c");
    for _ in 0..4 {
        s.push(a[(rng.next() % 26) as usize] as char);
    }
    s
}

fn decompose(value: u64, rng: &mut Rng) -> String {
    let (lo, hi) = if value == MOD16 {
        (3u64, 255u64)
    } else {
        (256u64, 65535u64)
    };
    loop {
        let a = lo + rng.below(hi - lo + 1);
        let q = value / a;
        let r = value - a * q;
        if a * q + r != value || a * q >= (1u64 << 53) {
            continue;
        }
        let expr = match rng.below(3) {
            0 if r == 0 => format!("{a} * {q}"),
            1 if r == 0 => format!("{q} * {a}"),
            _ => format!("{a} * {q} + {r}"),
        };
        if !expr.contains("65536") {
            return expr;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(expr: &str) -> u64 {
        let (prod, rest) = expr
            .split_once('+')
            .map_or((expr, "0"), |(p, r)| (p, r.trim()));
        let mut factors = prod.split('*').map(|t| t.trim().parse::<u64>().unwrap());
        let a = factors.next().unwrap();
        let b = factors.next().unwrap();
        a * b + rest.parse::<u64>().unwrap()
    }

    #[test]
    fn decompositions_are_exact() {
        for seed in 1u64..=200 {
            let mut rng = Rng::new(seed ^ DOMAIN);
            for _ in 0..8 {
                assert_eq!(eval(&decompose(MOD32, &mut rng)), MOD32);
                assert_eq!(eval(&decompose(MOD16, &mut rng)), MOD16);
            }
        }
    }

    #[test]
    fn intermediates_stay_below_2_53() {
        for seed in 1u64..=200 {
            let mut rng = Rng::new(seed ^ DOMAIN);
            for _ in 0..8 {
                for e in [decompose(MOD32, &mut rng), decompose(MOD16, &mut rng)] {
                    let prod = e.split_once('+').map_or(e.as_str(), |(p, _)| p);
                    let v: u64 = prod
                        .split('*')
                        .map(|t| t.trim().parse::<u64>().unwrap())
                        .product();
                    assert!(v < (1u64 << 53), "{e}");
                }
            }
        }
    }

    #[test]
    fn same_seed_is_deterministic() {
        for seed in [1u64, 7, 42, 305419896, u64::MAX] {
            assert_eq!(apply(sample(), seed), apply(sample(), seed));
        }
    }

    #[test]
    fn different_seeds_differ_sometimes() {
        let distinct: std::collections::HashSet<String> =
            (1u64..=64).map(|s| apply(sample(), s)).collect();
        assert!(distinct.len() > 1);
    }

    #[test]
    fn code_literals_replaced_but_strings_and_comments_preserved() {
        let out = apply(sample(), 99);
        assert!(
            !out.contains("% 0x100000000"),
            "code modulus replaced: {out}"
        );
        assert!(!out.contains("// 65536"), "code divide replaced");
        assert!(!out.contains("* 65536"), "code multiply replaced");
        assert!(out.contains("getfenv(1)"));
        assert!(
            out.contains("\"keep 65536 and 0x100000000 literally\""),
            "string literal untouched"
        );
        assert!(
            out.contains("[==[ 0x100000000 blob ]==]"),
            "long-bracket blob untouched"
        );
        assert!(
            out.contains("-- 65536 in a comment stays 65536"),
            "comment untouched"
        );
    }

    #[test]
    fn missing_anchor_is_identity() {
        let s = "x = y % 0x100000000\n".to_string();
        assert_eq!(apply(s.clone(), 3), s);
    }

    fn sample() -> String {
        "return (function()\nlocal genv = getfenv(1)\n\
         local m = (a + b) % 0x100000000\n\
         local h = (h // 65536) * 65536 % 0x100000000\n\
         local s = \"keep 65536 and 0x100000000 literally\"\n\
         -- 65536 in a comment stays 65536\n\
         local t = [==[ 0x100000000 blob ]==]\n\
         return m + h + t\nend)()\n"
            .to_string()
    }
}
