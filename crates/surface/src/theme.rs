use crate::rng::{Rng, DOMAIN_ALPHABET};
use crate::UnicodeTheme;

pub struct Theme {
    pub kind: UnicodeTheme,
    pub width: usize,
    pub symbols: [&'static str; 16],
}

const ASCII: [&str; 16] = [
    "!", "#", "$", "%", "&", "*", "+", ",", ".", "/", ":", ";", "<", ">", "?", "@",
];

pub fn get(kind: UnicodeTheme) -> Option<Theme> {
    let (width, symbols) = match kind {
        UnicodeTheme::None => return None,
        UnicodeTheme::Ascii => (1, ASCII),
    };
    Some(Theme {
        kind,
        width,
        symbols,
    })
}

pub fn value_order(theme: &Theme, seed: u64) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = theme.symbols.to_vec();
    let mut rng =
        Rng::new(seed ^ DOMAIN_ALPHABET ^ (theme.kind as u64).wrapping_mul(0x100000001B3));
    rng.shuffle(&mut order);
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_theme_has_16_distinct_width_1_symbols() {
        let t = get(UnicodeTheme::Ascii).unwrap();
        assert_eq!(t.width, 1);
        assert_eq!(t.symbols.len(), 16);
        for s in t.symbols {
            assert_eq!(s.len(), 1, "ascii symbol {s:?} must be width 1");
            assert!(!s.is_empty());
        }
        let mut uniq: Vec<&str> = t.symbols.to_vec();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), 16, "symbols must be distinct");
    }

    #[test]
    fn ascii_codepoints_are_pinned() {
        let t = get(UnicodeTheme::Ascii).unwrap();
        let cp: Vec<u32> = t
            .symbols
            .iter()
            .map(|s| s.chars().next().unwrap() as u32)
            .collect();
        assert_eq!(
            cp,
            vec![
                0x21, 0x23, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C, 0x2E, 0x2F, 0x3A, 0x3B, 0x3C, 0x3E,
                0x3F, 0x40
            ]
        );
    }

    #[test]
    fn ascii_symbols_are_long_bracket_and_quote_safe() {
        let t = get(UnicodeTheme::Ascii).unwrap();
        for s in t.symbols {
            for b in s.bytes() {
                assert!(
                    b != b']' && b != b'[' && b != b'"' && b != b'\'' && b != b'\\' && b != b'=',
                    "ascii symbol {s:?} byte {b:#x} unsafe in a [==[ ]==] carrier"
                );
            }
        }
    }

    #[test]
    fn none_theme_has_no_symbols() {
        assert!(get(UnicodeTheme::None).is_none());
    }

    #[test]
    fn value_order_is_deterministic_and_a_permutation() {
        let t = get(UnicodeTheme::Ascii).unwrap();
        let a = value_order(&t, 42);
        let b = value_order(&t, 42);
        assert_eq!(a, b);
        let mut sorted = a.clone();
        sorted.sort_unstable();
        let mut base = t.symbols.to_vec();
        base.sort_unstable();
        assert_eq!(sorted, base, "value order must be a permutation of the set");
    }
}
