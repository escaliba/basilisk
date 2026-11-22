use crate::rng::{Rng, DOMAIN_KEYS};
use crate::theme;
use crate::UnicodeTheme;

pub fn generate(theme_kind: UnicodeTheme, seed: u64, count: usize) -> Vec<String> {
    let Some(t) = theme::get(theme_kind) else {
        return Vec::new();
    };
    let mut rng = Rng::new(seed ^ DOMAIN_KEYS ^ (theme_kind as u64).wrapping_mul(0x100000001B3));
    let mut out: Vec<String> = Vec::new();
    let mut guard = 0usize;
    while out.len() < count && guard < count * 64 + 64 {
        guard += 1;
        let len = rng.range(6, 14) as usize;
        let mut s = String::new();
        for _ in 0..len {
            s.push_str(t.symbols[rng.below(16) as usize]);
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

pub fn luau_string_key(key: &str) -> String {
    let mut s = String::from("\"");
    for &b in key.as_bytes() {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7E => s.push(b as char),
            _ => s.push_str(&format!("\\{b}")),
        }
    }
    s.push('"');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const THEMED: [UnicodeTheme; 1] = [UnicodeTheme::Ascii];

    #[test]
    fn keys_are_collision_free_and_alphabet_only() {
        for k in THEMED {
            let t = theme::get(k).unwrap();
            let alphabet: std::collections::HashSet<&str> = t.symbols.iter().copied().collect();
            for seed in 0..40u64 {
                let keys = generate(k, seed, 8);
                assert_eq!(keys.len(), 8, "{k:?} seed {seed}: wanted 8 keys");
                let uniq: std::collections::HashSet<&String> = keys.iter().collect();
                assert_eq!(
                    uniq.len(),
                    keys.len(),
                    "{k:?} seed {seed}: keys must be unique"
                );
                for key in &keys {
                    let mut rest = key.as_str();
                    while !rest.is_empty() {
                        let sym = &rest[..t.width];
                        assert!(
                            alphabet.contains(sym),
                            "{k:?}: key symbol {sym:?} off-alphabet"
                        );
                        rest = &rest[t.width..];
                    }
                }
            }
        }
    }

    #[test]
    fn deterministic_per_seed() {
        assert_eq!(
            generate(UnicodeTheme::Ascii, 5, 6),
            generate(UnicodeTheme::Ascii, 5, 6)
        );
        assert_ne!(
            generate(UnicodeTheme::Ascii, 5, 6),
            generate(UnicodeTheme::Ascii, 6, 6)
        );
    }

    #[test]
    fn none_theme_yields_no_keys() {
        assert!(generate(UnicodeTheme::None, 1, 8).is_empty());
    }
}
