use crate::rng::Rng;

const ALIAS_NAMES: &[&str] = &["bt", "bz", "bk", "bf", "bq", "bw", "bv", "bn"];

pub(crate) fn emit(rng: &mut Rng, pairs: &[(&str, &str)]) -> String {
    let alias = ALIAS_NAMES[(rng.next() % ALIAS_NAMES.len() as u64) as usize];
    let lhs = pairs.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
    match rng.next() % 2 {
        0 => {
            let rets = pairs
                .iter()
                .map(|(_, f)| format!("{alias}.{f}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("local {lhs} = (function({alias}) return {rets} end)(bit32)\n")
        }
        _ => {
            let inner: Vec<String> = (0..pairs.len()).map(|i| format!("_a{i}")).collect();
            let binds = pairs
                .iter()
                .zip(&inner)
                .map(|((_, f), v)| format!("local {v} = {alias}.{f}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "local {lhs} = (function({alias}) {binds} return {} end)(bit32)\n",
                inner.join(", ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TMPL: &[(&str, &str)] = &[
        ("band", "band"),
        ("bxor", "bxor"),
        ("lrotate", "lrotate"),
        ("rshift", "rshift"),
        ("lshift", "lshift"),
    ];

    #[test]
    fn no_bit32_field_literal_and_references_bit32() {
        for seed in 0..128u64 {
            let mut rng = Rng::new(seed);
            let s = emit(&mut rng, TMPL);
            assert!(
                !s.contains("bit32."),
                "no bit32.<field> literal may be emitted: {s:?}"
            );
            assert!(
                s.contains("(bit32)"),
                "must alias the bit32 global via the closure argument: {s:?}"
            );
            assert!(!s.contains("bxor("), "no bxor call surface: {s:?}");
        }
    }

    #[test]
    fn fields_bind_in_request_order_no_misalignment() {
        for seed in 0..128u64 {
            let mut rng = Rng::new(seed);
            let s = emit(&mut rng, TMPL);
            let mut cursor = 0;
            for (_, f) in TMPL {
                let needle = format!(".{f}");
                let pos = s[cursor..]
                    .find(&needle)
                    .unwrap_or_else(|| panic!("missing {needle} in {s:?}"));
                cursor += pos + needle.len();
            }
            for (n, _) in TMPL {
                assert!(s.contains(n), "local {n} must be declared in {s:?}");
            }
        }
    }

    #[test]
    fn adds_no_top_level_local_beyond_the_requested_names() {
        for seed in 0..128u64 {
            let mut rng = Rng::new(seed);
            let s = emit(&mut rng, TMPL);
            let head = s.split('=').next().unwrap();
            assert_eq!(
                head.matches("local").count(),
                1,
                "exactly one chunk-level `local` binding list: {s:?}"
            );
        }
    }

    #[test]
    fn deterministic_per_seed_and_diverse_across_seeds() {
        let mut a = Rng::new(11);
        let mut b = Rng::new(11);
        assert_eq!(
            emit(&mut a, TMPL),
            emit(&mut b, TMPL),
            "deterministic per seed"
        );
        let mut forms = std::collections::HashSet::new();
        let mut structures = std::collections::HashSet::new();
        for seed in 0..64u64 {
            let mut rng = Rng::new(seed);
            let s = emit(&mut rng, TMPL);
            forms.insert(s.clone());
            structures.insert(s.contains("_a0"));
        }
        assert_eq!(
            structures.len(),
            2,
            "both closure staging structures must appear across seeds"
        );
        assert!(
            forms.len() >= 6,
            "alias name + structure must diversify across seeds: {}",
            forms.len()
        );
    }
}
