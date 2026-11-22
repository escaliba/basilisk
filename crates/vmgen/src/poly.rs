use std::collections::HashSet;

use bytecode::encoding::Encoding;
use bytecode::opcode::{self, Opcode};

use crate::litgen;
use crate::rng::Rng;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolyStream {
    Off,
    Conservative,
    Aggressive,
}

const BASES: [Opcode; 14] = [
    Opcode::LoadK,
    Opcode::Mul,
    Opcode::Move,
    Opcode::Add,
    Opcode::Sub,
    Opcode::GetTable,
    Opcode::Concat,
    Opcode::GetGlobal,
    Opcode::SetTable,
    Opcode::NewTable,
    Opcode::Eq,
    Opcode::Lt,
    Opcode::Le,
    Opcode::Ge,
];

pub struct Plan {
    pub cycle: Vec<(u8, u8)>,
    pub salt: u8,
    pub thresh: u32,
}

pub fn plan(enc: &Encoding, seed: u64, used: &HashSet<Opcode>, mode: PolyStream) -> Option<Plan> {
    let thresh = match mode {
        PolyStream::Off => return None,
        PolyStream::Conservative => 4,
        PolyStream::Aggressive => 12,
    };
    let mut rng = Rng::new(seed ^ 0x_504F_4C59_5354_524D);
    let mut cycle: Vec<(u8, u8)> = Vec::new();
    for base in BASES {
        let mut ids: Vec<u8> = opcode::synonyms_of(base)
            .into_iter()
            .filter(|op| used.contains(op))
            .map(|op| enc.phys(op))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() < 2 {
            continue;
        }
        rng.shuffle(&mut ids);
        for k in 0..ids.len() {
            cycle.push((ids[k], ids[(k + 1) % ids.len()]));
        }
    }
    if cycle.is_empty() {
        return None;
    }
    let salt = (rng.next() & 0xFF) as u8;
    Some(Plan {
        cycle,
        salt,
        thresh,
    })
}

pub fn emit(
    enc: &Encoding,
    seed: u64,
    used: &HashSet<Opcode>,
    mode: PolyStream,
    surface: bool,
) -> (String, String) {
    match plan(enc, seed, used, mode) {
        None => (String::new(), String::new()),
        Some(p) => {
            let mut rng = Rng::new(seed ^ 0x_5259_5F54_4142_4C45);
            (
                emit_table(&p, &mut rng, surface),
                emit_stmt(&p, &mut rng, surface),
            )
        }
    }
}

fn emit_table(p: &Plan, rng: &mut Rng, surface: bool) -> String {
    if surface {
        let mut e = p.cycle.clone();
        rng.shuffle(&mut e);
        let lines: Vec<String> = e
            .iter()
            .map(|&(k, v)| {
                format!(
                    "RXT[{}] = {}",
                    litgen::num_lit(k, rng),
                    litgen::num_lit(v, rng)
                )
            })
            .collect();
        format!("local RXT = {{}}\n{}", lines.join("\n"))
    } else {
        let entries: Vec<String> = p
            .cycle
            .iter()
            .map(|&(k, v)| format!("[{k}] = {v}"))
            .collect();
        format!("local RXT = {{ {} }}", entries.join(", "))
    }
}

fn emit_stmt(p: &Plan, rng: &mut Rng, surface: bool) -> String {
    let salt = if surface {
        litgen::num_lit(p.salt, rng)
    } else {
        p.salt.to_string()
    };
    format!(
        "local _rn = RXT[inst[KOP]]\n\t\t\t\t\tif _rn and band(bxor(pc, {}), 15) < {} then inst[KOP] = _rn end",
        salt, p.thresh
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_of(seed: u64) -> Encoding {
        Encoding::from_seed(seed)
    }

    fn used_with(ops: &[Opcode]) -> HashSet<Opcode> {
        ops.iter().copied().collect()
    }

    fn full_synonym_used() -> HashSet<Opcode> {
        let mut u = HashSet::new();
        for base in BASES {
            for op in opcode::synonyms_of(base) {
                u.insert(op);
            }
        }
        u
    }

    fn apply(cycle: &[(u8, u8)], op: u8, times: usize) -> u8 {
        let mut cur = op;
        for _ in 0..times {
            cur = cycle
                .iter()
                .find(|(k, _)| *k == cur)
                .map(|(_, v)| *v)
                .unwrap_or(cur);
        }
        cur
    }

    #[test]
    fn off_plan_is_none() {
        assert!(plan(&enc_of(1), 1, &full_synonym_used(), PolyStream::Off).is_none());
    }

    #[test]
    fn enabled_plan_nonempty_when_synonyms_used() {
        let p = plan(
            &enc_of(7),
            7,
            &full_synonym_used(),
            PolyStream::Conservative,
        )
        .unwrap();
        assert!(!p.cycle.is_empty());
    }

    #[test]
    fn no_cycle_without_two_used_aliases() {
        assert!(plan(
            &enc_of(9),
            9,
            &used_with(&[Opcode::LoadK]),
            PolyStream::Aggressive
        )
        .is_none());
    }

    #[test]
    fn plan_deterministic_for_same_seed() {
        let u = full_synonym_used();
        let a = plan(&enc_of(42), 42, &u, PolyStream::Aggressive).unwrap();
        let b = plan(&enc_of(42), 42, &u, PolyStream::Aggressive).unwrap();
        assert_eq!(a.cycle, b.cycle);
        assert_eq!(a.salt, b.salt);
    }

    #[test]
    fn plan_varies_across_seeds() {
        let u = full_synonym_used();
        let mut distinct = std::collections::HashSet::new();
        for seed in 0..24u64 {
            let p = plan(&enc_of(seed), seed, &u, PolyStream::Aggressive).unwrap();
            distinct.insert((p.cycle.clone(), p.salt));
        }
        assert!(
            distinct.len() > 12,
            "per-build plan should vary widely, got {}",
            distinct.len()
        );
    }

    #[test]
    fn aggressive_threshold_exceeds_conservative() {
        let u = full_synonym_used();
        let c = plan(&enc_of(3), 3, &u, PolyStream::Conservative).unwrap();
        let a = plan(&enc_of(3), 3, &u, PolyStream::Aggressive).unwrap();
        assert!(a.thresh > c.thresh);
    }

    #[test]
    fn every_cycle_endpoint_is_a_used_handler() {
        let u = full_synonym_used();
        let used_phys: HashSet<u8> = u.iter().map(|op| enc_of(11).phys(*op)).collect();
        let p = plan(&enc_of(11), 11, &u, PolyStream::Aggressive).unwrap();
        for (k, v) in &p.cycle {
            assert!(used_phys.contains(k), "cycle key {k} not a used opcode");
            assert!(
                used_phys.contains(v),
                "cycle target {v} not a used opcode (no handler)"
            );
        }
    }

    #[test]
    fn cycle_keys_are_unique_and_advance() {
        let p = plan(&enc_of(5), 5, &full_synonym_used(), PolyStream::Aggressive).unwrap();
        let mut keys: Vec<u8> = p.cycle.iter().map(|(k, _)| *k).collect();
        let n = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), n, "each opcode appears once as a key");
        for (k, v) in &p.cycle {
            assert_ne!(k, v, "one step must always change the opcode");
        }
    }

    #[test]
    fn simulated_record_differs_across_execution_states_then_returns() {
        let p = plan(
            &enc_of(17),
            17,
            &full_synonym_used(),
            PolyStream::Aggressive,
        )
        .unwrap();
        for base in BASES {
            let ids: Vec<u8> = opcode::synonyms_of(base)
                .into_iter()
                .map(|op| enc_of(17).phys(op))
                .collect();
            let group_len = ids
                .iter()
                .filter(|id| p.cycle.iter().any(|(k, _)| k == *id))
                .count();
            if group_len < 2 {
                continue;
            }
            let start = ids
                .into_iter()
                .find(|id| p.cycle.iter().any(|(k, _)| k == id))
                .unwrap();
            assert_ne!(
                apply(&p.cycle, start, 1),
                start,
                "1 execution mutates the record"
            );
            assert_eq!(
                apply(&p.cycle, start, group_len),
                start,
                "cycles back after a full lap"
            );
        }
    }

    #[test]
    fn coverage_histogram_reflects_expanded_family_surface() {
        let u = full_synonym_used();
        let enc = enc_of(23);
        let p = plan(&enc, 23, &u, PolyStream::Aggressive).unwrap();
        let mut family_size: std::collections::HashMap<Opcode, usize> =
            std::collections::HashMap::new();
        for base in BASES {
            let ids: HashSet<u8> = opcode::synonyms_of(base)
                .into_iter()
                .filter(|op| u.contains(op))
                .map(|op| enc.phys(op))
                .collect();
            let size = p.cycle.iter().filter(|(k, _)| ids.contains(k)).count();
            if size >= 2 {
                family_size.insert(base, size);
            }
        }
        assert_eq!(
            family_size.len(),
            BASES.len(),
            "every base family morphs when its synonyms are used"
        );
        assert_eq!(family_size.len(), 14, "expanded to 14 morphable families");
        for rich in [
            Opcode::LoadK,
            Opcode::Mul,
            Opcode::Concat,
            Opcode::GetGlobal,
        ] {
            assert_eq!(
                family_size[&rich], 3,
                "{rich:?} is a 3-cycle (base + two synonyms)"
            );
        }
        for lean in [
            Opcode::Move,
            Opcode::Add,
            Opcode::Sub,
            Opcode::GetTable,
            Opcode::SetTable,
            Opcode::NewTable,
            Opcode::Eq,
            Opcode::Lt,
            Opcode::Le,
            Opcode::Ge,
        ] {
            assert_eq!(
                family_size[&lean], 2,
                "{lean:?} is a 2-cycle (base + one synonym)"
            );
        }
        let endpoints: usize = family_size.values().sum();
        assert_eq!(endpoints, p.cycle.len());
        assert_eq!(
            endpoints, 32,
            "32 morphable opcode-id endpoints (was 24 pre-compare-expansion)"
        );
    }

    #[test]
    fn new_families_are_morphable_and_const_carrying_getglobal_included() {
        let u = full_synonym_used();
        for base in [
            Opcode::Concat,
            Opcode::GetGlobal,
            Opcode::SetTable,
            Opcode::NewTable,
        ] {
            assert!(BASES.contains(&base), "{base:?} is a poly base");
        }
        let enc = enc_of(31);
        let p = plan(&enc, 31, &u, PolyStream::Conservative).unwrap();
        let gg: HashSet<u8> = opcode::synonyms_of(Opcode::GetGlobal)
            .into_iter()
            .map(|op| enc.phys(op))
            .collect();
        let gg_start = gg
            .iter()
            .copied()
            .find(|id| p.cycle.iter().any(|(k, _)| k == id))
            .unwrap();
        assert_ne!(
            apply(&p.cycle, gg_start, 1),
            gg_start,
            "GetGlobal record mutates across execution states"
        );
        assert_eq!(
            opcode::const_slot(Opcode::GetGlobal1),
            opcode::const_slot(Opcode::GetGlobal)
        );
        assert_eq!(
            opcode::const_slot(Opcode::GetGlobal2),
            opcode::const_slot(Opcode::GetGlobal)
        );
    }

    #[test]
    fn compare_families_are_value_producing_not_branches_and_morphable() {
        let u = full_synonym_used();
        let enc = enc_of(41);
        let p = plan(&enc, 41, &u, PolyStream::Conservative).unwrap();
        for base in [Opcode::Eq, Opcode::Lt, Opcode::Le, Opcode::Ge] {
            assert!(BASES.contains(&base), "{base:?} is a poly base");
            for slot in 0..3 {
                assert_eq!(
                    opcode::patch_cf_role(base, slot),
                    opcode::OperandRole::None,
                    "{base:?} is value-producing, not a control-flow/branch op"
                );
            }
            assert_eq!(
                opcode::const_slot(base),
                None,
                "{base:?} carries no constant operand"
            );
            let ids: HashSet<u8> = opcode::synonyms_of(base)
                .into_iter()
                .map(|op| enc.phys(op))
                .collect();
            let start = ids
                .iter()
                .copied()
                .find(|id| p.cycle.iter().any(|(k, _)| k == id))
                .unwrap();
            assert_ne!(
                apply(&p.cycle, start, 1),
                start,
                "{base:?} record mutates across execution states"
            );
        }
        assert!(
            !BASES.contains(&Opcode::Gt),
            "Gt stays excluded (below dead-synonym floor)"
        );
        assert!(
            !BASES.contains(&Opcode::Ne),
            "Ne stays excluded (below dead-synonym floor)"
        );
    }

    #[test]
    fn emit_off_is_empty() {
        let (t, s) = emit(&enc_of(1), 1, &full_synonym_used(), PolyStream::Off, true);
        assert!(t.is_empty() && s.is_empty());
    }

    #[test]
    fn emit_enabled_has_table_and_statement() {
        let (t, s) = emit(
            &enc_of(2),
            2,
            &full_synonym_used(),
            PolyStream::Conservative,
            true,
        );
        assert!(t.contains("RXT"));
        assert!(s.contains("RXT[inst[KOP]]") && s.contains("inst[KOP] = _rn"));
    }

    #[test]
    fn emitted_output_carries_no_readable_intent_anchors() {
        for surface in [true, false] {
            let (t, s) = emit(
                &enc_of(4),
                4,
                &full_synonym_used(),
                PolyStream::Aggressive,
                surface,
            );
            for anchor in [
                "poly",
                "morph",
                "rewrite",
                "alias",
                "PolyStream",
                ".op",
                ".ops",
            ] {
                assert!(!t.contains(anchor), "table leaks anchor {anchor}");
                assert!(!s.contains(anchor), "statement leaks anchor {anchor}");
            }
        }
    }
}
