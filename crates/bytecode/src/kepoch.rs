use crate::opcode::{self, Opcode, OperandRole};
use crate::proto::Proto;

pub const NEPOCH: u32 = 8;
pub const DOMAIN: i64 = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KepochMode {
    Off,
    Conservative,
    Aggressive,
}

pub struct Params {
    pub step: u32,
    pub base: u32,
    pub mstep: u32,
    pub mbase: u32,
    pub salt_e: u32,
    pub salt_s: u32,
    pub thresh: u32,
}

fn splitmix(seed: u64) -> u32 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)) as u32
}

pub fn params(seed: u64, mode: KepochMode) -> Option<Params> {
    let thresh = match mode {
        KepochMode::Off => return None,
        KepochMode::Conservative => 2,
        KepochMode::Aggressive => 5,
    };
    let step = (splitmix(seed ^ 0x_4B45_5F53_5450) % 128) * 2 + 1;
    let base = splitmix(seed ^ 0x_4B45_5F42_4153) % 256;
    let mstep = (splitmix(seed ^ 0x_4B4D_5F53_5450) % 128) * 2 + 1;
    let mbase = splitmix(seed ^ 0x_4B4D_5F42_4153) % 256;
    let salt_e = splitmix(seed ^ 0x_4B45_5F45_5043) | 1;
    let salt_s = splitmix(seed ^ 0x_4B45_5F53_454C) | 1;
    Some(Params {
        step,
        base,
        mstep,
        mbase,
        salt_e,
        salt_s,
        thresh,
    })
}

pub fn mix(pid: u32, i: u32, salt: u32) -> u32 {
    let mut h = salt ^ pid.rotate_left(13) ^ i.rotate_left(7);
    h ^= h >> 15;
    h = h.rotate_left(11);
    h ^= h >> 9;
    h
}

pub fn epoch0(pid: u32, i: u32, p: &Params) -> u32 {
    mix(pid, i, p.salt_e) & (NEPOCH - 1)
}

pub fn selected(pid: u32, i: u32, p: &Params) -> bool {
    (mix(pid, i, p.salt_s) & 15) < p.thresh
}

pub fn shift(e: u32, p: &Params) -> i64 {
    ((e.wrapping_mul(p.step).wrapping_add(p.base)) % (DOMAIN as u32)) as i64
}

pub fn encode(real: i64, e: u32, p: &Params) -> i64 {
    (real + shift(e, p)).rem_euclid(DOMAIN)
}

pub fn decode(token: i64, e: u32, p: &Params) -> i64 {
    (token - shift(e, p)).rem_euclid(DOMAIN)
}

pub fn rotate(e: u32) -> u32 {
    (e + 1) & (NEPOCH - 1)
}

fn base_of(op: Opcode) -> Opcode {
    opcode::SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op)
}

use Opcode::*;
const ELIGIBLE_BASES: [Opcode; 18] = [
    Move, LoadK, GetGlobal, NewTable, Add, Sub, Mul, Div, Mod, Pow, IDiv, Concat, Eq, Lt, Le, Ge,
    GetTable, SetTable,
];

fn base_index(op: Opcode) -> usize {
    ELIGIBLE_BASES
        .iter()
        .position(|&o| o == base_of(op))
        .unwrap_or(0)
}

pub fn family_of(op: Opcode, seed: u64) -> u32 {
    let mut assign = [0u32; ELIGIBLE_BASES.len()];
    let mut ones = 0u32;
    for (idx, _) in ELIGIBLE_BASES.iter().enumerate() {
        let f = splitmix(seed ^ 0x_4B46_414D_0000 ^ idx as u64) & 1;
        assign[idx] = f;
        ones += f;
    }
    if ones == 0 {
        assign[0] = 1;
    } else if ones as usize == ELIGIBLE_BASES.len() {
        assign[0] = 0;
    }
    assign[base_index(op)]
}

pub fn site_key(op: Opcode, seed: u64) -> u32 {
    splitmix(seed ^ 0x_4B53_4954_4500 ^ (base_index(op) as u64 + 1)) % (DOMAIN as u32)
}

pub fn mask(e: u32, sk: u32, p: &Params) -> i64 {
    (((e.wrapping_mul(p.mstep).wrapping_add(p.mbase)) % (DOMAIN as u32))
        ^ (sk & (DOMAIN as u32 - 1))) as i64
}

pub fn encode_xor(real: i64, e: u32, sk: u32, p: &Params) -> i64 {
    real ^ mask(e, sk, p)
}

pub fn decode_xor(token: i64, e: u32, sk: u32, p: &Params) -> i64 {
    token ^ mask(e, sk, p)
}

pub fn encode_op(real: i64, op: Opcode, e: u32, seed: u64, p: &Params) -> i64 {
    if family_of(op, seed) == 1 {
        encode_xor(real, e, site_key(op, seed), p)
    } else {
        encode(real, e, p)
    }
}

pub fn decode_op(token: i64, op: Opcode, e: u32, seed: u64, p: &Params) -> i64 {
    if family_of(op, seed) == 1 {
        decode_xor(token, e, site_key(op, seed), p)
    } else {
        decode(token, e, p)
    }
}

pub fn eligible_family(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        base_of(op),
        Move | LoadK
            | GetGlobal
            | NewTable
            | Add
            | Sub
            | Mul
            | Div
            | Mod
            | Pow
            | IDiv
            | Concat
            | Eq
            | Lt
            | Le
            | Ge
            | GetTable
            | SetTable
    )
}

fn is_register_role(role: OperandRole) -> bool {
    matches!(
        role,
        OperandRole::DstReg | OperandRole::SrcReg | OperandRole::TableReg
    )
}

pub fn slot_eligible(op: Opcode, slot: usize) -> bool {
    eligible_family(op) && is_register_role(opcode::patch_role(op, slot))
}

pub fn eligible_slots(op: Opcode) -> Vec<usize> {
    (0..3).filter(|&s| slot_eligible(op, s)).collect()
}

pub fn tokenize_code(proto: &Proto, pid: u32, seed: u64, mode: KepochMode) -> Proto {
    let Some(p) = params(seed, mode) else {
        return proto.clone();
    };
    let mut out = proto.clone();
    for (i0, inst) in out.code.iter_mut().enumerate() {
        let i = i0 as u32 + 1;
        if crate::superop::is_super(inst.op)
            || crate::opcode::is_gensuper(inst.op)
            || !eligible_family(inst.op)
            || !selected(pid, i, &p)
        {
            continue;
        }
        let e = epoch0(pid, i, &p);
        for slot in 0..3 {
            if !slot_eligible(inst.op, slot) {
                continue;
            }
            let field = match slot {
                0 => &mut inst.a,
                1 => &mut inst.b,
                _ => &mut inst.c,
            };
            let real = *field as i64;
            if (0..DOMAIN).contains(&real) {
                *field = encode_op(real, inst.op, e, seed, &p) as i32;
            }
        }
    }
    out
}

pub fn wide_operand_count(proto: &Proto, pid: u32, seed: u64, mode: KepochMode) -> usize {
    let Some(p) = params(seed, mode) else {
        return 0;
    };
    let mut n = 0;
    for (i0, inst) in proto.code.iter().enumerate() {
        let i = i0 as u32 + 1;
        if crate::superop::is_super(inst.op)
            || crate::opcode::is_gensuper(inst.op)
            || !eligible_family(inst.op)
            || !selected(pid, i, &p)
        {
            continue;
        }
        for slot in 0..3 {
            if slot_eligible(inst.op, slot)
                && !(0..DOMAIN).contains(&([inst.a, inst.b, inst.c][slot] as i64))
            {
                n += 1;
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inst::Inst;

    fn p_of(seed: u64) -> Params {
        params(seed, KepochMode::Aggressive).unwrap()
    }

    #[test]
    fn off_has_no_params() {
        assert!(params(1, KepochMode::Off).is_none());
    }

    #[test]
    fn encode_decode_roundtrips_over_full_domain() {
        let p = p_of(0x1234);
        for e in 0..NEPOCH {
            for real in 0..DOMAIN {
                let t = encode(real, e, &p);
                assert!((0..DOMAIN).contains(&t), "token {t} left the domain");
                assert_eq!(
                    decode(t, e, &p),
                    real,
                    "roundtrip failed for real={real} e={e}"
                );
            }
        }
    }

    #[test]
    fn edge_operands_roundtrip_for_many_epochs_and_seeds() {
        for seed in [1u64, 7, 42, 0xDEAD, 0x9017_57EE] {
            let p = p_of(seed);
            for e in 0..NEPOCH {
                for &real in &[0i64, 1, 2, 127, 128, 254, 255] {
                    assert_eq!(decode(encode(real, e, &p), e, &p), real);
                }
            }
        }
    }

    #[test]
    fn rotation_invariant_holds_forever() {
        let p = p_of(0x5EED);
        for &real in &[0i64, 3, 100, 255] {
            let mut e = epoch0(11, 5, &p);
            let mut token = encode(real, e, &p);
            for _ in 0..10_000 {
                assert_eq!(decode(token, e, &p), real, "state desynced");
                let n = rotate(e);
                token = encode(real, n, &p);
                e = n;
            }
            assert_eq!(decode(token, e, &p), real);
        }
    }

    #[test]
    fn token_changes_on_every_rotate() {
        for seed in [1u64, 0x5EED, 0xDEADBEEF, 0xA5A5, 42, 0xFF00FF00] {
            let p = p_of(seed);
            assert_eq!(
                p.step % 2,
                1,
                "step must be odd so shift is injective across epochs"
            );
            for real in 0..DOMAIN {
                for e in 0..NEPOCH {
                    let n = rotate(e);
                    assert_ne!(
                        encode(real, e, &p),
                        encode(real, n, &p),
                        "operand token must visibly churn on every rotate (seed {seed}, real {real}, e {e})"
                    );
                }
            }
        }
    }

    #[test]
    fn xor_family_roundtrips_over_full_domain() {
        let p = p_of(0x1234);
        for sk in [0u32, 1, 63, 128, 200, 255] {
            for e in 0..NEPOCH {
                for real in 0..DOMAIN {
                    let t = encode_xor(real, e, sk, &p);
                    assert!((0..DOMAIN).contains(&t), "xor token {t} left the domain");
                    assert_eq!(
                        decode_xor(t, e, sk, &p),
                        real,
                        "xor roundtrip failed real={real} e={e} sk={sk}"
                    );
                }
            }
        }
    }

    #[test]
    fn xor_family_edges_over_epochs_seeds_and_sitekeys() {
        for seed in [1u64, 7, 42, 0xDEAD, 0x9017_57EE] {
            let p = p_of(seed);
            for sk in [0u32, 1, 128, 254, 255] {
                for e in 0..NEPOCH {
                    for &real in &[0i64, 1, 2, 127, 128, 254, 255] {
                        assert_eq!(decode_xor(encode_xor(real, e, sk, &p), e, sk, &p), real);
                    }
                }
            }
        }
    }

    #[test]
    fn xor_family_rotation_invariant_holds_forever() {
        let p = p_of(0x5EED);
        let sk = site_key(Opcode::Add, 0x5EED);
        for &real in &[0i64, 3, 100, 255] {
            let mut e = epoch0(11, 5, &p);
            let mut token = encode_xor(real, e, sk, &p);
            for _ in 0..10_000 {
                assert_eq!(decode_xor(token, e, sk, &p), real, "xor state desynced");
                let n = rotate(e);
                token = encode_xor(real, n, sk, &p);
                e = n;
            }
            assert_eq!(decode_xor(token, e, sk, &p), real);
        }
    }

    #[test]
    fn xor_family_token_changes_on_every_rotate() {
        for seed in [1u64, 0x5EED, 0xDEADBEEF, 0xA5A5, 42, 0xFF00FF00] {
            let p = p_of(seed);
            assert_eq!(
                p.mstep % 2,
                1,
                "mstep must be odd so the xor mask is injective across epochs"
            );
            for sk in [0u32, 77, 255] {
                for real in 0..DOMAIN {
                    for e in 0..NEPOCH {
                        let n = rotate(e);
                        assert_ne!(
                            encode_xor(real, e, sk, &p),
                            encode_xor(real, n, sk, &p),
                            "xor token must churn on every rotate (seed {seed}, real {real}, e {e}, sk {sk})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn family_assignment_is_deterministic_and_seed_varies() {
        for seed in [1u64, 5, 42, 0xDEAD, 0x1234] {
            for op in ELIGIBLE_BASES {
                assert_eq!(
                    family_of(op, seed),
                    family_of(op, seed),
                    "family assignment must be deterministic"
                );
            }
        }
        let a: Vec<u32> = ELIGIBLE_BASES.iter().map(|&o| family_of(o, 5)).collect();
        let b: Vec<u32> = ELIGIBLE_BASES.iter().map(|&o| family_of(o, 6)).collect();
        assert_ne!(a, b, "different seeds must alter formula assignment");
    }

    #[test]
    fn both_families_are_present_for_every_seed() {
        for seed in [
            0u64,
            1,
            5,
            6,
            42,
            0xDEAD,
            0x1234,
            0xFFFF_FFFF_FFFF_FFFF,
            0xA5A55A5A,
        ] {
            let fams: Vec<u32> = ELIGIBLE_BASES.iter().map(|&o| family_of(o, seed)).collect();
            assert!(
                fams.iter().any(|&f| f == 0),
                "seed {seed}: family 0 must not be dead"
            );
            assert!(
                fams.iter().any(|&f| f == 1),
                "seed {seed}: family 1 must not be dead"
            );
        }
    }

    #[test]
    fn synonyms_inherit_base_family_and_sitekey() {
        for seed in [3u64, 5, 42] {
            assert_eq!(
                family_of(Opcode::Move1, seed),
                family_of(Opcode::Move, seed)
            );
            assert_eq!(
                family_of(Opcode::Concat2, seed),
                family_of(Opcode::Concat, seed)
            );
            assert_eq!(
                site_key(Opcode::GetGlobal1, seed),
                site_key(Opcode::GetGlobal, seed)
            );
        }
    }

    #[test]
    fn encode_op_decode_op_roundtrip_every_eligible_op() {
        for seed in [0u64, 5, 42, 0xDEAD] {
            let p = p_of(seed);
            for &op in &ELIGIBLE_BASES {
                for e in 0..NEPOCH {
                    for real in 0..DOMAIN {
                        let t = encode_op(real, op, e, seed, &p);
                        assert!((0..DOMAIN).contains(&t), "op token out of domain");
                        assert_eq!(
                            decode_op(t, op, e, seed, &p),
                            real,
                            "encode_op/decode_op mismatch op={op:?} e={e} real={real}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_two_families_are_structurally_different_transforms() {
        let p = p_of(0x1234);
        let sk = 91;
        let e = 2u32;
        let (r1, r2) = (40i64, 73i64);
        assert_eq!(
            (encode(r1, e, &p) - encode(r2, e, &p)).rem_euclid(DOMAIN),
            (r1 - r2).rem_euclid(DOMAIN),
            "additive family preserves additive differences"
        );
        assert_eq!(
            encode_xor(r1, e, sk, &p) ^ encode_xor(r2, e, sk, &p),
            r1 ^ r2,
            "xor family preserves xor differences"
        );
        let differ = (0..DOMAIN).any(|real| encode_xor(real, e, sk, &p) != encode(real, e, &p));
        assert!(differ, "the xor family must produce different tokens than the additive family for the same epoch");
    }

    #[test]
    fn rotate_cycles_through_every_epoch() {
        let mut seen = std::collections::HashSet::new();
        let mut e = 3;
        for _ in 0..NEPOCH {
            seen.insert(e);
            e = rotate(e);
        }
        assert_eq!(
            seen.len(),
            NEPOCH as usize,
            "rotation must visit every epoch"
        );
    }

    #[test]
    fn epoch0_is_bounded_and_selection_is_deterministic() {
        let p = p_of(3);
        for pid in 0..8u32 {
            for i in 1..40u32 {
                assert!(epoch0(pid, i, &p) < NEPOCH);
                assert_eq!(selected(pid, i, &p), selected(pid, i, &p));
            }
        }
    }

    #[test]
    fn aggressive_selects_at_least_as_much_as_conservative() {
        let c = params(9, KepochMode::Conservative).unwrap();
        let a = params(9, KepochMode::Aggressive).unwrap();
        assert!(a.thresh > c.thresh);
        for pid in 0..6u32 {
            for i in 1..64u32 {
                if selected(pid, i, &c) {
                    assert!(
                        selected(pid, i, &a),
                        "aggressive must be a superset of conservative"
                    );
                }
            }
        }
    }

    #[test]
    fn only_register_roles_of_eligible_families_are_slots() {
        assert!(slot_eligible(Opcode::Move, 0));
        assert!(slot_eligible(Opcode::Move, 1));
        assert!(slot_eligible(Opcode::LoadK, 0));
        assert!(
            !slot_eligible(Opcode::LoadK, 1),
            "LoadK const index must never be a KEPOCH slot"
        );
        assert!(
            !slot_eligible(Opcode::GetGlobal, 1),
            "GetGlobal const index stays untouched"
        );
        assert_eq!(eligible_slots(Opcode::SetTable), vec![0, 1, 2]);
        assert_eq!(eligible_slots(Opcode::GetTable), vec![0, 1, 2]);
    }

    #[test]
    fn control_call_loop_upval_families_are_excluded() {
        for op in [
            Opcode::Call,
            Opcode::Return,
            Opcode::Vararg,
            Opcode::Closure,
            Opcode::Close,
            Opcode::ForPrep,
            Opcode::ForLoop,
            Opcode::TForCall,
            Opcode::TForLoop,
            Opcode::Jmp,
            Opcode::JmpIf,
            Opcode::JmpIfNot,
            Opcode::EncFunc,
            Opcode::Crash,
            Opcode::GetUpval,
            Opcode::SetUpval,
            Opcode::SetGlobal,
            Opcode::Self_,
            Opcode::Gt,
            Opcode::Ne,
        ] {
            assert!(!eligible_family(op), "{op:?} must be excluded from KEPOCH");
            assert!(
                eligible_slots(op).is_empty(),
                "{op:?} must expose no KEPOCH slots"
            );
        }
    }

    #[test]
    fn synonyms_inherit_base_eligibility() {
        assert!(eligible_family(Opcode::Move1));
        assert!(eligible_family(Opcode::GetGlobal1));
        assert!(eligible_family(Opcode::Concat2));
        assert!(slot_eligible(Opcode::LoadK1, 0));
        assert!(!slot_eligible(Opcode::LoadK1, 1));
    }

    #[test]
    fn tokenize_off_is_identity() {
        let proto = Proto {
            max_stack: 8,
            code: vec![
                Inst::new(Opcode::Move, 1, 2, 0),
                Inst::new(Opcode::Add, 3, 1, 2),
            ],
            ..Default::default()
        };
        assert_eq!(tokenize_code(&proto, 0, 5, KepochMode::Off), proto);
    }

    #[test]
    fn tokenize_changes_only_register_slots() {
        let p = params(5, KepochMode::Aggressive).unwrap();
        let proto = Proto {
            max_stack: 16,
            code: vec![
                Inst::new(Opcode::Move, 1, 2, 0),
                Inst::new(Opcode::LoadK, 3, 7, 0),
                Inst::new(Opcode::Call, 1, 2, 1),
                Inst::new(Opcode::Return, 0, 1, 0),
            ],
            ..Default::default()
        };
        let tok = tokenize_code(&proto, 0, 5, KepochMode::Aggressive);
        for (i0, (o, t)) in proto.code.iter().zip(tok.code.iter()).enumerate() {
            let i = i0 as u32 + 1;
            assert_eq!(o.op, t.op, "opcode never changes");
            if !eligible_family(o.op) || !selected(0, i, &p) {
                assert_eq!(o, t, "non-selected/ineligible instruction untouched");
                continue;
            }
            let e = epoch0(0, i, &p);
            for slot in 0..3 {
                let (ov, tv) = ([o.a, o.b, o.c][slot], [t.a, t.b, t.c][slot]);
                if slot_eligible(o.op, slot) {
                    assert_eq!(
                        decode_op(tv as i64, o.op, e, 5, &p) as i32,
                        ov,
                        "token must decode back to real"
                    );
                } else {
                    assert_eq!(ov, tv, "non-register slot (e.g. const index) stays real");
                }
            }
        }
    }

    #[test]
    fn wide_register_operands_are_skipped_not_encoded_or_panicked() {
        let seed = 15089456739989719121u64;
        let p = params(seed, KepochMode::Aggressive).unwrap();
        let proto = Proto {
            max_stack: 500,
            code: (0..300)
                .map(|_| Inst::new(Opcode::Add, 343, 5, 10))
                .collect(),
            ..Default::default()
        };
        let tok = tokenize_code(&proto, 117, seed, KepochMode::Aggressive);
        let mut in_domain_churned = false;
        for (i0, (o, t)) in proto.code.iter().zip(tok.code.iter()).enumerate() {
            let i = i0 as u32 + 1;
            assert_eq!(t.a, 343, "wide destination register (>= DOMAIN) must be left unchanged, never wrapped into [0,256)");
            if eligible_family(o.op) && selected(117, i, &p) {
                let e = epoch0(117, i, &p);
                assert_eq!(
                    decode_op(t.b as i64, o.op, e, seed, &p) as i32,
                    5,
                    "in-domain src operand tokenizes and decodes back to real"
                );
                assert_eq!(
                    decode_op(t.c as i64, o.op, e, seed, &p) as i32,
                    10,
                    "in-domain src operand tokenizes and decodes back to real"
                );
                in_domain_churned |= t.b != 5 || t.c != 10;
            } else {
                assert_eq!(o, t, "non-selected/ineligible instruction untouched");
            }
        }
        assert!(
            in_domain_churned,
            "in-domain register operands must still be tokenized alongside a skipped wide operand"
        );
    }
}
