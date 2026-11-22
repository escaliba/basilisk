use bytecode::crypt;
use std::collections::HashSet;

fn is_perm(p: [u8; 3]) -> bool {
    let mut s = [false; 3];
    for &x in &p {
        if x > 2 || s[x as usize] {
            return false;
        }
        s[x as usize] = true;
    }
    true
}

#[test]
fn oplayout_is_always_a_valid_permutation() {
    for seed in [1u64, 0x20260809, 0xDEAD, 0x5151_5151] {
        for pid in 0..2000u32 {
            assert!(
                is_perm(crypt::oplayout_perm(seed, pid)),
                "seed {seed:#x} pid {pid}"
            );
        }
    }
}

#[test]
fn oplayout_varies_per_proto_within_a_build() {
    let seed = 0x2026_0809u64;
    let mut seen = HashSet::new();
    for pid in 0..1176u32 {
        seen.insert(crypt::oplayout_perm(seed, pid));
    }
    assert!(
        seen.len() >= 5,
        "per-proto operand layout must span the permutation space: {}",
        seen.len()
    );
}

#[test]
fn oplayout_varies_per_build_for_the_same_proto() {
    let seeds = [1u64, 2, 3, 4, 5, 6, 7, 8, 20260809, 0xABCD];
    let mut differ = 0u32;
    for &pid in &[0u32, 7, 41, 258, 977] {
        let base = crypt::oplayout_perm(seeds[0], pid);
        if seeds[1..]
            .iter()
            .any(|&s| crypt::oplayout_perm(s, pid) != base)
        {
            differ += 1;
        }
    }
    assert_eq!(
        differ, 5,
        "every sampled proto's layout moves across builds"
    );
}

#[test]
fn build_a_layout_does_not_parse_build_b() {
    let seed_a = 0xA1A1u64;
    let seed_b = 0xB2B2u64;
    let mut mismatched = 0u32;
    let total = 1176u32;
    for pid in 0..total {
        if crypt::oplayout_perm(seed_a, pid) != crypt::oplayout_perm(seed_b, pid) {
            mismatched += 1;
        }
    }
    let frac = mismatched as f64 / total as f64;
    println!("OPLAYOUT build-A-vs-B role-map mismatch = {frac:.3}");
    assert!(
        frac > 0.7,
        "most protos must have a different physical role map across builds (got {frac:.3})"
    );
}

#[test]
fn maskperm_is_valid_and_independent_of_role_order() {
    let seed = 0x2026_0809u64;
    let mut order_only_insufficient = 0u32;
    for pid in 0..1176u32 {
        let order = crypt::oplayout_perm(seed, pid);
        let mperm = crypt::oplayout_maskperm(seed, pid);
        assert!(
            is_perm(mperm),
            "maskperm must be a valid permutation (pid {pid})"
        );
        if order != mperm {
            order_only_insufficient += 1;
        }
    }
    let frac = order_only_insufficient as f64 / 1176.0;
    println!("OPLAYOUT maskperm != role order for {frac:.3} of protos");
    assert!(
        frac > 0.7,
        "the operand mask-slot map is independent of the scalar role order (got {frac:.3})"
    );
}

#[test]
fn phase20_scalar_only_map_is_insufficient_for_phase21() {
    let seed = 0xC0FFEEu64;
    let mut wrong_operand_decode = 0u32;
    let total = 1176u32;
    for pid in 0..total {
        if crypt::oplayout_maskperm(seed, pid) != [0, 1, 2] {
            wrong_operand_decode += 1;
        }
    }
    let frac = wrong_operand_decode as f64 / total as f64;
    println!("OPLAYOUT scalar-only parser mis-unmasks operands for {frac:.3} of protos");
    assert!(
        frac > 0.7,
        "a role-order-only parser mis-decodes operand values on most protos (got {frac:.3})"
    );
}

#[test]
fn gmode_varies_per_proto_and_build() {
    let mut both = [false; 2];
    for pid in 0..2048u32 {
        both[(crypt::oplayout_gmode(0x2026_0809, pid) & 1) as usize] = true;
    }
    assert!(
        both[0] && both[1],
        "both superop list directions must occur across protos"
    );
}
