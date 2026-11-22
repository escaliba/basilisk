use crate::opcode::{Opcode, ALL};

pub const OP_COUNT: usize = ALL.len();

const SHUFFLE_LEN: usize = Opcode::EncFunc as usize;
const REMAP_SCATTER_LEN: usize = Opcode::BStateStep as usize;

pub struct Encoding {
    op_to_concrete: [u8; OP_COUNT],
    operand_perm: [u8; 3],
    op_remap: [u8; OP_COUNT],
}

impl Encoding {
    pub fn fixed() -> Self {
        let mut op_to_concrete = [0u8; OP_COUNT];
        let mut op_remap = [0u8; OP_COUNT];
        for i in 0..OP_COUNT {
            op_to_concrete[i] = i as u8;
            op_remap[i] = i as u8;
        }
        Encoding {
            op_to_concrete,
            operand_perm: [0, 1, 2],
            op_remap,
        }
    }

    pub fn from_seed(seed: u64) -> Self {
        let mut rng = SplitMix(seed);
        let mut op_to_concrete = [0u8; OP_COUNT];
        for (i, slot) in op_to_concrete.iter_mut().enumerate() {
            *slot = i as u8;
        }
        for i in (1..SHUFFLE_LEN).rev() {
            op_to_concrete.swap(i, (rng.next() % (i as u64 + 1)) as usize);
        }
        let mut operand_perm = [0u8, 1, 2];
        for i in (1..3).rev() {
            operand_perm.swap(i, (rng.next() % (i as u64 + 1)) as usize);
        }

        let mut remap_rng = SplitMix(seed ^ 0x_4F50_5245_4D41_505F);
        let mut op_remap = [0u8; OP_COUNT];
        for (i, slot) in op_remap.iter_mut().enumerate() {
            *slot = i as u8;
        }
        for i in (1..REMAP_SCATTER_LEN).rev() {
            op_remap.swap(i, (remap_rng.next() % (i as u64 + 1)) as usize);
        }
        Encoding {
            op_to_concrete,
            operand_perm,
            op_remap,
        }
    }

    pub fn concrete(&self, op: Opcode) -> u8 {
        self.op_to_concrete[op as usize]
    }

    pub fn phys(&self, op: Opcode) -> u8 {
        self.op_remap[self.concrete(op) as usize]
    }

    pub fn swap_phys(&mut self, a: Opcode, b: Opcode) {
        let ca = self.concrete(a) as usize;
        let cb = self.concrete(b) as usize;
        self.op_remap.swap(ca, cb);
    }

    pub fn operand_order(&self) -> [u8; 3] {
        self.operand_perm
    }

    pub fn operand_inverse(&self) -> [usize; 3] {
        let mut inv = [0usize; 3];
        for (phys, &logical) in self.operand_perm.iter().enumerate() {
            inv[logical as usize] = phys;
        }
        inv
    }
}

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_is_identity() {
        let e = Encoding::fixed();
        for (op, _) in ALL {
            assert_eq!(e.concrete(*op) as usize, *op as usize);
        }
        assert_eq!(e.operand_order(), [0, 1, 2]);
        assert_eq!(e.operand_inverse(), [0, 1, 2]);
    }

    #[test]
    fn from_seed_is_a_bijection() {
        let e = Encoding::from_seed(0x1234_5678);
        let mut seen = [false; OP_COUNT];
        for (op, _) in ALL {
            let c = e.concrete(*op) as usize;
            assert!(!seen[c], "concrete byte {c} assigned to two opcodes");
            seen[c] = true;
        }
        let mut sorted = e.operand_inverse();
        sorted.sort_unstable();
        assert_eq!(sorted, [0, 1, 2], "operand permutation must be a bijection");
    }

    #[test]
    fn distinct_seeds_differ() {
        let a = Encoding::from_seed(1);
        let b = Encoding::from_seed(2);
        assert!(ALL.iter().any(|(op, _)| a.concrete(*op) != b.concrete(*op)));
    }

    #[test]
    fn same_seed_is_deterministic() {
        let a = Encoding::from_seed(42);
        let b = Encoding::from_seed(42);
        assert!(ALL.iter().all(|(op, _)| a.concrete(*op) == b.concrete(*op)));
        assert_eq!(a.operand_order(), b.operand_order());
    }

    fn identity_tail() -> &'static [Opcode] {
        &[
            Opcode::EncFunc,
            Opcode::GetGlobalI,
            Opcode::SelfI,
            Opcode::Pad,
        ]
    }

    #[test]
    fn phys_is_a_full_bijection_over_every_opcode() {
        let e = Encoding::from_seed(0x1234_5678);
        let mut seen = [false; OP_COUNT];
        for (op, _) in ALL {
            let p = e.phys(*op) as usize;
            assert!(p < OP_COUNT, "phys {p} out of range");
            assert!(!seen[p], "physical id {p} assigned to two opcodes");
            seen[p] = true;
        }
        assert!(
            seen.iter().all(|&b| b),
            "phys covers the whole 0..OP_COUNT range"
        );
    }

    #[test]
    fn phys_fixed_is_identity() {
        let e = Encoding::fixed();
        for (op, _) in ALL {
            assert_eq!(
                e.phys(*op) as usize,
                *op as usize,
                "fixed().phys must be identity"
            );
        }
    }

    #[test]
    fn phys_scatters_the_identity_tail_and_dissolves_the_band() {
        for op in identity_tail() {
            assert!(
                *op as usize >= SHUFFLE_LEN,
                "tail opcode {op:?} is outside the concrete shuffle"
            );
            assert_eq!(
                Encoding::fixed().concrete(*op) as usize,
                *op as usize,
                "tail concrete is identity"
            );
        }
        let (mut moved, mut below_band) = (false, false);
        for seed in 1u64..=8 {
            let e = Encoding::from_seed(seed);
            for op in identity_tail() {
                if e.phys(*op) != e.concrete(*op) {
                    moved = true;
                }
                if (e.phys(*op) as usize) < SHUFFLE_LEN {
                    below_band = true;
                }
            }
        }
        assert!(
            moved,
            "the remap moves identity-tail opcodes off their stable id"
        );
        assert!(
            below_band,
            "tail opcodes intermix below SHUFFLE_LEN — no reserved high band remains"
        );
    }

    #[test]
    fn phys_varies_across_seeds_including_the_stable_tail() {
        let seeds = [1u64, 2, 3, 4, 5];

        let tail: Vec<u8> = seeds
            .iter()
            .map(|&s| Encoding::from_seed(s).phys(Opcode::EncFunc))
            .collect();
        assert!(
            tail.iter().any(|&v| v != tail[0]),
            "ENCFUNC physical id varies across seeds"
        );
        let core: Vec<u8> = seeds
            .iter()
            .map(|&s| Encoding::from_seed(s).phys(Opcode::Move))
            .collect();
        assert!(
            core.iter().any(|&v| v != core[0]),
            "a common opcode's physical id varies across seeds"
        );
        assert_eq!(
            Encoding::from_seed(7).phys(Opcode::Add),
            Encoding::from_seed(7).phys(Opcode::Add),
            "phys is deterministic per seed"
        );
    }
}
