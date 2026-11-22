use bytecode::inst::Inst;
use bytecode::opcode::Opcode;
use bytecode::proto::Const;

use crate::lower::add_number;
use crate::rng::Rng;

pub struct Pool {
    pub zero: i32,
    pub seed: i32,
    pub muts: Vec<i32>,
}

pub fn pool(consts: &mut Vec<Const>, rng: &mut Rng) -> Pool {
    Pool {
        zero: add_number(consts, 0.0),
        seed: add_number(consts, (rng.below(9_000) + 1_000) as f64),
        muts: (0..3)
            .map(|_| add_number(consts, (rng.below(64) * 2 + 1) as f64))
            .collect(),
    }
}

pub fn emit_guard(
    code: &mut Vec<Inst>,
    rng: &mut Rng,
    r_op: i32,
    s: i32,
    z: i32,
    p: &Pool,
) -> usize {
    code.push(Inst::new(Opcode::LoadK, r_op, p.seed, 0));
    if rng.chance(34) {
        let kc = p.muts[rng.below(p.muts.len() as u64) as usize];
        code.push(Inst::new(Opcode::LoadK, z, kc, 0));
        code.push(Inst::new(Opcode::Add, r_op, r_op, z));
    }
    let jmp = match rng.below(4) {
        0 => {
            code.push(Inst::new(Opcode::Mul, s, r_op, r_op));
            code.push(Inst::new(Opcode::LoadK, z, p.zero, 0));
            code.push(Inst::new(Opcode::Ge, s, s, z));
            Opcode::JmpIfNot
        }
        1 => {
            code.push(Inst::new(Opcode::Mul, s, r_op, r_op));
            code.push(Inst::new(Opcode::LoadK, z, p.zero, 0));
            code.push(Inst::new(Opcode::Lt, s, s, z));
            Opcode::JmpIf
        }
        2 => {
            code.push(Inst::new(Opcode::Le, s, r_op, r_op));
            Opcode::JmpIfNot
        }
        _ => {
            code.push(Inst::new(Opcode::Lt, s, r_op, r_op));
            Opcode::JmpIf
        }
    };
    let at = code.len();
    code.push(Inst::new(jmp, s, 0, 0));
    at
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    #[test]
    fn guard_reloads_r_op_before_its_arithmetic() {
        let pool = Pool {
            zero: 0,
            seed: 1,
            muts: vec![2, 3, 4],
        };
        let r_op = 9;
        for seed in 0..256u64 {
            let mut code: Vec<Inst> = Vec::new();
            let mut rng = Rng::new(seed);
            emit_guard(&mut code, &mut rng, r_op, r_op + 1, r_op + 2, &pool);
            assert!(!code.is_empty());
            assert_eq!(
                code[0].op,
                Opcode::LoadK,
                "guard must first (re)load r_op (seed {seed})"
            );
            assert_eq!(code[0].a, r_op, "reload targets r_op (seed {seed})");
            assert_eq!(
                code[0].b, pool.seed,
                "reload uses the numeric seed constant (seed {seed})"
            );
            let first_rop_arith = code.iter().position(|i| {
                matches!(i.op, Opcode::Mul | Opcode::Add) && (i.b == r_op || i.c == r_op)
            });
            if let Some(p) = first_rop_arith {
                assert!(
                    p > 0,
                    "arithmetic on r_op is preceded by its reload (seed {seed})"
                );
            }
        }
    }
}
