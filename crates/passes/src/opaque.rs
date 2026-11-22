use bytecode::cfg::Cfg;
use bytecode::inst::Inst;
use bytecode::opcode::Opcode;
use bytecode::proto::Proto;

use crate::rng::Rng;
use crate::{lower, predicate};

const GUARD_PERCENT: u64 = 50;

pub fn opaque(proto: &Proto, seed: u64) -> Proto {
    let mut rng = Rng::new(seed);
    insert_proto(proto, &mut rng)
}

fn insert_proto(proto: &Proto, rng: &mut Rng) -> Proto {
    let protos: Vec<Proto> = proto.protos.iter().map(|c| insert_proto(c, rng)).collect();

    let cfg = Cfg::from_code(&proto.code);
    let n = cfg.blocks.len();

    let r_op = proto.max_stack as i32;
    let (s, z) = (r_op + 1, r_op + 2);

    let mut consts = proto.consts.clone();
    let pool = predicate::pool(&mut consts, rng);

    let mut guarded = vec![false; n];
    let mut any = false;
    for g in guarded.iter_mut() {
        if rng.chance(GUARD_PERCENT) {
            *g = true;
            any = true;
        }
    }
    if !any && n > 0 {
        guarded[rng.below(n as u64) as usize] = true;
        any = true;
    }
    if !any {
        return Proto {
            protos,
            ..proto.clone()
        };
    }

    let mut code: Vec<Inst> = Vec::new();
    code.push(Inst::new(Opcode::LoadK, r_op, pool.seed, 0));

    let mut block_start = vec![0usize; n];
    let mut jumps: Vec<(usize, usize)> = Vec::new();
    let mut guard_jumps: Vec<usize> = Vec::new();

    for b in 0..n {
        block_start[b] = code.len();
        if guarded[b] {
            guard_jumps.push(predicate::emit_guard(&mut code, rng, r_op, s, z, &pool));
        }
        code.extend_from_slice(&cfg.blocks[b].body);
        lower::emit_terminator(&mut code, &cfg.blocks[b].term, b, &mut jumps);
    }

    let junk_start = code.len();
    code.push(Inst::new(Opcode::Mul, z, r_op, r_op));
    code.push(Inst::new(Opcode::Return, z, 1, 0));

    for (at, target) in jumps {
        lower::patch_jump(&mut code, at, block_start[target]);
    }
    for at in guard_jumps {
        code[at].b = lower::rel(junk_start, at);
    }

    Proto {
        code,
        consts,
        protos,
        max_stack: proto.max_stack + 3,
        ..proto.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecode::proto::Const;

    #[test]
    fn guards_compute_over_a_runtime_register() {
        let mut p = Proto::default();
        p.max_stack = 4;
        p.consts = vec![Const::Number(1.0)];
        p.code = vec![
            Inst::new(Opcode::LoadBool, 0, 1, 0),
            Inst::new(Opcode::JmpIf, 0, 1, 0),
            Inst::new(Opcode::LoadK, 1, 0, 0),
            Inst::new(Opcode::Return, 0, 1, 0),
        ];
        let out = opaque(&p, 7);
        let r_op = 4;
        let over_r_op = out.code.iter().any(|i| {
            matches!(i.op, Opcode::Mul | Opcode::Le | Opcode::Lt | Opcode::Ge)
                && (i.b == r_op || i.c == r_op)
        });
        assert!(
            over_r_op,
            "opaque guard must compute over the runtime register r_op"
        );
        let to_junk = out
            .code
            .iter()
            .any(|i| matches!(i.op, Opcode::JmpIf | Opcode::JmpIfNot) && i.a == r_op + 1);
        assert!(to_junk, "a guard must branch on the predicate register");
        assert_eq!(out.max_stack, p.max_stack + 3);
    }
}
