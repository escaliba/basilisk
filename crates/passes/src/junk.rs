use bytecode::cfg::Cfg;
use bytecode::inst::Inst;
use bytecode::opcode::Opcode;
use bytecode::proto::Proto;

use crate::rng::Rng;
use crate::{lower, predicate};

const GUARD_PERCENT: u64 = 40;
const JUNK_BLOCK_MIN: u64 = 4;
const JUNK_BLOCK_SPAN: u64 = 9;
const FAKE_CONST_COUNT: usize = 8;

pub fn junk(proto: &Proto, seed: u64) -> Proto {
    let mut rng = Rng::new(seed);
    insert_proto(proto, &mut rng)
}

fn insert_proto(proto: &Proto, rng: &mut Rng) -> Proto {
    let protos: Vec<Proto> = proto.protos.iter().map(|c| insert_proto(c, rng)).collect();

    let cfg = Cfg::from_code(&proto.code);
    let n = cfg.blocks.len();

    let r_op = proto.max_stack as i32;
    let (s, z) = (r_op + 1, r_op + 2);
    let scratch = [r_op + 1, r_op + 2, r_op + 3, r_op + 4];

    let mut consts = proto.consts.clone();
    let pool = predicate::pool(&mut consts, rng);
    let fake: Vec<i32> = (0..FAKE_CONST_COUNT)
        .map(|_| lower::add_number(&mut consts, rng.below(1_000_000) as f64))
        .collect();

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

    let mut junk_start = Vec::with_capacity(guard_jumps.len());
    for _ in 0..guard_jumps.len() {
        junk_start.push(code.len());
        emit_junk_block(&mut code, rng, &scratch, &fake, n, &mut jumps);
    }

    for (i, at) in guard_jumps.iter().enumerate() {
        code[*at].b = lower::rel(junk_start[i], *at);
    }
    for (at, target) in jumps {
        lower::patch_jump(&mut code, at, block_start[target]);
    }

    Proto {
        code,
        consts,
        protos,
        max_stack: proto.max_stack + 5,
        ..proto.clone()
    }
}

fn emit_fake_op(code: &mut Vec<Inst>, rng: &mut Rng, scratch: &[i32], fake: &[i32]) {
    let d = scratch[rng.below(scratch.len() as u64) as usize];
    let a = scratch[rng.below(scratch.len() as u64) as usize];
    let b = scratch[rng.below(scratch.len() as u64) as usize];
    match rng.below(7) {
        0 => code.push(Inst::new(
            Opcode::LoadK,
            d,
            fake[rng.below(fake.len() as u64) as usize],
            0,
        )),
        1 => code.push(Inst::new(Opcode::Move, d, a, 0)),
        2 => code.push(Inst::new(Opcode::Add, d, a, b)),
        3 => code.push(Inst::new(Opcode::Mul, d, a, b)),
        4 => code.push(Inst::new(Opcode::Sub, d, a, b)),
        5 => code.push(Inst::new(Opcode::Concat, d, a, b)),
        _ => code.push(Inst::new(Opcode::GetTable, d, a, b)),
    }
}

fn emit_junk_block(
    code: &mut Vec<Inst>,
    rng: &mut Rng,
    scratch: &[i32],
    fake: &[i32],
    n_blocks: usize,
    jumps: &mut Vec<(usize, usize)>,
) {
    for _ in 0..JUNK_BLOCK_MIN + rng.below(JUNK_BLOCK_SPAN) {
        emit_fake_op(code, rng, scratch, fake);
    }
    if rng.chance(60) {
        code.push(Inst::new(Opcode::Return, scratch[0], 1, 0));
    } else {
        jumps.push((code.len(), rng.below(n_blocks as u64) as usize));
        code.push(Inst::new(Opcode::Jmp, 0, 0, 0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecode::proto::Const;

    #[test]
    fn junk_blocks_are_opaque_gated() {
        let mut p = Proto::default();
        p.max_stack = 4;
        p.consts = vec![Const::Number(1.0)];
        p.code = vec![
            Inst::new(Opcode::LoadBool, 0, 1, 0),
            Inst::new(Opcode::JmpIf, 0, 1, 0),
            Inst::new(Opcode::LoadK, 1, 0, 0),
            Inst::new(Opcode::Return, 0, 1, 0),
        ];
        let out = junk(&p, 3);

        let r_op = 4;
        let gated = out.code.iter().any(|i| {
            matches!(i.op, Opcode::Mul | Opcode::Le | Opcode::Lt | Opcode::Ge)
                && (i.b == r_op || i.c == r_op)
        });
        assert!(
            gated,
            "junk must be reached only through an opaque guard over r_op"
        );
        assert!(out.code.len() > p.code.len(), "junk must add instructions");
    }
}
