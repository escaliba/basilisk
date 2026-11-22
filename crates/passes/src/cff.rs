use bytecode::cfg::{Cfg, Terminator};
use bytecode::inst::{Inst, Prov};
use bytecode::opcode::Opcode;
use bytecode::proto::{Const, Proto};

use crate::rng::Rng;

pub fn flatten(proto: &Proto, seed: u64) -> Proto {
    let mut rng = Rng::new(seed);
    flatten_proto(proto, &mut rng, false)
}

pub fn flatten_d1(proto: &Proto, seed: u64) -> Proto {
    let mut rng = Rng::new(seed);
    flatten_proto(proto, &mut rng, true)
}

fn flatten_proto(proto: &Proto, rng: &mut Rng, d1: bool) -> Proto {
    let protos: Vec<Proto> = proto
        .protos
        .iter()
        .map(|c| flatten_proto(c, rng, d1))
        .collect();

    let cfg = Cfg::from_code(&proto.code);
    let nblocks = cfg.blocks.len();
    if nblocks < 2 {
        return Proto {
            protos,
            ..proto.clone()
        };
    }

    let mut consts = proto.consts.clone();
    let state_reg = proto.max_stack as i32;
    let cmp_reg = state_reg + 1;

    let mult = rng.next_u64() | 1;
    let offset = rng.next_u64();
    let mut id_const = Vec::with_capacity(nblocks);
    for i in 0..nblocks {
        let id = ((i as u64).wrapping_mul(mult).wrapping_add(offset) & 0xFFFF_FFFF) as f64;
        id_const.push(consts.len() as i32);
        consts.push(Const::FlatBlockId(id));
    }

    let mut code: Vec<Inst> = Vec::new();
    code.push(Inst::new(Opcode::LoadK, state_reg, id_const[0], 0));
    let dispatcher = code.len();

    let mut disp_order: Vec<usize> = (0..nblocks).collect();
    rng.shuffle(&mut disp_order);
    let mut disp_jmpif: Vec<(usize, usize)> = Vec::new();
    for &b in &disp_order {
        let mut load_id = Inst::new(Opcode::LoadK, cmp_reg, id_const[b], 0);
        load_id.prov = Some(Prov::FlatDispatchCmp);
        code.push(load_id);
        let mut cmp = Inst::new(Opcode::Eq, cmp_reg, state_reg, cmp_reg);
        cmp.prov = Some(Prov::FlatDispatchCmp);
        code.push(cmp);
        disp_jmpif.push((code.len(), b));
        code.push(Inst::new(Opcode::JmpIf, cmp_reg, 0, 0));
    }

    code.push(Inst::new(Opcode::Return, state_reg, 1, 0));

    let mut layout: Vec<usize> = (0..nblocks).collect();
    rng.shuffle(&mut layout);
    let mut block_start = vec![0usize; nblocks];
    let mut back_to_dispatcher: Vec<usize> = Vec::new();
    for &b in &layout {
        block_start[b] = code.len();
        code.extend_from_slice(&cfg.blocks[b].body);
        emit_terminator(
            &mut code,
            &cfg.blocks[b].term,
            state_reg,
            &id_const,
            &mut back_to_dispatcher,
            d1,
            b,
        );
    }

    for (at, b) in disp_jmpif {
        code[at].b = rel(block_start[b], at);
    }
    for at in back_to_dispatcher {
        code[at].a = rel(dispatcher, at);
    }

    Proto {
        code,
        consts,
        protos,
        max_stack: proto.max_stack + 2,
        ..proto.clone()
    }
}

fn rel(to: usize, at: usize) -> i32 {
    (to as i64 - (at as i64 + 1)) as i32
}

fn emit_goto(
    code: &mut Vec<Inst>,
    block: usize,
    state_reg: i32,
    id_const: &[i32],
    back: &mut Vec<usize>,
    d1: bool,
    pred: usize,
) {
    if d1 {
        let mut bs = Inst::new(Opcode::BStateStep, 0, 0, 0);
        bs.prov = Some(Prov::BStateEdge(pred as u32, block as u32));
        code.push(bs);
    }
    code.push(Inst::new(Opcode::LoadK, state_reg, id_const[block], 0));
    back.push(code.len());
    code.push(Inst::new(Opcode::Jmp, 0, 0, 0));
}

fn emit_terminator(
    code: &mut Vec<Inst>,
    term: &Terminator,
    state_reg: i32,
    id_const: &[i32],
    back: &mut Vec<usize>,
    d1: bool,
    pred: usize,
) {
    match term {
        Terminator::Goto(s) => emit_goto(code, *s, state_reg, id_const, back, d1, pred),
        Terminator::Branch {
            cond,
            when_true,
            when_false,
        } => {
            let jmpif = code.len();
            code.push(Inst::new(Opcode::JmpIf, *cond, 0, 0));
            emit_goto(code, *when_false, state_reg, id_const, back, d1, pred);
            let l_true = code.len();
            code[jmpif].b = rel(l_true, jmpif);
            emit_goto(code, *when_true, state_reg, id_const, back, d1, pred);
        }
        Terminator::NumericForPrep { a, target } => {
            code.push(Inst::new(Opcode::ForPrep, *a, 0, 0));
            emit_goto(code, *target, state_reg, id_const, back, d1, pred);
        }
        Terminator::NumericForLoop { a, body, exit } => {
            let forl = code.len();
            code.push(Inst::new(Opcode::ForLoop, *a, 0, 0));
            emit_goto(code, *exit, state_reg, id_const, back, d1, pred);
            let l_cont = code.len();
            code[forl].b = rel(l_cont, forl);
            emit_goto(code, *body, state_reg, id_const, back, d1, pred);
        }
        Terminator::GenericForLoop { a, body, exit } => {
            let tforl = code.len();
            code.push(Inst::new(Opcode::TForLoop, *a, 0, 0));
            emit_goto(code, *exit, state_reg, id_const, back, d1, pred);
            let l_cont = code.len();
            code[tforl].b = rel(l_cont, tforl);
            emit_goto(code, *body, state_reg, id_const, back, d1, pred);
        }
        Terminator::Return(inst) => code.push(inst.clone()),
    }
}
