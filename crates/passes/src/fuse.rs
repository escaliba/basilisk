use std::collections::HashSet;

use bytecode::inst::Inst;
use bytecode::opcode::{fused_k, Opcode};
use bytecode::proto::Proto;
use bytecode::superop;

use crate::rng::Rng;

const FUSABLE: &[Opcode] = &[
    Opcode::Add,
    Opcode::Sub,
    Opcode::Mul,
    Opcode::Div,
    Opcode::Mod,
    Opcode::Pow,
    Opcode::IDiv,
    Opcode::Concat,
    Opcode::Eq,
    Opcode::Ne,
    Opcode::Lt,
    Opcode::Le,
    Opcode::Gt,
    Opcode::Ge,
];
const ENABLE_PERCENT: u64 = 60;
const SUPER_ENABLE_PERCENT: u64 = 60;

pub fn fuse(proto: &Proto, seed: u64) -> Proto {
    let mut rng = Rng::new(seed);
    let mut enabled_k: HashSet<Opcode> = HashSet::new();
    for &op in FUSABLE {
        if rng.chance(ENABLE_PERCENT) {
            enabled_k.insert(op);
        }
    }
    let mut enabled_super: HashSet<Opcode> = HashSet::new();
    for (sop, _) in superop::CATALOGUE {
        if superop::provenance_only(*sop) {
            continue;
        }
        if rng.chance(SUPER_ENABLE_PERCENT) {
            enabled_super.insert(*sop);
        }
    }
    fuse_proto(proto, &enabled_k, &enabled_super)
}

fn fuse_proto(
    proto: &Proto,
    enabled_k: &HashSet<Opcode>,
    enabled_super: &HashSet<Opcode>,
) -> Proto {
    let protos: Vec<Proto> = proto
        .protos
        .iter()
        .map(|c| fuse_proto(c, enabled_k, enabled_super))
        .collect();
    let mut code = proto.code.clone();

    let targets = jump_targets(&code);
    for i in 0..code.len().saturating_sub(1) {
        if code[i].op != Opcode::LoadK {
            continue;
        }
        let (rr, kc) = (code[i].a, code[i].b);
        let next = code[i + 1].clone();
        if next.a == next.b
            && next.c == rr
            && enabled_k.contains(&next.op)
            && !targets.contains(&(i + 1))
        {
            if let Some(fop) = fused_k(next.op) {
                code[i + 1].op = fop;
                code[i + 1].c = kc;
            }
        }
    }

    let code = fuse_super(code, enabled_super);
    Proto {
        code,
        protos,
        ..proto.clone()
    }
}

fn match_catalogue(
    code: &[Inst],
    i: usize,
    targets: &HashSet<usize>,
    enabled: &HashSet<Opcode>,
) -> Option<(Opcode, usize)> {
    for (sop, shape) in superop::CATALOGUE {
        if !enabled.contains(sop) {
            continue;
        }
        let len = shape.len();
        if i + len > code.len() {
            continue;
        }
        if (0..len).any(|k| code[i + k].op != shape[k]) {
            continue;
        }
        if (1..len).any(|k| targets.contains(&(i + k))) {
            continue;
        }
        return Some((*sop, len));
    }
    None
}

fn fuse_super(code: Vec<Inst>, enabled: &HashSet<Opcode>) -> Vec<Inst> {
    if enabled.is_empty() {
        return code;
    }
    let targets = jump_targets(&code);
    let mut fusions: Vec<(usize, Opcode, usize)> = Vec::new();
    let mut i = 0;
    while i < code.len() {
        if let Some((sop, len)) = match_catalogue(&code, i, &targets, enabled) {
            fusions.push((i, sop, len));
            i += len;
        } else {
            i += 1;
        }
    }
    if fusions.is_empty() {
        return code;
    }
    renumber(code, &fusions)
}

fn renumber(code: Vec<Inst>, fusions: &[(usize, Opcode, usize)]) -> Vec<Inst> {
    let n = code.len();
    let mut old_to_new = vec![0usize; n + 1];
    let mut new_pos = 0;
    let mut fi = 0;
    let mut i = 0;
    while i < n {
        if fi < fusions.len() && fusions[fi].0 == i {
            let len = fusions[fi].2;
            for k in 0..len {
                old_to_new[i + k] = new_pos;
            }
            new_pos += 1;
            i += len;
            fi += 1;
        } else {
            old_to_new[i] = new_pos;
            new_pos += 1;
            i += 1;
        }
    }
    old_to_new[n] = new_pos;

    let mut out = Vec::with_capacity(new_pos);
    let mut fi = 0;
    let mut i = 0;
    while i < n {
        if fi < fusions.len() && fusions[fi].0 == i {
            let (start, sop, len) = fusions[fi];
            let mut ops = Vec::with_capacity(3 * len);
            for k in 0..len {
                ops.push(code[start + k].a);
                ops.push(code[start + k].b);
                ops.push(code[start + k].c);
            }
            out.push(Inst::super_op(sop, ops));
            i += len;
            fi += 1;
        } else {
            let mut inst = code[i].clone();
            if let Some(off) = jump_off(&inst) {
                let t = i as i64 + 1 + off as i64;
                if (0..=n as i64).contains(&t) {
                    let new_off = old_to_new[t as usize] as i64 - old_to_new[i] as i64 - 1;
                    set_jump_off(&mut inst, new_off as i32);
                }
            }
            out.push(inst);
            i += 1;
        }
    }
    out
}

pub(crate) fn jump_off(inst: &Inst) -> Option<i32> {
    match inst.op {
        Opcode::Jmp => Some(inst.a),
        Opcode::JmpIf | Opcode::JmpIfNot | Opcode::ForPrep | Opcode::ForLoop | Opcode::TForLoop => {
            Some(inst.b)
        }
        _ => None,
    }
}

pub(crate) fn set_jump_off(inst: &mut Inst, off: i32) {
    match inst.op {
        Opcode::Jmp => inst.a = off,
        Opcode::JmpIf | Opcode::JmpIfNot | Opcode::ForPrep | Opcode::ForLoop | Opcode::TForLoop => {
            inst.b = off
        }
        _ => {}
    }
}

fn jump_targets(code: &[Inst]) -> HashSet<usize> {
    let mut targets = HashSet::new();
    for (p, inst) in code.iter().enumerate() {
        let off = match inst.op {
            Opcode::Jmp => Some(inst.a),
            Opcode::JmpIf
            | Opcode::JmpIfNot
            | Opcode::ForPrep
            | Opcode::ForLoop
            | Opcode::TForLoop => Some(inst.b),
            _ => None,
        };
        if let Some(off) = off {
            let target = p as i64 + 1 + off as i64;
            if (0..=code.len() as i64).contains(&target) {
                targets.insert(target as usize);
            }
        }
    }
    targets
}
