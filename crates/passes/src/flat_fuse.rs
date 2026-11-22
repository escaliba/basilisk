use bytecode::inst::{Inst, Prov};
use bytecode::opcode::Opcode;
use bytecode::proto::Proto;

use crate::fuse::{jump_off, set_jump_off};

pub fn flat_fuse(proto: &Proto) -> Proto {
    let protos: Vec<Proto> = proto.protos.iter().map(flat_fuse).collect();
    let code = &proto.code;

    let targets = jump_targets(code);
    let mut fuse_at: Vec<usize> = Vec::new();
    let mut i = 0;
    while i + 1 < code.len() {
        if is_disp_cmp(&code[i], Opcode::LoadK)
            && is_disp_cmp(&code[i + 1], Opcode::Eq)
            && structural_ok(&code[i], &code[i + 1])
            && !targets.contains(&(i + 1))
        {
            fuse_at.push(i);
            i += 2;
        } else {
            i += 1;
        }
    }

    if fuse_at.is_empty() {
        return Proto {
            protos,
            ..proto.clone()
        };
    }

    let n = code.len();
    let mut old_to_new = vec![0usize; n + 1];
    let mut new_pos = 0;
    let mut fi = 0;
    let mut i = 0;
    while i < n {
        if fi < fuse_at.len() && fuse_at[fi] == i {
            old_to_new[i] = new_pos;
            old_to_new[i + 1] = new_pos;
            new_pos += 1;
            i += 2;
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
        if fi < fuse_at.len() && fuse_at[fi] == i {
            let (lk, eq) = (&code[i], &code[i + 1]);
            out.push(Inst::super_op(
                Opcode::FlatStateEq,
                vec![lk.a, lk.b, lk.c, eq.a, eq.b, eq.c],
            ));
            i += 2;
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

    Proto {
        code: out,
        protos,
        ..proto.clone()
    }
}

fn is_disp_cmp(inst: &Inst, op: Opcode) -> bool {
    inst.op == op && inst.prov == Some(Prov::FlatDispatchCmp)
}

fn structural_ok(lk: &Inst, eq: &Inst) -> bool {
    lk.a == eq.a && eq.a == eq.c && eq.b == lk.a - 1
}

fn jump_targets(code: &[Inst]) -> std::collections::HashSet<usize> {
    let mut targets = std::collections::HashSet::new();
    for (p, inst) in code.iter().enumerate() {
        if let Some(off) = jump_off(inst) {
            let target = p as i64 + 1 + off as i64;
            if (0..=code.len() as i64).contains(&target) {
                targets.insert(target as usize);
            }
        }
    }
    targets
}
