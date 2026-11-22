use bytecode::opcode::{const_slot, super_const_slots, KSlot, Opcode};
use bytecode::proto::Proto;
use bytecode::superop::is_super;

use crate::rng::Rng;

pub fn shuffle_structure(proto: &Proto, seed: u64) -> Proto {
    let mut rng = Rng::new(seed ^ 0x_4259_5445_3142_5348);
    shuffle(proto, &mut rng)
}

pub fn root_proto_order(proto: &Proto, seed: u64) -> Vec<usize> {
    let mut rng = Rng::new(seed ^ 0x_4259_5445_3142_5348);
    if proto.consts.len() > 1 {
        let _ = perm(proto.consts.len(), &mut rng);
    }
    perm(proto.protos.len(), &mut rng)
}

fn perm(n: usize, rng: &mut Rng) -> Vec<usize> {
    let mut p: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        p.swap(i, rng.below(i as u64 + 1) as usize);
    }
    p
}

fn inverse(order: &[usize]) -> Vec<usize> {
    let mut inv = vec![0usize; order.len()];
    for (new_pos, &old) in order.iter().enumerate() {
        inv[old] = new_pos;
    }
    inv
}

fn shuffle(proto: &Proto, rng: &mut Rng) -> Proto {
    let mut p = proto.clone();

    let n = p.consts.len();
    if n > 1 {
        let order = perm(n, rng);
        let inv = inverse(&order);
        let new_consts: Vec<_> = order.iter().map(|&old| p.consts[old].clone()).collect();
        p.consts = new_consts;
        for inst in &mut p.code {
            if is_super(inst.op) {
                for slot in super_const_slots(inst.op) {
                    inst.ops[slot - 1] = inv[inst.ops[slot - 1] as usize] as i32;
                }
            } else {
                match const_slot(inst.op) {
                    Some(KSlot::B) => inst.b = inv[inst.b as usize] as i32,
                    Some(KSlot::C) => inst.c = inv[inst.c as usize] as i32,
                    None => {}
                }
            }
        }
    }

    let m = p.protos.len();
    if m > 1 {
        let order = perm(m, rng);
        let inv = inverse(&order);
        let new_protos: Vec<_> = order.iter().map(|&old| p.protos[old].clone()).collect();
        p.protos = new_protos;
        for inst in &mut p.code {
            if inst.op == Opcode::Closure {
                inst.b = inv[inst.b as usize] as i32;
            }
        }
    }

    let children: Vec<_> = p.protos.iter().map(|c| shuffle(c, rng)).collect();
    p.protos = children;
    p
}
