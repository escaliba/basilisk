use bytecode::inst::Inst;
use bytecode::opcode::Opcode;
use bytecode::proto::Proto;

use crate::fuse::{jump_off, set_jump_off};
use crate::rng::Rng;

const DENSITY: u64 = 28;

pub fn pad_decoys(proto: &Proto, seed: u64) -> Proto {
    let mut rng = Rng::new(seed ^ 0x_4259_5445_3143_5041);
    pad(proto, &mut rng)
}

fn pad(proto: &Proto, rng: &mut Rng) -> Proto {
    let mut p = proto.clone();
    p.code = insert_pads(&p.code, rng);
    let children: Vec<_> = p.protos.iter().map(|c| pad(c, rng)).collect();
    p.protos = children;
    p
}

fn insert_pads(code: &[Inst], rng: &mut Rng) -> Vec<Inst> {
    let n = code.len();
    if n == 0 {
        return Vec::new();
    }

    let pad_before: Vec<bool> = (0..n).map(|i| i > 0 && rng.below(DENSITY) == 0).collect();
    let mut old_to_new = vec![0usize; n + 1];
    let mut acc = 0usize;
    for i in 0..n {
        if pad_before[i] {
            acc += 1;
        }
        old_to_new[i] = i + acc;
    }
    old_to_new[n] = n + acc;
    let mut out: Vec<Inst> = Vec::with_capacity(n + acc);
    for i in 0..n {
        if pad_before[i] {
            out.push(make_pad(rng));
        }
        let mut inst = code[i].clone();
        if let Some(off) = jump_off(&inst) {
            let t = i as i64 + 1 + off as i64;
            if (0..=n as i64).contains(&t) {
                let new_off = old_to_new[t as usize] as i64 - old_to_new[i] as i64 - 1;
                set_jump_off(&mut inst, new_off as i32);
            }
        }
        out.push(inst);
    }
    out
}

fn make_pad(rng: &mut Rng) -> Inst {
    Inst {
        op: Opcode::Pad,
        a: rng.below(256) as i32,
        b: rng.below(256) as i32,
        c: rng.below(256) as i32,
        ops: Vec::new(),
        prov: None,
    }
}
