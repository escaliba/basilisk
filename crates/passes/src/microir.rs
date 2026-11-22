use std::collections::{HashMap, HashSet};

use bytecode::cfg::Cfg;
use bytecode::opcode::Opcode;
use bytecode::proto::Proto;

use crate::rng::Rng;

const MULT: u32 = 1000003;

fn mix(sel: u32, imm: u32) -> u32 {
    sel.wrapping_mul(MULT).wrapping_add(imm)
}

fn reset_sel(imm: u32) -> u32 {
    imm.wrapping_mul(MULT)
}

fn target_code(op: Opcode) -> Option<u32> {
    match op {
        Opcode::AddK => Some(0),
        Opcode::SubK => Some(1),
        Opcode::MulK => Some(2),
        _ => None,
    }
}

fn blocks_on_cycle(cfg: &Cfg) -> HashSet<usize> {
    let n = cfg.blocks.len();
    let succ: Vec<Vec<usize>> = (0..n)
        .map(|b| {
            bytecode::blockstate::successors(&cfg.blocks[b].term)
                .into_iter()
                .filter(|&s| s < n)
                .collect()
        })
        .collect();
    let mut on_cycle = HashSet::new();
    for start in 0..n {
        let mut stack = vec![(start, 0usize)];
        let mut seen = HashSet::new();
        seen.insert(start);
        while let Some(&(node, i)) = stack.last() {
            if i < succ[node].len() {
                stack.last_mut().unwrap().1 += 1;
                let s = succ[node][i];
                if s == start {
                    on_cycle.insert(start);
                    break;
                }
                if seen.insert(s) {
                    stack.push((s, 0));
                }
            } else {
                stack.pop();
            }
        }
    }
    on_cycle
}

pub fn lower_microir(proto: &Proto, seed: u64) -> Proto {
    let mut p = proto.clone();
    p.protos = p.protos.iter().map(|c| lower_microir(c, seed)).collect();

    let cfg = Cfg::from_code(&p.code);
    let loops = blocks_on_cycle(&cfg);
    let mut rng = Rng::new(seed ^ 0x_4D49_4352_4F49_5231);
    let mut reset_done: HashSet<usize> = HashSet::new();
    let mut sel_of: HashMap<usize, u32> = HashMap::new();

    for pc in 0..p.code.len() {
        let Some(target) = target_code(p.code[pc].op) else {
            continue;
        };
        let block = cfg.block_of(pc);
        if loops.contains(&block) {
            continue;
        }
        if reset_done.insert(block) {
            let base = (rng.below(80) as u32) * 3;
            let imm = base + target;
            sel_of.insert(block, reset_sel(imm));
            p.code[pc].op = Opcode::MApplyReset;
            p.code[pc].b = imm as i32;
        } else {
            let prev = *sel_of.get(&block).unwrap();
            let base = rng.below(253) as u32;
            let mut chosen = base;
            for d in 0..3u32 {
                if mix(prev, base + d) % 3 == target {
                    chosen = base + d;
                    break;
                }
            }
            sel_of.insert(block, mix(prev, chosen));
            p.code[pc].op = Opcode::MApplyFold;
            p.code[pc].b = chosen as i32;
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_op_is_imm_mod_three() {
        for op in 0..3u32 {
            let imm = 3 * 7 + op;
            assert_eq!(reset_sel(imm) % 3, op, "reset delta encodes the op mod 3");
        }
    }

    #[test]
    fn fold_search_always_hits_target() {
        for prev in [0u32, 1, 2, 12345, 0xFFFF_FFFF, 0x8000_0000] {
            for target in 0..3u32 {
                let base = 100u32;
                let mut ok = false;
                for d in 0..3 {
                    if mix(prev, base + d) % 3 == target {
                        ok = true;
                        break;
                    }
                }
                assert!(
                    ok,
                    "a delta in {{base,base+1,base+2}} always reaches the target op"
                );
            }
        }
    }
}
