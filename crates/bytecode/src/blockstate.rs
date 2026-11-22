use crate::cfg::{Cfg, Terminator};
use crate::crypt;
use crate::opcode::{self, KSlot};
use crate::proto::{Const, Proto};
use crate::superop;
use std::collections::{BTreeMap, HashMap, VecDeque};

pub struct Aliased {
    pub proto: Proto,
    pub record_block: Vec<usize>,
}

fn alias_of(
    map: &mut HashMap<(usize, usize), usize>,
    new_consts: &mut Vec<Const>,
    record_block: &mut Vec<usize>,
    orig: &[Const],
    block: usize,
    ci: usize,
) -> usize {
    if let Some(&idx) = map.get(&(block, ci)) {
        return idx;
    }
    let idx = new_consts.len();
    new_consts.push(orig[ci].clone());
    record_block.push(block);
    map.insert((block, ci), idx);
    idx
}

pub fn d1_alias(proto: &Proto) -> Aliased {
    let cfg = Cfg::from_code(&proto.code);
    let mut code = proto.code.clone();
    let mut new_consts: Vec<Const> = Vec::new();
    let mut record_block: Vec<usize> = Vec::new();
    let mut map: HashMap<(usize, usize), usize> = HashMap::new();

    for pc in 0..code.len() {
        let block = cfg.block_of(pc);
        let op = code[pc].op;
        if superop::is_super(op) {
            for slot in opcode::super_const_slots(op) {
                let ci = code[pc].ops[slot - 1] as usize;
                let idx = alias_of(
                    &mut map,
                    &mut new_consts,
                    &mut record_block,
                    &proto.consts,
                    block,
                    ci,
                );
                code[pc].ops[slot - 1] = idx as i32;
            }
        } else if let Some(s) = opcode::const_slot(op) {
            let ci = (match s {
                KSlot::B => code[pc].b,
                KSlot::C => code[pc].c,
            }) as usize;
            let idx = alias_of(
                &mut map,
                &mut new_consts,
                &mut record_block,
                &proto.consts,
                block,
                ci,
            );
            match s {
                KSlot::B => code[pc].b = idx as i32,
                KSlot::C => code[pc].c = idx as i32,
            }
        }
    }

    for (ci, k) in proto.consts.iter().enumerate() {
        if !map.keys().any(|&(_, o)| o == ci) {
            new_consts.push(k.clone());
            record_block.push(0);
        }
    }

    let proto = Proto {
        consts: new_consts,
        code,
        ..proto.clone()
    };
    Aliased {
        proto,
        record_block,
    }
}

pub fn d1_prepare(proto: &Proto) -> Proto {
    let a = d1_alias(proto);
    let mut p = a.proto;
    p.d1 = Some(crate::proto::D1Meta {
        record_block: a.record_block,
    });
    p.protos = p.protos.iter().map(d1_prepare).collect();
    p
}

pub struct BlockState {
    pub bstate: Vec<u32>,
    pub edge_corr: BTreeMap<(usize, usize), u32>,
}

pub fn solve_edges(
    nblocks: usize,
    edges: &[(usize, usize)],
    genkey: &[u32; 8],
    seed: u64,
    pid: u32,
) -> BlockState {
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); nblocks];
    for &(p, s) in edges {
        if p < nblocks && s < nblocks {
            succ[p].push(s);
        }
    }
    let mut bstate = vec![0u32; nblocks];
    let mut edge_corr = BTreeMap::new();
    if nblocks == 0 {
        return BlockState { bstate, edge_corr };
    }
    bstate[0] = crypt::d1_root(genkey, seed, pid);
    let mut set = vec![false; nblocks];
    set[0] = true;
    let mut queue = VecDeque::new();
    queue.push_back(0usize);
    while let Some(p) = queue.pop_front() {
        for &s in &succ[p] {
            if !set[s] {
                let corr = crypt::block_tree_corr(seed, pid, p as u32, s as u32);
                bstate[s] = crypt::block_state_transition(bstate[p], corr, seed);
                edge_corr.insert((p, s), corr);
                set[s] = true;
                queue.push_back(s);
            }
        }
    }
    for &(p, s) in edges {
        if p < nblocks && s < nblocks {
            edge_corr
                .entry((p, s))
                .or_insert_with(|| crypt::block_edge_correction(bstate[s], bstate[p], seed));
        }
    }
    BlockState { bstate, edge_corr }
}

pub fn successors(t: &Terminator) -> Vec<usize> {
    match t {
        Terminator::Goto(b) => vec![*b],
        Terminator::Branch {
            when_true,
            when_false,
            ..
        } => vec![*when_true, *when_false],
        Terminator::NumericForPrep { target, .. } => vec![*target],
        Terminator::NumericForLoop { body, exit, .. } => vec![*body, *exit],
        Terminator::GenericForLoop { body, exit, .. } => vec![*body, *exit],
        Terminator::Return(_) => vec![],
    }
}

pub fn solve(cfg: &Cfg, genkey: &[u32; 8], seed: u64, pid: u32) -> BlockState {
    let nb = cfg.blocks.len();
    let mut bstate = vec![0u32; nb];
    let mut edge_corr = BTreeMap::new();
    if nb == 0 {
        return BlockState { bstate, edge_corr };
    }
    bstate[0] = crypt::d1_root(genkey, seed, pid);
    let mut set = vec![false; nb];
    set[0] = true;
    let mut queue = VecDeque::new();
    queue.push_back(0usize);
    while let Some(p) = queue.pop_front() {
        for s in successors(&cfg.blocks[p].term) {
            if s >= nb {
                continue;
            }
            if !set[s] {
                let corr = crypt::block_tree_corr(seed, pid, p as u32, s as u32);
                bstate[s] = crypt::block_state_transition(bstate[p], corr, seed);
                edge_corr.insert((p, s), corr);
                set[s] = true;
                queue.push_back(s);
            }
        }
    }
    for p in 0..nb {
        for s in successors(&cfg.blocks[p].term) {
            if s >= nb {
                continue;
            }
            edge_corr
                .entry((p, s))
                .or_insert_with(|| crypt::block_edge_correction(bstate[s], bstate[p], seed));
        }
    }
    BlockState { bstate, edge_corr }
}

pub fn use_site_blocks(proto: &Proto) -> Vec<Option<usize>> {
    let cfg = Cfg::from_code(&proto.code);
    let mut out = vec![None; proto.consts.len()];
    for (pc, inst) in proto.code.iter().enumerate() {
        let block = cfg.block_of(pc);
        let mut bind = |ci: usize| {
            if ci < out.len() && out[ci].is_none() {
                out[ci] = Some(block);
            }
        };
        if superop::is_super(inst.op) {
            for slot in opcode::super_const_slots(inst.op) {
                bind(inst.ops[slot - 1] as usize);
            }
        } else if let Some(s) = opcode::const_slot(inst.op) {
            bind(match s {
                KSlot::B => inst.b,
                KSlot::C => inst.c,
            } as usize);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::BasicBlock;
    use crate::inst::Inst;
    use crate::opcode::Opcode;
    use crate::proto::Const;

    fn manual_cfg(terms: Vec<Terminator>) -> Cfg {
        let nb = terms.len();
        let blocks = terms
            .into_iter()
            .map(|t| BasicBlock {
                body: vec![],
                term: t,
            })
            .collect();
        Cfg {
            blocks,
            starts: (0..nb).collect(),
        }
    }

    fn simulate(bs: &BlockState, seed: u64, path: &[(usize, usize)]) -> u32 {
        let mut st = bs.bstate[0];
        for &(p, s) in path {
            st = crypt::block_state_transition(st, bs.edge_corr[&(p, s)], seed);
        }
        st
    }

    #[test]
    fn diamond_and_loop_converge_across_paths() {
        let cfg = manual_cfg(vec![
            Terminator::Branch {
                cond: 0,
                when_true: 1,
                when_false: 2,
            },
            Terminator::Goto(3),
            Terminator::Goto(3),
            Terminator::Goto(4),
            Terminator::Branch {
                cond: 0,
                when_true: 5,
                when_false: 6,
            },
            Terminator::Goto(4),
            Terminator::Return(Inst::new(Opcode::Return, 0, 1, 0)),
        ]);
        let seed = 0xABCDEF;
        let genkey = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let bs = solve(&cfg, &genkey, seed, 3);

        let via1 = simulate(&bs, seed, &[(0, 1), (1, 3)]);
        let via2 = simulate(&bs, seed, &[(0, 2), (2, 3)]);
        assert_eq!(via1, bs.bstate[3]);
        assert_eq!(via2, bs.bstate[3]);
        assert_eq!(via1, via2);

        let iter0 = simulate(&bs, seed, &[(0, 1), (1, 3), (3, 4)]);
        let iter1 = simulate(&bs, seed, &[(0, 1), (1, 3), (3, 4), (4, 5), (5, 4)]);
        let iter2 = simulate(
            &bs,
            seed,
            &[(0, 1), (1, 3), (3, 4), (4, 5), (5, 4), (4, 5), (5, 4)],
        );
        assert_eq!(iter0, bs.bstate[4]);
        assert_eq!(iter1, bs.bstate[4]);
        assert_eq!(iter2, bs.bstate[4]);
    }

    #[test]
    fn edge_correction_requires_predecessor_propagation() {
        let seed = 0x1234_5678;
        let cfg = manual_cfg(vec![
            Terminator::Branch {
                cond: 0,
                when_true: 1,
                when_false: 2,
            },
            Terminator::Goto(2),
            Terminator::Return(Inst::new(Opcode::Return, 0, 1, 0)),
        ]);
        let bs = solve(&cfg, &[1u32; 8], seed, 0);
        let corr = bs.edge_corr[&(1, 2)];
        let wrong = crypt::block_state_transition(bs.bstate[0], corr, seed);
        assert_ne!(wrong, bs.bstate[2]);
        assert_eq!(
            crypt::block_state_transition(bs.bstate[1], corr, seed),
            bs.bstate[2]
        );
    }

    fn num(c: &Const) -> f64 {
        match c {
            Const::Number(n) | Const::FlatBlockId(n) => *n,
            Const::Str(_) => f64::NAN,
        }
    }

    fn use_site_const(code: &[Inst], pc: usize) -> Option<usize> {
        let inst = &code[pc];
        if let Some(s) = opcode::const_slot(inst.op) {
            return Some(
                (match s {
                    KSlot::B => inst.b,
                    KSlot::C => inst.c,
                }) as usize,
            );
        }
        None
    }

    #[test]
    fn d1_root_is_deterministic_input_sensitive_and_code_independent() {
        let gk = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let a = crypt::d1_root(&gk, 7, 3);
        assert_eq!(a, crypt::d1_root(&gk, 7, 3));
        assert_ne!(a, crypt::d1_root(&gk, 7, 4));
        assert_ne!(a, crypt::d1_root(&gk, 8, 3));
        assert_ne!(a, crypt::d1_root(&[1u32, 2, 3, 99, 5, 6, 7, 8], 7, 3));
        assert_ne!(a, crypt::d1_root(&[1u32, 2, 3, 4, 99, 6, 7, 8], 7, 3));
    }

    #[test]
    fn d1_root_golden_vectors() {
        let gk = [
            0x1111_1111u32,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x5555_5555,
            0x6666_6666,
            0x7777_7777,
            0x8888_8888,
        ];
        let vals = [
            crypt::d1_root(&gk, 7, 0),
            crypt::d1_root(&gk, 7, 3),
            crypt::d1_root(&gk, 42, 1),
        ];
        assert_eq!(vals, [1699860353u32, 3801864019, 2657421996]);
    }

    #[test]
    fn code_digest_ignores_operand_values_so_d1_root_cannot_include_corr() {
        let enc = crate::encoding::Encoding::from_seed(3);
        let mk = |corr: i32| Proto {
            num_params: 0,
            is_vararg: false,
            max_stack: 1,
            code: vec![
                Inst::new(Opcode::BStateStep, corr, 0, 0),
                Inst::new(Opcode::Return, 0, 1, 0),
            ],
            consts: vec![],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        assert_eq!(
            crypt::code_digest(&mk(111), &enc),
            crypt::code_digest(&mk(222), &enc),
            "genkey digest must not fold the BStateStep corr operand (acyclic gate)"
        );
    }

    #[test]
    fn solver_root_is_d1_root_and_has_no_code_dependency() {
        let cfg = manual_cfg(vec![
            Terminator::Branch {
                cond: 0,
                when_true: 1,
                when_false: 2,
            },
            Terminator::Goto(2),
            Terminator::Return(Inst::new(Opcode::Return, 0, 1, 0)),
        ]);
        let gk = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let bs = solve(&cfg, &gk, 5, 0);
        assert_eq!(bs.bstate[0], crypt::d1_root(&gk, 5, 0));
    }

    #[test]
    fn same_const_twice_in_one_block_shares_one_alias() {
        let code = vec![
            Inst::new(Opcode::LoadK, 0, 0, 0),
            Inst::new(Opcode::LoadK, 1, 0, 0),
            Inst::new(Opcode::Return, 0, 1, 0),
        ];
        let proto = Proto {
            num_params: 0,
            is_vararg: false,
            max_stack: 2,
            code,
            consts: vec![Const::Number(7.0)],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        let a = d1_alias(&proto);
        assert_eq!(a.proto.consts.len(), 1);
        assert_eq!(a.proto.code[0].b, a.proto.code[1].b);
        assert_eq!(a.record_block, vec![0]);
    }

    #[test]
    fn same_const_in_sibling_branches_gets_distinct_aliases() {
        let code = vec![
            Inst::new(Opcode::LoadBool, 0, 1, 0),
            Inst::new(Opcode::JmpIf, 0, 2, 0),
            Inst::new(Opcode::LoadK, 1, 0, 0),
            Inst::new(Opcode::Jmp, 1, 0, 0),
            Inst::new(Opcode::LoadK, 1, 0, 0),
            Inst::new(Opcode::Return, 0, 1, 0),
        ];
        let proto = Proto {
            num_params: 0,
            is_vararg: false,
            max_stack: 2,
            code,
            consts: vec![Const::Number(42.0)],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        let a = d1_alias(&proto);
        assert_eq!(a.proto.consts.len(), 2, "one alias per branch block");
        assert_ne!(
            a.proto.code[2].b, a.proto.code[4].b,
            "distinct physical records"
        );
        assert_eq!(num(&a.proto.consts[a.proto.code[2].b as usize]), 42.0);
        assert_eq!(num(&a.proto.consts[a.proto.code[4].b as usize]), 42.0);
        let b1 = a.record_block[a.proto.code[2].b as usize];
        let b2 = a.record_block[a.proto.code[4].b as usize];
        assert_ne!(b1, b2, "aliases keyed to different blocks");
    }

    #[test]
    fn every_use_site_preserves_the_original_value() {
        let code = vec![
            Inst::new(Opcode::LoadK, 0, 0, 0),
            Inst::new(Opcode::LoadK, 1, 1, 0),
            Inst::new(Opcode::JmpIf, 0, 1, 0),
            Inst::new(Opcode::LoadK, 2, 0, 0),
            Inst::new(Opcode::LoadK, 3, 1, 0),
            Inst::new(Opcode::Return, 0, 1, 0),
        ];
        let orig = Proto {
            num_params: 0,
            is_vararg: false,
            max_stack: 4,
            code,
            consts: vec![Const::Number(11.0), Const::Number(22.0)],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        let a = d1_alias(&orig);
        for pc in 0..orig.code.len() {
            if let (Some(oc), Some(nc)) = (
                use_site_const(&orig.code, pc),
                use_site_const(&a.proto.code, pc),
            ) {
                assert_eq!(
                    num(&orig.consts[oc]),
                    num(&a.proto.consts[nc]),
                    "use-site pc={pc} value preserved after aliasing"
                );
            }
        }
    }

    #[test]
    fn use_site_blocks_maps_constants_to_first_use_block() {
        let code = vec![
            Inst::new(Opcode::LoadK, 0, 0, 0),
            Inst::new(Opcode::Jmp, 0, 0, 0),
            Inst::new(Opcode::LoadK, 1, 1, 0),
            Inst::new(Opcode::Return, 0, 1, 0),
        ];
        let proto = Proto {
            num_params: 0,
            is_vararg: false,
            max_stack: 2,
            code,
            consts: vec![Const::Number(1.0), Const::Number(2.0)],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        let m = use_site_blocks(&proto);
        assert_eq!(m[0], Some(0));
        assert_eq!(m[1], Some(1));
    }
}
