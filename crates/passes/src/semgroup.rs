use crate::dataflow::{effect, is_simple, liveness, Liveness};
use bytecode::cfg::Cfg;
use bytecode::gensuper::{self, GenCatalogue, GenTopo, Member as GMember, Src};
use bytecode::inst::Inst;
use bytecode::opcode::Opcode;
use bytecode::proto::{Const, Proto};

fn base_op(op: Opcode) -> Opcode {
    bytecode::opcode::SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op)
}

struct Uf {
    parent: Vec<usize>,
}
impl Uf {
    fn new(n: usize) -> Uf {
        Uf {
            parent: (0..n).collect(),
        }
    }
    fn find(&mut self, x: usize) -> usize {
        let mut r = x;
        while self.parent[r] != r {
            r = self.parent[r];
        }
        let mut c = x;
        while self.parent[c] != c {
            let n = self.parent[c];
            self.parent[c] = r;
            c = n;
        }
        r
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra] = rb;
        }
    }
}

#[derive(Default)]
pub struct GroupStats {
    pub total: usize,
    pub region_insts: usize,
    pub grouped_insts: usize,
    pub groups: usize,
    pub bucket2: usize,
    pub bucket3: usize,
    pub bucket4: usize,
    pub bucket5p: usize,
    pub insts2: usize,
    pub insts3: usize,
    pub insts4: usize,
    pub insts5p: usize,
    pub sum_edges: usize,
    pub sum_depth: usize,
    pub sum_live_in: usize,
    pub sum_live_out: usize,
    pub sum_hidden: usize,
    pub arith_total: usize,
    pub arith_numeric_safe: usize,
}

fn is_arith(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        base_op(op),
        Add | Sub | Mul | Div | Mod | Pow | IDiv | AddK | SubK | MulK | DivK | ModK | PowK | IDivK
    )
}

fn numeric_regs(block_body: &[Inst], proto: &Proto) -> Vec<Vec<bool>> {
    use Opcode::*;
    let nregs = proto.max_stack as usize;
    let mut cur = vec![false; nregs];
    let mut out = Vec::with_capacity(block_body.len());
    let getr = |v: &[bool], i: i32| -> bool { i >= 0 && (i as usize) < v.len() && v[i as usize] };
    let set = |v: &mut Vec<bool>, i: i32, val: bool| {
        if i >= 0 && (i as usize) < v.len() {
            v[i as usize] = val;
        }
    };
    for inst in block_body {
        out.push(cur.clone());
        let a = inst.a;
        let bop = base_op(inst.op);
        let const_number = |ci: i32| {
            matches!(
                proto.consts.get(ci.max(0) as usize),
                Some(Const::Number(_) | Const::FlatBlockId(_))
            )
        };
        let becomes_num = match bop {
            LoadK => const_number(inst.b),
            Len => true,
            Neg => getr(&cur, inst.b),
            Add | Sub | Mul | Div | Mod | Pow | IDiv => getr(&cur, inst.b) && getr(&cur, inst.c),
            AddK | SubK | MulK | DivK | ModK | PowK | IDivK => {
                getr(&cur, inst.b) && const_number(inst.c)
            }
            ForLoop | ForPrep => true,
            _ => false,
        };
        let e = effect(inst, nregs as u32, proto);
        for &d in &e.defs {
            set(&mut cur, d as i32, false);
        }
        if e.defs.len() == 1 {
            set(&mut cur, a, becomes_num);
        }
    }
    out
}

pub fn group_stats(proto: &Proto) -> GroupStats {
    let (cfg, live): (Cfg, Liveness) = liveness(proto);
    let nregs = proto.max_stack as u32;
    let mut st = GroupStats::default();

    for (bi, blk) in cfg.blocks.iter().enumerate() {
        st.total += blk.body.len() + 1;
        let term_uses = term_reg_uses(&blk.term, proto);

        let numflags = numeric_regs(&blk.body, proto);
        for (k, inst) in blk.body.iter().enumerate() {
            if is_arith(inst.op) {
                st.arith_total += 1;
                let nf = &numflags[k];
                let getr = |i: i32| i >= 0 && (i as usize) < nf.len() && nf[i as usize];
                let safe = match base_op(inst.op) {
                    Opcode::AddK
                    | Opcode::SubK
                    | Opcode::MulK
                    | Opcode::DivK
                    | Opcode::ModK
                    | Opcode::PowK
                    | Opcode::IDivK => getr(inst.b),
                    _ => getr(inst.b) && getr(inst.c),
                };
                if safe {
                    st.arith_numeric_safe += 1;
                }
            }
        }

        let mut i = 0usize;
        while i < blk.body.len() {
            if !region_op(blk.body[i].op) {
                i += 1;
                continue;
            }
            let start = i;
            while i < blk.body.len() && region_op(blk.body[i].op) {
                i += 1;
            }
            let region: Vec<&Inst> = blk.body[start..i].iter().collect();
            if region.len() >= 2 {
                st.region_insts += region.len();
                account_region(&region, bi, &live, nregs, proto, &term_uses, &mut st);
            }
        }
    }
    st
}

fn term_reg_uses(term: &bytecode::cfg::Terminator, proto: &Proto) -> Vec<u32> {
    use bytecode::cfg::Terminator::*;
    let nregs = proto.max_stack as u32;
    let inst = match term {
        Return(i) => i.clone(),
        Branch { cond, .. } => Inst::new(Opcode::JmpIf, *cond, 0, 0),
        NumericForPrep { a, .. } => Inst::new(Opcode::ForPrep, *a, 0, 0),
        NumericForLoop { a, .. } => Inst::new(Opcode::ForLoop, *a, 0, 0),
        GenericForLoop { a, .. } => Inst::new(Opcode::TForLoop, *a, 0, 0),
        Goto(_) => return Vec::new(),
    };
    effect(&inst, nregs, proto).uses
}

fn account_region(
    region: &[&Inst],
    block: usize,
    live: &Liveness,
    nregs: u32,
    proto: &Proto,
    term_uses: &[u32],
    st: &mut GroupStats,
) {
    let n = region.len();
    let effs: Vec<_> = region
        .iter()
        .map(|inst| effect(inst, nregs, proto))
        .collect();

    let mut last_def: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    let mut uf = Uf::new(n);
    let mut indeg_src: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut edges = 0usize;
    for k in 0..n {
        for &u in &effs[k].uses {
            if let Some(&j) = last_def.get(&u) {
                uf.union(j, k);
                indeg_src[k].push(j);
                edges += 1;
            }
        }
        for &d in &effs[k].defs {
            last_def.insert(d, k);
        }
    }

    let mut comp_size = vec![0usize; n];
    let mut roots = vec![0usize; n];
    for k in 0..n {
        let r = uf.find(k);
        roots[k] = r;
        comp_size[r] += 1;
    }

    let mut depth = vec![1usize; n];
    for k in 0..n {
        let mut best = 0;
        for &j in &indeg_src[k] {
            best = best.max(depth[j]);
        }
        depth[k] = best + 1;
    }
    let mut comp_depth: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for k in 0..n {
        let e = comp_depth.entry(roots[k]).or_insert(0);
        *e = (*e).max(depth[k]);
    }

    let mut comp_edges: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();

    let mut last_def2: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for k in 0..n {
        for &u in &effs[k].uses {
            if let Some(&j) = last_def2.get(&u) {
                *comp_edges.entry(uf_root(&roots, j)).or_insert(0) += 1;
                let _ = j;
            }
        }
        for &d in &effs[k].defs {
            last_def2.insert(d, k);
        }
    }

    let mut members: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for k in 0..n {
        members.entry(roots[k]).or_default().push(k);
    }
    for (root, ms) in &members {
        let size = ms.len();
        if size < 2 {
            continue;
        }
        st.groups += 1;
        st.grouped_insts += size;
        let d = *comp_depth.get(root).unwrap_or(&1);
        let e = *comp_edges.get(root).unwrap_or(&0);
        st.sum_edges += e;
        st.sum_depth += d;
        match size {
            2 => {
                st.bucket2 += 1;
                st.insts2 += size;
            }
            3 => {
                st.bucket3 += 1;
                st.insts3 += size;
            }
            4 => {
                st.bucket4 += 1;
                st.insts4 += size;
            }
            _ => {
                st.bucket5p += 1;
                st.insts5p += size;
            }
        }

        let member_set: std::collections::HashSet<usize> = ms.iter().copied().collect();
        let mut group_defs: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for &k in ms {
            for &dreg in &effs[k].defs {
                group_defs.insert(dreg);
            }
        }

        let mut live_in: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut ld: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
        for k in 0..n {
            if member_set.contains(&k) {
                for &u in &effs[k].uses {
                    let from_group = ld.get(&u).map(|j| member_set.contains(j)).unwrap_or(false);
                    if !from_group {
                        live_in.insert(u);
                    }
                }
            }
            for &dreg in &effs[k].defs {
                ld.insert(dreg, k);
            }
        }

        let last_k = *ms.iter().max().unwrap();
        let mut live_out = 0usize;
        let mut hidden = 0usize;
        for &dreg in &group_defs {
            let used_after_in_region = (last_k + 1..n).any(|kk| effs[kk].uses.contains(&dreg));
            let out_of_block = live.reg_live_out(block, dreg) || term_uses.contains(&dreg);
            if used_after_in_region || out_of_block {
                live_out += 1;
            } else {
                hidden += 1;
            }
        }
        st.sum_live_in += live_in.len();
        st.sum_live_out += live_out;
        st.sum_hidden += hidden;
    }
    let _ = edges;
}

fn uf_root(roots: &[usize], k: usize) -> usize {
    roots[k]
}

pub struct Group {
    pub member_pcs: Vec<usize>,
    pub members: Vec<Inst>,
    pub signature: String,
    pub live_in: usize,
    pub live_out: usize,
    pub hidden: usize,
    pub edges: usize,
    pub depth: usize,

    pub topo: Option<GenTopo>,

    pub iface_regs_in: Vec<u32>,
    pub iface_consts: Vec<i32>,
    pub iface_imms: Vec<i32>,
    pub iface_regs_out: Vec<u32>,
}

fn imm_slot(op: Opcode, slot: usize) -> bool {
    matches!(
        (base_op(op), slot),
        (Opcode::LoadBool, 1) | (Opcode::GetUpval, 1) | (Opcode::SetUpval, 1)
    )
}

fn effect_seq(op: Opcode) -> bool {
    matches!(
        base_op(op),
        Opcode::SetTable | Opcode::SetGlobal | Opcode::SetUpval
    )
}

fn region_op(op: Opcode) -> bool {
    is_simple(op) || effect_seq(op)
}

#[derive(Clone, Copy, PartialEq)]
enum Slot {
    Dead,
    Dst,
    RegUse,
    Const,
}

fn slot_kind(op: Opcode, slot: usize) -> Slot {
    use bytecode::opcode::{const_slot, KSlot};
    let ol = bytecode::opcode::operand_live(op);
    if !ol[slot] {
        return Slot::Dead;
    }
    if slot == 0 {
        return if effect_seq(op) {
            Slot::RegUse
        } else {
            Slot::Dst
        };
    }
    match const_slot(op) {
        Some(KSlot::B) if slot == 1 => Slot::Const,
        Some(KSlot::C) if slot == 2 => Slot::Const,
        _ => Slot::RegUse,
    }
}

fn slot_reg(inst: &Inst, slot: usize) -> i32 {
    match slot {
        0 => inst.a,
        1 => inst.b,
        _ => inst.c,
    }
}

fn op_name(op: Opcode) -> &'static str {
    bytecode::opcode::ALL
        .iter()
        .find(|(o, _)| *o == op)
        .map(|(_, n)| *n)
        .unwrap_or("?")
}

pub fn form_groups(proto: &Proto) -> Vec<Group> {
    let (cfg, live) = liveness(proto);
    let max_stack = proto.max_stack as u32;
    let mut out = Vec::new();
    for (bi, blk) in cfg.blocks.iter().enumerate() {
        let term_uses = term_reg_uses(&blk.term, proto);
        let block_start = cfg.starts.get(bi).copied().unwrap_or(0);
        let mut i = 0usize;
        while i < blk.body.len() {
            if !region_op(blk.body[i].op) {
                i += 1;
                continue;
            }
            let start = i;
            while i < blk.body.len() && region_op(blk.body[i].op) {
                i += 1;
            }
            if i - start >= 2 {
                let mut after_uses: std::collections::HashSet<u32> =
                    std::collections::HashSet::new();
                for inst in &blk.body[i..] {
                    for u in effect(inst, max_stack, proto).uses {
                        after_uses.insert(u);
                    }
                }

                extract_groups(
                    &blk.body[start..i],
                    block_start + start,
                    bi,
                    &live,
                    max_stack,
                    proto,
                    &term_uses,
                    &after_uses,
                    &mut out,
                );
            }
        }
    }
    out
}

fn extract_groups(
    region: &[Inst],
    region_start: usize,
    block: usize,
    live: &Liveness,
    nregs: u32,
    proto: &Proto,
    term_uses: &[u32],
    after_uses: &std::collections::HashSet<u32>,
    out: &mut Vec<Group>,
) {
    let n = region.len();
    let effs: Vec<_> = region
        .iter()
        .map(|inst| effect(inst, nregs, proto))
        .collect();

    let mut producer: Vec<[Option<usize>; 3]> = vec![[None; 3]; n];
    let mut cur_def: std::collections::HashMap<i32, usize> = std::collections::HashMap::new();
    let mut uf = Uf::new(n);
    for k in 0..n {
        for slot in 0..3 {
            if slot_kind(region[k].op, slot) == Slot::RegUse {
                let reg = slot_reg(&region[k], slot);
                if let Some(&p) = cur_def.get(&reg) {
                    producer[k][slot] = Some(p);
                    uf.union(p, k);
                }
            }
        }
        for &d in &effs[k].defs {
            cur_def.insert(d as i32, k);
        }
    }

    let mut members: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for k in 0..n {
        members.entry(uf.find(k)).or_default().push(k);
    }

    for (_root, ms) in members.iter() {
        if ms.len() < 2 {
            continue;
        }
        let mut ms = ms.clone();
        ms.sort_unstable();
        let pos: std::collections::HashMap<usize, usize> =
            ms.iter().enumerate().map(|(p, &k)| (k, p)).collect();
        let member_set: std::collections::HashSet<usize> = ms.iter().copied().collect();

        let mut ext_ids: std::collections::HashMap<i32, usize> = std::collections::HashMap::new();
        let mut iface_regs_in: Vec<u32> = Vec::new();
        let mut iface_consts: Vec<i32> = Vec::new();
        let mut iface_imms: Vec<i32> = Vec::new();
        let mut member_srcs: Vec<Vec<Src>> = Vec::with_capacity(ms.len());
        let mut sig = String::new();
        let mut edges = 0usize;
        let mut all_ok = true;
        for (p, &k) in ms.iter().enumerate() {
            let ndef = effs[k].defs.len();
            let def_ok = ndef == 1 || (ndef == 0 && effect_seq(region[k].op));
            if !gensuper::supported(region[k].op) || !def_ok {
                all_ok = false;
            }
            if p > 0 {
                sig.push(';');
            }
            sig.push_str(op_name(base_op(region[k].op)));
            sig.push('(');
            let mut first = true;
            let mut srcs: Vec<Src> = Vec::new();
            for slot in 0..3 {
                if imm_slot(region[k].op, slot) {
                    if !first {
                        sig.push(',');
                    }
                    first = false;
                    sig.push('m');
                    srcs.push(Src::Imm(iface_imms.len()));
                    iface_imms.push(slot_reg(&region[k], slot));
                    continue;
                }
                match slot_kind(region[k].op, slot) {
                    Slot::RegUse => {
                        if !first {
                            sig.push(',');
                        }
                        first = false;
                        match producer[k][slot] {
                            Some(pp) if member_set.contains(&pp) => {
                                sig.push('i');
                                sig.push_str(&pos[&pp].to_string());
                                edges += 1;
                                srcs.push(Src::Internal(pos[&pp]));
                            }
                            _ => {
                                let reg = slot_reg(&region[k], slot);
                                let next = ext_ids.len();
                                let id = *ext_ids.entry(reg).or_insert(next);
                                if id == iface_regs_in.len() {
                                    iface_regs_in.push(reg.max(0) as u32);
                                }
                                sig.push('e');
                                sig.push_str(&id.to_string());
                                srcs.push(Src::LiveIn(id));
                            }
                        }
                    }
                    Slot::Const => {
                        if !first {
                            sig.push(',');
                        }
                        first = false;
                        sig.push('K');
                        srcs.push(Src::Const(iface_consts.len()));
                        iface_consts.push(slot_reg(&region[k], slot));
                    }
                    _ => {}
                }
            }
            sig.push(')');
            member_srcs.push(srcs);
        }

        let live_in = ext_ids.len();

        let mut iface_regs_out: Vec<u32> = Vec::new();
        let mut member_out: Vec<Option<usize>> = Vec::with_capacity(ms.len());
        for &k in &ms {
            let dreg = effs[k].defs.get(0).copied();
            let is_out = dreg.map_or(false, |d| {
                live.reg_live_out(block, d)
                    || term_uses.contains(&d)
                    || after_uses.contains(&d)
                    || (k + 1..n).any(|kk| !member_set.contains(&kk) && effs[kk].uses.contains(&d))
            });
            if is_out {
                let oj = iface_regs_out.len();
                iface_regs_out.push(dreg.unwrap_or(0));
                member_out.push(Some(oj));
            } else {
                member_out.push(None);
            }
        }
        let live_out = iface_regs_out.len();
        let hidden = ms.len() - live_out;
        let out_positions: Vec<String> = member_out
            .iter()
            .enumerate()
            .filter_map(|(p, o)| o.map(|_| p.to_string()))
            .collect();
        sig.push_str("|o");
        sig.push_str(&out_positions.join(","));

        let mut depth = vec![1usize; n];
        for &k in &ms {
            let mut best = 0;
            for slot in 0..3 {
                if let Some(p) = producer[k][slot] {
                    if member_set.contains(&p) {
                        best = best.max(depth[p]);
                    }
                }
            }
            depth[k] = best + 1;
        }
        let dmax = ms.iter().map(|&k| depth[k]).max().unwrap_or(1);

        let topo = if all_ok {
            let gmembers: Vec<GMember> = ms
                .iter()
                .enumerate()
                .map(|(p, &k)| GMember {
                    op: base_op(region[k].op),
                    srcs: member_srcs[p].clone(),
                    out: member_out[p],
                })
                .collect();
            let candidate = GenTopo {
                members: gmembers,
                n_livein: iface_regs_in.len(),
                n_const: iface_consts.len(),
                n_imm: iface_imms.len(),
                n_out: iface_regs_out.len(),
                signature: sig.clone(),
            };
            gensuper::topo_lowerable(&candidate).then_some(candidate)
        } else {
            None
        };

        out.push(Group {
            member_pcs: ms.iter().map(|&k| region_start + k).collect(),
            members: ms.iter().map(|&k| region[k].clone()).collect(),
            signature: sig,
            live_in,
            live_out,
            hidden,
            edges,
            depth: dmax,
            topo,
            iface_regs_in,
            iface_consts,
            iface_imms,
            iface_regs_out,
        });
    }
}

pub fn select_catalogue(root: &Proto, capacity: usize) -> Vec<(String, usize, usize)> {
    use std::collections::HashMap;
    let mut freq: HashMap<String, (usize, usize)> = HashMap::new();
    fn walk(p: &Proto, freq: &mut HashMap<String, (usize, usize)>) {
        for g in form_groups(p) {
            let e = freq.entry(g.signature).or_insert((0, 0));
            e.0 += 1;
            e.1 += g.members.len();
        }
        for c in &p.protos {
            walk(c, freq);
        }
    }
    walk(root, &mut freq);
    let mut v: Vec<(String, usize, usize)> =
        freq.into_iter().map(|(s, (g, i))| (s, g, i)).collect();

    v.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.cmp(&b.0)));
    v.truncate(capacity);
    v
}

pub fn build_gen_catalogue(root: &Proto, capacity: usize) -> GenCatalogue {
    use std::collections::HashMap;
    let mut tally: HashMap<String, (usize, usize, GenTopo)> = HashMap::new();
    fn walk(p: &Proto, tally: &mut HashMap<String, (usize, usize, GenTopo)>) {
        for g in form_groups(p) {
            if let Some(t) = g.topo {
                let e = tally
                    .entry(g.signature.clone())
                    .or_insert((0, 0, t.clone()));
                e.0 += 1;
                e.1 += t.members.len();
            }
        }
        for c in &p.protos {
            walk(c, tally);
        }
    }
    walk(root, &mut tally);
    let mut v: Vec<(String, usize, usize, GenTopo)> = tally
        .into_iter()
        .map(|(s, (g, i, t))| (s, g, i, t))
        .collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.cmp(&b.0)));
    v.truncate(capacity);
    GenCatalogue {
        slots: v.into_iter().map(|(_, _, _, t)| t).collect(),
    }
}

fn contiguous(member_pcs: &[usize]) -> Option<(usize, usize)> {
    let mut v = member_pcs.to_vec();
    v.sort_unstable();
    let (lo, hi) = (*v.first()?, *v.last()?);
    if hi - lo + 1 == v.len() {
        Some((lo, v.len()))
    } else {
        None
    }
}

fn gensuper_inst(slot: usize, g: &Group) -> Inst {
    let mut ops: Vec<i32> = Vec::with_capacity(
        g.iface_regs_in.len() + g.iface_consts.len() + g.iface_imms.len() + g.iface_regs_out.len(),
    );
    ops.extend(g.iface_regs_in.iter().map(|&r| r as i32));
    ops.extend(g.iface_consts.iter().copied());
    ops.extend(g.iface_imms.iter().copied());
    ops.extend(g.iface_regs_out.iter().map(|&r| r as i32));

    Inst {
        op: Opcode::GenSuper,
        a: slot as i32,
        b: g.iface_regs_in.len() as i32,
        c: g.iface_consts.len() as i32,
        ops,
        prov: None,
    }
}

fn fuse_proto(proto: &Proto, sig_slot: &std::collections::HashMap<String, usize>) -> Proto {
    let protos: Vec<Proto> = proto
        .protos
        .iter()
        .map(|c| fuse_proto(c, sig_slot))
        .collect();
    let mut fusions: Vec<(usize, usize, Inst)> = Vec::new();
    for g in form_groups(proto) {
        if g.topo.is_none() {
            continue;
        }
        let Some(&slot) = sig_slot.get(&g.signature) else {
            continue;
        };
        let Some((start, len)) = contiguous(&g.member_pcs) else {
            continue;
        };
        fusions.push((start, len, gensuper_inst(slot, &g)));
    }
    if fusions.is_empty() {
        return Proto {
            protos,
            ..proto.clone()
        };
    }
    fusions.sort_by_key(|f| f.0);

    let mut chosen: Vec<(usize, usize, Inst)> = Vec::new();
    let mut next_free = 0usize;
    for f in fusions {
        if f.0 >= next_free {
            next_free = f.0 + f.1;
            chosen.push(f);
        }
    }
    let code = renumber_gen(proto.code.clone(), &chosen);
    Proto {
        code,
        protos,
        ..proto.clone()
    }
}

fn renumber_gen(code: Vec<Inst>, fusions: &[(usize, usize, Inst)]) -> Vec<Inst> {
    let n = code.len();
    let mut old_to_new = vec![0usize; n + 1];
    let mut new_pos = 0;
    let mut fi = 0;
    let mut i = 0;
    while i < n {
        if fi < fusions.len() && fusions[fi].0 == i {
            let len = fusions[fi].1;
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
            let (_start, len, inst) = &fusions[fi];
            out.push(inst.clone());
            i += len;
            fi += 1;
        } else {
            let mut inst = code[i].clone();
            if let Some(off) = crate::fuse::jump_off(&inst) {
                let t = i as i64 + 1 + off as i64;
                if (0..=n as i64).contains(&t) {
                    let new_off = old_to_new[t as usize] as i64 - old_to_new[i] as i64 - 1;
                    crate::fuse::set_jump_off(&mut inst, new_off as i32);
                }
            }
            out.push(inst);
            i += 1;
        }
    }
    out
}

pub fn fuse_semgroups(root: &Proto, capacity: usize) -> (Proto, GenCatalogue) {
    let cat = build_gen_catalogue(root, capacity);
    if cat.is_empty() {
        return (root.clone(), cat);
    }
    let sig_slot: std::collections::HashMap<String, usize> = cat
        .slots
        .iter()
        .enumerate()
        .map(|(i, t)| (t.signature.clone(), i))
        .collect();
    (fuse_proto(root, &sig_slot), cat)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto(code: Vec<Inst>, max_stack: u16) -> Proto {
        Proto {
            num_params: 0,
            is_vararg: false,
            max_stack,
            code,
            consts: vec![Const::Number(1.0), Const::Number(2.0)],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        }
    }

    #[test]
    fn fuse_semgroups_rewrites_group_to_gensuper_interface_only() {
        let p = proto(
            vec![
                Inst::new(Opcode::GetGlobal, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::GetTable, 2, 0, 1),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
        );
        let (out, cat) = fuse_semgroups(&p, 8);
        assert_eq!(cat.slots.len(), 1);
        assert_eq!(out.code.len(), 2, "3-op group collapsed to 1 + Return");
        assert_eq!(out.code[0].op, Opcode::GenSuper);
        assert_eq!(out.code[0].a, 0, "slot 0");

        assert_eq!(out.code[0].ops, vec![0, 1, 2]);
        assert_eq!(out.code[1].op, Opcode::Return);
    }

    #[test]
    fn gensuper_records_are_interface_only_and_consistent() {
        let p = proto(
            vec![
                Inst::new(Opcode::GetGlobal, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::GetTable, 2, 0, 1),
                Inst::new(Opcode::Add, 2, 2, 2),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
        );
        let (out, cat) = fuse_semgroups(&p, 8);
        let mut seen = 0;
        for inst in &out.code {
            if inst.op == Opcode::GenSuper {
                seen += 1;
                let slot = inst.a as usize;
                let topo = cat.get(slot).expect("slot in catalogue");
                assert_eq!(inst.b as usize, topo.n_livein, "b == n_livein");
                assert_eq!(inst.c as usize, topo.n_const, "c == n_const");
                assert_eq!(
                    inst.ops.len(),
                    topo.interface_len(),
                    "ops carry exactly the interface"
                );
                assert_eq!(
                    inst.ops.len(),
                    topo.n_livein + topo.n_const + topo.n_imm + topo.n_out
                );

                assert!(
                    inst.ops.len() < 1 + topo.members.len() * 3,
                    "no per-member operand program serialized"
                );
            }
        }
        assert!(seen >= 1, "at least one GenSuper emitted");
    }

    #[test]
    fn fuse_semgroups_renumbers_jump_offsets() {
        let p = proto(
            vec![
                Inst::new(Opcode::Jmp, 3, 0, 0),
                Inst::new(Opcode::GetGlobal, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::GetTable, 2, 0, 1),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
        );
        let (out, _cat) = fuse_semgroups(&p, 8);
        assert_eq!(out.code.len(), 3, "Jmp + GenSuper + Return");
        assert_eq!(out.code[0].op, Opcode::Jmp);
        assert_eq!(
            out.code[0].a, 1,
            "offset renumbered: still targets Return (new pc2)"
        );
        assert_eq!(out.code[1].op, Opcode::GenSuper);
        assert_eq!(out.code[2].op, Opcode::Return);
    }

    #[test]
    fn compound_k_op_group_is_not_admitted_and_catalogue_is_all_lowerable() {
        let p = proto(
            vec![
                Inst::new(Opcode::NeK, 2, 0, 0),
                Inst::new(Opcode::Move, 3, 2, 0),
                Inst::new(Opcode::Add, 4, 0, 1),
                Inst::new(Opcode::Move, 5, 4, 0),
                Inst::new(Opcode::Return, 3, 4, 0),
            ],
            6,
        );
        let groups = form_groups(&p);
        let k_group = groups
            .iter()
            .find(|g| g.members.iter().any(|m| base_op(m.op) == Opcode::NeK));
        assert!(k_group.is_some(), "the NeK group forms");
        assert!(
            k_group.unwrap().topo.is_none(),
            "a compound K-op group must not be fusable"
        );

        let cat = build_gen_catalogue(&p, 8);
        for slot in &cat.slots {
            assert!(
                gensuper::topo_lowerable(slot),
                "every catalogue slot must be lowerable: {}",
                slot.signature
            );
            assert!(
                slot.members.iter().all(|m| base_op(m.op) != Opcode::NeK),
                "no compound K-op reaches the catalogue"
            );
        }

        assert!(cat
            .slots
            .iter()
            .any(|t| t.members.iter().any(|m| base_op(m.op) == Opcode::Add)));
    }

    #[test]
    fn fuse_semgroups_off_is_noop() {
        let p = proto(
            vec![
                Inst::new(Opcode::GetGlobal, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::GetTable, 2, 0, 1),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
        );
        let (out, cat) = fuse_semgroups(&p, 0);
        assert!(cat.is_empty());
        assert_eq!(out.code, p.code, "capacity 0 => unchanged");
    }

    #[test]
    fn build_gen_catalogue_lowers_global_field_access() {
        let p = proto(
            vec![
                Inst::new(Opcode::GetGlobal, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::GetTable, 2, 0, 1),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
        );
        let cat = build_gen_catalogue(&p, 8);
        assert_eq!(cat.slots.len(), 1);
        let t = &cat.slots[0];
        assert_eq!(
            t.n_livein, 0,
            "global name + key are consts, no reg live-in"
        );
        assert_eq!(t.n_const, 2);
        assert_eq!(t.n_out, 1, "r2 escapes via return");
        assert_eq!(t.members.len(), 3);
        assert_eq!(t.members[0].op, Opcode::GetGlobal);
        assert_eq!(t.members[0].srcs, vec![Src::Const(0)]);
        assert_eq!(t.members[0].out, None);
        assert_eq!(t.members[1].op, Opcode::LoadK);
        assert_eq!(t.members[1].srcs, vec![Src::Const(1)]);
        assert_eq!(t.members[2].op, Opcode::GetTable);
        assert_eq!(t.members[2].srcs, vec![Src::Internal(0), Src::Internal(1)]);
        assert_eq!(t.members[2].out, Some(0));
    }

    #[test]
    fn select_catalogue_ranks_by_instruction_coverage_and_caps() {
        let p = proto(
            vec![
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Mul, 3, 2, 0),
                Inst::new(Opcode::Sub, 4, 3, 1),
                Inst::new(Opcode::SetGlobal, 4, 0, 0),
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Mul, 3, 2, 0),
                Inst::new(Opcode::Sub, 4, 3, 1),
                Inst::new(Opcode::SetGlobal, 4, 0, 0),
                Inst::new(Opcode::Add, 5, 0, 1),
                Inst::new(Opcode::Mul, 6, 5, 0),
                Inst::new(Opcode::Return, 6, 2, 0),
            ],
            7,
        );
        let cat = select_catalogue(&p, 8);
        assert!(cat.len() >= 2);
        for w in cat.windows(2) {
            assert!(w[0].2 >= w[1].2, "ranked by instruction-weighted coverage");
        }
        let capped = select_catalogue(&p, 1);
        assert_eq!(capped.len(), 1, "capacity cap honored");
    }

    #[test]
    fn topology_signature_erases_regs_keeps_wiring() {
        let p = proto(
            vec![
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Mul, 3, 2, 0),
                Inst::new(Opcode::Return, 3, 2, 0),
            ],
            4,
        );
        let g = form_groups(&p);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].signature, "ADD(e0,e1);MUL(i0,e0)|o1");
        assert_eq!(g[0].live_in, 2, "r0,r1 external");
        assert_eq!(g[0].live_out, 1, "r3 escapes via return");
        assert_eq!(g[0].hidden, 1, "r2 dies inside");
    }

    #[test]
    fn a_dependent_chain_is_one_group_with_depth() {
        let p = proto(
            vec![
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Mul, 3, 2, 0),
                Inst::new(Opcode::Sub, 4, 3, 1),
                Inst::new(Opcode::Return, 4, 2, 0),
            ],
            5,
        );
        let s = group_stats(&p);
        assert_eq!(s.groups, 1, "one connected component");
        assert_eq!(s.grouped_insts, 3);
        assert_eq!(s.bucket3, 1);
        assert_eq!(s.sum_depth, 3, "chain of 3");
        assert_eq!(s.sum_hidden, 2, "r2,r3 die inside; r4 is live-out");
    }

    #[test]
    fn two_independent_ops_are_islands_not_a_group() {
        let p = proto(
            vec![
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Add, 3, 4, 5),
                Inst::new(Opcode::Return, 2, 3, 0),
            ],
            6,
        );
        let s = group_stats(&p);
        assert_eq!(
            s.groups, 0,
            "no internal producer->consumer edge => no interlocked group"
        );
    }

    #[test]
    fn numeric_safe_arith_tracks_number_provenance() {
        let p = proto(
            vec![
                Inst::new(Opcode::LoadK, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Add, 3, 2, 0),
                Inst::new(Opcode::Return, 3, 2, 0),
            ],
            4,
        );
        let s = group_stats(&p);
        assert_eq!(s.arith_total, 2);
        assert_eq!(
            s.arith_numeric_safe, 2,
            "both adds are number+number => metamethod-free"
        );
    }

    #[test]
    fn arith_on_unknown_values_is_not_numeric_safe() {
        let p = proto(
            vec![
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
        );
        let mut p = p;
        p.num_params = 2;
        let s = group_stats(&p);
        assert_eq!(s.arith_total, 1);
        assert_eq!(s.arith_numeric_safe, 0);
    }
}
