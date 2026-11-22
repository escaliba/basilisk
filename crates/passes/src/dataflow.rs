use bytecode::blockstate::successors;
use bytecode::cfg::Cfg;
use bytecode::inst::Inst;
use bytecode::opcode::{Opcode, SYNONYMS};
use bytecode::proto::Proto;
use bytecode::superop;

pub struct Effect {
    pub defs: Vec<u32>,
    pub uses: Vec<u32>,
}

fn base_op(op: Opcode) -> Opcode {
    SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op)
}

fn r(x: i32) -> u32 {
    x.max(0) as u32
}

fn span(lo: u32, hi_excl: u32) -> Vec<u32> {
    if hi_excl <= lo {
        Vec::new()
    } else {
        (lo..hi_excl).collect()
    }
}

pub fn effect(inst: &Inst, max_stack: u32, proto: &Proto) -> Effect {
    use Opcode::*;
    let a = r(inst.a);
    let b = inst.b;
    let c = inst.c;
    let op = base_op(inst.op);

    let barrier = |uses: Vec<u32>| Effect {
        defs: Vec::new(),
        uses,
    };

    match op {
        Move => Effect {
            defs: vec![a],
            uses: vec![r(b)],
        },
        LoadK | LoadNil | LoadBool | GetUpval | GetGlobal | GetGlobalI | NewTable | LoadNative => {
            Effect {
                defs: vec![a],
                uses: Vec::new(),
            }
        }
        SetUpval | SetGlobal => Effect {
            defs: Vec::new(),
            uses: vec![a],
        },
        GetTable => Effect {
            defs: vec![a],
            uses: vec![r(b), r(c)],
        },
        SetTable => Effect {
            defs: Vec::new(),
            uses: vec![a, r(b), r(c)],
        },
        Self_ | SelfI => Effect {
            defs: vec![a, a + 1],
            uses: vec![r(b)],
        },
        Add | Sub | Mul | Div | Mod | Pow | IDiv | Concat | Eq | Ne | Lt | Le | Gt | Ge => Effect {
            defs: vec![a],
            uses: vec![r(b), r(c)],
        },
        AddK | SubK | MulK | DivK | ModK | PowK | IDivK | ConcatK | EqK | NeK | LtK | LeK | GtK
        | GeK => Effect {
            defs: vec![a],
            uses: vec![r(b)],
        },
        MApplyReset | MApplyFold => Effect {
            defs: vec![a],
            uses: vec![a],
        },
        Neg | Not | Len => Effect {
            defs: vec![a],
            uses: vec![r(b)],
        },
        Jmp => Effect {
            defs: Vec::new(),
            uses: Vec::new(),
        },
        JmpIf | JmpIfNot => barrier(vec![a]),
        Call => {
            let uses = if b > 0 {
                span(a, a + b as u32)
            } else {
                span(a, max_stack)
            };
            let defs = if c > 0 {
                span(a, a + (c as u32) - 1)
            } else {
                Vec::new()
            };
            Effect { defs, uses }
        }
        Return => {
            let uses = if b > 0 {
                span(a, a + (b as u32) - 1)
            } else {
                span(a, max_stack)
            };
            barrier(uses)
        }
        Vararg => {
            let defs = if b > 0 {
                span(a, a + (b as u32) - 1)
            } else {
                Vec::new()
            };
            Effect {
                defs,
                uses: Vec::new(),
            }
        }
        SetList => {
            let uses = if b > 0 {
                span(a, a + (b as u32) + 1)
            } else {
                span(a, max_stack)
            };
            barrier(uses)
        }
        Closure | EncFunc => {
            let mut uses = Vec::new();
            if let Some(child) = proto.protos.get(b.max(0) as usize) {
                for d in &child.upvals {
                    if d.in_stack {
                        uses.push(d.index as u32);
                    }
                }
            } else {
                uses = span(0, max_stack);
            }
            Effect {
                defs: vec![a],
                uses,
            }
        }
        ForPrep => Effect {
            defs: vec![a],
            uses: vec![a, a + 2],
        },
        ForLoop => Effect {
            defs: vec![a, a + 3],
            uses: vec![a, a + 1, a + 2],
        },
        TForCall => {
            let mut defs = vec![a, a + 1, a + 2];
            if b > 0 {
                defs.extend(span(a + 3, a + 3 + b as u32));
            }
            Effect {
                defs,
                uses: vec![a, a + 1, a + 2],
            }
        }
        TForLoop => Effect {
            defs: vec![a + 2],
            uses: vec![a + 3],
        },
        Close => barrier(span(a, max_stack)),
        Pad | Crash | BStateStep => Effect {
            defs: Vec::new(),
            uses: Vec::new(),
        },
        _ if superop::is_super(op) || matches!(op, FlatStateEq) => barrier(span(0, max_stack)),
        _ => barrier(span(0, max_stack)),
    }
}

pub fn is_simple(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        base_op(op),
        Move | LoadK
            | LoadNil
            | LoadBool
            | GetUpval
            | GetGlobal
            | GetGlobalI
            | NewTable
            | GetTable
            | Self_
            | SelfI
            | Add
            | Sub
            | Mul
            | Div
            | Mod
            | Pow
            | IDiv
            | Concat
            | Eq
            | Ne
            | Lt
            | Le
            | Gt
            | Ge
            | AddK
            | SubK
            | MulK
            | DivK
            | ModK
            | PowK
            | IDivK
            | ConcatK
            | EqK
            | NeK
            | LtK
            | LeK
            | GtK
            | GeK
            | Neg
            | Not
            | Len
    )
}

pub struct Liveness {
    pub live_in: Vec<Vec<bool>>,
    pub live_out: Vec<Vec<bool>>,
    pub nregs: usize,
}

impl Liveness {
    pub fn reg_live_out(&self, block: usize, reg: u32) -> bool {
        let reg = reg as usize;
        reg < self.nregs && self.live_out[block][reg]
    }
}

fn gen_kill(
    block_body: &[Inst],
    term: &Inst,
    max_stack: u32,
    proto: &Proto,
    nregs: usize,
) -> (Vec<bool>, Vec<bool>) {
    let mut gen = vec![false; nregs];
    let mut kill = vec![false; nregs];
    let mut defined = vec![false; nregs];
    let mut visit = |inst: &Inst| {
        let e = effect(inst, max_stack, proto);
        for u in e.uses {
            let u = u as usize;
            if u < nregs && !defined[u] {
                gen[u] = true;
            }
        }
        for d in e.defs {
            let d = d as usize;
            if d < nregs {
                defined[d] = true;
                kill[d] = true;
            }
        }
    };
    for inst in block_body {
        visit(inst);
    }
    visit(term);
    (gen, kill)
}

pub fn liveness(proto: &Proto) -> (Cfg, Liveness) {
    let cfg = Cfg::from_code(&proto.code);
    let nb = cfg.blocks.len();
    let nregs = proto.max_stack as usize;
    let max_stack = proto.max_stack as u32;

    let mut gen = Vec::with_capacity(nb);
    let mut kill = Vec::with_capacity(nb);
    for blk in &cfg.blocks {
        let (g, k) = gen_kill(&blk.body, &term_inst(&blk.term), max_stack, proto, nregs);
        gen.push(g);
        kill.push(k);
    }

    let mut live_in = vec![vec![false; nregs]; nb];
    let mut live_out = vec![vec![false; nregs]; nb];
    let succ: Vec<Vec<usize>> = cfg.blocks.iter().map(|b| successors(&b.term)).collect();

    let mut changed = true;
    while changed {
        changed = false;
        for bi in (0..nb).rev() {
            let mut out = vec![false; nregs];
            for &s in &succ[bi] {
                if s < nb {
                    for reg in 0..nregs {
                        out[reg] |= live_in[s][reg];
                    }
                }
            }
            let mut inb = gen[bi].clone();
            for reg in 0..nregs {
                if out[reg] && !kill[bi][reg] {
                    inb[reg] = true;
                }
            }
            if out != live_out[bi] {
                live_out[bi] = out;
                changed = true;
            }
            if inb != live_in[bi] {
                live_in[bi] = inb;
                changed = true;
            }
        }
    }

    (
        cfg,
        Liveness {
            live_in,
            live_out,
            nregs,
        },
    )
}

fn term_inst(term: &bytecode::cfg::Terminator) -> Inst {
    use bytecode::cfg::Terminator::*;
    match term {
        Return(i) => i.clone(),
        Branch { cond, .. } => Inst::new(Opcode::JmpIf, *cond, 0, 0),
        NumericForPrep { a, .. } => Inst::new(Opcode::ForPrep, *a, 0, 0),
        NumericForLoop { a, .. } => Inst::new(Opcode::ForLoop, *a, 0, 0),
        GenericForLoop { a, .. } => Inst::new(Opcode::TForLoop, *a, 0, 0),
        Goto(_) => Inst::new(Opcode::Jmp, 0, 0, 0),
    }
}

pub struct RegionStats {
    pub total: usize,
    pub simple: usize,
    pub simple_confined: usize,
    pub region_insts: usize,
    pub regions: usize,
}

pub fn region_stats(proto: &Proto) -> RegionStats {
    let (cfg, live) = liveness(proto);
    let max_stack = proto.max_stack as u32;
    let mut st = RegionStats {
        total: 0,
        simple: 0,
        simple_confined: 0,
        region_insts: 0,
        regions: 0,
    };

    for (bi, blk) in cfg.blocks.iter().enumerate() {
        st.total += blk.body.len();
        let mut run = 0usize;
        for inst in &blk.body {
            if is_simple(inst.op) {
                st.simple += 1;
                let e = effect(inst, max_stack, proto);
                let confined = e.defs.iter().all(|&d| !live.reg_live_out(bi, d));
                if confined {
                    st.simple_confined += 1;
                }
                run += 1;
            } else {
                if run >= 2 {
                    st.regions += 1;
                    st.region_insts += run;
                }
                run = 0;
            }
        }
        if run >= 2 {
            st.regions += 1;
            st.region_insts += run;
        }
        st.total += 1;
    }
    st
}

pub fn closure_escapes(proto: &Proto, def_pc: usize) -> bool {
    use Opcode::*;
    let code = &proto.code;
    if def_pc >= code.len() {
        return true;
    }
    let home = r(code[def_pc].a);
    let max_stack = proto.max_stack as u32;
    let mut tainted = vec![false; max_stack.max(1) as usize];
    let ti = |reg: u32, v: &[bool]| -> bool { (reg as usize) < v.len() && v[reg as usize] };
    if (home as usize) < tainted.len() {
        tainted[home as usize] = true;
    }

    for pc in (def_pc + 1)..code.len() {
        let inst = &code[pc];
        let op = base_op(inst.op);
        let a = r(inst.a);
        let b = r(inst.b);
        let c = r(inst.c);
        match op {
            Move => {
                if ti(b, &tainted) {
                    if (a as usize) < tainted.len() {
                        tainted[a as usize] = true;
                    }
                } else if (a as usize) < tainted.len() && a != home {
                    tainted[a as usize] = false;
                }
            }
            SetTable => {
                if ti(a, &tainted) || ti(b, &tainted) || ti(c, &tainted) {
                    return true;
                }
            }
            SetGlobal | SetUpval => {
                if ti(a, &tainted) {
                    return true;
                }
            }
            Return => {
                let hi = if inst.b > 0 {
                    a + (inst.b as u32) - 1
                } else {
                    max_stack
                };
                if (a..hi).any(|reg| ti(reg, &tainted)) {
                    return true;
                }
            }
            Call => {
                let hi = if inst.b > 0 {
                    a + (inst.b as u32)
                } else {
                    max_stack
                };
                if ((a + 1)..hi).any(|reg| ti(reg, &tainted)) {
                    return true;
                }
                let defhi = if inst.c > 0 {
                    a + (inst.c as u32) - 1
                } else {
                    max_stack
                };
                for reg in a..defhi {
                    if (reg as usize) < tainted.len() {
                        tainted[reg as usize] = false;
                    }
                }
            }
            SetList => {
                return ti(a, &tainted) || {
                    let hi = if inst.b > 0 {
                        a + (inst.b as u32) + 1
                    } else {
                        max_stack
                    };
                    ((a + 1)..hi).any(|reg| ti(reg, &tainted))
                }
            }
            Closure | EncFunc => {
                if let Some(child) = proto.protos.get(inst.b.max(0) as usize) {
                    if child
                        .upvals
                        .iter()
                        .any(|d| d.in_stack && ti(d.index as u32, &tainted))
                    {
                        return true;
                    }
                }
            }
            _ => {
                let e = effect(inst, max_stack, proto);
                for &d in &e.defs {
                    if (d as usize) < tainted.len() && d != home {
                        tainted[d as usize] = false;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecode::proto::Const;

    fn proto(code: Vec<Inst>, max_stack: u16, consts: Vec<Const>, protos: Vec<Proto>) -> Proto {
        Proto {
            num_params: 0,
            is_vararg: false,
            max_stack,
            code,
            consts,
            upvals: vec![],
            protos,
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        }
    }

    #[test]
    fn straight_line_temp_is_dead_after_last_use() {
        let p = proto(
            vec![
                Inst::new(Opcode::LoadK, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
            vec![Const::Number(1.0), Const::Number(2.0)],
            vec![],
        );
        let (_cfg, live) = liveness(&p);
        assert!(!live.reg_live_out(0, 0));
        assert!(!live.reg_live_out(0, 1));
    }

    #[test]
    fn value_live_across_branch_join_is_live_out() {
        let p = proto(
            vec![
                Inst::new(Opcode::LoadK, 0, 0, 0),
                Inst::new(Opcode::JmpIf, 0, 1, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::Return, 0, 2, 0),
            ],
            2,
            vec![Const::Number(1.0), Const::Number(2.0)],
            vec![],
        );
        let (_cfg, live) = liveness(&p);
        assert!(
            live.reg_live_out(0, 0),
            "r0 crosses the branch to the Return"
        );
    }

    #[test]
    fn loop_carried_value_stays_live_across_back_edge() {
        let p = proto(
            vec![
                Inst::new(Opcode::LoadK, 0, 0, 0),
                Inst::new(Opcode::Add, 1, 0, 0),
                Inst::new(Opcode::Jmp, -2, 0, 0),
            ],
            2,
            vec![Const::Number(1.0)],
            vec![],
        );
        let (_cfg, live) = liveness(&p);
        for bi in 0..live.live_out.len() {
            assert!(
                live.reg_live_out(bi, 0),
                "r0 is loop-carried across the back edge"
            );
        }
    }

    #[test]
    fn region_stats_counts_confined_temporaries() {
        let p = proto(
            vec![
                Inst::new(Opcode::LoadK, 0, 0, 0),
                Inst::new(Opcode::LoadK, 1, 1, 0),
                Inst::new(Opcode::Add, 2, 0, 1),
                Inst::new(Opcode::Return, 2, 2, 0),
            ],
            3,
            vec![Const::Number(1.0), Const::Number(2.0)],
            vec![],
        );
        let s = region_stats(&p);
        assert_eq!(s.simple, 3);
        assert_eq!(s.simple_confined, 3, "r0,r1,r2 all die inside the block");
        assert_eq!(s.regions, 1);
        assert_eq!(s.region_insts, 3);
    }

    #[test]
    fn returned_closure_escapes() {
        let child = proto(vec![Inst::new(Opcode::Return, 0, 1, 0)], 1, vec![], vec![]);
        let p = proto(
            vec![
                Inst::new(Opcode::Closure, 0, 0, 0),
                Inst::new(Opcode::Return, 0, 2, 0),
            ],
            1,
            vec![],
            vec![child],
        );
        assert!(closure_escapes(&p, 0));
    }

    #[test]
    fn confined_directly_called_closure_does_not_escape() {
        let child = proto(vec![Inst::new(Opcode::Return, 0, 1, 0)], 1, vec![], vec![]);
        let p = proto(
            vec![
                Inst::new(Opcode::Closure, 0, 0, 0),
                Inst::new(Opcode::Call, 0, 1, 1),
                Inst::new(Opcode::Return, 0, 1, 0),
            ],
            2,
            vec![],
            vec![child],
        );
        assert!(
            !closure_escapes(&p, 0),
            "called in place, home reg not stored/returned/passed"
        );
    }

    #[test]
    fn closure_escapes_through_move_into_table() {
        let child = proto(vec![Inst::new(Opcode::Return, 0, 1, 0)], 1, vec![], vec![]);
        let p = proto(
            vec![
                Inst::new(Opcode::NewTable, 1, 0, 0),
                Inst::new(Opcode::Closure, 0, 0, 0),
                Inst::new(Opcode::Move, 2, 0, 0),
                Inst::new(Opcode::SetTable, 1, 3, 2),
                Inst::new(Opcode::Return, 1, 2, 0),
            ],
            4,
            vec![],
            vec![child],
        );
        assert!(
            closure_escapes(&p, 1),
            "move-routed store into a table must be detected"
        );
    }
}
