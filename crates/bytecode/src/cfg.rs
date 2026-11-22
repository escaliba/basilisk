use crate::inst::Inst;
use crate::opcode::Opcode;

pub struct BasicBlock {
    pub body: Vec<Inst>,
    pub term: Terminator,
}

pub enum Terminator {
    Goto(usize),

    Branch {
        cond: i32,
        when_true: usize,
        when_false: usize,
    },
    NumericForPrep {
        a: i32,
        target: usize,
    },
    NumericForLoop {
        a: i32,
        body: usize,
        exit: usize,
    },
    GenericForLoop {
        a: i32,
        body: usize,
        exit: usize,
    },
    Return(Inst),
}

pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub starts: Vec<usize>,
}

fn is_terminator(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Jmp
            | Opcode::JmpIf
            | Opcode::JmpIfNot
            | Opcode::Return
            | Opcode::ForPrep
            | Opcode::ForLoop
            | Opcode::TForLoop
    )
}

impl Cfg {
    pub fn from_code(code: &[Inst]) -> Cfg {
        let n = code.len();
        let mut leader = vec![false; n + 1];
        if n > 0 {
            leader[0] = true;
        }
        for (i, inst) in code.iter().enumerate() {
            if is_terminator(inst.op) {
                if i + 1 < n {
                    leader[i + 1] = true;
                }
                if matches!(
                    inst.op,
                    Opcode::Jmp
                        | Opcode::JmpIf
                        | Opcode::JmpIfNot
                        | Opcode::ForPrep
                        | Opcode::ForLoop
                        | Opcode::TForLoop
                ) {
                    let target = jump_target(i, inst);
                    if target < n {
                        leader[target] = true;
                    }
                }
            }
        }

        let starts: Vec<usize> = (0..n).filter(|&i| leader[i]).collect();
        let block_of =
            |code_idx: usize| -> usize { starts.partition_point(|&s| s <= code_idx) - 1 };

        let mut blocks = Vec::with_capacity(starts.len());
        for (bi, &start) in starts.iter().enumerate() {
            let end = starts.get(bi + 1).copied().unwrap_or(n);
            let last = end - 1;
            let last_inst = code[last].clone();
            let (body_end, term) = if is_terminator(last_inst.op) {
                let term = match last_inst.op {
                    Opcode::Jmp => Terminator::Goto(block_of(jump_target(last, &last_inst))),
                    Opcode::JmpIf => Terminator::Branch {
                        cond: last_inst.a,
                        when_true: block_of(jump_target(last, &last_inst)),
                        when_false: block_of(last + 1),
                    },
                    Opcode::JmpIfNot => Terminator::Branch {
                        cond: last_inst.a,
                        when_true: block_of(last + 1),
                        when_false: block_of(jump_target(last, &last_inst)),
                    },
                    Opcode::ForPrep => Terminator::NumericForPrep {
                        a: last_inst.a,
                        target: block_of(jump_target(last, &last_inst)),
                    },
                    Opcode::ForLoop => Terminator::NumericForLoop {
                        a: last_inst.a,
                        body: block_of(jump_target(last, &last_inst)),
                        exit: block_of(last + 1),
                    },
                    Opcode::TForLoop => Terminator::GenericForLoop {
                        a: last_inst.a,
                        body: block_of(jump_target(last, &last_inst)),
                        exit: block_of(last + 1),
                    },
                    Opcode::Return => Terminator::Return(last_inst),
                    _ => unreachable!(),
                };
                (last, term)
            } else {
                (end, Terminator::Goto(bi + 1))
            };
            blocks.push(BasicBlock {
                body: code[start..body_end].to_vec(),
                term,
            });
        }

        Cfg { blocks, starts }
    }

    pub fn block_of(&self, pc: usize) -> usize {
        self.starts.partition_point(|&s| s <= pc).saturating_sub(1)
    }
}

fn jump_target(idx: usize, inst: &Inst) -> usize {
    let offset = if inst.op == Opcode::Jmp {
        inst.a
    } else {
        inst.b
    };
    (idx as i64 + 1 + offset as i64) as usize
}
