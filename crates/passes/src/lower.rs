use bytecode::cfg::Terminator;
use bytecode::inst::Inst;
use bytecode::opcode::Opcode;
use bytecode::proto::Const;

pub fn rel(to: usize, at: usize) -> i32 {
    (to as i64 - (at as i64 + 1)) as i32
}

pub fn patch_jump(code: &mut [Inst], at: usize, to: usize) {
    let off = rel(to, at);
    match code[at].op {
        Opcode::Jmp => code[at].a = off,
        _ => code[at].b = off,
    }
}

pub fn add_number(consts: &mut Vec<Const>, n: f64) -> i32 {
    for (i, c) in consts.iter().enumerate() {
        if let Const::Number(m) = c {
            if m.to_bits() == n.to_bits() {
                return i as i32;
            }
        }
    }
    consts.push(Const::Number(n));
    (consts.len() - 1) as i32
}

pub fn emit_terminator(
    code: &mut Vec<Inst>,
    term: &Terminator,
    b: usize,
    jumps: &mut Vec<(usize, usize)>,
) {
    match term {
        Terminator::Goto(t) => {
            if *t != b + 1 {
                jumps.push((code.len(), *t));
                code.push(Inst::new(Opcode::Jmp, 0, 0, 0));
            }
        }
        Terminator::Branch {
            cond,
            when_true,
            when_false,
        } => {
            jumps.push((code.len(), *when_true));
            code.push(Inst::new(Opcode::JmpIf, *cond, 0, 0));
            if *when_false != b + 1 {
                jumps.push((code.len(), *when_false));
                code.push(Inst::new(Opcode::Jmp, 0, 0, 0));
            }
        }
        Terminator::NumericForPrep { a, target } => {
            jumps.push((code.len(), *target));
            code.push(Inst::new(Opcode::ForPrep, *a, 0, 0));
        }
        Terminator::NumericForLoop { a, body, exit } => {
            jumps.push((code.len(), *body));
            code.push(Inst::new(Opcode::ForLoop, *a, 0, 0));
            if *exit != b + 1 {
                jumps.push((code.len(), *exit));
                code.push(Inst::new(Opcode::Jmp, 0, 0, 0));
            }
        }
        Terminator::GenericForLoop { a, body, exit } => {
            jumps.push((code.len(), *body));
            code.push(Inst::new(Opcode::TForLoop, *a, 0, 0));
            if *exit != b + 1 {
                jumps.push((code.len(), *exit));
                code.push(Inst::new(Opcode::Jmp, 0, 0, 0));
            }
        }
        Terminator::Return(inst) => code.push(inst.clone()),
    }
}
