use crate::opcode::Opcode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prov {
    FlatDispatchCmp,
    BStateEdge(u32, u32),
}

#[derive(Clone, Debug)]
pub struct Inst {
    pub op: Opcode,
    pub a: i32,
    pub b: i32,
    pub c: i32,
    pub ops: Vec<i32>,
    pub prov: Option<Prov>,
}

impl PartialEq for Inst {
    fn eq(&self, other: &Self) -> bool {
        self.op == other.op
            && self.a == other.a
            && self.b == other.b
            && self.c == other.c
            && self.ops == other.ops
    }
}

impl Inst {
    pub fn new(op: Opcode, a: i32, b: i32, c: i32) -> Self {
        Inst {
            op,
            a,
            b,
            c,
            ops: Vec::new(),
            prov: None,
        }
    }

    pub fn super_op(op: Opcode, ops: Vec<i32>) -> Self {
        Inst {
            op,
            a: 0,
            b: 0,
            c: 0,
            ops,
            prov: None,
        }
    }
}
