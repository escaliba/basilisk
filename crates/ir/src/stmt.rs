use crate::block::Block;
use crate::expr::{Expr, FuncBody};

#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    Local {
        names: Vec<String>,
        exprs: Vec<Expr>,
    },
    Assign {
        targets: Vec<Expr>,
        exprs: Vec<Expr>,
    },
    Compound {
        target: Expr,
        op: CompoundOp,
        value: Expr,
    },
    Call(Expr),
    Do(Block),
    While {
        cond: Expr,
        body: Block,
    },
    Repeat {
        body: Block,
        until: Expr,
    },
    NumericFor {
        var: String,
        start: Expr,
        end: Expr,
        step: Option<Expr>,
        body: Block,
    },
    GenericFor {
        names: Vec<String>,
        exprs: Vec<Expr>,
        body: Block,
    },
    If {
        cond: Expr,
        body: Block,
        else_ifs: Vec<(Expr, Block)>,
        otherwise: Option<Block>,
    },
    Function {
        name: FunctionName,
        body: FuncBody,
    },
    LocalFunction {
        name: String,
        body: FuncBody,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum LastStmt {
    Break,
    Continue,
    Return(Vec<Expr>),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CompoundOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Concat,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FunctionName {
    pub path: Vec<String>,
    pub method: Option<String>,
}

impl CompoundOp {
    pub fn as_str(self) -> &'static str {
        match self {
            CompoundOp::Add => "+=",
            CompoundOp::Sub => "-=",
            CompoundOp::Mul => "*=",
            CompoundOp::Div => "/=",
            CompoundOp::FloorDiv => "//=",
            CompoundOp::Mod => "%=",
            CompoundOp::Pow => "^=",
            CompoundOp::Concat => "..=",
        }
    }
}
