use crate::block::Block;

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Nil,
    True,
    False,

    Vararg,

    Number(String),

    Str(String),
    Name(String),

    Paren(Box<Expr>),
    Field {
        base: Box<Expr>,
        name: String,
    },
    Index {
        base: Box<Expr>,
        key: Box<Expr>,
    },
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
        site: Option<u32>,
    },

    MethodCall {
        base: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    Function(FuncBody),
    Table(Vec<Field>),
    Binop {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Unop {
        op: UnOp,
        expr: Box<Expr>,
    },
    IfExpr {
        cond: Box<Expr>,
        then: Box<Expr>,
        else_ifs: Vec<(Expr, Expr)>,
        otherwise: Box<Expr>,
    },
    Interp(Vec<InterpPart>),

    NativeRef(u32),

    Crash,

    EncFunc {
        id: u32,
        key: Box<Expr>,
    },

    OpcodeHint {
        family: OpFamily,
        intensity: u8,
        key: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpFamily {
    Move,
    LoadK,
    Call,
    Eq,
    Lt,
    Le,
    Concat,
}

impl OpFamily {
    pub fn from_name(s: &str) -> Option<OpFamily> {
        Some(match s {
            "MOVE" => OpFamily::Move,
            "LOADK" => OpFamily::LoadK,
            "CALL" => OpFamily::Call,
            "EQ" => OpFamily::Eq,
            "LT" => OpFamily::Lt,
            "LE" => OpFamily::Le,
            "CONCAT" => OpFamily::Concat,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            OpFamily::Move => "MOVE",
            OpFamily::LoadK => "LOADK",
            OpFamily::Call => "CALL",
            OpFamily::Eq => "EQ",
            OpFamily::Lt => "LT",
            OpFamily::Le => "LE",
            OpFamily::Concat => "CONCAT",
        }
    }

    pub const SUPPORTED: &'static [&'static str] =
        &["MOVE", "LOADK", "CALL", "EQ", "LT", "LE", "CONCAT"];
}

#[derive(Clone, Debug, PartialEq)]
pub enum InterpPart {
    Lit(String),
    Expr(Expr),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Field {
    Positional(Expr),
    Named { name: String, value: Expr },
    Keyed { key: Expr, value: Expr },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCat {
    Input,
    Render,
    Event,
    Generic,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FuncBody {
    pub params: Vec<Param>,
    pub block: Block,
    pub hot_callback: Option<HotCat>,
    pub stable_id: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Param {
    Name(String),
    Vararg,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UnOp {
    Neg,
    Not,
    Len,
}

impl BinOp {
    pub fn as_str(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::FloorDiv => "//",
            BinOp::Mod => "%",
            BinOp::Pow => "^",
            BinOp::Concat => "..",
            BinOp::Eq => "==",
            BinOp::Ne => "~=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::And => "and",
            BinOp::Or => "or",
        }
    }
}

impl UnOp {
    pub fn as_str(self) -> &'static str {
        match self {
            UnOp::Neg => "-",
            UnOp::Not => "not",
            UnOp::Len => "#",
        }
    }
}

impl Expr {
    pub fn each_child(&self, f: &mut impl FnMut(&Expr)) {
        match self {
            Expr::Nil
            | Expr::True
            | Expr::False
            | Expr::Vararg
            | Expr::Number(_)
            | Expr::Str(_)
            | Expr::Name(_)
            | Expr::NativeRef(_)
            | Expr::Crash
            | Expr::OpcodeHint { .. }
            | Expr::Function(_) => {}
            Expr::Paren(e) | Expr::Unop { expr: e, .. } | Expr::EncFunc { key: e, .. } => f(e),
            Expr::Field { base, .. } => f(base),
            Expr::Index { base, key } => {
                f(base);
                f(key);
            }
            Expr::Call { func, args, .. } => {
                f(func);
                args.iter().for_each(f);
            }
            Expr::MethodCall { base, args, .. } => {
                f(base);
                args.iter().for_each(f);
            }
            Expr::Table(fields) => {
                for fld in fields {
                    match fld {
                        Field::Positional(v) => f(v),
                        Field::Named { value, .. } => f(value),
                        Field::Keyed { key, value } => {
                            f(key);
                            f(value);
                        }
                    }
                }
            }
            Expr::Binop { lhs, rhs, .. } => {
                f(lhs);
                f(rhs);
            }
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                f(cond);
                f(then);
                for (c, v) in else_ifs {
                    f(c);
                    f(v);
                }
                f(otherwise);
            }
            Expr::Interp(parts) => {
                for p in parts {
                    if let InterpPart::Expr(e) = p {
                        f(e);
                    }
                }
            }
        }
    }

    pub fn each_child_mut(&mut self, f: &mut impl FnMut(&mut Expr)) {
        match self {
            Expr::Nil
            | Expr::True
            | Expr::False
            | Expr::Vararg
            | Expr::Number(_)
            | Expr::Str(_)
            | Expr::Name(_)
            | Expr::NativeRef(_)
            | Expr::Crash
            | Expr::OpcodeHint { .. }
            | Expr::Function(_) => {}
            Expr::Paren(e) | Expr::Unop { expr: e, .. } | Expr::EncFunc { key: e, .. } => f(e),
            Expr::Field { base, .. } => f(base),
            Expr::Index { base, key } => {
                f(base);
                f(key);
            }
            Expr::Call { func, args, .. } => {
                f(func);
                args.iter_mut().for_each(f);
            }
            Expr::MethodCall { base, args, .. } => {
                f(base);
                args.iter_mut().for_each(f);
            }
            Expr::Table(fields) => {
                for fld in fields {
                    match fld {
                        Field::Positional(v) => f(v),
                        Field::Named { value, .. } => f(value),
                        Field::Keyed { key, value } => {
                            f(key);
                            f(value);
                        }
                    }
                }
            }
            Expr::Binop { lhs, rhs, .. } => {
                f(lhs);
                f(rhs);
            }
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                f(cond);
                f(then);
                for (c, v) in else_ifs {
                    f(c);
                    f(v);
                }
                f(otherwise);
            }
            Expr::Interp(parts) => {
                for p in parts {
                    if let InterpPart::Expr(e) = p {
                        f(e);
                    }
                }
            }
        }
    }

    pub fn each_child_block(&self) -> Option<&Block> {
        match self {
            Expr::Function(f) => Some(&f.block),
            _ => None,
        }
    }
}
