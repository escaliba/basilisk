pub mod block;
pub mod cfg;
pub mod expr;
pub mod hot_callbacks;
pub mod stmt;

mod emit;

pub use block::Block;
pub use expr::{BinOp, Expr, Field, FuncBody, HotCat, InterpPart, OpFamily, Param, UnOp};
pub use stmt::{CompoundOp, FunctionName, LastStmt, Stmt};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Module {
    pub block: Block,

    pub natives: Vec<FuncBody>,

    pub hash_helper: bool,

    pub encfuncs: Vec<EncFunc>,

    pub prechecks: Vec<Precheck>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CompileKeySource {
    Managed { seed: u64, key: [u8; 32] },
    Literal([u8; 32]),
}

impl CompileKeySource {
    pub fn literal_hex(&self) -> Option<String> {
        match self {
            CompileKeySource::Managed { key, .. } => {
                Some(key.iter().map(|b| format!("{b:02x}")).collect())
            }
            CompileKeySource::Literal(bytes) => {
                Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
            }
        }
    }

    pub fn is_managed(&self) -> bool {
        matches!(self, CompileKeySource::Managed { .. })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncFunc {
    pub body: FuncBody,
    pub key: CompileKeySource,
    pub class: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Precheck {
    pub body: FuncBody,
    pub expected: Vec<i64>,
}

pub fn emit(module: &Module) -> String {
    emit::emit(module)
}

pub fn emit_func(body: &FuncBody) -> String {
    emit::emit_func(body)
}
