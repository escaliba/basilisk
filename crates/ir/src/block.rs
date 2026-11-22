use crate::stmt::{LastStmt, Stmt};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub last: Option<LastStmt>,
}
