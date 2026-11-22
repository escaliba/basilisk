use bytecode::literal::{decode_number, decode_string};
use ir::{BinOp, Block, Expr, FuncBody, LastStmt, Module, Stmt, UnOp};

pub fn optimize(module: &mut Module) {
    optimize_with_level(module, 3);
}

pub fn optimize_with_level(module: &mut Module, level: u8) {
    if level == 0 {
        return;
    }
    opt_block(&mut module.block, level >= 2);
}

fn opt_block(block: &mut Block, prune: bool) {
    let stmts = std::mem::take(&mut block.stmts);
    for mut stmt in stmts {
        opt_stmt(&mut stmt, prune);
        match stmt {
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } if prune => {
                push_if(&mut block.stmts, cond, body, else_ifs, otherwise);
            }
            other => block.stmts.push(other),
        }
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs {
            fold_expr(e, prune);
        }
    }
}

fn opt_stmt(stmt: &mut Stmt, prune: bool) {
    match stmt {
        Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| fold_expr(e, prune)),
        Stmt::Assign { exprs, .. } => exprs.iter_mut().for_each(|e| fold_expr(e, prune)),
        Stmt::Compound { value, .. } => fold_expr(value, prune),
        Stmt::Call(e) => fold_expr(e, prune),
        Stmt::Do(b) => opt_block(b, prune),
        Stmt::While { cond, body } => {
            fold_expr(cond, prune);
            opt_block(body, prune);
        }
        Stmt::Repeat { body, until } => {
            opt_block(body, prune);
            fold_expr(until, prune);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            fold_expr(start, prune);
            fold_expr(end, prune);
            if let Some(s) = step {
                fold_expr(s, prune);
            }
            opt_block(body, prune);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter_mut().for_each(|e| fold_expr(e, prune));
            opt_block(body, prune);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            fold_expr(cond, prune);
            opt_block(body, prune);
            for (c, b) in else_ifs {
                fold_expr(c, prune);
                opt_block(b, prune);
            }
            if let Some(b) = otherwise {
                opt_block(b, prune);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            opt_block(&mut body.block, prune)
        }
    }
}

fn push_if(
    out: &mut Vec<Stmt>,
    cond: Expr,
    body: Block,
    else_ifs: Vec<(Expr, Block)>,
    otherwise: Option<Block>,
) {
    let mut chain: Vec<(Option<Expr>, Block)> = Vec::with_capacity(else_ifs.len() + 2);
    chain.push((Some(cond), body));
    for (c, b) in else_ifs {
        chain.push((Some(c), b));
    }
    if let Some(b) = otherwise {
        chain.push((None, b));
    }

    let mut kept: Vec<(Option<Expr>, Block)> = Vec::with_capacity(chain.len());
    for (c, b) in chain {
        match c {
            None => {
                kept.push((None, b));
                break;
            }
            Some(e) => match literal_truthiness(&e) {
                Some(true) => {
                    kept.push((None, b));
                    break;
                }
                Some(false) => {}
                None => kept.push((Some(e), b)),
            },
        }
    }

    if kept.is_empty() {
        return;
    }
    if kept.len() == 1 && kept[0].0.is_none() {
        out.push(Stmt::Do(kept.pop().unwrap().1));
        return;
    }
    let mut iter = kept.into_iter();
    let (first_cond, first_body) = iter.next().unwrap();
    let cond = first_cond.expect("first surviving branch always has a real condition");
    let mut else_ifs = Vec::new();
    let mut otherwise = None;
    for (c, b) in iter {
        match c {
            Some(e) => else_ifs.push((e, b)),
            None => otherwise = Some(b),
        }
    }
    out.push(Stmt::If {
        cond,
        body: first_body,
        else_ifs,
        otherwise,
    });
}

fn fold_expr(expr: &mut Expr, prune: bool) {
    match expr {
        Expr::Paren(inner) => fold_expr(inner, prune),
        Expr::Function(FuncBody { block, .. }) => opt_block(block, prune),
        Expr::Unop { op, expr: inner } => {
            fold_expr(inner, prune);
            if let Some(folded) = fold_unop(*op, inner) {
                *expr = folded;
            }
        }
        Expr::Binop { op, lhs, rhs } => {
            fold_expr(lhs, prune);
            fold_expr(rhs, prune);
            if let Some(folded) = fold_binop(*op, lhs, rhs) {
                *expr = folded;
            }
        }
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            fold_expr(cond, prune);
            fold_expr(then, prune);
            for (c, v) in else_ifs.iter_mut() {
                fold_expr(c, prune);
                fold_expr(v, prune);
            }
            fold_expr(otherwise, prune);
            if prune {
                if let Some(folded) = fold_if_expr(cond, then, else_ifs, otherwise) {
                    *expr = folded;
                }
            }
        }
        _ => {}
    }
}

fn fold_if_expr(
    cond: &Expr,
    then: &Expr,
    else_ifs: &[(Expr, Expr)],
    otherwise: &Expr,
) -> Option<Expr> {
    let mut branches: Vec<(Option<&Expr>, &Expr)> = Vec::with_capacity(else_ifs.len() + 2);
    branches.push((Some(cond), then));
    for (c, v) in else_ifs {
        branches.push((Some(c), v));
    }
    branches.push((None, otherwise));

    for (c, v) in branches {
        match c {
            None => return Some(v.clone()),
            Some(e) => match literal_truthiness(e) {
                Some(true) => return Some(v.clone()),
                Some(false) => {}
                None => return None,
            },
        }
    }
    None
}

#[derive(Clone, PartialEq)]
enum Lit {
    Nil,
    Bool(bool),
    Num(f64),
    Str(Vec<u8>),
}

fn as_lit(e: &Expr) -> Option<Lit> {
    match e {
        Expr::Nil => Some(Lit::Nil),
        Expr::True => Some(Lit::Bool(true)),
        Expr::False => Some(Lit::Bool(false)),
        Expr::Number(t) => decode_number(t).map(Lit::Num),
        Expr::Str(t) => decode_string(t).map(Lit::Str),
        _ => None,
    }
}

fn lit_truthy(l: &Lit) -> bool {
    !matches!(l, Lit::Nil | Lit::Bool(false))
}

fn literal_truthiness(e: &Expr) -> Option<bool> {
    as_lit(e).map(|l| lit_truthy(&l))
}

fn bool_expr(b: bool) -> Expr {
    if b {
        Expr::True
    } else {
        Expr::False
    }
}

fn int_expr(v: f64) -> Option<Expr> {
    if v == 0.0 && v.is_sign_negative() {
        return None;
    }
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 9_007_199_254_740_992.0 {
        Some(Expr::Number(format!("{}", v as i64)))
    } else {
        None
    }
}

fn fold_unop(op: UnOp, inner: &Expr) -> Option<Expr> {
    match op {
        UnOp::Not => as_lit(inner).map(|l| bool_expr(!lit_truthy(&l))),
        UnOp::Len => match as_lit(inner) {
            Some(Lit::Str(b)) => int_expr(b.len() as f64),
            _ => None,
        },
        UnOp::Neg => match as_lit(inner) {
            Some(Lit::Num(n)) => int_expr(-n),
            _ => None,
        },
    }
}

fn fold_binop(op: BinOp, lhs: &Expr, rhs: &Expr) -> Option<Expr> {
    match op {
        BinOp::And => as_lit(lhs).map(|l| {
            if lit_truthy(&l) {
                rhs.clone()
            } else {
                lhs.clone()
            }
        }),
        BinOp::Or => as_lit(lhs).map(|l| {
            if lit_truthy(&l) {
                lhs.clone()
            } else {
                rhs.clone()
            }
        }),
        BinOp::Add | BinOp::Sub | BinOp::Mul => match (as_lit(lhs), as_lit(rhs)) {
            (Some(Lit::Num(a)), Some(Lit::Num(b))) => {
                if a.fract() != 0.0 || b.fract() != 0.0 {
                    return None;
                }
                let r = match op {
                    BinOp::Add => a + b,
                    BinOp::Sub => a - b,
                    _ => a * b,
                };
                int_expr(r)
            }
            _ => None,
        },
        BinOp::Concat => match (lhs, rhs) {
            (Expr::Str(a), Expr::Str(b)) => concat_dquote(a, b),
            _ => None,
        },
        BinOp::Eq | BinOp::Ne => match (as_lit(lhs), as_lit(rhs)) {
            (Some(a), Some(b)) => {
                let eq = a == b;
                Some(bool_expr(if matches!(op, BinOp::Eq) { eq } else { !eq }))
            }
            _ => None,
        },
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => match (as_lit(lhs), as_lit(rhs)) {
            (Some(Lit::Num(a)), Some(Lit::Num(b))) => Some(bool_expr(num_rel(op, a, b))),
            (Some(Lit::Str(a)), Some(Lit::Str(b))) => Some(bool_expr(str_rel(op, &a, &b))),
            _ => None,
        },
        BinOp::Div | BinOp::FloorDiv | BinOp::Mod | BinOp::Pow => None,
    }
}

fn num_rel(op: BinOp, a: f64, b: f64) -> bool {
    match op {
        BinOp::Lt => a < b,
        BinOp::Le => a <= b,
        BinOp::Gt => a > b,
        _ => a >= b,
    }
}

fn str_rel(op: BinOp, a: &[u8], b: &[u8]) -> bool {
    match op {
        BinOp::Lt => a < b,
        BinOp::Le => a <= b,
        BinOp::Gt => a > b,
        _ => a >= b,
    }
}

fn concat_dquote(a: &str, b: &str) -> Option<Expr> {
    let ai = plain_dquote_inner(a)?;
    let bi = plain_dquote_inner(b)?;
    Some(Expr::Str(format!("\"{ai}{bi}\"")))
}

fn plain_dquote_inner(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('\\') || inner.contains('"') {
        return None;
    }
    Some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit_num(n: &str) -> Expr {
        Expr::Number(n.into())
    }
    fn bin(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::Binop {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        }
    }

    fn folded(mut e: Expr) -> Expr {
        fold_expr(&mut e, true);
        e
    }

    fn folded_l1(mut e: Expr) -> Expr {
        fold_expr(&mut e, false);
        e
    }

    #[test]
    fn folds_integer_arithmetic() {
        assert_eq!(
            folded(bin(BinOp::Add, lit_num("2"), lit_num("3"))),
            lit_num("5")
        );
        assert_eq!(
            folded(bin(BinOp::Mul, lit_num("4"), lit_num("5"))),
            lit_num("20")
        );
        assert_eq!(
            folded(bin(BinOp::Sub, lit_num("10"), lit_num("4"))),
            lit_num("6")
        );
        let nested = bin(
            BinOp::Mul,
            bin(BinOp::Add, lit_num("2"), lit_num("3")),
            lit_num("4"),
        );
        assert_eq!(folded(nested), lit_num("20"));
    }

    #[test]
    fn does_not_fold_non_integer_or_division() {
        let div = bin(BinOp::Div, lit_num("1"), lit_num("2"));
        assert_eq!(folded(div.clone()), div);
        let f = bin(BinOp::Add, lit_num("1.5"), lit_num("2.5"));
        assert_eq!(folded(f.clone()), f);
    }

    fn run_level(stmts: Vec<Stmt>, level: u8) -> Vec<Stmt> {
        let mut m = Module {
            block: Block { stmts, last: None },
            natives: vec![],
            hash_helper: false,
            encfuncs: vec![],
            prechecks: vec![],
        };
        optimize_with_level(&mut m, level);
        m.block.stmts
    }

    fn if_false(dead: &str) -> Stmt {
        Stmt::If {
            cond: Expr::False,
            body: Block {
                stmts: vec![Stmt::Call(Expr::Name(dead.into()))],
                last: None,
            },
            else_ifs: vec![],
            otherwise: None,
        }
    }

    fn local_of(name: &str, e: Expr) -> Stmt {
        Stmt::Local {
            names: vec![name.into()],
            exprs: vec![e],
        }
    }

    #[test]
    fn level0_is_a_noop() {
        let stmts = vec![
            local_of("x", bin(BinOp::Add, lit_num("1"), lit_num("2"))),
            if_false("dead"),
        ];
        let out = run_level(stmts.clone(), 0);
        assert_eq!(out, stmts, "level 0 changes nothing");
    }

    #[test]
    fn level1_folds_literals_but_never_prunes_branches() {
        let out = run_level(
            vec![
                local_of("x", bin(BinOp::Add, lit_num("1"), lit_num("2"))),
                if_false("dead"),
            ],
            1,
        );
        assert!(
            matches!(&out[0], Stmt::Local { exprs, .. } if exprs[0] == lit_num("3")),
            "level 1 folds 1+2 -> 3"
        );
        assert!(
            matches!(
                &out[1],
                Stmt::If {
                    cond: Expr::False,
                    ..
                }
            ),
            "level 1 keeps a literal-false branch (no pruning)"
        );
    }

    #[test]
    fn level2_folds_and_prunes_literal_false_branches() {
        let out = run_level(
            vec![
                local_of("x", bin(BinOp::Add, lit_num("1"), lit_num("2"))),
                if_false("dead"),
            ],
            2,
        );
        assert!(
            matches!(&out[0], Stmt::Local { exprs, .. } if exprs[0] == lit_num("3")),
            "level 2 also folds"
        );
        assert_eq!(
            out.len(),
            1,
            "level 2 removes the dead literal-false branch"
        );
    }

    #[test]
    fn level3_matches_level2_currently() {
        let stmts = vec![
            local_of("x", bin(BinOp::Add, lit_num("2"), lit_num("3"))),
            if_false("dead"),
            local_of(
                "y",
                bin(
                    BinOp::Concat,
                    Expr::Str("\"a\"".into()),
                    Expr::Str("\"b\"".into()),
                ),
            ),
        ];
        assert_eq!(
            run_level(stmts.clone(), 2),
            run_level(stmts, 3),
            "level 3 has no extra behavior over level 2 in this branch"
        );
    }

    #[test]
    fn never_folds_env_or_metamethod_sensitive_operands() {
        let index = Expr::Index {
            base: Box::new(Expr::Name("t".into())),
            key: Box::new(lit_num("1")),
        };
        let e = bin(BinOp::Add, index, lit_num("2"));
        assert_eq!(
            folded_l1(e.clone()),
            e,
            "table-index operand is never folded (could trigger __index)"
        );
        let call = Expr::Call {
            func: Box::new(Expr::Name("f".into())),
            args: vec![],
            site: None,
        };
        let e = bin(BinOp::Add, call, lit_num("1"));
        assert_eq!(folded_l1(e.clone()), e, "call operand is never folded");
        let glob = bin(BinOp::Add, Expr::Name("G".into()), lit_num("1"));
        assert_eq!(
            folded_l1(glob.clone()),
            glob,
            "global operand is never folded"
        );
        for op in [BinOp::Div, BinOp::FloorDiv, BinOp::Mod, BinOp::Pow] {
            let e = bin(op, lit_num("6"), lit_num("2"));
            assert_eq!(folded_l1(e.clone()), e, "{op:?} is never folded");
        }
        let mixed = bin(BinOp::Lt, lit_num("1"), Expr::Str("\"2\"".into()));
        assert_eq!(
            folded_l1(mixed.clone()),
            mixed,
            "number < string is never folded (preserves the runtime error)"
        );
    }

    #[test]
    fn negative_zero_is_never_folded() {
        let neg0 = Expr::Unop {
            op: UnOp::Neg,
            expr: Box::new(lit_num("0")),
        };
        assert_eq!(folded_l1(neg0.clone()), neg0, "-0 must stay unfolded");
        let mul = bin(
            BinOp::Mul,
            lit_num("0"),
            Expr::Unop {
                op: UnOp::Neg,
                expr: Box::new(lit_num("1")),
            },
        );
        assert!(
            matches!(folded_l1(mul), Expr::Binop { op: BinOp::Mul, .. }),
            "0 * -1 (= -0.0) must not collapse to 0"
        );
    }

    #[test]
    fn folds_comparisons_and_booleans() {
        assert_eq!(
            folded(bin(BinOp::Eq, lit_num("1"), lit_num("1"))),
            Expr::True
        );
        assert_eq!(
            folded(bin(BinOp::Ne, lit_num("1"), lit_num("2"))),
            Expr::True
        );
        assert_eq!(
            folded(bin(BinOp::Lt, lit_num("1"), lit_num("2"))),
            Expr::True
        );
        assert_eq!(
            folded(Expr::Unop {
                op: UnOp::Not,
                expr: Box::new(Expr::True)
            }),
            Expr::False
        );

        assert_eq!(
            folded(Expr::Unop {
                op: UnOp::Not,
                expr: Box::new(lit_num("0"))
            }),
            Expr::False
        );
    }

    #[test]
    fn short_circuit_and_or() {
        assert_eq!(
            folded(bin(BinOp::And, Expr::False, Expr::Name("X".into()))),
            Expr::False
        );
        assert_eq!(
            folded(bin(BinOp::And, Expr::True, Expr::Name("X".into()))),
            Expr::Name("X".into())
        );
        assert_eq!(
            folded(bin(BinOp::Or, Expr::True, Expr::Name("X".into()))),
            Expr::True
        );
        assert_eq!(
            folded(bin(BinOp::Or, Expr::False, Expr::Name("X".into()))),
            Expr::Name("X".into())
        );
    }

    #[test]
    fn folds_plain_dquote_concat_only() {
        assert_eq!(
            folded(bin(
                BinOp::Concat,
                Expr::Str("\"ab\"".into()),
                Expr::Str("\"cd\"".into())
            )),
            Expr::Str("\"abcd\"".into())
        );
        let esc = bin(
            BinOp::Concat,
            Expr::Str("\"a\\n\"".into()),
            Expr::Str("\"b\"".into()),
        );
        assert_eq!(folded(esc.clone()), esc);
    }

    #[test]
    fn removes_literal_dead_branches() {
        let mut block = Block {
            stmts: vec![Stmt::If {
                cond: Expr::False,
                body: Block {
                    stmts: vec![Stmt::Call(Expr::Name("dead".into()))],
                    last: None,
                },
                else_ifs: vec![],
                otherwise: Some(Block {
                    stmts: vec![Stmt::Call(Expr::Name("live".into()))],
                    last: None,
                }),
            }],
            last: None,
        };
        opt_block(&mut block, true);
        match &block.stmts[..] {
            [Stmt::Do(b)] => {
                assert!(matches!(&b.stmts[0], Stmt::Call(Expr::Name(n)) if n == "live"))
            }
            other => panic!("expected a single Do block, got {other:?}"),
        }
    }

    #[test]
    fn keeps_side_effecting_unknown_condition() {
        let s = Stmt::If {
            cond: Expr::Call {
                func: Box::new(Expr::Name("cond".into())),
                args: vec![],
                site: None,
            },
            body: Block {
                stmts: vec![Stmt::Call(Expr::Name("body".into()))],
                last: None,
            },
            else_ifs: vec![],
            otherwise: None,
        };
        let mut block = Block {
            stmts: vec![s],
            last: None,
        };
        opt_block(&mut block, true);
        assert!(
            matches!(&block.stmts[0], Stmt::If { .. }),
            "non-literal if must survive"
        );
    }

    #[test]
    fn truncates_chain_at_literal_true_elseif() {
        let mut block = Block {
            stmts: vec![Stmt::If {
                cond: Expr::Name("c".into()),
                body: Block {
                    stmts: vec![Stmt::Call(Expr::Name("A".into()))],
                    last: None,
                },
                else_ifs: vec![(
                    Expr::True,
                    Block {
                        stmts: vec![Stmt::Call(Expr::Name("B".into()))],
                        last: None,
                    },
                )],
                otherwise: Some(Block {
                    stmts: vec![Stmt::Call(Expr::Name("C".into()))],
                    last: None,
                }),
            }],
            last: None,
        };
        opt_block(&mut block, true);
        match &block.stmts[..] {
            [Stmt::If {
                cond,
                else_ifs,
                otherwise,
                ..
            }] => {
                assert!(matches!(cond, Expr::Name(n) if n == "c"));
                assert!(else_ifs.is_empty());
                let ow = otherwise
                    .as_ref()
                    .expect("else taken from literal-true elseif");
                assert!(matches!(&ow.stmts[0], Stmt::Call(Expr::Name(n)) if n == "B"));
            }
            other => panic!("expected pruned If, got {other:?}"),
        }
    }
}
