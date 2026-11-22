use ir::{Block, Expr, Field, LastStmt, Module, Param, Precheck, Stmt};

use crate::Error;

const MACRO: &str = "BASIL_PRECHECK";
const MAX_EXPECTED: usize = 8;

pub fn extract(module: &mut Module) -> Result<(), Error> {
    let mut out: Vec<Precheck> = Vec::new();
    extract_block(&mut module.block, &mut out)?;
    module.prechecks = out;
    Ok(())
}

fn extract_block(block: &mut Block, out: &mut Vec<Precheck>) -> Result<(), Error> {
    let stmts = std::mem::take(&mut block.stmts);
    let mut kept: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for mut stmt in stmts {
        if let Some(pc) = as_precheck(&stmt)? {
            out.push(pc);
            continue;
        }
        recurse(&mut stmt, out)?;
        kept.push(stmt);
    }
    block.stmts = kept;
    if let Some(LastStmt::Return(es)) = &mut block.last {
        for e in es {
            reject_in_expr(e)?;
        }
    }
    Ok(())
}

fn recurse(stmt: &mut Stmt, out: &mut Vec<Precheck>) -> Result<(), Error> {
    match stmt {
        Stmt::Do(b) => extract_block(b, out)?,
        Stmt::While { body, .. } | Stmt::Repeat { body, .. } => extract_block(body, out)?,
        Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => extract_block(body, out)?,
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            extract_block(body, out)?;
            for (_, b) in else_ifs {
                extract_block(b, out)?;
            }
            if let Some(b) = otherwise {
                extract_block(b, out)?;
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            extract_block(&mut body.block, out)?
        }
        other => {
            let mut r = Ok(());
            each_expr(other, &mut |e| {
                if r.is_ok() {
                    r = reject_in_expr(e);
                }
            });
            r?;
        }
    }
    Ok(())
}

fn as_precheck(stmt: &Stmt) -> Result<Option<Precheck>, Error> {
    let Stmt::Call(Expr::Call { func, args, .. }) = stmt else {
        return Ok(None);
    };
    if !matches!(&**func, Expr::Name(n) if n == MACRO) {
        return Ok(None);
    }
    if args.len() != 2 {
        return Err(err(&format!(
            "{MACRO} takes exactly two arguments: a check function and an expected value"
        )));
    }
    let Expr::Function(fb) = &args[0] else {
        return Err(err(&format!(
            "{MACRO} first argument must be an inline function"
        )));
    };
    if !fb.params.is_empty() && !(fb.params.len() == 1 && matches!(fb.params[0], Param::Vararg)) {
        return Err(err(&format!(
            "{MACRO} check function must take no parameters"
        )));
    }
    if fb.params.iter().any(|p| matches!(p, Param::Vararg)) {
        return Err(err(&format!(
            "{MACRO} check function must take no parameters"
        )));
    }
    reject_macros(&fb.block)?;
    let expected = parse_expected(&args[1])?;
    Ok(Some(Precheck {
        body: fb.clone(),
        expected,
    }))
}

fn parse_expected(e: &Expr) -> Result<Vec<i64>, Error> {
    match e {
        Expr::Table(fields) => {
            if fields.is_empty() || fields.len() > MAX_EXPECTED {
                return Err(err(&format!(
                    "{MACRO} expected list must hold 1..={MAX_EXPECTED} integers"
                )));
            }
            let mut out = Vec::with_capacity(fields.len());
            for f in fields {
                match f {
                    Field::Positional(v) => out.push(int_lit(v)?),
                    _ => {
                        return Err(err(&format!(
                            "{MACRO} expected list must be `{{ int, int, ... }}`"
                        )))
                    }
                }
            }
            Ok(out)
        }
        _ => Ok(vec![int_lit(e)?]),
    }
}

fn int_lit(e: &Expr) -> Result<i64, Error> {
    let v = match e {
        Expr::Number(t) => bytecode::literal::decode_number(t),
        Expr::Unop {
            op: ir::UnOp::Neg,
            expr,
        } => match &**expr {
            Expr::Number(t) => bytecode::literal::decode_number(t).map(|n| -n),
            _ => None,
        },
        _ => None,
    };
    v.filter(|n| n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0)
        .map(|n| n as i64)
        .ok_or_else(|| {
            err(&format!(
                "{MACRO} expected value must be an integer literal"
            ))
        })
}

fn reject_macros(block: &Block) -> Result<(), Error> {
    let mut found: Option<String> = None;
    walk_names(block, &mut |n| {
        if found.is_none() && n.starts_with("BASIL_") {
            found = Some(n.to_string());
        }
    });
    match found {
        Some(n) => Err(err(&format!(
            "{MACRO} check function must not use `{n}`; it runs natively before the VM"
        ))),
        None => Ok(()),
    }
}

fn reject_in_expr(e: &Expr) -> Result<(), Error> {
    if matches!(e, Expr::Call { func, .. } if matches!(&**func, Expr::Name(n) if n == MACRO)) {
        return Err(err(&format!(
            "{MACRO} may only appear as a statement, not in an expression"
        )));
    }
    let mut r = Ok(());
    e.each_child(&mut |c| {
        if r.is_ok() {
            r = reject_in_expr(c);
        }
    });
    r
}

fn err(msg: &str) -> Error {
    Error::Macro(msg.to_string())
}

fn each_expr(stmt: &mut Stmt, f: &mut impl FnMut(&mut Expr)) {
    match stmt {
        Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => exprs.iter_mut().for_each(f),
        Stmt::Assign { targets, exprs } => targets.iter_mut().chain(exprs.iter_mut()).for_each(f),
        Stmt::Compound { target, value, .. } => {
            f(target);
            f(value);
        }
        Stmt::Call(e) | Stmt::While { cond: e, .. } | Stmt::Repeat { until: e, .. } => f(e),
        Stmt::NumericFor {
            start, end, step, ..
        } => {
            f(start);
            f(end);
            if let Some(s) = step {
                f(s);
            }
        }
        Stmt::If { cond, else_ifs, .. } => {
            f(cond);
            for (c, _) in else_ifs {
                f(c);
            }
        }
        _ => {}
    }
}

fn walk_names(block: &Block, f: &mut impl FnMut(&str)) {
    for s in &block.stmts {
        walk_stmt_names(s, f);
    }
    if let Some(LastStmt::Return(es)) = &block.last {
        for e in es {
            walk_expr_names(e, f);
        }
    }
}

fn walk_stmt_names(stmt: &Stmt, f: &mut impl FnMut(&str)) {
    match stmt {
        Stmt::Local { names, exprs } => {
            names.iter().for_each(|n| f(n));
            exprs.iter().for_each(|e| walk_expr_names(e, f));
        }
        Stmt::Assign { targets, exprs } => targets
            .iter()
            .chain(exprs.iter())
            .for_each(|e| walk_expr_names(e, f)),
        Stmt::Compound { target, value, .. } => {
            walk_expr_names(target, f);
            walk_expr_names(value, f);
        }
        Stmt::Call(e) | Stmt::While { cond: e, .. } | Stmt::Repeat { until: e, .. } => {
            walk_expr_names(e, f)
        }
        Stmt::Do(b) => walk_names(b, f),
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        } => {
            f(var);
            walk_expr_names(start, f);
            walk_expr_names(end, f);
            if let Some(s) = step {
                walk_expr_names(s, f);
            }
            walk_names(body, f);
        }
        Stmt::GenericFor { names, exprs, body } => {
            names.iter().for_each(|n| f(n));
            exprs.iter().for_each(|e| walk_expr_names(e, f));
            walk_names(body, f);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            walk_expr_names(cond, f);
            walk_names(body, f);
            for (c, b) in else_ifs {
                walk_expr_names(c, f);
                walk_names(b, f);
            }
            if let Some(b) = otherwise {
                walk_names(b, f);
            }
        }
        Stmt::Function { name, body } => {
            f(&name.path[0]);
            walk_names(&body.block, f);
        }
        Stmt::LocalFunction { name, body } => {
            f(name);
            walk_names(&body.block, f);
        }
    }
}

fn walk_expr_names(e: &Expr, f: &mut impl FnMut(&str)) {
    if let Expr::Name(n) = e {
        f(n);
    }
    e.each_child(&mut |c| walk_expr_names(c, f));
    if let Expr::Function(fb) = e {
        walk_names(&fb.block, f);
    }
}
