use ir::{Block, Expr, Field, FuncBody, InterpPart, LastStmt, Module, Stmt};

pub const ENV_INTROSPECTION: [&str; 2] = ["getfenv", "setfenv"];

pub fn scan(module: &Module) -> Vec<&'static str> {
    let mut found = std::collections::BTreeSet::new();
    block(&module.block, &mut found);
    for fb in &module.natives {
        block(&fb.block, &mut found);
    }
    ENV_INTROSPECTION
        .iter()
        .copied()
        .filter(|t| found.contains(t))
        .collect()
}

fn note(e: &Expr, found: &mut std::collections::BTreeSet<&'static str>) {
    if let Expr::Name(n) = e {
        for t in ENV_INTROSPECTION {
            if n == t {
                found.insert(t);
            }
        }
    }
}

fn block(b: &Block, found: &mut std::collections::BTreeSet<&'static str>) {
    for s in &b.stmts {
        stmt(s, found);
    }
    if let Some(LastStmt::Return(exprs)) = &b.last {
        for e in exprs {
            expr(e, found);
        }
    }
}

fn stmt(s: &Stmt, found: &mut std::collections::BTreeSet<&'static str>) {
    match s {
        Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| expr(e, found)),
        Stmt::Assign { targets, exprs } => targets.iter().chain(exprs).for_each(|e| expr(e, found)),
        Stmt::Compound { target, value, .. } => {
            expr(target, found);
            expr(value, found);
        }
        Stmt::Call(e) => expr(e, found),
        Stmt::Do(b) => block(b, found),
        Stmt::While { cond, body } => {
            expr(cond, found);
            block(body, found);
        }
        Stmt::Repeat { body, until } => {
            block(body, found);
            expr(until, found);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            expr(start, found);
            expr(end, found);
            if let Some(s) = step {
                expr(s, found);
            }
            block(body, found);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter().for_each(|e| expr(e, found));
            block(body, found);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            expr(cond, found);
            block(body, found);
            for (c, b) in else_ifs {
                expr(c, found);
                block(b, found);
            }
            if let Some(b) = otherwise {
                block(b, found);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => funcbody(body, found),
    }
}

fn funcbody(fb: &FuncBody, found: &mut std::collections::BTreeSet<&'static str>) {
    block(&fb.block, found);
}

fn expr(e: &Expr, found: &mut std::collections::BTreeSet<&'static str>) {
    note(e, found);
    match e {
        Expr::Paren(i) | Expr::Unop { expr: i, .. } => expr(i, found),
        Expr::Field { base, .. } => expr(base, found),
        Expr::Index { base, key } => {
            expr(base, found);
            expr(key, found);
        }
        Expr::Call { func, args, .. } => {
            expr(func, found);
            args.iter().for_each(|a| expr(a, found));
        }
        Expr::MethodCall { base, args, .. } => {
            expr(base, found);
            args.iter().for_each(|a| expr(a, found));
        }
        Expr::Binop { lhs, rhs, .. } => {
            expr(lhs, found);
            expr(rhs, found);
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    Field::Positional(e) | Field::Named { value: e, .. } => expr(e, found),
                    Field::Keyed { key, value } => {
                        expr(key, found);
                        expr(value, found);
                    }
                }
            }
        }
        Expr::Function(fb) => funcbody(fb, found),
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            expr(cond, found);
            expr(then, found);
            for (c, t) in else_ifs {
                expr(c, found);
                expr(t, found);
            }
            expr(otherwise, found);
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    expr(e, found);
                }
            }
        }
        Expr::EncFunc { key, .. } => expr(key, found),
        other => other.each_child(&mut |c| expr(c, found)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_src(src: &str) -> Vec<&'static str> {
        scan(&crate::lower_str(src).unwrap())
    }

    #[test]
    fn detects_getfenv_call() {
        assert_eq!(
            scan_src("local e = getfenv(1)\nreturn e\n"),
            vec!["getfenv"]
        );
    }

    #[test]
    fn detects_setfenv_call() {
        assert_eq!(scan_src("setfenv(1, {})\n"), vec!["setfenv"]);
    }

    #[test]
    fn detects_both_and_nested_in_functions() {
        let src = "local function f()\n  return getfenv(2)\nend\nlocal g = function() setfenv(1, {}) end\nreturn f, g\n";
        assert_eq!(scan_src(src), vec!["getfenv", "setfenv"]);
    }

    #[test]
    fn clean_script_reports_nothing() {
        assert!(scan_src("local x = 1\nlocal t = { a = 2 }\nreturn x + t.a\n").is_empty());
    }

    #[test]
    fn does_not_false_positive_on_strings_or_fields() {
        let src = "local s = \"getfenv is a word\"\nlocal t = {}\nt.setfenv = 1\nreturn s, t\n";
        assert!(
            scan_src(src).is_empty(),
            "string contents and table field names must not trigger detection"
        );
    }
}
