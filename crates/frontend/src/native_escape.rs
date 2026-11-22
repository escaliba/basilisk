use std::collections::BTreeSet;

use ir::{Block, Expr, Field, FuncBody, LastStmt, Module, Stmt};

use crate::free_vars;

#[derive(Debug)]
pub struct Selection {
    pub stable_id: u32,
    pub captured_locals: BTreeSet<String>,
    pub free_vars: BTreeSet<String>,
}

pub fn inspect(module: &Module, stable_id: u32) -> Result<Selection, String> {
    let mut s = Scan {
        want: stable_id,
        scope: Vec::new(),
        found: Vec::new(),
    };
    s.block(&module.block);
    match s.found.len() {
        1 => {}
        0 => return Err(format!("native escape: stable id {stable_id} absent")),
        n => {
            return Err(format!(
                "native escape: stable id {stable_id} ambiguous ({n})"
            ))
        }
    }
    let (free, enclosing) = s.found.pop().unwrap();
    let captured: BTreeSet<String> = free.intersection(&enclosing).cloned().collect();
    Ok(Selection {
        stable_id,
        captured_locals: captured,
        free_vars: free,
    })
}

pub fn check_leaf(module: &Module, stable_id: u32) -> Result<(), String> {
    let sel = inspect(module, stable_id)?;
    if sel.captured_locals.is_empty() {
        return Ok(());
    }
    let names: Vec<&str> = sel.captured_locals.iter().map(|s| s.as_str()).collect();
    Err(format!(
        "native escape: stable id {stable_id} captures enclosing local(s) {}; \
         a native body is emitted as real Luau and cannot share the VM's locals, so this \
         function is not a leaf and cannot be extracted",
        names.join(", ")
    ))
}

struct Scan {
    want: u32,
    scope: Vec<String>,
    found: Vec<(BTreeSet<String>, BTreeSet<String>)>,
}

impl Scan {
    fn consider(&mut self, f: &FuncBody) {
        if f.stable_id == Some(self.want) {
            let free = free_vars(f);
            let enclosing: BTreeSet<String> = self.scope.iter().cloned().collect();
            self.found.push((free, enclosing));
        }
        let depth = self.scope.len();
        for p in &f.params {
            if let ir::Param::Name(n) = p {
                self.scope.push(n.clone());
            }
        }
        self.block(&f.block);
        self.scope.truncate(depth);
    }

    fn block(&mut self, b: &Block) {
        let depth = self.scope.len();
        for s in &b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &b.last {
            for e in es {
                self.expr(e);
            }
        }
        self.scope.truncate(depth);
    }

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Local { names, exprs } => {
                exprs.iter().for_each(|e| self.expr(e));
                names.iter().for_each(|n| self.scope.push(n.clone()));
            }
            Stmt::LocalFunction { name, body } => {
                self.scope.push(name.clone());
                self.consider(body);
            }
            Stmt::Function { body, .. } => self.consider(body),
            Stmt::Assign { targets, exprs } => {
                targets.iter().for_each(|e| self.expr(e));
                exprs.iter().for_each(|e| self.expr(e));
            }
            Stmt::Compound { target, value, .. } => {
                self.expr(target);
                self.expr(value);
            }
            Stmt::Call(e) => self.expr(e),
            Stmt::Do(x) => self.block(x),
            Stmt::While { cond, body } => {
                self.expr(cond);
                self.block(body);
            }
            Stmt::Repeat { body, until } => {
                self.block(body);
                self.expr(until);
            }
            Stmt::NumericFor {
                var,
                start,
                end,
                step,
                body,
            } => {
                self.expr(start);
                self.expr(end);
                if let Some(x) = step {
                    self.expr(x);
                }
                let d = self.scope.len();
                self.scope.push(var.clone());
                self.block(body);
                self.scope.truncate(d);
            }
            Stmt::GenericFor { names, exprs, body } => {
                exprs.iter().for_each(|e| self.expr(e));
                let d = self.scope.len();
                names.iter().for_each(|n| self.scope.push(n.clone()));
                self.block(body);
                self.scope.truncate(d);
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond);
                self.block(body);
                for (c, x) in else_ifs {
                    self.expr(c);
                    self.block(x);
                }
                if let Some(x) = otherwise {
                    self.block(x);
                }
            }
        }
    }

    fn expr(&mut self, e: &Expr) {
        match e {
            Expr::Function(f) => self.consider(f),
            Expr::Call { func, args, .. } => {
                self.expr(func);
                args.iter().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter().for_each(|a| self.expr(a));
            }
            Expr::Field { base, .. } => self.expr(base),
            Expr::Paren(x) | Expr::Unop { expr: x, .. } => self.expr(x),
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
            Expr::Table(fs) => {
                for f in fs {
                    match f {
                        Field::Positional(v) => self.expr(v),
                        Field::Named { value, .. } => self.expr(value),
                        Field::Keyed { key, value } => {
                            self.expr(key);
                            self.expr(value);
                        }
                    }
                }
            }
            Expr::Binop { lhs, rhs, .. } => {
                self.expr(lhs);
                self.expr(rhs);
            }
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond);
                self.expr(then);
                for (c, v) in else_ifs {
                    self.expr(c);
                    self.expr(v);
                }
                self.expr(otherwise);
            }
            Expr::Interp(ps) => {
                for p in ps {
                    if let ir::InterpPart::Expr(x) = p {
                        self.expr(x);
                    }
                }
            }
            Expr::EncFunc { key, .. } => self.expr(key),
            other => other.each_child(&mut |c| self.expr(c)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lowered(src: &str) -> Module {
        crate::lower_str(src).unwrap()
    }

    fn tag(m: &mut Module, name: &str, id: u32) {
        for s in &mut m.block.stmts {
            match s {
                Stmt::Assign { targets, exprs } => {
                    for (t, e) in targets.iter().zip(exprs.iter_mut()) {
                        if matches!(t, Expr::Name(n) if n == name) {
                            if let Expr::Function(f) = e {
                                f.stable_id = Some(id);
                            }
                        }
                    }
                }
                Stmt::LocalFunction { name: n, body } if n == name => body.stable_id = Some(id),
                _ => {}
            }
        }
    }

    #[test]
    fn a_leaf_function_is_accepted() {
        let mut m = lowered(
            "Leaf = function(a, b)\n\treturn a:lower():find(b) and true\nend\nreturn Leaf\n",
        );
        tag(&mut m, "Leaf", 7);
        let sel = inspect(&m, 7).unwrap();
        assert!(
            sel.captured_locals.is_empty(),
            "captured {:?}",
            sel.captured_locals
        );
        check_leaf(&m, 7).unwrap();
    }

    #[test]
    fn capturing_an_enclosing_local_fails_closed() {
        let mut m = lowered(
            "local shared = nil\n\
             Capturer = function(x)\n\
             \tshared = x\n\
             \treturn shared\n\
             end\n\
             return Capturer\n",
        );
        tag(&mut m, "Capturer", 8);
        let sel = inspect(&m, 8).unwrap();
        assert!(
            sel.captured_locals.contains("shared"),
            "captured {:?}",
            sel.captured_locals
        );
        let e = check_leaf(&m, 8).unwrap_err();
        assert!(e.contains("shared"), "{e}");
        assert!(e.contains("not a leaf"), "{e}");
    }

    #[test]
    fn globals_do_not_count_as_captures() {
        let mut m = lowered(
            "GlobalThing = 1\n\
             User = function(x)\n\
             \tGlobalThing = x\n\
             \treturn GlobalThing\n\
             end\n\
             return User\n",
        );
        tag(&mut m, "User", 9);
        let sel = inspect(&m, 9).unwrap();
        assert!(
            sel.captured_locals.is_empty(),
            "a global is not an enclosing local: {:?}",
            sel.captured_locals
        );
        check_leaf(&m, 9).unwrap();
    }

    #[test]
    fn absent_and_ambiguous_identities_fail_closed() {
        let m = lowered("Solo = function() return 1 end\nreturn Solo\n");
        let e = inspect(&m, 4242).unwrap_err();
        assert!(e.contains("absent"), "{e}");

        let mut dup =
            lowered("A = function() return 1 end\nB = function() return 2 end\nreturn A, B\n");
        tag(&mut dup, "A", 11);
        tag(&mut dup, "B", 11);
        let e2 = inspect(&dup, 11).unwrap_err();
        assert!(e2.contains("ambiguous"), "{e2}");
    }

    #[test]
    fn parameters_and_own_locals_are_not_captures() {
        let mut m = lowered(
            "Fn = function(p)\n\tlocal own = p\n\tfor i, v in next, own do own = v end\n\treturn own\nend\nreturn Fn\n",
        );
        tag(&mut m, "Fn", 12);
        let sel = inspect(&m, 12).unwrap();
        assert!(
            sel.captured_locals.is_empty(),
            "captured {:?}",
            sel.captured_locals
        );
    }
}
