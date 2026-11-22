use crate::block::Block;
use crate::expr::{Expr, Field, FuncBody, InterpPart, Param};
use crate::stmt::{LastStmt, Stmt};
use crate::Module;

pub fn emit(module: &Module) -> String {
    let mut emitter = Emitter {
        out: String::new(),
        depth: 0,
    };
    emitter.block(&module.block);
    emitter.out
}

pub fn emit_func(body: &FuncBody) -> String {
    let mut emitter = Emitter {
        out: String::new(),
        depth: 0,
    };
    emitter.func_expr(body);
    emitter.out
}

struct Emitter {
    out: String,
    depth: usize,
}

impl Emitter {
    fn pad(&mut self) {
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }

    fn body(&mut self, block: &Block) {
        self.depth += 1;
        self.block(block);
        self.depth -= 1;
    }

    fn block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.stmt(stmt);
        }
        if let Some(last) = &block.last {
            self.last(last);
        }
    }

    fn stmt(&mut self, stmt: &Stmt) {
        self.pad();
        match stmt {
            Stmt::Local { names, exprs } => {
                self.out.push_str("local ");
                self.out.push_str(&names.join(", "));
                if !exprs.is_empty() {
                    self.out.push_str(" = ");
                    self.exprs(exprs);
                }
                self.out.push_str(";\n");
            }
            Stmt::Assign { targets, exprs } => {
                self.exprs(targets);
                self.out.push_str(" = ");
                self.exprs(exprs);
                self.out.push_str(";\n");
            }
            Stmt::Compound { target, op, value } => {
                self.expr(target);
                self.out.push(' ');
                self.out.push_str(op.as_str());
                self.out.push(' ');
                self.expr(value);
                self.out.push_str(";\n");
            }
            Stmt::Call(call) => {
                self.expr(call);
                self.out.push_str(";\n");
            }
            Stmt::Do(block) => {
                self.out.push_str("do\n");
                self.body(block);
                self.pad();
                self.out.push_str("end;\n");
            }
            Stmt::While { cond, body } => {
                self.out.push_str("while ");
                self.expr(cond);
                self.out.push_str(" do\n");
                self.body(body);
                self.pad();
                self.out.push_str("end;\n");
            }
            Stmt::Repeat { body, until } => {
                self.out.push_str("repeat\n");
                self.body(body);
                self.pad();
                self.out.push_str("until ");
                self.expr(until);
                self.out.push_str(";\n");
            }
            Stmt::NumericFor {
                var,
                start,
                end,
                step,
                body,
            } => {
                self.out.push_str("for ");
                self.out.push_str(var);
                self.out.push_str(" = ");
                self.expr(start);
                self.out.push_str(", ");
                self.expr(end);
                if let Some(step) = step {
                    self.out.push_str(", ");
                    self.expr(step);
                }
                self.out.push_str(" do\n");
                self.body(body);
                self.pad();
                self.out.push_str("end;\n");
            }
            Stmt::GenericFor { names, exprs, body } => {
                self.out.push_str("for ");
                self.out.push_str(&names.join(", "));
                self.out.push_str(" in ");
                self.exprs(exprs);
                self.out.push_str(" do\n");
                self.body(body);
                self.pad();
                self.out.push_str("end;\n");
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.out.push_str("if ");
                self.expr(cond);
                self.out.push_str(" then\n");
                self.body(body);
                for (econd, eblock) in else_ifs {
                    self.pad();
                    self.out.push_str("elseif ");
                    self.expr(econd);
                    self.out.push_str(" then\n");
                    self.body(eblock);
                }
                if let Some(otherwise) = otherwise {
                    self.pad();
                    self.out.push_str("else\n");
                    self.body(otherwise);
                }
                self.pad();
                self.out.push_str("end;\n");
            }
            Stmt::Function { name, body } => {
                self.out.push_str("function ");
                self.out.push_str(&name.path.join("."));
                if let Some(method) = &name.method {
                    self.out.push(':');
                    self.out.push_str(method);
                }
                self.func_tail(body);
            }
            Stmt::LocalFunction { name, body } => {
                self.out.push_str("local function ");
                self.out.push_str(name);
                self.func_tail(body);
            }
        }
    }

    fn func_tail(&mut self, body: &FuncBody) {
        self.out.push('(');
        self.params(&body.params);
        self.out.push_str(")\n");
        self.body(&body.block);
        self.pad();
        self.out.push_str("end;\n");
    }

    fn last(&mut self, last: &LastStmt) {
        self.pad();
        match last {
            LastStmt::Break => self.out.push_str("break;\n"),
            LastStmt::Continue => self.out.push_str("continue;\n"),
            LastStmt::Return(exprs) => {
                self.out.push_str("return");
                if !exprs.is_empty() {
                    self.out.push(' ');
                    self.exprs(exprs);
                }
                self.out.push_str(";\n");
            }
        }
    }

    fn params(&mut self, params: &[Param]) {
        for (i, param) in params.iter().enumerate() {
            if i > 0 {
                self.out.push_str(", ");
            }
            match param {
                Param::Name(name) => self.out.push_str(name),
                Param::Vararg => self.out.push_str("..."),
            }
        }
    }

    fn exprs(&mut self, exprs: &[Expr]) {
        for (i, expr) in exprs.iter().enumerate() {
            if i > 0 {
                self.out.push_str(", ");
            }
            self.expr(expr);
        }
    }

    fn expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Nil => self.out.push_str("nil"),
            Expr::True => self.out.push_str("true"),
            Expr::False => self.out.push_str("false"),
            Expr::Vararg => self.out.push_str("..."),
            Expr::Number(text) | Expr::Str(text) | Expr::Name(text) => self.out.push_str(text),
            Expr::Paren(inner) => {
                self.out.push('(');
                self.expr(inner);
                self.out.push(')');
            }
            Expr::Field { base, name } => {
                self.base(base);
                self.out.push('.');
                self.out.push_str(name);
            }
            Expr::Index { base, key } => {
                self.base(base);
                self.out.push('[');
                self.expr(key);
                self.out.push(']');
            }
            Expr::Call { func, args, .. } => {
                self.base(func);
                self.out.push('(');
                self.exprs(args);
                self.out.push(')');
            }
            Expr::MethodCall { base, method, args } => {
                self.base(base);
                self.out.push(':');
                self.out.push_str(method);
                self.out.push('(');
                self.exprs(args);
                self.out.push(')');
            }
            Expr::Function(body) => self.func_expr(body),
            Expr::Table(fields) => {
                if fields.is_empty() {
                    self.out.push_str("{}");
                } else {
                    self.out.push_str("{ ");
                    for (i, field) in fields.iter().enumerate() {
                        if i > 0 {
                            self.out.push_str(", ");
                        }
                        self.field(field);
                    }
                    self.out.push_str(" }");
                }
            }
            Expr::Binop { op, lhs, rhs } => {
                self.out.push('(');
                self.expr(lhs);
                self.out.push(' ');
                self.out.push_str(op.as_str());
                self.out.push(' ');
                self.expr(rhs);
                self.out.push(')');
            }
            Expr::Unop { op, expr } => {
                self.out.push('(');
                self.out.push_str(op.as_str());
                self.out.push(' ');
                self.expr(expr);
                self.out.push(')');
            }
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                self.out.push_str("(if ");
                self.expr(cond);
                self.out.push_str(" then ");
                self.expr(then);
                for (econd, eexpr) in else_ifs {
                    self.out.push_str(" elseif ");
                    self.expr(econd);
                    self.out.push_str(" then ");
                    self.expr(eexpr);
                }
                self.out.push_str(" else ");
                self.expr(otherwise);
                self.out.push(')');
            }
            Expr::Interp(parts) => {
                self.out.push('`');
                for part in parts {
                    match part {
                        InterpPart::Lit(text) => self.out.push_str(text),
                        InterpPart::Expr(inner) => {
                            self.out.push('{');
                            self.expr(inner);
                            self.out.push('}');
                        }
                    }
                }
                self.out.push('`');
            }
            Expr::NativeRef(_) => {
                unreachable!(
                    "NativeRef is lowered by the bytecode compiler, never emitted as source"
                )
            }
            Expr::Crash => {
                unreachable!("Crash is lowered by the bytecode compiler, never emitted as source")
            }
            Expr::EncFunc { .. } => {
                unreachable!("EncFunc is lowered by the bytecode compiler, never emitted as source")
            }
            Expr::OpcodeHint { .. } => {
                unreachable!(
                    "OpcodeHint is lowered by the bytecode compiler, never emitted as source"
                )
            }
        }
    }

    fn func_expr(&mut self, body: &FuncBody) {
        self.out.push_str("function(");
        self.params(&body.params);
        self.out.push_str(")\n");
        self.body(&body.block);
        self.pad();
        self.out.push_str("end");
    }

    fn base(&mut self, expr: &Expr) {
        match expr {
            Expr::Name(_)
            | Expr::Paren(_)
            | Expr::Field { .. }
            | Expr::Index { .. }
            | Expr::Call { .. }
            | Expr::MethodCall { .. }
            | Expr::Binop { .. }
            | Expr::Unop { .. }
            | Expr::IfExpr { .. } => self.expr(expr),
            _ => {
                self.out.push('(');
                self.expr(expr);
                self.out.push(')');
            }
        }
    }

    fn field(&mut self, field: &Field) {
        match field {
            Field::Positional(value) => self.expr(value),
            Field::Named { name, value } => {
                self.out.push_str(name);
                self.out.push_str(" = ");
                self.expr(value);
            }
            Field::Keyed { key, value } => {
                self.out.push('[');
                self.expr(key);
                self.out.push_str("] = ");
                self.expr(value);
            }
        }
    }
}
