use std::collections::{HashMap, HashSet};

use ir::expr::{Expr, Field, FuncBody, Param};
use ir::stmt::{LastStmt, Stmt};
use ir::Module;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    VmFunc,
    Native,
    Other,
}

#[derive(Default)]
struct Counts {
    total_calls: u64,
    a_local: u64,
    a_iife: u64,
    a_global: u64,
    host_native: u64,
    host_global: u64,
    unknown_local: u64,
    unknown_field: u64,
    unknown_other: u64,
    method: u64,
}

struct Ctx {
    reassigned: HashSet<String>,
    global_fns: HashSet<String>,
    c: Counts,
}

fn each_field<'a>(f: &'a Field, mut go: impl FnMut(&'a Expr)) {
    match f {
        Field::Positional(x) => go(x),
        Field::Named { value, .. } => go(value),
        Field::Keyed { key, value } => {
            go(key);
            go(value);
        }
    }
}

fn collect_reassigned(b: &ir::Block, out: &mut HashSet<String>) {
    for s in &b.stmts {
        match s {
            Stmt::Assign { targets, exprs } => {
                for t in targets {
                    if let Expr::Name(n) = t {
                        out.insert(n.clone());
                    }
                }
                for e in exprs {
                    collect_reassigned_expr(e, out);
                }
            }
            Stmt::Compound { target, value, .. } => {
                if let Expr::Name(n) = target {
                    out.insert(n.clone());
                }
                collect_reassigned_expr(value, out);
            }
            Stmt::Local { exprs, .. } => {
                for e in exprs {
                    collect_reassigned_expr(e, out);
                }
            }
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                collect_reassigned(&body.block, out);
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                collect_reassigned_expr(cond, out);
                collect_reassigned(body, out);
                for (c, blk) in else_ifs {
                    collect_reassigned_expr(c, out);
                    collect_reassigned(blk, out);
                }
                if let Some(blk) = otherwise {
                    collect_reassigned(blk, out);
                }
            }
            Stmt::While { cond, body } => {
                collect_reassigned_expr(cond, out);
                collect_reassigned(body, out);
            }
            Stmt::Repeat { body, until } => {
                collect_reassigned(body, out);
                collect_reassigned_expr(until, out);
            }
            Stmt::NumericFor {
                start,
                end,
                step,
                body,
                ..
            } => {
                collect_reassigned_expr(start, out);
                collect_reassigned_expr(end, out);
                if let Some(s) = step {
                    collect_reassigned_expr(s, out);
                }
                collect_reassigned(body, out);
            }
            Stmt::GenericFor { exprs, body, .. } => {
                for e in exprs {
                    collect_reassigned_expr(e, out);
                }
                collect_reassigned(body, out);
            }
            Stmt::Do(blk) => collect_reassigned(blk, out),
            Stmt::Call(e) => collect_reassigned_expr(e, out),
        }
    }
    if let Some(LastStmt::Return(es)) = &b.last {
        for e in es {
            collect_reassigned_expr(e, out);
        }
    }
}

fn collect_reassigned_expr(e: &Expr, out: &mut HashSet<String>) {
    match e {
        Expr::Function(fb) => collect_reassigned(&fb.block, out),
        Expr::Call { func, args, .. } => {
            collect_reassigned_expr(func, out);
            for a in args {
                collect_reassigned_expr(a, out);
            }
        }
        Expr::MethodCall { base, args, .. } => {
            collect_reassigned_expr(base, out);
            for a in args {
                collect_reassigned_expr(a, out);
            }
        }
        Expr::Paren(x) | Expr::Unop { expr: x, .. } => collect_reassigned_expr(x, out),
        Expr::Field { base, .. } => collect_reassigned_expr(base, out),
        Expr::Index { base, key } => {
            collect_reassigned_expr(base, out);
            collect_reassigned_expr(key, out);
        }
        Expr::Binop { lhs, rhs, .. } => {
            collect_reassigned_expr(lhs, out);
            collect_reassigned_expr(rhs, out);
        }
        Expr::Table(fields) => {
            for f in fields {
                each_field(f, |x| collect_reassigned_expr(x, out));
            }
        }
        _ => {}
    }
}

fn collect_global_fns(b: &ir::Block, out: &mut HashSet<String>) {
    for s in &b.stmts {
        match s {
            Stmt::Function { name, body } => {
                if name.path.len() == 1 {
                    out.insert(name.path[0].clone());
                }
                collect_global_fns(&body.block, out);
            }
            Stmt::LocalFunction { body, .. } => collect_global_fns(&body.block, out),
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                collect_global_fns(body, out);
                for (_, blk) in else_ifs {
                    collect_global_fns(blk, out);
                }
                if let Some(blk) = otherwise {
                    collect_global_fns(blk, out);
                }
            }
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } | Stmt::Do(body) => {
                collect_global_fns(body, out)
            }
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => {
                collect_global_fns(body, out)
            }
            _ => {}
        }
    }
}

fn walk_block(b: &ir::Block, scope: &mut Vec<HashMap<String, Kind>>, ctx: &mut Ctx) {
    scope.push(HashMap::new());
    for s in &b.stmts {
        walk_stmt(s, scope, ctx);
    }
    if let Some(LastStmt::Return(es)) = &b.last {
        for e in es {
            walk_expr(e, scope, ctx);
        }
    }
    scope.pop();
}

fn bind(scope: &mut [HashMap<String, Kind>], name: &str, kind: Kind) {
    if let Some(top) = scope.last_mut() {
        top.insert(name.to_string(), kind);
    }
}

fn lookup(scope: &[HashMap<String, Kind>], name: &str) -> Option<Kind> {
    for m in scope.iter().rev() {
        if let Some(k) = m.get(name) {
            return Some(*k);
        }
    }
    None
}

fn expr_kind(e: &Expr) -> Option<Kind> {
    match e {
        Expr::Function(_) => Some(Kind::VmFunc),
        Expr::NativeRef(_) => Some(Kind::Native),
        Expr::Paren(x) => expr_kind(x),
        _ => None,
    }
}

fn walk_stmt(s: &Stmt, scope: &mut Vec<HashMap<String, Kind>>, ctx: &mut Ctx) {
    match s {
        Stmt::LocalFunction { name, body } => {
            let k = if ctx.reassigned.contains(name) {
                Kind::Other
            } else {
                Kind::VmFunc
            };
            bind(scope, name, k);
            walk_func(body, scope, ctx);
        }
        Stmt::Function { body, .. } => {
            walk_func(body, scope, ctx);
        }
        Stmt::Local { names, exprs } => {
            for e in exprs {
                walk_expr(e, scope, ctx);
            }
            for (i, n) in names.iter().enumerate() {
                let k = match exprs.get(i).and_then(expr_kind) {
                    Some(Kind::VmFunc) if !ctx.reassigned.contains(n) => Kind::VmFunc,
                    Some(Kind::Native) => Kind::Native,
                    _ => Kind::Other,
                };
                bind(scope, n, k);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for t in targets {
                walk_expr(t, scope, ctx);
            }
            for e in exprs {
                walk_expr(e, scope, ctx);
            }
        }
        Stmt::Compound { target, value, .. } => {
            walk_expr(target, scope, ctx);
            walk_expr(value, scope, ctx);
        }
        Stmt::Call(e) => walk_expr(e, scope, ctx),
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            walk_expr(cond, scope, ctx);
            walk_block(body, scope, ctx);
            for (c, blk) in else_ifs {
                walk_expr(c, scope, ctx);
                walk_block(blk, scope, ctx);
            }
            if let Some(blk) = otherwise {
                walk_block(blk, scope, ctx);
            }
        }
        Stmt::While { cond, body } => {
            walk_expr(cond, scope, ctx);
            walk_block(body, scope, ctx);
        }
        Stmt::Repeat { body, until } => {
            walk_block(body, scope, ctx);
            walk_expr(until, scope, ctx);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            walk_expr(start, scope, ctx);
            walk_expr(end, scope, ctx);
            if let Some(s) = step {
                walk_expr(s, scope, ctx);
            }
            walk_block(body, scope, ctx);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            for e in exprs {
                walk_expr(e, scope, ctx);
            }
            walk_block(body, scope, ctx);
        }
        Stmt::Do(blk) => walk_block(blk, scope, ctx),
    }
}

fn walk_func(body: &FuncBody, scope: &mut Vec<HashMap<String, Kind>>, ctx: &mut Ctx) {
    scope.push(HashMap::new());
    for p in &body.params {
        if let Param::Name(n) = p {
            bind(scope, n, Kind::Other);
        }
    }
    for s in &body.block.stmts {
        walk_stmt(s, scope, ctx);
    }
    if let Some(LastStmt::Return(es)) = &body.block.last {
        for e in es {
            walk_expr(e, scope, ctx);
        }
    }
    scope.pop();
}

fn walk_expr(e: &Expr, scope: &mut Vec<HashMap<String, Kind>>, ctx: &mut Ctx) {
    match e {
        Expr::Call { func, args, .. } => {
            ctx.c.total_calls += 1;
            classify_call(func, scope, ctx);
            walk_expr(func, scope, ctx);
            for a in args {
                walk_expr(a, scope, ctx);
            }
        }
        Expr::MethodCall { base, args, .. } => {
            ctx.c.method += 1;
            walk_expr(base, scope, ctx);
            for a in args {
                walk_expr(a, scope, ctx);
            }
        }
        Expr::Function(fb) => walk_func(fb, scope, ctx),
        Expr::Paren(x) | Expr::Unop { expr: x, .. } => walk_expr(x, scope, ctx),
        Expr::Field { base, .. } => walk_expr(base, scope, ctx),
        Expr::Index { base, key } => {
            walk_expr(base, scope, ctx);
            walk_expr(key, scope, ctx);
        }
        Expr::Binop { lhs, rhs, .. } => {
            walk_expr(lhs, scope, ctx);
            walk_expr(rhs, scope, ctx);
        }
        Expr::Table(fields) => {
            for f in fields {
                each_field(f, |x| walk_expr(x, scope, ctx));
            }
        }
        _ => {}
    }
}

fn classify_call(func: &Expr, scope: &[HashMap<String, Kind>], ctx: &mut Ctx) {
    match func {
        Expr::Function(_) => ctx.c.a_iife += 1,
        Expr::Paren(x) if matches!(&**x, Expr::Function(_)) => ctx.c.a_iife += 1,
        Expr::NativeRef(_) => ctx.c.host_native += 1,
        Expr::Name(n) => match lookup(scope, n) {
            Some(Kind::VmFunc) => ctx.c.a_local += 1,
            Some(Kind::Native) => ctx.c.host_native += 1,
            Some(Kind::Other) => ctx.c.unknown_local += 1,
            None => {
                if ctx.global_fns.contains(n) && !ctx.reassigned.contains(n) {
                    ctx.c.a_global += 1;
                } else {
                    ctx.c.host_global += 1;
                }
            }
        },
        Expr::Field { .. } | Expr::Index { .. } => ctx.c.unknown_field += 1,
        _ => ctx.c.unknown_other += 1,
    }
}

fn report(path: &str, c: &Counts) {
    let vm = c.a_local + c.a_iife;
    let vmish = vm + c.a_global;
    let host = c.host_native + c.host_global;
    let unknown = c.unknown_local + c.unknown_field + c.unknown_other;
    let denom = c.total_calls.max(1) as f64;
    println!("== {path} ==");
    println!(
        "  total func-calls: {}   (method-calls: {})",
        c.total_calls, c.method
    );
    println!(
        "  A  VM->VM local+iife:      {vm:6}  ({:.1}%)   [local {} iife {}]",
        100.0 * vm as f64 / denom,
        c.a_local,
        c.a_iife
    );
    println!(
        "  A' VM-via-global-fn:       {:6}  ({:.1}%)",
        c.a_global,
        100.0 * c.a_global as f64 / denom
    );
    println!(
        "  B  host native+global:     {host:6}  ({:.1}%)   [native {} global {}]",
        100.0 * host as f64 / denom,
        c.host_native,
        c.host_global
    );
    println!(
        "  C  unknown local+field+oth:{unknown:6}  ({:.1}%)   [local {} field {} other {}]",
        100.0 * unknown as f64 / denom,
        c.unknown_local,
        c.unknown_field,
        c.unknown_other
    );
    println!(
        "  => strong-VM A: {:.1}%   A+A': {:.1}%",
        100.0 * vm as f64 / denom,
        100.0 * vmish as f64 / denom
    );
    println!();
}

fn measure(path: &str, agg: &mut Counts) {
    let src = std::fs::read_to_string(path).expect("read");
    let mut m: Module = match frontend::lower_str(&src) {
        Ok(m) => m,
        Err(e) => {
            println!("== {path} == LOWER ERROR: {e}");
            return;
        }
    };
    let _ = frontend::optin::extract(&mut m);
    let m = frontend::macros::expand(m, 0).expect("expand");
    let mut reassigned = HashSet::new();
    collect_reassigned(&m.block, &mut reassigned);
    let mut global_fns = HashSet::new();
    collect_global_fns(&m.block, &mut global_fns);
    let mut ctx = Ctx {
        reassigned,
        global_fns,
        c: Counts::default(),
    };
    let mut scope: Vec<HashMap<String, Kind>> = Vec::new();
    walk_block(&m.block, &mut scope, &mut ctx);
    report(path, &ctx.c);
    agg.total_calls += ctx.c.total_calls;
    agg.a_local += ctx.c.a_local;
    agg.a_iife += ctx.c.a_iife;
    agg.a_global += ctx.c.a_global;
    agg.host_native += ctx.c.host_native;
    agg.host_global += ctx.c.host_global;
    agg.unknown_local += ctx.c.unknown_local;
    agg.unknown_field += ctx.c.unknown_field;
    agg.unknown_other += ctx.c.unknown_other;
    agg.method += ctx.c.method;
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut agg = Counts::default();
    for p in &args {
        measure(p, &mut agg);
    }
    if args.len() > 1 {
        report("AGGREGATE", &agg);
    }
}
