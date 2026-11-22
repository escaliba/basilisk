use std::collections::HashSet;

use ir::{Block, Expr, FuncBody, LastStmt, Module, Stmt};

use crate::Error;

pub const MACRO: &str = "BASIL_STACKALLOC";

const MAX_SIZE: i64 = 64;

struct Slot {
    base: i64,
    names: Vec<String>,
}

impl Slot {
    fn size(&self) -> i64 {
        self.names.len() as i64
    }
    fn name_for(&self, index: i64) -> Option<&str> {
        if index < self.base || index >= self.base + self.size() {
            return None;
        }
        Some(&self.names[(index - self.base) as usize])
    }
    fn range(&self, first: Option<i64>, last: Option<i64>) -> Result<(i64, i64), Error> {
        let a = first.unwrap_or(self.base);
        let b = last.unwrap_or(self.base + self.size() - 1);
        if a < self.base || b >= self.base + self.size() || a > b + 1 {
            return Err(err(format!(
                "{MACRO} range [{a}, {b}] is outside the allocation [{}, {}]",
                self.base,
                self.base + self.size() - 1
            )));
        }
        Ok((a, b))
    }
}

struct Ctx {
    slots: std::collections::HashMap<String, Slot>,
}

impl Ctx {
    fn get(&self, name: &str) -> Option<&Slot> {
        self.slots.get(name)
    }
    fn tracks(&self, name: &str) -> bool {
        self.slots.contains_key(name)
    }
}

fn err(msg: String) -> Error {
    Error::Macro(msg)
}

fn is_macro_call(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, .. } if matches!(&**func, Expr::Name(n) if n == MACRO))
}

fn const_int(e: &Expr) -> Option<i64> {
    match e {
        Expr::Number(t) => {
            let f = bytecode::literal::decode_number(t)?;
            if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
                Some(f as i64)
            } else {
                None
            }
        }
        Expr::Unop {
            op: ir::UnOp::Neg,
            expr,
        } => const_int(expr).and_then(|v| v.checked_neg()),
        Expr::Paren(inner) => const_int(inner),
        _ => None,
    }
}

pub fn expand(module: &mut Module) -> Result<(), Error> {
    let mut used: HashSet<String> = HashSet::new();
    collect_idents(&module.block, &mut used);
    let mut prefix = "__bsa".to_string();
    while used.iter().any(|u| u.starts_with(&prefix)) {
        prefix.push('_');
    }
    let mut uid = 0u32;
    scope(&mut module.block, &prefix, &mut uid)?;
    if let Some(e) = leftover(&module.block) {
        return Err(e);
    }
    Ok(())
}

fn scope(block: &mut Block, prefix: &str, uid: &mut u32) -> Result<(), Error> {
    let mut r = Ok(());
    each_func_body_in_scope_mut(block, &mut |fb| {
        if r.is_ok() {
            r = scope(&mut fb.block, prefix, uid);
        }
    });
    r?;

    let mut ctx = Ctx {
        slots: std::collections::HashMap::new(),
    };
    let mut decl_positions: Vec<(String, usize)> = Vec::new();
    for (i, stmt) in block.stmts.iter().enumerate() {
        if let Stmt::Local { names, exprs } = stmt {
            if exprs.len() == 1 && is_macro_call(&exprs[0]) {
                if names.len() != 1 {
                    return Err(err(format!(
                        "{MACRO} must initialize exactly one local, as `local v = {MACRO}(n)`"
                    )));
                }
                let (size, base) = parse_args(&exprs[0])?;
                let mut slot_names = Vec::with_capacity(size as usize);
                for s in 0..size {
                    slot_names.push(format!("{prefix}{uid}_{s}"));
                }
                *uid += 1;
                ctx.slots.insert(
                    names[0].clone(),
                    Slot {
                        base,
                        names: slot_names,
                    },
                );
                decl_positions.push((names[0].clone(), i));
            }
        }
    }
    if ctx.slots.is_empty() {
        return Ok(());
    }

    for (var, decl_idx) in &decl_positions {
        let mut count = 0u32;
        count_decls(block, var, &mut count);
        if count > 1 {
            return Err(err(format!(
                "{MACRO} local `{var}` is declared more than once in this scope; \
                 shadowing makes the allocation impossible to track"
            )));
        }
        if used_before(block, *decl_idx, var) {
            return Err(err(format!(
                "{MACRO} local `{var}` is referenced before it is allocated"
            )));
        }
    }

    rewrite_block(block, &ctx)?;
    Ok(())
}

fn parse_args(call: &Expr) -> Result<(i64, i64), Error> {
    let Expr::Call { args, .. } = call else {
        unreachable!()
    };
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!(
            "{MACRO} takes a compile-time size and an optional index base (0 or 1), got {} argument(s)",
            args.len()
        )));
    }
    let size = const_int(&args[0]).ok_or_else(|| {
        err(format!(
            "{MACRO} size must be a compile-time integer literal"
        ))
    })?;
    if size <= 0 || size > MAX_SIZE {
        return Err(err(format!(
            "{MACRO} size must be in 1..={MAX_SIZE}, got {size}"
        )));
    }
    let base = match args.get(1) {
        None => 1,
        Some(e) => match const_int(e) {
            Some(0) => 0,
            Some(1) => 1,
            _ => {
                return Err(err(format!(
                    "{MACRO} index base must be the literal 0 or 1"
                )))
            }
        },
    };
    Ok((size, base))
}

fn rewrite_block(block: &mut Block, ctx: &Ctx) -> Result<(), Error> {
    let stmts = std::mem::take(&mut block.stmts);
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        out.extend(rewrite_stmt(stmt, ctx)?);
    }
    block.stmts = out;
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        rewrite_list(exprs, ctx)?;
    }
    Ok(())
}

fn rewrite_stmt(stmt: Stmt, ctx: &Ctx) -> Result<Vec<Stmt>, Error> {
    match stmt {
        Stmt::Local { names, exprs } if exprs.len() == 1 && is_macro_call(&exprs[0]) => {
            let slot = ctx.get(&names[0]).expect("collected");
            let decl_names = slot.names.clone();
            Ok(vec![Stmt::Local {
                names: decl_names,
                exprs: vec![],
            }])
        }
        Stmt::Call(Expr::MethodCall { base, method, args }) if matches!(&*base, Expr::Name(n) if ctx.tracks(n)) =>
        {
            let Expr::Name(var) = &*base else {
                unreachable!()
            };
            let slot = ctx.get(var).unwrap();
            if method == "clear" {
                let (a, b) = clear_range(slot, &args, ctx)?;
                if a > b {
                    return Ok(vec![]);
                }
                let mut targets = Vec::new();
                let mut vals = Vec::new();
                for i in a..=b {
                    targets.push(Expr::Name(slot.name_for(i).unwrap().to_string()));
                    vals.push(Expr::Nil);
                }
                Ok(vec![Stmt::Assign {
                    targets,
                    exprs: vals,
                }])
            } else {
                Err(err(format!(
                    "{MACRO} `{var}:{method}(...)` is only valid as an expression (pack/unpack); \
                     `clear` is the only statement method"
                )))
            }
        }
        mut other => {
            rewrite_stmt_exprs(&mut other, ctx)?;
            let mut r = Ok(());
            each_sub_block_mut(&mut other, &mut |b| {
                if r.is_ok() {
                    r = rewrite_block(b, ctx);
                }
            });
            r?;
            reject_in_bodies(&other, ctx)?;
            Ok(vec![other])
        }
    }
}

fn rewrite_stmt_exprs(stmt: &mut Stmt, ctx: &Ctx) -> Result<(), Error> {
    match stmt {
        Stmt::Local { exprs, .. } => rewrite_list(exprs, ctx),
        Stmt::Assign { targets, exprs } => {
            for t in targets.iter_mut() {
                rewrite_target(t, ctx)?;
            }
            rewrite_list(exprs, ctx)
        }
        Stmt::Compound { target, value, .. } => {
            rewrite_target(target, ctx)?;
            rewrite_expr(value, ctx)
        }
        Stmt::Call(e) => rewrite_expr(e, ctx),
        Stmt::While { cond, .. } => rewrite_expr(cond, ctx),
        Stmt::Repeat { until, .. } => rewrite_expr(until, ctx),
        Stmt::NumericFor {
            start, end, step, ..
        } => {
            rewrite_expr(start, ctx)?;
            rewrite_expr(end, ctx)?;
            if let Some(s) = step {
                rewrite_expr(s, ctx)?;
            }
            Ok(())
        }
        Stmt::GenericFor { exprs, .. } => rewrite_list(exprs, ctx),
        Stmt::If { cond, else_ifs, .. } => {
            rewrite_expr(cond, ctx)?;
            for (c, _) in else_ifs.iter_mut() {
                rewrite_expr(c, ctx)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn rewrite_target(e: &mut Expr, ctx: &Ctx) -> Result<(), Error> {
    if let Expr::Index { base, key } = e {
        if let Expr::Name(n) = &**base {
            if let Some(slot) = ctx.get(n) {
                let name = index_name(slot, key, n)?;
                *e = Expr::Name(name);
                return Ok(());
            }
        }
    }
    if matches!(e, Expr::Name(n) if ctx.tracks(n)) {
        let Expr::Name(n) = e else { unreachable!() };
        return Err(escape(n, "be reassigned as a whole"));
    }
    rewrite_expr(e, ctx)
}

fn rewrite_list(exprs: &mut Vec<Expr>, ctx: &Ctx) -> Result<(), Error> {
    let n = exprs.len();
    let mut out: Vec<Expr> = Vec::with_capacity(n);
    for (i, mut e) in std::mem::take(exprs).into_iter().enumerate() {
        if i + 1 == n {
            if let Some(names) = as_unpack(&e, ctx)? {
                for nm in names {
                    out.push(Expr::Name(nm));
                }
                continue;
            }
        }
        rewrite_expr(&mut e, ctx)?;
        out.push(e);
    }
    *exprs = out;
    Ok(())
}

fn as_unpack(e: &Expr, ctx: &Ctx) -> Result<Option<Vec<String>>, Error> {
    if let Expr::MethodCall { base, method, args } = e {
        if let Expr::Name(n) = &**base {
            if let Some(slot) = ctx.get(n) {
                if method == "unpack" {
                    let (a, b) = clear_range(slot, args, ctx)?;
                    let mut names = Vec::new();
                    let mut i = a;
                    while i <= b {
                        names.push(slot.name_for(i).unwrap().to_string());
                        i += 1;
                    }
                    return Ok(Some(names));
                }
            }
        }
    }
    Ok(None)
}

fn rewrite_expr(e: &mut Expr, ctx: &Ctx) -> Result<(), Error> {
    match e {
        Expr::Index { base, key } if matches!(&**base, Expr::Name(n) if ctx.tracks(n)) => {
            let Expr::Name(n) = &**base else {
                unreachable!()
            };
            let slot = ctx.get(n).unwrap();
            let name = index_name(slot, key, n)?;
            *e = Expr::Name(name);
            return Ok(());
        }
        Expr::Unop {
            op: ir::UnOp::Len,
            expr,
        } if matches!(&**expr, Expr::Name(n) if ctx.tracks(n)) => {
            let Expr::Name(n) = &**expr else {
                unreachable!()
            };
            let slot = ctx.get(n).unwrap();
            *e = Expr::Number(slot.size().to_string());
            return Ok(());
        }
        Expr::MethodCall { base, method, args } if matches!(&**base, Expr::Name(n) if ctx.tracks(n)) =>
        {
            let Expr::Name(n) = &**base else {
                unreachable!()
            };
            let slot = ctx.get(n).unwrap();
            match method.as_str() {
                "pack" => {
                    let (a, b) = clear_range(slot, args, ctx)?;
                    let mut vals = Vec::new();
                    let mut i = a;
                    while i <= b {
                        vals.push(Expr::Name(slot.name_for(i).unwrap().to_string()));
                        i += 1;
                    }
                    *e = table_pack(vals);
                    return Ok(());
                }
                "unpack" => {
                    let (a, _) = clear_range(slot, args, ctx)?;
                    let first = slot.name_for(a).map(|s| s.to_string());
                    *e = match first {
                        Some(nm) => Expr::Name(nm),
                        None => Expr::Nil,
                    };
                    return Ok(());
                }
                m => return Err(escape(n, &format!("be used with method `:{m}(...)`"))),
            }
        }
        Expr::Field { base, name } if matches!(&**base, Expr::Name(n) if ctx.tracks(n)) => {
            let Expr::Name(n) = &**base else {
                unreachable!()
            };
            return Err(escape(n, &format!("be field-indexed as `.{name}`")));
        }
        Expr::Call { func, args, .. } => {
            rewrite_expr(func, ctx)?;
            rewrite_list(args, ctx)?;
            return Ok(());
        }
        Expr::MethodCall { base, args, .. } => {
            rewrite_expr(base, ctx)?;
            rewrite_list(args, ctx)?;
            return Ok(());
        }
        Expr::Name(n) if ctx.tracks(n) => {
            return Err(escape(n, "be used as a bare value"));
        }
        Expr::Function(_) => {
            reject_in_expr_body(e, ctx)?;
            return Ok(());
        }
        _ => {}
    }
    let mut r = Ok(());
    e.each_child_mut(&mut |c| {
        if r.is_ok() {
            r = rewrite_expr(c, ctx);
        }
    });
    r
}

fn index_name(slot: &Slot, key: &Expr, var: &str) -> Result<String, Error> {
    match const_int(key) {
        Some(i) => slot.name_for(i).map(|s| s.to_string()).ok_or_else(|| {
            err(format!(
                "{MACRO} index {i} on `{var}` is out of bounds [{}, {}]",
                slot.base,
                slot.base + slot.size() - 1
            ))
        }),
        None => Err(err(format!(
            "{MACRO} `{var}` supports only compile-time integer indices in V1; a dynamic index \
             cannot be lowered to a frame slot without a table"
        ))),
    }
}

fn clear_range(slot: &Slot, args: &[Expr], ctx: &Ctx) -> Result<(i64, i64), Error> {
    for a in args {
        if references_track(a, ctx) {
            return Err(err(format!(
                "{MACRO} range arguments must be compile-time integers"
            )));
        }
    }
    let first = args.first().map(const_int).transpose_opt()?;
    let last = args.get(1).map(const_int).transpose_opt()?;
    slot.range(first, last)
}

trait TransposeOpt {
    fn transpose_opt(self) -> Result<Option<i64>, Error>;
}
impl TransposeOpt for Option<Option<i64>> {
    fn transpose_opt(self) -> Result<Option<i64>, Error> {
        match self {
            None => Ok(None),
            Some(Some(v)) => Ok(Some(v)),
            Some(None) => Err(err(format!(
                "{MACRO} range arguments must be compile-time integers"
            ))),
        }
    }
}

fn references_track(e: &Expr, ctx: &Ctx) -> bool {
    let mut found = false;
    walk_names(e, &mut |n| {
        if ctx.tracks(n) {
            found = true;
        }
    });
    found
}

fn table_pack(vals: Vec<Expr>) -> Expr {
    Expr::Call {
        func: Box::new(Expr::Field {
            base: Box::new(Expr::Name("table".to_string())),
            name: "pack".to_string(),
        }),
        args: vals,
        site: None,
    }
}

fn escape(var: &str, what: &str) -> Error {
    err(format!(
        "{MACRO} allocation `{var}` cannot {what}; it lives in frame registers and never exists as a \
         first-class value"
    ))
}

fn reject_in_bodies(stmt: &Stmt, ctx: &Ctx) -> Result<(), Error> {
    let mut r = Ok(());
    each_sub_body(stmt, &mut |fb| {
        if r.is_ok() {
            r = reject_body(&fb.block, ctx);
        }
    });
    r
}

fn reject_in_expr_body(e: &Expr, ctx: &Ctx) -> Result<(), Error> {
    if let Expr::Function(fb) = e {
        return reject_body(&fb.block, ctx);
    }
    Ok(())
}

fn reject_body(block: &Block, ctx: &Ctx) -> Result<(), Error> {
    let mut found: Option<String> = None;
    walk_block_names(block, &mut |n| {
        if found.is_none() && ctx.tracks(n) {
            found = Some(n.to_string());
        }
    });
    match found {
        Some(n) => Err(escape(&n, "be captured by a nested function")),
        None => Ok(()),
    }
}

fn leftover(block: &Block) -> Option<Error> {
    let mut found = None;
    walk_block_exprs(block, &mut |e| {
        if found.is_none() && is_macro_call(e) {
            found = Some(err(format!(
                "{MACRO} may only appear as `local v = {MACRO}(n)`; it cannot be used in any other position"
            )));
        }
    });
    found
}

fn count_decls(block: &Block, var: &str, out: &mut u32) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Local { names, .. } => {
                if names.iter().any(|n| n == var) {
                    *out += 1;
                }
            }
            Stmt::LocalFunction { name, .. } if name == var => *out += 1,
            Stmt::NumericFor { var: v, .. } if v == var => *out += 1,
            Stmt::GenericFor { names, .. } if names.iter().any(|n| n == var) => *out += 1,
            _ => {}
        }
        each_sub_block(stmt, &mut |b| count_decls(b, var, out));
    }
}

fn used_before(block: &Block, decl_idx: usize, var: &str) -> bool {
    let mut found = false;
    for stmt in block.stmts.iter().take(decl_idx) {
        walk_stmt_names(stmt, &mut |n| {
            if n == var {
                found = true;
            }
        });
    }
    found
}

fn collect_idents(block: &Block, out: &mut HashSet<String>) {
    walk_block_names(block, &mut |n| {
        out.insert(n.to_string());
    });
}

fn each_func_body_in_scope_mut(block: &mut Block, f: &mut impl FnMut(&mut FuncBody)) {
    for stmt in &mut block.stmts {
        each_direct_body_mut(stmt, f);
        each_sub_block_mut(stmt, &mut |b| each_func_body_in_scope_mut(b, f));
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs {
            each_body_in_expr_mut(e, f);
        }
    }
}

fn each_direct_body_mut(stmt: &mut Stmt, f: &mut impl FnMut(&mut FuncBody)) {
    match stmt {
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => f(body),
        Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => {
            for e in exprs {
                each_body_in_expr_mut(e, f);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter_mut().chain(exprs.iter_mut()) {
                each_body_in_expr_mut(e, f);
            }
        }
        Stmt::Compound { target, value, .. } => {
            each_body_in_expr_mut(target, f);
            each_body_in_expr_mut(value, f);
        }
        Stmt::Call(e) | Stmt::While { cond: e, .. } | Stmt::Repeat { until: e, .. } => {
            each_body_in_expr_mut(e, f)
        }
        Stmt::NumericFor {
            start, end, step, ..
        } => {
            each_body_in_expr_mut(start, f);
            each_body_in_expr_mut(end, f);
            if let Some(s) = step {
                each_body_in_expr_mut(s, f);
            }
        }
        Stmt::If { cond, else_ifs, .. } => {
            each_body_in_expr_mut(cond, f);
            for (c, _) in else_ifs {
                each_body_in_expr_mut(c, f);
            }
        }
        _ => {}
    }
}

fn each_body_in_expr_mut(e: &mut Expr, f: &mut impl FnMut(&mut FuncBody)) {
    if let Expr::Function(fb) = e {
        f(fb);
        return;
    }
    e.each_child_mut(&mut |c| each_body_in_expr_mut(c, f));
}

fn each_sub_block(stmt: &Stmt, f: &mut impl FnMut(&Block)) {
    match stmt {
        Stmt::Do(b) | Stmt::While { body: b, .. } | Stmt::Repeat { body: b, .. } => f(b),
        Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => f(body),
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            f(body);
            for (_, b) in else_ifs {
                f(b);
            }
            if let Some(b) = otherwise {
                f(b);
            }
        }
        _ => {}
    }
}

fn each_sub_block_mut(stmt: &mut Stmt, f: &mut impl FnMut(&mut Block)) {
    match stmt {
        Stmt::Do(b) | Stmt::While { body: b, .. } | Stmt::Repeat { body: b, .. } => f(b),
        Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => f(body),
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            f(body);
            for (_, b) in else_ifs {
                f(b);
            }
            if let Some(b) = otherwise {
                f(b);
            }
        }
        _ => {}
    }
}

fn each_sub_body(stmt: &Stmt, f: &mut impl FnMut(&FuncBody)) {
    match stmt {
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => f(body),
        Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => {
            for e in exprs {
                each_body_in_expr(e, f);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter().chain(exprs.iter()) {
                each_body_in_expr(e, f);
            }
        }
        Stmt::Compound { target, value, .. } => {
            each_body_in_expr(target, f);
            each_body_in_expr(value, f);
        }
        Stmt::Call(e) | Stmt::While { cond: e, .. } | Stmt::Repeat { until: e, .. } => {
            each_body_in_expr(e, f)
        }
        Stmt::NumericFor {
            start, end, step, ..
        } => {
            each_body_in_expr(start, f);
            each_body_in_expr(end, f);
            if let Some(s) = step {
                each_body_in_expr(s, f);
            }
        }
        Stmt::If { cond, else_ifs, .. } => {
            each_body_in_expr(cond, f);
            for (c, _) in else_ifs {
                each_body_in_expr(c, f);
            }
        }
        _ => {}
    }
}

fn each_body_in_expr(e: &Expr, f: &mut impl FnMut(&FuncBody)) {
    if let Expr::Function(fb) = e {
        f(fb);
        return;
    }
    e.each_child(&mut |c| each_body_in_expr(c, f));
}

fn walk_names(e: &Expr, f: &mut impl FnMut(&str)) {
    if let Expr::Name(n) = e {
        f(n);
    }
    e.each_child(&mut |c| walk_names(c, f));
    if let Expr::Function(fb) = e {
        walk_block_names(&fb.block, f);
    }
}

fn walk_stmt_names(stmt: &Stmt, f: &mut impl FnMut(&str)) {
    each_expr_in_stmt(stmt, &mut |e| walk_names(e, f));
    each_sub_block(stmt, &mut |b| walk_block_names(b, f));
    each_sub_body(stmt, &mut |fb| walk_block_names(&fb.block, f));
}

fn walk_block_names(block: &Block, f: &mut impl FnMut(&str)) {
    for stmt in &block.stmts {
        walk_stmt_names(stmt, f);
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            walk_names(e, f);
        }
    }
}

fn walk_block_exprs(block: &Block, f: &mut impl FnMut(&Expr)) {
    for stmt in &block.stmts {
        each_expr_in_stmt(stmt, &mut |e| walk_expr_deep(e, f));
        each_sub_block(stmt, &mut |b| walk_block_exprs(b, f));
        each_sub_body(stmt, &mut |fb| walk_block_exprs(&fb.block, f));
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            walk_expr_deep(e, f);
        }
    }
}

fn walk_expr_deep(e: &Expr, f: &mut impl FnMut(&Expr)) {
    f(e);
    e.each_child(&mut |c| walk_expr_deep(c, f));
    if let Expr::Function(fb) = e {
        walk_block_exprs(&fb.block, f);
    }
}

fn each_expr_in_stmt(stmt: &Stmt, f: &mut impl FnMut(&Expr)) {
    match stmt {
        Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => {
            for e in exprs {
                f(e);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter().chain(exprs.iter()) {
                f(e);
            }
        }
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
