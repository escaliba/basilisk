use crate::Error;
use ir::cfg::{self, ReturnClass};
use ir::{Block, Expr, Field, FuncBody, InterpPart, LastStmt, Module, Param, Stmt};

pub const INLINE: &str = "BASIL_INLINE";

const MAX_BODY_STMTS: usize = 24;
const MAX_CALL_SITES: usize = 16;
const MAX_PROJECTED_STMTS: usize = 96;

struct Ctx {
    counter: u32,
    prefix: String,
    helper_names: Vec<String>,
}

pub fn apply(module: &mut Module) -> Result<(), Error> {
    let mut used = Vec::new();
    collect_idents_block(&module.block, &mut used);
    for n in &module.natives {
        collect_idents_block(&n.block, &mut used);
    }
    for e in &module.encfuncs {
        collect_idents_block(&e.body.block, &mut used);
    }
    let mut prefix = "__bi".to_string();
    while used.iter().any(|u| u.starts_with(&prefix)) {
        prefix.push('_');
    }
    let mut helper_names = Vec::new();
    collect_helper_names(&module.block, &mut helper_names);
    let mut cx = Ctx {
        counter: 0,
        prefix,
        helper_names,
    };
    block(&mut module.block, &mut cx)?;
    for n in &mut module.natives {
        reject_any(&n.block, "a BASIL_NO_VIRTUALIZE function")?;
    }
    for e in &mut module.encfuncs {
        reject_any(&e.body.block, "a BASIL_ENCFUNC function")?;
    }
    reject_any(&module.block, "this program")?;
    Ok(())
}

fn err(msg: String) -> Error {
    Error::Macro(msg)
}

fn is_inline_call(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, .. } if matches!(&**func, Expr::Name(n) if n == INLINE))
}

fn reject_any(b: &Block, where_: &str) -> Result<(), Error> {
    let mut bad = false;
    walk_exprs_block(b, &mut |e| {
        if matches!(e, Expr::Name(n) if n == INLINE) {
            bad = true;
        }
    });
    if bad {
        return Err(err(format!(
            "{INLINE} may only appear as `local f = {INLINE}(function(...) ... end)`; \
             an unsupported use was found in {where_}"
        )));
    }
    Ok(())
}

fn block(b: &mut Block, cx: &mut Ctx) -> Result<(), Error> {
    let mut i = 0;
    while i < b.stmts.len() {
        let taken = match &b.stmts[i] {
            Stmt::Local { names, exprs } if exprs.len() == 1 && is_inline_call(&exprs[0]) => {
                if names.len() != 1 {
                    return Err(err(format!(
                        "{INLINE} must be bound to exactly one local; `local {}` declares {}",
                        names.join(", "),
                        names.len()
                    )));
                }
                Some(names[0].clone())
            }
            _ => None,
        };
        match taken {
            Some(name) => {
                let call = match &b.stmts[i] {
                    Stmt::Local { exprs, .. } => exprs[0].clone(),
                    _ => unreachable!(),
                };
                let fb = extract(&call)?;
                let rest_has = uses_after(&b.stmts[i + 1..], &b.last, &name);
                inline_one(b, i, &name, &fb, rest_has, cx)?;
            }
            None => {
                descend(&mut b.stmts[i], cx)?;
                i += 1;
            }
        }
    }
    if let Some(LastStmt::Return(es)) = &mut b.last {
        for e in es.iter_mut() {
            descend_expr(e, cx)?;
        }
    }
    Ok(())
}

fn extract(call: &Expr) -> Result<FuncBody, Error> {
    let args = match call {
        Expr::Call { args, .. } => args,
        _ => unreachable!(),
    };
    if args.len() != 1 {
        return Err(err(format!(
            "{INLINE} takes exactly one function-literal argument, got {}",
            args.len()
        )));
    }
    match &args[0] {
        Expr::Function(fb) => Ok(fb.clone()),
        Expr::Name(n) => Err(err(format!(
            "{INLINE} requires a function literal, not a reference (`{n}`)"
        ))),
        _ => Err(err(format!(
            "{INLINE} requires a function-literal argument"
        ))),
    }
}

fn descend(s: &mut Stmt, cx: &mut Ctx) -> Result<(), Error> {
    match s {
        Stmt::Do(b) => block(b, cx)?,
        Stmt::While { body, .. } | Stmt::Repeat { body, .. } => block(body, cx)?,
        Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => block(body, cx)?,
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            block(body, cx)?;
            for (_, x) in else_ifs.iter_mut() {
                block(x, cx)?;
            }
            if let Some(x) = otherwise {
                block(x, cx)?;
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            block(&mut body.block, cx)?
        }
        Stmt::Local { exprs, .. } => {
            for e in exprs.iter_mut() {
                descend_expr(e, cx)?;
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter_mut().chain(exprs.iter_mut()) {
                descend_expr(e, cx)?;
            }
        }
        Stmt::Compound { target, value, .. } => {
            descend_expr(target, cx)?;
            descend_expr(value, cx)?;
        }
        Stmt::Call(e) => descend_expr(e, cx)?,
    }
    Ok(())
}

fn descend_expr(e: &mut Expr, cx: &mut Ctx) -> Result<(), Error> {
    if let Expr::Function(fb) = e {
        return block(&mut fb.block, cx);
    }
    let mut r = Ok(());
    each_child_mut(e, &mut |c| {
        if r.is_ok() {
            r = descend_expr(c, cx);
        }
    });
    r
}

#[derive(Default)]
struct Sites {
    stmt_calls: usize,
    value_calls: usize,
    escapes: usize,
    unsupported: usize,
}

fn uses_after(rest: &[Stmt], tail: &Option<LastStmt>, name: &str) -> Sites {
    let mut s = Sites::default();
    count_seq(rest, tail, name, &mut s);
    s
}

fn is_direct(e: &Expr, name: &str) -> bool {
    matches!(e, Expr::Call { func, .. } if matches!(&**func, Expr::Name(n) if n == name))
}

fn shadows(st: &Stmt, name: &str) -> bool {
    match st {
        Stmt::Local { names, .. } => names.iter().any(|n| n == name),
        Stmt::LocalFunction { name: n, .. } => n == name,
        _ => false,
    }
}

fn count_seq(stmts: &[Stmt], tail: &Option<LastStmt>, name: &str, s: &mut Sites) {
    for st in stmts {
        count_stmt(st, name, s);
        if shadows(st, name) {
            return;
        }
    }
    if let Some(LastStmt::Return(es)) = tail {
        if es.len() == 1 && is_direct(&es[0], name) {
            s.value_calls += 1;
            if let Expr::Call { args, .. } = &es[0] {
                for a in args {
                    count_expr(a, name, s);
                }
            }
        } else {
            for e in es {
                count_expr(e, name, s);
            }
        }
    }
}

fn count_block(b: &Block, name: &str, s: &mut Sites) {
    count_seq(&b.stmts, &b.last, name, s);
}

fn count_stmt(st: &Stmt, name: &str, s: &mut Sites) {
    match st {
        Stmt::Call(e) if is_direct(e, name) => {
            s.stmt_calls += 1;
            if let Expr::Call { args, .. } = e {
                for a in args {
                    count_expr(a, name, s);
                }
            }
        }
        Stmt::Local { names: _, exprs } if exprs.len() == 1 && is_direct(&exprs[0], name) => {
            s.value_calls += 1;
            if let Expr::Call { args, .. } = &exprs[0] {
                for a in args {
                    count_expr(a, name, s);
                }
            }
        }
        Stmt::Assign { targets, exprs }
            if targets.len() == 1 && exprs.len() == 1 && is_direct(&exprs[0], name) =>
        {
            s.value_calls += 1;
            count_expr(&targets[0], name, s);
            if let Expr::Call { args, .. } = &exprs[0] {
                for a in args {
                    count_expr(a, name, s);
                }
            }
        }
        Stmt::Local { exprs, .. } => {
            for e in exprs {
                count_expr(e, name, s);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter().chain(exprs.iter()) {
                count_expr(e, name, s);
            }
        }
        Stmt::Compound { target, value, .. } => {
            count_expr(target, name, s);
            count_expr(value, name, s);
        }
        Stmt::Call(e) => count_expr(e, name, s),
        Stmt::Do(b) => count_block(b, name, s),
        Stmt::While { cond, body } => {
            count_expr(cond, name, s);
            count_block(body, name, s);
        }
        Stmt::Repeat { body, until } => {
            count_block(body, name, s);
            count_expr(until, name, s);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            count_expr(start, name, s);
            count_expr(end, name, s);
            if let Some(x) = step {
                count_expr(x, name, s);
            }
            count_block(body, name, s);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            for e in exprs {
                count_expr(e, name, s);
            }
            count_block(body, name, s);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            count_expr(cond, name, s);
            count_block(body, name, s);
            for (c, b) in else_ifs {
                count_expr(c, name, s);
                count_block(b, name, s);
            }
            if let Some(b) = otherwise {
                count_block(b, name, s);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            if body
                .params
                .iter()
                .any(|p| matches!(p, Param::Name(n) if n == name))
            {
                return;
            }
            count_block(&body.block, name, s);
        }
    }
}

fn count_expr(e: &Expr, name: &str, s: &mut Sites) {
    if matches!(e, Expr::Name(n) if n == name) {
        s.escapes += 1;
        return;
    }
    if is_direct(e, name) {
        s.unsupported += 1;
        if let Expr::Call { args, .. } = e {
            for a in args {
                count_expr(a, name, s);
            }
        }
        return;
    }
    if let Expr::Function(fb) = e {
        if fb
            .params
            .iter()
            .any(|p| matches!(p, Param::Name(n) if n == name))
        {
            return;
        }
        count_block(&fb.block, name, s);
        return;
    }
    e.each_child(&mut |c| count_expr(c, name, s));
}

fn inline_one(
    b: &mut Block,
    at: usize,
    name: &str,
    fb: &FuncBody,
    sites: Sites,
    cx: &mut Ctx,
) -> Result<(), Error> {
    let mut nested_macro = false;
    walk_exprs_block(&fb.block, &mut |e| {
        if matches!(e, Expr::Name(n) if n == INLINE) {
            nested_macro = true;
        }
    });
    if nested_macro {
        return Err(err(format!(
            "{INLINE} helper `{name}` contains a nested {INLINE}; nested inlining is not supported"
        )));
    }
    if body_has_nested_function(&fb.block) {
        return Err(err(format!(
            "{INLINE} helper `{name}` contains a nested function literal; this BASIL_INLINE version does \
             not inline helpers that create nested functions (they may escape the sealed inline body)"
        )));
    }
    let c = cfg::build(fb);
    if c.is_vararg {
        return Err(err(format!(
            "{INLINE} helper `{name}` takes varargs; varargs are not inlinable"
        )));
    }
    if sites.escapes > 0 {
        return Err(err(format!(
            "{INLINE} helper `{name}` is used as a value (stored, compared, passed or returned); \
             it must only ever be called directly"
        )));
    }
    if sites.unsupported > 0 {
        return Err(err(format!(
            "{INLINE} helper `{name}` is called in an expression context this transformation does not \
             support; supported call sites are `local r = {name}(...)`, `r = {name}(...)`, \
             `{name}(...)` as a statement, and `return {name}(...)`"
        )));
    }
    if c.free_names.iter().any(|n| n == name) {
        return Err(err(format!(
            "{INLINE} helper `{name}` is recursive; recursive helpers are not inlinable"
        )));
    }
    let params: Vec<String> = fb
        .params
        .iter()
        .filter_map(|p| match p {
            Param::Name(n) => Some(n.clone()),
            Param::Vararg => None,
        })
        .collect();
    let outer = outer_locals(b, at);
    let captured: Vec<&String> = c
        .free_names
        .iter()
        .filter(|n| outer.contains(n) && !params.contains(n))
        .collect();
    if let Some(first) = captured.first() {
        return Err(err(format!(
            "{INLINE} helper `{name}` captures the enclosing local `{first}`; inlinable helpers must be \
             capture-free — arguments in, one value out"
        )));
    }
    if let Some(other) = c
        .free_names
        .iter()
        .find(|n| n.as_str() != name && cx.helper_names.contains(n))
    {
        return Err(err(format!(
            "{INLINE} helper `{name}` references another BASIL_INLINE helper `{other}`; an inline helper \
             must not depend on another inline helper (the referenced helper is removed before this one)"
        )));
    }
    let class = c.return_class();
    match class {
        ReturnClass::SingleValue => {}
        ReturnClass::Void => {
            if sites.value_calls > 0 {
                return Err(err(format!(
                    "{INLINE} helper `{name}` returns no value but is used in a value position"
                )));
            }
        }
        ReturnClass::MultiValue => {
            return Err(err(format!(
                "{INLINE} helper `{name}` returns several values; only a single ordinary value is inlinable"
            )))
        }
        ReturnClass::Mixed => {
            return Err(err(format!(
                "{INLINE} helper `{name}` has both value-returning and bare-return paths; \
                 mixed return arity is not inlinable"
            )))
        }
    }
    if c.early_return_count() > 0 {
        return Err(err(format!(
            "{INLINE} helper `{name}` has {} early return(s); only a single terminal return is \
             supported by this transformation",
            c.early_return_count()
        )));
    }
    let total = sites.stmt_calls + sites.value_calls;
    if total == 0 {
        return Err(err(format!(
            "{INLINE} helper `{name}` is never called; remove it or drop the macro"
        )));
    }
    let body_stmts = count_stmts(&fb.block);
    if body_stmts > MAX_BODY_STMTS {
        return Err(err(format!(
            "{INLINE} helper `{name}` has {body_stmts} statements, over the inline budget of {MAX_BODY_STMTS}"
        )));
    }
    if total > MAX_CALL_SITES {
        return Err(err(format!(
            "{INLINE} helper `{name}` has {total} call sites, over the inline budget of {MAX_CALL_SITES}"
        )));
    }
    let projected = body_stmts * total;
    if projected > MAX_PROJECTED_STMTS {
        return Err(err(format!(
            "{INLINE} helper `{name}` would expand to about {projected} statements \
             ({body_stmts} × {total} call sites), over the inline budget of {MAX_PROJECTED_STMTS}"
        )));
    }

    let tail = tail_return(&fb.block);
    b.stmts.remove(at);
    let mut site = Site {
        name: name.to_string(),
        fb: fb.clone(),
        params,
        tail,
        cx,
    };
    let rest = b.stmts.split_off(at);
    let mut rb = Block {
        stmts: rest,
        last: b.last.take(),
    };
    rewrite_block(&mut rb, &mut site);
    b.stmts.extend(rb.stmts);
    b.last = rb.last;
    block_after(b, at, site.cx)
}

struct Site<'a> {
    name: String,
    fb: FuncBody,
    params: Vec<String>,
    tail: Option<Expr>,
    cx: &'a mut Ctx,
}

fn rewrite_block(b: &mut Block, s: &mut Site) {
    rewrite_seq(&mut b.stmts, s);
    let shadowed = b.stmts.iter().any(|st| shadows(st, &s.name));
    if shadowed {
        return;
    }
    if let Some(LastStmt::Return(es)) = b.last.clone() {
        if es.len() == 1 && is_direct(&es[0], &s.name) {
            let (pre, res) = build_expansion(&es[0], &s.fb, &s.params, &s.tail, s.cx);
            b.stmts.extend(pre);
            b.last = Some(LastStmt::Return(vec![
                res.expect("value class yields a result")
            ]));
        }
    }
}

fn rewrite_seq(stmts: &mut Vec<Stmt>, s: &mut Site) {
    let mut i = 0;
    while i < stmts.len() {
        if shadows(&stmts[i], &s.name) {
            return;
        }
        let repl: Option<(Vec<Stmt>, Option<Stmt>)> = match &stmts[i] {
            Stmt::Call(e) if is_direct(e, &s.name) => {
                let (pre, _) = build_expansion(e, &s.fb, &s.params, &s.tail, s.cx);
                Some((pre, None))
            }
            Stmt::Local { names, exprs } if exprs.len() == 1 && is_direct(&exprs[0], &s.name) => {
                let (pre, res) = build_expansion(&exprs[0], &s.fb, &s.params, &s.tail, s.cx);
                let r = res.expect("value class yields a result");
                Some((
                    pre,
                    Some(Stmt::Local {
                        names: names.clone(),
                        exprs: vec![r],
                    }),
                ))
            }
            Stmt::Assign { targets, exprs }
                if targets.len() == 1 && exprs.len() == 1 && is_direct(&exprs[0], &s.name) =>
            {
                let (pre, res) = build_expansion(&exprs[0], &s.fb, &s.params, &s.tail, s.cx);
                let r = res.expect("value class yields a result");
                Some((
                    pre,
                    Some(Stmt::Assign {
                        targets: targets.clone(),
                        exprs: vec![r],
                    }),
                ))
            }
            _ => None,
        };
        match repl {
            Some((pre, after)) => {
                stmts.remove(i);
                let mut n = 0;
                for st in pre.into_iter().rev() {
                    stmts.insert(i, st);
                    n += 1;
                }
                if let Some(a) = after {
                    stmts.insert(i + n, a);
                    n += 1;
                }
                i += n;
            }
            None => {
                rewrite_nested(&mut stmts[i], s);
                i += 1;
            }
        }
    }
}

fn rewrite_nested(st: &mut Stmt, s: &mut Site) {
    match st {
        Stmt::Do(b) => rewrite_block(b, s),
        Stmt::While { body, .. } | Stmt::Repeat { body, .. } => rewrite_block(body, s),
        Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => rewrite_block(body, s),
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            rewrite_block(body, s);
            for (_, x) in else_ifs.iter_mut() {
                rewrite_block(x, s);
            }
            if let Some(x) = otherwise {
                rewrite_block(x, s);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            if body
                .params
                .iter()
                .any(|p| matches!(p, Param::Name(n) if *n == s.name))
            {
                return;
            }
            rewrite_block(&mut body.block, s);
        }
        _ => {}
    }
}

fn block_after(b: &mut Block, from: usize, cx: &mut Ctx) -> Result<(), Error> {
    let mut i = from;
    while i < b.stmts.len() {
        descend(&mut b.stmts[i], cx)?;
        i += 1;
    }
    Ok(())
}

fn tail_return(b: &Block) -> Option<Expr> {
    match &b.last {
        Some(LastStmt::Return(es)) if es.len() == 1 => Some(es[0].clone()),
        _ => None,
    }
}

fn build_expansion(
    call: &Expr,
    fb: &FuncBody,
    params: &[String],
    tail: &Option<Expr>,
    cx: &mut Ctx,
) -> (Vec<Stmt>, Option<Expr>) {
    let args = match call {
        Expr::Call { args, .. } => args.clone(),
        _ => unreachable!(),
    };
    let mut ren = Renamer {
        map: Vec::new(),
        cx,
    };
    let mut pre: Vec<Stmt> = Vec::new();
    let mut inner: Vec<Stmt> = Vec::new();

    for (k, p) in params.iter().enumerate() {
        let fresh = ren.fresh(p);
        let v = args.get(k).cloned().unwrap_or(Expr::Nil);
        inner.push(Stmt::Local {
            names: vec![fresh],
            exprs: vec![v],
        });
    }
    for extra in args.iter().skip(params.len()) {
        let fresh = ren.cx.next("arg");
        inner.push(Stmt::Local {
            names: vec![fresh],
            exprs: vec![extra.clone()],
        });
    }

    let mut body = fb.block.clone();
    body.last = None;
    for st in body.stmts.iter_mut() {
        ren.stmt(st);
    }
    inner.extend(body.stmts);

    let result = tail.as_ref().map(|t| {
        let mut t = t.clone();
        ren.expr(&mut t);
        t
    });
    match result {
        Some(t) => {
            let slot = ren.cx.next("r");
            inner.push(Stmt::Assign {
                targets: vec![Expr::Name(slot.clone())],
                exprs: vec![t],
            });
            pre.push(Stmt::Local {
                names: vec![slot.clone()],
                exprs: Vec::new(),
            });
            pre.push(Stmt::Do(Block {
                stmts: inner,
                last: None,
            }));
            (pre, Some(Expr::Name(slot)))
        }
        None => {
            pre.push(Stmt::Do(Block {
                stmts: inner,
                last: None,
            }));
            (pre, None)
        }
    }
}

impl Ctx {
    fn next(&mut self, tag: &str) -> String {
        self.counter += 1;
        format!("{}{}_{}", self.prefix, self.counter, tag)
    }
}

struct Renamer<'a> {
    map: Vec<Vec<(String, String)>>,
    cx: &'a mut Ctx,
}

impl<'a> Renamer<'a> {
    fn fresh(&mut self, name: &str) -> String {
        let f = self.cx.next(name);
        if self.map.is_empty() {
            self.map.push(Vec::new());
        }
        self.map
            .last_mut()
            .unwrap()
            .push((name.to_string(), f.clone()));
        f
    }

    fn lookup(&self, n: &str) -> Option<String> {
        for frame in self.map.iter().rev() {
            for (from, to) in frame.iter().rev() {
                if from == n {
                    return Some(to.clone());
                }
            }
        }
        None
    }

    fn block(&mut self, b: &mut Block) {
        self.map.push(Vec::new());
        for s in b.stmts.iter_mut() {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &mut b.last {
            for e in es.iter_mut() {
                self.expr(e);
            }
        }
        self.map.pop();
    }

    fn stmt(&mut self, s: &mut Stmt) {
        match s {
            Stmt::Local { names, exprs } => {
                for e in exprs.iter_mut() {
                    self.expr(e);
                }
                for n in names.iter_mut() {
                    *n = self.fresh(n);
                }
            }
            Stmt::LocalFunction { name, body } => {
                *name = self.fresh(name);
                self.map.push(Vec::new());
                for p in body.params.iter_mut() {
                    if let Param::Name(n) = p {
                        *n = self.fresh(n);
                    }
                }
                self.block(&mut body.block);
                self.map.pop();
            }
            Stmt::Function { name, body } => {
                if let Some(to) = self.lookup(&name.path[0]) {
                    name.path[0] = to;
                }
                self.map.push(Vec::new());
                for p in body.params.iter_mut() {
                    if let Param::Name(n) = p {
                        *n = self.fresh(n);
                    }
                }
                self.block(&mut body.block);
                self.map.pop();
            }
            Stmt::Assign { targets, exprs } => {
                for e in targets.iter_mut().chain(exprs.iter_mut()) {
                    self.expr(e);
                }
            }
            Stmt::Compound { target, value, .. } => {
                self.expr(target);
                self.expr(value);
            }
            Stmt::Call(e) => self.expr(e),
            Stmt::Do(b) => self.block(b),
            Stmt::While { cond, body } => {
                self.expr(cond);
                self.block(body);
            }
            Stmt::Repeat { body, until } => {
                self.map.push(Vec::new());
                for s in body.stmts.iter_mut() {
                    self.stmt(s);
                }
                if let Some(LastStmt::Return(es)) = &mut body.last {
                    for e in es.iter_mut() {
                        self.expr(e);
                    }
                }
                self.expr(until);
                self.map.pop();
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
                self.map.push(Vec::new());
                *var = self.fresh(var);
                self.block(body);
                self.map.pop();
            }
            Stmt::GenericFor { names, exprs, body } => {
                for e in exprs.iter_mut() {
                    self.expr(e);
                }
                self.map.push(Vec::new());
                for n in names.iter_mut() {
                    *n = self.fresh(n);
                }
                self.block(body);
                self.map.pop();
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond);
                self.block(body);
                for (c, x) in else_ifs.iter_mut() {
                    self.expr(c);
                    self.block(x);
                }
                if let Some(x) = otherwise {
                    self.block(x);
                }
            }
        }
    }

    fn expr(&mut self, e: &mut Expr) {
        match e {
            Expr::Name(n) => {
                if let Some(to) = self.lookup(n) {
                    *n = to;
                }
            }
            Expr::Function(fb) => {
                self.map.push(Vec::new());
                for p in fb.params.iter_mut() {
                    if let Param::Name(n) = p {
                        *n = self.fresh(n);
                    }
                }
                self.block(&mut fb.block);
                self.map.pop();
            }
            _ => each_child_mut(e, &mut |c| self.expr(c)),
        }
    }
}

fn count_stmts(b: &Block) -> usize {
    let mut n = b.stmts.len() + b.last.is_some() as usize;
    for s in &b.stmts {
        n += match s {
            Stmt::Do(x) => count_stmts(x),
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => count_stmts(body),
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => count_stmts(body),
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                count_stmts(body)
                    + else_ifs.iter().map(|(_, b)| count_stmts(b)).sum::<usize>()
                    + otherwise.as_ref().map(count_stmts).unwrap_or(0)
            }
            _ => 0,
        };
    }
    n
}

fn body_has_nested_function(b: &Block) -> bool {
    let mut found = false;
    for st in &b.stmts {
        match st {
            Stmt::Function { .. } | Stmt::LocalFunction { .. } => return true,
            Stmt::Do(x) => found |= body_has_nested_function(x),
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => {
                found |= body_has_nested_function(body)
            }
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => {
                found |= body_has_nested_function(body)
            }
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                found |= body_has_nested_function(body);
                for (_, x) in else_ifs {
                    found |= body_has_nested_function(x);
                }
                if let Some(x) = otherwise {
                    found |= body_has_nested_function(x);
                }
            }
            _ => {}
        }
        if found {
            return true;
        }
    }
    let mut in_expr = false;
    walk_exprs_block(b, &mut |e| {
        if matches!(e, Expr::Function(_)) {
            in_expr = true;
        }
    });
    in_expr
}

fn collect_helper_names(b: &Block, out: &mut Vec<String>) {
    for st in &b.stmts {
        if let Stmt::Local { names, exprs } = st {
            if names.len() == 1 && exprs.len() == 1 && is_inline_call(&exprs[0]) {
                out.push(names[0].clone());
            }
        }
        match st {
            Stmt::Do(x) => collect_helper_names(x, out),
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => collect_helper_names(body, out),
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => {
                collect_helper_names(body, out)
            }
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                collect_helper_names(body, out);
                for (_, x) in else_ifs {
                    collect_helper_names(x, out);
                }
                if let Some(x) = otherwise {
                    collect_helper_names(x, out);
                }
            }
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                collect_helper_names(&body.block, out)
            }
            _ => {}
        }
    }
}

fn outer_locals(b: &Block, before: usize) -> Vec<String> {
    let mut v = Vec::new();
    for s in b.stmts.iter().take(before) {
        match s {
            Stmt::Local { names, .. } => v.extend(names.clone()),
            Stmt::LocalFunction { name, .. } => v.push(name.clone()),
            _ => {}
        }
    }
    v
}

fn each_child_mut(e: &mut Expr, f: &mut impl FnMut(&mut Expr)) {
    match e {
        Expr::Paren(x) | Expr::Unop { expr: x, .. } => f(x),
        Expr::Field { base, .. } => f(base),
        Expr::Index { base, key } => {
            f(base);
            f(key);
        }
        Expr::Call { func, args, .. } => {
            f(func);
            for a in args.iter_mut() {
                f(a);
            }
        }
        Expr::MethodCall { base, args, .. } => {
            f(base);
            for a in args.iter_mut() {
                f(a);
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
            for (c, v) in else_ifs.iter_mut() {
                f(c);
                f(v);
            }
            f(otherwise);
        }
        Expr::Table(fs) => {
            for fl in fs.iter_mut() {
                match fl {
                    Field::Positional(v) => f(v),
                    Field::Named { value, .. } => f(value),
                    Field::Keyed { key, value } => {
                        f(key);
                        f(value);
                    }
                }
            }
        }
        Expr::Interp(ps) => {
            for p in ps.iter_mut() {
                if let InterpPart::Expr(x) = p {
                    f(x);
                }
            }
        }
        Expr::EncFunc { key, .. } => f(key),
        Expr::Function(_) => {}
        _ => {}
    }
}

fn walk_exprs_block(b: &Block, f: &mut impl FnMut(&Expr)) {
    for s in &b.stmts {
        walk_exprs_stmt(s, f);
    }
    if let Some(LastStmt::Return(es)) = &b.last {
        for e in es {
            walk_expr(e, f);
        }
    }
}

fn walk_exprs_stmt(s: &Stmt, f: &mut impl FnMut(&Expr)) {
    match s {
        Stmt::Local { exprs, .. } => {
            for e in exprs {
                walk_expr(e, f);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter().chain(exprs.iter()) {
                walk_expr(e, f);
            }
        }
        Stmt::Compound { target, value, .. } => {
            walk_expr(target, f);
            walk_expr(value, f);
        }
        Stmt::Call(e) => walk_expr(e, f),
        Stmt::Do(b) => walk_exprs_block(b, f),
        Stmt::While { cond, body } => {
            walk_expr(cond, f);
            walk_exprs_block(body, f);
        }
        Stmt::Repeat { body, until } => {
            walk_exprs_block(body, f);
            walk_expr(until, f);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            walk_expr(start, f);
            walk_expr(end, f);
            if let Some(x) = step {
                walk_expr(x, f);
            }
            walk_exprs_block(body, f);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            for e in exprs {
                walk_expr(e, f);
            }
            walk_exprs_block(body, f);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            walk_expr(cond, f);
            walk_exprs_block(body, f);
            for (c, b) in else_ifs {
                walk_expr(c, f);
                walk_exprs_block(b, f);
            }
            if let Some(b) = otherwise {
                walk_exprs_block(b, f);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            walk_exprs_block(&body.block, f)
        }
    }
}

fn walk_expr(e: &Expr, f: &mut impl FnMut(&Expr)) {
    f(e);
    if let Expr::Function(fb) = e {
        walk_exprs_block(&fb.block, f);
        return;
    }
    e.each_child(&mut |c| walk_expr(c, f));
}

fn collect_idents_block(b: &Block, out: &mut Vec<String>) {
    walk_exprs_block(b, &mut |e| {
        if let Expr::Name(n) = e {
            out.push(n.clone());
        }
    });
    for s in &b.stmts {
        collect_decl_stmt(s, out);
    }
}

fn collect_decl_stmt(s: &Stmt, out: &mut Vec<String>) {
    match s {
        Stmt::Local { names, .. } => out.extend(names.clone()),
        Stmt::LocalFunction { name, body } => {
            out.push(name.clone());
            collect_idents_block(&body.block, out);
        }
        Stmt::Function { body, .. } => collect_idents_block(&body.block, out),
        Stmt::Do(b) => collect_idents_block(b, out),
        Stmt::While { body, .. } | Stmt::Repeat { body, .. } => collect_idents_block(body, out),
        Stmt::NumericFor { var, body, .. } => {
            out.push(var.clone());
            collect_idents_block(body, out);
        }
        Stmt::GenericFor { names, body, .. } => {
            out.extend(names.clone());
            collect_idents_block(body, out);
        }
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            collect_idents_block(body, out);
            for (_, b) in else_ifs {
                collect_idents_block(b, out);
            }
            if let Some(b) = otherwise {
                collect_idents_block(b, out);
            }
        }
        _ => {}
    }
}
