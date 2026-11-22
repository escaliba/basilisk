use std::collections::{BTreeMap, BTreeSet};

use ir::{Block, Expr, Field, FuncBody, LastStmt, Module, Stmt};

pub const NATIVE_LEAF: &str = "BASIL_NATIVE_LEAF";
pub const PRIVATE_SCAN: &str = "BASIL_PRIVATE_SCAN";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OptIn {
    pub native_leaves: Vec<String>,

    pub scans: Vec<ScanRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanRequest {
    pub producer: String,
    pub scalar: String,
    pub matcher: String,
}

impl OptIn {
    pub fn is_empty(&self) -> bool {
        self.native_leaves.is_empty() && self.scans.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedScan {
    pub scalar: String,
    pub producer: u32,
    pub consumer: u32,
    pub matcher: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub scans: Vec<ResolvedScan>,

    pub leaves: Vec<(String, u32, Vec<String>)>,
}

pub fn extract(module: &mut Module) -> Result<OptIn, String> {
    let mut out = OptIn::default();
    scan(&module.block, &mut out)?;
    prune(&mut module.block);
    Ok(out)
}

fn scan(b: &Block, out: &mut OptIn) -> Result<(), String> {
    for s in &b.stmts {
        if let Some(names) = marker(s, NATIVE_LEAF)? {
            if names.len() != 1 {
                return Err(format!(
                    "{NATIVE_LEAF} takes exactly one function binding, got {}",
                    names.len()
                ));
            }
            out.native_leaves.push(names[0].clone());
            continue;
        }
        if let Some(names) = marker(s, PRIVATE_SCAN)? {
            if names.len() != 3 {
                return Err(format!(
                    "{PRIVATE_SCAN} takes exactly three names (producer, scalar, matcher), got {}",
                    names.len()
                ));
            }
            out.scans.push(ScanRequest {
                producer: names[0].clone(),
                scalar: names[1].clone(),
                matcher: names[2].clone(),
            });
            continue;
        }
        descend(s, out)?;
    }
    Ok(())
}

fn is_marker(s: &Stmt) -> bool {
    let Stmt::Call(Expr::Call { func, .. }) = s else {
        return false;
    };
    let Expr::Name(n) = func.as_ref() else {
        return false;
    };
    n == NATIVE_LEAF || n == PRIVATE_SCAN
}

fn prune(b: &mut Block) {
    b.stmts.retain(|s| !is_marker(s));
    for s in &mut b.stmts {
        match s {
            Stmt::Do(x) => prune(x),
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => prune(body),
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => prune(body),
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                prune(&mut body.block)
            }
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                prune(body);
                for (_, x) in else_ifs {
                    prune(x);
                }
                if let Some(x) = otherwise {
                    prune(x);
                }
            }
            _ => {}
        }
    }
}

fn marker(s: &Stmt, want: &str) -> Result<Option<Vec<String>>, String> {
    let Stmt::Call(Expr::Call { func, args, .. }) = s else {
        return Ok(None);
    };
    let Expr::Name(n) = func.as_ref() else {
        return Ok(None);
    };
    if n != want {
        return Ok(None);
    }
    let mut names = Vec::new();
    for a in args {
        match a {
            Expr::Name(x) => names.push(x.clone()),
            _ => {
                return Err(format!(
                    "{want} arguments must be bare function/variable names written directly in the call"
                ))
            }
        }
    }
    Ok(Some(names))
}

fn descend(s: &Stmt, out: &mut OptIn) -> Result<(), String> {
    match s {
        Stmt::Do(x) => scan(x, out),
        Stmt::While { body, .. } | Stmt::Repeat { body, .. } => scan(body, out),
        Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => scan(body, out),
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => scan(&body.block, out),
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            scan(body, out)?;
            for (_, x) in else_ifs {
                scan(x, out)?;
            }
            if let Some(x) = otherwise {
                scan(x, out)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn resolve(module: &Module, optin: &OptIn) -> Result<Resolved, String> {
    let binds = bindings(module);
    let mut resolved = Resolved::default();

    for req in &optin.scans {
        let producer = unique_binding(&binds, &req.producer, PRIVATE_SCAN)?;
        let matcher = unique_binding(&binds, &req.matcher, PRIVATE_SCAN)?;
        validate_native_leaf(module, &binds, &req.matcher, matcher)
            .map_err(|e| format!("{PRIVATE_SCAN} matcher `{}`: {e}", req.matcher))?;
        let consumer = validate_scan(module, req, producer, matcher)?;
        resolved.scans.push(ResolvedScan {
            scalar: req.scalar.clone(),
            producer,
            consumer,
            matcher,
        });
    }

    for name in &optin.native_leaves {
        let id = unique_binding(&binds, name, NATIVE_LEAF)?;
        let free = validate_native_leaf(module, &binds, name, id)
            .map_err(|e| format!("{NATIVE_LEAF} `{name}`: {e}"))?;
        resolved.leaves.push((name.clone(), id, free));
    }
    Ok(resolved)
}

fn unique_binding(binds: &Bindings, name: &str, marker: &str) -> Result<u32, String> {
    let bodies = binds
        .by_name
        .get(name)
        .ok_or_else(|| format!("{marker}: `{name}` does not resolve to a function binding"))?;
    if bodies.len() != 1 {
        return Err(format!(
            "{marker}: `{name}` is bound to a function {} times; it must resolve exactly once",
            bodies.len()
        ));
    }
    if binds.writes.get(name).copied().unwrap_or(0) > 1 {
        return Err(format!(
            "{marker}: `{name}` is reassigned after its definition, so the extracted body could be \
             replaced at runtime"
        ));
    }
    bodies[0]
        .stable_id
        .ok_or_else(|| format!("{marker}: `{name}` has no stable identity"))
}

pub fn validate_native_leaf(
    module: &Module,
    binds: &Bindings,
    name: &str,
    stable_id: u32,
) -> Result<Vec<String>, String> {
    let body = &binds.by_name[name][0];
    if body.params.iter().any(|p| matches!(p, ir::Param::Vararg)) {
        return Err(
            "the binding is variadic; a native body cannot reproduce the VM's vararg frame".into(),
        );
    }
    let free: BTreeSet<String> = crate::free_vars(body);
    let mut shape = Shape::new(name, &free);
    shape.block(&body.block);
    if shape.nested > 0 {
        return Err("the binding creates a nested closure".into());
    }
    if shape.opaque > 0 {
        return Err("the binding contains a native, encrypted, crash or guard node".into());
    }
    if shape.self_calls > 0 {
        return Err("the binding is directly recursive".into());
    }
    if shape.bad_writes > 0 {
        return Err(
            "the binding assigns to something other than its own locals; a native body must not \
             mutate shared state it cannot reach"
                .into(),
        );
    }
    crate::native_escape::check_leaf(module, stable_id).map_err(|e| e.to_string())?;
    if let Some(kind) = crate::audit::body_high_confidence_secret(body) {
        return Err(format!(
            "the binding contains a high-confidence secret literal ({kind}); a native body is \
             emitted as plaintext, so extracting it would publish that value"
        ));
    }
    Ok(free.into_iter().collect())
}

fn validate_scan(
    module: &Module,
    req: &ScanRequest,
    producer: u32,
    matcher: u32,
) -> Result<u32, String> {
    let census = crate::state_cell::audit(module, &req.scalar);
    if census.declarations != 1 {
        return Err(format!(
            "{PRIVATE_SCAN}: `{}` must be a chunk-level local with exactly one declaration, found {}",
            req.scalar, census.declarations
        ));
    }
    if !declared_at_chunk_level(&module.block, &req.scalar) {
        return Err(format!(
            "{PRIVATE_SCAN}: `{}` is not declared as a chunk-level local",
            req.scalar
        ));
    }

    let reads = census.reads.get(&Some(producer)).copied().unwrap_or(0);
    let writes = census.writes.get(&Some(producer)).copied().unwrap_or(0);
    if reads == 0 || writes == 0 {
        return Err(format!(
            "{PRIVATE_SCAN}: the producer must both read and write `{}` (reads {reads}, writes {writes})",
            req.scalar
        ));
    }

    let mut consumers: Vec<u32> = Vec::new();
    for owner in census.functions() {
        let Some(id) = owner else {
            return Err(format!(
                "{PRIVATE_SCAN}: `{}` is referenced outside any function body",
                req.scalar
            ));
        };
        if id == producer {
            continue;
        }
        if census.writes.get(&Some(id)).copied().unwrap_or(0) > 0 {
            return Err(format!(
                "{PRIVATE_SCAN}: `{}` is written by a function other than the producer",
                req.scalar
            ));
        }
        consumers.push(id);
    }
    if consumers.len() != 1 {
        return Err(format!(
            "{PRIVATE_SCAN}: exactly one read-only consumer of `{}` is required, found {}",
            req.scalar,
            consumers.len()
        ));
    }

    let pbody = find_body(module, producer)
        .ok_or_else(|| format!("{PRIVATE_SCAN}: producer {producer} is not resolvable"))?;

    if pbody.params.iter().any(|p| matches!(p, ir::Param::Vararg)) {
        return Err(format!(
            "{PRIVATE_SCAN}: the producer is variadic; the wrapper rebuilds arguments from named \
             parameters and would drop `...`"
        ));
    }
    let mut flow = Flow {
        scalar: &req.scalar,
        matcher: &req.matcher,
        loop_depth: 0,
        cond_depth: 0,
        writes_total: 0,
        writes_in_loop: 0,
        writes_matcher_controlled: 0,
        resets_before_loop: 0,
        seen_loop: false,
    };
    flow.block(&pbody.block);
    if flow.writes_total == 0 {
        return Err(format!(
            "{PRIVATE_SCAN}: the producer does not write `{}`",
            req.scalar
        ));
    }

    let accounted = flow.writes_in_loop + flow.resets_before_loop;
    if accounted != flow.writes_total {
        return Err(format!(
            "{PRIVATE_SCAN}: {} of {} producer writes to `{}` occur outside the scan loop and are \
             not literal resets preceding it",
            flow.writes_total - accounted,
            flow.writes_total,
            req.scalar
        ));
    }
    if flow.writes_in_loop == 0 {
        return Err(format!(
            "{PRIVATE_SCAN}: the producer never writes `{}` inside a loop",
            req.scalar
        ));
    }
    if flow.writes_matcher_controlled == 0 {
        return Err(format!(
            "{PRIVATE_SCAN}: no write to `{}` is control-dependent on a `{}` result; the marked \
             matcher does not select the scanned value",
            req.scalar, req.matcher
        ));
    }
    let _ = matcher;
    Ok(consumers[0])
}

fn declared_at_chunk_level(b: &Block, name: &str) -> bool {
    b.stmts
        .iter()
        .any(|s| matches!(s, Stmt::Local { names, .. } if names.iter().any(|n| n == name)))
}

fn find_body(module: &Module, want: u32) -> Option<FuncBody> {
    fn blk(b: &Block, want: u32, out: &mut Option<FuncBody>) {
        for s in &b.stmts {
            st(s, want, out);
        }
        if let Some(LastStmt::Return(es)) = &b.last {
            for e in es {
                ex(e, want, out);
            }
        }
    }
    fn take(f: &FuncBody, want: u32, out: &mut Option<FuncBody>) {
        if f.stable_id == Some(want) && out.is_none() {
            *out = Some(f.clone());
        }
        blk(&f.block, want, out);
    }
    fn st(s: &Stmt, want: u32, out: &mut Option<FuncBody>) {
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => take(body, want, out),
            Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| ex(e, want, out)),
            Stmt::Assign { targets, exprs } => {
                targets.iter().for_each(|e| ex(e, want, out));
                exprs.iter().for_each(|e| ex(e, want, out));
            }
            Stmt::Compound { target, value, .. } => {
                ex(target, want, out);
                ex(value, want, out);
            }
            Stmt::Call(e) => ex(e, want, out),
            Stmt::Do(x) => blk(x, want, out),
            Stmt::While { cond, body } => {
                ex(cond, want, out);
                blk(body, want, out);
            }
            Stmt::Repeat { body, until } => {
                blk(body, want, out);
                ex(until, want, out);
            }
            Stmt::NumericFor {
                start,
                end,
                step,
                body,
                ..
            } => {
                ex(start, want, out);
                ex(end, want, out);
                if let Some(x) = step {
                    ex(x, want, out);
                }
                blk(body, want, out);
            }
            Stmt::GenericFor { exprs, body, .. } => {
                exprs.iter().for_each(|e| ex(e, want, out));
                blk(body, want, out);
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                ex(cond, want, out);
                blk(body, want, out);
                for (c, x) in else_ifs {
                    ex(c, want, out);
                    blk(x, want, out);
                }
                if let Some(x) = otherwise {
                    blk(x, want, out);
                }
            }
        }
    }
    fn ex(e: &Expr, want: u32, out: &mut Option<FuncBody>) {
        match e {
            Expr::Function(f) => take(f, want, out),
            Expr::Field { base, .. } | Expr::Paren(base) | Expr::Unop { expr: base, .. } => {
                ex(base, want, out)
            }
            Expr::Index { base, key } => {
                ex(base, want, out);
                ex(key, want, out);
            }
            Expr::Call { func, args, .. } => {
                ex(func, want, out);
                args.iter().for_each(|a| ex(a, want, out));
            }
            Expr::MethodCall { base, args, .. } => {
                ex(base, want, out);
                args.iter().for_each(|a| ex(a, want, out));
            }
            Expr::Table(fs) => {
                for f in fs {
                    match f {
                        Field::Positional(v) => ex(v, want, out),
                        Field::Named { value, .. } => ex(value, want, out),
                        Field::Keyed { key, value } => {
                            ex(key, want, out);
                            ex(value, want, out);
                        }
                    }
                }
            }
            Expr::Binop { lhs, rhs, .. } => {
                ex(lhs, want, out);
                ex(rhs, want, out);
            }
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                ex(cond, want, out);
                ex(then, want, out);
                for (c, v) in else_ifs {
                    ex(c, want, out);
                    ex(v, want, out);
                }
                ex(otherwise, want, out);
            }
            other => other.each_child(&mut |c| ex(c, want, out)),
        }
    }
    let mut out = None;
    blk(&module.block, want, &mut out);
    out
}

struct Flow<'a> {
    scalar: &'a str,
    matcher: &'a str,
    loop_depth: usize,
    cond_depth: usize,
    writes_total: usize,
    writes_in_loop: usize,
    writes_matcher_controlled: usize,

    resets_before_loop: usize,
    seen_loop: bool,
}

impl Flow<'_> {
    fn note_write(&mut self, value: Option<&Expr>) {
        self.writes_total += 1;
        if self.loop_depth > 0 {
            self.writes_in_loop += 1;
            if self.cond_depth > 0 {
                self.writes_matcher_controlled += 1;
            }
            return;
        }
        let literal = matches!(
            value,
            Some(Expr::Nil | Expr::True | Expr::False | Expr::Number(_) | Expr::Str(_))
        );
        if literal && !self.seen_loop {
            self.resets_before_loop += 1;
        }
    }

    fn calls_matcher(&self, e: &Expr) -> bool {
        let mut hit = false;
        scan_calls(e, &mut |n| {
            if n == self.matcher {
                hit = true;
            }
        });
        hit
    }

    fn block(&mut self, b: &Block) {
        for s in &b.stmts {
            self.stmt(s);
        }
    }

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Assign { targets, exprs } => {
                for (i, t) in targets.iter().enumerate() {
                    if matches!(t, Expr::Name(n) if n == self.scalar) {
                        self.note_write(exprs.get(i));
                    }
                }
            }
            Stmt::Compound { target, .. } => {
                if matches!(target, Expr::Name(n) if n == self.scalar) {
                    self.note_write(None);
                }
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                let gated = self.calls_matcher(cond);
                if gated {
                    self.cond_depth += 1;
                }
                self.block(body);
                if gated {
                    self.cond_depth -= 1;
                }
                for (c, x) in else_ifs {
                    let g = self.calls_matcher(c);
                    if g {
                        self.cond_depth += 1;
                    }
                    self.block(x);
                    if g {
                        self.cond_depth -= 1;
                    }
                }
                if let Some(x) = otherwise {
                    self.block(x);
                }
            }
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => {
                self.loop_depth += 1;
                self.block(body);
                self.loop_depth -= 1;
                self.seen_loop = true;
            }
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => {
                self.loop_depth += 1;
                self.block(body);
                self.loop_depth -= 1;
                self.seen_loop = true;
            }
            Stmt::Do(x) => self.block(x),
            _ => {}
        }
    }
}

fn scan_calls(e: &Expr, f: &mut impl FnMut(&str)) {
    match e {
        Expr::Call { func, args, .. } => {
            if let Expr::Name(n) = func.as_ref() {
                f(n);
            }
            scan_calls(func, f);
            args.iter().for_each(|a| scan_calls(a, f));
        }
        Expr::MethodCall { base, args, .. } => {
            scan_calls(base, f);
            args.iter().for_each(|a| scan_calls(a, f));
        }
        Expr::Field { base, .. } | Expr::Paren(base) | Expr::Unop { expr: base, .. } => {
            scan_calls(base, f)
        }
        Expr::Index { base, key } => {
            scan_calls(base, f);
            scan_calls(key, f);
        }
        Expr::Binop { lhs, rhs, .. } => {
            scan_calls(lhs, f);
            scan_calls(rhs, f);
        }
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            scan_calls(cond, f);
            scan_calls(then, f);
            for (c, v) in else_ifs {
                scan_calls(c, f);
                scan_calls(v, f);
            }
            scan_calls(otherwise, f);
        }
        other => other.each_child(&mut |c| scan_calls(c, f)),
    }
}

pub struct Bindings {
    pub by_name: BTreeMap<String, Vec<FuncBody>>,
    pub writes: BTreeMap<String, usize>,
}

pub fn bindings(module: &Module) -> Bindings {
    let mut b = Bindings {
        by_name: BTreeMap::new(),
        writes: BTreeMap::new(),
    };
    fn walk(blk: &Block, b: &mut Bindings) {
        for s in &blk.stmts {
            match s {
                Stmt::Function { name, body } if name.method.is_none() && name.path.len() == 1 => {
                    b.by_name
                        .entry(name.path[0].clone())
                        .or_default()
                        .push(body.clone());
                    *b.writes.entry(name.path[0].clone()).or_insert(0) += 1;
                    walk(&body.block, b);
                }
                Stmt::LocalFunction { name, body } => {
                    b.by_name
                        .entry(name.clone())
                        .or_default()
                        .push(body.clone());
                    *b.writes.entry(name.clone()).or_insert(0) += 1;
                    walk(&body.block, b);
                }
                Stmt::Local { names, exprs } => {
                    for (i, e) in exprs.iter().enumerate() {
                        if let (Some(n), Expr::Function(f)) = (names.get(i), e) {
                            b.by_name.entry(n.clone()).or_default().push(f.clone());
                            *b.writes.entry(n.clone()).or_insert(0) += 1;
                            walk(&f.block, b);
                        }
                    }
                }
                Stmt::Assign { targets, exprs } => {
                    for (i, t) in targets.iter().enumerate() {
                        if let Expr::Name(n) = t {
                            *b.writes.entry(n.clone()).or_insert(0) += 1;
                            if let Some(Expr::Function(f)) = exprs.get(i) {
                                b.by_name.entry(n.clone()).or_default().push(f.clone());
                                walk(&f.block, b);
                            }
                        }
                    }
                }
                Stmt::Do(x) => walk(x, b),
                Stmt::While { body, .. } | Stmt::Repeat { body, .. } => walk(body, b),
                Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => walk(body, b),
                Stmt::If {
                    body,
                    else_ifs,
                    otherwise,
                    ..
                } => {
                    walk(body, b);
                    for (_, x) in else_ifs {
                        walk(x, b);
                    }
                    if let Some(x) = otherwise {
                        walk(x, b);
                    }
                }
                _ => {}
            }
        }
    }
    walk(&module.block, &mut b);
    b
}

struct Shape<'a> {
    target: &'a str,
    free: &'a BTreeSet<String>,
    nested: usize,
    opaque: usize,
    self_calls: usize,
    bad_writes: usize,
}

impl<'a> Shape<'a> {
    fn new(target: &'a str, free: &'a BTreeSet<String>) -> Self {
        Shape {
            target,
            free,
            nested: 0,
            opaque: 0,
            self_calls: 0,
            bad_writes: 0,
        }
    }

    fn check_target(&mut self, t: &Expr) {
        match t {
            Expr::Name(n) if !self.free.contains(n) => {}
            _ => self.bad_writes += 1,
        }
    }

    fn block(&mut self, b: &Block) {
        for s in &b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &b.last {
            for e in es {
                self.expr(e);
            }
        }
    }

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                self.nested += 1;
                self.block(&body.block);
            }
            Stmt::Assign { targets, exprs } => {
                targets.iter().for_each(|t| self.check_target(t));
                exprs.iter().for_each(|e| self.expr(e));
            }
            Stmt::Compound { target, value, .. } => {
                self.check_target(target);
                self.expr(value);
            }
            Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| self.expr(e)),
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
                start,
                end,
                step,
                body,
                ..
            } => {
                self.expr(start);
                self.expr(end);
                if let Some(x) = step {
                    self.expr(x);
                }
                self.block(body);
            }
            Stmt::GenericFor { exprs, body, .. } => {
                exprs.iter().for_each(|e| self.expr(e));
                self.block(body);
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
            Expr::Function(f) => {
                self.nested += 1;
                self.block(&f.block);
            }
            Expr::NativeRef(_) | Expr::EncFunc { .. } | Expr::Crash => self.opaque += 1,
            Expr::Call { func, args, .. } => {
                if matches!(func.as_ref(), Expr::Name(n) if n == self.target) {
                    self.self_calls += 1;
                }
                self.expr(func);
                args.iter().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter().for_each(|a| self.expr(a));
            }
            Expr::Field { base, .. } | Expr::Paren(base) | Expr::Unop { expr: base, .. } => {
                self.expr(base)
            }
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
            other => other.each_child(&mut |c| self.expr(c)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(src: &'static str) -> Module {
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(move || crate::lower_str(src).unwrap())
            .expect("spawn")
            .join()
            .expect("parse")
    }

    fn ids(m: &mut Module) {
        let mut n = 1u32;
        fn blk(b: &mut Block, n: &mut u32) {
            for s in &mut b.stmts {
                match s {
                    Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                        body.stable_id = Some(*n);
                        *n += 1;
                        blk(&mut body.block, n);
                    }
                    Stmt::Assign { exprs, .. } | Stmt::Local { exprs, .. } => {
                        for e in exprs {
                            if let Expr::Function(f) = e {
                                f.stable_id = Some(*n);
                                *n += 1;
                                blk(&mut f.block, n);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        blk(&mut m.block, &mut n);
    }

    fn prep(src: &'static str) -> (Module, OptIn) {
        let mut m = lower(src);
        let o = extract(&mut m).expect("markers strip");
        ids(&mut m);
        (m, o)
    }

    const SHAPE: &str = "local top = nil\n\
                         Pred = function(a, b) return a:lower():find(b:lower()) and true end\n\
                         Prod = function(q, flag)\n\
                         \ttop = nil\n\
                         \tfor i, v in next, List() do\n\
                         \t\tif flag then\n\
                         \t\t\tif Pred(v.Text, q) then\n\
                         \t\t\t\tif top == nil then top = v.Text end\n\
                         \t\t\tend\n\
                         \t\telse\n\
                         \t\t\tif top == nil then top = v.Text end\n\
                         \t\tend\n\
                         \tend\n\
                         end\n\
                         BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                         Cons = function()\n\
                         \tif top ~= nil then Complete(top) end\n\
                         end\n\
                         Other = function(t, v)\n\
                         \tfor _, x in pairs(t) do if x == v then return true end end\n\
                         \treturn false\n\
                         end\n\
                         BASIL_NATIVE_LEAF(Other)\n\
                         return Prod, Cons\n";

    #[test]
    fn markers_are_stripped_and_recorded() {
        let (m, o) = prep(SHAPE);
        assert_eq!(o.native_leaves, vec!["Other".to_string()]);
        assert_eq!(o.scans.len(), 1);
        assert_eq!(o.scans[0].producer, "Prod");
        assert_eq!(o.scans[0].scalar, "top");
        assert_eq!(o.scans[0].matcher, "Pred");
        let out = ir::emit(&m);
        assert!(
            !out.contains("BASIL_"),
            "no marker survives into the IR: {out}"
        );
    }

    #[test]
    fn stripping_leaves_the_ir_identical_to_the_unannotated_twin() {
        let (annotated, _) = prep(SHAPE);
        let plain = SHAPE
            .replace(
                "BASIL_PRIVATE_SCAN(Prod, top, Pred)\\n\\\n                         ",
                "",
            )
            .replace(
                "BASIL_NATIVE_LEAF(Other)\\n\\\n                         ",
                "",
            );
        let _ = plain;

        let mut twin = lower(
            "local top = nil\n\
                             Pred = function(a, b) return a:lower():find(b:lower()) and true end\n\
                             Prod = function(q, flag)\n\
                             \ttop = nil\n\
                             \tfor i, v in next, List() do\n\
                             \t\tif flag then\n\
                             \t\t\tif Pred(v.Text, q) then\n\
                             \t\t\t\tif top == nil then top = v.Text end\n\
                             \t\t\tend\n\
                             \t\telse\n\
                             \t\t\tif top == nil then top = v.Text end\n\
                             \t\tend\n\
                             \tend\n\
                             end\n\
                             Cons = function()\n\
                             \tif top ~= nil then Complete(top) end\n\
                             end\n\
                             Other = function(t, v)\n\
                             \tfor _, x in pairs(t) do if x == v then return true end end\n\
                             \treturn false\n\
                             end\n\
                             return Prod, Cons\n",
        );
        ids(&mut twin);
        assert_eq!(
            ir::emit(&annotated),
            ir::emit(&twin),
            "markers must lower to nothing"
        );
    }

    #[test]
    fn it_resolves_the_real_topology_including_a_non_matcher_write() {
        let (m, o) = prep(SHAPE);
        let r = resolve(&m, &o).expect("resolves");
        assert_eq!(r.scans.len(), 1);
        assert_eq!(r.leaves.len(), 1, "only the marked leaf");
        assert_eq!(r.leaves[0].0, "Other");
        assert_ne!(r.scans[0].producer, r.scans[0].consumer);
    }

    #[test]
    fn only_the_marked_helper_is_extracted_when_two_are_eligible() {
        let src = "local top = nil\n\
                   Pred = function(a, b) return a == b end\n\
                   Prod = function(q)\n\
                   \ttop = nil\n\
                   \tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\n\
                   end\n\
                   BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                   Cons = function() return top end\n\
                   Other = function(t, v) for _, x in pairs(t) do if x == v then return true end end return false end\n\
                   Second = function(t, v) for _, x in pairs(t) do if x == v then return true end end return false end\n\
                   BASIL_NATIVE_LEAF(Other)\n\
                   return Prod, Cons, Second\n";
        let (m, o) = prep(src);
        let r = resolve(&m, &o).expect("resolves");
        let names: Vec<&str> = r.leaves.iter().map(|l| l.0.as_str()).collect();
        assert_eq!(
            names,
            vec!["Other"],
            "an equally eligible unmarked helper stays virtualized"
        );
    }

    fn err_for(src: &'static str) -> String {
        let (m, o) = prep(src);
        resolve(&m, &o).unwrap_err()
    }

    #[test]
    fn an_unresolved_marker_fails_closed() {
        let e = err_for("BASIL_NATIVE_LEAF(Nope)\nreturn 1\n");
        assert!(e.contains("does not resolve"), "{e}");
    }

    #[test]
    fn a_malformed_marker_fails_closed() {
        let mut m = lower("BASIL_NATIVE_LEAF(\"Match\")\nreturn 1\n");
        let e = extract(&mut m).unwrap_err();
        assert!(e.contains("bare function/variable names"), "{e}");
    }

    #[test]
    fn a_reassigned_binding_fails_closed() {
        let e =
            err_for("H = function(a) return a end\nBASIL_NATIVE_LEAF(H)\nH = print\nreturn 1\n");
        assert!(e.contains("reassigned"), "{e}");
    }

    #[test]
    fn a_variadic_binding_fails_closed() {
        let e = err_for(
            "H = function(...) return select(\"#\", ...) end\nBASIL_NATIVE_LEAF(H)\nreturn 1\n",
        );
        assert!(e.contains("variadic"), "{e}");
    }

    #[test]
    fn a_capturing_binding_fails_closed() {
        let e = err_for("local hidden = 1\nH = function(a) return a + hidden end\nBASIL_NATIVE_LEAF(H)\nreturn 1\n");
        assert!(e.contains("captures enclosing local"), "{e}");
    }

    #[test]
    fn a_binding_writing_shared_state_fails_closed() {
        let e = err_for("Counter = 0\nH = function(a) Counter = a return true end\nBASIL_NATIVE_LEAF(H)\nreturn 1\n");
        assert!(e.contains("other than its own locals"), "{e}");
    }

    #[test]
    fn a_recursive_binding_fails_closed() {
        let e = err_for("H = function(a) if a > 0 then return H(a-1) end return 0 end\nBASIL_NATIVE_LEAF(H)\nreturn 1\n");
        assert!(e.contains("recursive"), "{e}");
    }

    #[test]
    fn a_nested_closure_fails_closed() {
        let e = err_for(
            "H = function(a) return function() return a end end\nBASIL_NATIVE_LEAF(H)\nreturn 1\n",
        );
        assert!(e.contains("nested closure"), "{e}");
    }

    #[test]
    fn a_scalar_with_three_owners_fails_closed() {
        let e = err_for("local top = nil\n\
                         Pred = function(a, b) return a == b end\n\
                         Prod = function(q)\n\ttop = nil\n\tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\nend\n\
                         BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                         A = function() return top end\n\
                         B = function() return top end\n\
                         return Prod\n");
        assert!(e.contains("exactly one read-only consumer"), "{e}");
    }

    #[test]
    fn a_consumer_that_writes_the_scalar_fails_closed() {
        let e = err_for("local top = nil\n\
                         Pred = function(a, b) return a == b end\n\
                         Prod = function(q)\n\ttop = nil\n\tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\nend\n\
                         BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                         Cons = function() top = 1 return top end\n\
                         return Prod\n");
        assert!(
            e.contains("written by a function other than the producer"),
            "{e}"
        );
    }

    #[test]
    fn a_non_reset_write_outside_the_loop_fails_closed() {
        let e = err_for("local top = nil\n\
                         Pred = function(a, b) return a == b end\n\
                         Prod = function(q)\n\
                         \ttop = nil\n\
                         \tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\n\
                         \ttop = Compute()\n\
                         end\n\
                         BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                         Cons = function() return top end\n\
                         return Prod\n");
        assert!(e.contains("not literal resets preceding it"), "{e}");
    }

    #[test]
    fn a_scan_whose_matcher_does_not_gate_the_write_fails_closed() {
        let e = err_for("local top = nil\n\
                         Pred = function(a, b) return a == b end\n\
                         Prod = function(q)\n\
                         \ttop = nil\n\
                         \tfor i, v in next, List() do Pred(v, q) if top == nil then top = v end end\n\
                         end\n\
                         BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                         Cons = function() return top end\n\
                         return Prod\n");
        assert!(e.contains("control-dependent"), "{e}");
    }

    #[test]
    fn a_variadic_producer_fails_closed() {
        let e = err_for("local top = nil\n\
                         Pred = function(a, b) return a == b end\n\
                         Prod = function(q, ...)\n\ttop = nil\n\tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\nend\n\
                         BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                         Cons = function() return top end\n\
                         return Prod\n");
        assert!(e.contains("variadic"), "{e}");
    }

    #[test]
    fn admission_is_structural_not_nominal() {
        let (m, o) = prep(SHAPE);
        let a = resolve(&m, &o).expect("resolves");
        let renamed = SHAPE
            .replace("Pred", "Zq7")
            .replace("Prod", "Wp2")
            .replace("Cons", "Kx4")
            .replace("top", "s9");
        let leaked: &'static str = Box::leak(renamed.into_boxed_str());
        let (m2, o2) = prep(leaked);
        let b = resolve(&m2, &o2).expect("renamed clone resolves identically");
        assert_eq!(a.scans.len(), b.scans.len());
        assert_eq!(a.leaves.len(), b.leaves.len());
        assert_eq!(a.scans[0].producer, b.scans[0].producer);
    }

    #[test]
    fn a_literal_reset_before_the_loop_is_accepted() {
        let (m, o) = prep("local top = nil\n\
                           Pred = function(a, b) return a == b end\n\
                           Prod = function(q)\n\
                           \ttop = nil\n\
                           \tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\n\
                           end\n\
                           BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                           Cons = function() return top end\n\
                           return Prod\n");
        let r = resolve(&m, &o).expect("a literal pre-loop reset is an accumulator initialisation");
        assert_eq!(r.scans.len(), 1);
        assert_eq!(r.scans[0].scalar, "top");
    }

    #[test]
    fn a_computed_write_before_the_loop_fails_closed() {
        let e = err_for("local top = nil\n\
                         Pred = function(a, b) return a == b end\n\
                         Prod = function(q)\n\
                         \ttop = Compute()\n\
                         \tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\n\
                         end\n\
                         BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                         Cons = function() return top end\n\
                         return Prod\n");
        assert!(e.contains("not literal resets preceding it"), "{e}");
    }

    #[test]
    fn a_malformed_marker_leaves_the_module_unmutated() {
        let src = "local top = nil\n\
                   Other = function(t, v) for _, x in pairs(t) do if x == v then return true end end return false end\n\
                   BASIL_NATIVE_LEAF(\"Other\")\n\
                   return Other\n";
        let mut m = lower(src);
        let before = ir::emit(&m);
        let natives_before = m.natives.len();
        let e = extract(&mut m).expect_err("a string argument is not a bare name");
        assert!(e.contains("bare function/variable names"), "{e}");
        assert_eq!(
            ir::emit(&m),
            before,
            "a rejected marker must not mutate the module"
        );
        assert_eq!(m.natives.len(), natives_before);
    }

    #[test]
    fn markers_do_not_perturb_stable_ids_or_the_macro_rng() {
        const TWIN: &str = "local top = nil\n\
                            local seedcheck = BASIL_HASH(\"promotion-probe\")\n\
                            Pred = function(a, b) return a == b end\n\
                            Prod = function(q)\n\
                            \ttop = nil\n\
                            \tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\n\
                            end\n\
                            Cons = function() return top end\n\
                            return Prod, seedcheck\n";
        const MARKED: &str = "local top = nil\n\
                              local seedcheck = BASIL_HASH(\"promotion-probe\")\n\
                              Pred = function(a, b) return a == b end\n\
                              Prod = function(q)\n\
                              \ttop = nil\n\
                              \tfor i, v in next, List() do if Pred(v, q) then if top == nil then top = v end end end\n\
                              end\n\
                              BASIL_PRIVATE_SCAN(Prod, top, Pred)\n\
                              Cons = function() return top end\n\
                              return Prod, seedcheck\n";

        let mut plain = lower(TWIN);
        let mut marked = lower(MARKED);
        extract(&mut marked).expect("markers strip");
        ids(&mut plain);
        ids(&mut marked);

        let map = |m: &Module| {
            let mut v: Vec<(u32, String)> = Vec::new();
            fn blk(b: &Block, v: &mut Vec<(u32, String)>) {
                for s in &b.stmts {
                    match s {
                        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                            v.push((body.stable_id.unwrap(), format!("{:?}", body.block)));
                            blk(&body.block, v);
                        }
                        Stmt::Assign { exprs, .. } | Stmt::Local { exprs, .. } => {
                            for e in exprs {
                                if let Expr::Function(f) = e {
                                    v.push((f.stable_id.unwrap(), format!("{:?}", f.block)));
                                    blk(&f.block, v);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            blk(&m.block, &mut v);
            v
        };
        assert_eq!(
            map(&plain),
            map(&marked),
            "a marker must not shift stable-id assignment"
        );

        let seed = 0x5EED_1234_ABCD_9876u64;
        let a = ir::emit(&crate::macros::expand(plain, seed).expect("expand twin"));
        let b = ir::emit(&crate::macros::expand(marked, seed).expect("expand marked"));
        assert_eq!(a, b, "a marker must not advance the macro RNG");
    }
}
