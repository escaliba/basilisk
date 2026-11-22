use std::collections::BTreeMap;

use ir::{Block, Expr, Field, FuncBody, LastStmt, Module, Stmt};

#[derive(Debug, Default, Clone)]
pub struct Census {
    pub declarations: usize,
    pub reads: BTreeMap<Option<u32>, usize>,
    pub writes: BTreeMap<Option<u32>, usize>,
}

impl Census {
    pub fn total_refs(&self) -> usize {
        self.reads.values().sum::<usize>() + self.writes.values().sum::<usize>()
    }
    pub fn functions(&self) -> Vec<Option<u32>> {
        let mut v: Vec<Option<u32>> = self
            .reads
            .keys()
            .chain(self.writes.keys())
            .cloned()
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

pub fn audit(module: &Module, name: &str) -> Census {
    let mut c = Census::default();
    let mut w = Walk {
        name,
        owner: None,
        census: &mut c,
    };
    w.block(&module.block);
    c
}

struct Walk<'a> {
    name: &'a str,
    owner: Option<u32>,
    census: &'a mut Census,
}

impl Walk<'_> {
    fn is_it(&self, e: &Expr) -> bool {
        matches!(e, Expr::Name(n) if n == self.name)
    }

    fn read(&mut self) {
        *self.census.reads.entry(self.owner).or_insert(0) += 1;
    }

    fn write(&mut self) {
        *self.census.writes.entry(self.owner).or_insert(0) += 1;
    }

    fn func(&mut self, f: &FuncBody) {
        let prev = self.owner;
        self.owner = f.stable_id;
        self.block(&f.block);
        self.owner = prev;
    }

    fn block(&mut self, b: &Block) {
        for s in &b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &b.last {
            es.iter().for_each(|e| self.expr(e));
        }
    }

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Local { names, exprs } => {
                if names.iter().any(|n| n == self.name) {
                    self.census.declarations += 1;
                }
                exprs.iter().for_each(|e| self.expr(e));
            }
            Stmt::Assign { targets, exprs } => {
                for t in targets {
                    if self.is_it(t) {
                        self.write();
                    } else {
                        self.expr(t);
                    }
                }
                exprs.iter().for_each(|e| self.expr(e));
            }
            Stmt::Compound { target, value, .. } => {
                if self.is_it(target) {
                    self.write();
                    self.read();
                } else {
                    self.expr(target);
                }
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
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => self.func(body),
        }
    }

    fn expr(&mut self, e: &Expr) {
        if self.is_it(e) {
            self.read();
            return;
        }
        match e {
            Expr::Function(f) => self.func(f),
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

pub const CELL_NAME: &str = "_basil_topcmd_cell";
pub const CELL_PARAM: &str = "_basil_cell";

#[derive(Debug)]
pub struct Applied {
    pub before: Census,
    pub after: Census,
    pub native_index: u32,
    pub helper_free_vars: Vec<String>,
}

pub fn extract_global_native(
    module: &mut Module,
    stable_id: u32,
) -> Result<(u32, Vec<String>), String> {
    let mut g = GlobalNative {
        want: stable_id,
        taken: None,
        hits: 0,
    };
    g.block(&mut module.block);
    if g.hits != 1 {
        return Err(format!(
            "native extraction: stable id {stable_id} matched {} times, expected 1",
            g.hits
        ));
    }
    let body = g
        .taken
        .ok_or_else(|| format!("native extraction: stable id {stable_id} not extracted"))?;
    let free: Vec<String> = crate::free_vars(&body).into_iter().collect();
    module.natives.push(body);
    let idx = (module.natives.len() - 1) as u32;
    let mut b = BindGlobal {
        want: stable_id,
        idx,
        done: false,
    };
    b.block(&mut module.block);
    if !b.done {
        return Err(format!(
            "native extraction: stable id {stable_id} binding not replaced"
        ));
    }
    Ok((idx, free))
}

struct GlobalNative {
    want: u32,
    taken: Option<FuncBody>,
    hits: usize,
}

impl GlobalNative {
    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            if let Stmt::Assign { exprs, .. } = s {
                for e in exprs.iter_mut() {
                    if let Expr::Function(f) = e {
                        if f.stable_id == Some(self.want) {
                            self.hits += 1;
                            self.taken = Some(f.clone());
                            continue;
                        }
                        self.block(&mut f.block);
                    }
                }
                continue;
            }
            self.stmt(s);
        }
    }
    fn stmt(&mut self, s: &mut Stmt) {
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                self.block(&mut body.block)
            }
            Stmt::Local { exprs, .. } => {
                for e in exprs.iter_mut() {
                    if let Expr::Function(f) = e {
                        self.block(&mut f.block);
                    }
                }
            }
            Stmt::Do(x) => self.block(x),
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => self.block(body),
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => self.block(body),
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                self.block(body);
                for (_, x) in else_ifs {
                    self.block(x);
                }
                if let Some(x) = otherwise {
                    self.block(x);
                }
            }
            _ => {}
        }
    }
}

struct BindGlobal {
    want: u32,
    idx: u32,
    done: bool,
}

impl BindGlobal {
    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            if let Stmt::Assign { exprs, .. } = s {
                for e in exprs.iter_mut() {
                    let hit = matches!(e, Expr::Function(f) if f.stable_id == Some(self.want));
                    if hit {
                        *e = Expr::NativeRef(self.idx);
                        self.done = true;
                    } else if let Expr::Function(f) = e {
                        self.block(&mut f.block);
                    }
                }
                continue;
            }
            match s {
                Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                    self.block(&mut body.block)
                }
                Stmt::Local { exprs, .. } => {
                    for e in exprs.iter_mut() {
                        if let Expr::Function(f) = e {
                            self.block(&mut f.block);
                        }
                    }
                }
                Stmt::Do(x) => self.block(x),
                Stmt::While { body, .. } | Stmt::Repeat { body, .. } => self.block(body),
                Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => self.block(body),
                Stmt::If {
                    body,
                    else_ifs,
                    otherwise,
                    ..
                } => {
                    self.block(body);
                    for (_, x) in else_ifs {
                        self.block(x);
                    }
                    if let Some(x) = otherwise {
                        self.block(x);
                    }
                }
                _ => {}
            }
        }
    }
}

pub fn apply(
    module: &mut Module,
    scalar: &str,
    owners: &[u32],
    container: u32,
) -> Result<Applied, String> {
    let before = audit(module, scalar);
    if before.declarations != 1 {
        return Err(format!(
            "state cell: expected exactly one `{scalar}` declaration, found {}",
            before.declarations
        ));
    }
    let mut found = before.functions();
    found.retain(|f| f.is_some());
    let mut want: Vec<Option<u32>> = owners.iter().map(|o| Some(*o)).collect();
    want.sort();
    if found != want {
        return Err(format!(
            "state cell: `{scalar}` owners changed: expected {want:?}, found {found:?}"
        ));
    }

    let sel =
        crate::native_escape::inspect(module, container).map_err(|e| format!("state cell: {e}"))?;
    let stray: Vec<&str> = sel
        .captured_locals
        .iter()
        .filter(|n| n.as_str() != scalar)
        .map(|s| s.as_str())
        .collect();
    if !stray.is_empty() {
        return Err(format!(
            "state cell: producer {container} captures enclosing local(s) {} besides `{scalar}`; \
             the extracted native body cannot reach them",
            stray.join(", ")
        ));
    }

    let producer_params = find_params(module, container)
        .ok_or_else(|| format!("state cell: producer {container} is not resolvable"))?;
    if producer_params
        .iter()
        .any(|p| matches!(p, ir::Param::Vararg))
    {
        return Err(format!(
            "state cell: producer {container} is variadic; the wrapper rebuilds arguments from \
             named parameters and would drop `...`"
        ));
    }

    let mut r = Rewrite {
        scalar,
        cell: CELL_NAME,
        decl: 0,
    };
    r.block(&mut module.block);
    if r.decl != 1 {
        return Err(format!(
            "state cell: rewrote {} declarations, expected 1",
            r.decl
        ));
    }

    let after = audit(module, scalar);
    if after.total_refs() != 0 || after.declarations != 0 {
        return Err(format!(
            "state cell: {} scalar references survived the rewrite",
            after.total_refs() + after.declarations
        ));
    }

    let mut split = Split {
        container,
        cell: CELL_NAME,
        param: CELL_PARAM,
        taken: None,
        hits: 0,
    };
    split.block(&mut module.block);
    if split.hits != 1 {
        return Err(format!(
            "state cell: container {container} matched {} times, expected 1",
            split.hits
        ));
    }
    let helper = split
        .taken
        .ok_or("state cell: container body was not extracted")?;

    let free: Vec<String> = crate::free_vars(&helper).into_iter().collect();
    module.natives.push(helper);
    let idx = (module.natives.len() - 1) as u32;

    let mut bind = BindWrapper {
        container,
        cell: CELL_NAME,
        idx,
        done: false,
    };
    bind.block(&mut module.block);
    if !bind.done {
        return Err("state cell: wrapper was not bound to the native helper".into());
    }

    Ok(Applied {
        before,
        after: audit(module, CELL_NAME),
        native_index: idx,
        helper_free_vars: free,
    })
}

fn find_params(module: &Module, want: u32) -> Option<Vec<ir::Param>> {
    fn walk(b: &Block, want: u32, out: &mut Option<Vec<ir::Param>>) {
        for s in &b.stmts {
            walk_stmt(s, want, out);
        }
        if let Some(LastStmt::Return(es)) = &b.last {
            for e in es {
                walk_expr(e, want, out);
            }
        }
    }
    fn take(f: &FuncBody, want: u32, out: &mut Option<Vec<ir::Param>>) {
        if f.stable_id == Some(want) && out.is_none() {
            *out = Some(f.params.clone());
        }
        walk(&f.block, want, out);
    }
    fn walk_stmt(s: &Stmt, want: u32, out: &mut Option<Vec<ir::Param>>) {
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => take(body, want, out),
            Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| walk_expr(e, want, out)),
            Stmt::Assign { targets, exprs } => {
                targets.iter().for_each(|e| walk_expr(e, want, out));
                exprs.iter().for_each(|e| walk_expr(e, want, out));
            }
            Stmt::Compound { target, value, .. } => {
                walk_expr(target, want, out);
                walk_expr(value, want, out);
            }
            Stmt::Call(e) => walk_expr(e, want, out),
            Stmt::Do(x) => walk(x, want, out),
            Stmt::While { cond, body } => {
                walk_expr(cond, want, out);
                walk(body, want, out);
            }
            Stmt::Repeat { body, until } => {
                walk(body, want, out);
                walk_expr(until, want, out);
            }
            Stmt::NumericFor {
                start,
                end,
                step,
                body,
                ..
            } => {
                walk_expr(start, want, out);
                walk_expr(end, want, out);
                if let Some(x) = step {
                    walk_expr(x, want, out);
                }
                walk(body, want, out);
            }
            Stmt::GenericFor { exprs, body, .. } => {
                exprs.iter().for_each(|e| walk_expr(e, want, out));
                walk(body, want, out);
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                walk_expr(cond, want, out);
                walk(body, want, out);
                for (c, x) in else_ifs {
                    walk_expr(c, want, out);
                    walk(x, want, out);
                }
                if let Some(x) = otherwise {
                    walk(x, want, out);
                }
            }
        }
    }
    fn walk_expr(e: &Expr, want: u32, out: &mut Option<Vec<ir::Param>>) {
        match e {
            Expr::Function(f) => take(f, want, out),
            Expr::Field { base, .. } | Expr::Paren(base) | Expr::Unop { expr: base, .. } => {
                walk_expr(base, want, out)
            }
            Expr::Index { base, key } => {
                walk_expr(base, want, out);
                walk_expr(key, want, out);
            }
            Expr::Call { func, args, .. } => {
                walk_expr(func, want, out);
                args.iter().for_each(|a| walk_expr(a, want, out));
            }
            Expr::MethodCall { base, args, .. } => {
                walk_expr(base, want, out);
                args.iter().for_each(|a| walk_expr(a, want, out));
            }
            Expr::Table(fs) => {
                for f in fs {
                    match f {
                        Field::Positional(v) => walk_expr(v, want, out),
                        Field::Named { value, .. } => walk_expr(value, want, out),
                        Field::Keyed { key, value } => {
                            walk_expr(key, want, out);
                            walk_expr(value, want, out);
                        }
                    }
                }
            }
            Expr::Binop { lhs, rhs, .. } => {
                walk_expr(lhs, want, out);
                walk_expr(rhs, want, out);
            }
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                walk_expr(cond, want, out);
                walk_expr(then, want, out);
                for (c, v) in else_ifs {
                    walk_expr(c, want, out);
                    walk_expr(v, want, out);
                }
                walk_expr(otherwise, want, out);
            }
            Expr::Interp(ps) => {
                for p in ps {
                    if let ir::InterpPart::Expr(x) = p {
                        walk_expr(x, want, out);
                    }
                }
            }
            Expr::EncFunc { key, .. } => walk_expr(key, want, out),
            other => other.each_child(&mut |c| walk_expr(c, want, out)),
        }
    }
    let mut out = None;
    walk(&module.block, want, &mut out);
    out
}

fn cell_slot(cell: &str) -> Expr {
    Expr::Index {
        base: Box::new(Expr::Name(cell.into())),
        key: Box::new(Expr::Number("1".into())),
    }
}

struct Rewrite<'a> {
    scalar: &'a str,
    cell: &'a str,
    decl: usize,
}

impl Rewrite<'_> {
    fn is_it(&self, e: &Expr) -> bool {
        matches!(e, Expr::Name(n) if n == self.scalar)
    }

    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &mut b.last {
            es.iter_mut().for_each(|e| self.expr(e));
        }
    }

    fn stmt(&mut self, s: &mut Stmt) {
        if let Stmt::Local { names, exprs } = s {
            if names.len() == 1 && names[0] == self.scalar {
                self.decl += 1;
                names[0] = self.cell.to_string();
                *exprs = vec![Expr::Table(Vec::new())];
                return;
            }
        }
        match s {
            Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| self.expr(e)),
            Stmt::Assign { targets, exprs } => {
                for t in targets.iter_mut() {
                    if self.is_it(t) {
                        *t = cell_slot(self.cell);
                    } else {
                        self.expr(t);
                    }
                }
                exprs.iter_mut().for_each(|e| self.expr(e));
            }
            Stmt::Compound { target, value, .. } => {
                if self.is_it(target) {
                    *target = cell_slot(self.cell);
                } else {
                    self.expr(target);
                }
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
                exprs.iter_mut().for_each(|e| self.expr(e));
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
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                self.block(&mut body.block)
            }
        }
    }

    fn expr(&mut self, e: &mut Expr) {
        if self.is_it(e) {
            *e = cell_slot(self.cell);
            return;
        }
        match e {
            Expr::Function(f) => self.block(&mut f.block),
            Expr::Call { func, args, .. } => {
                self.expr(func);
                args.iter_mut().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter_mut().for_each(|a| self.expr(a));
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
            other => other.each_child_mut(&mut |c| self.expr(c)),
        }
    }
}

struct Split<'a> {
    container: u32,
    cell: &'a str,
    param: &'a str,
    taken: Option<FuncBody>,
    hits: usize,
}

impl Split<'_> {
    fn consider(&mut self, f: &mut FuncBody) {
        if f.stable_id != Some(self.container) {
            self.block(&mut f.block);
            return;
        }
        self.hits += 1;
        let mut helper = FuncBody {
            params: vec![ir::Param::Name(self.param.into())],
            block: std::mem::replace(
                &mut f.block,
                Block {
                    stmts: Vec::new(),
                    last: None,
                },
            ),
            hot_callback: None,
            stable_id: None,
        };
        helper.params.extend(f.params.iter().cloned());
        let mut ren = Rename {
            from: self.cell,
            to: self.param,
        };
        ren.block(&mut helper.block);
        self.taken = Some(helper);
    }

    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &mut b.last {
            es.iter_mut().for_each(|e| self.expr(e));
        }
    }

    fn stmt(&mut self, s: &mut Stmt) {
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => self.consider(body),
            Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| self.expr(e)),
            Stmt::Assign { targets, exprs } => {
                targets.iter_mut().for_each(|e| self.expr(e));
                exprs.iter_mut().for_each(|e| self.expr(e));
            }
            Stmt::Call(e) => self.expr(e),
            Stmt::Do(x) => self.block(x),
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => self.block(body),
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => self.block(body),
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                self.block(body);
                for (_, x) in else_ifs {
                    self.block(x);
                }
                if let Some(x) = otherwise {
                    self.block(x);
                }
            }
            Stmt::Compound { .. } => {}
        }
    }

    fn expr(&mut self, e: &mut Expr) {
        match e {
            Expr::Function(f) => self.consider(f),
            Expr::Call { func, args, .. } => {
                self.expr(func);
                args.iter_mut().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter_mut().for_each(|a| self.expr(a));
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
            other => other.each_child_mut(&mut |c| self.expr(c)),
        }
    }
}

struct Rename<'a> {
    from: &'a str,
    to: &'a str,
}

impl Rename<'_> {
    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &mut b.last {
            es.iter_mut().for_each(|e| self.expr(e));
        }
    }
    fn stmt(&mut self, s: &mut Stmt) {
        match s {
            Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| self.expr(e)),
            Stmt::Assign { targets, exprs } => {
                targets.iter_mut().for_each(|e| self.expr(e));
                exprs.iter_mut().for_each(|e| self.expr(e));
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
                exprs.iter_mut().for_each(|e| self.expr(e));
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
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                self.block(&mut body.block)
            }
        }
    }
    fn expr(&mut self, e: &mut Expr) {
        if matches!(e, Expr::Name(n) if n == self.from) {
            *e = Expr::Name(self.to.into());
            return;
        }
        match e {
            Expr::Function(f) => self.block(&mut f.block),
            Expr::Call { func, args, .. } => {
                self.expr(func);
                args.iter_mut().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter_mut().for_each(|a| self.expr(a));
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
            other => other.each_child_mut(&mut |c| self.expr(c)),
        }
    }
}

struct BindWrapper<'a> {
    container: u32,
    cell: &'a str,
    idx: u32,
    done: bool,
}

impl BindWrapper<'_> {
    fn consider(&mut self, f: &mut FuncBody) {
        if f.stable_id != Some(self.container) {
            self.block(&mut f.block);
            return;
        }
        let mut args = vec![Expr::Name(self.cell.into())];
        for p in &f.params {
            if let ir::Param::Name(n) = p {
                args.push(Expr::Name(n.clone()));
            }
        }
        f.block = Block {
            stmts: Vec::new(),
            last: Some(LastStmt::Return(vec![Expr::Call {
                func: Box::new(Expr::NativeRef(self.idx)),
                args,
                site: None,
            }])),
        };
        self.done = true;
    }

    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &mut b.last {
            es.iter_mut().for_each(|e| self.expr(e));
        }
    }

    fn stmt(&mut self, s: &mut Stmt) {
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => self.consider(body),
            Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| self.expr(e)),
            Stmt::Assign { targets, exprs } => {
                targets.iter_mut().for_each(|e| self.expr(e));
                exprs.iter_mut().for_each(|e| self.expr(e));
            }
            Stmt::Call(e) => self.expr(e),
            Stmt::Do(x) => self.block(x),
            Stmt::While { body, .. } | Stmt::Repeat { body, .. } => self.block(body),
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => self.block(body),
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                self.block(body);
                for (_, x) in else_ifs {
                    self.block(x);
                }
                if let Some(x) = otherwise {
                    self.block(x);
                }
            }
            Stmt::Compound { .. } => {}
        }
    }

    fn expr(&mut self, e: &mut Expr) {
        match e {
            Expr::Function(f) => self.consider(f),
            Expr::Call { func, args, .. } => {
                self.expr(func);
                args.iter_mut().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter_mut().for_each(|a| self.expr(a));
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
            other => other.each_child_mut(&mut |c| self.expr(c)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "local topCommand = nil\n\
                       Container = function(a, b, c, d)\n\
                       \ttopCommand = nil\n\
                       \tfor i, v in next, List() do\n\
                       \t\tif Matcher(v, a) then\n\
                       \t\t\tif topCommand == nil then topCommand = v end\n\
                       \t\tend\n\
                       \tend\n\
                       \treturn topCommand\n\
                       end\n\
                       Tab = function()\n\
                       \tif topCommand ~= nil then Complete(topCommand) end\n\
                       end\n\
                       return Container, Tab\n";

    fn prepared() -> Module {
        let mut m = crate::lower_str(SRC).unwrap();
        tag(&mut m, "Container", 220);
        tag(&mut m, "Tab", 296);
        m
    }

    fn tag(m: &mut Module, name: &str, id: u32) {
        for s in &mut m.block.stmts {
            if let Stmt::Assign { targets, exprs } = s {
                for (t, e) in targets.iter().zip(exprs.iter_mut()) {
                    if matches!(t, Expr::Name(n) if n == name) {
                        if let Expr::Function(f) = e {
                            f.stable_id = Some(id);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn audit_reports_declaration_reads_and_writes_per_owner() {
        let m = prepared();
        let c = audit(&m, "topCommand");
        assert_eq!(c.declarations, 1);
        assert_eq!(c.functions(), vec![Some(220), Some(296)]);
        assert_eq!(
            c.writes.get(&Some(220)).copied().unwrap_or(0),
            2,
            "nil reset plus first-match capture"
        );
        assert!(c.reads.get(&Some(220)).copied().unwrap_or(0) >= 2);
        assert_eq!(c.reads.get(&Some(296)).copied().unwrap_or(0), 2);
        assert!(
            c.writes.get(&Some(296)).is_none(),
            "the tab handler only reads"
        );
    }

    #[test]
    fn apply_removes_every_scalar_reference_and_creates_no_global() {
        let mut m = prepared();
        let applied = apply(&mut m, "topCommand", &[220, 296], 220).unwrap();
        assert_eq!(
            applied.after.total_refs(),
            3,
            "wrapper passes the cell; tab reads it twice"
        );

        let residual = audit(&m, "topCommand");
        assert_eq!(
            residual.total_refs(),
            0,
            "no plain scalar reference remains"
        );
        assert_eq!(residual.declarations, 0);

        let declared_local = m.block.stmts.iter().any(
            |s| matches!(s, Stmt::Local { names, .. } if names.iter().any(|n| n == CELL_NAME)),
        );
        assert!(
            declared_local,
            "the cell is declared as a chunk-level local, never a global"
        );

        let assigns_global = m.block.stmts.iter().any(|s| {
            matches!(s, Stmt::Assign { targets, .. }
                if targets.iter().any(|t| matches!(t, Expr::Name(n) if n == CELL_NAME)))
        });
        assert!(
            !assigns_global,
            "no global environment entry is created for the cell"
        );
    }

    #[test]
    fn helper_is_a_leaf_and_wrapper_keeps_the_signature() {
        let mut m = prepared();
        let applied = apply(&mut m, "topCommand", &[220, 296], 220).unwrap();

        for v in &applied.helper_free_vars {
            assert_ne!(
                v, CELL_NAME,
                "the cell must reach the helper as a parameter, not a capture"
            );
            assert_ne!(v, "topCommand");
        }
        assert!(
            applied.helper_free_vars.iter().any(|v| v == "Matcher"),
            "globals still free: {:?}",
            applied.helper_free_vars
        );

        assert_eq!(m.natives.len(), 1, "exactly one helper extracted");
        let helper = &m.natives[0];
        assert_eq!(
            helper.params.len(),
            5,
            "cell plus the original four arguments"
        );

        let mut wrapper_params = None;
        for s in &m.block.stmts {
            if let Stmt::Assign { targets, exprs } = s {
                for (t, e) in targets.iter().zip(exprs.iter()) {
                    if matches!(t, Expr::Name(n) if n == "Container") {
                        if let Expr::Function(f) = e {
                            wrapper_params = Some(f.params.len());
                        }
                    }
                }
            }
        }
        assert_eq!(
            wrapper_params,
            Some(4),
            "the wrapper keeps the original four-argument signature"
        );
    }

    #[test]
    fn apply_fails_closed_on_a_changed_owner_set_or_missing_declaration() {
        let mut wrong = prepared();
        let e = apply(&mut wrong, "topCommand", &[220], 220).unwrap_err();
        assert!(e.contains("owners changed"), "{e}");

        let mut none =
            crate::lower_str("Container = function() return 1 end\nreturn Container\n").unwrap();
        tag(&mut none, "Container", 220);
        let e2 = apply(&mut none, "topCommand", &[220], 220).unwrap_err();
        assert!(e2.contains("exactly one"), "{e2}");
    }

    #[test]
    fn a_producer_capturing_another_enclosing_local_fails_closed() {
        let src = "local topCommand = nil\n\
                   local hidden = 7\n\
                   Container = function(a)\n\
                   \ttopCommand = nil\n\
                   \tfor i, v in next, List() do\n\
                   \t\tif Matcher(v, a) then\n\
                   \t\t\tif topCommand == nil then topCommand = v + hidden end\n\
                   \t\tend\n\
                   \tend\n\
                   end\n\
                   Tab = function()\n\
                   \tif topCommand ~= nil then Complete(topCommand) end\n\
                   end\n\
                   return Container, Tab\n";
        let mut m = crate::lower_str(src).unwrap();
        tag(&mut m, "Container", 220);
        tag(&mut m, "Tab", 296);
        let e = apply(&mut m, "topCommand", &[220, 296], 220).unwrap_err();
        assert!(e.contains("captures enclosing local"), "{e}");
        assert!(e.contains("hidden"), "the offending capture is named: {e}");
    }

    #[test]
    fn a_variadic_producer_fails_closed() {
        let src = "local topCommand = nil\n\
                   Container = function(a, ...)\n\
                   \ttopCommand = nil\n\
                   \tfor i, v in next, List() do\n\
                   \t\tif Matcher(v, a) then\n\
                   \t\t\tif topCommand == nil then topCommand = v end\n\
                   \t\tend\n\
                   \tend\n\
                   end\n\
                   Tab = function()\n\
                   \tif topCommand ~= nil then Complete(topCommand) end\n\
                   end\n\
                   return Container, Tab\n";
        let mut m = crate::lower_str(src).unwrap();
        tag(&mut m, "Container", 220);
        tag(&mut m, "Tab", 296);
        let e = apply(&mut m, "topCommand", &[220, 296], 220).unwrap_err();
        assert!(e.contains("variadic"), "{e}");
    }

    #[test]
    fn nothing_is_mutated_when_a_gate_rejects() {
        let src = "local topCommand = nil\n\
                   Container = function(a, ...)\n\
                   \ttopCommand = nil\n\
                   \tfor i, v in next, List() do\n\
                   \t\tif Matcher(v, a) then topCommand = v end\n\
                   \tend\n\
                   end\n\
                   Tab = function()\n\
                   \tif topCommand ~= nil then Complete(topCommand) end\n\
                   end\n\
                   return Container, Tab\n";
        let mut m = crate::lower_str(src).unwrap();
        tag(&mut m, "Container", 220);
        tag(&mut m, "Tab", 296);
        let before = ir::emit(&m);
        assert!(apply(&mut m, "topCommand", &[220, 296], 220).is_err());
        assert_eq!(
            ir::emit(&m),
            before,
            "a rejected build must leave the module untouched"
        );
        assert!(m.natives.is_empty(), "no native is pushed on rejection");
    }

    #[test]
    fn the_renamer_reaches_extracted_natives_when_run_after_extraction() {
        let mut m = prepared();
        apply(&mut m, "topCommand", &[220, 296], 220).expect("applies");
        assert_eq!(m.natives.len(), 1);
        let before = ir::emit_func(&m.natives[0]);
        assert!(
            before.contains(CELL_PARAM),
            "the cell param is present pre-rename"
        );

        crate::sanitize::strip_source_names(&mut m, 0xB451_115C);
        let after = ir::emit_func(&m.natives[0]);
        assert!(
            !after.contains(CELL_PARAM),
            "the renamer reached the native body: {after}"
        );
        for leaked in ["topCommand", "indexnum"] {
            assert!(
                !after.contains(leaked),
                "`{leaked}` must not survive into plaintext: {after}"
            );
        }
        assert!(
            after.contains("Matcher"),
            "globals are still globals, not renamed: {after}"
        );
    }
}
