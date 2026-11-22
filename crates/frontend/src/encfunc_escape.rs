use crate::Error;
use ir::{Block, Expr, Field, FuncBody, InterpPart, LastStmt, Param, Stmt};

#[derive(Clone, Copy, Default, PartialEq)]
struct Kind {
    func: bool,
    table: bool,
}

impl Kind {
    fn any(self) -> bool {
        self.func || self.table
    }
    fn merge(self, o: Kind) -> Kind {
        Kind {
            func: self.func || o.func,
            table: self.table || o.table,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Prov {
    Owned,
    Borrowed,
    Unknown,
}

#[derive(Clone, Copy)]
struct ProvInfo {
    saw_owned: bool,
    saw_foreign: bool,
    foreign: Prov,
}

impl Default for ProvInfo {
    fn default() -> Self {
        ProvInfo {
            saw_owned: false,
            saw_foreign: false,
            foreign: Prov::Unknown,
        }
    }
}

#[derive(Clone, Copy)]
enum Why {
    Return,
    Global,
    OuterObject,
    BorrowedStore,
    UnknownStore,
    UnknownCall,
    AsyncCall,
    Ambiguous,
}

const ASYNC_METHODS: &[&str] = &[
    "Connect",
    "connect",
    "ConnectParallel",
    "Once",
    "once",
    "Wait",
    "wait",
    "Bind",
    "bind",
    "BindAction",
    "BindActionAtPriority",
    "BindToRenderStep",
    "BindToClose",
];

const ASYNC_TABLES: &[(&str, &[&str])] = &[
    (
        "task",
        &[
            "spawn",
            "defer",
            "delay",
            "wait",
            "synchronize",
            "desynchronize",
        ],
    ),
    ("coroutine", &["create", "wrap", "resume"]),
];

const ASYNC_GLOBALS: &[&str] = &["spawn", "delay", "defer", "wait", "setmetatable"];

pub fn check(body: &FuncBody, macro_name: &str) -> Result<(), Error> {
    let mut cx = Cx {
        env: Vec::new(),
        next_id: 0,
        kind: Vec::new(),
        prov: Vec::new(),
        aliases: Vec::new(),
        reassigned_globals: Vec::new(),
        classify: true,
        changed: false,
        macro_name: macro_name.to_string(),
    };
    for _ in 0..64 {
        cx.changed = false;
        cx.next_id = 0;
        cx.env.clear();
        cx.aliases.clear();
        cx.func(body)?;
        cx.propagate_aliases();
        if !cx.changed {
            break;
        }
    }
    cx.classify = false;
    cx.next_id = 0;
    cx.env.clear();
    cx.func(body)
}

struct Cx {
    env: Vec<Vec<(String, usize)>>,
    next_id: usize,
    kind: Vec<Kind>,
    prov: Vec<ProvInfo>,
    aliases: Vec<(usize, usize)>,
    reassigned_globals: Vec<String>,
    classify: bool,
    changed: bool,
    macro_name: String,
}

impl Cx {
    fn err(&self, why: Why, what: &str) -> Error {
        let m = &self.macro_name;
        Error::Macro(match why {
            Why::Return => format!(
                "{m} function returns {what}; a nested function must not outlive the sealed body \
                 (escaping closure)"
            ),
            Why::Global => format!(
                "{m} function assigns {what} to a global or `_G`; a nested function must stay inside \
                 the sealed body (escaping closure)"
            ),
            Why::OuterObject => format!(
                "{m} function stores {what} into a table it does not own; the containing table \
                 escapes the sealed body (escaping table containing closure)"
            ),
            Why::BorrowedStore => format!(
                "{m} function stores {what} into a borrowed table it does not own (a parameter, \
                 global or environment table); the containing table escapes the sealed body \
                 (escaping table containing closure)"
            ),
            Why::UnknownStore => format!(
                "{m} function stores {what} into a table whose ownership cannot be proven (a call \
                 result, dynamic value or nested field); the containing table escapes the sealed \
                 body (escaping table containing closure)"
            ),
            Why::UnknownCall => format!(
                "{m} function passes {what} to a function that is not a supported synchronous \
                 consumer; it may retain the callback beyond the sealed body (unknown retaining callback)"
            ),
            Why::AsyncCall => format!(
                "{m} function passes {what} to an asynchronous, deferred or event-connection API; \
                 the callback outlives the sealed body (asynchronous callback)"
            ),
            Why::Ambiguous => format!(
                "{m} function uses {what} in a position where its ownership cannot be proven; \
                 nested functions must be provably confined to the sealed body (ambiguous alias/ownership)"
            ),
        })
    }

    fn propagate_aliases(&mut self) {
        loop {
            let mut moved = false;
            for &(a, b) in &self.aliases {
                let u = self.kind[a].merge(self.kind[b]);
                if u != self.kind[a] {
                    self.kind[a] = u;
                    moved = true;
                }
                if u != self.kind[b] {
                    self.kind[b] = u;
                    moved = true;
                }
            }
            if !moved {
                break;
            }
            self.changed = true;
        }
    }

    fn alias_src(&self, e: &Expr) -> Option<usize> {
        match e {
            Expr::Name(n) => self.lookup(n),
            Expr::Paren(i) => self.alias_src(i),
            _ => None,
        }
    }

    fn add_alias(&mut self, a: usize, b: usize) {
        if self.classify && a != b && !self.aliases.contains(&(a, b)) {
            self.aliases.push((a, b));
        }
    }

    fn new_id(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        if self.kind.len() <= id {
            self.kind.push(Kind::default());
        }
        if self.prov.len() <= id {
            self.prov.push(ProvInfo::default());
        }
        id
    }

    fn declare(&mut self, name: &str) -> usize {
        let id = self.new_id();
        if let Some(top) = self.env.last_mut() {
            top.push((name.to_string(), id));
        }
        id
    }

    fn lookup(&self, name: &str) -> Option<usize> {
        for frame in self.env.iter().rev() {
            for (n, id) in frame.iter().rev() {
                if n == name {
                    return Some(*id);
                }
            }
        }
        None
    }

    fn kind_of(&self, name: &str) -> Kind {
        self.lookup(name)
            .map(|id| self.kind[id])
            .unwrap_or_default()
    }

    fn set_kind(&mut self, id: usize, k: Kind) {
        if !self.classify {
            return;
        }
        let merged = self.kind[id].merge(k);
        if merged != self.kind[id] {
            self.kind[id] = merged;
            self.changed = true;
        }
    }

    fn is_local(&self, name: &str) -> bool {
        self.lookup(name).is_some()
    }

    fn binding_prov(&self, id: usize) -> Prov {
        let p = self.prov[id];
        if p.saw_foreign {
            p.foreign
        } else if p.saw_owned {
            Prov::Owned
        } else {
            Prov::Unknown
        }
    }

    fn set_prov(&mut self, id: usize, prov: Prov) {
        match prov {
            Prov::Owned => self.prov[id].saw_owned = true,
            Prov::Borrowed => {
                if !self.prov[id].saw_foreign {
                    self.prov[id].saw_foreign = true;
                    self.prov[id].foreign = Prov::Borrowed;
                }
            }
            Prov::Unknown => {
                self.prov[id].saw_foreign = true;
                self.prov[id].foreign = Prov::Unknown;
            }
        }
    }

    fn expr_prov(&self, e: &Expr) -> Prov {
        match e {
            Expr::Table(_) => Prov::Owned,
            Expr::Name(n) => match self.lookup(n) {
                Some(id) => self.binding_prov(id),
                None => Prov::Borrowed,
            },
            Expr::Paren(i) => self.expr_prov(i),
            _ => Prov::Unknown,
        }
    }

    fn store_base_prov(&self, base: &Expr) -> Prov {
        match base {
            Expr::Name(n) => match self.lookup(n) {
                Some(id) => self.binding_prov(id),
                None => Prov::Borrowed,
            },
            Expr::Paren(i) => self.store_base_prov(i),
            _ => Prov::Unknown,
        }
    }

    fn base_owned(&self, base: &Expr) -> bool {
        matches!(self.store_base_prov(base), Prov::Owned)
    }

    fn store_target_why(&self, t: &Expr) -> Why {
        match t {
            Expr::Name(_) => Why::Global,
            Expr::Paren(i) => self.store_target_why(i),
            Expr::Field { base, .. } | Expr::Index { base, .. } => match self.store_base_prov(base)
            {
                Prov::Borrowed => Why::BorrowedStore,
                _ => Why::UnknownStore,
            },
            _ => Why::OuterObject,
        }
    }

    fn is_consumer_global(name: &str) -> bool {
        matches!(name, "pcall" | "xpcall" | "table" | "string")
    }

    fn is_reassigned(&self, name: &str) -> bool {
        self.reassigned_globals.iter().any(|n| n == name)
    }

    fn mark_reassigned(&mut self, name: &str) {
        if !self.is_reassigned(name) {
            self.reassigned_globals.push(name.to_string());
            if self.classify {
                self.changed = true;
            }
        }
    }

    fn value_kind(&self, e: &Expr) -> Kind {
        match e {
            Expr::Function(_) => Kind {
                func: true,
                table: false,
            },
            Expr::Name(n) => self.kind_of(n),
            Expr::Paren(inner) => self.value_kind(inner),
            Expr::Field { base, .. } | Expr::Index { base, .. } => {
                if self.value_kind(base).table {
                    Kind {
                        func: true,
                        table: true,
                    }
                } else {
                    Kind::default()
                }
            }
            Expr::Table(fields) => {
                let holds = fields.iter().any(|f| match f {
                    Field::Positional(v) => self.value_kind(v).any(),
                    Field::Named { value, .. } => self.value_kind(value).any(),
                    Field::Keyed { value, .. } => self.value_kind(value).any(),
                });
                if holds {
                    Kind {
                        func: false,
                        table: true,
                    }
                } else {
                    Kind::default()
                }
            }
            _ => Kind::default(),
        }
    }

    fn describe(&self, e: &Expr) -> String {
        match e {
            Expr::Function(_) => "a nested function".to_string(),
            Expr::Name(n) => {
                let k = self.kind_of(n);
                if k.table {
                    format!("the local table `{n}`, which holds a nested function,")
                } else {
                    format!("the nested function `{n}`")
                }
            }
            Expr::Table(_) => "a table holding a nested function".to_string(),
            Expr::Paren(inner) => self.describe(inner),
            Expr::Field { base, name } => {
                format!("`{}.{name}`, a nested function", self.base_name(base))
            }
            Expr::Index { base, .. } => {
                format!("a nested function read out of `{}`", self.base_name(base))
            }
            _ => "a nested function value".to_string(),
        }
    }

    fn base_name(&self, e: &Expr) -> String {
        match e {
            Expr::Name(n) => n.clone(),
            Expr::Paren(i) => self.base_name(i),
            Expr::Field { base, .. } | Expr::Index { base, .. } => self.base_name(base),
            _ => "a table".to_string(),
        }
    }

    fn func(&mut self, body: &FuncBody) -> Result<(), Error> {
        self.env.push(Vec::new());
        for p in &body.params {
            if let Param::Name(n) = p {
                let id = self.declare(n);
                self.set_prov(id, Prov::Borrowed);
            }
        }
        let r = self.block(&body.block);
        self.env.pop();
        r
    }

    fn method_func(&mut self, body: &FuncBody, has_self: bool) -> Result<(), Error> {
        self.env.push(Vec::new());
        if has_self {
            let id = self.declare("self");
            self.set_prov(id, Prov::Borrowed);
        }
        for p in &body.params {
            if let Param::Name(n) = p {
                let id = self.declare(n);
                self.set_prov(id, Prov::Borrowed);
            }
        }
        let r = self.block(&body.block);
        self.env.pop();
        r
    }

    fn scoped(&mut self, b: &Block, predeclare: &[&str]) -> Result<(), Error> {
        self.env.push(Vec::new());
        for n in predeclare {
            self.declare(n);
        }
        let r = self.block(b);
        self.env.pop();
        r
    }

    fn block(&mut self, b: &Block) -> Result<(), Error> {
        for s in &b.stmts {
            self.stmt(s)?;
        }
        if let Some(LastStmt::Return(exprs)) = &b.last {
            for e in exprs {
                if self.value_kind(e).any() {
                    return Err(self.err(Why::Return, &self.describe(e)));
                }
                self.value(e, Why::Return)?;
            }
        }
        Ok(())
    }

    fn stmt(&mut self, s: &Stmt) -> Result<(), Error> {
        match s {
            Stmt::Local { names, exprs } => {
                for (i, e) in exprs.iter().enumerate() {
                    if i < names.len() {
                        self.intro(e)?;
                    } else {
                        self.value(e, Why::Ambiguous)?;
                    }
                }
                let kinds: Vec<Kind> = (0..names.len())
                    .map(|i| exprs.get(i).map(|e| self.value_kind(e)).unwrap_or_default())
                    .collect();
                let srcs: Vec<Option<usize>> = (0..names.len())
                    .map(|i| exprs.get(i).and_then(|e| self.alias_src(e)))
                    .collect();
                let provs: Vec<Option<Prov>> = (0..names.len())
                    .map(|i| exprs.get(i).map(|e| self.expr_prov(e)))
                    .collect();
                for (i, n) in names.iter().enumerate() {
                    let id = self.declare(n);
                    self.set_kind(id, kinds[i]);
                    if let Some(s) = srcs[i] {
                        self.add_alias(id, s);
                    }
                    if let Some(p) = provs[i] {
                        self.set_prov(id, p);
                    }
                }
            }
            Stmt::LocalFunction { name, body } => {
                let id = self.declare(name);
                self.set_kind(
                    id,
                    Kind {
                        func: true,
                        table: false,
                    },
                );
                self.func(body)?;
            }
            Stmt::Function { name, body } => {
                let root = &name.path[0];
                let is_field = name.path.len() > 1 || name.method.is_some();
                if !is_field {
                    if !self.is_local(root) {
                        return Err(self.err(Why::Global, "a nested function"));
                    }
                    let id = self.lookup(root).unwrap();
                    self.set_kind(
                        id,
                        Kind {
                            func: true,
                            table: false,
                        },
                    );
                } else {
                    let depth1 = (name.method.is_some() && name.path.len() == 1)
                        || (name.method.is_none() && name.path.len() == 2);
                    let owned = depth1
                        && matches!(self.lookup(root), Some(id) if self.binding_prov(id) == Prov::Owned);
                    if !owned {
                        let why = if !self.is_local(root) {
                            Why::OuterObject
                        } else if !depth1 {
                            Why::UnknownStore
                        } else if matches!(self.lookup(root), Some(id) if self.binding_prov(id) == Prov::Borrowed)
                        {
                            Why::BorrowedStore
                        } else {
                            Why::UnknownStore
                        };
                        return Err(self.err(why, "a nested function"));
                    }
                    let id = self.lookup(root).unwrap();
                    self.set_kind(
                        id,
                        Kind {
                            func: false,
                            table: true,
                        },
                    );
                }
                self.method_func(body, name.method.is_some())?;
            }
            Stmt::Assign { targets, exprs } => {
                for t in targets {
                    if let Expr::Name(n) = t {
                        if !self.is_local(n) && Self::is_consumer_global(n) {
                            self.mark_reassigned(n);
                        }
                    }
                }
                for (i, e) in exprs.iter().enumerate() {
                    match targets.get(i) {
                        Some(t) if self.owned_target(t) => self.intro(e)?,
                        Some(t) => {
                            let why = self.store_target_why(t);
                            self.value(e, why)?;
                        }
                        None => self.value(e, Why::Ambiguous)?,
                    }
                }
                let tprovs: Vec<Option<(usize, Prov)>> = targets
                    .iter()
                    .enumerate()
                    .map(|(i, t)| match t {
                        Expr::Name(n) => self.lookup(n).map(|id| {
                            let p = exprs
                                .get(i)
                                .map(|e| self.expr_prov(e))
                                .unwrap_or(Prov::Unknown);
                            (id, p)
                        }),
                        _ => None,
                    })
                    .collect();
                for tp in tprovs.into_iter().flatten() {
                    self.set_prov(tp.0, tp.1);
                }
                for (i, t) in targets.iter().enumerate() {
                    let k = exprs.get(i).map(|e| self.value_kind(e)).unwrap_or_default();
                    let src = exprs.get(i).and_then(|e| self.alias_src(e));
                    self.assign_target(t, k, src)?;
                }
            }
            Stmt::Compound { target, value, .. } => {
                self.value(target, Why::Ambiguous)?;
                self.value(value, Why::Ambiguous)?;
            }
            Stmt::Call(e) => self.value(e, Why::UnknownCall)?,
            Stmt::Do(b) => self.scoped(b, &[])?,
            Stmt::While { cond, body } => {
                self.value(cond, Why::Ambiguous)?;
                self.scoped(body, &[])?;
            }
            Stmt::Repeat { body, until } => {
                self.env.push(Vec::new());
                let r = self
                    .block(body)
                    .and_then(|_| self.value(until, Why::Ambiguous));
                self.env.pop();
                r?;
            }
            Stmt::NumericFor {
                var,
                start,
                end,
                step,
                body,
            } => {
                self.value(start, Why::Ambiguous)?;
                self.value(end, Why::Ambiguous)?;
                if let Some(s) = step {
                    self.value(s, Why::Ambiguous)?;
                }
                self.scoped(body, &[var.as_str()])?;
            }
            Stmt::GenericFor { names, exprs, body } => {
                for e in exprs {
                    self.value(e, Why::Ambiguous)?;
                }
                let pre: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                self.scoped(body, &pre)?;
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.value(cond, Why::Ambiguous)?;
                self.scoped(body, &[])?;
                for (c, b) in else_ifs {
                    self.value(c, Why::Ambiguous)?;
                    self.scoped(b, &[])?;
                }
                if let Some(b) = otherwise {
                    self.scoped(b, &[])?;
                }
            }
        }
        Ok(())
    }

    fn owned_target(&self, t: &Expr) -> bool {
        match t {
            Expr::Name(n) => self.is_local(n),
            Expr::Field { base, .. } | Expr::Index { base, .. } => self.base_owned(base),
            Expr::Paren(i) => self.owned_target(i),
            _ => false,
        }
    }

    fn assign_target(&mut self, t: &Expr, k: Kind, src: Option<usize>) -> Result<(), Error> {
        match t {
            Expr::Name(n) => match self.lookup(n) {
                Some(id) => {
                    self.set_kind(id, k);
                    if let Some(s) = src {
                        self.add_alias(id, s);
                    }
                    Ok(())
                }
                None => {
                    if k.any() {
                        Err(self.err(Why::Global, "a nested function"))
                    } else {
                        Ok(())
                    }
                }
            },
            Expr::Field { base, .. } | Expr::Index { base, .. } => {
                if !self.owned_target(t) {
                    if k.any() {
                        return Err(self.err(self.store_target_why(t), "a nested function"));
                    }
                    return self.value(t, Why::Ambiguous);
                }
                let root = self.root_local(base);
                if let Some(id) = root {
                    if k.any() {
                        self.set_kind(
                            id,
                            Kind {
                                func: false,
                                table: true,
                            },
                        );
                    }
                }
                if let Expr::Index { key, .. } = t {
                    self.value(key, Why::Ambiguous)?;
                }
                Ok(())
            }
            _ => self.value(t, Why::Ambiguous),
        }
    }

    fn root_local(&self, e: &Expr) -> Option<usize> {
        match e {
            Expr::Name(n) => self.lookup(n),
            Expr::Paren(i) => self.root_local(i),
            Expr::Field { base, .. } | Expr::Index { base, .. } => self.root_local(base),
            _ => None,
        }
    }

    fn intro(&mut self, e: &Expr) -> Result<(), Error> {
        match e {
            Expr::Function(fb) => self.func(fb),
            Expr::Paren(inner) => self.intro(inner),
            Expr::Table(fields) => {
                for f in fields {
                    match f {
                        Field::Positional(v) => self.intro(v)?,
                        Field::Named { value, .. } => self.intro(value)?,
                        Field::Keyed { key, value } => {
                            self.value(key, Why::Ambiguous)?;
                            self.intro(value)?;
                        }
                    }
                }
                Ok(())
            }
            Expr::Name(_) => Ok(()),
            Expr::Field { base, .. } => {
                if self.value_kind(base).table {
                    Ok(())
                } else {
                    self.value(e, Why::Ambiguous)
                }
            }
            Expr::Index { base, key } => {
                if self.value_kind(base).table {
                    self.value(key, Why::Ambiguous)
                } else {
                    self.value(e, Why::Ambiguous)
                }
            }
            _ => self.value(e, Why::Ambiguous),
        }
    }

    fn value(&mut self, e: &Expr, why: Why) -> Result<(), Error> {
        match e {
            Expr::Name(n) => {
                if self.kind_of(n).any() {
                    return Err(self.err(why, &self.describe(e)));
                }
                Ok(())
            }
            Expr::Function(_) => Err(self.err(why, "a nested function")),
            Expr::Paren(inner) => self.value(inner, why),
            Expr::Field { base, .. } => {
                if self.value_kind(e).any() {
                    return Err(self.err(why, &self.describe(e)));
                }
                self.base(base)
            }
            Expr::Index { base, key } => {
                if self.value_kind(e).any() {
                    return Err(self.err(why, &self.describe(e)));
                }
                self.base(base)?;
                self.value(key, Why::Ambiguous)
            }
            Expr::Table(fields) => {
                for f in fields {
                    match f {
                        Field::Positional(v) => self.value(v, why)?,
                        Field::Named { value, .. } => self.value(value, why)?,
                        Field::Keyed { key, value } => {
                            self.value(key, Why::Ambiguous)?;
                            self.value(value, why)?;
                        }
                    }
                }
                Ok(())
            }
            Expr::Call { func, args, .. } => self.call(func, args),
            Expr::MethodCall { base, method, args } => {
                self.base(base)?;
                let why = if ASYNC_METHODS.contains(&method.as_str()) {
                    Why::AsyncCall
                } else {
                    Why::UnknownCall
                };
                for a in args {
                    self.value(a, why)?;
                }
                Ok(())
            }
            Expr::Binop { lhs, rhs, .. } => {
                self.value(lhs, Why::Ambiguous)?;
                self.value(rhs, Why::Ambiguous)
            }
            Expr::Unop { expr, .. } => self.value(expr, Why::Ambiguous),
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                self.value(cond, Why::Ambiguous)?;
                self.value(then, Why::Ambiguous)?;
                for (c, v) in else_ifs {
                    self.value(c, Why::Ambiguous)?;
                    self.value(v, Why::Ambiguous)?;
                }
                self.value(otherwise, Why::Ambiguous)
            }
            Expr::Interp(parts) => {
                for p in parts {
                    if let InterpPart::Expr(x) = p {
                        self.value(x, Why::Ambiguous)?;
                    }
                }
                Ok(())
            }
            Expr::EncFunc { key, .. } => self.value(key, Why::Ambiguous),
            _ => Ok(()),
        }
    }

    fn base(&mut self, e: &Expr) -> Result<(), Error> {
        match e {
            Expr::Name(_) => Ok(()),
            Expr::Paren(i) => self.base(i),
            Expr::Field { base, .. } => self.base(base),
            Expr::Index { base, key } => {
                self.base(base)?;
                self.value(key, Why::Ambiguous)
            }
            _ => self.value(e, Why::Ambiguous),
        }
    }

    fn callee(&mut self, f: &Expr) -> Result<(), Error> {
        match f {
            Expr::Name(_) => Ok(()),
            Expr::Paren(inner) => match &**inner {
                Expr::Function(fb) => self.func(fb),
                other => self.callee(other),
            },
            Expr::Function(fb) => self.func(fb),
            Expr::Field { base, .. } => self.base(base),
            Expr::Index { base, key } => {
                self.base(base)?;
                self.value(key, Why::Ambiguous)
            }
            other => self.value(other, Why::Ambiguous),
        }
    }

    fn allowlisted_consumer(&self, f: &Expr, args: &[Expr]) -> Option<&'static [usize]> {
        match f {
            Expr::Name(n) if !self.is_local(n) && !self.is_reassigned(n) => match n.as_str() {
                "pcall" if !args.is_empty() => Some(&[0]),
                "xpcall" if args.len() >= 2 => Some(&[0, 1]),
                _ => None,
            },
            Expr::Field { base, name } => match &**base {
                Expr::Name(t) if !self.is_local(t) && !self.is_reassigned(t) => {
                    match (t.as_str(), name.as_str()) {
                        ("table", "sort") if args.len() == 2 => Some(&[1]),
                        ("string", "gsub") if args.len() >= 3 => Some(&[2]),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn call(&mut self, f: &Expr, args: &[Expr]) -> Result<(), Error> {
        if let Some(positions) = self.allowlisted_consumer(f, args) {
            for (i, a) in args.iter().enumerate() {
                if positions.contains(&i) {
                    self.callback_arg(a)?;
                } else {
                    self.value(a, Why::UnknownCall)?;
                }
            }
            return Ok(());
        }
        self.callee(f)?;
        let why = if self.async_callee(f) {
            Why::AsyncCall
        } else {
            Why::UnknownCall
        };
        for a in args {
            self.value(a, why)?;
        }
        Ok(())
    }

    fn async_callee(&self, f: &Expr) -> bool {
        match f {
            Expr::Name(n) => !self.is_local(n) && ASYNC_GLOBALS.contains(&n.as_str()),
            Expr::Paren(i) => self.async_callee(i),
            Expr::Field { base, name } => match &**base {
                Expr::Name(t) if !self.is_local(t) => ASYNC_TABLES
                    .iter()
                    .any(|(tbl, fns)| tbl == t && fns.contains(&name.as_str())),
                _ => false,
            },
            _ => false,
        }
    }

    fn callback_arg(&mut self, e: &Expr) -> Result<(), Error> {
        match e {
            Expr::Function(fb) => self.func(fb),
            Expr::Paren(inner) => self.callback_arg(inner),
            Expr::Name(n) => {
                let k = self.kind_of(n);
                if k.table {
                    return Err(self.err(Why::UnknownCall, &self.describe(e)));
                }
                Ok(())
            }
            other => self.value(other, Why::UnknownCall),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lower_str;
    use crate::macros::expand;

    const K: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn seal(body: &str) -> String {
        format!("local rk = BASILISK_RUNTIME_KEY\nlocal f = BASIL_ENCFUNC(function(n)\n{body}\nend, \"{K}\", rk)\nreturn f(1)\n")
    }

    fn accept(label: &str, body: &str) {
        let src = seal(body);
        match expand(lower_str(&src).expect("lower"), 0) {
            Ok(m) => assert_eq!(m.encfuncs.len(), 1, "[{label}] one sealed body expected"),
            Err(e) => panic!("[{label}] must be ACCEPTED, got: {e}"),
        }
    }

    fn reject(label: &str, body: &str) -> String {
        let src = seal(body);
        match expand(lower_str(&src).expect("lower"), 0) {
            Ok(_) => panic!("[{label}] must be REJECTED, but the build was accepted"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a01_plain_body_without_nested_functions() {
        accept("plain", "return n * 2");
    }

    #[test]
    fn a02_one_local_helper() {
        accept(
            "one helper",
            "local function d(x) return x * 2 end\nreturn d(n)",
        );
    }

    #[test]
    fn a03_several_local_helpers() {
        accept(
            "several",
            "local function a(x) return x + 1 end\nlocal function b(x) return x * 2 end\n\
             local function c(x) return a(b(x)) end\nreturn c(n)",
        );
    }

    #[test]
    fn a04_anonymous_immediately_invoked_callback() {
        accept(
            "iife",
            "local v = (function(x) return x + 1 end)(n)\nreturn v",
        );
    }

    #[test]
    fn a05_table_sort_callback_literal_and_alias() {
        accept(
            "sort literal",
            "local t = { 3, 1, 2 }\ntable.sort(t, function(a, b) return a < b end)\nreturn t[1]",
        );
        accept(
            "sort alias",
            "local t = { 3, 1, 2 }\nlocal function cmp(a, b) return a < b end\ntable.sort(t, cmp)\nreturn t[1]",
        );
    }

    #[test]
    fn a06_child_captures_an_encfunc_parameter() {
        accept(
            "param capture",
            "local function add(x) return x + n end\nreturn add(5)",
        );
    }

    #[test]
    fn a07_child_captures_an_encfunc_body_local() {
        accept(
            "local capture",
            "local base = 10\nlocal function add(x) return x + base end\nreturn add(n)",
        );
    }

    #[test]
    fn a08_mutable_local_capture() {
        accept(
            "mutable capture",
            "local acc = 0\nlocal function bump(x) acc = acc + x return acc end\nbump(n)\nreturn acc",
        );
    }

    #[test]
    fn a09_two_children_share_one_mutable_capture() {
        accept(
            "shared capture",
            "local acc = 0\nlocal function inc() acc = acc + 1 end\nlocal function get() return acc end\n\
             inc()\ninc()\nreturn get()",
        );
    }

    #[test]
    fn a10_direct_recursion() {
        accept("direct recursion", "local function fac(x) if x <= 1 then return 1 end return x * fac(x - 1) end\nreturn fac(n)");
    }

    #[test]
    fn a11_mutual_recursion_via_forward_locals() {
        accept(
            "mutual recursion",
            "local isEven, isOdd\nfunction isEven(x) if x == 0 then return true end return isOdd(x - 1) end\n\
             function isOdd(x) if x == 0 then return false end return isEven(x - 1) end\nreturn isEven(n)",
        );
        accept(
            "mutual recursion assign",
            "local a, b\na = function(x) if x == 0 then return 0 end return b(x - 1) end\n\
             b = function(x) return a(x) end\nreturn a(n)",
        );
    }

    #[test]
    fn a12_shadowed_recursive_name() {
        accept(
            "shadow",
            "local function f(x) return x + 1 end\ndo local f = 3 print(f) end\nreturn f(n)",
        );
    }

    #[test]
    fn a13_nested_block_shadowing_of_a_helper_name() {
        accept(
            "block shadow",
            "local function g(x) return x end\nif n > 0 then local g = 7 print(g) end\nreturn g(n)",
        );
    }

    #[test]
    fn a15_crash_hash_opaque_inside_a_child() {
        accept(
            "crash in child",
            "local function c(x) if x < 0 then BASIL_CRASH() end return x end\nreturn c(n)",
        );
        accept(
            "hash in child",
            "local function c(x) return BASIL_HASH(tostring(x)) end\nreturn c(n)",
        );
        accept(
            "opaque in child",
            "local function c(x) if BASIL_OPAQUE(true) then return x end return 0 end\nreturn c(n)",
        );
    }

    #[test]
    fn a17_local_non_escaping_function_table_and_method() {
        accept(
            "function table",
            "local ops = { inc = function(x) return x + 1 end, dec = function(x) return x - 1 end }\nreturn ops.inc(n)",
        );
        accept(
            "method decl",
            "local obj = {}\nfunction obj.plain(x) return x + 1 end\nfunction obj:m(x) return x + 2 end\nreturn obj.plain(n) + obj:m(n)",
        );
        accept(
            "field assigned function",
            "local obj = {}\nobj.f = function(x) return x * 3 end\nreturn obj.f(n)",
        );
    }

    #[test]
    fn a18_child_returning_one_and_multiple_ordinary_values() {
        accept(
            "one value",
            "local function c(x) return x * 2 end\nreturn c(n)",
        );
        accept(
            "multi value",
            "local function c(x) return x, x + 1, x + 2 end\nreturn c(n)",
        );
    }

    #[test]
    fn a19_sibling_child_capture() {
        accept(
            "sibling capture",
            "local function base(x) return x * 2 end\nlocal function outer(x) return base(x) + 1 end\nreturn outer(n)",
        );
    }

    #[test]
    fn a20_children_inside_loops_and_branches() {
        accept(
            "loop child",
            "local s = 0\nfor i = 1, 3 do local function f(x) return x + i end s = s + f(n) end\nreturn s",
        );
    }

    #[test]
    fn scratch_loop_reassign_param_escape() {
        let body =
            "local a = {}\nfor i = 1, 2 do\na.f = function() return i end\na = n\nend\nreturn 0";
        let src = seal(body);
        match expand(lower_str(&src).expect("lower"), 0) {
            Ok(_) => println!("SCRATCH: ACCEPTED (escape hole)"),
            Err(e) => println!("SCRATCH: rejected: {e}"),
        }
    }

    #[test]
    fn scratch_while_reassign_param_escape() {
        let body = "local a = {}\nlocal first = true\nwhile true do\na.f = function() return 1 end\nif not first then break end\nfirst = false\na = n\nend\nreturn 0";
        let src = seal(body);
        match expand(lower_str(&src).expect("lower"), 0) {
            Ok(_) => println!("SCRATCH2: ACCEPTED (escape hole)"),
            Err(e) => println!("SCRATCH2: rejected: {e}"),
        }
    }

    #[test]
    fn r01_nested_encfunc() {
        let e = reject(
            "nested encfunc",
            &format!("local g = BASIL_ENCFUNC(function(x) return x end, \"{K}\", rk)\nreturn g(n)"),
        );
        assert!(e.contains("nested"), "nested-ENCFUNC diagnostic, got: {e}");
    }

    #[test]
    fn r02_nested_encfunc_hidden_through_alias_or_parentheses() {
        for (label, body) in [
            ("alias", format!("local E = BASIL_ENCFUNC\nlocal g = E(function(x) return x end, \"{K}\", rk)\nreturn g(n)")),
            ("paren", format!("local g = (BASIL_ENCFUNC)(function(x) return x end, \"{K}\", rk)\nreturn g(n)")),
        ] {
            let e = reject(label, &body);
            assert!(e.contains("BASIL_ENCFUNC"), "[{label}] must name the macro, got: {e}");
        }
    }

    #[test]
    fn r03_no_virtualize_inside_and_hidden_variants() {
        let e = reject(
            "native",
            "local g = BASIL_NO_VIRTUALIZE(function(x) return x end)\nreturn g(n)",
        );
        assert!(
            e.contains("BASIL_NO_VIRTUALIZE"),
            "native diagnostic, got: {e}"
        );
        for (label, body) in [
            (
                "alias",
                "local V = BASIL_NO_VIRTUALIZE\nlocal g = V(function(x) return x end)\nreturn g(n)",
            ),
            (
                "paren",
                "local g = (BASIL_NO_VIRTUALIZE)(function(x) return x end)\nreturn g(n)",
            ),
        ] {
            let e = reject(label, body);
            assert!(
                e.contains("BASIL_NO_VIRTUALIZE"),
                "[{label}] must name the macro, got: {e}"
            );
        }
    }

    #[test]
    fn r04_outer_local_capture() {
        let src = format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal secret = 42\n\
             local f = BASIL_ENCFUNC(function(n) local function c(x) return x + secret end return c(n) end, \"{K}\", rk)\nreturn f(1)\n"
        );
        let e = expand(lower_str(&src).expect("lower"), 0)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("captures the enclosing local"),
            "outer-capture diagnostic, got: {e}"
        );
    }

    #[test]
    fn r05_returned_closure() {
        let e = reject(
            "returned closure",
            "local function c(x) return x end\nreturn c",
        );
        assert!(
            e.contains("escaping closure"),
            "escape diagnostic, got: {e}"
        );
        let e2 = reject("returned literal", "return function(x) return x end");
        assert!(
            e2.contains("escaping closure"),
            "escape diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r06_returned_table_containing_a_closure() {
        let e = reject(
            "returned table",
            "local function c(x) return x end\nreturn { go = c }",
        );
        assert!(
            e.contains("escaping closure"),
            "escape diagnostic, got: {e}"
        );
        let e2 = reject(
            "returned table literal",
            "return { go = function(x) return x end }",
        );
        assert!(
            e2.contains("escaping closure"),
            "escape diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r07_global_and_g_assignment() {
        let e = reject(
            "global",
            "local function c(x) return x end\nLEAK = c\nreturn n",
        );
        assert!(e.contains("global"), "global diagnostic, got: {e}");
        let e2 = reject(
            "_G",
            "local function c(x) return x end\n_G.leak = c\nreturn n",
        );
        assert!(e2.contains("escap"), "_G diagnostic, got: {e2}");
    }

    #[test]
    fn r08_outer_local_assignment_of_a_closure() {
        let src = format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal sink\n\
             local f = BASIL_ENCFUNC(function(n) sink = function(x) return x end return n end, \"{K}\", rk)\nreturn f(1)\n"
        );
        let e = expand(lower_str(&src).expect("lower"), 0)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("escaping closure") || e.contains("captures the enclosing local"),
            "got: {e}"
        );
    }

    #[test]
    fn r09_unknown_callback_consumer() {
        let e = reject(
            "unknown call",
            "local function c(x) return x end\nregister(c)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "unknown-consumer diagnostic, got: {e}"
        );
        let e2 = reject(
            "unknown literal",
            "register(function(x) return x end)\nreturn n",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "unknown-consumer diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r10_event_and_deferred_callbacks() {
        let e = reject(
            "event",
            "local function c() end\nsignal:Connect(c)\nreturn n",
        );
        assert!(
            e.contains("asynchronous callback"),
            "event diagnostic, got: {e}"
        );
        let e2 = reject(
            "deferred",
            "local function c() end\ntask.defer(c)\nreturn n",
        );
        assert!(
            e2.contains("asynchronous callback"),
            "deferred diagnostic, got: {e2}"
        );
        let e3 = reject("spawn", "task.spawn(function() end)\nreturn n");
        assert!(
            e3.contains("asynchronous callback"),
            "spawn diagnostic, got: {e3}"
        );
    }

    #[test]
    fn r11_escaping_table_containing_a_closure() {
        let e = reject(
            "escaping table",
            "local t = { f = function(x) return x end }\nreturn t",
        );
        assert!(
            e.contains("escaping closure"),
            "table-escape diagnostic, got: {e}"
        );
        let e2 = reject(
            "table to unknown call",
            "local t = { f = function(x) return x end }\nsend(t)\nreturn n",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "table-arg diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r12_table_alias_used_to_escape_a_closure() {
        let e = reject(
            "table alias",
            "local t = { f = function(x) return x end }\nlocal u = t\nreturn u",
        );
        assert!(e.contains("escaping closure"), "alias diagnostic, got: {e}");
    }

    #[test]
    fn r13_closure_alias_returned_or_passed_to_an_unknown_call() {
        let e = reject(
            "alias return",
            "local function c(x) return x end\nlocal a = c\nreturn a",
        );
        assert!(
            e.contains("escaping closure"),
            "alias-return diagnostic, got: {e}"
        );
        let e2 = reject(
            "alias call",
            "local function c(x) return x end\nlocal a = c\nsend(a)\nreturn n",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "alias-arg diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r14_closure_read_out_of_a_function_table_then_escapes() {
        let e = reject(
            "read out and return",
            "local t = { f = function(x) return x end }\nlocal g = t.f\nreturn g",
        );
        assert!(
            e.contains("escaping closure"),
            "field-read escape diagnostic, got: {e}"
        );
        let e2 = reject(
            "index out and return",
            "local t = { f = function(x) return x end }\nlocal g = t[\"f\"]\nreturn g",
        );
        assert!(
            e2.contains("escaping closure"),
            "index-read escape diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r15_callback_hidden_through_an_alias_chain() {
        let e = reject(
            "alias chain",
            "local function c(x) return x end\nlocal a = c\nlocal b = a\nregister(b)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "chain diagnostic, got: {e}"
        );
    }

    #[test]
    fn r16_closure_captured_by_an_escaping_closure() {
        let e = reject(
            "captured by escaping",
            "local function inner(x) return x end\nlocal function outer(x) return inner(x) end\nreturn outer",
        );
        assert!(
            e.contains("escaping closure"),
            "capture diagnostic, got: {e}"
        );
    }

    #[test]
    fn r17_nested_function_returning_a_closure() {
        let e = reject(
            "factory",
            "local function make() return function(x) return x end end\nlocal g = make()\nreturn g(n)",
        );
        assert!(
            e.contains("escaping closure"),
            "factory diagnostic, got: {e}"
        );
    }

    #[test]
    fn r18_function_table_passed_to_an_unknown_call() {
        let e = reject(
            "function table arg",
            "local ops = {}\nfunction ops.go(x) return x end\ninstall(ops)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "function-table-arg diagnostic, got: {e}"
        );
    }

    #[test]
    fn r19_child_stored_into_an_outer_object() {
        let src = format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal host = {{}}\n\
             local f = BASIL_ENCFUNC(function(n) host.cb = function(x) return x end return n end, \"{K}\", rk)\nreturn f(1)\n"
        );
        let e = expand(lower_str(&src).expect("lower"), 0)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("escapes the sealed body") || e.contains("captures the enclosing local"),
            "outer-object diagnostic, got: {e}"
        );
    }

    #[test]
    fn r20_global_function_declaration_inside_the_sealed_body() {
        let e = reject(
            "global fn decl",
            "function LeakedHelper(x) return x end\nreturn n",
        );
        assert!(e.contains("global"), "global-decl diagnostic, got: {e}");
    }

    #[test]
    fn r21_ambiguous_positions_reject() {
        let e = reject(
            "binop",
            "local function c(x) return x end\nlocal v = c or 1\nreturn n",
        );
        assert!(
            e.contains("ambiguous") || e.contains("escap"),
            "ambiguous diagnostic, got: {e}"
        );
        let e2 = reject("interp", "local function c(x) return x end\nreturn `{c}`");
        assert!(
            e2.contains("ambiguous") || e2.contains("escap"),
            "interp diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r22_table_sort_rejects_a_function_table_as_the_list() {
        let e = reject(
            "sort function table",
            "local t = { function(x) return x end }\ntable.sort(t, function(a, b) return true end)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "sort-list diagnostic, got: {e}"
        );
    }

    #[test]
    fn r23_shadowed_table_sort_is_not_allowlisted() {
        let e = reject(
            "shadowed table",
            "local table = { sort = function(a, b) return a end }\n\
             local function cmp(a, b) return a < b end\ntable.sort({ 1 }, cmp)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "shadowed-allowlist diagnostic, got: {e}"
        );
    }

    #[test]
    fn a21_pcall_synchronous_callback_literal_and_helper() {
        accept(
            "pcall literal",
            "local ok, r = pcall(function() return n * 2 end)\nreturn ok, r",
        );
        accept(
            "pcall helper",
            "local function work() return n * 2 end\nlocal ok, r = pcall(work)\nreturn ok, r",
        );
    }

    #[test]
    fn a22_pcall_callback_mutates_a_captured_body_local() {
        accept(
            "pcall mutate capture",
            "local acc = 0\nlocal function bump() acc = acc + n end\nlocal ok = pcall(bump)\nreturn ok, acc",
        );
    }

    #[test]
    fn a23_xpcall_callback_and_handler_literal_and_helper() {
        accept(
            "xpcall literal",
            "local ok, r = xpcall(function() error(n) end, function(m) return \"h:\" .. tostring(m) end)\nreturn ok, r",
        );
        accept(
            "xpcall helpers",
            "local function work() error(n) end\nlocal function handle(m) return tostring(m) end\nlocal ok, r = xpcall(work, handle)\nreturn ok, r",
        );
    }

    #[test]
    fn a24_xpcall_handler_mutates_shared_state() {
        accept(
            "xpcall handler mutate",
            "local fails = 0\nlocal function work() error(n) end\nlocal function handle(m) fails = fails + 1 return m end\n\
             local ok = xpcall(work, handle)\nreturn ok, fails",
        );
    }

    #[test]
    fn a25_gsub_function_replacement_literal_helper_and_callback_alias() {
        accept("gsub literal", "local s = string.gsub(\"a b\", \"%a+\", function(w) return \"[\" .. w .. \"]\" end)\nreturn s");
        accept(
            "gsub helper",
            "local count = 0\nlocal function rep(w) count = count + 1 return \"[\" .. w .. \"]\" end\n\
             local s = string.gsub(\"a b\", \"%a+\", rep)\nreturn s, count",
        );
        accept(
            "gsub callback alias",
            "local function rep(w) return w end\nlocal alias = rep\nlocal s = string.gsub(\"ab\", \"%a\", alias)\nreturn s",
        );
    }

    #[test]
    fn a26_recursion_used_from_an_allowed_callback() {
        accept(
            "pcall recursion",
            "local function fac(x) if x <= 1 then return 1 end return x * fac(x - 1) end\nlocal ok, r = pcall(fac, n)\nreturn ok, r",
        );
    }

    #[test]
    fn r24_shadowed_pcall_is_not_allowlisted() {
        let e = reject(
            "shadowed pcall",
            "local pcall = function(g) return 0 end\nlocal function work() return n end\npcall(work)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "shadowed-pcall diagnostic, got: {e}"
        );
    }

    #[test]
    fn r25_shadowed_xpcall_is_not_allowlisted() {
        let e = reject(
            "shadowed xpcall",
            "local xpcall = function(a, b) return 0 end\nlocal function work() return n end\n\
             local function handle(m) return m end\nxpcall(work, handle)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "shadowed-xpcall diagnostic, got: {e}"
        );
    }

    #[test]
    fn r26_shadowed_string_gsub_is_not_allowlisted() {
        let e = reject(
            "shadowed string",
            "local string = { gsub = function(a, b, c) return a end }\nlocal function rep(w) return w end\n\
             string.gsub(\"ab\", \"%a\", rep)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "shadowed-string diagnostic, got: {e}"
        );
    }

    #[test]
    fn r27_aliased_pcall_and_xpcall_consumers_reject() {
        let e = reject(
            "pcall alias",
            "local protectedCall = pcall\nlocal function work() return n end\nprotectedCall(work)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "pcall-alias diagnostic, got: {e}"
        );
        let e2 = reject(
            "xpcall alias",
            "local xp = xpcall\nlocal function work() return n end\nlocal function h(m) return m end\nxp(work, h)\nreturn n",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "xpcall-alias diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r28_aliased_string_gsub_consumer_rejects() {
        let e = reject(
            "gsub alias",
            "local g = string.gsub\nlocal function rep(w) return w end\ng(\"ab\", \"%a\", rep)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "gsub-alias diagnostic, got: {e}"
        );
    }

    #[test]
    fn r29_dynamic_pcall_lookup_rejects() {
        let e = reject(
            "_G.pcall",
            "local function work() return n end\n_G.pcall(work)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "dynamic-_G-pcall diagnostic, got: {e}"
        );
        let e2 = reject(
            "env index pcall",
            "local env = {}\nlocal function work() return n end\nenv[\"pcall\"](work)\nreturn n",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "env-index-pcall diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r30_dynamic_index_and_method_gsub_reject() {
        let e = reject(
            "gsub index",
            "local function rep(w) return w end\nlocal s = string[\"gsub\"](\"ab\", \"%a\", rep)\nreturn s",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "gsub-index diagnostic, got: {e}"
        );
        let e2 = reject(
            "gsub method",
            "local function rep(w) return w end\nlocal s = (\"ab\"):gsub(\"%a\", rep)\nreturn s",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "gsub-method diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r31_function_bearing_pcall_argument_after_the_callback_rejects() {
        let e = reject(
            "pcall extra fn",
            "local function work() return n end\nlocal function extra() return n end\npcall(work, extra)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "pcall-extra-arg diagnostic, got: {e}"
        );
    }

    #[test]
    fn r32_function_bearing_xpcall_argument_after_the_handler_rejects() {
        let e = reject(
            "xpcall extra fn",
            "local function work() return n end\nlocal function handle(m) return m end\nlocal function extra() return n end\n\
             xpcall(work, handle, extra)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "xpcall-extra-arg diagnostic, got: {e}"
        );
    }

    #[test]
    fn r33_function_bearing_gsub_arguments_outside_the_replacement_reject() {
        let e = reject(
            "gsub fn subject",
            "local function subj() return \"x\" end\nlocal function rep(w) return w end\nstring.gsub(subj, \"%a\", rep)\nreturn n",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "gsub-subject diagnostic, got: {e}"
        );
        let e2 = reject(
            "gsub fn limit",
            "local function rep(w) return w end\nlocal function lim() return 1 end\nstring.gsub(\"ab\", \"%a\", rep, lim)\nreturn n",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "gsub-limit diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r34_gsub_replacement_table_with_a_closure_rejects() {
        let e = reject(
            "gsub table closure",
            "local tbl = { a = function() return n end }\nlocal s = string.gsub(\"a\", \"%a\", tbl)\nreturn s",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "gsub-table-closure diagnostic, got: {e}"
        );
    }

    #[test]
    fn r35_allowed_callback_returning_a_closure_rejects() {
        let e = reject(
            "pcall return closure",
            "local ok = pcall(function() return function() return n end end)\nreturn ok",
        );
        assert!(
            e.contains("escaping closure"),
            "callback-return-closure diagnostic, got: {e}"
        );
        let e2 = reject(
            "gsub return table closure",
            "local s = string.gsub(\"a\", \"%a\", function(w) return { f = function() return w end } end)\nreturn s",
        );
        assert!(
            e2.contains("escaping closure"),
            "callback-return-table diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r36_allowed_callback_storing_a_closure_into_a_global_rejects() {
        let e = reject(
            "pcall store global",
            "local ok = pcall(function() LEAK = function() return n end return 1 end)\nreturn ok",
        );
        assert!(
            e.contains("global") || e.contains("escap"),
            "callback-global-store diagnostic, got: {e}"
        );
    }

    #[test]
    fn r37_async_inside_an_allowed_callback_still_rejects() {
        let e = reject("pcall wrapping spawn", "local ok = pcall(function() task.spawn(function() return n end) return 1 end)\nreturn ok");
        assert!(
            e.contains("asynchronous callback"),
            "async-in-pcall diagnostic, got: {e}"
        );
        let e2 = reject(
            "gsub wrapping coroutine",
            "local s = string.gsub(\"a\", \"%a\", function(w) coroutine.wrap(function() return w end) return w end)\nreturn s",
        );
        assert!(
            e2.contains("asynchronous callback"),
            "coroutine-in-gsub diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r38_allowed_callback_capturing_an_outer_local_rejects() {
        let src = format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal secret = 42\n\
             local f = BASIL_ENCFUNC(function(n) local ok, r = pcall(function() return n + secret end) return ok, r end, \"{K}\", rk)\nreturn f(1)\n"
        );
        let e = expand(lower_str(&src).expect("lower"), 0)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("captures the enclosing local"),
            "outer-capture-via-callback diagnostic, got: {e}"
        );
    }

    #[test]
    fn r39_allowed_callback_storing_into_an_outer_object_rejects() {
        let src = format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal host = {{}}\n\
             local f = BASIL_ENCFUNC(function(n) pcall(function() host.cb = function() return n end return 1 end) return n end, \"{K}\", rk)\nreturn f(1)\n"
        );
        let e = expand(lower_str(&src).expect("lower"), 0)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("captures the enclosing local") || e.contains("escapes the sealed body"),
            "outer-object-via-callback diagnostic, got: {e}"
        );
    }

    #[test]
    fn r40_nested_macros_and_events_inside_an_allowed_callback_reject() {
        let e = reject("event in callback", "local ok = pcall(function() signal:Connect(function() return n end) return 1 end)\nreturn ok");
        assert!(
            e.contains("asynchronous callback"),
            "event-in-callback diagnostic, got: {e}"
        );
        let e2 = reject(
            "no_virtualize in callback",
            "local ok = pcall(function() local g = BASIL_NO_VIRTUALIZE(function() return n end) return g() end)\nreturn ok",
        );
        assert!(
            e2.contains("BASIL_NO_VIRTUALIZE"),
            "native-in-callback diagnostic, got: {e2}"
        );
        let e3 = reject(
            "nested encfunc in callback",
            &format!("local ok = pcall(function() local h = BASIL_ENCFUNC(function(x) return x end, \"{K}\", rk) return h(1) end)\nreturn ok"),
        );
        assert!(
            e3.contains("nested") || e3.contains("BASIL_ENCFUNC"),
            "nested-encfunc-in-callback diagnostic, got: {e3}"
        );
    }

    #[test]
    fn a27_parenthesized_bare_consumer_is_still_the_real_global() {
        accept(
            "paren pcall",
            "local ok, r = (pcall)(function() return n * 2 end)\nreturn ok, r",
        );
        accept("paren gsub base", "local function rep(w) return w end\nlocal s = (string).gsub(\"ab\", \"%a\", rep)\nreturn s");
    }

    #[test]
    fn r41_reassigned_consumer_global_is_not_allowlisted() {
        let e = reject(
            "reassigned pcall",
            "pcall = register\nlocal ok = pcall(function() return n end)\nreturn ok",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "reassigned-pcall diagnostic, got: {e}"
        );
        let e2 = reject(
            "reassigned xpcall",
            "xpcall = register\nlocal function h(m) return m end\nlocal ok = xpcall(function() return n end, h)\nreturn ok",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "reassigned-xpcall diagnostic, got: {e2}"
        );
        let e3 = reject(
            "reassigned table",
            "table = other\nlocal t = { 3, 1, 2 }\ntable.sort(t, function(a, b) return a < b end)\nreturn n",
        );
        assert!(
            e3.contains("unknown retaining callback"),
            "reassigned-table diagnostic, got: {e3}"
        );
        let e4 = reject(
            "reassigned string",
            "string = other\nlocal function rep(w) return w end\nstring.gsub(\"ab\", \"%a\", rep)\nreturn n",
        );
        assert!(
            e4.contains("unknown retaining callback"),
            "reassigned-string diagnostic, got: {e4}"
        );
    }

    #[test]
    fn r42_reassignment_before_or_after_the_callback_use_both_reject() {
        let e = reject(
            "callback use before reassign",
            "local ok = pcall(function() return n end)\npcall = register\nreturn ok",
        );
        assert!(
            e.contains("unknown retaining callback"),
            "pre-reassign-use diagnostic, got: {e}"
        );
        let e2 = reject(
            "shadowed base through parens",
            "local string = { gsub = function(a, b, c) return a end }\nlocal function rep(w) return w end\n\
             local s = (string).gsub(\"ab\", \"%a\", rep)\nreturn s",
        );
        assert!(
            e2.contains("unknown retaining callback"),
            "paren-shadow diagnostic, got: {e2}"
        );
    }

    #[test]
    fn a28_owned_local_function_table_store() {
        accept("owned field store", "local handlers = {}\nhandlers.run = function(v) return v * 2 end\nreturn handlers.run(5)");
    }

    #[test]
    fn a29_owned_method_and_field_declarations() {
        accept(
            "owned method decls",
            "local handlers = {}\nfunction handlers.run(v) return v + 1 end\nfunction handlers:method(v) return v + 2 end\nreturn handlers.run(1)",
        );
    }

    #[test]
    fn a30_owned_alias_function_store() {
        accept(
            "owned alias store",
            "local handlers = {}\nlocal alias = handlers\nalias.run = function(v) return v * 3 end\nreturn handlers.run(4)",
        );
    }

    #[test]
    fn a31_declare_then_assign_owned_then_store() {
        accept("decl then assign owned", "local handlers\nhandlers = {}\nhandlers.run = function() return 7 end\nreturn handlers.run()");
    }

    #[test]
    fn a32_branch_join_of_two_owned_tables_stores() {
        accept("branch both owned", "local t\nif n > 0 then t = {} else t = {} end\nt.run = function() return 1 end\nreturn t.run()");
    }

    #[test]
    fn a33_non_closure_store_into_a_parameter_table_is_still_allowed() {
        accept(
            "param non-closure store",
            "n.count = 5\nn.label = \"x\"\nreturn n.count",
        );
    }

    #[test]
    fn a34_non_closure_store_into_a_call_result_local_is_still_allowed() {
        accept(
            "call-result non-closure store",
            "local cfg = getConfig()\ncfg.x = 5\nreturn 1",
        );
    }

    #[test]
    fn a35_returning_a_non_function_owned_table_is_allowed() {
        accept(
            "return owned data table",
            "local data = { x = 1, y = 2 }\nreturn data",
        );
    }

    #[test]
    fn r43_closure_stored_into_a_parameter_table_rejects() {
        let e = reject(
            "param assign store",
            "n.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("borrowed") && e.contains("escaping table"),
            "param-store diagnostic, got: {e}"
        );
        let e2 = reject(
            "param method decl",
            "function n.cb(v) return v end\nreturn 1",
        );
        assert!(
            e2.contains("borrowed"),
            "param-method diagnostic, got: {e2}"
        );
        let e3 = reject(
            "param colon method decl",
            "function n:cb(v) return v end\nreturn 1",
        );
        assert!(
            e3.contains("borrowed"),
            "param-colon-method diagnostic, got: {e3}"
        );
    }

    #[test]
    fn r44_closure_stored_through_parameter_aliases_rejects() {
        let e = reject(
            "param alias",
            "local p = n\np.cb = function() return 1 end\nreturn 1",
        );
        assert!(e.contains("borrowed"), "param-alias diagnostic, got: {e}");
        let e2 = reject(
            "double param alias",
            "local p = n\nlocal q = p\nq.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e2.contains("borrowed"),
            "double-param-alias diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r45_closure_stored_into_globals_and_g_rejects() {
        let e = reject(
            "_G alias",
            "local x = _G\nx.cb = function() return 1 end\nreturn 1",
        );
        assert!(e.contains("borrowed"), "_G-alias diagnostic, got: {e}");
        let e2 = reject("_G direct", "_G.cb = function() return 1 end\nreturn 1");
        assert!(e2.contains("borrowed"), "_G-direct diagnostic, got: {e2}");
        let e3 = reject(
            "global table",
            "sharedTable.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e3.contains("borrowed"),
            "global-table diagnostic, got: {e3}"
        );
        let e4 = reject(
            "global table alias",
            "local x = sharedTable\nx.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e4.contains("borrowed"),
            "global-table-alias diagnostic, got: {e4}"
        );
    }

    #[test]
    fn r46_closure_stored_into_a_call_result_rejects() {
        let e = reject(
            "call result",
            "local x = getExternalTable()\nx.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("ownership cannot be proven"),
            "call-result diagnostic, got: {e}"
        );
        let e2 = reject(
            "call result alias",
            "local x = factory()\nlocal y = x\ny.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e2.contains("ownership cannot be proven"),
            "call-result-alias diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r47_closure_stored_into_method_call_and_dynamic_index_results_rejects() {
        let e = reject(
            "method call result",
            "local x = obj:GetTable()\nx.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("ownership cannot be proven"),
            "method-result diagnostic, got: {e}"
        );
        let e2 = reject(
            "index result",
            "local x = env[\"t\"]\nx.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e2.contains("ownership cannot be proven"),
            "index-result diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r48_owned_reassigned_to_borrowed_or_unknown_before_store_rejects() {
        let e = reject(
            "owned to borrowed",
            "local h = {}\nh = sharedTable\nh.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("borrowed"),
            "owned-to-borrowed diagnostic, got: {e}"
        );
        let e2 = reject(
            "owned to unknown",
            "local h = {}\nh = factory()\nh.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e2.contains("ownership cannot be proven"),
            "owned-to-unknown diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r49_branch_join_of_owned_and_borrowed_rejects() {
        let e = reject(
            "branch owned borrowed",
            "local t\nif n > 0 then t = {} else t = sharedTable end\nt.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("escaping table"),
            "branch-join diagnostic, got: {e}"
        );
    }

    #[test]
    fn r50_loop_that_may_replace_owned_with_borrowed_rejects() {
        let e = reject(
            "loop replace owned",
            "local t = {}\nfor i = 1, 3 do if n > 0 then t = sharedTable end end\nt.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("escaping table"),
            "loop-replace diagnostic, got: {e}"
        );
    }

    #[test]
    fn r51_nested_field_stores_reject_conservatively() {
        let e = reject(
            "external nested field",
            "local root = {}\nroot.child = sharedTable\nroot.child.run = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("ownership cannot be proven"),
            "external-nested diagnostic, got: {e}"
        );
        let e2 = reject(
            "unknown nested field",
            "local root = {}\nroot.child = factory()\nroot.child.run = function() return 1 end\nreturn 1",
        );
        assert!(
            e2.contains("ownership cannot be proven"),
            "unknown-nested diagnostic, got: {e2}"
        );
        let e3 = reject(
            "constructor nested is conservatively rejected",
            "local state = { nested = {} }\nstate.nested.run = function() return 1 end\nreturn 1",
        );
        assert!(
            e3.contains("ownership cannot be proven"),
            "constructor-nested diagnostic, got: {e3}"
        );
    }

    #[test]
    fn r52_borrowed_read_out_of_an_owned_container_then_used_rejects() {
        let e = reject(
            "borrowed from container",
            "local root = {}\nroot.child = n\nlocal c = root.child\nc.run = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("ownership cannot be proven"),
            "container-read diagnostic, got: {e}"
        );
    }

    #[test]
    fn r53_storing_a_table_of_closures_into_a_borrowed_target_rejects() {
        let e = reject(
            "table with closure into param",
            "n.data = { run = function() return 1 end }\nreturn 1",
        );
        assert!(
            e.contains("borrowed"),
            "table-of-closures diagnostic, got: {e}"
        );
    }

    #[test]
    fn r54_dynamic_key_closure_store_on_borrowed_or_unknown_base_rejects() {
        let e = reject(
            "dynamic key on param",
            "n[keyName] = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("borrowed"),
            "dynamic-key-param diagnostic, got: {e}"
        );
        let e2 = reject(
            "dynamic key on call result",
            "local x = factory()\nx[keyName] = function() return 1 end\nreturn 1",
        );
        assert!(
            e2.contains("ownership cannot be proven"),
            "dynamic-key-unknown diagnostic, got: {e2}"
        );
    }

    #[test]
    fn r55_method_declaration_on_borrowed_unknown_or_nested_base_rejects() {
        let e = reject(
            "method decl on call result",
            "local x = factory()\nfunction x.m(v) return v end\nreturn 1",
        );
        assert!(
            e.contains("ownership cannot be proven"),
            "method-on-unknown diagnostic, got: {e}"
        );
        let e2 = reject(
            "nested method decl",
            "local root = {}\nfunction root.child.m(v) return v end\nreturn 1",
        );
        assert!(
            e2.contains("ownership cannot be proven"),
            "nested-method-decl diagnostic, got: {e2}"
        );
    }

    #[test]
    fn a36_stores_into_owned_tables_via_dynamic_key_and_parentheses() {
        accept(
            "dynamic key into owned",
            "local h = {}\nh[\"k\"] = function() return 1 end\nreturn h.k()",
        );
        accept(
            "paren owned store",
            "local h = ({})\nh.run = function() return 1 end\nreturn h.run()",
        );
    }

    #[test]
    fn a37_non_closure_store_into_self_inside_a_method_is_allowed() {
        accept(
            "self non-closure store",
            "local obj = {}\nfunction obj:setup() self.count = 5 return self.count end\nreturn obj:setup()",
        );
    }

    #[test]
    fn r56_owned_table_stored_into_another_then_returned_rejects() {
        let e = reject(
            "child aliased into root then returned",
            "local root = {}\nlocal child = {}\nroot.child = child\nchild.run = function() return 1 end\nreturn root",
        );
        assert!(
            e.contains("escaping closure"),
            "container-escape diagnostic, got: {e}"
        );
    }

    #[test]
    fn r57_closure_store_into_self_inside_a_method_rejects() {
        let e = reject(
            "self closure store",
            "local obj = {}\nfunction obj:setup() self.cb = function() return 1 end end\nreturn obj:setup()",
        );
        assert!(
            e.contains("borrowed") || e.contains("escaping table"),
            "self-store diagnostic, got: {e}"
        );
    }

    #[test]
    fn r58_alias_cycles_and_parenthesized_params_reject() {
        let e = reject(
            "alias cycle to param",
            "local a = n\nlocal b = a\na = b\nb.cb = function() return 1 end\nreturn 1",
        );
        assert!(e.contains("borrowed"), "alias-cycle diagnostic, got: {e}");
        let e2 = reject(
            "paren param store",
            "local p = (n)\np.cb = function() return 1 end\nreturn 1",
        );
        assert!(e2.contains("borrowed"), "paren-param diagnostic, got: {e2}");
    }

    #[test]
    fn r59_owned_table_holding_a_closure_cannot_escape() {
        let e = reject(
            "owned with closure returned via alias",
            "local h = {}\nh.run = function() return 1 end\nlocal g = h\nreturn g",
        );
        assert!(
            e.contains("escaping closure"),
            "alias-return diagnostic, got: {e}"
        );
        let e2 = reject(
            "owned with closure in multi-return",
            "local h = {}\nh.run = function() return 1 end\nreturn n, h",
        );
        assert!(
            e2.contains("escaping closure"),
            "multi-return diagnostic, got: {e2}"
        );
        let e3 = reject(
            "owned with closure to unknown consumer",
            "local h = {}\nh.run = function() return 1 end\nsend(h)\nreturn 1",
        );
        assert!(
            e3.contains("unknown retaining callback"),
            "consumer diagnostic, got: {e3}"
        );
    }

    #[test]
    fn r60_owned_reassigned_via_alias_to_unknown_before_store_rejects() {
        let e = reject(
            "owned to unknown via alias",
            "local a = {}\nlocal b = factory()\na = b\na.cb = function() return 1 end\nreturn 1",
        );
        assert!(
            e.contains("ownership cannot be proven"),
            "reassign-via-alias diagnostic, got: {e}"
        );
    }

    #[test]
    fn r61_closure_store_inside_a_loop_that_later_reassigns_the_base_rejects() {
        let e = reject(
            "for-loop store then foreign reassign",
            "local x = {}\nfor i = 1, 2 do\nx.f = function() return n end\nx = _G\nend\nreturn n",
        );
        assert!(
            e.contains("borrowed"),
            "for-loop-store diagnostic, got: {e}"
        );
        let e2 = reject(
            "while-loop store then foreign reassign",
            "local x = {}\nwhile n > 0 do\nx.f = function() return n end\nx = sharedTable\nn = n - 1\nend\nreturn 1",
        );
        assert!(
            e2.contains("borrowed"),
            "while-loop-store diagnostic, got: {e2}"
        );
        let e3 = reject(
            "loop method decl then foreign reassign",
            "local x = {}\nfor i = 1, 2 do\nfunction x.m() return i end\nx = _G\nend\nreturn n",
        );
        assert!(e3.contains("borrowed"), "loop-method diagnostic, got: {e3}");
        let e4 = reject(
            "loop dynamic-key store then foreign reassign",
            "local x = {}\nfor i = 1, 2 do\nx[i] = function() return i end\nx = sharedTable\nend\nreturn n",
        );
        assert!(e4.contains("borrowed"), "loop-dynkey diagnostic, got: {e4}");
        let e5 = reject(
            "repeat-loop store then foreign reassign",
            "local x = {}\nrepeat\nx.f = function() return n end\nx = _G\nuntil n > 0\nreturn n",
        );
        assert!(
            e5.contains("borrowed"),
            "repeat-loop-store diagnostic, got: {e5}"
        );
        let e6 = reject(
            "sibling-branch store and foreign reassign in a loop",
            "local x = {}\nfor i = 1, 2 do\nif n > 0 then x.f = function() return n end else x = _G end\nend\nreturn n",
        );
        assert!(
            e6.contains("borrowed"),
            "loop-sibling diagnostic, got: {e6}"
        );
    }
}

#[cfg(test)]
mod alias_regressions {
    use crate::lower_str;
    use crate::macros::expand;
    const K: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn table_alias_written_through_one_name_and_escaped_through_the_other() {
        let src = format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal f = BASIL_ENCFUNC(function(n)\n\
             local t = {{}}\nlocal u = t\nu.cb = function(x) return x end\nreturn t\n\
             end, \"{K}\", rk)\nreturn f(1)\n"
        );
        let r = expand(lower_str(&src).expect("lower"), 0);
        assert!(
            r.is_err(),
            "a closure added through an alias and escaped through the original must be rejected"
        );
    }

    #[test]
    fn closure_alias_written_through_one_name_and_escaped_through_the_other() {
        let src = format!(
            "local rk = BASILISK_RUNTIME_KEY\nlocal f = BASIL_ENCFUNC(function(n)\n\
             local a\nlocal b = a\na = function(x) return x end\nreturn b\n\
             end, \"{K}\", rk)\nreturn f(1)\n"
        );
        let r = expand(lower_str(&src).expect("lower"), 0);
        assert!(
            r.is_err(),
            "a closure reachable through an alias must not escape through either name"
        );
    }
}
