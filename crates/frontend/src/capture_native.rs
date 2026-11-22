use std::collections::HashSet;

use ir::{Block, Expr, Field, FuncBody, InterpPart, LastStmt, Param, Stmt};

use crate::Error;

const NO_VIRTUALIZE: &str = "BASIL_NO_VIRTUALIZE";

type Bid = u32;

pub fn promote(block: &mut Block) -> Result<(), Error> {
    let mut a = Analyze::default();
    a.block(block);
    let cells: HashSet<Bid> = a.captured.intersection(&a.assigned).copied().collect();
    if std::env::var_os("BASIL_CAPTURE_STATS").is_some() {
        eprintln!("basilisk_capture_stats {}", stats(block, &cells));
    }
    if cells.is_empty() {
        return Ok(());
    }
    let mut r = Rewrite {
        next_id: 0,
        env: Vec::new(),
        cells,
    };
    r.block(block)
}

#[derive(Default)]
pub struct CaptureStats {
    pub direct_natives: usize,
    pub factory_natives: usize,
    pub total_capture_args: usize,
    pub snapshot_capture_args: usize,
    pub cell_capture_args: usize,
    pub promoted_cell_bindings: usize,
}

impl std::fmt::Display for CaptureStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "direct={} factory={} capture_args={} snapshot_args={} cell_args={} promoted_bindings={}",
            self.direct_natives, self.factory_natives, self.total_capture_args,
            self.snapshot_capture_args, self.cell_capture_args, self.promoted_cell_bindings
        )
    }
}

pub fn stats(block: &Block, cells: &HashSet<Bid>) -> CaptureStats {
    let mut c = Count {
        next_id: 0,
        env: Vec::new(),
        native: None,
        cells,
        out: CaptureStats::default(),
    };
    c.out.promoted_cell_bindings = cells.len();
    c.block(block);
    c.out
}

fn is_no_virt(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, args, .. }
        if matches!(&**func, Expr::Name(n) if n == NO_VIRTUALIZE) && args.len() == 1
           && matches!(args.first(), Some(Expr::Function(_))))
}

fn box_assign(name: &str) -> Stmt {
    Stmt::Assign {
        targets: vec![Expr::Name(name.to_string())],
        exprs: vec![Expr::Table(vec![Field::Positional(Expr::Name(
            name.to_string(),
        ))])],
    }
}

fn boxed_read(name: &str) -> Expr {
    Expr::Index {
        base: Box::new(Expr::Name(name.to_string())),
        key: Box::new(Expr::Number("1".to_string())),
    }
}

#[derive(Default)]
struct Analyze {
    next_id: Bid,
    env: Vec<Vec<(String, Bid)>>,
    native_floor: Option<usize>,
    captured: HashSet<Bid>,
    assigned: HashSet<Bid>,
}

impl Analyze {
    fn declare(&mut self, name: &str) -> Bid {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(top) = self.env.last_mut() {
            top.push((name.to_string(), id));
        }
        id
    }

    fn resolve(&self, name: &str) -> Option<(usize, Bid)> {
        for (i, frame) in self.env.iter().enumerate().rev() {
            for (n, id) in frame.iter().rev() {
                if n == name {
                    return Some((i, *id));
                }
            }
        }
        None
    }

    fn read(&mut self, name: &str) {
        if let (Some((frame, id)), Some(floor)) = (self.resolve(name), self.native_floor) {
            if frame < floor {
                self.captured.insert(id);
            }
        }
    }

    fn write(&mut self, name: &str) {
        if let Some((frame, id)) = self.resolve(name) {
            self.assigned.insert(id);
            if let Some(floor) = self.native_floor {
                if frame < floor {
                    self.captured.insert(id);
                }
            }
        }
    }

    fn block(&mut self, b: &Block) {
        self.env.push(Vec::new());
        self.body(b);
        self.env.pop();
    }

    fn body(&mut self, b: &Block) {
        for s in &b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &b.last {
            for e in es {
                self.expr(e);
            }
        }
    }

    fn func(&mut self, body: &FuncBody, has_self: bool, native: bool) {
        let saved = self.native_floor;
        self.env.push(Vec::new());
        if native {
            self.native_floor = Some(self.env.len() - 1);
        }
        if has_self {
            self.declare("self");
        }
        for p in &body.params {
            if let Param::Name(n) = p {
                self.declare(n);
            }
        }
        self.body(&body.block);
        self.env.pop();
        self.native_floor = saved;
    }

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Local { names, exprs } => {
                for e in exprs {
                    self.expr(e);
                }
                for n in names {
                    self.declare(n);
                }
            }
            Stmt::Assign { targets, exprs } => {
                for t in targets {
                    self.target(t);
                }
                for e in exprs {
                    self.expr(e);
                }
            }
            Stmt::Compound { target, value, .. } => {
                self.target(target);
                self.expr(value);
            }
            Stmt::Call(e) => self.expr(e),
            Stmt::Do(b) => self.block(b),
            Stmt::While { cond, body } => {
                self.expr(cond);
                self.block(body);
            }
            Stmt::Repeat { body, until } => {
                self.env.push(Vec::new());
                self.body(body);
                self.expr(until);
                self.env.pop();
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
                self.env.push(Vec::new());
                self.declare(var);
                self.body(body);
                self.env.pop();
            }
            Stmt::GenericFor { names, exprs, body } => {
                for e in exprs {
                    self.expr(e);
                }
                self.env.push(Vec::new());
                for n in names {
                    self.declare(n);
                }
                self.body(body);
                self.env.pop();
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond);
                self.block(body);
                for (c, b) in else_ifs {
                    self.expr(c);
                    self.block(b);
                }
                if let Some(b) = otherwise {
                    self.block(b);
                }
            }
            Stmt::Function { name, body } => {
                if name.method.is_none() && name.path.len() == 1 {
                    self.write(&name.path[0]);
                } else {
                    self.read(&name.path[0]);
                }
                self.func(body, name.method.is_some(), false);
            }
            Stmt::LocalFunction { name, body } => {
                self.declare(name);
                self.func(body, false, false);
            }
        }
    }

    fn target(&mut self, t: &Expr) {
        match t {
            Expr::Name(n) => self.write(n),
            Expr::Field { base, .. } => self.expr(base),
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
            Expr::Paren(x) => self.target(x),
            other => self.expr(other),
        }
    }

    fn expr(&mut self, e: &Expr) {
        if is_no_virt(e) {
            if let Expr::Call { args, .. } = e {
                if let Some(Expr::Function(fb)) = args.first() {
                    self.func(fb, false, true);
                }
            }
            return;
        }
        match e {
            Expr::Name(n) => self.read(n),
            Expr::Function(fb) => self.func(fb, false, false),
            Expr::Call { func, args, .. } => {
                self.expr(func);
                for a in args {
                    self.expr(a);
                }
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                for a in args {
                    self.expr(a);
                }
            }
            Expr::Field { base, .. } => self.expr(base),
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
            Expr::Paren(x) | Expr::Unop { expr: x, .. } => self.expr(x),
            Expr::Binop { lhs, rhs, .. } => {
                self.expr(lhs);
                self.expr(rhs);
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
                    if let InterpPart::Expr(x) = p {
                        self.expr(x);
                    }
                }
            }
            Expr::EncFunc { key, .. } => self.expr(key),
            Expr::Nil
            | Expr::True
            | Expr::False
            | Expr::Vararg
            | Expr::Number(_)
            | Expr::Str(_)
            | Expr::NativeRef(_)
            | Expr::OpcodeHint { .. }
            | Expr::Crash => {}
        }
    }
}

struct Rewrite {
    next_id: Bid,
    env: Vec<Vec<(String, Bid)>>,
    cells: HashSet<Bid>,
}

impl Rewrite {
    fn declare(&mut self, name: &str) -> Bid {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(top) = self.env.last_mut() {
            top.push((name.to_string(), id));
        }
        id
    }

    fn resolve(&self, name: &str) -> Option<Bid> {
        for frame in self.env.iter().rev() {
            for (n, id) in frame.iter().rev() {
                if n == name {
                    return Some(*id);
                }
            }
        }
        None
    }

    fn is_cell(&self, name: &str) -> bool {
        self.resolve(name)
            .is_some_and(|id| self.cells.contains(&id))
    }

    fn block(&mut self, b: &mut Block) -> Result<(), Error> {
        self.env.push(Vec::new());
        self.body(b)?;
        self.env.pop();
        Ok(())
    }

    fn body(&mut self, b: &mut Block) -> Result<(), Error> {
        let old = std::mem::take(&mut b.stmts);
        let mut out = Vec::with_capacity(old.len());
        for mut s in old {
            let append = self.stmt(&mut s)?;
            out.push(s);
            for name in append {
                out.push(box_assign(&name));
            }
        }
        b.stmts = out;
        if let Some(LastStmt::Return(es)) = &mut b.last {
            for e in es {
                self.expr(e)?;
            }
        }
        Ok(())
    }

    fn func(&mut self, body: &mut FuncBody, has_self: bool) -> Result<(), Error> {
        self.env.push(Vec::new());
        let mut prepend = Vec::new();
        if has_self {
            let id = self.declare("self");
            if self.cells.contains(&id) {
                prepend.push("self".to_string());
            }
        }
        for p in &body.params {
            if let Param::Name(n) = p {
                let id = self.declare(n);
                if self.cells.contains(&id) {
                    prepend.push(n.clone());
                }
            }
        }
        self.body(&mut body.block)?;
        self.prepend_boxes(&mut body.block, prepend);
        self.env.pop();
        Ok(())
    }

    fn prepend_boxes(&self, b: &mut Block, names: Vec<String>) {
        if names.is_empty() {
            return;
        }
        let mut boxes: Vec<Stmt> = names.iter().map(|n| box_assign(n)).collect();
        boxes.append(&mut b.stmts);
        b.stmts = boxes;
    }

    fn stmt(&mut self, s: &mut Stmt) -> Result<Vec<String>, Error> {
        match s {
            Stmt::Local { names, exprs } => {
                for e in exprs.iter_mut() {
                    self.expr(e)?;
                }
                let mut boxed = Vec::new();
                for n in names.iter() {
                    let id = self.declare(n);
                    if self.cells.contains(&id) {
                        boxed.push(n.clone());
                    }
                }
                Ok(boxed)
            }
            Stmt::Assign { targets, exprs } => {
                for t in targets.iter_mut() {
                    self.expr(t)?;
                }
                for e in exprs.iter_mut() {
                    self.expr(e)?;
                }
                Ok(Vec::new())
            }
            Stmt::Compound { target, value, .. } => {
                self.expr(target)?;
                self.expr(value)?;
                Ok(Vec::new())
            }
            Stmt::Call(e) => {
                self.expr(e)?;
                Ok(Vec::new())
            }
            Stmt::Do(b) => {
                self.block(b)?;
                Ok(Vec::new())
            }
            Stmt::While { cond, body } => {
                self.expr(cond)?;
                self.block(body)?;
                Ok(Vec::new())
            }
            Stmt::Repeat { body, until } => {
                self.env.push(Vec::new());
                self.body(body)?;
                self.expr(until)?;
                self.env.pop();
                Ok(Vec::new())
            }
            Stmt::NumericFor {
                var,
                start,
                end,
                step,
                body,
            } => {
                self.expr(start)?;
                self.expr(end)?;
                if let Some(x) = step {
                    self.expr(x)?;
                }
                self.env.push(Vec::new());
                let id = self.declare(var);
                let cell = self.cells.contains(&id);
                self.body(body)?;
                if cell {
                    self.prepend_boxes(body, vec![var.clone()]);
                }
                self.env.pop();
                Ok(Vec::new())
            }
            Stmt::GenericFor { names, exprs, body } => {
                for e in exprs.iter_mut() {
                    self.expr(e)?;
                }
                self.env.push(Vec::new());
                let mut prepend = Vec::new();
                for n in names.iter() {
                    let id = self.declare(n);
                    if self.cells.contains(&id) {
                        prepend.push(n.clone());
                    }
                }
                self.body(body)?;
                self.prepend_boxes(body, prepend);
                self.env.pop();
                Ok(Vec::new())
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond)?;
                self.block(body)?;
                for (c, b) in else_ifs {
                    self.expr(c)?;
                    self.block(b)?;
                }
                if let Some(b) = otherwise {
                    self.block(b)?;
                }
                Ok(Vec::new())
            }
            Stmt::Function { name, body } => {
                let base_cell = self.is_cell(&name.path[0]);
                self.func(body, name.method.is_some())?;
                if base_cell {
                    let mut lvalue = boxed_read(&name.path[0]);
                    for seg in &name.path[1..] {
                        lvalue = Expr::Field {
                            base: Box::new(lvalue),
                            name: seg.clone(),
                        };
                    }
                    if let Some(m) = &name.method {
                        lvalue = Expr::Field {
                            base: Box::new(lvalue),
                            name: m.clone(),
                        };
                    }
                    if let Stmt::Function { name, body } =
                        std::mem::replace(s, Stmt::Call(Expr::Nil))
                    {
                        let mut fb = body;
                        if name.method.is_some() {
                            fb.params.insert(0, Param::Name("self".to_string()));
                        }
                        *s = Stmt::Assign {
                            targets: vec![lvalue],
                            exprs: vec![Expr::Function(fb)],
                        };
                    }
                }
                Ok(Vec::new())
            }
            Stmt::LocalFunction { name, body } => {
                let id = self.declare(name);
                self.func(body, false)?;
                if self.cells.contains(&id) {
                    Ok(vec![name.clone()])
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    fn expr(&mut self, e: &mut Expr) -> Result<(), Error> {
        if is_no_virt(e) {
            if let Expr::Call { args, .. } = e {
                if let Some(Expr::Function(fb)) = args.first_mut() {
                    self.func(fb, false)?;
                }
            }
            return Ok(());
        }
        match e {
            Expr::Name(n) => {
                if self.is_cell(n) {
                    *e = boxed_read(n);
                }
            }
            Expr::Function(fb) => self.func(fb, false)?,
            Expr::Call { func, args, .. } => {
                self.expr(func)?;
                for a in args.iter_mut() {
                    self.expr(a)?;
                }
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base)?;
                for a in args.iter_mut() {
                    self.expr(a)?;
                }
            }
            Expr::Field { base, .. } => self.expr(base)?,
            Expr::Index { base, key } => {
                self.expr(base)?;
                self.expr(key)?;
            }
            Expr::Paren(x) | Expr::Unop { expr: x, .. } => self.expr(x)?,
            Expr::Binop { lhs, rhs, .. } => {
                self.expr(lhs)?;
                self.expr(rhs)?;
            }
            Expr::Table(fs) => {
                for f in fs {
                    match f {
                        Field::Positional(v) => self.expr(v)?,
                        Field::Named { value, .. } => self.expr(value)?,
                        Field::Keyed { key, value } => {
                            self.expr(key)?;
                            self.expr(value)?;
                        }
                    }
                }
            }
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond)?;
                self.expr(then)?;
                for (c, v) in else_ifs {
                    self.expr(c)?;
                    self.expr(v)?;
                }
                self.expr(otherwise)?;
            }
            Expr::Interp(ps) => {
                for p in ps {
                    if let InterpPart::Expr(x) = p {
                        self.expr(x)?;
                    }
                }
            }
            Expr::EncFunc { key, .. } => self.expr(key)?,
            Expr::Nil
            | Expr::True
            | Expr::False
            | Expr::Vararg
            | Expr::Number(_)
            | Expr::Str(_)
            | Expr::NativeRef(_)
            | Expr::OpcodeHint { .. }
            | Expr::Crash => {}
        }
        Ok(())
    }
}

struct Count<'a> {
    next_id: Bid,
    env: Vec<Vec<(String, Bid)>>,
    native: Option<(usize, HashSet<Bid>)>,
    cells: &'a HashSet<Bid>,
    out: CaptureStats,
}

impl Count<'_> {
    fn declare(&mut self, name: &str) {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(top) = self.env.last_mut() {
            top.push((name.to_string(), id));
        }
    }
    fn touch(&mut self, name: &str) {
        let hit = self.env.iter().enumerate().rev().find_map(|(i, frame)| {
            frame
                .iter()
                .rev()
                .find(|(n, _)| n == name)
                .map(|(_, id)| (i, *id))
        });
        if let (Some((frame, id)), Some((floor, caps))) = (hit, self.native.as_mut()) {
            if frame < *floor {
                caps.insert(id);
            }
        }
    }
    fn block(&mut self, b: &Block) {
        self.env.push(Vec::new());
        self.body(b);
        self.env.pop();
    }
    fn body(&mut self, b: &Block) {
        for s in &b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &b.last {
            for e in es {
                self.expr(e);
            }
        }
    }
    fn func(&mut self, body: &FuncBody, has_self: bool) {
        self.env.push(Vec::new());
        if has_self {
            self.declare("self");
        }
        for p in &body.params {
            if let Param::Name(n) = p {
                self.declare(n);
            }
        }
        self.body(&body.block);
        self.env.pop();
    }
    fn native(&mut self, body: &FuncBody) {
        let saved = self.native.take();
        self.env.push(Vec::new());
        self.native = Some((self.env.len() - 1, HashSet::new()));
        for p in &body.params {
            if let Param::Name(n) = p {
                self.declare(n);
            }
        }
        self.body(&body.block);
        self.env.pop();
        let caps = self.native.take().map(|(_, c)| c).unwrap_or_default();
        self.native = saved;
        if caps.is_empty() {
            self.out.direct_natives += 1;
        } else {
            self.out.factory_natives += 1;
            self.out.total_capture_args += caps.len();
            for id in caps {
                if self.cells.contains(&id) {
                    self.out.cell_capture_args += 1;
                } else {
                    self.out.snapshot_capture_args += 1;
                }
            }
        }
    }
    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Local { names, exprs } => {
                for e in exprs {
                    self.expr(e);
                }
                for n in names {
                    self.declare(n);
                }
            }
            Stmt::Assign { targets, exprs } => {
                for t in targets {
                    self.target(t);
                }
                for e in exprs {
                    self.expr(e);
                }
            }
            Stmt::Compound { target, value, .. } => {
                self.target(target);
                self.expr(value);
            }
            Stmt::Call(e) => self.expr(e),
            Stmt::Do(b) => self.block(b),
            Stmt::While { cond, body } => {
                self.expr(cond);
                self.block(body);
            }
            Stmt::Repeat { body, until } => {
                self.env.push(Vec::new());
                self.body(body);
                self.expr(until);
                self.env.pop();
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
                self.env.push(Vec::new());
                self.declare(var);
                self.body(body);
                self.env.pop();
            }
            Stmt::GenericFor { names, exprs, body } => {
                for e in exprs {
                    self.expr(e);
                }
                self.env.push(Vec::new());
                for n in names {
                    self.declare(n);
                }
                self.body(body);
                self.env.pop();
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond);
                self.block(body);
                for (c, b) in else_ifs {
                    self.expr(c);
                    self.block(b);
                }
                if let Some(b) = otherwise {
                    self.block(b);
                }
            }
            Stmt::Function { name, body } => {
                self.touch(&name.path[0]);
                self.func(body, name.method.is_some());
            }
            Stmt::LocalFunction { name, body } => {
                self.declare(name);
                self.func(body, false);
            }
        }
    }
    fn target(&mut self, t: &Expr) {
        match t {
            Expr::Name(n) => self.touch(n),
            Expr::Field { base, .. } => self.expr(base),
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
            Expr::Paren(x) => self.target(x),
            other => self.expr(other),
        }
    }
    fn expr(&mut self, e: &Expr) {
        if is_no_virt(e) {
            if let Expr::Call { args, .. } = e {
                if let Some(Expr::Function(fb)) = args.first() {
                    self.native(fb);
                }
            }
            return;
        }
        match e {
            Expr::Name(n) => self.touch(n),
            Expr::Function(fb) => self.func(fb, false),
            Expr::Call { func, args, .. } => {
                self.expr(func);
                for a in args {
                    self.expr(a);
                }
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                for a in args {
                    self.expr(a);
                }
            }
            Expr::Field { base, .. } => self.expr(base),
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
            Expr::Paren(x) | Expr::Unop { expr: x, .. } => self.expr(x),
            Expr::Binop { lhs, rhs, .. } => {
                self.expr(lhs);
                self.expr(rhs);
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
                    if let InterpPart::Expr(x) = p {
                        self.expr(x);
                    }
                }
            }
            Expr::EncFunc { key, .. } => self.expr(key),
            Expr::Nil
            | Expr::True
            | Expr::False
            | Expr::Vararg
            | Expr::Number(_)
            | Expr::Str(_)
            | Expr::NativeRef(_)
            | Expr::OpcodeHint { .. }
            | Expr::Crash => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lowered(src: &str) -> ir::Module {
        crate::lower_str(src).unwrap()
    }

    fn native_body(call: &Expr) -> &FuncBody {
        match call {
            Expr::Call { args, .. } => match args.first() {
                Some(Expr::Function(fb)) => fb,
                other => panic!("expected native function arg, got {other:?}"),
            },
            other => panic!("expected NO_VIRTUALIZE call, got {other:?}"),
        }
    }

    fn is_box_assign(s: &Stmt, name: &str) -> bool {
        matches!(s, Stmt::Assign { targets, exprs }
            if matches!(&targets[0], Expr::Name(n) if n == name)
               && matches!(&exprs[0], Expr::Table(_)))
    }

    #[test]
    fn capture_free_is_byte_identical() {
        let mut m = lowered("local f = BASIL_NO_VIRTUALIZE(function(x) return x + 1 end)\n");
        let before = ir::emit(&m);
        promote(&mut m.block).unwrap();
        assert_eq!(before, ir::emit(&m), "no captures -> zero mutation");
    }

    #[test]
    fn inner_shadow_mutation_does_not_box_outer_capture() {
        let mut m = lowered(
            "local x = 10\ndo local x = 20 x = 30 end\nlocal f = BASIL_NO_VIRTUALIZE(function() return x end)\n",
        );
        let before = ir::emit(&m);
        promote(&mut m.block).unwrap();
        assert_eq!(
            before,
            ir::emit(&m),
            "a distinct inner binding must not promote the outer capture"
        );
    }

    #[test]
    fn reassigned_captured_binding_is_boxed_by_identity() {
        let mut m = lowered(
            "local x = 10\nx = 30\nlocal f = BASIL_NO_VIRTUALIZE(function() return x end)\n",
        );
        promote(&mut m.block).unwrap();
        assert!(matches!(&m.block.stmts[0], Stmt::Local { .. }));
        assert!(
            is_box_assign(&m.block.stmts[1], "x"),
            "cell binding is boxed right after declaration"
        );

        match &m.block.stmts[2] {
            Stmt::Assign { targets, .. } => assert!(matches!(&targets[0], Expr::Index { .. })),
            s => panic!("expected `x[1] = 30`, got {s:?}"),
        }

        let body = native_body(match &m.block.stmts[3] {
            Stmt::Local { exprs, .. } => &exprs[0],
            s => panic!("{s:?}"),
        });
        assert!(
            matches!(&body.block.last, Some(LastStmt::Return(es)) if matches!(&es[0], Expr::Index { .. }))
        );
    }

    #[test]
    fn distinct_scopes_same_spelling_are_independent() {
        let mut m = lowered(
            "local v = 1\nlocal f = BASIL_NO_VIRTUALIZE(function() return v end)\n\
             do local v = 2 local g = BASIL_NO_VIRTUALIZE(function() return v end) v = 3 end\n",
        );
        promote(&mut m.block).unwrap();

        let outer = native_body(match &m.block.stmts[1] {
            Stmt::Local { exprs, .. } => &exprs[0],
            s => panic!("{s:?}"),
        });
        assert!(
            matches!(&outer.block.last, Some(LastStmt::Return(es)) if matches!(&es[0], Expr::Name(n) if n == "v")),
            "outer capture stays a plain read"
        );

        let inner = match &m.block.stmts[2] {
            Stmt::Do(b) => b,
            s => panic!("expected do-block, got {s:?}"),
        };
        assert!(
            inner.stmts.iter().any(|s| is_box_assign(s, "v")),
            "inner reassigned binding is boxed"
        );
        let g_body = native_body(match &inner.stmts[2] {
            Stmt::Local { exprs, .. } => &exprs[0],
            s => panic!("{s:?}"),
        });
        assert!(
            matches!(&g_body.block.last, Some(LastStmt::Return(es)) if matches!(&es[0], Expr::Index { .. })),
            "inner capture reads the cell"
        );
    }

    #[test]
    fn loop_variable_reassigned_and_captured_is_boxed_per_iteration() {
        let mut m = lowered(
            "local fns = {}\nfor i = 1, 3 do i = i * 10 fns[i] = BASIL_NO_VIRTUALIZE(function() return i end) end\n",
        );
        promote(&mut m.block).unwrap();
        let body = match &m.block.stmts[1] {
            Stmt::NumericFor { body, .. } => body,
            s => panic!("expected numeric for, got {s:?}"),
        };
        assert!(
            is_box_assign(&body.stmts[0], "i"),
            "loop var boxed at the top of the body (fresh box per iteration)"
        );
    }
}
