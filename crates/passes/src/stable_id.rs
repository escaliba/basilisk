use ir::{Block, Expr, Field, FuncBody, LastStmt, Module, Stmt};

pub fn assign_stable_ids(module: &mut Module) -> u32 {
    let mut w = Walker { next: 1 };
    w.block(&mut module.block);
    for n in &mut module.natives {
        w.block(&mut n.block);
    }
    for ef in &mut module.encfuncs {
        w.func(&mut ef.body);
    }
    w.next - 1
}

struct Walker {
    next: u32,
}

impl Walker {
    fn func(&mut self, f: &mut FuncBody) {
        f.stable_id = Some(self.next);
        self.next += 1;
        self.block(&mut f.block);
    }

    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(exprs)) = &mut b.last {
            for e in exprs {
                self.expr(e);
            }
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
            Stmt::Do(b) => self.block(b),
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
                if let Some(st) = step {
                    self.expr(st);
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
                for (c, b) in else_ifs {
                    self.expr(c);
                    self.block(b);
                }
                if let Some(b) = otherwise {
                    self.block(b);
                }
            }
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => self.func(body),
        }
    }

    fn expr(&mut self, e: &mut Expr) {
        match e {
            Expr::Field { base, .. } => self.expr(base),
            Expr::Paren(inner) | Expr::Unop { expr: inner, .. } => self.expr(inner),
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
            Expr::Call { func, args, .. } => {
                self.expr(func);
                args.iter_mut().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter_mut().for_each(|a| self.expr(a));
            }
            Expr::Function(body) => self.func(body),
            Expr::Table(fields) => {
                for f in fields {
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
            Expr::Interp(parts) => {
                for p in parts {
                    if let ir::InterpPart::Expr(x) = p {
                        self.expr(x);
                    }
                }
            }
            Expr::EncFunc { key, .. } => self.expr(key),
            Expr::Str(_)
            | Expr::Nil
            | Expr::True
            | Expr::False
            | Expr::Vararg
            | Expr::Number(_)
            | Expr::Name(_)
            | Expr::NativeRef(_)
            | Expr::OpcodeHint { .. }
            | Expr::Crash => {}
        }
    }
}

pub fn reference_census(module: &Module, name: &str) -> (usize, usize, usize) {
    let mut r = Refs {
        name,
        callee: 0,
        value: 0,
        target: 0,
    };
    r.block(&module.block);
    for n in &module.natives {
        r.block(&n.block);
    }
    for ef in &module.encfuncs {
        r.block(&ef.body.block);
    }
    (r.callee, r.value, r.target)
}

struct Refs<'a> {
    name: &'a str,
    callee: usize,
    value: usize,
    target: usize,
}

impl Refs<'_> {
    fn is_it(&self, e: &Expr) -> bool {
        matches!(e, Expr::Name(n) if n == self.name)
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
            Stmt::Assign { targets, exprs } => {
                for t in targets {
                    if self.is_it(t) {
                        self.target += 1;
                    } else {
                        self.expr(t);
                    }
                }
                exprs.iter().for_each(|e| self.expr(e));
            }
            Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| self.expr(e)),
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
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                self.block(&body.block)
            }
        }
    }

    fn expr(&mut self, e: &Expr) {
        match e {
            Expr::Call { func, args, .. } => {
                if self.is_it(func) {
                    self.callee += 1;
                } else {
                    self.expr(func);
                }
                args.iter().for_each(|a| self.expr(a));
            }
            Expr::Name(n) if n == self.name => self.value += 1,
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
            Expr::Function(f) => self.block(&f.block),
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

    fn ids(m: &Module) -> Vec<u32> {
        fn walk(b: &Block, out: &mut Vec<u32>) {
            for s in &b.stmts {
                match s {
                    Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                        out.push(body.stable_id.expect("assigned"));
                        walk(&body.block, out);
                    }
                    Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| we(e, out)),
                    Stmt::Assign { exprs, .. } => exprs.iter().for_each(|e| we(e, out)),
                    Stmt::Call(e) => we(e, out),
                    Stmt::Do(x) => walk(x, out),
                    Stmt::GenericFor { body, .. } | Stmt::NumericFor { body, .. } => {
                        walk(body, out)
                    }
                    Stmt::If {
                        body,
                        else_ifs,
                        otherwise,
                        ..
                    } => {
                        walk(body, out);
                        for (_, x) in else_ifs {
                            walk(x, out);
                        }
                        if let Some(x) = otherwise {
                            walk(x, out);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(LastStmt::Return(exprs)) = &b.last {
                exprs.iter().for_each(|e| we(e, out));
            }
        }
        fn we(e: &Expr, out: &mut Vec<u32>) {
            match e {
                Expr::Function(body) => {
                    out.push(body.stable_id.expect("assigned"));
                    walk(&body.block, out);
                }
                Expr::Call { func, args, .. } => {
                    we(func, out);
                    args.iter().for_each(|a| we(a, out));
                }
                Expr::Table(fields) => {
                    for f in fields {
                        match f {
                            Field::Positional(v) => we(v, out),
                            Field::Named { value, .. } => we(value, out),
                            Field::Keyed { key, value } => {
                                we(key, out);
                                we(value, out);
                            }
                        }
                    }
                }
                other => other.each_child(&mut |c| we(c, out)),
            }
        }
        let mut out = Vec::new();
        walk(&m.block, &mut out);
        out
    }

    const SRC: &str = "local function outer(t)\n\
                       \tlocal name = \"alphabetagamma\"\n\
                       \tlocal cb = function(v) return v .. \"suffixvalue\" end\n\
                       \tfor _, x in ipairs(t) do\n\
                       \t\tlocal inner = function() return name end\n\
                       \t\tcb(inner())\n\
                       \tend\n\
                       end\n\
                       local tbl = { handler = function() return \"tablefieldstring\" end }\n\
                       return outer, tbl\n";

    #[test]
    fn stable_ids_are_identical_with_and_without_fragmentation() {
        let mut plain = frontend::lower_str(SRC).unwrap();
        let n = assign_stable_ids(&mut plain);
        assert!(n >= 4, "fixture must contain several functions, got {n}");

        let mut fragmented = plain.clone();
        crate::fragment_strings(&mut fragmented, 0xABCD, false);

        assert_eq!(
            ids(&plain),
            ids(&fragmented),
            "fragmentation must not change any function's stable id"
        );

        let out = ir::emit(&fragmented);
        assert!(
            !out.contains("alphabetagamma"),
            "fixture must actually be fragmented: {out}"
        );
    }

    #[test]
    fn stable_ids_are_dense_unique_and_deterministic() {
        let mut a = frontend::lower_str(SRC).unwrap();
        let n = assign_stable_ids(&mut a);
        let mut b = frontend::lower_str(SRC).unwrap();
        assert_eq!(n, assign_stable_ids(&mut b), "count is deterministic");

        let got = ids(&a);
        assert_eq!(got, ids(&b), "ids are deterministic across runs");
        let mut sorted = got.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), got.len(), "ids are unique: {got:?}");
        assert_eq!(*sorted.first().unwrap(), 1, "ids are 1-based");
    }

    #[test]
    fn reference_census_distinguishes_callee_value_and_target() {
        let direct = "Target = function(a, b) return a + b end\n\
                      local r = Target(1, 2)\n\
                      return r\n";
        let m = frontend::lower_str(direct).unwrap();
        assert_eq!(
            reference_census(&m, "Target"),
            (1, 0, 1),
            "one call, no bare value, one definition"
        );

        let aliased = "Target = function(a) return a end\n\
                       local alias = Target\n\
                       return alias(1)\n";
        let m2 = frontend::lower_str(aliased).unwrap();
        let (callee, value, target) = reference_census(&m2, "Target");
        assert_eq!((callee, target), (0, 1));
        assert!(
            value >= 1,
            "aliasing must surface as a bare-value reference"
        );
    }

    fn iy_source() -> Option<String> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../reference/bench-inputs/real-world/infinite_yield_source.lua");
        std::fs::read_to_string(p).ok()
    }

    #[test]
    fn iy_match_has_exactly_one_call_site_and_no_indirect_reference() {
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(iy_match_census)
            .unwrap();
        handle.join().unwrap();
    }

    fn iy_match_census() {
        let Some(src) = iy_source() else {
            eprintln!("IY benchmark source unavailable; skipping");
            return;
        };
        let mut plain = frontend::lower_str(&src).unwrap();
        assign_stable_ids(&mut plain);
        let mut fragmented = plain.clone();
        crate::fragment_strings(&mut fragmented, 17906244878785717735, false);

        for (label, m) in [("unfragmented", &plain), ("fragmented", &fragmented)] {
            let census = reference_census(m, "Match");
            assert_eq!(
                census,
                (1, 0, 1),
                "{label}: the container-scoped P1-H2 gate is only exact while Match has \
                 exactly one call site, no bare-value reference and one definition; got {census:?}"
            );
        }
    }
}

pub const MATCH_CALL_SITE: u32 = 1;

pub fn mark_match_call_site(module: &mut Module, container: u32, name: &str) -> Result<(), String> {
    let mut m = Marker {
        container,
        name,
        marked: 0,
    };
    m.block(&mut module.block);
    match m.marked {
        1 => Ok(()),
        0 => Err(format!(
            "call-site identity absent: no call to {name} inside stable id {container}"
        )),
        n => Err(format!(
            "call-site identity ambiguous: {n} calls to {name} inside stable id {container}"
        )),
    }
}

struct Marker<'a> {
    container: u32,
    name: &'a str,
    marked: usize,
}

impl Marker<'_> {
    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &mut b.last {
            for e in es {
                self.scan_for_container(e);
            }
        }
    }

    fn stmt(&mut self, s: &mut Stmt) {
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => self.func(body),
            Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| self.scan_for_container(e)),
            Stmt::Assign { exprs, .. } => exprs.iter_mut().for_each(|e| self.scan_for_container(e)),
            Stmt::Call(e) => self.scan_for_container(e),
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

    fn func(&mut self, f: &mut FuncBody) {
        if f.stable_id == Some(self.container) {
            let mut inner = Tagger {
                name: self.name,
                marked: 0,
            };
            inner.block(&mut f.block);
            self.marked += inner.marked;
            return;
        }
        self.block(&mut f.block);
    }

    fn scan_for_container(&mut self, e: &mut Expr) {
        match e {
            Expr::Function(f) => self.func(f),
            Expr::Call { func, args, .. } => {
                self.scan_for_container(func);
                args.iter_mut().for_each(|a| self.scan_for_container(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.scan_for_container(base);
                args.iter_mut().for_each(|a| self.scan_for_container(a));
            }
            Expr::Table(fs) => {
                for f in fs {
                    match f {
                        Field::Positional(v) => self.scan_for_container(v),
                        Field::Named { value, .. } => self.scan_for_container(value),
                        Field::Keyed { key, value } => {
                            self.scan_for_container(key);
                            self.scan_for_container(value);
                        }
                    }
                }
            }
            Expr::Paren(x) | Expr::Unop { expr: x, .. } => self.scan_for_container(x),
            Expr::Index { base, key } => {
                self.scan_for_container(base);
                self.scan_for_container(key);
            }
            Expr::Field { base, .. } => self.scan_for_container(base),
            Expr::Binop { lhs, rhs, .. } => {
                self.scan_for_container(lhs);
                self.scan_for_container(rhs);
            }
            other => other.each_child_mut(&mut |c| self.scan_for_container(c)),
        }
    }
}

struct Tagger<'a> {
    name: &'a str,
    marked: usize,
}

impl Tagger<'_> {
    fn block(&mut self, b: &mut Block) {
        for s in &mut b.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(es)) = &mut b.last {
            for e in es {
                self.expr(e);
            }
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
        if let Expr::Call { func, site, .. } = e {
            if matches!(&**func, Expr::Name(n) if n == self.name) {
                *site = Some(MATCH_CALL_SITE);
                self.marked += 1;
            }
        }
        match e {
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
            Expr::Function(f) => self.block(&mut f.block),
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

#[cfg(test)]
mod call_site_tests {
    use super::*;

    fn container_src() -> &'static str {
        "Match = function(a,b) return a end\n\
         Container = function(x)\n\
         \tlocal t = {}\n\
         \tfor _, v in ipairs(t) do\n\
         \t\tif tostring(v) then\n\
         \t\t\tif Match(v, x) then return v end\n\
         \t\tend\n\
         \tend\n\
         end\n\
         return Container\n"
    }

    fn container_id(m: &Module) -> u32 {
        for s in &m.block.stmts {
            if let Stmt::Assign { targets, exprs } = s {
                for (t, e) in targets.iter().zip(exprs.iter()) {
                    if matches!(t, Expr::Name(n) if n == "Container") {
                        if let Expr::Function(f) = e {
                            return f.stable_id.unwrap();
                        }
                    }
                }
            }
        }
        panic!("container not found")
    }

    fn marked_count(m: &Module) -> usize {
        fn blk(b: &Block, n: &mut usize) {
            for s in &b.stmts {
                stmt(s, n);
            }
            if let Some(LastStmt::Return(es)) = &b.last {
                es.iter().for_each(|e| ex(e, n));
            }
        }
        fn stmt(s: &Stmt, n: &mut usize) {
            match s {
                Stmt::Assign { exprs, .. } | Stmt::Local { exprs, .. } => {
                    exprs.iter().for_each(|e| ex(e, n))
                }
                Stmt::Call(e) => ex(e, n),
                Stmt::Do(x) => blk(x, n),
                Stmt::While { body, .. } | Stmt::Repeat { body, .. } => blk(body, n),
                Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => blk(body, n),
                Stmt::If {
                    cond,
                    body,
                    else_ifs,
                    otherwise,
                } => {
                    ex(cond, n);
                    blk(body, n);
                    for (c, x) in else_ifs {
                        ex(c, n);
                        blk(x, n);
                    }
                    if let Some(x) = otherwise {
                        blk(x, n);
                    }
                }
                Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                    blk(&body.block, n)
                }
                Stmt::Compound { .. } => {}
            }
        }
        fn ex(e: &Expr, n: &mut usize) {
            if let Expr::Call { site: Some(_), .. } = e {
                *n += 1;
            }
            match e {
                Expr::Call { func, args, .. } => {
                    ex(func, n);
                    args.iter().for_each(|a| ex(a, n));
                }
                Expr::MethodCall { base, args, .. } => {
                    ex(base, n);
                    args.iter().for_each(|a| ex(a, n));
                }
                Expr::Function(f) => blk(&f.block, n),
                Expr::Binop { lhs, rhs, .. } => {
                    ex(lhs, n);
                    ex(rhs, n);
                }
                Expr::Paren(x) | Expr::Unop { expr: x, .. } => ex(x, n),
                other => other.each_child(&mut |c| ex(c, n)),
            }
        }
        let mut n = 0;
        blk(&m.block, &mut n);
        n
    }

    #[test]
    fn call_site_marker_is_deterministic_with_and_without_fragmentation() {
        let mut plain = frontend::lower_str(container_src()).unwrap();
        assign_stable_ids(&mut plain);
        let cid = container_id(&plain);
        let mut fragmented = plain.clone();
        crate::fragment_strings(&mut fragmented, 0xABCD, false);

        mark_match_call_site(&mut plain, cid, "Match").unwrap();
        mark_match_call_site(&mut fragmented, cid, "Match").unwrap();

        assert_eq!(
            marked_count(&plain),
            1,
            "exactly one site marked, unfragmented"
        );
        assert_eq!(
            marked_count(&fragmented),
            1,
            "exactly one site marked, fragmented"
        );
    }

    #[test]
    fn call_site_marker_fails_closed_when_absent_or_ambiguous() {
        let mut m = frontend::lower_str(container_src()).unwrap();
        assign_stable_ids(&mut m);
        let cid = container_id(&m);

        let mut missing = m.clone();
        let e = mark_match_call_site(&mut missing, cid, "NoSuchFunction").unwrap_err();
        assert!(e.contains("absent"), "{e}");

        let mut bad_container = m.clone();
        let e2 = mark_match_call_site(&mut bad_container, 99_999, "Match").unwrap_err();
        assert!(
            e2.contains("absent"),
            "unknown container must fail closed: {e2}"
        );

        let two = "Match = function(a,b) return a end\n\
                   Container = function(x)\n\
                   \tif Match(x, x) then return 1 end\n\
                   \treturn Match(x, x)\n\
                   end\n\
                   return Container\n";
        let mut dup = frontend::lower_str(two).unwrap();
        assign_stable_ids(&mut dup);
        let did = container_id(&dup);
        let e3 = mark_match_call_site(&mut dup, did, "Match").unwrap_err();
        assert!(e3.contains("ambiguous"), "two calls must fail closed: {e3}");
    }

    #[test]
    fn call_site_marker_only_tags_calls_inside_the_named_container() {
        let src = "Match = function(a,b) return a end\n\
                   Other = function(x) return Match(x, x) end\n\
                   Container = function(x) return x end\n\
                   return Container, Other\n";
        let mut m = frontend::lower_str(src).unwrap();
        assign_stable_ids(&mut m);
        let cid = container_id(&m);
        let e = mark_match_call_site(&mut m, cid, "Match").unwrap_err();
        assert!(
            e.contains("absent"),
            "a call outside the container must not be tagged: {e}"
        );
        assert_eq!(
            marked_count(&m),
            0,
            "nothing tagged when the container has no call"
        );
    }
}
