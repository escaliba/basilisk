use ir::{Block, Expr, Field, FuncBody, LastStmt, Module, Stmt};

#[derive(Debug)]
pub struct Extracted {
    pub stable_id: u32,
    pub binding: String,
    pub native_index: u32,
    pub free_vars: Vec<String>,
}

#[derive(Debug)]
pub struct LookupReport {
    pub extracted: Vec<Extracted>,
}

pub fn extract_at(module: &mut Module, id: u32) -> Result<LookupReport, String> {
    crate::native_escape::check_leaf(module, id)
        .map_err(|e| format!("command-lookup native: {e}"))?;
    let (binding, body) =
        take_global(module, id).map_err(|e| format!("command-lookup native: {e}"))?;
    let free_vars: Vec<String> = crate::free_vars(&body).into_iter().collect();
    module.natives.push(body);
    let native_index = (module.natives.len() - 1) as u32;
    bind_global(module, id, native_index).map_err(|e| format!("command-lookup native: {e}"))?;
    Ok(LookupReport {
        extracted: vec![Extracted {
            stable_id: id,
            binding,
            native_index,
            free_vars,
        }],
    })
}

fn take_global(module: &mut Module, want: u32) -> Result<(String, FuncBody), String> {
    let mut s = Scan {
        want,
        found: Vec::new(),
    };
    s.block(&module.block);
    match s.found.len() {
        1 => {}
        0 => return Err(format!("stable id {want} is not a global function binding")),
        n => {
            return Err(format!(
                "stable id {want} matched {n} global bindings, expected 1"
            ))
        }
    }
    let (name, body) = s.found.pop().unwrap();
    Ok((name, body))
}

struct Scan {
    want: u32,
    found: Vec<(String, FuncBody)>,
}

impl Scan {
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
            Stmt::Function { name, body } => {
                if body.stable_id == Some(self.want)
                    && name.method.is_none()
                    && name.path.len() == 1
                {
                    self.found.push((name.path[0].clone(), body.clone()));
                    return;
                }
                self.block(&body.block);
            }
            Stmt::LocalFunction { body, .. } => self.block(&body.block),
            Stmt::Assign { targets, exprs } => {
                for (i, e) in exprs.iter().enumerate() {
                    if let Expr::Function(f) = e {
                        if f.stable_id == Some(self.want) {
                            if let Some(Expr::Name(n)) = targets.get(i) {
                                self.found.push((n.clone(), f.clone()));
                                continue;
                            }
                        }
                    }
                    self.expr(e);
                }
                for t in targets {
                    self.expr(t);
                }
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
        }
    }

    fn expr(&mut self, e: &Expr) {
        match e {
            Expr::Function(f) => self.block(&f.block),
            Expr::Field { base, .. } | Expr::Paren(base) | Expr::Unop { expr: base, .. } => {
                self.expr(base)
            }
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
            Expr::Call { func, args, .. } => {
                self.expr(func);
                args.iter().for_each(|a| self.expr(a));
            }
            Expr::MethodCall { base, args, .. } => {
                self.expr(base);
                args.iter().for_each(|a| self.expr(a));
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

fn bind_global(module: &mut Module, want: u32, idx: u32) -> Result<(), String> {
    let mut b = Bind { want, idx, done: 0 };
    b.block(&mut module.block);
    match b.done {
        1 => Ok(()),
        n => Err(format!(
            "stable id {want} binding replaced {n} times, expected 1"
        )),
    }
}

struct Bind {
    want: u32,
    idx: u32,
    done: usize,
}

impl Bind {
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
        if let Stmt::Function { name, body } = s {
            if body.stable_id == Some(self.want) && name.method.is_none() && name.path.len() == 1 {
                self.done += 1;
                *s = Stmt::Assign {
                    targets: vec![Expr::Name(name.path[0].clone())],
                    exprs: vec![Expr::NativeRef(self.idx)],
                };
                return;
            }
        }
        match s {
            Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
                self.block(&mut body.block)
            }
            Stmt::Assign { targets, exprs } => {
                for e in exprs.iter_mut() {
                    if matches!(e, Expr::Function(f) if f.stable_id == Some(self.want)) {
                        self.done += 1;
                        *e = Expr::NativeRef(self.idx);
                        continue;
                    }
                    self.expr(e);
                }
                for t in targets.iter_mut() {
                    self.expr(t);
                }
            }
            Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| self.expr(e)),
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
        }
    }

    fn expr(&mut self, e: &mut Expr) {
        match e {
            Expr::Function(f) => self.block(&mut f.block),
            Expr::Field { base, .. } | Expr::Paren(base) | Expr::Unop { expr: base, .. } => {
                self.expr(base)
            }
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
mod tests {

    const FIXTURE_ID: u32 = 230;
    use super::*;
    use ir::Module;

    const SCAN_ID: u32 = 243;
    const CALLER_ID: u32 = 246;

    const SRC: &str = "cmds = {}\n\
                       customAlias = {}\n\
                       function FindInTable(tbl, val)\n\
                       \tif tbl == nil then return false end\n\
                       \tfor _, v in pairs(tbl) do\n\
                       \t\tif v == val then return true end\n\
                       \tend\n\
                       \treturn false\n\
                       end\n\
                       findCmd = function(cmd_name)\n\
                       \tfor i, v in pairs(cmds) do\n\
                       \t\tif v.NAME:lower() == cmd_name:lower() or FindInTable(v.ALIAS, cmd_name:lower()) then\n\
                       \t\t\treturn v\n\
                       \t\tend\n\
                       \tend\n\
                       \treturn customAlias[cmd_name:lower()]\n\
                       end\n\
                       function execCmd(cmdStr, speaker, store)\n\
                       \ttask.spawn(function()\n\
                       \t\tlocal args = splitString(cmdStr)\n\
                       \t\tlocal cmd = findCmd(args[1])\n\
                       \t\tif cmd then\n\
                       \t\t\tcmd.FUNC(args, speaker)\n\
                       \t\tend\n\
                       \tend)\n\
                       end\n\
                       return findCmd, FindInTable, execCmd\n";

    fn lower(src: &'static str) -> Module {
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(move || crate::lower_str(src).unwrap())
            .expect("spawn parser thread")
            .join()
            .expect("parser thread")
    }

    fn build() -> Module {
        let mut m = lower(SRC);
        retag(&mut m);
        m
    }

    fn retag(m: &mut Module) {
        for s in &mut m.block.stmts {
            match s {
                Stmt::Function { name, body } if name.path == vec!["FindInTable".to_string()] => {
                    body.stable_id = Some(FIXTURE_ID)
                }
                Stmt::Function { name, body } if name.path == vec!["execCmd".to_string()] => {
                    for inner in &mut body.block.stmts {
                        if let Stmt::Call(Expr::Call { args, .. }) = inner {
                            for a in args.iter_mut() {
                                if let Expr::Function(f) = a {
                                    f.stable_id = Some(CALLER_ID);
                                }
                            }
                        }
                    }
                }
                Stmt::Assign { targets, exprs } => {
                    for (t, e) in targets.iter().zip(exprs.iter_mut()) {
                        if matches!(t, Expr::Name(n) if n == "findCmd") {
                            if let Expr::Function(f) = e {
                                f.stable_id = Some(SCAN_ID);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn native_sources(m: &Module) -> Vec<String> {
        m.natives.iter().map(ir::emit_func).collect()
    }

    fn emit_module(m: &Module) -> String {
        let mut c = m.clone();
        for s in &mut c.block.stmts {
            if let Stmt::Assign { exprs, .. } = s {
                for e in exprs.iter_mut() {
                    if let Expr::NativeRef(i) = e {
                        *e = Expr::Name(format!("__NATIVE_{i}"));
                    }
                }
            }
        }
        c.natives.clear();
        ir::emit(&c)
    }

    #[test]
    fn it_extracts_only_the_helper_and_leaves_the_scan_virtualized() {
        let mut m = build();
        let r = extract_at(&mut m, FIXTURE_ID).unwrap();
        assert_eq!(r.extracted.len(), 1, "exactly one body is extracted");
        assert_eq!(r.extracted[0].stable_id, FIXTURE_ID);
        assert_eq!(r.extracted[0].binding, "FindInTable");
        assert_eq!(m.natives.len(), 1);

        let out = emit_module(&m);
        assert!(
            !out.contains("function FindInTable"),
            "the helper body left the payload: {out}"
        );
        assert!(
            out.contains("findCmd = function"),
            "the scan stays virtualized: {out}"
        );
        assert!(
            out.contains("FindInTable(v.ALIAS"),
            "the scan still calls the helper: {out}"
        );

        let native = &native_sources(&m)[0];
        assert!(
            native.contains("pairs(tbl)"),
            "the native carries the real helper body: {native}"
        );
        assert!(
            native.contains("return false"),
            "the nil guard travels with it: {native}"
        );
    }

    #[test]
    fn the_helper_is_a_leaf_over_globals_only() {
        let mut m = build();
        let r = extract_at(&mut m, FIXTURE_ID).unwrap();
        assert_eq!(
            r.extracted[0].free_vars,
            vec!["pairs".to_string()],
            "the native helper reaches nothing but a stdlib global"
        );
    }

    #[test]
    fn the_caller_and_command_execution_are_untouched() {
        let mut m = build();
        extract_at(&mut m, FIXTURE_ID).unwrap();
        let out = emit_module(&m);
        assert!(out.contains("task.spawn"), "execCmd still spawns: {out}");
        assert!(out.contains("splitString(cmdStr)"), "splitString preserved");
        assert!(
            out.contains("findCmd(args[1])"),
            "the lookup call is preserved"
        );
        assert!(
            out.contains("cmd.FUNC(args, speaker)"),
            "execution preserved"
        );
        assert!(
            m.natives
                .iter()
                .all(|n| n.stable_id != Some(CALLER_ID) && n.stable_id != Some(SCAN_ID)),
            "neither the spawned body nor the scan is ever made native"
        );
    }

    #[test]
    fn no_admission_or_diagnostic_output_is_emitted() {
        let mut m = build();
        extract_at(&mut m, FIXTURE_ID).unwrap();
        let out = emit_module(&m);
        for probe in ["BASIL_", "print(", "os.clock", "tick("] {
            assert!(
                !out.contains(probe),
                "the promoted pass emits no `{probe}`: {out}"
            );
        }
        for native in native_sources(&m) {
            assert!(
                !native.contains("BASIL_"),
                "no admission inside the native body: {native}"
            );
        }
    }

    #[test]
    fn it_fails_closed_on_an_absent_identity() {
        let mut m = lower(SRC);
        let e = extract_at(&mut m, FIXTURE_ID).unwrap_err();
        assert!(e.contains("absent"), "must fail closed when absent: {e}");
    }

    #[test]
    fn it_fails_closed_on_an_ambiguous_identity() {
        let mut m = build();
        for s in &mut m.block.stmts {
            if let Stmt::Function { name, body } = s {
                if name.path == vec!["execCmd".to_string()] {
                    body.stable_id = Some(FIXTURE_ID);
                }
            }
        }
        let e = extract_at(&mut m, FIXTURE_ID).unwrap_err();
        assert!(
            e.contains("ambiguous"),
            "duplicate ids must fail closed: {e}"
        );
    }

    #[test]
    fn captured_local_fails_closed() {
        let src = "local hidden = 1\n\
                   function FindInTable(tbl, val)\n\
                   \treturn hidden\n\
                   end\n\
                   return FindInTable\n";
        let mut m = lower(src);
        for s in &mut m.block.stmts {
            if let Stmt::Function { name, body } = s {
                if name.path == vec!["FindInTable".to_string()] {
                    body.stable_id = Some(FIXTURE_ID);
                }
            }
        }
        let e = extract_at(&mut m, FIXTURE_ID).unwrap_err();
        assert!(
            e.contains("captures enclosing local"),
            "a non-leaf must fail closed and name the capture: {e}"
        );
    }

    #[test]
    fn the_pass_is_deterministic() {
        let mut a = build();
        let mut b = build();
        extract_at(&mut a, FIXTURE_ID).unwrap();
        extract_at(&mut b, FIXTURE_ID).unwrap();
        assert_eq!(
            emit_module(&a),
            emit_module(&b),
            "the pass is deterministic"
        );
        assert_eq!(
            native_sources(&a),
            native_sources(&b),
            "native bodies are stable"
        );
    }
}
