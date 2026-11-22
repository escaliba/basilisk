use ir::{Block, Expr, Field, FuncBody, InterpPart, LastStmt, Module, Stmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptMode {
    Off,
    Safe,
    Experimental,
}

impl OptMode {
    pub fn label(self) -> &'static str {
        match self {
            OptMode::Off => "off",
            OptMode::Safe => "safe",
            OptMode::Experimental => "experimental",
        }
    }
    fn enabled(self) -> bool {
        !matches!(self, OptMode::Off)
    }
}

#[derive(Clone, Debug, Default)]
pub struct OptReport {
    pub mode: &'static str,
    pub functions_examined: u32,
    pub functions_changed: u32,
    pub passes_run: u32,
    pub const_propagated: u32,
    pub copies_propagated: u32,
    pub dead_locals_removed: u32,
    pub self_assigns_removed: u32,
    pub string_builders: u32,
    pub ir_ops_before: u32,
    pub ir_ops_after: u32,
}

impl OptReport {
    pub fn changed(&self) -> bool {
        self.const_propagated
            + self.copies_propagated
            + self.dead_locals_removed
            + self.self_assigns_removed
            + self.string_builders
            > 0
    }
}

pub fn optimize(module: &mut Module, mode: OptMode) -> OptReport {
    let mut report = OptReport {
        mode: mode.label(),
        ..Default::default()
    };
    if !mode.enabled() {
        report.ir_ops_before = count_block(&module.block);
        report.ir_ops_after = report.ir_ops_before;
        return report;
    }
    report.ir_ops_before = count_block(&module.block);
    report.functions_examined = count_function_scopes(&module.block);

    for _ in 0..10 {
        let mut round_changed = false;
        report.passes_run += 1;

        round_changed |= propagate_scope(&mut module.block, mode, &mut report);
        crate::optimize::optimize_with_level(module, 2);
        round_changed |= dead_local_elim_scope(&mut module.block, &mut report);
        round_changed |= self_assign_elim_scope(&mut module.block, &mut report);

        if !round_changed {
            break;
        }
    }

    crate::optimize::optimize_with_level(module, 2);
    report.ir_ops_after = count_block(&module.block);
    report
}

fn count_function_scopes(block: &Block) -> u32 {
    let mut c = 1;
    let mut b = block.clone();
    count_fn_scopes_rec(&mut b, &mut c);
    c
}

fn count_fn_scopes_rec(block: &mut Block, c: &mut u32) {
    for_each_direct_child_function(block, &mut |fb| {
        *c += 1;
        count_fn_scopes_rec(&mut fb.block, c);
    });
}

fn is_literal(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Nil | Expr::True | Expr::False | Expr::Number(_) | Expr::Str(_)
    )
}

fn scope_stmts<'a>(block: &'a Block, out: &mut Vec<&'a Stmt>) {
    for s in &block.stmts {
        out.push(s);
        match s {
            Stmt::Do(b) | Stmt::While { body: b, .. } | Stmt::Repeat { body: b, .. } => {
                scope_stmts(b, out)
            }
            Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => scope_stmts(body, out),
            Stmt::If {
                body,
                else_ifs,
                otherwise,
                ..
            } => {
                scope_stmts(body, out);
                for (_, b) in else_ifs {
                    scope_stmts(b, out);
                }
                if let Some(b) = otherwise {
                    scope_stmts(b, out);
                }
            }
            _ => {}
        }
    }
}

fn scope_introductions(block: &Block, params: &[String], out: &mut Vec<String>) {
    out.extend(params.iter().cloned());
    let mut stmts = Vec::new();
    scope_stmts(block, &mut stmts);
    for s in stmts {
        match s {
            Stmt::Local { names, .. } => out.extend(names.iter().cloned()),
            Stmt::NumericFor { var, .. } => out.push(var.clone()),
            Stmt::GenericFor { names, .. } => out.extend(names.iter().cloned()),
            Stmt::LocalFunction { name, .. } => out.push(name.clone()),
            _ => {}
        }
    }
}

fn constant_candidates(block: &Block, params: &[String]) -> Vec<(String, Expr)> {
    let mut intros = Vec::new();
    scope_introductions(block, params, &mut intros);

    let count = |name: &str, v: &[String]| v.iter().filter(|x| x.as_str() == name).count();

    let mut out = Vec::new();
    let mut stmts = Vec::new();
    scope_stmts(block, &mut stmts);
    for s in &stmts {
        if let Stmt::Local { names, exprs } = s {
            if names.len() == 1 && exprs.len() == 1 && is_literal(&exprs[0]) {
                let n = &names[0];
                if count(n, &intros) == 1 && !assigned_including_captures(block, n) {
                    out.push((n.clone(), exprs[0].clone()));
                }
            }
        }
    }
    out
}

fn assigned_including_captures(block: &Block, name: &str) -> bool {
    let mut found = false;
    assigned_block(block, name, &mut found);
    found
}

fn assigned_block(block: &Block, name: &str, found: &mut bool) {
    for s in &block.stmts {
        if *found {
            return;
        }
        assigned_stmt(s, name, found);
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            assigned_expr(e, name, found);
        }
    }
}

fn assigned_stmt(s: &Stmt, name: &str, found: &mut bool) {
    match s {
        Stmt::Assign { targets, exprs } => {
            for t in targets {
                if let Expr::Name(n) = t {
                    if n == name {
                        *found = true;
                    }
                }
                assigned_lvalue_subexprs(t, name, found);
            }
            exprs.iter().for_each(|e| assigned_expr(e, name, found));
        }
        Stmt::Compound { target, value, .. } => {
            if let Expr::Name(n) = target {
                if n == name {
                    *found = true;
                }
            }
            assigned_lvalue_subexprs(target, name, found);
            assigned_expr(value, name, found);
        }
        Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| assigned_expr(e, name, found)),
        Stmt::Call(e) => assigned_expr(e, name, found),
        Stmt::Do(b) | Stmt::While { body: b, .. } | Stmt::Repeat { body: b, .. } => {
            assigned_block(b, name, found)
        }
        Stmt::NumericFor {
            body,
            start,
            end,
            step,
            ..
        } => {
            assigned_expr(start, name, found);
            assigned_expr(end, name, found);
            if let Some(s) = step {
                assigned_expr(s, name, found);
            }
            assigned_block(body, name, found);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter().for_each(|e| assigned_expr(e, name, found));
            assigned_block(body, name, found);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            assigned_expr(cond, name, found);
            assigned_block(body, name, found);
            for (c, b) in else_ifs {
                assigned_expr(c, name, found);
                assigned_block(b, name, found);
            }
            if let Some(b) = otherwise {
                assigned_block(b, name, found);
            }
        }
        Stmt::Function { body, .. } => {
            if !binds_name(body, name) {
                assigned_block(&body.block, name, found);
            }
        }
        Stmt::LocalFunction { name: fname, body } => {
            if fname != name && !binds_name(body, name) {
                assigned_block(&body.block, name, found);
            }
        }
    }
}

fn assigned_lvalue_subexprs(e: &Expr, name: &str, found: &mut bool) {
    match e {
        Expr::Name(_) => {}
        Expr::Field { base, .. } => assigned_expr(base, name, found),
        Expr::Index { base, key } => {
            assigned_expr(base, name, found);
            assigned_expr(key, name, found);
        }
        _ => {}
    }
}

fn assigned_expr(e: &Expr, name: &str, found: &mut bool) {
    if *found {
        return;
    }
    if let Expr::Function(fb) = e {
        if !binds_name(fb, name) {
            assigned_block(&fb.block, name, found);
        }
        return;
    }
    e.each_child(&mut |c| assigned_expr(c, name, found));
}

fn propagate_scope(block: &mut Block, mode: OptMode, report: &mut OptReport) -> bool {
    propagate_scope_params(block, &[], mode, report)
}

fn propagate_scope_params(
    block: &mut Block,
    params: &[String],
    mode: OptMode,
    report: &mut OptReport,
) -> bool {
    let mut changed = false;

    for_each_direct_child_function(block, &mut |fb| {
        let p: Vec<String> = fb
            .params
            .iter()
            .filter_map(|x| match x {
                ir::Param::Name(n) => Some(n.clone()),
                ir::Param::Vararg => None,
            })
            .collect();
        changed |= propagate_scope_params(&mut fb.block, &p, mode, report);
    });

    let candidates = constant_candidates(block, params);
    for (name, lit) in candidates {
        let mut n = 0u32;
        find_and_subst_in_scope(block, &name, &lit, &mut n);
        if n > 0 {
            report.const_propagated += n;
            changed = true;
        }
    }
    let _ = mode;
    changed
}

fn find_and_subst_in_scope(block: &mut Block, name: &str, lit: &Expr, n: &mut u32) -> bool {
    let mut decl_idx = None;
    for (i, s) in block.stmts.iter().enumerate() {
        if let Stmt::Local { names, .. } = s {
            if names.iter().any(|x| x == name) {
                decl_idx = Some(i);
                break;
            }
        }
    }
    if let Some(i) = decl_idx {
        let len = block.stmts.len();
        for s in &mut block.stmts[i + 1..len] {
            subst_stmt(s, name, lit, n);
        }
        if let Some(LastStmt::Return(exprs)) = &mut block.last {
            for e in exprs {
                subst_expr(e, name, lit, n);
            }
        }
        return true;
    }
    let mut found = false;
    for s in &mut block.stmts {
        recurse_child_blocks(s, &mut |b| {
            if !found {
                found = find_and_subst_in_scope(b, name, lit, n);
            }
        });
        if found {
            break;
        }
    }
    found
}

fn for_each_direct_child_function(block: &mut Block, f: &mut impl FnMut(&mut FuncBody)) {
    for s in &mut block.stmts {
        if let Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } = s {
            f(body);
            continue;
        }
        stmt_exprs_mut(s, &mut |e| direct_functions_in_expr(e, f));
        recurse_child_blocks(s, &mut |b| for_each_direct_child_function(b, f));
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs {
            direct_functions_in_expr(e, f);
        }
    }
}

fn direct_functions_in_expr(e: &mut Expr, f: &mut impl FnMut(&mut FuncBody)) {
    if let Expr::Function(fb) = e {
        f(fb);
        return;
    }
    e.each_child_mut(&mut |c| direct_functions_in_expr(c, f));
}

fn binds_name(fb: &FuncBody, name: &str) -> bool {
    if fb
        .params
        .iter()
        .any(|p| matches!(p, ir::Param::Name(x) if x == name))
    {
        return true;
    }
    let mut intro = Vec::new();
    scope_introductions(&fb.block, &[], &mut intro);
    intro.iter().any(|x| x == name)
}

fn subst_stmt(s: &mut Stmt, name: &str, lit: &Expr, n: &mut u32) {
    match s {
        Stmt::Local { exprs, names } => {
            for e in exprs.iter_mut() {
                subst_expr(e, name, lit, n);
            }

            let _ = names;
        }
        Stmt::Assign { targets, exprs } => {
            for t in targets.iter_mut() {
                subst_lvalue(t, name, lit, n);
            }
            for e in exprs.iter_mut() {
                subst_expr(e, name, lit, n);
            }
        }
        Stmt::Compound { target, value, .. } => {
            subst_lvalue(target, name, lit, n);
            subst_expr(value, name, lit, n);
        }
        Stmt::Call(e) => subst_expr(e, name, lit, n),
        Stmt::Do(b) => subst_block_scoped(b, name, lit, n),
        Stmt::While { cond, body } => {
            subst_expr(cond, name, lit, n);
            subst_block_scoped(body, name, lit, n);
        }
        Stmt::Repeat { body, until } => {
            subst_block_scoped(body, name, lit, n);
            subst_expr(until, name, lit, n);
        }
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        } => {
            subst_expr(start, name, lit, n);
            subst_expr(end, name, lit, n);
            if let Some(s) = step {
                subst_expr(s, name, lit, n);
            }
            if var != name {
                subst_block_scoped(body, name, lit, n);
            }
        }
        Stmt::GenericFor { names, exprs, body } => {
            for e in exprs.iter_mut() {
                subst_expr(e, name, lit, n);
            }
            if !names.iter().any(|x| x == name) {
                subst_block_scoped(body, name, lit, n);
            }
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            subst_expr(cond, name, lit, n);
            subst_block_scoped(body, name, lit, n);
            for (c, b) in else_ifs.iter_mut() {
                subst_expr(c, name, lit, n);
                subst_block_scoped(b, name, lit, n);
            }
            if let Some(b) = otherwise {
                subst_block_scoped(b, name, lit, n);
            }
        }
        Stmt::Function { body, .. } => {
            if !binds_name(body, name) {
                subst_funcbody(body, name, lit, n);
            }
        }
        Stmt::LocalFunction { name: fname, body } => {
            if fname != name && !binds_name(body, name) {
                subst_funcbody(body, name, lit, n);
            }
        }
    }
}

fn subst_block_scoped(block: &mut Block, name: &str, lit: &Expr, n: &mut u32) {
    for s in &mut block.stmts {
        subst_stmt(s, name, lit, n);
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs {
            subst_expr(e, name, lit, n);
        }
    }
}

fn subst_funcbody(body: &mut FuncBody, name: &str, lit: &Expr, n: &mut u32) {
    subst_block_scoped(&mut body.block, name, lit, n);
}

fn subst_lvalue(e: &mut Expr, name: &str, lit: &Expr, n: &mut u32) {
    match e {
        Expr::Name(_) => {}
        Expr::Field { base, .. } => subst_expr(base, name, lit, n),
        Expr::Index { base, key } => {
            subst_expr(base, name, lit, n);
            subst_expr(key, name, lit, n);
        }
        _ => {}
    }
}

fn subst_expr(e: &mut Expr, name: &str, lit: &Expr, n: &mut u32) {
    match e {
        Expr::Name(x) if x == name => {
            *e = lit.clone();
            *n += 1;
        }
        Expr::Function(fb) => {
            if !binds_name(fb, name) {
                subst_funcbody(fb, name, lit, n);
            }
        }
        Expr::Field { base, .. } => subst_expr(base, name, lit, n),
        Expr::Index { base, key } => {
            subst_expr(base, name, lit, n);
            subst_expr(key, name, lit, n);
        }
        Expr::Call { func, args, .. } => {
            subst_expr(func, name, lit, n);
            for a in args {
                subst_expr(a, name, lit, n);
            }
        }
        Expr::MethodCall { base, args, .. } => {
            subst_expr(base, name, lit, n);
            for a in args {
                subst_expr(a, name, lit, n);
            }
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    Field::Positional(v) | Field::Named { value: v, .. } => {
                        subst_expr(v, name, lit, n)
                    }
                    Field::Keyed { key, value } => {
                        subst_expr(key, name, lit, n);
                        subst_expr(value, name, lit, n);
                    }
                }
            }
        }
        Expr::Binop { lhs, rhs, .. } => {
            subst_expr(lhs, name, lit, n);
            subst_expr(rhs, name, lit, n);
        }
        Expr::Unop { expr, .. } | Expr::Paren(expr) => subst_expr(expr, name, lit, n),
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            subst_expr(cond, name, lit, n);
            subst_expr(then, name, lit, n);
            for (c, v) in else_ifs {
                subst_expr(c, name, lit, n);
                subst_expr(v, name, lit, n);
            }
            subst_expr(otherwise, name, lit, n);
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    subst_expr(e, name, lit, n);
                }
            }
        }
        _ => {}
    }
}

fn pure_total(e: &Expr) -> bool {
    match e {
        Expr::Nil | Expr::True | Expr::False | Expr::Number(_) | Expr::Str(_) | Expr::Vararg => {
            true
        }
        Expr::Function(_) => true,
        Expr::Paren(inner) => pure_total(inner),
        Expr::Table(fields) => fields.iter().all(|f| match f {
            Field::Positional(v) | Field::Named { value: v, .. } => pure_total(v),
            Field::Keyed { key, value } => pure_total(key) && pure_total(value),
        }),
        _ => false,
    }
}

fn count_reads_scope(block: &Block, name: &str) -> u32 {
    let mut c = 0u32;
    count_reads_block(block, name, &mut c, true);
    c
}

fn count_reads_block(block: &Block, name: &str, c: &mut u32, active: bool) {
    for s in &block.stmts {
        count_reads_stmt(s, name, c, active);
    }
    if active {
        if let Some(LastStmt::Return(exprs)) = &block.last {
            for e in exprs {
                count_reads_expr(e, name, c);
            }
        }
    }
}

fn count_reads_stmt(s: &Stmt, name: &str, c: &mut u32, active: bool) {
    match s {
        Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| count_reads_expr(e, name, c)),
        Stmt::Assign { targets, exprs } => {
            for t in targets {
                count_reads_lvalue(t, name, c);
            }
            exprs.iter().for_each(|e| count_reads_expr(e, name, c));
        }
        Stmt::Compound { target, value, .. } => {
            count_reads_lvalue(target, name, c);

            if let Expr::Name(nn) = target {
                if nn == name {
                    *c += 1;
                }
            }
            count_reads_expr(value, name, c);
        }
        Stmt::Call(e) => count_reads_expr(e, name, c),
        Stmt::Do(b) => count_reads_block(b, name, c, active),
        Stmt::While { cond, body } => {
            count_reads_expr(cond, name, c);
            count_reads_block(body, name, c, active);
        }
        Stmt::Repeat { body, until } => {
            count_reads_block(body, name, c, active);
            count_reads_expr(until, name, c);
        }
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        } => {
            count_reads_expr(start, name, c);
            count_reads_expr(end, name, c);
            if let Some(s) = step {
                count_reads_expr(s, name, c);
            }
            count_reads_block(body, name, c, active && var != name);
        }
        Stmt::GenericFor { names, exprs, body } => {
            exprs.iter().for_each(|e| count_reads_expr(e, name, c));
            count_reads_block(body, name, c, active && !names.iter().any(|x| x == name));
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            count_reads_expr(cond, name, c);
            count_reads_block(body, name, c, active);
            for (cc, b) in else_ifs {
                count_reads_expr(cc, name, c);
                count_reads_block(b, name, c, active);
            }
            if let Some(b) = otherwise {
                count_reads_block(b, name, c, active);
            }
        }
        Stmt::Function { body, .. } => {
            if !binds_name(body, name) {
                count_reads_block(&body.block, name, c, true);
            }
        }
        Stmt::LocalFunction { name: fname, body } => {
            if fname != name && !binds_name(body, name) {
                count_reads_block(&body.block, name, c, true);
            }
        }
    }
}

fn count_reads_lvalue(e: &Expr, name: &str, c: &mut u32) {
    match e {
        Expr::Name(_) => {}
        Expr::Field { base, .. } => count_reads_expr(base, name, c),
        Expr::Index { base, key } => {
            count_reads_expr(base, name, c);
            count_reads_expr(key, name, c);
        }
        _ => {}
    }
}

fn count_reads_expr(e: &Expr, name: &str, c: &mut u32) {
    match e {
        Expr::Name(x) if x == name => *c += 1,
        Expr::Function(fb) => {
            if !binds_name(fb, name) {
                count_reads_block(&fb.block, name, c, true);
            }
        }
        _ => e.each_child(&mut |child| count_reads_expr(child, name, c)),
    }
}

fn dead_local_elim_scope(block: &mut Block, report: &mut OptReport) -> bool {
    let mut changed = false;
    dead_local_elim_block(block, report, &mut changed);
    changed
}

fn dead_local_elim_block(block: &mut Block, report: &mut OptReport, changed: &mut bool) {
    for_each_direct_child_function(block, &mut |fb| {
        dead_local_elim_block(&mut fb.block, report, changed)
    });

    let mut i = 0;
    while i < block.stmts.len() {
        let drop = matches!(&block.stmts[i], Stmt::Local { names, exprs }
            if names.len() == 1
                && (exprs.is_empty() || (exprs.len() == 1 && pure_total(&exprs[0])))
                && !assigned_including_captures(block, &names[0])
                && count_reads_scope(block, &names[0]) == 0);
        if drop {
            block.stmts.remove(i);
            report.dead_locals_removed += 1;
            *changed = true;
        } else {
            recurse_child_blocks(&mut block.stmts[i], &mut |b| {
                dead_local_elim_block(b, report, changed)
            });
            i += 1;
        }
    }
}

fn self_assign_elim_scope(block: &mut Block, report: &mut OptReport) -> bool {
    let mut intro = Vec::new();
    scope_introductions(block, &[], &mut intro);
    let mut changed = false;
    self_assign_elim_block(block, &intro, report, &mut changed);
    changed
}

fn self_assign_elim_block(
    block: &mut Block,
    locals: &[String],
    report: &mut OptReport,
    changed: &mut bool,
) {
    for_each_direct_child_function(block, &mut |fb| {
        let mut intro = Vec::new();
        scope_introductions(&fb.block, &[], &mut intro);
        for p in &fb.params {
            if let ir::Param::Name(n) = p {
                intro.push(n.clone());
            }
        }
        self_assign_elim_block(&mut fb.block, &intro, report, changed)
    });

    let mut i = 0;
    while i < block.stmts.len() {
        let is_self = matches!(&block.stmts[i], Stmt::Assign { targets, exprs }
            if targets.len() == 1 && exprs.len() == 1
                && matches!((&targets[0], &exprs[0]), (Expr::Name(a), Expr::Name(b))
                    if a == b && locals.iter().any(|l| l == a)));
        if is_self {
            block.stmts.remove(i);
            report.self_assigns_removed += 1;
            *changed = true;
        } else {
            recurse_child_blocks(&mut block.stmts[i], &mut |b| {
                self_assign_elim_block(b, locals, report, changed)
            });
            i += 1;
        }
    }
}

fn recurse_child_blocks(s: &mut Stmt, f: &mut impl FnMut(&mut Block)) {
    match s {
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

fn stmt_exprs_mut(s: &mut Stmt, f: &mut impl FnMut(&mut Expr)) {
    match s {
        Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(f),
        Stmt::Assign { targets, exprs } => {
            targets.iter_mut().for_each(&mut *f);
            exprs.iter_mut().for_each(f);
        }
        Stmt::Compound { target, value, .. } => {
            f(target);
            f(value);
        }
        Stmt::Call(e) => f(e),
        Stmt::While { cond, .. } => f(cond),
        Stmt::Repeat { until, .. } => f(until),
        Stmt::NumericFor {
            start, end, step, ..
        } => {
            f(start);
            f(end);
            if let Some(s) = step {
                f(s);
            }
        }
        Stmt::GenericFor { exprs, .. } => exprs.iter_mut().for_each(f),
        Stmt::If { cond, else_ifs, .. } => {
            f(cond);
            for (c, _) in else_ifs {
                f(c);
            }
        }
        _ => {}
    }
}

fn count_block(block: &Block) -> u32 {
    let mut c = 0u32;
    for s in &block.stmts {
        c += count_stmt(s);
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        c += 1;
        for e in exprs {
            c += count_expr(e);
        }
    } else if block.last.is_some() {
        c += 1;
    }
    c
}

fn count_stmt(s: &Stmt) -> u32 {
    let mut c = 1;
    stmt_child_blocks(s, &mut |b| c += count_block(b));
    stmt_child_exprs(s, &mut |e| c += count_expr(e));
    if let Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } = s {
        c += count_block(&body.block);
    }
    c
}

fn stmt_child_blocks(s: &Stmt, f: &mut impl FnMut(&Block)) {
    match s {
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

fn stmt_child_exprs(s: &Stmt, f: &mut impl FnMut(&Expr)) {
    match s {
        Stmt::Local { exprs, .. } => exprs.iter().for_each(f),
        Stmt::Assign { targets, exprs } => {
            targets.iter().for_each(&mut *f);
            exprs.iter().for_each(f);
        }
        Stmt::Compound { target, value, .. } => {
            f(target);
            f(value);
        }
        Stmt::Call(e) => f(e),
        Stmt::While { cond, .. } => f(cond),
        Stmt::Repeat { until, .. } => f(until),
        Stmt::NumericFor {
            start, end, step, ..
        } => {
            f(start);
            f(end);
            if let Some(s) = step {
                f(s);
            }
        }
        Stmt::GenericFor { exprs, .. } => exprs.iter().for_each(f),
        Stmt::If { cond, else_ifs, .. } => {
            f(cond);
            for (c, _) in else_ifs {
                f(c);
            }
        }
        _ => {}
    }
}

fn count_expr(e: &Expr) -> u32 {
    let mut c = 1;
    if let Expr::Function(fb) = e {
        c += count_block(&fb.block);
    }
    e.each_child(&mut |child| c += count_expr(child));
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::{Param, Stmt};

    fn module(stmts: Vec<Stmt>, last: Option<LastStmt>) -> Module {
        Module {
            block: Block { stmts, last },
            natives: vec![],
            hash_helper: false,
            encfuncs: vec![],
            prechecks: vec![],
        }
    }

    fn opt(stmts: Vec<Stmt>, last: Option<LastStmt>, mode: OptMode) -> (String, OptReport) {
        let mut m = module(stmts, last);
        let r = optimize(&mut m, mode);
        (ir::emit(&m), r)
    }

    fn local(name: &str, e: Expr) -> Stmt {
        Stmt::Local {
            names: vec![name.into()],
            exprs: vec![e],
        }
    }
    fn num(n: &str) -> Expr {
        Expr::Number(n.into())
    }
    fn name(n: &str) -> Expr {
        Expr::Name(n.into())
    }
    fn call(f: &str, args: Vec<Expr>) -> Expr {
        Expr::Call {
            func: Box::new(name(f)),
            args,
            site: None,
        }
    }

    #[test]
    fn off_mode_is_identity() {
        let stmts = vec![local("N", num("5")), Stmt::Call(call("f", vec![name("N")]))];
        let mut m = module(stmts.clone(), None);
        let before = m.clone();
        let r = optimize(&mut m, OptMode::Off);
        assert_eq!(m, before, "off mode must not touch the module");
        assert_eq!(r.mode, "off");
        assert!(!r.changed());
    }

    #[test]
    fn const_propagates_and_drops_dead_local() {
        let stmts = vec![local("N", num("5")), Stmt::Call(call("f", vec![name("N")]))];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert!(out.contains("f(5)"), "N propagated into the call: {out}");
        assert!(!out.contains("local N"), "dead constant removed: {out}");
        assert!(
            r.const_propagated >= 1 && r.dead_locals_removed >= 1,
            "{r:?}"
        );
    }

    #[test]
    fn const_prop_enables_folding() {
        let two = Expr::Binop {
            op: ir::BinOp::Mul,
            lhs: Box::new(name("N")),
            rhs: Box::new(num("2")),
        };
        let stmts = vec![local("N", num("5"))];
        let (out, _) = opt(stmts, Some(LastStmt::Return(vec![two])), OptMode::Safe);
        assert!(
            out.contains("return 10"),
            "5*2 folds after propagation: {out}"
        );
    }

    #[test]
    fn feature_flag_branch_is_eliminated() {
        let if_stmt = Stmt::If {
            cond: name("DEBUG"),
            body: Block {
                stmts: vec![Stmt::Call(call("dead", vec![]))],
                last: None,
            },
            else_ifs: vec![],
            otherwise: Some(Block {
                stmts: vec![Stmt::Call(call("live", vec![]))],
                last: None,
            }),
        };
        let stmts = vec![local("DEBUG", Expr::False), if_stmt];
        let (out, _) = opt(stmts, None, OptMode::Safe);
        assert!(out.contains("live()"), "live branch kept: {out}");
        assert!(!out.contains("dead()"), "dead false-branch removed: {out}");
        assert!(!out.contains("DEBUG"), "flag local removed: {out}");
    }

    #[test]
    fn reassigned_local_is_not_propagated() {
        let stmts = vec![
            local("x", num("1")),
            Stmt::Assign {
                targets: vec![name("x")],
                exprs: vec![num("2")],
            },
            Stmt::Call(call("f", vec![name("x")])),
        ];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert!(
            out.contains("f(x)"),
            "reassigned x must not be constant-folded: {out}"
        );
        assert_eq!(
            r.const_propagated, 0,
            "no propagation of a reassigned local"
        );
    }

    #[test]
    fn pre_declaration_read_is_a_different_binding() {
        let stmts = vec![
            Stmt::Call(call("f", vec![name("N")])),
            local("N", num("5")),
            Stmt::Call(call("g", vec![name("N")])),
        ];
        let (out, _) = opt(stmts, None, OptMode::Safe);
        assert!(
            out.contains("f(N)"),
            "read before the decl is the outer/global N: {out}"
        );
        assert!(
            out.contains("g(5)"),
            "read after the decl is the constant: {out}"
        );
    }

    #[test]
    fn param_shadow_blocks_substitution_but_capture_allows_it() {
        let f = Expr::Function(FuncBody {
            params: vec![Param::Name("N".into())],
            block: Block {
                stmts: vec![],
                last: Some(LastStmt::Return(vec![name("N")])),
            },
            hot_callback: None,
            stable_id: None,
        });
        let g = Expr::Function(FuncBody {
            params: vec![],
            block: Block {
                stmts: vec![],
                last: Some(LastStmt::Return(vec![name("N")])),
            },
            hot_callback: None,
            stable_id: None,
        });
        let stmts = vec![
            local("N", num("5")),
            local("f", f),
            local("g", g),
            Stmt::Call(call("use", vec![name("f"), name("g")])),
        ];
        let (out, _) = opt(stmts, None, OptMode::Safe);

        assert!(
            out.contains("function(N)") && out.contains("return N"),
            "param shadow preserved: {out}"
        );
        assert!(
            out.contains("return 5"),
            "capture of the constant substituted: {out}"
        );
    }

    #[test]
    fn dead_pure_local_removed_impure_kept() {
        let stmts = vec![
            local("a", num("5")),
            local("t", Expr::Table(vec![])),
            local("b", call("side", vec![])),
        ];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert!(
            !out.contains("local a"),
            "dead literal local removed: {out}"
        );
        assert!(
            !out.contains("local t"),
            "dead empty-table local removed: {out}"
        );
        assert!(
            out.contains("side()"),
            "impure initializer preserved: {out}"
        );
        assert!(r.dead_locals_removed >= 2);
    }

    #[test]
    fn macro_calls_are_never_removed_or_folded() {
        let stmts = vec![
            local("N", num("7")),
            local("x", call("BASIL_ENCFUNC", vec![name("N")])),
            Stmt::Call(call("BASIL_CRASH", vec![])),
        ];
        let (out, _) = opt(stmts, None, OptMode::Safe);
        assert!(
            out.contains("BASIL_ENCFUNC(7)"),
            "macro call kept, arg constant-propagated: {out}"
        );
        assert!(
            out.contains("BASIL_CRASH()"),
            "macro side-effect call preserved: {out}"
        );
    }

    #[test]
    fn self_assignment_of_local_removed() {
        let stmts = vec![
            local("x", num("1")),
            Stmt::Assign {
                targets: vec![name("x")],
                exprs: vec![name("x")],
            },
            Stmt::Call(call("f", vec![name("x")])),
        ];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert!(r.self_assigns_removed >= 1, "x = x removed: {r:?}");
        assert!(
            out.contains("f(1)"),
            "x still 1 after removing the no-op: {out}"
        );
    }

    #[test]
    fn global_self_assignment_is_not_removed() {
        let stmts = vec![Stmt::Assign {
            targets: vec![name("G")],
            exprs: vec![name("G")],
        }];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert_eq!(r.self_assigns_removed, 0, "global self-assign preserved");
        assert!(out.contains("G = G"), "{out}");
    }

    #[test]
    fn deterministic_and_report_populated() {
        let stmts = vec![local("N", num("3")), Stmt::Call(call("f", vec![name("N")]))];
        let (a, ra) = opt(stmts.clone(), None, OptMode::Safe);
        let (b, _rb) = opt(stmts, None, OptMode::Safe);
        assert_eq!(a, b, "same input -> identical output");
        assert!(ra.functions_examined >= 1);
        assert!(
            ra.ir_ops_before > ra.ir_ops_after,
            "work strictly reduced: {ra:?}"
        );
        assert_eq!(ra.mode, "safe");
    }

    #[test]
    fn nested_block_constant_is_propagated() {
        let inner = Block {
            stmts: vec![local("K", num("9")), Stmt::Call(call("f", vec![name("K")]))],
            last: None,
        };
        let (out, _) = opt(vec![Stmt::Do(inner)], None, OptMode::Safe);
        assert!(
            out.contains("f(9)"),
            "constant inside a do-block propagated: {out}"
        );
    }

    #[test]
    fn mutable_captured_upvalue_is_not_treated_as_constant() {
        let step = Expr::Function(FuncBody {
            params: vec![],
            block: Block {
                stmts: vec![Stmt::Assign {
                    targets: vec![name("n")],
                    exprs: vec![Expr::Binop {
                        op: ir::BinOp::Add,
                        lhs: Box::new(name("n")),
                        rhs: Box::new(num("1")),
                    }],
                }],
                last: Some(LastStmt::Return(vec![name("n")])),
            },
            hot_callback: None,
            stable_id: None,
        });
        let stmts = vec![
            local("n", num("0")),
            local("step", step),
            Stmt::Call(call("use", vec![name("step")])),
        ];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert_eq!(
            r.const_propagated, 0,
            "a mutated upvalue must not be constant-propagated: {out}"
        );
        assert!(
            out.contains("n + 1") && out.contains("return n"),
            "upvalue logic intact: {out}"
        );
        assert!(
            out.contains("local n = 0"),
            "the upvalue local must not be dropped: {out}"
        );
    }

    #[test]
    fn upvalue_mutated_in_a_returned_closure_is_safe() {
        let closure = Expr::Function(FuncBody {
            params: vec![],
            block: Block {
                stmts: vec![Stmt::Assign {
                    targets: vec![name("n")],
                    exprs: vec![Expr::Binop {
                        op: ir::BinOp::Add,
                        lhs: Box::new(name("n")),
                        rhs: Box::new(num("1")),
                    }],
                }],
                last: Some(LastStmt::Return(vec![name("n")])),
            },
            hot_callback: None,
            stable_id: None,
        });
        let mk_body = FuncBody {
            params: vec![],
            block: Block {
                stmts: vec![local("n", num("0"))],
                last: Some(LastStmt::Return(vec![closure])),
            },
            hot_callback: None,
            stable_id: None,
        };
        let stmts = vec![Stmt::LocalFunction {
            name: "mk".into(),
            body: mk_body,
        }];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert_eq!(
            r.const_propagated, 0,
            "upvalue in a returned closure must not be propagated: {out}"
        );
        assert!(
            out.contains("return n"),
            "counter returns the live upvalue, not a constant: {out}"
        );
    }

    #[test]
    fn write_only_captured_local_is_not_dead_eliminated() {
        let setf = Expr::Function(FuncBody {
            params: vec![],
            block: Block {
                stmts: vec![Stmt::Assign {
                    targets: vec![name("flag")],
                    exprs: vec![num("5")],
                }],
                last: None,
            },
            hot_callback: None,
            stable_id: None,
        });
        let stmts = vec![
            local("flag", num("0")),
            local("set", setf),
            Stmt::Call(call("set", vec![])),
        ];
        let (out, r) = opt(stmts, None, OptMode::Safe);
        assert_eq!(
            r.dead_locals_removed, 0,
            "a local written by a closure must not be dropped: {out}"
        );
        assert!(
            out.contains("local flag = 0"),
            "upvalue target preserved: {out}"
        );
    }

    #[test]
    fn experimental_is_at_least_as_strong_as_safe() {
        let stmts = vec![local("N", num("5")), Stmt::Call(call("f", vec![name("N")]))];
        let (safe, _) = opt(stmts.clone(), None, OptMode::Safe);
        let (exp, _) = opt(stmts, None, OptMode::Experimental);
        assert!(exp.contains("f(5)") && safe.contains("f(5)"));
    }
}
