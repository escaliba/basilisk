use ir::{Block, Expr, FuncBody, LastStmt, Stmt, UnOp};

use crate::Error;

const ATTRIBUTES: &str = "BASIL_ATTRIBUTES";
const A_INLINE: &str = "INLINE";
const A_VM: &str = "VM";
const A_ENCRYPT: &str = "ENCRYPT";
const A_UNROLL: &str = "UNROLL";
const VM_NONE: &str = "NONE";
const VM_PROTECTED: &str = "PROTECTED";

const M_INLINE: &str = "BASIL_INLINE";
const M_NO_VIRTUALIZE: &str = "BASIL_NO_VIRTUALIZE";
const M_ENCFUNC: &str = "BASIL_ENCFUNC";

const MAX_TRIP_COUNT: i128 = 64;
const MAX_UNROLL_COST: i128 = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
enum VmKind {
    Protected,
    None,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Checked,
    BestEffort,
}

struct AttrSet {
    inline: Option<Mode>,
    vm: Option<VmKind>,
    encrypt: Option<(Expr, Expr)>,
    unroll: Option<Mode>,
}

impl AttrSet {
    fn is_empty_effect(&self) -> bool {
        self.inline.is_none()
            && self.encrypt.is_none()
            && self.unroll.is_none()
            && !matches!(self.vm, Some(VmKind::None))
    }
}

pub fn lower(block: &mut Block) -> Result<(), Error> {
    lower_block(block)
}

fn lower_block(block: &mut Block) -> Result<(), Error> {
    let stmts = std::mem::take(&mut block.stmts);
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for s in stmts {
        out.extend(lower_one(s)?);
    }
    block.stmts = out;
    if let Some(LastStmt::Return(es)) = &mut block.last {
        for e in es {
            lower_expr(e)?;
        }
    }
    Ok(())
}

fn lower_one(stmt: Stmt) -> Result<Vec<Stmt>, Error> {
    match stmt {
        Stmt::LocalFunction { name, mut body } => {
            let attrs = take_marker(&mut body.block)?;
            lower_block(&mut body.block)?;
            match attrs {
                None => Ok(vec![Stmt::LocalFunction { name, body }]),
                Some(a) => func_local_binding(name, body, a),
            }
        }
        Stmt::Local { names, mut exprs } => {
            let marker = if exprs.len() == 1 && matches!(exprs[0], Expr::Function(_)) {
                let Expr::Function(fb) = &mut exprs[0] else {
                    unreachable!()
                };
                let m = take_marker(&mut fb.block)?;
                if m.is_some() {
                    lower_block(&mut fb.block)?;
                }
                m
            } else {
                None
            };
            if let Some(a) = marker {
                if names.len() != 1 {
                    return Err(macro_err(
                        "BASIL_ATTRIBUTES on a function must bind exactly one local",
                    ));
                }
                forbid_loop_attrs(&a, "a function")?;
                let Expr::Function(fb) = std::mem::replace(&mut exprs[0], Expr::Nil) else {
                    unreachable!()
                };
                let wrapped = build_func_wrap(fb, a, true)?;
                return Ok(vec![Stmt::Local {
                    names,
                    exprs: vec![wrapped],
                }]);
            }
            for e in &mut exprs {
                lower_expr(e)?;
            }
            Ok(vec![Stmt::Local { names, exprs }])
        }
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            mut body,
        } => {
            let attrs = take_marker(&mut body)?;
            lower_block(&mut body)?;
            match attrs {
                None => Ok(vec![Stmt::NumericFor {
                    var,
                    start,
                    end,
                    step,
                    body,
                }]),
                Some(a) => unroll_or_keep(var, start, end, step, body, a),
            }
        }
        Stmt::Function { name, mut body } => {
            if body.block.stmts.first().is_some_and(is_marker_stmt) {
                return Err(macro_err(
                    "BASIL_ATTRIBUTES on a global or method function is not supported; bind the \
                     function to a local (e.g. `local function f(...)`)",
                ));
            }
            lower_block(&mut body.block)?;
            Ok(vec![Stmt::Function { name, body }])
        }
        Stmt::Call(e) => {
            if is_marker_call(&e) {
                return Err(misplaced());
            }
            let mut e = e;
            lower_expr(&mut e)?;
            Ok(vec![Stmt::Call(e)])
        }
        Stmt::Do(mut b) => {
            lower_block(&mut b)?;
            Ok(vec![Stmt::Do(b)])
        }
        Stmt::While { cond, mut body } => {
            let mut cond = cond;
            lower_expr(&mut cond)?;
            lower_block(&mut body)?;
            Ok(vec![Stmt::While { cond, body }])
        }
        Stmt::Repeat { mut body, until } => {
            let mut until = until;
            lower_block(&mut body)?;
            lower_expr(&mut until)?;
            Ok(vec![Stmt::Repeat { body, until }])
        }
        Stmt::GenericFor {
            names,
            exprs,
            mut body,
        } => {
            let mut exprs = exprs;
            for e in &mut exprs {
                lower_expr(e)?;
            }
            lower_block(&mut body)?;
            Ok(vec![Stmt::GenericFor { names, exprs, body }])
        }
        Stmt::If {
            cond,
            mut body,
            else_ifs,
            otherwise,
        } => {
            let mut cond = cond;
            lower_expr(&mut cond)?;
            lower_block(&mut body)?;
            let mut else_ifs = else_ifs;
            for (c, b) in &mut else_ifs {
                lower_expr(c)?;
                lower_block(b)?;
            }
            let mut otherwise = otherwise;
            if let Some(b) = &mut otherwise {
                lower_block(b)?;
            }
            Ok(vec![Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            }])
        }
        Stmt::Assign {
            mut targets,
            mut exprs,
        } => {
            for e in targets.iter_mut().chain(exprs.iter_mut()) {
                lower_expr(e)?;
            }
            Ok(vec![Stmt::Assign { targets, exprs }])
        }
        Stmt::Compound {
            mut target,
            op,
            mut value,
        } => {
            lower_expr(&mut target)?;
            lower_expr(&mut value)?;
            Ok(vec![Stmt::Compound { target, op, value }])
        }
    }
}

fn lower_expr(e: &mut Expr) -> Result<(), Error> {
    if is_marker_call(e) {
        return Err(misplaced());
    }
    if matches!(e, Expr::Function(_)) {
        let attrs = {
            let Expr::Function(fb) = e else {
                unreachable!()
            };
            let m = take_marker(&mut fb.block)?;
            lower_block(&mut fb.block)?;
            m
        };
        if let Some(a) = attrs {
            forbid_loop_attrs(&a, "a function")?;
            let Expr::Function(fb) = std::mem::replace(e, Expr::Nil) else {
                unreachable!()
            };
            *e = build_func_wrap(fb, a, false)?;
        }
        return Ok(());
    }
    let mut r = Ok(());
    e.each_child_mut(&mut |c| {
        if r.is_ok() {
            r = lower_expr(c);
        }
    });
    r
}

fn func_local_binding(name: String, body: FuncBody, attrs: AttrSet) -> Result<Vec<Stmt>, Error> {
    forbid_loop_attrs(&attrs, "a function")?;
    if attrs.is_empty_effect() {
        return Ok(vec![Stmt::LocalFunction { name, body }]);
    }
    if crate::free_vars(&body).contains(&name) {
        return Err(macro_err(&format!(
            "attributed local function `{name}` refers to itself; INLINE/VM/ENCRYPT require a \
             non-recursive function"
        )));
    }
    let wrapped = build_func_wrap(body, attrs, true)?;
    Ok(vec![Stmt::Local {
        names: vec![name],
        exprs: vec![wrapped],
    }])
}

fn build_func_wrap(body: FuncBody, attrs: AttrSet, allow_inline: bool) -> Result<Expr, Error> {
    let has_inline = attrs.inline.is_some();
    let has_encrypt = attrs.encrypt.is_some();
    let vm_none = matches!(attrs.vm, Some(VmKind::None));

    if vm_none && has_encrypt {
        return Err(macro_err(
            "VM(NONE) cannot be combined with ENCRYPT: a native function cannot be sealed",
        ));
    }
    if vm_none && has_inline {
        return Err(macro_err(
            "VM(NONE) cannot be combined with INLINE: a native function is not virtualized",
        ));
    }
    if has_inline && has_encrypt {
        return Err(macro_err(
            "INLINE cannot be combined with ENCRYPT: a sealed function's boundary must stay distinct",
        ));
    }

    let fn_expr = Expr::Function(body);
    if let Some((key, runtime)) = attrs.encrypt {
        return Ok(call(M_ENCFUNC, vec![fn_expr, key, runtime]));
    }
    if let Some(mode) = attrs.inline {
        if !allow_inline {
            return Err(macro_err(
                "INLINE requires the function to be bound to a single local, e.g. \
                 `local f = ...` or `local function f`",
            ));
        }
        if mode == Mode::BestEffort {
            return Err(macro_err(
                "INLINE(false) (best-effort inlining) is not yet supported; use INLINE() for \
                 checked inlining",
            ));
        }
        return Ok(call(M_INLINE, vec![fn_expr]));
    }
    if vm_none {
        return Ok(call(M_NO_VIRTUALIZE, vec![fn_expr]));
    }
    Ok(fn_expr)
}

fn unroll_or_keep(
    var: String,
    start: Expr,
    end: Expr,
    step: Option<Expr>,
    body: Block,
    attrs: AttrSet,
) -> Result<Vec<Stmt>, Error> {
    if attrs.inline.is_some() || attrs.vm.is_some() || attrs.encrypt.is_some() {
        return Err(macro_err("only UNROLL applies to a numeric-for loop"));
    }
    let mode = match attrs.unroll {
        Some(m) => m,
        None => {
            return Ok(vec![Stmt::NumericFor {
                var,
                start,
                end,
                step,
                body,
            }])
        }
    };
    let keep = |var, start, end, step, body| {
        vec![Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        }]
    };
    let bail = |msg: &str, var, start, end, step, body| -> Result<Vec<Stmt>, Error> {
        match mode {
            Mode::Checked => Err(macro_err(msg)),
            Mode::BestEffort => Ok(keep(var, start, end, step, body)),
        }
    };

    let (Some(s), Some(e)) = (int_lit(&start), int_lit(&end)) else {
        return bail(
            "BASIL_ATTRIBUTES(UNROLL()) requires compile-time-constant integer loop bounds",
            var,
            start,
            end,
            step,
            body,
        );
    };
    let t = match &step {
        None => 1,
        Some(se) => match int_lit(se) {
            Some(v) => v,
            None => {
                return bail(
                    "BASIL_ATTRIBUTES(UNROLL()) requires a compile-time-constant integer step",
                    var,
                    start,
                    end,
                    step,
                    body,
                )
            }
        },
    };
    if t == 0 {
        return bail(
            "a numeric-for step of zero cannot be unrolled",
            var,
            start,
            end,
            step,
            body,
        );
    }
    if has_loop_control(&body) {
        return bail(
            "cannot unroll a numeric-for whose body uses break or continue",
            var,
            start,
            end,
            step,
            body,
        );
    }

    let (s, e, t) = (s as i128, e as i128, t as i128);
    let count: i128 = if t > 0 {
        if e < s {
            0
        } else {
            (e - s) / t + 1
        }
    } else if e > s {
        0
    } else {
        (s - e) / (-t) + 1
    };
    let cost = count * (count_block(&body) as i128).max(1);
    if count > MAX_TRIP_COUNT || cost > MAX_UNROLL_COST {
        return bail(
            "loop is too large to unroll (trip count must be <= 64 and trip*body cost <= 256)",
            var,
            start,
            end,
            step,
            body,
        );
    }

    let returns = matches!(body.last, Some(LastStmt::Return(_)));
    let iters = if returns { count.min(1) } else { count };
    let mut out: Vec<Stmt> = Vec::with_capacity(iters as usize);
    for k in 0..iters {
        let value = (s + k * t) as i64;
        let mut stmts = Vec::with_capacity(body.stmts.len() + 1);
        stmts.push(Stmt::Local {
            names: vec![var.clone()],
            exprs: vec![num_lit(value)],
        });
        stmts.extend(body.stmts.iter().cloned());
        out.push(Stmt::Do(Block {
            stmts,
            last: body.last.clone(),
        }));
    }
    Ok(out)
}

fn take_marker(block: &mut Block) -> Result<Option<AttrSet>, Error> {
    if !block.stmts.first().is_some_and(is_marker_stmt) {
        return Ok(None);
    }
    let Stmt::Call(Expr::Call { args, .. }) = block.stmts.remove(0) else {
        unreachable!()
    };
    Ok(Some(parse_attrs(args)?))
}

fn parse_attrs(entries: Vec<Expr>) -> Result<AttrSet, Error> {
    let mut set = AttrSet {
        inline: None,
        vm: None,
        encrypt: None,
        unroll: None,
    };
    for entry in entries {
        let Expr::Call { func, args, .. } = entry else {
            return Err(macro_err(
                "each BASIL_ATTRIBUTES entry must be an attribute like INLINE(), VM(NONE), \
                 ENCRYPT(key, runtimeKey), or UNROLL()",
            ));
        };
        let Expr::Name(n) = *func else {
            return Err(macro_err(
                "BASIL_ATTRIBUTES entries must be plain attribute names",
            ));
        };
        match n.as_str() {
            A_INLINE => {
                if set.inline.is_some() {
                    return Err(dup(A_INLINE));
                }
                set.inline = Some(parse_mode(&args, A_INLINE)?);
            }
            A_UNROLL => {
                if set.unroll.is_some() {
                    return Err(dup(A_UNROLL));
                }
                set.unroll = Some(parse_mode(&args, A_UNROLL)?);
            }
            A_VM => {
                if set.vm.is_some() {
                    return Err(dup(A_VM));
                }
                set.vm = Some(parse_vm(args)?);
            }
            A_ENCRYPT => {
                if set.encrypt.is_some() {
                    return Err(dup(A_ENCRYPT));
                }
                if args.len() != 2 {
                    return Err(macro_err(
                        "ENCRYPT takes exactly two arguments: a 64-hex compile key and a runtime key",
                    ));
                }
                let mut it = args.into_iter();
                set.encrypt = Some((it.next().unwrap(), it.next().unwrap()));
            }
            other => {
                return Err(macro_err(&format!(
                    "unknown attribute `{other}` in BASIL_ATTRIBUTES; supported: INLINE, VM, ENCRYPT, UNROLL"
                )))
            }
        }
    }
    Ok(set)
}

fn parse_mode(args: &[Expr], name: &str) -> Result<Mode, Error> {
    match args {
        [] => Ok(Mode::Checked),
        [Expr::True] => Ok(Mode::Checked),
        [Expr::False] => Ok(Mode::BestEffort),
        _ => Err(macro_err(&format!(
            "{name} takes no arguments or a single boolean literal"
        ))),
    }
}

fn parse_vm(args: Vec<Expr>) -> Result<VmKind, Error> {
    match args.as_slice() {
        [Expr::Name(n)] if n == VM_PROTECTED => Ok(VmKind::Protected),
        [Expr::Name(n)] if n == VM_NONE => Ok(VmKind::None),
        _ => Err(macro_err("VM requires exactly one of PROTECTED or NONE")),
    }
}

fn forbid_loop_attrs(a: &AttrSet, where_: &str) -> Result<(), Error> {
    if a.unroll.is_some() {
        return Err(macro_err(&format!(
            "UNROLL applies to a numeric-for loop, not {where_}"
        )));
    }
    Ok(())
}

fn is_marker_call(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, .. } if matches!(&**func, Expr::Name(n) if n == ATTRIBUTES))
}

fn is_marker_stmt(s: &Stmt) -> bool {
    matches!(s, Stmt::Call(e) if is_marker_call(e))
}

fn call(name: &str, args: Vec<Expr>) -> Expr {
    Expr::Call {
        func: Box::new(Expr::Name(name.to_string())),
        args,
        site: None,
    }
}

fn num_lit(v: i64) -> Expr {
    if v < 0 {
        Expr::Unop {
            op: UnOp::Neg,
            expr: Box::new(Expr::Number((-(v as i128)).to_string())),
        }
    } else {
        Expr::Number(v.to_string())
    }
}

fn int_lit(e: &Expr) -> Option<i64> {
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
            op: UnOp::Neg,
            expr,
        } => int_lit(expr).and_then(|v| v.checked_neg()),
        Expr::Paren(inner) => int_lit(inner),
        _ => None,
    }
}

fn count_block(b: &Block) -> usize {
    let mut n = b.stmts.len();
    for s in &b.stmts {
        n += count_stmt(s);
    }
    n
}

fn count_stmt(s: &Stmt) -> usize {
    match s {
        Stmt::Do(b) | Stmt::While { body: b, .. } | Stmt::Repeat { body: b, .. } => count_block(b),
        Stmt::NumericFor { body, .. } | Stmt::GenericFor { body, .. } => count_block(body),
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            count_block(body)
                + else_ifs.iter().map(|(_, b)| count_block(b)).sum::<usize>()
                + otherwise.as_ref().map_or(0, count_block)
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => count_block(&body.block),
        _ => 0,
    }
}

fn has_loop_control(b: &Block) -> bool {
    if matches!(b.last, Some(LastStmt::Break) | Some(LastStmt::Continue)) {
        return true;
    }
    b.stmts.iter().any(stmt_has_loop_control)
}

fn stmt_has_loop_control(s: &Stmt) -> bool {
    match s {
        Stmt::Do(b) => has_loop_control(b),
        Stmt::If {
            body,
            else_ifs,
            otherwise,
            ..
        } => {
            has_loop_control(body)
                || else_ifs.iter().any(|(_, b)| has_loop_control(b))
                || otherwise.as_ref().is_some_and(has_loop_control)
        }
        _ => false,
    }
}

fn macro_err(msg: &str) -> Error {
    Error::Macro(msg.to_string())
}

fn dup(name: &str) -> Error {
    Error::Macro(format!("duplicate `{name}` attribute in BASIL_ATTRIBUTES"))
}

fn misplaced() -> Error {
    Error::Macro(
        "BASIL_ATTRIBUTES must be the first statement of the function or numeric-for body it \
         annotates"
            .into(),
    )
}
