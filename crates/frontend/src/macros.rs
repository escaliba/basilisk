use std::collections::{BTreeSet, HashMap};

use ir::{BinOp, Block, Expr, Field, FuncBody, InterpPart, LastStmt, Module, Param, Stmt, UnOp};

use bytecode::sha256;

use crate::Error;

const PREFIX: &str = "BASIL_";
const NO_VIRTUALIZE: &str = "BASIL_NO_VIRTUALIZE";
const OBFUSCATED_FLAG: &str = "BASIL_OBFUSCATED";
const CRASH: &str = "BASIL_CRASH";
const HASH: &str = "BASIL_HASH";
const OPAQUE: &str = "BASIL_OPAQUE";
const ENCFUNC: &str = "BASIL_ENCFUNC";
const ENCFUNC_SEED: &str = "BASIL_ENCFUNC_SEED";
const OPCODE: &str = "BASIL_OPCODE";

fn strip_quotes(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn parse_opcode(args: &[Expr]) -> Result<(ir::OpFamily, u8), Error> {
    if args.is_empty() || args.len() > 2 {
        return Err(Error::Macro(format!(
            "BASIL_OPCODE takes a family name and an optional intensity, got {} argument(s)",
            args.len()
        )));
    }
    let fam = match &args[0] {
        Expr::Str(s) => strip_quotes(s),
        _ => {
            return Err(Error::Macro(
                "BASIL_OPCODE family must be a string literal, e.g. BASIL_OPCODE(\"CALL\")".into(),
            ))
        }
    };
    let family = ir::OpFamily::from_name(&fam).ok_or_else(|| {
        Error::Macro(format!(
            "unknown BASIL_OPCODE family `{fam}`; supported: {}",
            ir::OpFamily::SUPPORTED.join(", ")
        ))
    })?;
    let intensity = match args.get(1) {
        None => 1u8,
        Some(Expr::Number(n)) => {
            let v: i64 = n.trim().parse().map_err(|_| {
                Error::Macro(format!(
                    "BASIL_OPCODE intensity must be an integer literal 1..8, got `{n}`"
                ))
            })?;
            if !(1..=8).contains(&v) {
                return Err(Error::Macro(format!(
                    "BASIL_OPCODE intensity must be 1..8, got {v}"
                )));
            }
            v as u8
        }
        Some(_) => {
            return Err(Error::Macro(
                "BASIL_OPCODE intensity must be an integer literal (1..8), not a dynamic value"
                    .into(),
            ))
        }
    };
    Ok((family, intensity))
}

fn assign_opcode_keys(block: &mut Block, seed: u64) {
    let mut counter = 0u64;
    keys_block(block, seed, &mut counter);
}

fn keys_block(block: &mut Block, seed: u64, counter: &mut u64) {
    for s in &mut block.stmts {
        keys_stmt(s, seed, counter);
    }
    if let Some(LastStmt::Return(es)) = &mut block.last {
        for e in es {
            keys_expr(e, seed, counter);
        }
    }
}

fn keys_stmt(stmt: &mut Stmt, seed: u64, counter: &mut u64) {
    match stmt {
        Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| keys_expr(e, seed, counter)),
        Stmt::Assign { targets, exprs } => targets
            .iter_mut()
            .chain(exprs)
            .for_each(|e| keys_expr(e, seed, counter)),
        Stmt::Compound { target, value, .. } => {
            keys_expr(target, seed, counter);
            keys_expr(value, seed, counter);
        }
        Stmt::Call(e) => keys_expr(e, seed, counter),
        Stmt::Do(b) => keys_block(b, seed, counter),
        Stmt::While { cond, body } => {
            keys_expr(cond, seed, counter);
            keys_block(body, seed, counter);
        }
        Stmt::Repeat { body, until } => {
            keys_block(body, seed, counter);
            keys_expr(until, seed, counter);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            keys_expr(start, seed, counter);
            keys_expr(end, seed, counter);
            if let Some(s) = step {
                keys_expr(s, seed, counter);
            }
            keys_block(body, seed, counter);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter_mut().for_each(|e| keys_expr(e, seed, counter));
            keys_block(body, seed, counter);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            keys_expr(cond, seed, counter);
            keys_block(body, seed, counter);
            for (c, b) in else_ifs {
                keys_expr(c, seed, counter);
                keys_block(b, seed, counter);
            }
            if let Some(b) = otherwise {
                keys_block(b, seed, counter);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            keys_block(&mut body.block, seed, counter)
        }
    }
}

fn keys_expr(expr: &mut Expr, seed: u64, counter: &mut u64) {
    match expr {
        Expr::OpcodeHint { key, .. } => {
            *key = opcode_key(seed, *counter);
            *counter += 1;
        }
        Expr::Function(fb) => keys_block(&mut fb.block, seed, counter),
        other => other.each_child_mut(&mut |c| keys_expr(c, seed, counter)),
    }
}

fn opcode_key(seed: u64, counter: u64) -> u64 {
    let mut x = seed ^ 0x_4F50_434F_4445_4B59 ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub fn expand(mut module: Module, seed: u64) -> Result<Module, Error> {
    fold_block(&mut module.block);
    crate::attributes::lower(&mut module.block)?;
    crate::stackalloc::expand(&mut module)?;
    crate::encval::lower(&mut module.block, seed)?;
    crate::precheck::extract(&mut module)?;
    crate::capture_native::promote(&mut module.block)?;

    let mut natives: Vec<FuncBody> = Vec::new();
    let mut encfuncs: Vec<ir::EncFunc> = Vec::new();
    let mut scope = Scope::new();

    let mut taint: TaintEnv = vec![HashMap::new()];
    scope.push();
    rewrite_block(
        &mut module.block,
        &mut natives,
        &mut encfuncs,
        &mut taint,
        &mut scope,
    )?;
    scope.pop();
    module.natives = natives;
    assign_opcode_keys(&mut module.block, seed);
    for ef in &mut encfuncs {
        assign_opcode_keys(&mut ef.body.block, seed);
    }

    let base = module.natives.len() as u32;
    let mut ctx = DrmCtx {
        hash_idx: base,
        hash_used: false,
        rng: Rng::new(seed ^ 0x_4452_4D5F_5345_4544),
    };
    drm_block(&mut module.block, &mut ctx)?;
    for ef in &mut encfuncs {
        drm_block(&mut ef.body.block, &mut ctx)?;
    }
    module.hash_helper = ctx.hash_used;
    module.encfuncs = encfuncs;

    for ef in &module.encfuncs {
        let Some(key) = ef.key.literal_hex() else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        let leaked = key_in_strings(&module.block, &key)
            || module
                .encfuncs
                .iter()
                .any(|o| key_in_strings(&o.body.block, &key));
        if leaked {
            return Err(Error::Macro(
                "BASIL_ENCFUNC key must appear only as the macro key; it was found in another string constant".into(),
            ));
        }
    }

    if let Some(name) = find_reserved(&module.block) {
        return Err(Error::Macro(format!(
            "`{name}` uses the reserved `BASIL_` prefix but is not a recognized macro"
        )));
    }

    for ef in &module.encfuncs {
        if let Some(name) = find_reserved(&ef.body.block) {
            return Err(Error::Macro(format!(
                "`{name}` uses the reserved `BASIL_` prefix but is not a recognized macro"
            )));
        }
    }
    Ok(module)
}

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + (self.next() % ((hi - lo + 1) as u64)) as i64
    }
}

struct DrmCtx {
    hash_idx: u32,
    hash_used: bool,
    rng: Rng,
}

fn num(n: i64) -> Expr {
    Expr::Number(n.to_string())
}

fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Binop {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn opaque_expr(value: bool, rng: &mut Rng) -> Expr {
    match rng.range(0, 3) {
        0 => {
            let (a, b, c, m) = (
                rng.range(2, 200),
                rng.range(2, 200),
                rng.range(1, 200),
                rng.range(3, 251),
            );
            let v = (a * b + c) % m;
            let k = if value { v } else { (v + 1) % m };
            bin(
                BinOp::Eq,
                bin(
                    BinOp::Mod,
                    bin(BinOp::Add, bin(BinOp::Mul, num(a), num(b)), num(c)),
                    num(m),
                ),
                num(k),
            )
        }
        1 => {
            let len = rng.range(1, 16);
            let lit: String = (0..len)
                .map(|_| (b'a' + (rng.range(0, 25) as u8)) as char)
                .collect();
            let n = rng.range(0, 200);
            let v = len + n;
            let m = if value { v } else { v + 1 };

            let s = Expr::Str(format!("\"{lit}\""));
            bin(
                BinOp::Eq,
                bin(
                    BinOp::Add,
                    Expr::Unop {
                        op: UnOp::Len,
                        expr: Box::new(s),
                    },
                    num(n),
                ),
                num(m),
            )
        }
        2 => {
            let (a, b, m) = (rng.range(2, 200), rng.range(2, 200), rng.range(3, 251));
            let v = (a * b) % m;
            let k = if value { (v + 1) % m } else { v };
            bin(
                BinOp::Ne,
                bin(BinOp::Mod, bin(BinOp::Mul, num(a), num(b)), num(m)),
                num(k),
            )
        }
        _ => {
            let (a, b, c) = (rng.range(50, 250), rng.range(50, 250), rng.range(1, 80));
            let v = a + b - c;
            let d = if value { v } else { v + 1 };
            bin(
                BinOp::Eq,
                bin(BinOp::Sub, bin(BinOp::Add, num(a), num(b)), num(c)),
                num(d),
            )
        }
    }
}

fn lower_hash(args: &mut Vec<Expr>, ctx: &mut DrmCtx) -> Result<Expr, Error> {
    if args.len() != 1 {
        return Err(Error::Macro(format!(
            "BASIL_HASH takes exactly one argument, got {}",
            args.len()
        )));
    }
    match args.remove(0) {

        Expr::Str(s) => {
            let bytes = bytecode::literal::decode_string(&s)
                .ok_or_else(|| Error::Macro(format!("BASIL_HASH literal is not a valid string: {s}")))?;
            Ok(Expr::Str(format!("\"{}\"", sha256::hex(&bytes))))
        }
        Expr::Number(_) | Expr::True | Expr::False | Expr::Nil | Expr::Table(_) | Expr::Vararg => Err(
            Error::Macro("BASIL_HASH expects a string literal or a runtime string expression, not a non-string literal/table".into()),
        ),
        other => {
            let mut arg = other;
            drm_expr(&mut arg, ctx)?;
            ctx.hash_used = true;
            Ok(Expr::Call { func: Box::new(Expr::NativeRef(ctx.hash_idx)), args: vec![arg], site: None })
        }
    }
}

fn lower_opaque(args: &[Expr], ctx: &mut DrmCtx) -> Result<Expr, Error> {
    if args.len() != 1 {
        return Err(Error::Macro(format!(
            "BASIL_OPAQUE takes exactly one boolean literal, got {}",
            args.len()
        )));
    }
    let value = match &args[0] {
        Expr::True => true,
        Expr::False => false,
        _ => {
            return Err(Error::Macro(
                "BASIL_OPAQUE accepts only the boolean literals `true` or `false`".into(),
            ))
        }
    };
    Ok(Expr::Paren(Box::new(opaque_expr(value, &mut ctx.rng))))
}

fn drm_block(block: &mut Block, ctx: &mut DrmCtx) -> Result<(), Error> {
    for stmt in &mut block.stmts {
        drm_stmt(stmt, ctx)?;
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs {
            drm_expr(e, ctx)?;
        }
    }
    Ok(())
}

fn drm_stmt(stmt: &mut Stmt, ctx: &mut DrmCtx) -> Result<(), Error> {
    match stmt {
        Stmt::Local { exprs, .. } => {
            for e in exprs {
                drm_expr(e, ctx)?;
            }
        }
        Stmt::Assign { targets, exprs } => {
            for t in targets {
                drm_expr(t, ctx)?;
            }
            for e in exprs {
                drm_expr(e, ctx)?;
            }
        }
        Stmt::Compound { target, value, .. } => {
            drm_expr(target, ctx)?;
            drm_expr(value, ctx)?;
        }
        Stmt::Call(e) => drm_expr(e, ctx)?,
        Stmt::Do(b) => drm_block(b, ctx)?,
        Stmt::While { cond, body } => {
            drm_expr(cond, ctx)?;
            drm_block(body, ctx)?;
        }
        Stmt::Repeat { body, until } => {
            drm_block(body, ctx)?;
            drm_expr(until, ctx)?;
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            drm_expr(start, ctx)?;
            drm_expr(end, ctx)?;
            if let Some(s) = step {
                drm_expr(s, ctx)?;
            }
            drm_block(body, ctx)?;
        }
        Stmt::GenericFor { exprs, body, .. } => {
            for e in exprs {
                drm_expr(e, ctx)?;
            }
            drm_block(body, ctx)?;
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            drm_expr(cond, ctx)?;
            drm_block(body, ctx)?;
            for (c, b) in else_ifs {
                drm_expr(c, ctx)?;
                drm_block(b, ctx)?;
            }
            if let Some(b) = otherwise {
                drm_block(b, ctx)?;
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            drm_block(&mut body.block, ctx)?
        }
    }
    Ok(())
}

fn drm_expr(expr: &mut Expr, ctx: &mut DrmCtx) -> Result<(), Error> {
    if let Expr::Call { func, args, .. } = expr {
        if matches!(&**func, Expr::Name(n) if n == HASH) {
            *expr = lower_hash(args, ctx)?;
            return Ok(());
        }
        if matches!(&**func, Expr::Name(n) if n == OPAQUE) {
            *expr = lower_opaque(args, ctx)?;
            return Ok(());
        }
    }
    match expr {
        Expr::Call { func, args, .. } => {
            drm_expr(func, ctx)?;
            for a in args {
                drm_expr(a, ctx)?;
            }
        }
        Expr::MethodCall { base, args, .. } => {
            drm_expr(base, ctx)?;
            for a in args {
                drm_expr(a, ctx)?;
            }
        }
        Expr::Field { base, .. } => drm_expr(base, ctx)?,
        Expr::Index { base, key } => {
            drm_expr(base, ctx)?;
            drm_expr(key, ctx)?;
        }
        Expr::Paren(e) => drm_expr(e, ctx)?,
        Expr::Binop { lhs, rhs, .. } => {
            drm_expr(lhs, ctx)?;
            drm_expr(rhs, ctx)?;
        }
        Expr::Unop { expr: e, .. } => drm_expr(e, ctx)?,
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            drm_expr(cond, ctx)?;
            drm_expr(then, ctx)?;
            for (c, e) in else_ifs {
                drm_expr(c, ctx)?;
                drm_expr(e, ctx)?;
            }
            drm_expr(otherwise, ctx)?;
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    Field::Positional(e) => drm_expr(e, ctx)?,
                    Field::Named { value, .. } => drm_expr(value, ctx)?,
                    Field::Keyed { key, value } => {
                        drm_expr(key, ctx)?;
                        drm_expr(value, ctx)?;
                    }
                }
            }
        }
        Expr::Function(fb) => drm_block(&mut fb.block, ctx)?,
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    drm_expr(e, ctx)?;
                }
            }
        }
        Expr::EncFunc { key, .. } => drm_expr(key, ctx)?,
        Expr::Nil
        | Expr::True
        | Expr::False
        | Expr::Vararg
        | Expr::Number(_)
        | Expr::Str(_)
        | Expr::Name(_)
        | Expr::NativeRef(_)
        | Expr::OpcodeHint { .. }
        | Expr::Crash => {}
    }
    Ok(())
}

fn fold_block(block: &mut Block) {
    let stmts = std::mem::take(&mut block.stmts);
    for stmt in stmts {
        if let Some(folded) = fold_stmt(stmt) {
            block.stmts.push(folded);
        }
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        exprs.iter_mut().for_each(fold_expr);
    }
}

fn fold_stmt(mut stmt: Stmt) -> Option<Stmt> {
    match &mut stmt {
        Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(fold_expr),
        Stmt::Assign { targets, exprs } => {
            targets.iter_mut().for_each(fold_expr);
            exprs.iter_mut().for_each(fold_expr);
        }
        Stmt::Compound { target, value, .. } => {
            fold_expr(target);
            fold_expr(value);
        }
        Stmt::Call(e) => fold_expr(e),
        Stmt::Do(b) => fold_block(b),
        Stmt::While { cond, body } => {
            fold_expr(cond);
            fold_block(body);
        }
        Stmt::Repeat { body, until } => {
            fold_block(body);
            fold_expr(until);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            fold_expr(start);
            fold_expr(end);
            if let Some(s) = step {
                fold_expr(s);
            }
            fold_block(body);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter_mut().for_each(fold_expr);
            fold_block(body);
        }
        Stmt::Function { body, .. } => fold_block(&mut body.block),
        Stmt::LocalFunction { body, .. } => fold_block(&mut body.block),
        Stmt::If { .. } => return fold_if(stmt),
    }
    Some(stmt)
}

fn fold_expr(expr: &mut Expr) {
    match expr {
        Expr::Name(n) if n == OBFUSCATED_FLAG => *expr = Expr::True,
        Expr::Name(_) => {}
        Expr::Function(fb) => fold_block(&mut fb.block),
        Expr::Paren(inner) => fold_expr(inner),
        Expr::Field { base, .. } => fold_expr(base),
        Expr::Index { base, key } => {
            fold_expr(base);
            fold_expr(key);
        }
        Expr::Call { func, args, .. } => {
            fold_expr(func);
            args.iter_mut().for_each(fold_expr);
        }
        Expr::MethodCall { base, args, .. } => {
            fold_expr(base);
            args.iter_mut().for_each(fold_expr);
        }
        Expr::Binop { lhs, rhs, .. } => {
            fold_expr(lhs);
            fold_expr(rhs);
        }
        Expr::Unop { expr: inner, .. } => fold_expr(inner),
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            fold_expr(cond);
            fold_expr(then);
            for (c, e) in else_ifs {
                fold_expr(c);
                fold_expr(e);
            }
            fold_expr(otherwise);
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    Field::Positional(e) => fold_expr(e),
                    Field::Named { value, .. } => fold_expr(value),
                    Field::Keyed { key, value } => {
                        fold_expr(key);
                        fold_expr(value);
                    }
                }
            }
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    fold_expr(e);
                }
            }
        }
        Expr::EncFunc { key, .. } => fold_expr(key),
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

fn fold_if(stmt: Stmt) -> Option<Stmt> {
    let Stmt::If {
        mut cond,
        mut body,
        else_ifs,
        otherwise,
    } = stmt
    else {
        unreachable!("fold_if called on a non-If statement");
    };
    fold_expr(&mut cond);
    fold_block(&mut body);
    let mut arms: Vec<(Expr, Block)> = Vec::with_capacity(else_ifs.len() + 1);
    arms.push((cond, body));
    for (mut c, mut b) in else_ifs {
        fold_expr(&mut c);
        fold_block(&mut b);
        arms.push((c, b));
    }
    let mut otherwise = otherwise;
    if let Some(b) = otherwise.as_mut() {
        fold_block(b);
    }

    let mut kept: Vec<(Expr, Block)> = Vec::new();
    let mut forced_else: Option<Block> = None;
    for (c, b) in arms {
        match const_bool(&c) {
            Some(true) => {
                forced_else = Some(b);
                break;
            }
            Some(false) => {}
            None => kept.push((c, b)),
        }
    }
    let else_block = forced_else.or(otherwise);

    if kept.is_empty() {
        return else_block.map(Stmt::Do);
    }
    let (cond, body) = kept.remove(0);
    Some(Stmt::If {
        cond,
        body,
        else_ifs: kept,
        otherwise: else_block,
    })
}

fn const_bool(e: &Expr) -> Option<bool> {
    match e {
        Expr::True => Some(true),
        Expr::False => Some(false),
        Expr::Paren(inner) => const_bool(inner),
        Expr::Unop {
            op: UnOp::Not,
            expr,
        } => const_bool(expr).map(|b| !b),
        _ => None,
    }
}

struct Scope {
    frames: Vec<Vec<String>>,
}

impl Scope {
    fn new() -> Self {
        Scope { frames: Vec::new() }
    }
    fn push(&mut self) {
        self.frames.push(Vec::new());
    }
    fn pop(&mut self) {
        self.frames.pop();
    }
    fn declare(&mut self, name: &str) {
        if let Some(top) = self.frames.last_mut() {
            top.push(name.to_string());
        }
    }
    fn contains(&self, name: &str) -> bool {
        self.frames.iter().any(|f| f.iter().any(|n| n == name))
    }
}

fn rewrite_block(
    block: &mut Block,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
) -> Result<(), Error> {
    for stmt in &mut block.stmts {
        rewrite_stmt(stmt, natives, encfuncs, taint, scope)?;
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs {
            rewrite_expr(e, natives, encfuncs, taint, scope)?;
        }
    }
    Ok(())
}

fn rewrite_scoped(
    block: &mut Block,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
    predeclare: &[&str],
) -> Result<(), Error> {
    scope.push();
    taint.push(HashMap::new());
    for n in predeclare {
        scope.declare(n);
        taint
            .last_mut()
            .unwrap()
            .insert(n.to_string(), Binding::Runtime);
    }
    rewrite_block(block, natives, encfuncs, taint, scope)?;
    taint.pop();
    scope.pop();
    Ok(())
}

fn rewrite_func(
    body: &mut FuncBody,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
    has_self: bool,
) -> Result<(), Error> {
    scope.push();
    taint.push(HashMap::new());
    if has_self {
        scope.declare("self");
        taint
            .last_mut()
            .unwrap()
            .insert("self".to_string(), Binding::Runtime);
    }
    for p in &body.params {
        if let Param::Name(n) = p {
            scope.declare(n);
            taint
                .last_mut()
                .unwrap()
                .insert(n.clone(), Binding::Runtime);
        }
    }
    rewrite_block(&mut body.block, natives, encfuncs, taint, scope)?;
    taint.pop();
    scope.pop();
    Ok(())
}

fn rewrite_stmt(
    stmt: &mut Stmt,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
) -> Result<(), Error> {
    match stmt {
        Stmt::Local { names, exprs } => {
            for e in exprs.iter_mut() {
                rewrite_expr(e, natives, encfuncs, taint, scope)?;
            }
            for (i, n) in names.iter().enumerate() {
                scope.declare(n);
                let b = exprs
                    .get(i)
                    .map(|e| Binding::Init(e.clone()))
                    .unwrap_or(Binding::Runtime);
                taint.last_mut().unwrap().insert(n.clone(), b);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for t in targets {
                rewrite_expr(t, natives, encfuncs, taint, scope)?;
            }
            for e in exprs {
                rewrite_expr(e, natives, encfuncs, taint, scope)?;
            }
        }
        Stmt::Compound { target, value, .. } => {
            rewrite_expr(target, natives, encfuncs, taint, scope)?;
            rewrite_expr(value, natives, encfuncs, taint, scope)?;
        }
        Stmt::Call(e) => {
            if let Expr::Call { func, args, .. } = e {
                if matches!(&**func, Expr::Name(n) if n == OPCODE) {
                    let (family, intensity) = parse_opcode(args)?;
                    *e = Expr::OpcodeHint {
                        family,
                        intensity,
                        key: 0,
                    };
                    return Ok(());
                }
            }
            rewrite_expr(e, natives, encfuncs, taint, scope)?
        }
        Stmt::Do(b) => rewrite_scoped(b, natives, encfuncs, taint, scope, &[])?,
        Stmt::While { cond, body } => {
            rewrite_expr(cond, natives, encfuncs, taint, scope)?;
            rewrite_scoped(body, natives, encfuncs, taint, scope, &[])?;
        }
        Stmt::Repeat { body, until } => {
            scope.push();
            taint.push(HashMap::new());
            rewrite_block(body, natives, encfuncs, taint, scope)?;
            rewrite_expr(until, natives, encfuncs, taint, scope)?;
            taint.pop();
            scope.pop();
        }
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        } => {
            rewrite_expr(start, natives, encfuncs, taint, scope)?;
            rewrite_expr(end, natives, encfuncs, taint, scope)?;
            if let Some(s) = step {
                rewrite_expr(s, natives, encfuncs, taint, scope)?;
            }
            rewrite_scoped(body, natives, encfuncs, taint, scope, &[var.as_str()])?;
        }
        Stmt::GenericFor { names, exprs, body } => {
            for e in exprs {
                rewrite_expr(e, natives, encfuncs, taint, scope)?;
            }
            let pre: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            rewrite_scoped(body, natives, encfuncs, taint, scope, &pre)?;
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            rewrite_expr(cond, natives, encfuncs, taint, scope)?;
            rewrite_scoped(body, natives, encfuncs, taint, scope, &[])?;
            for (c, b) in else_ifs {
                rewrite_expr(c, natives, encfuncs, taint, scope)?;
                rewrite_scoped(b, natives, encfuncs, taint, scope, &[])?;
            }
            if let Some(b) = otherwise {
                rewrite_scoped(b, natives, encfuncs, taint, scope, &[])?;
            }
        }
        Stmt::Function { name, body } => {
            rewrite_func(body, natives, encfuncs, taint, scope, name.method.is_some())?;
        }
        Stmt::LocalFunction { name, body } => {
            scope.declare(name);
            taint
                .last_mut()
                .unwrap()
                .insert(name.clone(), Binding::Init(Expr::Function(body.clone())));
            rewrite_func(body, natives, encfuncs, taint, scope, false)?;
        }
    }
    Ok(())
}

fn rewrite_expr(
    expr: &mut Expr,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
) -> Result<(), Error> {
    if is_no_virtualize_call(expr) {
        if let Expr::Call { args, .. } = expr {
            let (body, captures) = extract_no_virtualize(args, scope)?;
            let idx = natives.len() as u32;
            natives.push(body);
            *expr = if captures.is_empty() {
                Expr::NativeRef(idx)
            } else {
                Expr::Call {
                    func: Box::new(Expr::NativeRef(idx)),
                    args: captures.into_iter().map(Expr::Name).collect(),
                    site: None,
                }
            };
        }
        return Ok(());
    }

    if is_crash_call(expr) {
        *expr = Expr::Crash;
        return Ok(());
    }
    if is_encfunc_call(expr) {
        if let Expr::Call { args, .. } = expr {
            let (id, key) = extract_encfunc(args, natives, encfuncs, taint, scope)?;
            *expr = Expr::EncFunc {
                id,
                key: Box::new(key),
            };
        }
        return Ok(());
    }
    if is_encfunc_seed_call(expr) {
        if let Expr::Call { args, .. } = expr {
            let (id, key) = extract_encfunc_seed(args, natives, encfuncs, taint, scope)?;
            *expr = Expr::EncFunc {
                id,
                key: Box::new(key),
            };
        }
        return Ok(());
    }
    match expr {
        Expr::Call { func, args, .. } => {
            rewrite_expr(func, natives, encfuncs, taint, scope)?;
            for a in args {
                rewrite_expr(a, natives, encfuncs, taint, scope)?;
            }
        }
        Expr::MethodCall { base, args, .. } => {
            rewrite_expr(base, natives, encfuncs, taint, scope)?;
            for a in args {
                rewrite_expr(a, natives, encfuncs, taint, scope)?;
            }
        }
        Expr::Field { base, .. } => rewrite_expr(base, natives, encfuncs, taint, scope)?,
        Expr::Index { base, key } => {
            rewrite_expr(base, natives, encfuncs, taint, scope)?;
            rewrite_expr(key, natives, encfuncs, taint, scope)?;
        }
        Expr::Paren(inner) => rewrite_expr(inner, natives, encfuncs, taint, scope)?,
        Expr::Binop { lhs, rhs, .. } => {
            rewrite_expr(lhs, natives, encfuncs, taint, scope)?;
            rewrite_expr(rhs, natives, encfuncs, taint, scope)?;
        }
        Expr::Unop { expr: inner, .. } => rewrite_expr(inner, natives, encfuncs, taint, scope)?,
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            rewrite_expr(cond, natives, encfuncs, taint, scope)?;
            rewrite_expr(then, natives, encfuncs, taint, scope)?;
            for (c, e) in else_ifs {
                rewrite_expr(c, natives, encfuncs, taint, scope)?;
                rewrite_expr(e, natives, encfuncs, taint, scope)?;
            }
            rewrite_expr(otherwise, natives, encfuncs, taint, scope)?;
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    Field::Positional(e) => rewrite_expr(e, natives, encfuncs, taint, scope)?,
                    Field::Named { value, .. } => {
                        rewrite_expr(value, natives, encfuncs, taint, scope)?
                    }
                    Field::Keyed { key, value } => {
                        rewrite_expr(key, natives, encfuncs, taint, scope)?;
                        rewrite_expr(value, natives, encfuncs, taint, scope)?;
                    }
                }
            }
        }
        Expr::Function(fb) => rewrite_func(fb, natives, encfuncs, taint, scope, false)?,
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    rewrite_expr(e, natives, encfuncs, taint, scope)?;
                }
            }
        }
        Expr::EncFunc { key, .. } => rewrite_expr(key, natives, encfuncs, taint, scope)?,
        Expr::Nil
        | Expr::True
        | Expr::False
        | Expr::Vararg
        | Expr::Number(_)
        | Expr::Str(_)
        | Expr::Name(_)
        | Expr::NativeRef(_)
        | Expr::OpcodeHint { .. }
        | Expr::Crash => {}
    }
    Ok(())
}

fn is_no_virtualize_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { func, .. }
        if matches!(&**func, Expr::Name(n) if n == NO_VIRTUALIZE))
}

fn is_crash_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { func, .. }
        if matches!(&**func, Expr::Name(n) if n == CRASH))
}

fn is_encfunc_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { func, .. }
        if matches!(&**func, Expr::Name(n) if n == ENCFUNC))
}

fn is_encfunc_seed_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { func, .. }
        if matches!(&**func, Expr::Name(n) if n == ENCFUNC_SEED))
}

fn is_runtime_key(expr: &Expr) -> bool {
    match expr {
        Expr::Name(_) | Expr::Call { .. } | Expr::MethodCall { .. } => true,
        Expr::Field { base, .. } | Expr::Index { base, .. } => is_runtime_key(base),
        Expr::Paren(inner) => is_runtime_key(inner),
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Taint {
    LiteralDerived,
    RuntimeSourced,
    Unknown,
}

#[derive(Clone)]
enum Binding {
    Init(Expr),
    Runtime,
}

type TaintEnv = Vec<HashMap<String, Binding>>;

fn taint_lookup<'a>(env: &'a TaintEnv, name: &str) -> Option<&'a Binding> {
    env.iter().rev().find_map(|f| f.get(name))
}

fn is_literal_transform(func: &Expr) -> bool {
    match func {
        Expr::Name(n) => n == "tostring" || n == "tonumber",
        Expr::Field { base, name } => match &**base {
            Expr::Name(b) if b == "string" => true,
            Expr::Name(b) if b == "table" => name == "concat",
            _ => false,
        },
        _ => false,
    }
}

fn field_value(f: &Field) -> &Expr {
    match f {
        Field::Positional(e) | Field::Named { value: e, .. } | Field::Keyed { value: e, .. } => e,
    }
}

fn classify(e: &Expr, env: &TaintEnv, depth: u32) -> Taint {
    if depth > 64 {
        return Taint::Unknown;
    }
    match e {
        Expr::Str(_) | Expr::Number(_) | Expr::True | Expr::False | Expr::Nil | Expr::Interp(_) => {
            Taint::LiteralDerived
        }
        Expr::Vararg => Taint::RuntimeSourced,
        Expr::Paren(i) | Expr::Unop { expr: i, .. } => classify(i, env, depth + 1),
        Expr::Binop { lhs, rhs, .. } => {
            let (l, r) = (classify(lhs, env, depth + 1), classify(rhs, env, depth + 1));
            if l == Taint::LiteralDerived || r == Taint::LiteralDerived {
                Taint::LiteralDerived
            } else if l == Taint::RuntimeSourced || r == Taint::RuntimeSourced {
                Taint::RuntimeSourced
            } else {
                Taint::Unknown
            }
        }
        Expr::Table(fields) => {
            if fields
                .iter()
                .any(|f| classify(field_value(f), env, depth + 1) == Taint::LiteralDerived)
            {
                Taint::LiteralDerived
            } else {
                Taint::Unknown
            }
        }
        Expr::Name(n) => match taint_lookup(env, n) {
            Some(Binding::Init(e2)) => classify(e2, env, depth + 1),
            Some(Binding::Runtime) | None => Taint::RuntimeSourced,
        },
        Expr::Field { base, .. } | Expr::Index { base, .. } => classify(base, env, depth + 1),
        Expr::Call { func, args, .. } => {
            if is_literal_transform(func) {
                if args
                    .iter()
                    .any(|a| classify(a, env, depth + 1) == Taint::LiteralDerived)
                {
                    Taint::LiteralDerived
                } else {
                    Taint::RuntimeSourced
                }
            } else if let Expr::Name(n) = &**func {
                if let Some(Binding::Init(Expr::Function(fb))) = taint_lookup(env, n) {
                    classify_func_return(fb, env, depth + 1)
                } else {
                    Taint::RuntimeSourced
                }
            } else {
                Taint::RuntimeSourced
            }
        }
        Expr::MethodCall { .. } => Taint::RuntimeSourced,
        _ => Taint::Unknown,
    }
}

fn classify_func_return(fb: &FuncBody, env: &TaintEnv, depth: u32) -> Taint {
    if depth > 64 {
        return Taint::Unknown;
    }
    let mut frame = HashMap::new();
    for p in &fb.params {
        if let Param::Name(n) = p {
            frame.insert(n.clone(), Binding::Runtime);
        }
    }
    collect_locals(&fb.block, &mut frame);
    let mut env2 = env.clone();
    env2.push(frame);
    if let Some(LastStmt::Return(es)) = &fb.block.last {
        if let Some(first) = es.first() {
            return classify(first, &env2, depth + 1);
        }
    }
    Taint::Unknown
}

fn collect_locals(block: &Block, frame: &mut HashMap<String, Binding>) {
    for s in &block.stmts {
        match s {
            Stmt::Local { names, exprs } => {
                for (i, n) in names.iter().enumerate() {
                    let b = exprs
                        .get(i)
                        .map(|e| Binding::Init(e.clone()))
                        .unwrap_or(Binding::Runtime);
                    frame.insert(n.clone(), b);
                }
            }
            Stmt::LocalFunction { name, body } => {
                frame.insert(name.clone(), Binding::Init(Expr::Function(body.clone())));
            }
            _ => {}
        }
    }
}

fn is_key_material(bytes: &[u8], compile_key: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let low = text.to_ascii_lowercase();
    if low.len() >= 16
        && !compile_key.is_empty()
        && (compile_key.contains(&low) || low.contains(compile_key))
    {
        return true;
    }
    if low.len() >= 32 {
        let hex = low.bytes().filter(|b| b.is_ascii_hexdigit()).count();
        if hex * 10 >= low.len() * 9 {
            return true;
        }
        let b64 = low
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
            .count();
        let digits = low.bytes().filter(u8::is_ascii_digit).count();
        if b64 == low.len() && digits >= 2 && !low.contains(' ') {
            return true;
        }
    }
    false
}

fn key_material_in(e: &Expr, env: &TaintEnv, compile_key: &str, depth: u32) -> bool {
    if depth > 64 {
        return false;
    }
    let go = |x: &Expr| key_material_in(x, env, compile_key, depth + 1);
    match e {
        Expr::Str(s) => {
            bytecode::literal::decode_string(s).is_some_and(|b| is_key_material(&b, compile_key))
        }
        Expr::Paren(i) | Expr::Unop { expr: i, .. } => go(i),
        Expr::Binop { lhs, rhs, .. } => go(lhs) || go(rhs),
        Expr::Index { base, key } => go(base) || go(key),
        Expr::Field { base, .. } => go(base),
        Expr::Name(n) => matches!(taint_lookup(env, n), Some(Binding::Init(e2)) if go(e2)),
        Expr::Call { func, args, .. } => {
            args.iter().any(go)
                || matches!(&**func, Expr::Name(n) if matches!(taint_lookup(env, n), Some(Binding::Init(Expr::Function(fb))) if func_returns_key_material(fb, env, compile_key, depth + 1)))
        }
        Expr::MethodCall { args, .. } => args.iter().any(go),
        Expr::Table(fields) => fields.iter().any(|f| go(field_value(f))),
        Expr::Interp(parts) => parts.iter().any(|p| match p {
            InterpPart::Lit(s) => is_key_material(s.as_bytes(), compile_key),
            InterpPart::Expr(x) => go(x),
        }),
        other => {
            let mut found = false;
            other.each_child(&mut |c| found |= go(c));
            found
        }
    }
}

fn func_returns_key_material(fb: &FuncBody, env: &TaintEnv, compile_key: &str, depth: u32) -> bool {
    if depth > 64 {
        return false;
    }
    let mut frame = HashMap::new();
    collect_locals(&fb.block, &mut frame);
    let mut env2 = env.clone();
    env2.push(frame);
    matches!(&fb.block.last, Some(LastStmt::Return(es)) if es.iter().any(|e| key_material_in(e, &env2, compile_key, depth + 1)))
}

fn validate_runtime_key(arg3: &Expr, compile_key: &str, env: &TaintEnv) -> Result<(), Error> {
    if key_material_in(arg3, env, compile_key, 0) {
        return Err(Error::Macro(
            "BASIL_ENCFUNC runtime key expression contains literal key material; fetch it at runtime instead".into(),
        ));
    }
    if classify(arg3, env, 0) == Taint::LiteralDerived {
        return Err(Error::Macro(
            "BASIL_ENCFUNC runtime key must come from a runtime value, not a literal or literal-derived expression".into(),
        ));
    }
    Ok(())
}

fn extract_encfunc(
    args: &mut Vec<Expr>,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
) -> Result<(u32, Expr), Error> {
    if args.len() != 3 && args.len() != 4 {
        return Err(Error::Macro(format!(
            "BASIL_ENCFUNC takes one argument (managed: a function literal) or three (function, 64-hex key, runtime key), got {}",
            args.len()
        )));
    }
    let class = if args.len() == 4 {
        match args.pop() {
            Some(Expr::Number(n)) => n.parse::<u8>().map_err(|_| {
                Error::Macro("BASIL_ENCFUNC internal class tag must be a byte".into())
            })?,
            _ => {
                return Err(Error::Macro(
                    "BASIL_ENCFUNC takes at most three arguments".into(),
                ))
            }
        }
    } else {
        0
    };
    if !is_runtime_key(&args[2]) {
        return Err(Error::Macro(
            "BASIL_ENCFUNC runtime key must come from a runtime value, not a literal or literal-derived expression".into(),
        ));
    }
    let (key, vkey): (ir::CompileKeySource, String) = match &args[1] {
        Expr::Str(s) => {
            let bytes = bytecode::literal::decode_string(s).ok_or_else(|| {
                Error::Macro("BASIL_ENCFUNC key must be a constant string literal".into())
            })?;
            let hex = String::from_utf8(bytes)
                .map_err(|_| Error::Macro("BASIL_ENCFUNC key must be 64 hex characters".into()))?;
            if hex.len() != 64 {
                return Err(Error::Macro(format!(
                    "BASIL_ENCFUNC key must be exactly 64 hex characters (got {})",
                    hex.len()
                )));
            }
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Macro(
                    "BASIL_ENCFUNC key contains a non-hex character".into(),
                ));
            }
            let bytes = bytecode::aead::parse_hex_key(&hex)
                .ok_or_else(|| Error::Macro("BASIL_ENCFUNC key is not 64 hex characters".into()))?;
            let vkey = hex.to_ascii_lowercase();
            (ir::CompileKeySource::Literal(bytes), vkey)
        }
        Expr::Name(n) => {
            return Err(Error::Macro(format!(
            "BASIL_ENCFUNC key must be a constant 64-hex string literal, not a reference (`{n}`)"
        )))
        }
        _ => {
            return Err(Error::Macro(
                "BASIL_ENCFUNC key must be a constant 64-character hex string literal".into(),
            ))
        }
    };
    validate_runtime_key(&args[2], &vkey, taint)?;
    let key_expr = args.remove(2);
    let _ = args.remove(1);
    let fn_arg = args.remove(0);
    finish_encfunc(
        fn_arg, key_expr, key, class, ENCFUNC, natives, encfuncs, taint, scope,
    )
}

fn extract_encfunc_seed(
    args: &mut Vec<Expr>,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
) -> Result<(u32, Expr), Error> {
    if args.len() != 3 {
        return Err(Error::Macro(format!(
            "BASIL_ENCFUNC_SEED takes exactly three arguments (function, numeric compile seed, runtime seed), got {}",
            args.len()
        )));
    }
    if !is_runtime_key(&args[2]) {
        return Err(Error::Macro(
            "BASIL_ENCFUNC_SEED runtime seed must come from a runtime value, not a literal or literal-derived expression".into(),
        ));
    }

    let seed = parse_compile_seed(&args[1])?;
    validate_runtime_key(&args[2], &bytecode::aead::seed_key_hex(seed), taint)?;
    let key = ir::CompileKeySource::Managed {
        seed,
        key: bytecode::aead::seed_key(seed),
    };
    let key_expr = args.remove(2);
    let _ = args.remove(1);
    let fn_arg = args.remove(0);
    finish_encfunc(
        fn_arg,
        key_expr,
        key,
        0,
        ENCFUNC_SEED,
        natives,
        encfuncs,
        taint,
        scope,
    )
}

fn parse_compile_seed(e: &Expr) -> Result<u64, Error> {
    let n = match e {
        Expr::Number(text) => bytecode::literal::decode_number(text).ok_or_else(|| {
            Error::Macro("BASIL_ENCFUNC_SEED compile seed is not a valid numeric literal".into())
        })?,
        Expr::Name(name) => {
            return Err(Error::Macro(format!(
            "BASIL_ENCFUNC_SEED compile seed must be a numeric literal, not a reference (`{name}`)"
        )))
        }
        _ => {
            return Err(Error::Macro(
                "BASIL_ENCFUNC_SEED compile seed must be a non-negative integer literal".into(),
            ))
        }
    };
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 || n > 9_007_199_254_740_991.0 {
        return Err(Error::Macro(
            "BASIL_ENCFUNC_SEED compile seed must be an integer in [0, 2^53 - 1]".into(),
        ));
    }
    Ok(n as u64)
}

#[allow(clippy::too_many_arguments)]
fn finish_encfunc(
    fn_arg: Expr,
    key_expr: Expr,
    key: ir::CompileKeySource,
    class: u8,
    macro_name: &str,
    natives: &mut Vec<FuncBody>,
    encfuncs: &mut Vec<ir::EncFunc>,
    taint: &mut TaintEnv,
    scope: &mut Scope,
) -> Result<(u32, Expr), Error> {
    let mut body = match fn_arg {
        Expr::Function(fb) => fb,
        Expr::Name(n) => {
            return Err(Error::Macro(format!(
                "{macro_name} requires a function literal, not a reference (`{n}`)"
            )))
        }
        _ => {
            return Err(Error::Macro(format!(
                "{macro_name} requires a function-literal first argument"
            )))
        }
    };
    encfunc_scan(&body.block)?;
    for name in free_vars(&body) {
        if scope.contains(&name) {
            return Err(Error::Macro(format!(
                "{macro_name} function captures the enclosing local `{name}`; protected functions must be \
                 leaves — arguments in, values out, no shared upvalues"
            )));
        }
    }
    crate::encfunc_escape::check(&body, macro_name)?;
    let before = natives.len();
    rewrite_func(&mut body, natives, encfuncs, taint, scope, false)?;
    debug_assert_eq!(
        natives.len(),
        before,
        "no NO_VIRTUALIZE should extract inside an ENCFUNC"
    );
    let mut key_expr = key_expr;
    rewrite_expr(&mut key_expr, natives, encfuncs, taint, scope)?;
    let id = encfuncs.len() as u32;
    encfuncs.push(ir::EncFunc { body, key, class });
    Ok((id, key_expr))
}

fn encfunc_scan(block: &Block) -> Result<(), Error> {
    for s in &block.stmts {
        scan_stmt(s)?;
    }
    if let Some(LastStmt::Return(es)) = &block.last {
        for e in es {
            scan_expr(e)?;
        }
    }
    Ok(())
}

fn scan_stmt(stmt: &Stmt) -> Result<(), Error> {
    match stmt {
        Stmt::Local { exprs, .. } => exprs.iter().try_for_each(scan_expr)?,
        Stmt::Assign { targets, exprs } => {
            targets.iter().try_for_each(scan_expr)?;
            exprs.iter().try_for_each(scan_expr)?;
        }
        Stmt::Compound { target, value, .. } => {
            scan_expr(target)?;
            scan_expr(value)?;
        }
        Stmt::Call(e) => scan_expr(e)?,
        Stmt::Do(b) => encfunc_scan(b)?,
        Stmt::While { cond, body } => {
            scan_expr(cond)?;
            encfunc_scan(body)?;
        }
        Stmt::Repeat { body, until } => {
            encfunc_scan(body)?;
            scan_expr(until)?;
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            scan_expr(start)?;
            scan_expr(end)?;
            if let Some(s) = step {
                scan_expr(s)?;
            }
            encfunc_scan(body)?;
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter().try_for_each(scan_expr)?;
            encfunc_scan(body)?;
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            scan_expr(cond)?;
            encfunc_scan(body)?;
            for (c, b) in else_ifs {
                scan_expr(c)?;
                encfunc_scan(b)?;
            }
            if let Some(b) = otherwise {
                encfunc_scan(b)?;
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            encfunc_scan(&body.block)?;
        }
    }
    Ok(())
}

fn scan_expr(expr: &Expr) -> Result<(), Error> {
    if is_no_virtualize_call(expr) {
        return Err(Error::Macro(
            "BASIL_NO_VIRTUALIZE cannot appear inside a BASIL_ENCFUNC function".into(),
        ));
    }
    if is_encfunc_call(expr) || is_encfunc_seed_call(expr) {
        return Err(Error::Macro(
            "BASIL_ENCFUNC cannot be nested inside another BASIL_ENCFUNC".into(),
        ));
    }
    match expr {
        Expr::Name(n) if n == NO_VIRTUALIZE => {
            return Err(Error::Macro(
                "BASIL_NO_VIRTUALIZE cannot appear inside a BASIL_ENCFUNC function".into(),
            ))
        }
        Expr::Name(n) if n == ENCFUNC || n == ENCFUNC_SEED => {
            return Err(Error::Macro(
                "BASIL_ENCFUNC cannot be nested inside another BASIL_ENCFUNC".into(),
            ))
        }
        Expr::Function(fb) => encfunc_scan(&fb.block)?,
        Expr::Call { func, args, .. } => {
            scan_expr(func)?;
            args.iter().try_for_each(scan_expr)?;
        }
        Expr::MethodCall { base, args, .. } => {
            scan_expr(base)?;
            args.iter().try_for_each(scan_expr)?;
        }
        Expr::Field { base, .. } => scan_expr(base)?,
        Expr::Index { base, key } => {
            scan_expr(base)?;
            scan_expr(key)?;
        }
        Expr::Paren(e) => scan_expr(e)?,
        Expr::Binop { lhs, rhs, .. } => {
            scan_expr(lhs)?;
            scan_expr(rhs)?;
        }
        Expr::Unop { expr: e, .. } => scan_expr(e)?,
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            scan_expr(cond)?;
            scan_expr(then)?;
            for (c, e) in else_ifs {
                scan_expr(c)?;
                scan_expr(e)?;
            }
            scan_expr(otherwise)?;
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    Field::Positional(e) => scan_expr(e)?,
                    Field::Named { value, .. } => scan_expr(value)?,
                    Field::Keyed { key, value } => {
                        scan_expr(key)?;
                        scan_expr(value)?;
                    }
                }
            }
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    scan_expr(e)?;
                }
            }
        }
        other => {
            let mut failed = None;
            other.each_child(&mut |c| {
                if failed.is_none() {
                    if let Err(e) = scan_expr(c) {
                        failed = Some(e);
                    }
                }
            });
            if let Some(e) = failed {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn extract_no_virtualize(
    args: &mut Vec<Expr>,
    scope: &Scope,
) -> Result<(FuncBody, Vec<String>), Error> {
    if args.len() != 1 {
        return Err(Error::Macro(format!(
            "BASIL_NO_VIRTUALIZE takes exactly one function-literal argument, got {}",
            args.len()
        )));
    }
    let body = match args.remove(0) {
        Expr::Function(fb) => fb,
        Expr::Name(n) => {
            return Err(Error::Macro(format!(
                "BASIL_NO_VIRTUALIZE requires a function literal, not a reference (`{n}`)"
            )))
        }
        _ => {
            return Err(Error::Macro(
                "BASIL_NO_VIRTUALIZE requires a function-literal argument".into(),
            ))
        }
    };

    if let Some(name) = find_reserved(&body.block) {
        return Err(Error::Macro(format!(
            "`{name}` cannot appear inside a BASIL_NO_VIRTUALIZE function (BASIL_ macros do not nest)"
        )));
    }

    let captures: Vec<String> = free_vars(&body)
        .into_iter()
        .filter(|n| scope.contains(n))
        .collect();
    if captures.is_empty() {
        return Ok((body, Vec::new()));
    }
    let factory = FuncBody {
        params: captures.iter().cloned().map(Param::Name).collect(),
        block: Block {
            stmts: Vec::new(),
            last: Some(LastStmt::Return(vec![Expr::Function(body)])),
        },
        hot_callback: None,
        stable_id: None,
    };
    Ok((factory, captures))
}

pub fn free_vars(body: &FuncBody) -> BTreeSet<String> {
    let mut f = FreeFinder {
        scopes: Vec::new(),
        free: BTreeSet::new(),
    };
    f.func(body, false);
    f.free
}

struct FreeFinder {
    scopes: Vec<Vec<String>>,
    free: BTreeSet<String>,
}

impl FreeFinder {
    fn bound(&self, name: &str) -> bool {
        self.scopes.iter().any(|s| s.iter().any(|n| n == name))
    }
    fn declare(&mut self, name: &str) {
        if let Some(top) = self.scopes.last_mut() {
            top.push(name.to_string());
        }
    }
    fn use_name(&mut self, name: &str) {
        if !self.bound(name) {
            self.free.insert(name.to_string());
        }
    }
    fn func(&mut self, body: &FuncBody, has_self: bool) {
        self.scopes.push(Vec::new());
        if has_self {
            self.declare("self");
        }
        for p in &body.params {
            if let Param::Name(n) = p {
                self.declare(n);
            }
        }
        self.block_stmts(&body.block);
        self.scopes.pop();
    }
    fn scoped(&mut self, block: &Block, predeclare: &[&str]) {
        self.scopes.push(Vec::new());
        for n in predeclare {
            self.declare(n);
        }
        self.block_stmts(block);
        self.scopes.pop();
    }
    fn block_stmts(&mut self, block: &Block) {
        for s in &block.stmts {
            self.stmt(s);
        }
        if let Some(LastStmt::Return(exprs)) = &block.last {
            for e in exprs {
                self.expr(e);
            }
        }
    }
    fn stmt(&mut self, stmt: &Stmt) {
        match stmt {
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
                    self.expr(t);
                }
                for e in exprs {
                    self.expr(e);
                }
            }
            Stmt::Compound { target, value, .. } => {
                self.expr(target);
                self.expr(value);
            }
            Stmt::Call(e) => self.expr(e),
            Stmt::Do(b) => self.scoped(b, &[]),
            Stmt::While { cond, body } => {
                self.expr(cond);
                self.scoped(body, &[]);
            }
            Stmt::Repeat { body, until } => {
                self.scopes.push(Vec::new());
                self.block_stmts(body);
                self.expr(until);
                self.scopes.pop();
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
                if let Some(s) = step {
                    self.expr(s);
                }
                self.scoped(body, &[var.as_str()]);
            }
            Stmt::GenericFor { names, exprs, body } => {
                for e in exprs {
                    self.expr(e);
                }
                let pre: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                self.scoped(body, &pre);
            }
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond);
                self.scoped(body, &[]);
                for (c, b) in else_ifs {
                    self.expr(c);
                    self.scoped(b, &[]);
                }
                if let Some(b) = otherwise {
                    self.scoped(b, &[]);
                }
            }
            Stmt::Function { name, body } => {
                self.use_name(&name.path[0]);
                self.func(body, name.method.is_some());
            }
            Stmt::LocalFunction { name, body } => {
                self.declare(name);
                self.func(body, false);
            }
        }
    }
    fn expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Name(n) => self.use_name(n),
            Expr::Field { base, .. } => self.expr(base),
            Expr::Index { base, key } => {
                self.expr(base);
                self.expr(key);
            }
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
            Expr::Function(fb) => self.func(fb, false),
            Expr::Paren(e) => self.expr(e),
            Expr::Binop { lhs, rhs, .. } => {
                self.expr(lhs);
                self.expr(rhs);
            }
            Expr::Unop { expr: e, .. } => self.expr(e),
            Expr::IfExpr {
                cond,
                then,
                else_ifs,
                otherwise,
            } => {
                self.expr(cond);
                self.expr(then);
                for (c, e) in else_ifs {
                    self.expr(c);
                    self.expr(e);
                }
                self.expr(otherwise);
            }
            Expr::Table(fields) => {
                for f in fields {
                    match f {
                        Field::Positional(e) => self.expr(e),
                        Field::Named { value, .. } => self.expr(value),
                        Field::Keyed { key, value } => {
                            self.expr(key);
                            self.expr(value);
                        }
                    }
                }
            }
            Expr::Interp(parts) => {
                for p in parts {
                    if let InterpPart::Expr(e) = p {
                        self.expr(e);
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

fn key_in_strings(block: &Block, key_lower: &str) -> bool {
    let mut found = false;
    each_str_block(block, &mut |s| {
        if found {
            return;
        }
        if let Some(bytes) = bytecode::literal::decode_string(s) {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                let low = text.to_ascii_lowercase();
                if low.contains(key_lower) || (low.len() >= 16 && key_lower.contains(&low)) {
                    found = true;
                }
            }
        }
    });
    found
}

fn each_str_block(block: &Block, f: &mut impl FnMut(&str)) {
    for s in &block.stmts {
        each_str_stmt(s, f);
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            each_str_expr(e, f);
        }
    }
}

fn each_str_stmt(stmt: &Stmt, f: &mut impl FnMut(&str)) {
    match stmt {
        Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| each_str_expr(e, f)),
        Stmt::Assign { targets, exprs } => {
            targets.iter().for_each(|e| each_str_expr(e, f));
            exprs.iter().for_each(|e| each_str_expr(e, f));
        }
        Stmt::Compound { target, value, .. } => {
            each_str_expr(target, f);
            each_str_expr(value, f);
        }
        Stmt::Call(e) => each_str_expr(e, f),
        Stmt::Do(b) => each_str_block(b, f),
        Stmt::While { cond, body } => {
            each_str_expr(cond, f);
            each_str_block(body, f);
        }
        Stmt::Repeat { body, until } => {
            each_str_block(body, f);
            each_str_expr(until, f);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            each_str_expr(start, f);
            each_str_expr(end, f);
            if let Some(s) = step {
                each_str_expr(s, f);
            }
            each_str_block(body, f);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter().for_each(|e| each_str_expr(e, f));
            each_str_block(body, f);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            each_str_expr(cond, f);
            each_str_block(body, f);
            for (c, b) in else_ifs {
                each_str_expr(c, f);
                each_str_block(b, f);
            }
            if let Some(b) = otherwise {
                each_str_block(b, f);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            each_str_block(&body.block, f)
        }
    }
}

fn each_str_expr(expr: &Expr, f: &mut impl FnMut(&str)) {
    match expr {
        Expr::Str(s) => f(s),
        Expr::Paren(e) | Expr::Unop { expr: e, .. } => each_str_expr(e, f),
        Expr::Field { base, .. } => each_str_expr(base, f),
        Expr::Index { base, key } => {
            each_str_expr(base, f);
            each_str_expr(key, f);
        }
        Expr::Call { func, args, .. } => {
            each_str_expr(func, f);
            args.iter().for_each(|e| each_str_expr(e, f));
        }
        Expr::MethodCall { base, args, .. } => {
            each_str_expr(base, f);
            args.iter().for_each(|e| each_str_expr(e, f));
        }
        Expr::Function(fb) => each_str_block(&fb.block, f),
        Expr::Binop { lhs, rhs, .. } => {
            each_str_expr(lhs, f);
            each_str_expr(rhs, f);
        }
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            each_str_expr(cond, f);
            each_str_expr(then, f);
            for (c, e) in else_ifs {
                each_str_expr(c, f);
                each_str_expr(e, f);
            }
            each_str_expr(otherwise, f);
        }
        Expr::Table(fields) => {
            for fld in fields {
                match fld {
                    Field::Positional(e) => each_str_expr(e, f),
                    Field::Named { value, .. } => each_str_expr(value, f),
                    Field::Keyed { key, value } => {
                        each_str_expr(key, f);
                        each_str_expr(value, f);
                    }
                }
            }
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    each_str_expr(e, f);
                }
            }
        }
        Expr::EncFunc { key, .. } => each_str_expr(key, f),
        other => other.each_child(&mut |c| each_str_expr(c, f)),
    }
}

fn find_reserved(block: &Block) -> Option<String> {
    let mut found: Option<String> = None;
    each_var_name_block(block, &mut |n| {
        if found.is_none() && n.starts_with(PREFIX) && n != crate::inline::INLINE {
            found = Some(n.to_string());
        }
    });
    found
}

fn each_var_name_block(block: &Block, f: &mut impl FnMut(&str)) {
    for s in &block.stmts {
        each_var_name_stmt(s, f);
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            each_var_name_expr(e, f);
        }
    }
}

fn each_var_name_stmt(stmt: &Stmt, f: &mut impl FnMut(&str)) {
    match stmt {
        Stmt::Local { names, exprs } => {
            for n in names {
                f(n);
            }
            for e in exprs {
                each_var_name_expr(e, f);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for t in targets {
                each_var_name_expr(t, f);
            }
            for e in exprs {
                each_var_name_expr(e, f);
            }
        }
        Stmt::Compound { target, value, .. } => {
            each_var_name_expr(target, f);
            each_var_name_expr(value, f);
        }
        Stmt::Call(e) => each_var_name_expr(e, f),
        Stmt::Do(b) => each_var_name_block(b, f),
        Stmt::While { cond, body } => {
            each_var_name_expr(cond, f);
            each_var_name_block(body, f);
        }
        Stmt::Repeat { body, until } => {
            each_var_name_block(body, f);
            each_var_name_expr(until, f);
        }
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        } => {
            f(var);
            each_var_name_expr(start, f);
            each_var_name_expr(end, f);
            if let Some(s) = step {
                each_var_name_expr(s, f);
            }
            each_var_name_block(body, f);
        }
        Stmt::GenericFor { names, exprs, body } => {
            for n in names {
                f(n);
            }
            for e in exprs {
                each_var_name_expr(e, f);
            }
            each_var_name_block(body, f);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            each_var_name_expr(cond, f);
            each_var_name_block(body, f);
            for (c, b) in else_ifs {
                each_var_name_expr(c, f);
                each_var_name_block(b, f);
            }
            if let Some(b) = otherwise {
                each_var_name_block(b, f);
            }
        }
        Stmt::Function { name, body } => {
            f(&name.path[0]);
            for p in &body.params {
                if let Param::Name(n) = p {
                    f(n);
                }
            }
            each_var_name_block(&body.block, f);
        }
        Stmt::LocalFunction { name, body } => {
            f(name);
            for p in &body.params {
                if let Param::Name(n) = p {
                    f(n);
                }
            }
            each_var_name_block(&body.block, f);
        }
    }
}

fn each_var_name_expr(expr: &Expr, f: &mut impl FnMut(&str)) {
    match expr {
        Expr::Name(n) => f(n),
        Expr::Field { base, .. } => each_var_name_expr(base, f),
        Expr::Index { base, key } => {
            each_var_name_expr(base, f);
            each_var_name_expr(key, f);
        }
        Expr::Call { func, args, .. } => {
            each_var_name_expr(func, f);
            for a in args {
                each_var_name_expr(a, f);
            }
        }
        Expr::MethodCall { base, args, .. } => {
            each_var_name_expr(base, f);
            for a in args {
                each_var_name_expr(a, f);
            }
        }
        Expr::Function(fb) => {
            for p in &fb.params {
                if let Param::Name(n) = p {
                    f(n);
                }
            }
            each_var_name_block(&fb.block, f);
        }
        Expr::Paren(e) => each_var_name_expr(e, f),
        Expr::Binop { lhs, rhs, .. } => {
            each_var_name_expr(lhs, f);
            each_var_name_expr(rhs, f);
        }
        Expr::Unop { expr: e, .. } => each_var_name_expr(e, f),
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            each_var_name_expr(cond, f);
            each_var_name_expr(then, f);
            for (c, e) in else_ifs {
                each_var_name_expr(c, f);
                each_var_name_expr(e, f);
            }
            each_var_name_expr(otherwise, f);
        }
        Expr::Table(fields) => {
            for fld in fields {
                match fld {
                    Field::Positional(e) => each_var_name_expr(e, f),
                    Field::Named { value, .. } => each_var_name_expr(value, f),
                    Field::Keyed { key, value } => {
                        each_var_name_expr(key, f);
                        each_var_name_expr(value, f);
                    }
                }
            }
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    each_var_name_expr(e, f);
                }
            }
        }
        Expr::EncFunc { key, .. } => each_var_name_expr(key, f),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lower_str;

    fn run(src: &str) -> Result<Module, Error> {
        expand(lower_str(src).expect("lower"), 0)
    }

    fn count_native_refs(block: &Block) -> usize {
        let mut n = 0;
        for s in &block.stmts {
            if let Stmt::Local { exprs, .. } | Stmt::Assign { exprs, .. } = s {
                n += exprs
                    .iter()
                    .filter(|e| matches!(e, Expr::NativeRef(_)))
                    .count();
            }
        }
        n
    }

    #[test]
    fn valid_leaf_extracted() {
        let m =
            run("local f = BASIL_NO_VIRTUALIZE(function(x) return x * 2 end) return f(3)").unwrap();
        assert_eq!(m.natives.len(), 1);
        assert_eq!(count_native_refs(&m.block), 1);
    }

    #[test]
    fn basil_line_call_is_consumed_at_lowering() {
        let m = run("local x = BASIL_LINE()\nprint(x)\n").unwrap();
        assert!(!format!("{:?}", m.block).contains("BASIL_LINE"));
    }

    #[test]
    fn basil_line_bare_reference_is_reserved_rejected() {
        assert!(run("local x = BASIL_LINE\nprint(x)\n").is_err());
    }

    #[test]
    fn global_use_is_allowed() {
        let m = run("local f = BASIL_NO_VIRTUALIZE(function(x) return print(x) end)").unwrap();
        assert_eq!(m.natives.len(), 1);
    }

    #[test]
    fn param_and_field_not_a_capture() {
        run("local f = BASIL_NO_VIRTUALIZE(function(t) return t.x + t:m() end)").unwrap();
    }

    #[test]
    fn body_local_shadowing_enclosing_is_allowed() {
        run("local y = 1 local f = BASIL_NO_VIRTUALIZE(function() local y = 2 return y end)")
            .unwrap();
    }

    fn assert_macro_err(src: &str, needle: &str) {
        match run(src) {
            Err(Error::Macro(msg)) => assert!(msg.contains(needle), "got: {msg}"),
            other => panic!("expected Macro error containing {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn captures_enclosing_local_as_snapshot_factory() {
        let m = run("local y = 1 local f = BASIL_NO_VIRTUALIZE(function() return y end)").unwrap();
        assert_eq!(m.natives.len(), 1);
        assert_eq!(m.natives[0].params, vec![Param::Name("y".to_string())]);
        let init = match &m.block.stmts[1] {
            Stmt::Local { exprs, .. } => &exprs[0],
            s => panic!("expected local, got {s:?}"),
        };
        match init {
            Expr::Call { func, args, .. } => {
                assert!(matches!(**func, Expr::NativeRef(0)));
                assert_eq!(args, &vec![Expr::Name("y".to_string())]);
            }
            other => panic!("expected factory call, got {other:?}"),
        }

        assert!(
            matches!(&m.block.stmts[0], Stmt::Local { exprs, .. } if matches!(&exprs[0], Expr::Number(_)))
        );
    }

    #[test]
    fn self_recursion_is_supported_via_shared_cell() {
        let m = run("local f f = BASIL_NO_VIRTUALIZE(function(n) if n <= 0 then return 0 end return f(n - 1) end)").unwrap();
        assert_eq!(m.natives.len(), 1);
        assert!(
            matches!(&m.block.stmts[0], Stmt::Local { names, exprs } if names == &vec!["f".to_string()] && exprs.is_empty())
        );
        match &m.block.stmts[1] {
            Stmt::Assign { targets, exprs } => {
                assert_eq!(targets, &vec![Expr::Name("f".to_string())]);
                assert!(
                    matches!(&exprs[0], Expr::Table(_)),
                    "the reassigned+captured binding is boxed"
                );
            }
            s => panic!("expected box assign, got {s:?}"),
        }
        match &m.block.stmts[2] {
            Stmt::Assign { targets, exprs } => {
                assert!(
                    matches!(&targets[0], Expr::Index { .. }),
                    "closure creation writes through the cell"
                );
                match &exprs[0] {
                    Expr::Call { func, args, .. } => {
                        assert!(matches!(**func, Expr::NativeRef(0)));
                        assert_eq!(args, &vec![Expr::Name("f".to_string())]);
                    }
                    o => panic!("expected factory call, got {o:?}"),
                }
            }
            s => panic!("expected cell write, got {s:?}"),
        }
    }

    #[test]
    fn mutual_recursion_is_supported_via_shared_cells() {
        let m = run("local a, b a = BASIL_NO_VIRTUALIZE(function() return b() end) b = BASIL_NO_VIRTUALIZE(function() return a() end)").unwrap();
        assert_eq!(m.natives.len(), 2);
        let boxed = |nm: &str| {
            m.block.stmts.iter().any(|s| {
                matches!(s,
                Stmt::Assign { targets, exprs }
                    if matches!(&targets[0], Expr::Name(n) if n == nm)
                       && matches!(&exprs[0], Expr::Table(_)))
            })
        };
        assert!(
            boxed("a") && boxed("b"),
            "both mutually-recursive bindings are boxed"
        );
    }

    #[test]
    fn rejects_nested_no_virtualize() {
        assert_macro_err(
            "local f = BASIL_NO_VIRTUALIZE(function() return BASIL_NO_VIRTUALIZE(function() return 1 end) end)",
            "do not nest",
        );
    }

    #[test]
    fn rejects_reference_argument() {
        assert_macro_err(
            "local g = function() return 1 end local f = BASIL_NO_VIRTUALIZE(g)",
            "not a reference",
        );
    }

    #[test]
    fn rejects_wrong_arity() {
        assert_macro_err(
            "local f = BASIL_NO_VIRTUALIZE(function() end, 1)",
            "exactly one",
        );
    }

    #[test]
    fn rejects_stray_reserved_identifier() {
        assert_macro_err("local BASIL_secret = 1", "reserved");
    }

    #[test]
    fn dev_stub_guard_is_stripped() {
        let m = run(
            "if not BASIL_OBFUSCATED then function BASIL_NO_VIRTUALIZE(fn) return fn end end \
             local f = BASIL_NO_VIRTUALIZE(function() return 1 end) return f()",
        )
        .unwrap();
        assert_eq!(m.natives.len(), 1);
        assert!(
            find_reserved(&m.block).is_none(),
            "no BASIL_ identifiers should remain"
        );
    }

    #[test]
    fn captured_local_in_nested_scope_is_snapshotted() {
        let m =
            run("local cfg = 5 local f = BASIL_NO_VIRTUALIZE(function() do return cfg end end)")
                .unwrap();
        assert_eq!(m.natives.len(), 1);
        assert_eq!(m.natives[0].params, vec![Param::Name("cfg".to_string())]);
        assert!(
            matches!(&m.block.stmts[0], Stmt::Local { exprs, .. } if matches!(&exprs[0], Expr::Number(_)))
        );
    }

    fn block_mentions(block: &Block, name: &str) -> bool {
        let mut hit = false;
        each_var_name_block(block, &mut |n| {
            if n == name {
                hit = true;
            }
        });
        hit
    }

    #[test]
    fn obfuscated_keeps_true_branch_as_do_block() {
        let m = run("if BASIL_OBFUSCATED then prod() else dev() end").unwrap();
        assert_eq!(m.block.stmts.len(), 1);
        assert!(
            matches!(m.block.stmts[0], Stmt::Do(_)),
            "kept branch must be a do-block"
        );
        assert!(block_mentions(&m.block, "prod"), "true branch kept");
        assert!(
            !block_mentions(&m.block, "dev"),
            "false branch dead-stripped"
        );
    }

    #[test]
    fn obfuscated_not_drops_branch_entirely() {
        let m = run("if not BASIL_OBFUSCATED then devonly() end print(1)").unwrap();
        assert!(
            !block_mentions(&m.block, "devonly"),
            "if-not-OBFUSCATED branch dropped"
        );
        assert!(
            block_mentions(&m.block, "print"),
            "trailing statement survives"
        );
    }

    #[test]
    fn obfuscated_do_wrap_does_not_leak_locals() {
        let m = run("if BASIL_OBFUSCATED then local x = 1 end").unwrap();
        assert!(matches!(m.block.stmts[0], Stmt::Do(_)));
        assert!(
            !matches!(&m.block.stmts[0], Stmt::Local { .. }),
            "the branch's local must stay inside the do-block, not be spliced into the parent"
        );
    }

    #[test]
    fn obfuscated_dead_branch_macro_call_is_dropped_not_extracted() {
        let m = run(
            "local cap = 1 if not BASIL_OBFUSCATED then local f = BASIL_NO_VIRTUALIZE(function() return cap end) end",
        )
        .unwrap();
        assert_eq!(
            m.natives.len(),
            0,
            "a macro call in a dead branch must not be extracted"
        );
    }

    #[test]
    fn obfuscated_name_folds_to_true() {
        let m = run("local v = BASIL_OBFUSCATED").unwrap();
        match &m.block.stmts[0] {
            Stmt::Local { exprs, .. } => assert!(matches!(exprs[0], Expr::True)),
            other => panic!("expected local, got {other:?}"),
        }
    }

    #[test]
    fn obfuscated_elseif_promotes_const_true_and_drops_rest() {
        let m =
            run("if runtimeX() then a() elseif BASIL_OBFUSCATED then b() else c() end").unwrap();
        assert!(
            matches!(m.block.stmts[0], Stmt::If { .. }),
            "a runtime first arm keeps an if"
        );
        assert!(block_mentions(&m.block, "a") && block_mentions(&m.block, "b"));
        assert!(
            !block_mentions(&m.block, "c"),
            "else after a constant-true elseif is dead"
        );
    }

    #[test]
    fn obfuscated_non_constant_if_is_unchanged() {
        let m = run("if runtimeX() then a() else b() end").unwrap();
        assert!(matches!(m.block.stmts[0], Stmt::If { .. }));
        assert!(
            block_mentions(&m.block, "a") && block_mentions(&m.block, "b"),
            "no folding without a constant condition"
        );
    }

    #[test]
    fn obfuscated_folds_inside_nested_function() {
        let m = run("local f = function() if not BASIL_OBFUSCATED then trace() end return 1 end")
            .unwrap();
        assert!(
            !block_mentions(&m.block, "trace"),
            "dead branch inside a nested function is stripped"
        );
    }

    fn has_crash(block: &Block) -> bool {
        block.stmts.iter().any(|s| match s {
            Stmt::Call(e) => matches!(e, Expr::Crash),
            Stmt::If { body, .. } => body
                .stmts
                .iter()
                .any(|s| matches!(s, Stmt::Call(Expr::Crash))),
            _ => false,
        }) || matches!(&block.last, Some(LastStmt::Return(es)) if es.iter().any(|e| matches!(e, Expr::Crash)))
    }

    #[test]
    fn crash_direct_call_lowers_to_crash() {
        assert!(
            has_crash(&run("BASIL_CRASH()").unwrap().block),
            "statement call"
        );
        assert!(
            has_crash(&run("if tamper() then BASIL_CRASH() end").unwrap().block),
            "in a conditional"
        );
        assert!(
            has_crash(&run("return BASIL_CRASH()").unwrap().block),
            "return position"
        );
    }

    #[test]
    fn crash_args_are_ignored() {
        assert!(has_crash(&run("BASIL_CRASH(1, 2, 3)").unwrap().block));
    }

    #[test]
    fn crash_must_be_called_directly() {
        assert_macro_err("local c = BASIL_CRASH", "reserved");
        assert_macro_err("someFn(BASIL_CRASH)", "reserved");
        assert_macro_err("local t = { c = BASIL_CRASH }", "reserved");
    }

    #[test]
    fn crash_dev_stub_strips() {
        let m = run(
            "if not BASIL_OBFUSCATED then function BASIL_CRASH() end end \
             if tamper() then BASIL_CRASH() end print(1)",
        )
        .unwrap();
        assert!(
            find_reserved(&m.block).is_none(),
            "no BASIL_ identifiers remain after the stub strips"
        );
    }

    fn first_local_expr(m: &Module) -> &Expr {
        match &m.block.stmts[0] {
            Stmt::Local { exprs, .. } => &exprs[0],
            other => panic!("expected a local, got {other:?}"),
        }
    }

    #[test]
    fn hash_literal_becomes_compile_time_digest() {
        let m = run(r#"local h = BASIL_HASH("abc")"#).unwrap();
        let want = format!("\"{}\"", bytecode::sha256::hex(b"abc"));
        assert_eq!(
            first_local_expr(&m),
            &Expr::Str(want),
            "literal -> SHA-256 hex of decoded bytes"
        );
        assert!(!m.hash_helper, "literal-only build needs no runtime helper");
    }

    #[test]
    fn hash_literal_decodes_escapes_and_long_brackets() {
        let plain = run(r#"local h = BASIL_HASH("ab\tc")"#).unwrap();
        let want = format!("\"{}\"", bytecode::sha256::hex(b"ab\tc"));
        assert_eq!(first_local_expr(&plain), &Expr::Str(want));
        let bracket = run("local h = BASIL_HASH([[xy]])").unwrap();
        let want_b = format!("\"{}\"", bytecode::sha256::hex(b"xy"));
        assert_eq!(first_local_expr(&bracket), &Expr::Str(want_b));
    }

    #[test]
    fn hash_literal_has_no_plaintext() {
        let m = run(r#"local h = BASIL_HASH("super-secret-license")"#).unwrap();
        if let Expr::Str(s) = first_local_expr(&m) {
            assert!(
                !s.contains("super-secret-license"),
                "plaintext literal must not survive"
            );
        } else {
            panic!("expected Str digest");
        }
    }

    #[test]
    fn hash_runtime_becomes_native_call_and_flags_helper() {
        let m = run("local h = BASIL_HASH(userInput)").unwrap();
        assert!(m.hash_helper, "runtime hash flags the helper");
        match first_local_expr(&m) {
            Expr::Call { func, args, .. } => {
                assert!(
                    matches!(**func, Expr::NativeRef(0)),
                    "calls the appended hash native"
                );
                assert!(
                    matches!(args[0], Expr::Name(_)),
                    "passes the runtime argument"
                );
            }
            other => panic!("expected a native call, got {other:?}"),
        }
    }

    #[test]
    fn hash_canonical_compare_mixes_literal_and_runtime() {
        let m = run(r#"local ok = BASIL_HASH(key) == BASIL_HASH("expected")"#).unwrap();
        assert!(m.hash_helper);
        match first_local_expr(&m) {
            Expr::Binop {
                op: BinOp::Eq,
                lhs,
                rhs,
            } => {
                assert!(
                    matches!(**lhs, Expr::Call { .. }),
                    "lhs runtime -> native call"
                );
                assert!(
                    matches!(**rhs, Expr::Str(_)),
                    "rhs literal -> digest constant"
                );
            }
            other => panic!("expected an == compare, got {other:?}"),
        }
    }

    #[test]
    fn hash_arg_errors() {
        assert_macro_err("local h = BASIL_HASH()", "exactly one");
        assert_macro_err(r#"local h = BASIL_HASH("a", "b")"#, "exactly one");
        assert_macro_err("local h = BASIL_HASH(123)", "non-string literal");
        assert_macro_err("local h = BASIL_HASH({})", "non-string literal");
        assert_macro_err("local h = BASIL_HASH(true)", "non-string literal");
    }

    #[test]
    fn hash_indirect_use_is_rejected() {
        assert_macro_err("local f = BASIL_HASH", "reserved");
    }

    #[test]
    fn hash_dev_stub_strips() {
        let m = run(
            r#"if not BASIL_OBFUSCATED then BASIL_HASH = function(s) return s end end
               local h = BASIL_HASH("tok")"#,
        )
        .unwrap();
        assert!(
            find_reserved(&m.block).is_none(),
            "no BASIL_ identifiers remain"
        );
    }

    #[test]
    fn hash_deterministic_same_seed() {
        let src = r#"local h = BASIL_HASH(k) local g = BASIL_HASH("z")"#;
        let a = expand(lower_str(src).unwrap(), 7).unwrap();
        let b = expand(lower_str(src).unwrap(), 7).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn opaque_lowers_true_and_false_to_nonliteral_exprs() {
        for v in ["true", "false"] {
            let m = run(&format!("local x = BASIL_OPAQUE({v})")).unwrap();
            match first_local_expr(&m) {
                Expr::Paren(inner) => assert!(
                    matches!(**inner, Expr::Binop { .. }),
                    "opaque is an arithmetic compare"
                ),
                other => panic!("expected paren(binop), got {other:?}"),
            }
            assert!(
                const_bool(first_local_expr(&m)).is_none(),
                "opaque must not be const-foldable by the OBFUSCATED path"
            );
        }
    }

    #[test]
    fn opaque_only_accepts_boolean_literals() {
        assert_macro_err("local x = BASIL_OPAQUE(v)", "only the boolean literals");
        assert_macro_err("local x = BASIL_OPAQUE(1)", "only the boolean literals");
        assert_macro_err(
            r#"local x = BASIL_OPAQUE("s")"#,
            "only the boolean literals",
        );
        assert_macro_err("local x = BASIL_OPAQUE(nil)", "only the boolean literals");
        assert_macro_err(
            "local x = BASIL_OPAQUE(a and b)",
            "only the boolean literals",
        );
        assert_macro_err("local x = BASIL_OPAQUE()", "exactly one");
        assert_macro_err("local x = BASIL_OPAQUE(true, false)", "exactly one");
    }

    #[test]
    fn opaque_deterministic_and_varies() {
        let src = "local x = BASIL_OPAQUE(true) local y = BASIL_OPAQUE(false)";
        assert_eq!(
            expand(lower_str(src).unwrap(), 5).unwrap(),
            expand(lower_str(src).unwrap(), 5).unwrap()
        );
        assert_ne!(
            expand(lower_str(src).unwrap(), 5).unwrap(),
            expand(lower_str(src).unwrap(), 6).unwrap()
        );
    }

    #[test]
    fn opaque_dev_stub_strips() {
        let m = run(
            "if not BASIL_OBFUSCATED then BASIL_OPAQUE = function(v) return v end end \
             local x = BASIL_OPAQUE(true)",
        )
        .unwrap();
        assert!(
            find_reserved(&m.block).is_none(),
            "no BASIL_ identifiers remain"
        );
    }

    const ENC_K: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn encfunc_valid_extracts() {
        let m = run(&format!(
            "local f = BASIL_ENCFUNC(function(a, b) return a + b end, \"{ENC_K}\", runtimeKey)"
        ))
        .unwrap();
        assert_eq!(m.encfuncs.len(), 1, "one protected function extracted");
        assert_eq!(
            m.encfuncs[0].key,
            ir::CompileKeySource::Literal(bytecode::aead::parse_hex_key(ENC_K).unwrap())
        );
        match first_local_expr(&m) {
            Expr::EncFunc { id, key } => {
                assert_eq!(*id, 0);
                assert!(matches!(**key, Expr::Name(_)), "runtime key preserved");
            }
            other => panic!("expected EncFunc, got {other:?}"),
        }
        assert!(find_reserved(&m.block).is_none());
    }

    #[test]
    fn encfunc_runtime_key_forms_accepted() {
        for k in [
            "runtimeKey",
            "resp.key",
            "keys[userId]",
            "getKey()",
            "Auth:GetKey()",
            "(getKey())",
        ] {
            run(&format!(
                "local f = BASIL_ENCFUNC(function() return 1 end, \"{ENC_K}\", {k})"
            ))
            .unwrap_or_else(|e| panic!("runtime key `{k}` should be accepted: {e:?}"));
        }
    }

    #[test]
    fn encfunc_arg_and_key_errors() {
        assert_macro_err(
            &format!("local f = BASIL_ENCFUNC(function() end, \"{ENC_K}\")"),
            "or three",
        );
        assert_macro_err(
            &format!("local f = BASIL_ENCFUNC(g, \"{ENC_K}\", rt)"),
            "not a reference",
        );
        assert_macro_err(
            &format!("local f = BASIL_ENCFUNC(123, \"{ENC_K}\", rt)"),
            "function-literal",
        );
        assert_macro_err(
            "local f = BASIL_ENCFUNC(function() end, keyVar, rt)",
            "not a reference",
        );
        assert_macro_err(
            "local f = BASIL_ENCFUNC(function() end, 123, rt)",
            "constant 64-character hex",
        );
        assert_macro_err(
            "local f = BASIL_ENCFUNC(function() end, \"00aa\", rt)",
            "exactly 64 hex",
        );
        assert_macro_err(
            "local f = BASIL_ENCFUNC(function() end, \"zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\", rt)",
            "non-hex",
        );
    }

    #[test]
    fn encfunc_runtime_key_must_not_be_literal() {
        for bad in [
            "\"lit\"",
            "12345",
            "true",
            "nil",
            "{ x }",
            "\"00\" .. \"11\"",
            "(\"00\" .. s)",
        ] {
            assert_macro_err(
                &format!("local f = BASIL_ENCFUNC(function() return 1 end, \"{ENC_K}\", {bad})"),
                "runtime value",
            );
        }
    }

    #[test]
    fn encfunc_key_reuse_rejected() {
        assert_macro_err(
            &format!("local leak = \"{ENC_K}\" local f = BASIL_ENCFUNC(function() return 1 end, \"{ENC_K}\", rt)"),
            "appear only as the macro key",
        );
    }

    #[test]
    fn encfunc_eligibility_rejects() {
        assert_macro_err(
            &format!(
                "local x = 5 local f = BASIL_ENCFUNC(function() return x end, \"{ENC_K}\", rt)"
            ),
            "captures the enclosing local `x`",
        );
        assert_macro_err(
            &format!("local f = BASIL_ENCFUNC(function() return function() return 1 end end, \"{ENC_K}\", rt)"),
            "escaping closure",
        );
        assert_macro_err(
            &format!(
                "local f = BASIL_ENCFUNC(function() return BASIL_ENCFUNC(function() return 1 end, \"{ENC_K}\", rt) end, \"{ENC_K}\", rt)"
            ),
            "nested inside another BASIL_ENCFUNC",
        );
        assert_macro_err(
            &format!(
                "local f = BASIL_ENCFUNC(function() return BASIL_NO_VIRTUALIZE(function() return 1 end) end, \"{ENC_K}\", rt)"
            ),
            "cannot appear inside a BASIL_ENCFUNC",
        );
    }

    #[test]
    fn encfunc_indirect_use_rejected() {
        assert_macro_err("local c = BASIL_ENCFUNC", "reserved");
    }

    #[test]
    fn encfunc_allows_hash_opaque_crash_inside() {
        let m = run(&format!(
            "local f = BASIL_ENCFUNC(function(n) if BASIL_OPAQUE(true) and BASIL_HASH(n) == BASIL_HASH(\"x\") then return 1 end BASIL_CRASH() end, \"{ENC_K}\", rt)"
        ))
        .unwrap();
        assert_eq!(m.encfuncs.len(), 1);
        assert!(
            m.hash_helper,
            "runtime BASIL_HASH inside ENCFUNC flags the helper"
        );
        assert!(find_reserved(&m.encfuncs[0].body.block).is_none());
    }

    #[test]
    fn encfunc_deterministic_same_seed() {
        let src = format!("local f = BASIL_ENCFUNC(function(n) if BASIL_OPAQUE(true) then return n end end, \"{ENC_K}\", rt)");
        assert_eq!(
            expand(lower_str(&src).unwrap(), 9).unwrap(),
            expand(lower_str(&src).unwrap(), 9).unwrap()
        );
    }

    fn enc_rtk(setup: &str, rtk: &str) -> String {
        format!("{setup}\nlocal p = BASIL_ENCFUNC(function(u) return u end, \"{ENC_K}\", {rtk})")
    }

    #[test]
    fn taint_direct_and_concat_literals_rejected() {
        assert_macro_err(&enc_rtk("", "\"deadbeef00\""), "runtime value");
        assert_macro_err(&enc_rtk("", "\"de\" .. \"ad\""), "runtime value");
    }

    #[test]
    fn taint_local_from_literal_rejected() {
        assert_macro_err(
            &enc_rtk("local rk = \"de\" .. \"ad\"", "rk"),
            "runtime value",
        );
    }

    #[test]
    fn taint_alias_chain_rejected() {
        assert_macro_err(
            &enc_rtk("local a = \"de\"\nlocal b = a .. \"ad\"\nlocal c = b", "c"),
            "runtime value",
        );
    }

    #[test]
    fn taint_table_literal_storage_rejected() {
        assert_macro_err(
            &enc_rtk("local keys = { \"de\" .. \"ad\" }", "keys[1]"),
            "runtime value",
        );
    }

    #[test]
    fn taint_local_function_returning_literal_rejected() {
        assert_macro_err(
            &enc_rtk(
                "local function getKey() return \"de\" .. \"ad\" end",
                "getKey()",
            ),
            "runtime value",
        );
    }

    #[test]
    fn taint_closure_returning_literal_rejected() {
        assert_macro_err(
            &enc_rtk(
                "local getKey = function() return \"de\" .. \"ad\" end",
                "getKey()",
            ),
            "runtime value",
        );
    }

    #[test]
    fn taint_function_intermediate_local_literal_rejected() {
        assert_macro_err(
            &enc_rtk(
                "local function getKey() local k = \"de\" .. \"ad\" return k end",
                "getKey()",
            ),
            "runtime value",
        );
    }

    #[test]
    fn taint_literal_transforms_rejected() {
        assert_macro_err(&enc_rtk("", "tostring(\"deadbeef00\")"), "runtime value");
        assert_macro_err(
            &enc_rtk("", "table.concat({ \"de\", \"ad\" })"),
            "runtime value",
        );
        assert_macro_err(
            &enc_rtk("", "string.sub(\"deadbeef00\", 1, 4)"),
            "runtime value",
        );
    }

    #[test]
    fn taint_runtime_sources_accepted() {
        for rtk in [
            "_G.BASILISK_RUNTIME_KEY",
            "getRuntimeKey()",
            "Auth:GetKey()",
            "serverResponse.key",
            "script:GetAttribute(\"RuntimeKey\")",
        ] {
            run(&enc_rtk("local runtimeKey = SRC", "runtimeKey").replace("SRC", rtk))
                .unwrap_or_else(|e| panic!("runtime source `{rtk}` should be accepted: {e:?}"));
            run(&enc_rtk("", rtk))
                .unwrap_or_else(|e| panic!("direct runtime source `{rtk}` rejected: {e:?}"));
        }
    }

    #[test]
    fn taint_key_material_selector_rejected() {
        assert_macro_err(
            &enc_rtk(
                "",
                "script:GetAttribute(\"00112233445566778899aabbccddeeff\")",
            ),
            "literal key material",
        );
    }

    #[test]
    fn taint_old_insecure_split_key_sample_rejected() {
        let h = "00112233445566778899aabbccddeeff";
        assert_macro_err(
            &enc_rtk(
                &format!("local a = \"{h}\"\nlocal b = \"{h}\"\nlocal runtimeKey = a .. b"),
                "runtimeKey",
            ),
            "key material",
        );
    }

    #[test]
    fn taint_compile_key_chunk_elsewhere_rejected() {
        let h = "00112233445566778899aabbccddeeff";
        assert_macro_err(
            &enc_rtk(
                &format!("local junk = \"{h}\"\nlocal runtimeKey = getKey()"),
                "runtimeKey",
            ),
            "appear only as the macro key",
        );
    }

    fn enc_seed_rtk(setup: &str, rts: &str) -> String {
        format!("{setup}\nlocal p = BASIL_ENCFUNC_SEED(function(u) return u end, 1234567890123456, {rts})")
    }

    #[test]
    fn encfunc_seed_valid_extracts_with_kdf_key() {
        let m = run("local f = BASIL_ENCFUNC_SEED(function(a, b) return a + b end, 1234567890123456, runtimeSeed)").unwrap();
        assert_eq!(m.encfuncs.len(), 1, "one protected function extracted");
        assert_eq!(
            m.encfuncs[0].key,
            ir::CompileKeySource::Managed {
                seed: 1234567890123456,
                key: bytecode::aead::seed_key(1234567890123456)
            }
        );
        match first_local_expr(&m) {
            Expr::EncFunc { id, key } => {
                assert_eq!(*id, 0);
                assert!(matches!(**key, Expr::Name(_)), "runtime seed preserved");
            }
            other => panic!("expected EncFunc, got {other:?}"),
        }
        assert!(find_reserved(&m.block).is_none());
    }

    #[test]
    fn encfunc_seed_zero_and_max_seed_accepted() {
        assert!(run("local f = BASIL_ENCFUNC_SEED(function() return 1 end, 0, rs)").is_ok());
        assert!(
            run("local f = BASIL_ENCFUNC_SEED(function() return 1 end, 9007199254740991, rs)")
                .is_ok()
        );
    }

    #[test]
    fn encfunc_seed_compile_seed_must_be_valid_integer_literal() {
        for (bad, needle) in [
            ("\"123\"", "non-negative integer"),
            ("1.5", "[0, 2^53 - 1]"),
            ("-1", "non-negative integer"),
            ("9007199254740992", "[0, 2^53 - 1]"),
            ("someVar", "not a reference"),
            ("rs", "not a reference"),
        ] {
            assert_macro_err(
                &format!("local f = BASIL_ENCFUNC_SEED(function() return 1 end, {bad}, rs)"),
                needle,
            );
        }
    }

    #[test]
    fn encfunc_seed_runtime_seed_must_not_be_literal_or_literal_derived() {
        assert_macro_err(&enc_seed_rtk("", "1234567890123456"), "runtime");
        assert_macro_err(&enc_seed_rtk("", "100 + 200"), "runtime");
        assert_macro_err(&enc_seed_rtk("local s = 42\nlocal s2 = s", "s2"), "runtime");
        assert_macro_err(&enc_seed_rtk("local t = { 42 }", "t[1]"), "runtime");
        assert_macro_err(
            &enc_seed_rtk("local function gs() return 42 end", "gs()"),
            "runtime",
        );
    }

    #[test]
    fn encfunc_seed_runtime_seed_forms_accepted() {
        for ok in [
            "runtimeSeed",
            "_G.BASILISK_RUNTIME_SEED",
            "getSeed()",
            "Auth:GetSeed()",
            "resp.seed",
        ] {
            assert!(
                run(&enc_seed_rtk("", ok)).is_ok(),
                "{ok} should be accepted"
            );
        }
    }

    #[test]
    fn encfunc_seed_eligibility_and_nesting_rejected() {
        assert_macro_err(
            "local up = 1\nlocal f = BASIL_ENCFUNC_SEED(function() return up end, 7, rs)",
            "captures",
        );
        assert_macro_err(
            "local f = BASIL_ENCFUNC_SEED(function() return BASIL_ENCFUNC_SEED(function() return 1 end, 7, rs) end, 7, rs)",
            "nested",
        );
        assert_macro_err(
            &format!("local f = BASIL_ENCFUNC_SEED(function() return BASIL_ENCFUNC(function() return 1 end, \"{ENC_K}\", rk) end, 7, rs)"),
            "nested",
        );
        assert_macro_err(
            "local f = BASIL_ENCFUNC_SEED(function() return 1 end, 7)",
            "three arguments",
        );
        assert_macro_err(
            "local g = function() return 1 end\nlocal f = BASIL_ENCFUNC_SEED(g, 7, rs)",
            "function literal",
        );
    }

    #[test]
    fn encfunc_seed_deterministic_same_seed() {
        let a = run("local f = BASIL_ENCFUNC_SEED(function() return 1 end, 555, rs)").unwrap();
        let b = run("local f = BASIL_ENCFUNC_SEED(function() return 1 end, 555, rs)").unwrap();
        assert_eq!(a.encfuncs[0].key, b.encfuncs[0].key);
        let c = run("local f = BASIL_ENCFUNC_SEED(function() return 1 end, 556, rs)").unwrap();
        assert_ne!(a.encfuncs[0].key, c.encfuncs[0].key);
    }

    #[test]
    fn encfunc_managed_one_arg_desugars_to_managed_key() {
        let m = run("local f = BASIL_ENCFUNC(function(a, b) return a + b end)").unwrap();
        assert_eq!(m.encfuncs.len(), 1, "one protected function extracted");
        assert!(
            m.encfuncs[0].key.is_managed(),
            "one-arg form is compiler-managed"
        );
        match first_local_expr(&m) {
            Expr::EncFunc { id, key } => {
                assert_eq!(*id, 0);
                assert!(
                    matches!(**key, Expr::Call { .. }),
                    "managed runtime key is a self-derived call"
                );
            }
            other => panic!("expected EncFunc, got {other:?}"),
        }
        assert!(find_reserved(&m.block).is_none());
    }

    #[test]
    fn encfunc_managed_one_arg_non_function_rejected() {
        assert_macro_err("local f = BASIL_ENCFUNC(\"x\")", "function literal");
        assert_macro_err(
            "local g = function() end\nlocal f = BASIL_ENCFUNC(g)",
            "function literal",
        );
    }

    #[test]
    fn encfunc_strict_arity_two_and_five_rejected() {
        assert_macro_err(
            &format!("local f = BASIL_ENCFUNC(function() end, \"{ENC_K}\")"),
            "or three",
        );
        assert_macro_err(
            &format!("local f = BASIL_ENCFUNC(function() end, \"{ENC_K}\", rt, 1, 2)"),
            "or three",
        );
    }

    #[test]
    fn encfunc_managed_sites_derive_distinct_keys() {
        let m = run(
            "local a = BASIL_ENCFUNC(function() return 1 end)\nlocal b = BASIL_ENCFUNC(function() return 2 end)",
        )
        .unwrap();
        assert_eq!(m.encfuncs.len(), 2);
        assert_ne!(
            m.encfuncs[0].key, m.encfuncs[1].key,
            "each managed site derives a distinct key"
        );
    }

    #[test]
    fn encfunc_managed_domain_differs_from_encstr_managed() {
        let f = run("local a = BASIL_ENCFUNC(function() return \"X\" end)").unwrap();
        let s = run("local a = BASIL_ENCSTR(\"X\")").unwrap();
        assert_ne!(
            f.encfuncs[0].key, s.encfuncs[0].key,
            "ENCFUNC and ENCSTR managed forms derive from different domains"
        );
    }

    #[test]
    fn encfunc_managed_preserves_leaf_restrictions() {
        assert_macro_err(
            "local up = 1\nlocal f = BASIL_ENCFUNC(function() return up end)",
            "captures",
        );
        assert_macro_err(
            "local f = BASIL_ENCFUNC(function() return BASIL_ENCFUNC(function() return 1 end) end)",
            "nested",
        );
    }

    #[test]
    fn encfunc_managed_deterministic_same_seed() {
        let a = run("local f = BASIL_ENCFUNC(function() return 1 end)").unwrap();
        let b = run("local f = BASIL_ENCFUNC(function() return 1 end)").unwrap();
        assert_eq!(a.encfuncs[0].key, b.encfuncs[0].key);
    }
}
