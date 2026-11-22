use std::collections::HashMap;

use ir::{BinOp, CompoundOp, Expr, Field, Stmt, UnOp};

use crate::inst::Inst;
use crate::literal;
use crate::opcode::Opcode;
use crate::proto::{Const, Proto, UpvalDesc};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, PartialEq)]
enum NRes {
    None,
    One,
    Multi,
    Exact(u16),
}

enum ArgKind {
    Fixed(usize),
    Variadic,
}

enum NameKind {
    Local(u16),
    Upval(u16),
    Global,
}

struct LocalVar {
    name: String,
    reg: u16,
    captured: bool,
}

struct UpvalEntry {
    name: String,
    desc: UpvalDesc,
}

struct LoopCtx {
    close_level: u16,
    continue_target: usize,
    continue_jumps: Vec<usize>,
    breaks: Vec<usize>,
}

struct FuncState {
    num_params: u8,
    is_vararg: bool,
    has_closures: bool,
    code: Vec<Inst>,
    consts: Vec<Const>,
    const_num: HashMap<u64, i32>,
    const_str: HashMap<Vec<u8>, i32>,
    upvals: Vec<UpvalEntry>,
    protos: Vec<Proto>,
    locals: Vec<LocalVar>,
    locals_top: u16,
    free: u16,
    max: u16,
    loops: Vec<LoopCtx>,
}

impl FuncState {
    fn new(num_params: u8, is_vararg: bool, has_closures: bool) -> Self {
        FuncState {
            num_params,
            is_vararg,
            has_closures,
            code: Vec::new(),
            consts: Vec::new(),
            const_num: HashMap::new(),
            const_str: HashMap::new(),
            upvals: Vec::new(),
            protos: Vec::new(),
            locals: Vec::new(),
            locals_top: 0,
            free: 0,
            max: 0,
            loops: Vec::new(),
        }
    }

    fn emit(&mut self, op: Opcode, a: i32, b: i32, c: i32) -> usize {
        self.code.push(Inst::new(op, a, b, c));
        self.code.len() - 1
    }

    fn here(&self) -> usize {
        self.code.len()
    }

    fn patch(&mut self, at: usize, to: usize) {
        let offset = to as i64 - (at as i64 + 1);

        let slot = match self.code[at].op {
            Opcode::Jmp => &mut self.code[at].a,
            _ => &mut self.code[at].b,
        };
        *slot = offset as i32;
    }

    fn patch_here(&mut self, at: usize) {
        let to = self.here();
        self.patch(at, to);
    }

    fn konst_num(&mut self, n: f64) -> i32 {
        let key = n.to_bits();
        if let Some(&i) = self.const_num.get(&key) {
            return i;
        }
        let i = self.consts.len() as i32;
        self.consts.push(Const::Number(n));
        self.const_num.insert(key, i);
        i
    }

    fn konst_str(&mut self, bytes: &[u8]) -> i32 {
        if let Some(&i) = self.const_str.get(bytes) {
            return i;
        }
        let i = self.consts.len() as i32;
        self.consts.push(Const::Str(bytes.to_vec()));
        self.const_str.insert(bytes.to_vec(), i);
        i
    }

    fn set_free(&mut self, v: u16) {
        self.free = v;
        self.bump(v);
    }

    fn bump(&mut self, top: u16) {
        if top > self.max {
            self.max = top;
        }
    }

    fn alloc(&mut self) -> u16 {
        let r = self.free;
        self.free += 1;
        self.bump(self.free);
        r
    }

    fn reset_free(&mut self) {
        self.free = self.locals_top;
    }

    fn reserve_slot(&mut self) -> u16 {
        let r = self.locals_top;
        self.locals_top += 1;
        if self.free < self.locals_top {
            self.free = self.locals_top;
        }
        self.bump(self.locals_top);
        r
    }

    fn declare_local(&mut self, name: &str) -> u16 {
        let reg = self.reserve_slot();
        self.locals.push(LocalVar {
            name: name.to_string(),
            reg,
            captured: false,
        });
        reg
    }

    fn find_local(&self, name: &str) -> Option<u16> {
        self.locals
            .iter()
            .rev()
            .find(|l| l.name == name)
            .map(|l| l.reg)
    }

    fn mark_captured(&mut self, reg: u16) {
        if let Some(l) = self.locals.iter_mut().rev().find(|l| l.reg == reg) {
            l.captured = true;
        }
    }

    fn find_upval(&self, name: &str) -> Option<u16> {
        self.upvals
            .iter()
            .position(|u| u.name == name)
            .map(|i| i as u16)
    }

    fn add_upval(&mut self, name: &str, desc: UpvalDesc) -> u16 {
        let i = self.upvals.len() as u16;
        self.upvals.push(UpvalEntry {
            name: name.to_string(),
            desc,
        });
        i
    }

    fn finish(self) -> Proto {
        Proto {
            num_params: self.num_params,
            is_vararg: self.is_vararg,
            max_stack: self.max.max(self.num_params as u16).max(2),
            code: self.code,
            consts: self.consts,
            upvals: self.upvals.into_iter().map(|u| u.desc).collect(),
            protos: self.protos,
            line_info: Vec::new(),
            hot_callback: None,
            stable_id: None,
            d1: None,
        }
    }
}

pub fn compile(module: &ir::Module) -> Result<Proto> {
    let mut stack = Vec::new();
    let has_closures = block_has_closures(&module.block);
    stack.push(FuncState::new(0, true, has_closures));
    compile_block(&mut stack, &module.block)?;
    emit_implicit_return(&mut stack);
    let root = stack.pop().unwrap();
    Ok(root.finish())
}

pub fn compile_func(body: &ir::FuncBody) -> Result<Proto> {
    let num_params = body
        .params
        .iter()
        .filter(|p| matches!(p, ir::Param::Name(_)))
        .count() as u8;
    let is_vararg = body.params.iter().any(|p| matches!(p, ir::Param::Vararg));
    let has_closures = block_has_closures(&body.block);
    let mut stack = Vec::new();
    let mut fs = FuncState::new(num_params, is_vararg, has_closures);
    for param in &body.params {
        if let ir::Param::Name(name) = param {
            fs.declare_local(name);
        }
    }
    stack.push(fs);
    compile_block(&mut stack, &body.block)?;
    emit_implicit_return(&mut stack);
    Ok(stack.pop().unwrap().finish())
}

fn cur(stack: &mut [FuncState]) -> &mut FuncState {
    stack.last_mut().unwrap()
}

fn emit_implicit_return(stack: &mut [FuncState]) {
    let base = cur(stack).locals_top as i32;
    cur(stack).emit(Opcode::Return, base, 1, 0);
}

fn block_has_closures(block: &ir::Block) -> bool {
    block.stmts.iter().any(stmt_has_closures)
}

fn stmt_has_closures(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Function { .. } | Stmt::LocalFunction { .. } => true,
        Stmt::Local { exprs, .. } => exprs.iter().any(expr_has_closures),
        Stmt::Assign { targets, exprs } => targets.iter().chain(exprs).any(expr_has_closures),
        Stmt::Compound { target, value, .. } => {
            expr_has_closures(target) || expr_has_closures(value)
        }
        Stmt::Call(e) => expr_has_closures(e),
        Stmt::Do(b) => block_has_closures(b),
        Stmt::While { cond, body } => expr_has_closures(cond) || block_has_closures(body),
        Stmt::Repeat { body, until } => block_has_closures(body) || expr_has_closures(until),
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            expr_has_closures(start)
                || expr_has_closures(end)
                || step.as_ref().is_some_and(expr_has_closures)
                || block_has_closures(body)
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter().any(expr_has_closures) || block_has_closures(body)
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            expr_has_closures(cond)
                || block_has_closures(body)
                || else_ifs
                    .iter()
                    .any(|(c, b)| expr_has_closures(c) || block_has_closures(b))
                || otherwise.as_ref().is_some_and(block_has_closures)
        }
    }
}

fn expr_has_closures(expr: &Expr) -> bool {
    match expr {
        Expr::Function(_) => true,
        Expr::Paren(e) | Expr::Unop { expr: e, .. } => expr_has_closures(e),
        Expr::Field { base, .. } => expr_has_closures(base),
        Expr::Index { base, key } => expr_has_closures(base) || expr_has_closures(key),
        Expr::Call { func, args, .. } => {
            expr_has_closures(func) || args.iter().any(expr_has_closures)
        }
        Expr::MethodCall { base, args, .. } => {
            expr_has_closures(base) || args.iter().any(expr_has_closures)
        }
        Expr::Binop { lhs, rhs, .. } => expr_has_closures(lhs) || expr_has_closures(rhs),
        Expr::Table(fields) => fields.iter().any(|f| match f {
            Field::Positional(e) => expr_has_closures(e),
            Field::Named { value, .. } => expr_has_closures(value),
            Field::Keyed { key, value } => expr_has_closures(key) || expr_has_closures(value),
        }),
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            expr_has_closures(cond)
                || expr_has_closures(then)
                || else_ifs
                    .iter()
                    .any(|(c, e)| expr_has_closures(c) || expr_has_closures(e))
                || expr_has_closures(otherwise)
        }
        Expr::Interp(parts) => parts.iter().any(|p| match p {
            ir::InterpPart::Expr(e) => expr_has_closures(e),
            ir::InterpPart::Lit(_) => false,
        }),
        Expr::OpcodeHint { family, .. } => *family == ir::OpFamily::Call,
        other => {
            let mut found = false;
            other.each_child(&mut |c| found |= expr_has_closures(c));
            found
        }
    }
}

struct Scope {
    locals_top: u16,
    locals_len: usize,
}

fn enter_scope(stack: &mut [FuncState]) -> Scope {
    let fs = cur(stack);
    Scope {
        locals_top: fs.locals_top,
        locals_len: fs.locals.len(),
    }
}

fn exit_scope(stack: &mut [FuncState], scope: Scope) {
    let fs = cur(stack);
    fs.locals.truncate(scope.locals_len);
    fs.locals_top = scope.locals_top;
    fs.free = scope.locals_top;
}

fn maybe_close(stack: &mut [FuncState], level: u16) {
    let fs = cur(stack);
    if fs.has_closures {
        fs.emit(Opcode::Close, level as i32, 0, 0);
    }
}

fn compile_block(stack: &mut Vec<FuncState>, block: &ir::Block) -> Result<()> {
    for stmt in &block.stmts {
        compile_stmt(stack, stmt)?;
        cur(stack).reset_free();
    }
    if let Some(last) = &block.last {
        compile_last(stack, last)?;
    }
    Ok(())
}

fn compile_last(stack: &mut Vec<FuncState>, last: &ir::LastStmt) -> Result<()> {
    match last {
        ir::LastStmt::Break => {
            let jmp = cur(stack).emit(Opcode::Jmp, 0, 0, 0);
            cur(stack)
                .loops
                .last_mut()
                .ok_or("break outside loop")?
                .breaks
                .push(jmp);
            Ok(())
        }
        ir::LastStmt::Continue => {
            let fs = cur(stack);
            let ctx = fs.loops.last_mut().ok_or("continue outside loop")?;
            if ctx.continue_target == usize::MAX {
                let jmp = fs.emit(Opcode::Jmp, 0, 0, 0);
                fs.loops.last_mut().unwrap().continue_jumps.push(jmp);
            } else {
                let target = ctx.continue_target;
                let jmp = fs.emit(Opcode::Jmp, 0, 0, 0);
                fs.patch(jmp, target);
            }
            Ok(())
        }
        ir::LastStmt::Return(exprs) => {
            let base = cur(stack).locals_top;
            cur(stack).set_free(base);
            let kind = compile_list(stack, exprs)?;
            let b = match kind {
                ArgKind::Fixed(n) => n as i32 + 1,
                ArgKind::Variadic => 0,
            };
            cur(stack).emit(Opcode::Return, base as i32, b, 0);
            Ok(())
        }
    }
}

fn opc_rng(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn scratch_num(rng: &mut u64) -> f64 {
    (opc_rng(rng) % 1_000_000) as f64
}

fn scratch_str(rng: &mut u64) -> Vec<u8> {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let n = 2 + (opc_rng(rng) % 6) as usize;
    (0..n)
        .map(|_| A[(opc_rng(rng) % A.len() as u64) as usize])
        .collect()
}

fn emit_opcode_bundle(
    stack: &mut Vec<FuncState>,
    family: ir::OpFamily,
    intensity: u8,
    key: u64,
) -> Result<()> {
    let base = cur(stack).free;
    let mut rng = key ^ 0x_4F50_4844_5F53_4652;
    let reps = intensity.clamp(1, 8);
    for _ in 0..reps {
        emit_one_bundle(stack, family, &mut rng)?;
        cur(stack).set_free(base);
    }
    Ok(())
}

fn emit_one_bundle(stack: &mut Vec<FuncState>, family: ir::OpFamily, rng: &mut u64) -> Result<()> {
    use ir::OpFamily;
    match family {
        OpFamily::Move => {
            let a = cur(stack).alloc();
            let b = cur(stack).alloc();
            let k = cur(stack).konst_num(scratch_num(rng));
            cur(stack).emit(Opcode::LoadK, a as i32, k, 0);
            let hops = 1 + (opc_rng(rng) % 3);
            let (mut src, mut dst) = (a, b);
            for _ in 0..hops {
                cur(stack).emit(Opcode::Move, dst as i32, src as i32, 0);
                std::mem::swap(&mut src, &mut dst);
            }
        }
        OpFamily::LoadK => {
            let a = cur(stack).alloc();
            let loads = 1 + (opc_rng(rng) % 3);
            for _ in 0..loads {
                let k = if opc_rng(rng) & 1 == 0 {
                    cur(stack).konst_num(scratch_num(rng))
                } else {
                    let s = scratch_str(rng);
                    cur(stack).konst_str(&s)
                };
                cur(stack).emit(Opcode::LoadK, a as i32, k, 0);
            }
        }
        OpFamily::Eq | OpFamily::Lt | OpFamily::Le => {
            let a = cur(stack).alloc();
            let b = cur(stack).alloc();
            let c = cur(stack).alloc();
            let ka = cur(stack).konst_num(scratch_num(rng));
            let kb = cur(stack).konst_num(scratch_num(rng));
            cur(stack).emit(Opcode::LoadK, a as i32, ka, 0);
            cur(stack).emit(Opcode::LoadK, b as i32, kb, 0);
            let op = match family {
                OpFamily::Eq => Opcode::Eq,
                OpFamily::Lt => Opcode::Lt,
                _ => Opcode::Le,
            };
            cur(stack).emit(op, c as i32, a as i32, b as i32);
        }
        OpFamily::Concat => {
            let a = cur(stack).alloc();
            let b = cur(stack).alloc();
            let c = cur(stack).alloc();
            let sa = scratch_str(rng);
            let sb = scratch_str(rng);
            let ka = cur(stack).konst_str(&sa);
            let kb = cur(stack).konst_str(&sb);
            cur(stack).emit(Opcode::LoadK, a as i32, ka, 0);
            cur(stack).emit(Opcode::LoadK, b as i32, kb, 0);
            cur(stack).emit(Opcode::Concat, c as i32, a as i32, b as i32);
        }
        OpFamily::Call => {
            let empty: Vec<ir::Param> = Vec::new();
            let proto = compile_nested(stack, &empty, ir::Block::default(), None, None)?;
            let a = cur(stack).alloc();
            cur(stack).emit(Opcode::Closure, a as i32, proto as i32, 0);
            cur(stack).emit(Opcode::Call, a as i32, 1, 1);
        }
    }
    Ok(())
}

fn compile_stmt(stack: &mut Vec<FuncState>, stmt: &Stmt) -> Result<()> {
    match stmt {
        Stmt::Local { names, exprs } => {
            let base = cur(stack).locals_top;
            compile_adjusted(stack, exprs, base, names.len() as u16)?;
            for name in names {
                cur(stack).declare_local(name);
            }
        }
        Stmt::Assign { targets, exprs } => compile_assign(stack, targets, exprs)?,
        Stmt::Compound { target, op, value } => compile_compound(stack, target, *op, value)?,
        Stmt::Call(call) => {
            if let Expr::OpcodeHint {
                family,
                intensity,
                key,
            } = call
            {
                emit_opcode_bundle(stack, *family, *intensity, *key)?;
            } else if matches!(call, Expr::Crash) {
                compile_expr_push(stack, call)?;
            } else {
                compile_callish(stack, call, NRes::None)?;
            }
        }
        Stmt::Do(body) => {
            let scope = enter_scope(stack);
            compile_block(stack, body)?;
            maybe_close(stack, scope.locals_top);
            exit_scope(stack, scope);
        }
        Stmt::While { cond, body } => compile_while(stack, cond, body)?,
        Stmt::Repeat { body, until } => compile_repeat(stack, body, until)?,
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        } => compile_numeric_for(stack, var, start, end, step.as_ref(), body)?,
        Stmt::GenericFor { names, exprs, body } => compile_generic_for(stack, names, exprs, body)?,
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => compile_if(stack, cond, body, else_ifs, otherwise)?,
        Stmt::Function { name, body } => {
            let mut params = body.params.clone();
            if name.method.is_some() {
                params.insert(0, ir::Param::Name("self".to_string()));
            }
            let proto = compile_nested(
                stack,
                &params,
                body.block.clone(),
                body.hot_callback,
                body.stable_id,
            )?;
            let reg = cur(stack).alloc();
            cur(stack).emit(Opcode::Closure, reg as i32, proto as i32, 0);
            store_function_name(stack, name, reg)?;
        }
        Stmt::LocalFunction { name, body } => {
            let reg = cur(stack).declare_local(name);
            let proto = compile_nested(
                stack,
                &body.params,
                body.block.clone(),
                body.hot_callback,
                body.stable_id,
            )?;
            cur(stack).emit(Opcode::Closure, reg as i32, proto as i32, 0);
        }
    }
    Ok(())
}

fn store_function_name(
    stack: &mut Vec<FuncState>,
    name: &ir::FunctionName,
    value: u16,
) -> Result<()> {
    let mut place = Expr::Name(name.path[0].clone());
    for seg in &name.path[1..] {
        place = Expr::Field {
            base: Box::new(place),
            name: seg.clone(),
        };
    }
    if let Some(method) = &name.method {
        place = Expr::Field {
            base: Box::new(place),
            name: method.clone(),
        };
    }
    store_into(stack, &place, value)
}

fn compile_assign(stack: &mut Vec<FuncState>, targets: &[Expr], exprs: &[Expr]) -> Result<()> {
    if targets.len() == 1 {
        let base = cur(stack).free;
        compile_adjusted(stack, exprs, base, 1)?;
        store_into(stack, &targets[0], base)?;
        cur(stack).reset_free();
        return Ok(());
    }
    let mut places = Vec::new();
    for target in targets {
        places.push(prep_place(stack, target)?);
    }
    let base = cur(stack).free;
    compile_adjusted(stack, exprs, base, targets.len() as u16)?;
    for (i, place) in places.into_iter().enumerate() {
        emit_store(stack, place, base + i as u16);
    }
    cur(stack).reset_free();
    Ok(())
}

enum Place {
    Local(u16),
    Upval(u16),
    Global(i32),
    Table { obj: u16, key: u16 },
}

fn prep_place(stack: &mut Vec<FuncState>, target: &Expr) -> Result<Place> {
    match target {
        Expr::Name(name) => Ok(match resolve_name(stack, name) {
            NameKind::Local(r) => Place::Local(r),
            NameKind::Upval(u) => Place::Upval(u),
            NameKind::Global => Place::Global(cur(stack).konst_str(name.as_bytes())),
        }),
        Expr::Field { base, name } => {
            let obj = compile_expr_push(stack, base)?;
            let key = cur(stack).alloc();
            let k = cur(stack).konst_str(name.as_bytes());
            cur(stack).emit(Opcode::LoadK, key as i32, k, 0);
            Ok(Place::Table { obj, key })
        }
        Expr::Index { base, key } => {
            let obj = compile_expr_push(stack, base)?;
            let keyr = compile_expr_push(stack, key)?;
            Ok(Place::Table { obj, key: keyr })
        }
        _ => Err("invalid assignment target".into()),
    }
}

fn emit_store(stack: &mut Vec<FuncState>, place: Place, value: u16) {
    let fs = cur(stack);
    match place {
        Place::Local(r) => {
            fs.emit(Opcode::Move, r as i32, value as i32, 0);
        }
        Place::Upval(u) => {
            fs.emit(Opcode::SetUpval, value as i32, u as i32, 0);
        }
        Place::Global(k) => {
            fs.emit(Opcode::SetGlobal, value as i32, k, 0);
        }
        Place::Table { obj, key } => {
            fs.emit(Opcode::SetTable, obj as i32, key as i32, value as i32);
        }
    }
}

fn store_into(stack: &mut Vec<FuncState>, target: &Expr, value: u16) -> Result<()> {
    let place = prep_place(stack, target)?;
    emit_store(stack, place, value);
    Ok(())
}

fn compile_compound(
    stack: &mut Vec<FuncState>,
    target: &Expr,
    op: CompoundOp,
    value: &Expr,
) -> Result<()> {
    let arith = compound_opcode(op);
    match target {
        Expr::Name(name) => match resolve_name(stack, name) {
            NameKind::Local(reg) => {
                let rv = compile_expr_push(stack, value)?;
                cur(stack).emit(arith, reg as i32, reg as i32, rv as i32);
            }
            NameKind::Upval(u) => {
                let r = cur(stack).alloc();
                cur(stack).emit(Opcode::GetUpval, r as i32, u as i32, 0);
                let rv = compile_expr_push(stack, value)?;
                cur(stack).emit(arith, r as i32, r as i32, rv as i32);
                cur(stack).emit(Opcode::SetUpval, r as i32, u as i32, 0);
            }
            NameKind::Global => {
                let k = cur(stack).konst_str(name.as_bytes());
                let r = cur(stack).alloc();
                cur(stack).emit(Opcode::GetGlobal, r as i32, k, 0);
                let rv = compile_expr_push(stack, value)?;
                cur(stack).emit(arith, r as i32, r as i32, rv as i32);
                cur(stack).emit(Opcode::SetGlobal, r as i32, k, 0);
            }
        },
        Expr::Field { .. } | Expr::Index { .. } => {
            let place = prep_place(stack, target)?;
            let Place::Table { obj, key } = place else {
                unreachable!()
            };
            let cur_val = cur(stack).alloc();
            cur(stack).emit(Opcode::GetTable, cur_val as i32, obj as i32, key as i32);
            let rv = compile_expr_push(stack, value)?;
            cur(stack).emit(arith, cur_val as i32, cur_val as i32, rv as i32);
            cur(stack).emit(Opcode::SetTable, obj as i32, key as i32, cur_val as i32);
        }
        _ => return Err("invalid compound-assignment target".into()),
    }
    cur(stack).reset_free();
    Ok(())
}

fn compile_if(
    stack: &mut Vec<FuncState>,
    cond: &Expr,
    body: &ir::Block,
    else_ifs: &[(Expr, ir::Block)],
    otherwise: &Option<ir::Block>,
) -> Result<()> {
    let mut end_jumps = Vec::new();
    let mut next = compile_cond_branch(stack, cond, body)?;
    for (econd, eblock) in else_ifs {
        let jmp = cur(stack).emit(Opcode::Jmp, 0, 0, 0);
        end_jumps.push(jmp);
        cur(stack).patch_here(next);
        next = compile_cond_branch(stack, econd, eblock)?;
    }
    if let Some(eblock) = otherwise {
        let jmp = cur(stack).emit(Opcode::Jmp, 0, 0, 0);
        end_jumps.push(jmp);
        cur(stack).patch_here(next);
        let scope = enter_scope(stack);
        compile_block(stack, eblock)?;
        maybe_close(stack, scope.locals_top);
        exit_scope(stack, scope);
    } else {
        cur(stack).patch_here(next);
    }
    for jmp in end_jumps {
        cur(stack).patch_here(jmp);
    }
    Ok(())
}

fn compile_cond_branch(stack: &mut Vec<FuncState>, cond: &Expr, body: &ir::Block) -> Result<usize> {
    let rc = compile_expr_push(stack, cond)?;
    let skip = cur(stack).emit(Opcode::JmpIfNot, rc as i32, 0, 0);
    cur(stack).reset_free();
    let scope = enter_scope(stack);
    compile_block(stack, body)?;
    maybe_close(stack, scope.locals_top);
    exit_scope(stack, scope);
    Ok(skip)
}

fn compile_while(stack: &mut Vec<FuncState>, cond: &Expr, body: &ir::Block) -> Result<()> {
    let top = cur(stack).here();
    let rc = compile_expr_push(stack, cond)?;
    let exit = cur(stack).emit(Opcode::JmpIfNot, rc as i32, 0, 0);
    cur(stack).reset_free();
    let base = cur(stack).locals_top;
    cur(stack).loops.push(LoopCtx {
        close_level: base,
        continue_target: top,
        continue_jumps: Vec::new(),
        breaks: Vec::new(),
    });
    let scope = enter_scope(stack);
    compile_block(stack, body)?;
    exit_scope(stack, scope);
    maybe_close(stack, base);
    let back = cur(stack).emit(Opcode::Jmp, 0, 0, 0);
    cur(stack).patch(back, top);
    cur(stack).patch_here(exit);
    finish_loop(stack);
    Ok(())
}

fn compile_repeat(stack: &mut Vec<FuncState>, body: &ir::Block, until: &Expr) -> Result<()> {
    let top = cur(stack).here();
    let base = cur(stack).locals_top;
    cur(stack).loops.push(LoopCtx {
        close_level: base,
        continue_target: usize::MAX,
        continue_jumps: Vec::new(),
        breaks: Vec::new(),
    });
    let scope = enter_scope(stack);
    compile_block(stack, body)?;

    let cont = cur(stack).here();
    patch_continues(stack, cont);
    let rc = compile_expr_push(stack, until)?;
    maybe_close(stack, base);
    let back = cur(stack).emit(Opcode::JmpIfNot, rc as i32, 0, 0);
    cur(stack).patch(back, top);
    exit_scope(stack, scope);
    finish_loop(stack);
    Ok(())
}

fn compile_numeric_for(
    stack: &mut Vec<FuncState>,
    var: &str,
    start: &Expr,
    end: &Expr,
    step: Option<&Expr>,
    body: &ir::Block,
) -> Result<()> {
    let base = cur(stack).locals_top;
    compile_expr_to(stack, start, base)?;
    compile_expr_to(stack, end, base + 1)?;
    match step {
        Some(s) => compile_expr_to(stack, s, base + 2)?,
        None => {
            let k = cur(stack).konst_num(1.0);
            cur(stack).emit(Opcode::LoadK, (base + 2) as i32, k, 0);
        }
    }
    cur(stack).reserve_slot();
    cur(stack).reserve_slot();
    cur(stack).reserve_slot();
    let prep = cur(stack).emit(Opcode::ForPrep, base as i32, 0, 0);
    let top = cur(stack).here();
    cur(stack).loops.push(LoopCtx {
        close_level: base + 3,
        continue_target: usize::MAX,
        continue_jumps: Vec::new(),
        breaks: Vec::new(),
    });
    let scope = enter_scope(stack);
    cur(stack).declare_local(var);
    compile_block(stack, body)?;
    exit_scope(stack, scope);
    let cont = cur(stack).here();
    patch_continues(stack, cont);
    maybe_close(stack, base + 3);
    cur(stack).patch_here(prep);
    let loop_pos = cur(stack).emit(Opcode::ForLoop, base as i32, 0, 0);
    cur(stack).patch(loop_pos, top);
    cur(stack).locals_top = base;
    cur(stack).set_free(base);
    finish_loop(stack);
    Ok(())
}

fn compile_generic_for(
    stack: &mut Vec<FuncState>,
    names: &[String],
    exprs: &[Expr],
    body: &ir::Block,
) -> Result<()> {
    let base = cur(stack).locals_top;
    compile_adjusted(stack, exprs, base, 3)?;
    cur(stack).reserve_slot();
    cur(stack).reserve_slot();
    cur(stack).reserve_slot();
    let prep = cur(stack).emit(Opcode::Jmp, 0, 0, 0);
    let top = cur(stack).here();
    cur(stack).loops.push(LoopCtx {
        close_level: base + 3,
        continue_target: usize::MAX,
        continue_jumps: Vec::new(),
        breaks: Vec::new(),
    });
    let scope = enter_scope(stack);
    for name in names {
        cur(stack).declare_local(name);
    }
    compile_block(stack, body)?;
    exit_scope(stack, scope);
    let cont = cur(stack).here();
    patch_continues(stack, cont);
    maybe_close(stack, base + 3);
    cur(stack).patch_here(prep);
    cur(stack).emit(Opcode::TForCall, base as i32, names.len() as i32, 0);
    let loop_pos = cur(stack).emit(Opcode::TForLoop, base as i32, 0, 0);
    cur(stack).patch(loop_pos, top);
    cur(stack).locals_top = base;
    cur(stack).set_free(base);
    finish_loop(stack);
    Ok(())
}

fn patch_continues(stack: &mut [FuncState], target: usize) {
    let fs = cur(stack);
    let jumps = std::mem::take(&mut fs.loops.last_mut().unwrap().continue_jumps);
    for jmp in jumps {
        fs.patch(jmp, target);
    }
}

fn finish_loop(stack: &mut [FuncState]) {
    let ctx = cur(stack).loops.pop().unwrap();
    let exit = cur(stack).here();
    if cur(stack).has_closures {
        cur(stack).emit(Opcode::Close, ctx.close_level as i32, 0, 0);
    }
    let exit_after = cur(stack).here();
    for jmp in ctx.breaks {
        cur(stack).patch(jmp, exit);
    }
    let _ = exit_after;
}

fn compile_nested(
    stack: &mut Vec<FuncState>,
    params: &[ir::Param],
    block: ir::Block,
    hot: Option<ir::HotCat>,
    stable_id: Option<u32>,
) -> Result<usize> {
    let num_params = params
        .iter()
        .filter(|p| matches!(p, ir::Param::Name(_)))
        .count() as u8;
    let is_vararg = params.iter().any(|p| matches!(p, ir::Param::Vararg));
    let has_closures = block_has_closures(&block);
    let mut child = FuncState::new(num_params, is_vararg, has_closures);
    for param in params {
        if let ir::Param::Name(name) = param {
            child.declare_local(name);
        }
    }
    stack.push(child);
    compile_block(stack, &block)?;
    emit_implicit_return(stack);
    let child = stack.pop().unwrap();
    let mut proto = child.finish();
    proto.hot_callback = hot;
    proto.stable_id = stable_id;
    let parent = cur(stack);
    parent.protos.push(proto);
    Ok(parent.protos.len() - 1)
}

fn is_multi(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Call { .. } | Expr::MethodCall { .. } | Expr::Vararg
    )
}

fn compile_expr_push(stack: &mut Vec<FuncState>, expr: &Expr) -> Result<u16> {
    match expr {
        Expr::Nil => {
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::LoadNil, r as i32, 1, 0);
            Ok(r)
        }
        Expr::True => emit_bool(stack, true),
        Expr::False => emit_bool(stack, false),
        Expr::Number(text) => {
            let n = literal::decode_number(text).ok_or_else(|| format!("bad number: {text}"))?;
            let k = cur(stack).konst_num(n);
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::LoadK, r as i32, k, 0);
            Ok(r)
        }
        Expr::Str(text) => {
            let bytes =
                literal::decode_string(text).ok_or_else(|| format!("bad string: {text}"))?;
            let k = cur(stack).konst_str(&bytes);
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::LoadK, r as i32, k, 0);
            Ok(r)
        }
        Expr::Name(name) => match resolve_name(stack, name) {
            NameKind::Local(reg) => {
                let r = cur(stack).alloc();
                cur(stack).emit(Opcode::Move, r as i32, reg as i32, 0);
                Ok(r)
            }
            NameKind::Upval(u) => {
                let r = cur(stack).alloc();
                cur(stack).emit(Opcode::GetUpval, r as i32, u as i32, 0);
                Ok(r)
            }
            NameKind::Global => {
                let r = cur(stack).alloc();

                if let Some(iid) = crate::intrinsic::global_id(name) {
                    cur(stack).emit(Opcode::GetGlobalI, r as i32, iid as i32, 0);
                } else {
                    let k = cur(stack).konst_str(name.as_bytes());
                    cur(stack).emit(Opcode::GetGlobal, r as i32, k, 0);
                }
                Ok(r)
            }
        },
        Expr::Paren(inner) => compile_expr_push(stack, inner),
        Expr::Vararg => {
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::Vararg, r as i32, 2, 0);
            Ok(r)
        }
        Expr::Field { base, name } => {
            let obj = compile_expr_push(stack, base)?;
            let key = cur(stack).alloc();
            let k = cur(stack).konst_str(name.as_bytes());
            cur(stack).emit(Opcode::LoadK, key as i32, k, 0);
            cur(stack).emit(Opcode::GetTable, obj as i32, obj as i32, key as i32);
            cur(stack).set_free(obj + 1);
            Ok(obj)
        }
        Expr::Index { base, key } => {
            let obj = compile_expr_push(stack, base)?;
            let keyr = compile_expr_push(stack, key)?;
            cur(stack).emit(Opcode::GetTable, obj as i32, obj as i32, keyr as i32);
            cur(stack).set_free(obj + 1);
            Ok(obj)
        }
        Expr::Call { .. } | Expr::MethodCall { .. } => compile_callish(stack, expr, NRes::One),
        Expr::Function(body) => {
            let proto = compile_nested(
                stack,
                &body.params,
                body.block.clone(),
                body.hot_callback,
                body.stable_id,
            )?;
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::Closure, r as i32, proto as i32, 0);
            Ok(r)
        }
        Expr::NativeRef(i) => {
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::LoadNative, r as i32, *i as i32, 0);
            Ok(r)
        }
        Expr::Crash => {
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::Crash, r as i32, 0, 0);
            Ok(r)
        }
        Expr::OpcodeHint {
            family,
            intensity,
            key,
        } => {
            emit_opcode_bundle(stack, *family, *intensity, *key)?;
            let r = cur(stack).alloc();
            cur(stack).emit(Opcode::LoadNil, r as i32, 1, 0);
            Ok(r)
        }
        Expr::EncFunc { id, key } => {
            let r = compile_expr_push(stack, key)?;
            cur(stack).emit(Opcode::EncFunc, r as i32, *id as i32, r as i32);
            cur(stack).set_free(r + 1);
            Ok(r)
        }
        Expr::Table(fields) => compile_table(stack, fields),
        Expr::Binop { op, lhs, rhs } => compile_binop(stack, *op, lhs, rhs),
        Expr::Unop { op, expr } => {
            let ro = compile_expr_push(stack, expr)?;
            let opcode = match op {
                UnOp::Neg => Opcode::Neg,
                UnOp::Not => Opcode::Not,
                UnOp::Len => Opcode::Len,
            };
            cur(stack).emit(opcode, ro as i32, ro as i32, 0);
            cur(stack).set_free(ro + 1);
            Ok(ro)
        }
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => compile_if_expr(stack, cond, then, else_ifs, otherwise),
        Expr::Interp(parts) => compile_interp(stack, parts),
    }
}

fn emit_bool(stack: &mut [FuncState], value: bool) -> Result<u16> {
    let fs = cur(stack);
    let r = fs.alloc();
    fs.emit(Opcode::LoadBool, r as i32, value as i32, 0);
    Ok(r)
}

fn compile_expr_to(stack: &mut Vec<FuncState>, expr: &Expr, dst: u16) -> Result<()> {
    let r = compile_expr_push(stack, expr)?;
    if r != dst {
        cur(stack).emit(Opcode::Move, dst as i32, r as i32, 0);
    }
    cur(stack).set_free(dst + 1);
    Ok(())
}

fn compile_binop(stack: &mut Vec<FuncState>, op: BinOp, lhs: &Expr, rhs: &Expr) -> Result<u16> {
    if matches!(op, BinOp::And | BinOp::Or) {
        let dst = compile_expr_push(stack, lhs)?;
        let test = if op == BinOp::And {
            Opcode::JmpIfNot
        } else {
            Opcode::JmpIf
        };
        let skip = cur(stack).emit(test, dst as i32, 0, 0);
        cur(stack).set_free(dst + 1);
        compile_expr_to(stack, rhs, dst)?;
        cur(stack).patch_here(skip);
        cur(stack).set_free(dst + 1);
        return Ok(dst);
    }
    let rl = compile_expr_push(stack, lhs)?;
    let rr = compile_expr_push(stack, rhs)?;
    let opcode = binop_opcode(op);
    cur(stack).emit(opcode, rl as i32, rl as i32, rr as i32);
    cur(stack).set_free(rl + 1);
    Ok(rl)
}

fn compile_if_expr(
    stack: &mut Vec<FuncState>,
    cond: &Expr,
    then: &Expr,
    else_ifs: &[(Expr, Expr)],
    otherwise: &Expr,
) -> Result<u16> {
    let dst = cur(stack).alloc();
    let mut end_jumps = Vec::new();
    let rc = compile_expr_push(stack, cond)?;
    let mut next = cur(stack).emit(Opcode::JmpIfNot, rc as i32, 0, 0);
    cur(stack).set_free(dst + 1);
    compile_expr_to(stack, then, dst)?;
    for (econd, eexpr) in else_ifs {
        end_jumps.push(cur(stack).emit(Opcode::Jmp, 0, 0, 0));
        cur(stack).patch_here(next);
        cur(stack).set_free(dst + 1);
        let rc = compile_expr_push(stack, econd)?;
        next = cur(stack).emit(Opcode::JmpIfNot, rc as i32, 0, 0);
        cur(stack).set_free(dst + 1);
        compile_expr_to(stack, eexpr, dst)?;
    }
    end_jumps.push(cur(stack).emit(Opcode::Jmp, 0, 0, 0));
    cur(stack).patch_here(next);
    cur(stack).set_free(dst + 1);
    compile_expr_to(stack, otherwise, dst)?;
    for jmp in end_jumps {
        cur(stack).patch_here(jmp);
    }
    cur(stack).set_free(dst + 1);
    Ok(dst)
}

fn compile_interp(stack: &mut Vec<FuncState>, parts: &[ir::InterpPart]) -> Result<u16> {
    let mut pieces: Vec<u16> = Vec::new();
    let base = cur(stack).free;
    for part in parts {
        match part {
            ir::InterpPart::Lit(raw) => {
                if raw.is_empty() {
                    continue;
                }
                let bytes = literal::decode_interp_chunk(raw)
                    .ok_or_else(|| format!("bad interpolation chunk: {raw}"))?;
                let k = cur(stack).konst_str(&bytes);
                let r = cur(stack).alloc();
                cur(stack).emit(Opcode::LoadK, r as i32, k, 0);
                pieces.push(r);
            }
            ir::InterpPart::Expr(e) => {
                let func = cur(stack).alloc();
                let k = cur(stack).konst_str(b"tostring");
                cur(stack).emit(Opcode::GetGlobal, func as i32, k, 0);
                compile_expr_to(stack, e, func + 1)?;
                cur(stack).emit(Opcode::Call, func as i32, 2, 2);
                cur(stack).set_free(func + 1);
                pieces.push(func);
            }
        }
    }
    if pieces.is_empty() {
        let k = cur(stack).konst_str(b"");
        let r = cur(stack).alloc();
        cur(stack).emit(Opcode::LoadK, r as i32, k, 0);
        return Ok(r);
    }
    let mut acc = pieces[0];
    for &piece in &pieces[1..] {
        cur(stack).emit(Opcode::Concat, acc as i32, acc as i32, piece as i32);
    }
    cur(stack).set_free(base + 1);
    if acc != base {
        cur(stack).emit(Opcode::Move, base as i32, acc as i32, 0);
        acc = base;
    }
    Ok(acc)
}

fn compile_table(stack: &mut Vec<FuncState>, fields: &[Field]) -> Result<u16> {
    let table = cur(stack).alloc();
    cur(stack).emit(Opcode::NewTable, table as i32, 0, 0);
    let mut array_index = 1u32;
    let mut pending = 0u16;
    let positional: Vec<&Field> = fields
        .iter()
        .filter(|f| matches!(f, Field::Positional(_)))
        .collect();
    let n_positional = positional.len();
    let mut seen_positional = 0;
    for field in fields {
        match field {
            Field::Positional(e) => {
                seen_positional += 1;
                let is_last = seen_positional == n_positional;
                if is_last && is_multi(e) {
                    compile_expr_open(stack, e)?;
                    cur(stack).emit(Opcode::SetList, table as i32, 0, array_index as i32);
                    pending = 0;
                    cur(stack).set_free(table + 1);
                } else {
                    let r = cur(stack).alloc();
                    compile_expr_to(stack, e, r)?;
                    pending += 1;
                    if pending == array_flush_threshold() {
                        cur(stack).emit(
                            Opcode::SetList,
                            table as i32,
                            pending as i32,
                            array_index as i32,
                        );
                        array_index += pending as u32;
                        pending = 0;
                        cur(stack).set_free(table + 1);
                    }
                }
            }
            Field::Named { name, value } => {
                let key = cur(stack).alloc();
                let k = cur(stack).konst_str(name.as_bytes());
                cur(stack).emit(Opcode::LoadK, key as i32, k, 0);
                let val = cur(stack).alloc();
                compile_expr_to(stack, value, val)?;
                cur(stack).emit(Opcode::SetTable, table as i32, key as i32, val as i32);
                cur(stack).set_free(table + 1 + pending);
            }
            Field::Keyed { key, value } => {
                let keyr = cur(stack).alloc();
                compile_expr_to(stack, key, keyr)?;
                let val = cur(stack).alloc();
                compile_expr_to(stack, value, val)?;
                cur(stack).emit(Opcode::SetTable, table as i32, keyr as i32, val as i32);
                cur(stack).set_free(table + 1 + pending);
            }
        }
    }
    if pending > 0 {
        cur(stack).emit(
            Opcode::SetList,
            table as i32,
            pending as i32,
            array_index as i32,
        );
    }
    cur(stack).set_free(table + 1);
    Ok(table)
}

fn array_flush_threshold() -> u16 {
    50
}

fn compile_callish(stack: &mut Vec<FuncState>, expr: &Expr, nres: NRes) -> Result<u16> {
    let base = cur(stack).free;
    let b = match expr {
        Expr::Call { func, args, .. } => {
            compile_expr_to(stack, func, base)?;
            let kind = compile_list(stack, args)?;
            match kind {
                ArgKind::Fixed(n) => n as i32 + 1,
                ArgKind::Variadic => 0,
            }
        }
        Expr::MethodCall {
            base: obj,
            method,
            args,
        } => {
            compile_expr_to(stack, obj, base)?;

            if let Some(iid) = crate::intrinsic::method_id(method) {
                cur(stack).emit(Opcode::SelfI, base as i32, base as i32, iid as i32);
            } else {
                let k = cur(stack).konst_str(method.as_bytes());
                cur(stack).emit(Opcode::Self_, base as i32, base as i32, k);
            }
            cur(stack).set_free(base + 2);
            let kind = compile_list(stack, args)?;
            match kind {
                ArgKind::Fixed(n) => n as i32 + 2,
                ArgKind::Variadic => 0,
            }
        }
        _ => return Err("not a call".into()),
    };
    let c = match nres {
        NRes::None => 1,
        NRes::One => 2,
        NRes::Multi => 0,
        NRes::Exact(n) => n as i32 + 1,
    };
    cur(stack).emit(Opcode::Call, base as i32, b, c);
    match nres {
        NRes::None | NRes::Multi => cur(stack).set_free(base),
        NRes::One => cur(stack).set_free(base + 1),
        NRes::Exact(n) => cur(stack).set_free(base + n),
    }
    Ok(base)
}

fn compile_expr_open(stack: &mut Vec<FuncState>, expr: &Expr) -> Result<()> {
    match expr {
        Expr::Call { .. } | Expr::MethodCall { .. } => {
            compile_callish(stack, expr, NRes::Multi)?;
        }
        Expr::Vararg => {
            let base = cur(stack).free;
            cur(stack).emit(Opcode::Vararg, base as i32, 0, 0);
        }
        _ => return Err("expected multi-value expression".into()),
    }
    Ok(())
}

fn compile_list(stack: &mut Vec<FuncState>, exprs: &[Expr]) -> Result<ArgKind> {
    if exprs.is_empty() {
        return Ok(ArgKind::Fixed(0));
    }
    for e in &exprs[..exprs.len() - 1] {
        compile_expr_push(stack, e)?;
    }
    let last = &exprs[exprs.len() - 1];
    if is_multi(last) {
        compile_expr_open(stack, last)?;
        Ok(ArgKind::Variadic)
    } else {
        compile_expr_push(stack, last)?;
        Ok(ArgKind::Fixed(exprs.len()))
    }
}

fn compile_adjusted(
    stack: &mut Vec<FuncState>,
    exprs: &[Expr],
    base: u16,
    want: u16,
) -> Result<()> {
    cur(stack).set_free(base);
    if exprs.is_empty() {
        if want > 0 {
            cur(stack).emit(Opcode::LoadNil, base as i32, want as i32, 0);
        }
        cur(stack).set_free(base + want);
        return Ok(());
    }
    let fixed = exprs.len() - 1;
    for e in &exprs[..fixed] {
        compile_expr_push(stack, e)?;
    }
    let last = &exprs[fixed];
    let have = fixed as u16;
    if is_multi(last) {
        if have >= want {
            compile_callish_or_single(stack, last, NRes::None)?;
        } else {
            let need = want - have;
            compile_callish_or_single(stack, last, NRes::Exact(need))?;
        }
    } else {
        compile_expr_push(stack, last)?;
        let have = have + 1;
        if have < want {
            cur(stack).emit(
                Opcode::LoadNil,
                (base + have) as i32,
                (want - have) as i32,
                0,
            );
        }
    }
    cur(stack).set_free(base + want);
    Ok(())
}

fn compile_callish_or_single(stack: &mut Vec<FuncState>, expr: &Expr, nres: NRes) -> Result<()> {
    match expr {
        Expr::Call { .. } | Expr::MethodCall { .. } => {
            compile_callish(stack, expr, nres)?;
        }
        Expr::Vararg => {
            let base = cur(stack).free;
            let b = match nres {
                NRes::Exact(n) => n as i32 + 1,
                _ => 1,
            };
            cur(stack).emit(Opcode::Vararg, base as i32, b, 0);
        }
        _ => return Err("expected multi-value expression".into()),
    }
    Ok(())
}

fn resolve_name(stack: &mut Vec<FuncState>, name: &str) -> NameKind {
    let top = stack.len() - 1;
    if let Some(reg) = stack[top].find_local(name) {
        return NameKind::Local(reg);
    }
    if let Some(uv) = resolve_upval(stack, top, name) {
        return NameKind::Upval(uv);
    }
    NameKind::Global
}

fn resolve_upval(stack: &mut Vec<FuncState>, fi: usize, name: &str) -> Option<u16> {
    if let Some(idx) = stack[fi].find_upval(name) {
        return Some(idx);
    }
    if fi == 0 {
        return None;
    }
    let parent = fi - 1;
    if let Some(reg) = stack[parent].find_local(name) {
        stack[parent].mark_captured(reg);
        return Some(stack[fi].add_upval(
            name,
            UpvalDesc {
                in_stack: true,
                index: reg,
            },
        ));
    }
    let pidx = resolve_upval(stack, parent, name)?;
    Some(stack[fi].add_upval(
        name,
        UpvalDesc {
            in_stack: false,
            index: pidx,
        },
    ))
}

fn binop_opcode(op: BinOp) -> Opcode {
    match op {
        BinOp::Add => Opcode::Add,
        BinOp::Sub => Opcode::Sub,
        BinOp::Mul => Opcode::Mul,
        BinOp::Div => Opcode::Div,
        BinOp::FloorDiv => Opcode::IDiv,
        BinOp::Mod => Opcode::Mod,
        BinOp::Pow => Opcode::Pow,
        BinOp::Concat => Opcode::Concat,
        BinOp::Eq => Opcode::Eq,
        BinOp::Ne => Opcode::Ne,
        BinOp::Lt => Opcode::Lt,
        BinOp::Le => Opcode::Le,
        BinOp::Gt => Opcode::Gt,
        BinOp::Ge => Opcode::Ge,
        BinOp::And | BinOp::Or => unreachable!("handled separately"),
    }
}

fn compound_opcode(op: CompoundOp) -> Opcode {
    match op {
        CompoundOp::Add => Opcode::Add,
        CompoundOp::Sub => Opcode::Sub,
        CompoundOp::Mul => Opcode::Mul,
        CompoundOp::Div => Opcode::Div,
        CompoundOp::FloorDiv => Opcode::IDiv,
        CompoundOp::Mod => Opcode::Mod,
        CompoundOp::Pow => Opcode::Pow,
        CompoundOp::Concat => Opcode::Concat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk<'a>(p: &'a Proto, out: &mut Vec<&'a Proto>) {
        out.push(p);
        for c in &p.protos {
            walk(c, out);
        }
    }

    #[test]
    fn self_receiver_register_stays_inside_max_stack() {
        let src = "local function run(list)\n                   \tfor _, item in ipairs(list) do\n                   \t\tlocal cur = item\n                   \t\tcur:mark()\n                   \tend\n                   end\n                   return run\n";
        let m = frontend::lower_str(src).unwrap();
        let main = compile(&m).unwrap();
        let mut all = Vec::new();
        walk(&main, &mut all);
        let mut seen = false;
        for p in all {
            for inst in &p.code {
                if matches!(inst.op, Opcode::Self_ | Opcode::SelfI) {
                    seen = true;
                    assert!(
                        (inst.a as u16) + 2 <= p.max_stack,
                        "SELF at a={} writes R[{}] (the receiver) but max_stack is {}",
                        inst.a,
                        inst.a + 1,
                        p.max_stack
                    );
                }
            }
        }
        assert!(seen, "fixture must compile a method call to SELF/SELFI");
    }

    #[test]
    fn every_written_register_stays_inside_max_stack() {
        let src = "local function run(list, sink)\n                   \tfor _, item in ipairs(list) do\n                   \t\tlocal cur = item\n                   \t\tcur:mark()\n                   \tend\n                   \tlocal a, b = sink()\n                   \treturn a, b\n                   end\n                   return run\n";
        let m = frontend::lower_str(src).unwrap();
        let main = compile(&m).unwrap();
        let mut all = Vec::new();
        walk(&main, &mut all);
        for p in all {
            for inst in &p.code {
                let dst = match inst.op {
                    Opcode::Self_ | Opcode::SelfI => inst.a + 1,
                    Opcode::LoadNil => inst.a + inst.b - 1,
                    _ if crate::opcode::patch_role(inst.op, 0)
                        == crate::opcode::OperandRole::DstReg =>
                    {
                        inst.a
                    }
                    _ => continue,
                };
                assert!(
                    dst < p.max_stack as i32,
                    "{:?} writes R[{}] outside max_stack {}",
                    inst.op,
                    dst,
                    p.max_stack
                );
            }
        }
    }

    fn has_op(p: &Proto, op: Opcode) -> bool {
        p.code.iter().any(|i| i.op == op)
    }
    fn has_str_const(p: &Proto, s: &[u8]) -> bool {
        p.consts
            .iter()
            .any(|c| matches!(c, Const::Str(b) if b.as_slice() == s))
    }

    #[test]
    fn c3_intrinsic_names_lower_to_opcodes_and_leave_the_constant_pool() {
        let src = "local s = game:GetService(\"PlayersSvc\")\n\
                   local i = Instance.new(\"Thing\")\n\
                   local t = typeof(i)\n\
                   return s, i, t\n";
        let m = frontend::lower_str(src).unwrap();
        let p = compile(&m).unwrap();
        assert!(has_op(&p, Opcode::SelfI), "intrinsic method -> SELFI");
        assert!(
            has_op(&p, Opcode::GetGlobalI),
            "intrinsic global -> GETGLOBALI"
        );
        for name in [b"GetService".as_slice(), b"game", b"Instance", b"typeof"] {
            assert!(
                !has_str_const(&p, name),
                "intrinsic name {:?} must leave the constant pool",
                String::from_utf8_lossy(name)
            );
        }
        assert!(
            has_str_const(&p, b"PlayersSvc"),
            "string arg stays a normal constant at compile time"
        );
    }

    #[test]
    fn c3_non_intrinsic_method_and_global_keep_normal_lowering() {
        let src = "local x = obj:customThing(1)\nreturn print, x\n";
        let m = frontend::lower_str(src).unwrap();
        let p = compile(&m).unwrap();
        assert!(has_op(&p, Opcode::Self_), "non-intrinsic method stays SELF");
        assert!(
            !has_op(&p, Opcode::SelfI),
            "no intrinsic lowering for a user method"
        );
        assert!(
            has_op(&p, Opcode::GetGlobal),
            "non-intrinsic global (print/obj) stays GETGLOBAL"
        );
        assert!(
            has_str_const(&p, b"customThing"),
            "user method name stays a constant"
        );
    }
}
