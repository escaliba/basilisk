use std::collections::{HashMap, HashSet};

use ir::{Block, Expr, Field, FuncBody, InterpPart, LastStmt, Module, Param, Stmt};

pub fn strip_source_names(module: &mut Module, seed: u64) {
    let (starts, conts) = shuffled_alphabets(seed);
    let mut scope = ScopeStack::new();
    let mut gen = NameGen::new(&starts, &conts, forbidden(collect_block(&module.block)));
    rename_block(&mut module.block, &mut scope, &mut gen);
    for native in &mut module.natives {
        let mut ns = ScopeStack::new();
        let mut ng = NameGen::new(&starts, &conts, forbidden(collect_func(native)));
        rename_func(native, &mut ns, &mut ng);
    }
}

const RESERVED: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then", "true", "until", "while", "continue",
];

fn forbidden(mut used: HashSet<String>) -> HashSet<String> {
    used.extend(RESERVED.iter().map(|s| s.to_string()));
    used
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn shuffled_alphabets(seed: u64) -> (Vec<u8>, Vec<u8>) {
    let mut rng = seed ^ 0x5DEE_CE66_D000_0001;
    let mut starts: Vec<u8> = (b'a'..=b'z').chain(b'A'..=b'Z').collect();
    let mut conts: Vec<u8> = starts.iter().copied().chain(b'0'..=b'9').collect();
    shuffle(&mut starts, &mut rng);
    shuffle(&mut conts, &mut rng);
    (starts, conts)
}

fn shuffle(v: &mut [u8], rng: &mut u64) {
    for i in (1..v.len()).rev() {
        let j = (splitmix64(rng) % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

struct NameGen {
    starts: Vec<u8>,
    conts: Vec<u8>,
    forbidden: HashSet<String>,
    counter: u64,
}

impl NameGen {
    fn new(starts: &[u8], conts: &[u8], forbidden: HashSet<String>) -> Self {
        NameGen {
            starts: starts.to_vec(),
            conts: conts.to_vec(),
            forbidden,
            counter: 0,
        }
    }

    fn next(&mut self) -> String {
        loop {
            let name = self.encode(self.counter);
            self.counter += 1;
            if !self.forbidden.contains(&name) {
                return name;
            }
        }
    }

    fn encode(&self, mut n: u64) -> String {
        let s = self.starts.len() as u64;
        let c = self.conts.len() as u64;
        let mut len = 1u32;
        let mut block = s;
        while n >= block {
            n -= block;
            len += 1;
            block = block.saturating_mul(c);
        }
        let pow = c.pow(len - 1);
        let mut bytes = vec![self.starts[(n / pow) as usize]];
        let mut rest = n % pow;
        for i in (0..len - 1).rev() {
            let d = c.pow(i);
            bytes.push(self.conts[(rest / d) as usize]);
            rest %= d;
        }
        String::from_utf8(bytes).unwrap()
    }
}

fn collect_block(block: &Block) -> HashSet<String> {
    let mut set = HashSet::new();
    scan_block(block, &mut set);
    set
}

fn collect_func(fb: &FuncBody) -> HashSet<String> {
    let mut set = HashSet::new();
    scan_block(&fb.block, &mut set);
    set
}

fn scan_block(block: &Block, set: &mut HashSet<String>) {
    for stmt in &block.stmts {
        scan_stmt(stmt, set);
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            scan_expr(e, set);
        }
    }
}

fn scan_stmt(stmt: &Stmt, set: &mut HashSet<String>) {
    match stmt {
        Stmt::Local { exprs, .. } => exprs.iter().for_each(|e| scan_expr(e, set)),
        Stmt::Assign { targets, exprs } => {
            targets.iter().chain(exprs).for_each(|e| scan_expr(e, set))
        }
        Stmt::Compound { target, value, .. } => {
            scan_expr(target, set);
            scan_expr(value, set);
        }
        Stmt::Call(e) => scan_expr(e, set),
        Stmt::Do(b) => scan_block(b, set),
        Stmt::While { cond, body } => {
            scan_expr(cond, set);
            scan_block(body, set);
        }
        Stmt::Repeat { body, until } => {
            scan_block(body, set);
            scan_expr(until, set);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            scan_expr(start, set);
            scan_expr(end, set);
            if let Some(s) = step {
                scan_expr(s, set);
            }
            scan_block(body, set);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter().for_each(|e| scan_expr(e, set));
            scan_block(body, set);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            scan_expr(cond, set);
            scan_block(body, set);
            for (c, b) in else_ifs {
                scan_expr(c, set);
                scan_block(b, set);
            }
            if let Some(b) = otherwise {
                scan_block(b, set);
            }
        }
        Stmt::Function { name, body } => {
            if let Some(first) = name.path.first() {
                set.insert(first.clone());
            }
            scan_block(&body.block, set);
        }
        Stmt::LocalFunction { body, .. } => scan_block(&body.block, set),
    }
}

fn scan_expr(expr: &Expr, set: &mut HashSet<String>) {
    match expr {
        Expr::Name(n) => {
            set.insert(n.clone());
        }
        Expr::Function(body) => scan_block(&body.block, set),
        other => other.each_child(&mut |c| scan_expr(c, set)),
    }
}

struct ScopeStack {
    frames: Vec<HashMap<String, String>>,
}

impl ScopeStack {
    fn new() -> Self {
        ScopeStack { frames: Vec::new() }
    }

    fn push(&mut self) {
        self.frames.push(HashMap::new());
    }

    fn pop(&mut self) {
        self.frames.pop();
    }

    fn declare(&mut self, old: &str, gen: &mut NameGen) -> String {
        let new = gen.next();
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(old.to_string(), new.clone());
        }
        new
    }

    fn lookup(&self, name: &str) -> Option<String> {
        for frame in self.frames.iter().rev() {
            if let Some(new) = frame.get(name) {
                return Some(new.clone());
            }
        }
        None
    }
}

fn rename_block(block: &mut Block, scope: &mut ScopeStack, gen: &mut NameGen) {
    scope.push();
    rename_block_in_current(block, scope, gen);
    scope.pop();
}

fn rename_block_in_current(block: &mut Block, scope: &mut ScopeStack, gen: &mut NameGen) {
    for stmt in block.stmts.iter_mut() {
        rename_stmt(stmt, scope, gen);
    }
    if let Some(last) = block.last.as_mut() {
        rename_last(last, scope, gen);
    }
}

fn rename_func(fb: &mut FuncBody, scope: &mut ScopeStack, gen: &mut NameGen) {
    scope.push();
    for param in fb.params.iter_mut() {
        if let Param::Name(name) = param {
            *name = scope.declare(name, gen);
        }
    }
    rename_block_in_current(&mut fb.block, scope, gen);
    scope.pop();
}

fn rename_stmt(stmt: &mut Stmt, scope: &mut ScopeStack, gen: &mut NameGen) {
    match stmt {
        Stmt::Local { names, exprs } => {
            for e in exprs.iter_mut() {
                rename_expr(e, scope, gen);
            }
            for name in names.iter_mut() {
                *name = scope.declare(name, gen);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for t in targets.iter_mut() {
                rename_expr(t, scope, gen);
            }
            for e in exprs.iter_mut() {
                rename_expr(e, scope, gen);
            }
        }
        Stmt::Compound { target, value, .. } => {
            rename_expr(target, scope, gen);
            rename_expr(value, scope, gen);
        }
        Stmt::Call(e) => rename_expr(e, scope, gen),
        Stmt::Do(block) => rename_block(block, scope, gen),
        Stmt::While { cond, body } => {
            rename_expr(cond, scope, gen);
            rename_block(body, scope, gen);
        }
        Stmt::Repeat { body, until } => {
            scope.push();
            rename_block_in_current(body, scope, gen);
            rename_expr(until, scope, gen);
            scope.pop();
        }
        Stmt::NumericFor {
            var,
            start,
            end,
            step,
            body,
        } => {
            rename_expr(start, scope, gen);
            rename_expr(end, scope, gen);
            if let Some(step) = step {
                rename_expr(step, scope, gen);
            }
            scope.push();
            *var = scope.declare(var, gen);
            rename_block_in_current(body, scope, gen);
            scope.pop();
        }
        Stmt::GenericFor { names, exprs, body } => {
            for e in exprs.iter_mut() {
                rename_expr(e, scope, gen);
            }
            scope.push();
            for name in names.iter_mut() {
                *name = scope.declare(name, gen);
            }
            rename_block_in_current(body, scope, gen);
            scope.pop();
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            rename_expr(cond, scope, gen);
            rename_block(body, scope, gen);
            for (econd, eblock) in else_ifs.iter_mut() {
                rename_expr(econd, scope, gen);
                rename_block(eblock, scope, gen);
            }
            if let Some(otherwise) = otherwise {
                rename_block(otherwise, scope, gen);
            }
        }
        Stmt::Function { name, body } => {
            if let Some(first) = name.path.first_mut() {
                if let Some(new) = scope.lookup(first) {
                    *first = new;
                }
            }
            rename_func(body, scope, gen);
        }
        Stmt::LocalFunction { name, body } => {
            *name = scope.declare(name, gen);
            rename_func(body, scope, gen);
        }
    }
}

fn rename_last(last: &mut LastStmt, scope: &mut ScopeStack, gen: &mut NameGen) {
    if let LastStmt::Return(exprs) = last {
        for e in exprs.iter_mut() {
            rename_expr(e, scope, gen);
        }
    }
}

fn rename_expr(expr: &mut Expr, scope: &mut ScopeStack, gen: &mut NameGen) {
    match expr {
        Expr::Name(name) => {
            if let Some(new) = scope.lookup(name) {
                *name = new;
            }
        }
        Expr::Field { base, .. } => rename_expr(base, scope, gen),
        Expr::Index { base, key } => {
            rename_expr(base, scope, gen);
            rename_expr(key, scope, gen);
        }
        Expr::Call { func, args, .. } => {
            rename_expr(func, scope, gen);
            for a in args.iter_mut() {
                rename_expr(a, scope, gen);
            }
        }
        Expr::MethodCall { base, args, .. } => {
            rename_expr(base, scope, gen);
            for a in args.iter_mut() {
                rename_expr(a, scope, gen);
            }
        }
        Expr::Function(body) => rename_func(body, scope, gen),
        Expr::Table(fields) => {
            for field in fields.iter_mut() {
                match field {
                    Field::Positional(e) => rename_expr(e, scope, gen),
                    Field::Named { value, .. } => rename_expr(value, scope, gen),
                    Field::Keyed { key, value } => {
                        rename_expr(key, scope, gen);
                        rename_expr(value, scope, gen);
                    }
                }
            }
        }
        Expr::Binop { lhs, rhs, .. } => {
            rename_expr(lhs, scope, gen);
            rename_expr(rhs, scope, gen);
        }
        Expr::Unop { expr, .. } => rename_expr(expr, scope, gen),
        Expr::Paren(inner) => rename_expr(inner, scope, gen),
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            rename_expr(cond, scope, gen);
            rename_expr(then, scope, gen);
            for (econd, eexpr) in else_ifs.iter_mut() {
                rename_expr(econd, scope, gen);
                rename_expr(eexpr, scope, gen);
            }
            rename_expr(otherwise, scope, gen);
        }
        Expr::Interp(parts) => {
            for part in parts.iter_mut() {
                if let InterpPart::Expr(e) = part {
                    rename_expr(e, scope, gen);
                }
            }
        }
        Expr::EncFunc { key, .. } => rename_expr(key, scope, gen),
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

    fn sanitized_source(src: &str, seed: u64) -> String {
        let mut module = crate::lower_str(src).unwrap();
        strip_source_names(&mut module, seed);
        ir::emit(&module)
    }

    const SENSITIVE: &str = "\
local secretName = 41
local function helperFunc(paramValue)
    local temporary = paramValue + secretName
    return temporary
end
local box = { fieldKey = helperFunc(1) }
function box.method(selfish) return selfish end
print(box.fieldKey, math.floor(2.5), box:method())
";

    #[test]
    fn strips_local_param_function_names_but_keeps_globals_fields_methods() {
        let out = sanitized_source(SENSITIVE, 0x1234);
        for gone in [
            "secretName",
            "helperFunc",
            "paramValue",
            "temporary",
            "selfish",
        ] {
            assert!(
                !out.contains(gone),
                "source identifier {gone} must be stripped, got:\n{out}"
            );
        }
        for kept in ["print", "math", "floor", "fieldKey", "method"] {
            assert!(
                out.contains(kept),
                "runtime-visible name {kept} must survive"
            );
        }
        assert!(
            crate::lower_str(&out).is_ok(),
            "sanitized output must still parse"
        );
    }

    #[test]
    fn deterministic_for_fixed_seed() {
        assert_eq!(
            sanitized_source(SENSITIVE, 0xABCD),
            sanitized_source(SENSITIVE, 0xABCD)
        );
    }

    #[test]
    fn different_seed_changes_generated_names() {
        assert_ne!(
            sanitized_source(SENSITIVE, 0x1111),
            sanitized_source(SENSITIVE, 0x2222)
        );
    }

    #[test]
    fn shadowing_and_upvalues_stay_consistent() {
        let src = "\
local shared = 1
local function outer()
    local shared = shared + 1
    return function() return shared end
end
print(outer()(), shared)
";
        let out = sanitized_source(src, 7);
        assert!(
            !out.contains("shared"),
            "shadowed local must be gone:\n{out}"
        );
        assert!(!out.contains("outer"));
        assert!(crate::lower_str(&out).is_ok());
    }
}
