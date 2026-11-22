use std::collections::{BTreeMap, BTreeSet, HashSet};

use bytecode::sha256;
use ir::{Block, Expr, Field, FuncBody, LastStmt, Module, Stmt};

use crate::Error;

pub const MACRO: &str = "BASIL_TBL_SCRAMBLE";

const DOMAIN: &[u8] = b"basil-table-key-v1";
const KEY_LOW: u64 = 0x0010_0000;
const KEY_HIGH: u64 = 0x7FFF_0000;

const SAFE_TABLE_FNS: &[&str] = &[
    "clone", "freeze", "isfrozen", "clear", "find", "sort", "move", "unpack",
];

const KEY_EXPOSING: &[(&str, &str)] = &[
    ("pairs", "iterating it with `pairs` would yield the opaque integer key instead of the field name"),
    ("next", "`next` would yield the opaque integer key instead of the field name"),
    ("rawget", "`rawget` with a literal name bypasses the key mapping and would read a field that no longer exists"),
    ("rawset", "`rawset` with a literal name bypasses the key mapping and would add a second, unmapped entry"),
    ("setmetatable", "a metatable resolves `__index`/`__newindex` by the original field name, which no longer exists"),
    ("getmetatable", "metatable access is not supported for a scrambled table"),
];

fn macro_call_arg(e: &Expr) -> Option<&Expr> {
    match e {
        Expr::Call { func, args, .. } if matches!(&**func, Expr::Name(n) if n == MACRO) => {
            args.first()
        }
        _ => None,
    }
}

fn is_macro_call(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, .. } if matches!(&**func, Expr::Name(n) if n == MACRO))
}

fn err(msg: String) -> Error {
    Error::Macro(msg)
}

fn unquote(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        let inner = &raw[1..raw.len() - 1];
        if inner.contains('\\') {
            return None;
        }
        return Some(inner.to_string());
    }
    None
}

fn num_expr(k: u64) -> Expr {
    Expr::Number(k.to_string())
}

fn derive(seed: u64, table_id: u32, name: &str, bump: u32) -> u64 {
    let mut input = Vec::with_capacity(DOMAIN.len() + name.len() + 24);
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&seed.to_le_bytes());
    input.extend_from_slice(&table_id.to_le_bytes());
    input.extend_from_slice(&bump.to_le_bytes());
    input.extend_from_slice(&(name.len() as u32).to_le_bytes());
    input.extend_from_slice(name.as_bytes());
    let d = sha256::digest(&input);
    let raw = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
    KEY_LOW + raw % (KEY_HIGH - KEY_LOW)
}

fn build_map(seed: u64, table_id: u32, names: &BTreeSet<String>) -> BTreeMap<String, u64> {
    let mut used: HashSet<u64> = HashSet::new();
    let mut map = BTreeMap::new();
    for name in names {
        let mut bump = 0u32;
        let mut k = derive(seed, table_id, name, bump);
        while !used.insert(k) {
            bump += 1;
            k = derive(seed, table_id, name, bump);
        }
        map.insert(name.clone(), k);
    }
    map
}

struct Ctx {
    var: String,
    aliases: HashSet<String>,
    keys: BTreeMap<String, u64>,
}

impl Ctx {
    fn is_alias(&self, e: &Expr) -> bool {
        matches!(e, Expr::Name(n) if self.aliases.contains(n))
    }

    fn key_of(&self, name: &str) -> Result<u64, Error> {
        self.keys.get(name).copied().ok_or_else(|| {
            err(format!(
                "{MACRO} table `{}`: field `{name}` was not seen as a static key",
                self.var
            ))
        })
    }

    fn escape(&self, what: &str) -> Error {
        err(format!(
            "{MACRO} table `{}` cannot {what}; opaque key rewriting would not be visible there",
            self.var
        ))
    }
}

#[derive(Default, Debug, Clone)]
pub struct PropKeyStats {
    pub domains: usize,
    pub renamed_domains: usize,
    pub candidate_keys: usize,
    pub renamed_keys: usize,
    pub skipped_escape: usize,
    pub skipped_dynamic: usize,
    pub skipped_reflective: usize,
    pub skipped_external: usize,
    pub skipped_other: usize,
}

impl PropKeyStats {
    fn classify(&mut self, e: &Error) {
        let m = e.to_string();
        let has = |ss: &[&str]| ss.iter().any(|s| m.contains(s));
        if has(&["pairs", "next", "rawget", "rawset", "metatable", "colon"]) {
            self.skipped_reflective += 1;
        } else if has(&["computed", "dynamic key", "escape sequences"]) {
            self.skipped_dynamic += 1;
        } else if has(&["unknown call"]) {
            self.skipped_external += 1;
        } else if has(&["be returned", "bare value"]) {
            self.skipped_escape += 1;
        } else {
            self.skipped_other += 1;
        }
    }
}

fn record_candidate(stmt: &Stmt) -> Option<(String, usize)> {
    let Stmt::Local { names, exprs } = stmt else {
        return None;
    };
    if names.len() != 1 || exprs.len() != 1 {
        return None;
    }
    let Expr::Table(fields) = &exprs[0] else {
        return None;
    };
    let mut named = 0usize;
    for f in fields {
        match f {
            Field::Named { name, .. } => {
                if name.starts_with("__") {
                    return None;
                }
                named += 1;
            }
            Field::Keyed { key, .. } => match key {
                Expr::Str(raw) => match unquote(raw) {
                    Some(s) if !s.starts_with("__") => named += 1,
                    _ => return None,
                },
                _ => return None,
            },
            Field::Positional(_) => return None,
        }
    }
    (named >= 1).then(|| (names[0].clone(), named))
}

pub fn rename_internal(module: &mut Module, seed: u64) -> PropKeyStats {
    let mut stats = PropKeyStats::default();
    let mut id = 0u32;
    auto_block(&mut module.block, seed, &mut id, &mut stats);
    stats
}

fn auto_block(block: &mut Block, seed: u64, id: &mut u32, stats: &mut PropKeyStats) {
    let cands: Vec<(String, usize, usize)> = block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(i, s)| record_candidate(s).map(|(v, n)| (v, i, n)))
        .collect();
    for (var, idx, nkeys) in cands {
        stats.domains += 1;
        stats.candidate_keys += nkeys;
        let table_id = *id;
        *id += 1;
        let mut trial = block.clone();
        if let Stmt::Local { exprs, .. } = &mut trial.stmts[idx] {
            let tbl = std::mem::replace(&mut exprs[0], Expr::Nil);
            exprs[0] = Expr::Call {
                func: Box::new(Expr::Name(MACRO.to_string())),
                args: vec![tbl],
                site: None,
            };
        }
        match one_table(&mut trial, &var, idx, seed, table_id) {
            Ok(()) => {
                *block = trial;
                stats.renamed_domains += 1;
                stats.renamed_keys += nkeys;
            }
            Err(e) => stats.classify(&e),
        }
    }
    for stmt in &mut block.stmts {
        each_sub_block_mut(stmt, &mut |b| auto_block(b, seed, id, stats));
        each_sub_body_mut(stmt, &mut |fb| auto_block(&mut fb.block, seed, id, stats));
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs {
            each_body_in_expr_mut(e, &mut |fb| auto_block(&mut fb.block, seed, id, stats));
        }
    }
}

fn one_table(
    block: &mut Block,
    var: &str,
    idx: usize,
    seed: u64,
    table_id: u32,
) -> Result<(), Error> {
    let mut aliases: HashSet<String> = HashSet::new();
    aliases.insert(var.to_string());
    loop {
        let mut added = false;
        let mut found: Vec<String> = Vec::new();
        collect_aliases_block(block, &aliases, &mut found);
        for n in found {
            if aliases.insert(n) {
                added = true;
            }
        }
        if !added {
            break;
        }
    }

    let mut declared: BTreeMap<String, u32> = BTreeMap::new();
    count_decls_block(block, &mut declared);
    for a in &aliases {
        if declared.get(a).copied().unwrap_or(0) > 1 {
            return Err(err(format!(
                "{MACRO} table `{var}`: `{a}` is declared more than once in this scope; \
                 shadowing makes the binding impossible to track"
            )));
        }
    }

    let mut names: BTreeSet<String> = BTreeSet::new();
    if let Stmt::Local { exprs, .. } = &block.stmts[idx] {
        if let Some(Expr::Table(fields)) = macro_call_arg(&exprs[0]) {
            for f in fields {
                match f {
                    Field::Named { name, .. } => {
                        names.insert(name.clone());
                    }
                    Field::Keyed { key, .. } => {
                        if let Expr::Str(raw) = key {
                            match unquote(raw) {
                                Some(s) => {
                                    names.insert(s);
                                }
                                None => {
                                    return Err(err(format!(
                                        "{MACRO} table `{var}`: key {raw} uses escape sequences; \
                                         only plain literal string keys are supported"
                                    )))
                                }
                            }
                        } else if !matches!(key, Expr::Number(_)) {
                            return Err(err(format!(
                                "{MACRO} table `{var}`: computed constructor key; \
                                 every key must be a literal name or string"
                            )));
                        }
                    }
                    Field::Positional(_) => {}
                }
            }
        }
    }
    let mut scan = Ctx {
        var: var.to_string(),
        aliases: aliases.clone(),
        keys: BTreeMap::new(),
    };
    collect_keys_block(block, &scan, &mut names)?;
    scan.keys = build_map(seed, table_id, &names);

    rewrite_block(block, &scan)?;

    if let Stmt::Local { exprs, .. } = &mut block.stmts[idx] {
        let inner = match &mut exprs[0] {
            Expr::Call { args, .. } => std::mem::replace(&mut args[0], Expr::Nil),
            _ => unreachable!(),
        };
        let fields = match inner {
            Expr::Table(f) => f,
            _ => unreachable!(),
        };
        let mut out: Vec<Field> = Vec::with_capacity(fields.len());
        let mut seen: HashSet<u64> = HashSet::new();
        for f in fields {
            match f {
                Field::Named { name, value } => {
                    let k = scan.key_of(&name)?;
                    if !seen.insert(k) {
                        return Err(err(format!(
                            "{MACRO} table `{var}`: duplicate constructor key `{name}`"
                        )));
                    }
                    out.push(Field::Keyed {
                        key: num_expr(k),
                        value,
                    });
                }
                Field::Keyed { key, value } => match &key {
                    Expr::Str(raw) => {
                        let name = unquote(raw).expect("validated above");
                        let k = scan.key_of(&name)?;
                        if !seen.insert(k) {
                            return Err(err(format!(
                                "{MACRO} table `{var}`: duplicate constructor key `{name}`"
                            )));
                        }
                        out.push(Field::Keyed {
                            key: num_expr(k),
                            value,
                        });
                    }
                    _ => out.push(Field::Keyed { key, value }),
                },
                Field::Positional(v) => out.push(Field::Positional(v)),
            }
        }
        exprs[0] = Expr::Table(out);
    }
    Ok(())
}

fn collect_aliases_block(block: &Block, known: &HashSet<String>, out: &mut Vec<String>) {
    for stmt in &block.stmts {
        if let Stmt::Local { names, exprs } = stmt {
            if names.len() == 1 && exprs.len() == 1 && alias_source(&exprs[0], known) {
                out.push(names[0].clone());
            }
        }
        each_sub_block(stmt, &mut |b| collect_aliases_block(b, known, out));
        each_sub_body(stmt, &mut |fb| collect_aliases_block(&fb.block, known, out));
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            each_body_in_expr(e, &mut |fb| collect_aliases_block(&fb.block, known, out));
        }
    }
}

fn alias_source(e: &Expr, known: &HashSet<String>) -> bool {
    match e {
        Expr::Name(n) => known.contains(n),
        Expr::Call { func, args, .. } => {
            args.len() == 1
                && matches!(&args[0], Expr::Name(n) if known.contains(n))
                && matches!(&**func, Expr::Field { base, name }
                    if name == "clone" && matches!(&**base, Expr::Name(t) if t == "table"))
        }
        _ => false,
    }
}

fn count_decls_block(block: &Block, out: &mut BTreeMap<String, u32>) {
    let bump = |n: &String, out: &mut BTreeMap<String, u32>| {
        *out.entry(n.clone()).or_insert(0) += 1;
    };
    for stmt in &block.stmts {
        match stmt {
            Stmt::Local { names, .. } => {
                for n in names {
                    bump(n, out);
                }
            }
            Stmt::LocalFunction { name, .. } => bump(name, out),
            Stmt::NumericFor { var, .. } => bump(var, out),
            Stmt::GenericFor { names, .. } => {
                for n in names {
                    bump(n, out);
                }
            }
            _ => {}
        }
        each_sub_block(stmt, &mut |b| count_decls_block(b, out));
        each_sub_body(stmt, &mut |fb| {
            for p in &fb.params {
                if let ir::Param::Name(n) = p {
                    *out.entry(n.clone()).or_insert(0) += 1;
                }
            }
            count_decls_block(&fb.block, out);
        });
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            each_body_in_expr(e, &mut |fb| {
                for p in &fb.params {
                    if let ir::Param::Name(n) = p {
                        *out.entry(n.clone()).or_insert(0) += 1;
                    }
                }
                count_decls_block(&fb.block, out);
            });
        }
    }
}

fn each_sub_block(stmt: &Stmt, f: &mut impl FnMut(&Block)) {
    match stmt {
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

fn each_sub_body(stmt: &Stmt, f: &mut impl FnMut(&FuncBody)) {
    match stmt {
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => f(body),
        Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => {
            for e in exprs {
                each_body_in_expr(e, f);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter().chain(exprs.iter()) {
                each_body_in_expr(e, f);
            }
        }
        Stmt::Compound { target, value, .. } => {
            each_body_in_expr(target, f);
            each_body_in_expr(value, f);
        }
        Stmt::Call(e) => each_body_in_expr(e, f),
        _ => {}
    }
}

fn each_body_in_expr(e: &Expr, f: &mut impl FnMut(&FuncBody)) {
    if let Expr::Function(fb) = e {
        f(fb);
    }
    e.each_child(&mut |c| each_body_in_expr(c, f));
}

fn collect_keys_block(block: &Block, ctx: &Ctx, out: &mut BTreeSet<String>) -> Result<(), Error> {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => {
                for e in exprs {
                    collect_keys_expr(e, ctx, out)?;
                }
            }
            Stmt::Assign { targets, exprs } => {
                for e in targets.iter().chain(exprs.iter()) {
                    collect_keys_expr(e, ctx, out)?;
                }
            }
            Stmt::Compound { target, value, .. } => {
                collect_keys_expr(target, ctx, out)?;
                collect_keys_expr(value, ctx, out)?;
            }
            Stmt::Call(e) => collect_keys_expr(e, ctx, out)?,
            Stmt::While { cond, .. } => collect_keys_expr(cond, ctx, out)?,
            Stmt::Repeat { until, .. } => collect_keys_expr(until, ctx, out)?,
            Stmt::NumericFor {
                start, end, step, ..
            } => {
                collect_keys_expr(start, ctx, out)?;
                collect_keys_expr(end, ctx, out)?;
                if let Some(s) = step {
                    collect_keys_expr(s, ctx, out)?;
                }
            }
            Stmt::If { cond, else_ifs, .. } => {
                collect_keys_expr(cond, ctx, out)?;
                for (c, _) in else_ifs {
                    collect_keys_expr(c, ctx, out)?;
                }
            }
            Stmt::Function { name, .. } => {
                if !name.path.is_empty() && ctx.aliases.contains(&name.path[0]) {
                    if name.method.is_some() {
                        return Err(err(format!(
                            "{MACRO} table `{}`: colon method definition `function {}:{}` is not \
                             supported; the implicit `self` cannot be proven to be this table",
                            ctx.var,
                            name.path.join("."),
                            name.method.as_deref().unwrap_or("")
                        )));
                    }
                    if name.path.len() < 2 {
                        return Err(ctx.escape("be redefined as a function"));
                    }
                    out.insert(name.path[1].clone());
                }
            }
            _ => {}
        }
        each_sub_block(stmt, &mut |_| {});
        collect_keys_sub(stmt, ctx, out)?;
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            collect_keys_expr(e, ctx, out)?;
        }
    }
    Ok(())
}

fn collect_keys_sub(stmt: &Stmt, ctx: &Ctx, out: &mut BTreeSet<String>) -> Result<(), Error> {
    let mut res = Ok(());
    each_sub_block(stmt, &mut |b| {
        if res.is_ok() {
            res = collect_keys_block(b, ctx, out);
        }
    });
    res?;
    let mut res2 = Ok(());
    each_sub_body(stmt, &mut |fb| {
        if res2.is_ok() {
            res2 = collect_keys_block(&fb.block, ctx, out);
        }
    });
    res2
}

fn collect_keys_expr(e: &Expr, ctx: &Ctx, out: &mut BTreeSet<String>) -> Result<(), Error> {
    match e {
        Expr::Field { base, name } if ctx.is_alias(base) => {
            out.insert(name.clone());
            return Ok(());
        }
        Expr::Index { base, key } if ctx.is_alias(base) => {
            if let Expr::Str(raw) = &**key {
                match unquote(raw) {
                    Some(s) => {
                        out.insert(s);
                    }
                    None => {
                        return Err(err(format!(
                            "{MACRO} table `{}`: index {raw} uses escape sequences; \
                             only plain literal string keys are supported",
                            ctx.var
                        )))
                    }
                }
            }
            return Ok(());
        }
        Expr::Function(fb) => return collect_keys_block(&fb.block, ctx, out),
        _ => {}
    }
    let mut res = Ok(());
    e.each_child(&mut |c| {
        if res.is_ok() {
            res = collect_keys_expr(c, ctx, out);
        }
    });
    res
}

fn rewrite_block(block: &mut Block, ctx: &Ctx) -> Result<(), Error> {
    let mut i = 0usize;
    while i < block.stmts.len() {
        let replacement = match &mut block.stmts[i] {
            Stmt::Local { names, exprs } => {
                let tracked =
                    names.len() == 1 && exprs.len() == 1 && ctx.aliases.contains(&names[0]);
                for e in exprs.iter_mut() {
                    if is_macro_call(e) {
                        continue;
                    }
                    if tracked
                        && (matches!(e, Expr::Name(n) if ctx.aliases.contains(n))
                            || alias_source(e, &ctx.aliases))
                    {
                        continue;
                    }
                    rewrite_expr(e, ctx)?;
                }
                None
            }
            Stmt::Assign { targets, exprs } => {
                for t in targets.iter_mut() {
                    if matches!(t, Expr::Name(n) if ctx.aliases.contains(n)) {
                        return Err(err(format!(
                            "{MACRO} table `{}`: the binding is reassigned; \
                             the rewritten key mapping would not apply to the new value",
                            ctx.var
                        )));
                    }
                    rewrite_expr(t, ctx)?;
                }
                for e in exprs.iter_mut() {
                    rewrite_expr(e, ctx)?;
                }
                None
            }
            Stmt::Compound { target, value, .. } => {
                if matches!(target, Expr::Name(n) if ctx.aliases.contains(n)) {
                    return Err(err(format!(
                        "{MACRO} table `{}`: the binding is reassigned",
                        ctx.var
                    )));
                }
                rewrite_expr(target, ctx)?;
                rewrite_expr(value, ctx)?;
                None
            }
            Stmt::Call(e) => {
                rewrite_expr(e, ctx)?;
                None
            }
            Stmt::While { cond, .. } => {
                rewrite_expr(cond, ctx)?;
                None
            }
            Stmt::Repeat { until, .. } => {
                rewrite_expr(until, ctx)?;
                None
            }
            Stmt::NumericFor {
                start, end, step, ..
            } => {
                rewrite_expr(start, ctx)?;
                rewrite_expr(end, ctx)?;
                if let Some(s) = step {
                    rewrite_expr(s, ctx)?;
                }
                None
            }
            Stmt::GenericFor { exprs, .. } => {
                for e in exprs.iter_mut() {
                    rewrite_expr(e, ctx)?;
                }
                None
            }
            Stmt::If { cond, else_ifs, .. } => {
                rewrite_expr(cond, ctx)?;
                for (c, _) in else_ifs.iter_mut() {
                    rewrite_expr(c, ctx)?;
                }
                None
            }
            Stmt::Function { name, body } => {
                if !name.path.is_empty() && ctx.aliases.contains(&name.path[0]) {
                    let k = ctx.key_of(&name.path[1])?;
                    let mut place = Expr::Index {
                        base: Box::new(Expr::Name(name.path[0].clone())),
                        key: Box::new(num_expr(k)),
                    };
                    for seg in &name.path[2..] {
                        place = Expr::Field {
                            base: Box::new(place),
                            name: seg.clone(),
                        };
                    }
                    Some(Stmt::Assign {
                        targets: vec![place],
                        exprs: vec![Expr::Function(body.clone())],
                    })
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(new) = replacement {
            block.stmts[i] = new;
        }
        let mut res = Ok(());
        each_sub_block_mut(&mut block.stmts[i], &mut |b| {
            if res.is_ok() {
                res = rewrite_block(b, ctx);
            }
        });
        res?;
        let mut res2 = Ok(());
        each_sub_body_mut(&mut block.stmts[i], &mut |fb| {
            if res2.is_ok() {
                res2 = rewrite_block(&mut fb.block, ctx);
            }
        });
        res2?;
        i += 1;
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last {
        for e in exprs.iter_mut() {
            if matches!(e, Expr::Name(n) if ctx.aliases.contains(n)) {
                return Err(ctx.escape("be returned"));
            }
            rewrite_expr(e, ctx)?;
        }
    }
    Ok(())
}

fn each_sub_block_mut(stmt: &mut Stmt, f: &mut impl FnMut(&mut Block)) {
    match stmt {
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

fn each_sub_body_mut(stmt: &mut Stmt, f: &mut impl FnMut(&mut FuncBody)) {
    match stmt {
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => f(body),
        Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => {
            for e in exprs {
                each_body_in_expr_mut(e, f);
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter_mut().chain(exprs.iter_mut()) {
                each_body_in_expr_mut(e, f);
            }
        }
        Stmt::Compound { target, value, .. } => {
            each_body_in_expr_mut(target, f);
            each_body_in_expr_mut(value, f);
        }
        Stmt::Call(e) => each_body_in_expr_mut(e, f),
        _ => {}
    }
}

fn each_body_in_expr_mut(e: &mut Expr, f: &mut impl FnMut(&mut FuncBody)) {
    if let Expr::Function(fb) = e {
        f(fb);
        return;
    }
    e.each_child_mut(&mut |c| each_body_in_expr_mut(c, f));
}

fn rewrite_expr(e: &mut Expr, ctx: &Ctx) -> Result<(), Error> {
    match e {
        Expr::Field { base, name } if ctx.is_alias(base) => {
            let k = ctx.key_of(name)?;
            let b = std::mem::replace(&mut **base, Expr::Nil);
            *e = Expr::Index {
                base: Box::new(b),
                key: Box::new(num_expr(k)),
            };
            return Ok(());
        }
        Expr::Index { base, key } if ctx.is_alias(base) => {
            match &**key {
                Expr::Str(raw) => {
                    let name = unquote(raw).ok_or_else(|| {
                        err(format!(
                            "{MACRO} table `{}`: index {raw} uses escape sequences",
                            ctx.var
                        ))
                    })?;
                    let k = ctx.key_of(&name)?;
                    **key = num_expr(k);
                }
                Expr::Number(_) => {}
                _ => {
                    return Err(err(format!(
                        "{MACRO} table `{}` is indexed by a computed key; \
                         a dynamic key cannot be mapped at compile time",
                        ctx.var
                    )))
                }
            }
            return Ok(());
        }
        Expr::MethodCall { base, method, .. } if ctx.is_alias(base) => {
            return Err(err(format!(
                "{MACRO} table `{}`: colon call `:{method}(...)` is not supported; \
                 the callee would receive the table as `self` and index it by the original name",
                ctx.var
            )))
        }
        Expr::Unop {
            op: ir::UnOp::Len,
            expr,
        } if ctx.is_alias(expr) => return Ok(()),
        Expr::Call { func, args, .. } => {
            let direct: Vec<usize> = args
                .iter()
                .enumerate()
                .filter(|(_, a)| ctx.is_alias(a))
                .map(|(i, _)| i)
                .collect();
            if !direct.is_empty() {
                if let Expr::Name(n) = &**func {
                    if let Some((_, why)) = KEY_EXPOSING.iter().find(|(f, _)| f == n) {
                        return Err(err(format!(
                            "{MACRO} table `{}` cannot be passed to `{n}`: {why}",
                            ctx.var
                        )));
                    }
                    if n == "ipairs" {
                        rewrite_expr(func, ctx)?;
                        return Ok(());
                    }
                    return Err(ctx.escape(&format!("be passed to unknown call `{n}`")));
                }
                if let Expr::Field { base, name } = &**func {
                    if matches!(&**base, Expr::Name(t) if t == "table")
                        && SAFE_TABLE_FNS.contains(&name.as_str())
                    {
                        if name == "clone" {
                            return Err(err(format!(
                                "{MACRO} table `{}`: `table.clone` is only supported as the \
                                 direct initializer of a single local, so the copy inherits \
                                 the same key mapping",
                                ctx.var
                            )));
                        }
                        return Ok(());
                    }
                }
                return Err(ctx.escape("be passed to an unknown call"));
            }
            rewrite_expr(func, ctx)?;
            for a in args.iter_mut() {
                rewrite_expr(a, ctx)?;
            }
            return Ok(());
        }
        Expr::Name(n) if ctx.aliases.contains(n) => {
            return Err(ctx.escape("be used as a bare value"))
        }
        _ => {}
    }
    let mut res = Ok(());
    e.each_child_mut(&mut |c| {
        if res.is_ok() {
            res = rewrite_expr(c, ctx);
        }
    });
    res?;
    if let Expr::Function(fb) = e {
        rewrite_block(&mut fb.block, ctx)?;
    }
    Ok(())
}

#[cfg(test)]
mod auto_tests {
    use super::*;

    fn run(src: &str, seed: u64) -> (String, PropKeyStats) {
        let mut m = crate::lower_str(src).expect("lower");
        let stats = rename_internal(&mut m, seed);
        (ir::emit(&m), stats)
    }

    #[test]
    fn renames_closed_world_record_across_ctor_read_write_and_fn_def() {
        let src = "\
local rec = { fieldalpha = 1, fieldbeta = 2 }
rec.fieldgamma = rec.fieldalpha + rec.fieldbeta
rec['fielddelta'] = rec.fieldgamma
function rec.helper() return rec.fielddelta end
return rec.helper()";
        let (out, st) = run(src, 7);
        assert_eq!(st.renamed_domains, 1, "one closed domain renamed: {st:?}");
        for k in [
            "fieldalpha",
            "fieldbeta",
            "fieldgamma",
            "fielddelta",
            "helper",
        ] {
            assert!(!out.contains(k), "closed key `{k}` must be gone: {out}");
        }
        assert!(
            out.contains("rec["),
            "accesses lowered to numeric index: {out}"
        );
    }

    #[test]
    fn deterministic_per_seed_and_varies_across_seeds() {
        let src = "local r = { kk = 1, mm = 2 } r.nn = r.kk return r.nn";
        let a = run(src, 3).0;
        let b = run(src, 3).0;
        let c = run(src, 4).0;
        assert_eq!(a, b, "same seed deterministic");
        assert_ne!(a, c, "different seed varies the keys");
    }

    #[test]
    fn skips_returned_table_as_escape() {
        let (out, st) = run("local t = { openkey = 1 } return t", 7);
        assert_eq!(st.renamed_domains, 0);
        assert_eq!(st.skipped_escape, 1, "{st:?}");
        assert!(out.contains("openkey"), "escaping key preserved: {out}");
    }

    #[test]
    fn skips_dynamic_index() {
        let (out, st) = run("local t = { dk = 1 } local i = 'dk' return t[i]", 7);
        assert_eq!(st.renamed_domains, 0);
        assert_eq!(st.skipped_dynamic, 1, "{st:?}");
        assert!(out.contains("dk"));
    }

    #[test]
    fn skips_reflective_pairs_rawget_metatable() {
        for src in [
            "local t = { rk = 1 } for k in pairs(t) do print(k) end",
            "local t = { rk = 1 } return rawget(t, 'rk')",
            "local t = { rk = 1 } setmetatable(t, {}) return t.rk",
        ] {
            let (_, st) = run(src, 7);
            assert_eq!(st.renamed_domains, 0, "reflective must skip: {src}");
            assert_eq!(st.skipped_reflective, 1, "{src} -> {st:?}");
        }
    }

    #[test]
    fn skips_unknown_call_as_external() {
        let (out, st) = run("local t = { ek = 1 } unknownfn(t) return t.ek", 7);
        assert_eq!(st.renamed_domains, 0);
        assert_eq!(st.skipped_external, 1, "{st:?}");
        assert!(out.contains("ek"));
    }

    #[test]
    fn param_and_global_tables_are_never_candidates() {
        let (_, st) = run(
            "local function f(p) return p.px end return f({ px = 1 })",
            7,
        );
        assert_eq!(st.renamed_domains, 0, "param access never renamed: {st:?}");
        let (out, st2) = run("gtbl = { gk = 1 } return gtbl.gk", 7);
        assert_eq!(st2.domains, 0, "global assign is not a local candidate");
        assert!(out.contains("gk"));
    }

    #[test]
    fn metamethod_keyed_record_is_skipped_by_discovery() {
        let (out, st) = run(
            "local mt = { __index = function() return 0 end, real = 1 } return mt.real",
            7,
        );
        assert_eq!(st.domains, 0, "__* record excluded from discovery: {st:?}");
        assert!(out.contains("__index") && out.contains("real"));
    }

    #[test]
    fn array_and_numeric_tables_are_not_candidates() {
        let (_, st) = run("local a = { 1, 2, 3 } return a[1]", 7);
        assert_eq!(st.domains, 0, "positional array is not a record candidate");
        let (_, st2) = run("local n = { [100] = 1, [200] = 2 } return n[100]", 7);
        assert_eq!(
            st2.domains, 0,
            "explicit-numeric table is not a record candidate"
        );
    }

    #[test]
    fn generated_keys_are_above_the_array_range_by_construction() {
        let names: BTreeSet<String> = (0..300).map(|i| format!("field_{i}")).collect();
        for seed in 0u64..200 {
            for table_id in 0u32..4 {
                let map = build_map(seed, table_id, &names);
                assert_eq!(
                    map.len(),
                    names.len(),
                    "no key collisions collapse the domain"
                );
                for (_, &k) in &map {
                    assert!(k >= KEY_LOW, "key {k} below array-range floor");
                    assert!(k < KEY_HIGH, "key {k} above range ceiling");
                    assert!(k > names.len() as u64, "key {k} could join a 1..N run");
                }
            }
        }
    }

    #[test]
    fn renamed_domain_emits_only_high_numeric_keys() {
        let src = "\
local rec = { ka = 1, kb = 2, kc = 3, kd = 4 }
rec.ke = rec.ka
return rec.kb + rec.kc + rec.kd + rec.ke";
        for seed in [1u64, 7, 42, 305419896, 0xBEEF] {
            let (out, st) = run(src, seed);
            assert_eq!(st.renamed_domains, 1, "seed {seed}: {st:?}");
            let mut found = 0usize;
            let bytes = out.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'[' {
                    let mut j = i + 1;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j > i + 1 && j < bytes.len() && bytes[j] == b']' {
                        let k: u64 = out[i + 1..j].parse().unwrap();
                        assert!(
                            k >= KEY_LOW,
                            "seed {seed}: bracket key {k} entered array range: {out}"
                        );
                        found += 1;
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            assert!(
                found >= 5,
                "seed {seed}: expected the 5 renamed keys as numeric brackets, saw {found}"
            );
        }
    }

    #[test]
    fn skipped_domain_leaves_other_closed_domains_renamable() {
        let src = "\
local keep = { kalpha = 1 }
local gone = { galpha = 1 }
gone.gbeta = gone.galpha
return keep, gone.gbeta";
        let (out, st) = run(src, 7);
        assert_eq!(
            st.renamed_domains, 1,
            "only the non-escaping domain renames: {st:?}"
        );
        assert!(
            out.contains("kalpha"),
            "returned (escaping) domain preserved"
        );
        assert!(
            !out.contains("galpha") && !out.contains("gbeta"),
            "closed domain renamed: {out}"
        );
    }
}
