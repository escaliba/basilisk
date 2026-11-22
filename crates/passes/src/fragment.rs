use std::collections::BTreeSet;

use ir::{BinOp, Block, Expr, Field, FuncBody, LastStmt, Module, Stmt};

use crate::rng::Rng;

const DOMAIN: u64 = 0x_4652_4147_5F43_32;

const MIN_LEN: usize = 5;

pub fn fragment_strings(module: &mut Module, seed: u64, heavy: bool) {
    fragment_strings_scoped(module, seed, heavy, false);
}

pub fn fragment_strings_scoped(
    module: &mut Module,
    seed: u64,
    heavy: bool,
    skip_hot_callbacks: bool,
) {
    let mut fx = Fragmenter {
        seed,
        counter: 0,
        heavy,
        skip_hot_callbacks,
        selective: false,
        loop_depth: 0,
        budget: usize::MAX,
        stats: FragStats::default(),
    };
    fx.block(&mut module.block);
}

#[derive(Default, Clone, Debug)]
pub struct FragStats {
    pub candidates: u64,
    pub selected: u64,
    pub fragments: u64,
    pub skipped_hot: u64,
    pub skipped_budget: u64,
    pub multiplicity: Vec<usize>,
}

pub fn fragment_strings_selective(
    module: &mut Module,
    seed: u64,
    heavy: bool,
    skip_hot_callbacks: bool,
    budget: usize,
) -> FragStats {
    let mut fx = Fragmenter {
        seed,
        counter: 0,
        heavy,
        skip_hot_callbacks,
        selective: true,
        loop_depth: 0,
        budget,
        stats: FragStats::default(),
    };
    fx.block(&mut module.block);
    fx.stats
}

struct Fragmenter {
    seed: u64,
    counter: u64,
    heavy: bool,
    skip_hot_callbacks: bool,
    selective: bool,
    loop_depth: u32,
    budget: usize,
    stats: FragStats,
}

impl Fragmenter {
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
                self.loop_depth += 1;
                self.expr(cond);
                self.block(body);
                self.loop_depth -= 1;
            }
            Stmt::Repeat { body, until } => {
                self.loop_depth += 1;
                self.block(body);
                self.expr(until);
                self.loop_depth -= 1;
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
                self.loop_depth += 1;
                self.block(body);
                self.loop_depth -= 1;
            }
            Stmt::GenericFor { exprs, body, .. } => {
                exprs.iter_mut().for_each(|e| self.expr(e));
                self.loop_depth += 1;
                self.block(body);
                self.loop_depth -= 1;
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

    fn func(&mut self, f: &mut FuncBody) {
        if self.skip_hot_callbacks && f.hot_callback.is_some() {
            return;
        }
        self.block(&mut f.block);
    }

    fn expr(&mut self, e: &mut Expr) {
        match e {
            Expr::Str(text) => {
                if let Some(rep) = self.try_fragment_literal(text) {
                    *e = rep;
                }
            }

            Expr::Field { base, name } => {
                self.expr(base);
                if let Some(key) = self.try_fragment_bytes(name.as_bytes()) {
                    *e = Expr::Index {
                        base: std::mem::replace(base, Box::new(Expr::Nil)),
                        key: Box::new(key),
                    };
                }
            }
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
            Expr::Nil
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

    fn try_fragment_literal(&mut self, text: &str) -> Option<Expr> {
        let bytes = bytecode::literal::decode_string(text)?;
        self.try_fragment_bytes(&bytes)
    }

    fn try_fragment_bytes(&mut self, bytes: &[u8]) -> Option<Expr> {
        if bytes.len() < MIN_LEN {
            return None;
        }
        if self.selective {
            self.stats.candidates += 1;
            if self.loop_depth > 0 {
                self.stats.skipped_hot += 1;
                return None;
            }
        }
        self.counter += 1;
        let mut rng =
            Rng::new(self.seed ^ DOMAIN ^ self.counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));

        let len = bytes.len();
        let (lo, hi) = if self.selective {
            (2usize, 4usize)
        } else {
            (3usize, if self.heavy { 6 } else { 4 })
        };
        let nfrag = (lo + rng.below((hi - lo + 1) as u64) as usize).min(len);
        if self.selective {
            if self.budget < nfrag {
                self.stats.skipped_budget += 1;
                return None;
            }
            self.budget -= nfrag;
            self.stats.selected += 1;
            self.stats.fragments += nfrag as u64;
            self.stats.multiplicity.push(nfrag);
        }
        let parts = split(bytes, nfrag, &mut rng);
        let expr = reassemble(&parts, &mut rng, self.heavy);
        if self.heavy && rng.chance(60) {
            Some(decoy_wrap(expr, &mut rng))
        } else {
            Some(expr)
        }
    }
}

fn split(bytes: &[u8], nfrag: usize, rng: &mut Rng) -> Vec<Vec<u8>> {
    let len = bytes.len();
    let mut cuts: BTreeSet<usize> = BTreeSet::new();
    while cuts.len() < nfrag - 1 {
        cuts.insert(1 + rng.below((len - 1) as u64) as usize);
    }
    let mut bounds = vec![0usize];
    bounds.extend(cuts);
    bounds.push(len);
    bounds
        .windows(2)
        .map(|w| bytes[w[0]..w[1]].to_vec())
        .collect()
}

fn reassemble(parts: &[Vec<u8>], rng: &mut Rng, heavy: bool) -> Expr {
    let style = if heavy {
        rng.below(3)
    } else {
        match rng.below(8) {
            0..=4 => 0,
            5 => 1,
            _ => 2,
        }
    };
    match style {
        0 => combine_concat(parts, rng),
        1 => combine_dotdot(parts, rng),
        _ => combine_reverse(parts, rng, heavy),
    }
}

fn combine_concat(parts: &[Vec<u8>], rng: &mut Rng) -> Expr {
    if parts.len() >= 4 && rng.chance(45) {
        let mid = 1 + rng.below((parts.len() - 1) as u64) as usize;
        let left = intrinsic_join(&parts[..mid], rng);
        let right = intrinsic_join(&parts[mid..], rng);
        return Expr::Binop {
            op: BinOp::Concat,
            lhs: Box::new(left),
            rhs: Box::new(right),
        };
    }
    intrinsic_join(parts, rng)
}

fn combine_dotdot(parts: &[Vec<u8>], rng: &mut Rng) -> Expr {
    let exprs: Vec<Expr> = parts
        .iter()
        .map(|p| frag_route(p, pick_route(rng), rng))
        .collect();
    fold_concat(exprs, rng)
}

fn combine_reverse(parts: &[Vec<u8>], rng: &mut Rng, heavy: bool) -> Expr {
    let rev_parts: Vec<Vec<u8>> = parts
        .iter()
        .rev()
        .map(|p| {
            let mut v = p.clone();
            v.reverse();
            v
        })
        .collect();
    let inner = if heavy && rng.chance(50) {
        combine_dotdot(&rev_parts, rng)
    } else {
        combine_concat(&rev_parts, rng)
    };
    call(field(name("string"), "reverse"), vec![inner])
}

fn fold_concat(mut exprs: Vec<Expr>, _rng: &mut Rng) -> Expr {
    assert!(!exprs.is_empty());
    if exprs.len() == 1 {
        return exprs.pop().unwrap();
    }

    while exprs.len() > 1 {
        let mut next: Vec<Expr> = Vec::with_capacity(exprs.len().div_ceil(2));
        let mut it = exprs.into_iter();
        loop {
            let Some(a) = it.next() else { break };
            match it.next() {
                Some(b) => next.push(Expr::Binop {
                    op: BinOp::Concat,
                    lhs: Box::new(a),
                    rhs: Box::new(b),
                }),
                None => next.push(a),
            }
        }
        exprs = next;
    }
    exprs.pop().unwrap()
}

fn intrinsic_join(parts: &[Vec<u8>], rng: &mut Rng) -> Expr {
    if parts.len() == 1 {
        return frag_route(&parts[0], pick_route(rng), rng);
    }
    let exprs: Vec<Expr> = parts
        .iter()
        .map(|p| frag_route(p, pick_route(rng), rng))
        .collect();
    fold_concat(exprs, rng)
}

fn pick_route(_rng: &mut Rng) -> u8 {
    0
}

fn frag_route(bytes: &[u8], route: u8, rng: &mut Rng) -> Expr {
    match route {
        0 => Expr::Str(enc_ddd(bytes)),
        1 => char_call(bytes.iter().map(|&b| num(b as i64)).collect()),
        2 => char_call(bytes.iter().map(|&b| arith_byte(b, rng)).collect()),
        _ => char_call(bytes.iter().map(|&b| xor_byte(b, rng)).collect()),
    }
}

fn xor_byte(b: u8, rng: &mut Rng) -> Expr {
    let mask = rng.below(256) as i64;
    let stored = (b as i64) ^ mask;
    call(field(name("bit32"), "bxor"), vec![num(stored), num(mask)])
}

fn char_call(args: Vec<Expr>) -> Expr {
    call(field(name("string"), "char"), args)
}

fn arith_byte(b: u8, rng: &mut Rng) -> Expr {
    let d = 1 + rng.below(63) as i64;
    let b = b as i64;
    if rng.chance(50) && b >= d {
        Expr::Binop {
            op: BinOp::Add,
            lhs: Box::new(num(b - d)),
            rhs: Box::new(num(d)),
        }
    } else {
        Expr::Binop {
            op: BinOp::Sub,
            lhs: Box::new(num(b + d)),
            rhs: Box::new(num(d)),
        }
    }
}

fn decoy_wrap(real: Expr, rng: &mut Rng) -> Expr {
    let k = 1 + rng.below(3) as usize;
    let mut real = Some(real);
    let mut items: Vec<Field> = Vec::with_capacity(3);
    for i in 1..=3usize {
        if i == k {
            items.push(Field::Positional(real.take().unwrap()));
        } else {
            let dlen = 3 + rng.below(6) as usize;
            let bytes: Vec<u8> = (0..dlen).map(|_| 32 + rng.below(90) as u8).collect();
            let r = pick_route(rng);
            items.push(Field::Positional(frag_route(&bytes, r, rng)));
        }
    }
    Expr::Index {
        base: Box::new(Expr::Table(items)),
        key: Box::new(num(k as i64)),
    }
}

fn name(s: &str) -> Expr {
    Expr::Name(s.to_string())
}

fn field(base: Expr, n: &str) -> Expr {
    Expr::Field {
        base: Box::new(base),
        name: n.to_string(),
    }
}

fn call(func: Expr, args: Vec<Expr>) -> Expr {
    Expr::Call {
        func: Box::new(func),
        args,
        site: None,
    }
}

fn num(n: i64) -> Expr {
    Expr::Number(n.to_string())
}

fn enc_ddd(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 4 + 2);
    s.push('"');
    for &b in bytes {
        s.push('\\');
        s.push_str(&format!("{b:03}"));
    }
    s.push('"');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(e: &Expr) -> Vec<u8> {
        match e {
            Expr::Str(t) => bytecode::literal::decode_string(t).unwrap(),
            Expr::Number(t) => vec![bytecode::literal::decode_number(t).unwrap() as u8],
            Expr::Binop {
                op: BinOp::Concat,
                lhs,
                rhs,
            } => {
                let mut v = eval(lhs);
                v.extend(eval(rhs));
                v
            }
            Expr::Binop {
                op: BinOp::Add,
                lhs,
                rhs,
            } => vec![(num_of(lhs) + num_of(rhs)) as u8],
            Expr::Binop {
                op: BinOp::Sub,
                lhs,
                rhs,
            } => vec![(num_of(lhs) - num_of(rhs)) as u8],
            Expr::Call { func, args, .. } => match &**func {
                Expr::Field { base, name }
                    if matches!(&**base, Expr::Name(n) if n == "string") && name == "char" =>
                {
                    args.iter().map(|a| eval(a)[0]).collect()
                }
                Expr::Field { base, name }
                    if matches!(&**base, Expr::Name(n) if n == "string") && name == "reverse" =>
                {
                    let mut v = eval(&args[0]);
                    v.reverse();
                    v
                }
                Expr::Field { base, name }
                    if matches!(&**base, Expr::Name(n) if n == "bit32") && name == "bxor" =>
                {
                    vec![(num_of(&args[0]) ^ num_of(&args[1])) as u8]
                }
                Expr::Field { base, name }
                    if matches!(&**base, Expr::Name(n) if n == "table") && name == "concat" =>
                {
                    let Expr::Table(fields) = &args[0] else {
                        panic!("table.concat arg")
                    };
                    let mut by_key: Vec<(i64, Vec<u8>)> = fields
                        .iter()
                        .map(|f| match f {
                            Field::Keyed { key, value } => (num_of(key), eval(value)),
                            _ => panic!("expected keyed"),
                        })
                        .collect();
                    by_key.sort_by_key(|(k, _)| *k);
                    by_key.into_iter().flat_map(|(_, v)| v).collect()
                }
                _ => panic!("unexpected call"),
            },
            Expr::Index { base, key } => {
                let Expr::Table(items) = &**base else {
                    panic!("decoy base")
                };
                let k = num_of(key) as usize;
                match &items[k - 1] {
                    Field::Positional(v) => eval(v),
                    _ => panic!("decoy positional"),
                }
            }
            _ => panic!("unexpected node {e:?}"),
        }
    }
    fn num_of(e: &Expr) -> i64 {
        match e {
            Expr::Number(t) => bytecode::literal::decode_number(t).unwrap() as i64,
            Expr::Binop {
                op: BinOp::Add,
                lhs,
                rhs,
            } => num_of(lhs) + num_of(rhs),
            Expr::Binop {
                op: BinOp::Sub,
                lhs,
                rhs,
            } => num_of(lhs) - num_of(rhs),
            _ => panic!("not numeric"),
        }
    }

    const TARGETS: &[&str] = &[
        "hydroxide",
        "Invalid Service:",
        "yeah its working",
        "nah not ready",
        "cant find that",
        "data broken",
        "took too long",
        "starting up",
        "player:",
        "calculated:",
        "modified stuff:",
        "Players",
        "LocalPlayer",
        "TestPart",
        "BasePart",
        "SetAttribute",
        "GetAttribute",
        "VectorToWorldSpace",
    ];

    #[test]
    fn every_route_and_shape_reassembles_exactly() {
        for heavy in [false, true] {
            for seed in 0u64..40 {
                for s in TARGETS {
                    let mut fx = Fragmenter {
                        seed,
                        counter: 0,
                        heavy,
                        skip_hot_callbacks: false,
                        selective: false,
                        loop_depth: 0,
                        budget: usize::MAX,
                        stats: FragStats::default(),
                    };
                    let rep = fx
                        .try_fragment_literal(&format!("{s:?}"))
                        .expect("high-value must fragment");
                    assert_eq!(
                        eval(&rep),
                        s.as_bytes(),
                        "seed={seed} heavy={heavy} s={s:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn uses_three_to_six_fragments() {
        fn leaves(e: &Expr) -> usize {
            match e {
                Expr::Str(_) => 1,
                Expr::Call { func, args, .. } => match &**func {
                    Expr::Field { name, .. } if name == "char" => 1,
                    Expr::Field { name, .. } if name == "reverse" => leaves(&args[0]),
                    Expr::Field { name, .. } if name == "concat" => {
                        let Expr::Table(fields) = &args[0] else {
                            return 0;
                        };
                        fields.len()
                    }
                    _ => 0,
                },
                Expr::Binop {
                    op: BinOp::Concat,
                    lhs,
                    rhs,
                } => leaves(lhs) + leaves(rhs),
                Expr::Index { base, key } => {
                    let Expr::Table(items) = &**base else {
                        return 0;
                    };
                    let k = match &**key {
                        Expr::Number(t) => t.parse::<usize>().unwrap(),
                        _ => 1,
                    };
                    match &items[k - 1] {
                        Field::Positional(v) => leaves(v),
                        _ => 0,
                    }
                }
                _ => 0,
            }
        }
        for seed in 0u64..40 {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            let rep = fx
                .try_fragment_literal(&format!("{:?}", "VectorToWorldSpace"))
                .unwrap();
            let n = leaves(&rep);
            assert!(
                (3..=6).contains(&n),
                "expected 3-6 fragments, got {n} (seed={seed})"
            );
        }
    }

    #[test]
    fn fragments_never_reach_table_concat_or_string_char() {
        for seed in 0u64..120 {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            let rep = fx
                .try_fragment_literal(&format!("{:?}", "hydroxide"))
                .unwrap();
            let src = format!("{rep:?}");
            assert!(
                !src.contains("\"concat\""),
                "table.concat in fragment output (seed={seed})"
            );
            assert!(
                !src.contains("\"char\""),
                "string.char in fragment output (seed={seed})"
            );
            assert_eq!(
                eval(&rep),
                b"hydroxide",
                "value must stay exact (seed={seed})"
            );
        }
    }

    #[test]
    fn short_strings_are_left_whole() {
        let mut fx = Fragmenter {
            seed: 1,
            counter: 0,
            heavy: false,
            skip_hot_callbacks: false,
            selective: false,
            loop_depth: 0,
            budget: usize::MAX,
            stats: FragStats::default(),
        };
        for s in ["yo", "dev", "foo", "Name", "TYPE"] {
            assert!(
                fx.try_fragment_literal(&format!("{s:?}")).is_none(),
                "tiny string must stay whole: {s}"
            );
        }
    }

    #[test]
    fn deterministic_per_seed_and_varies_across_seeds() {
        let run = |seed: u64| {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            format!(
                "{:?}",
                fx.try_fragment_literal(&format!("{:?}", "VectorToWorldSpace"))
                    .unwrap()
            )
        };
        assert_eq!(run(7), run(7), "same seed deterministic");
        let shapes: std::collections::HashSet<String> = (0u64..16).map(run).collect();
        assert!(
            shapes.len() >= 8,
            "different seeds should vary fragment shape, got {}",
            shapes.len()
        );
    }

    #[test]
    fn heavy_decoys_do_not_change_the_value() {
        for seed in 0u64..40 {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: true,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            let rep = fx
                .try_fragment_literal(&format!("{:?}", "hydroxide"))
                .unwrap();
            assert_eq!(
                eval(&rep),
                b"hydroxide",
                "heavy decoys must be inert (seed={seed})"
            );
        }
    }

    fn str_leaves(e: &Expr) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        fn go(e: &Expr, out: &mut Vec<Vec<u8>>) {
            match e {
                Expr::Str(t) => out.push(bytecode::literal::decode_string(t).unwrap()),
                Expr::Call { func, args, .. } => {
                    let is_char = matches!(&**func, Expr::Field { name, .. } if name == "char");
                    if !is_char {
                        for a in args {
                            go(a, out);
                        }
                    }
                }
                Expr::Binop { lhs, rhs, .. } => {
                    go(lhs, out);
                    go(rhs, out);
                }
                Expr::Index { base, .. } => go(base, out),
                Expr::Table(fields) => {
                    for f in fields {
                        match f {
                            Field::Positional(v) | Field::Named { value: v, .. } => go(v, out),
                            Field::Keyed { value, .. } => go(value, out),
                        }
                    }
                }
                _ => {}
            }
        }
        go(e, &mut out);
        out
    }

    fn combiner_kind(rep: &Expr) -> &'static str {
        let src = format!("{rep:?}");
        if src.contains("\"reverse\"") {
            "reverse"
        } else if src.contains("\"concat\"") {
            "concat"
        } else if matches!(
            rep,
            Expr::Binop {
                op: BinOp::Concat,
                ..
            }
        ) {
            "dotdot"
        } else {
            "other"
        }
    }

    #[test]
    fn c22_no_universal_combiner_signature() {
        let mut kinds = std::collections::HashSet::new();
        for seed in 0u64..160 {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            let rep = fx
                .try_fragment_literal(&format!("{:?}", "VectorToWorldSpace"))
                .unwrap();
            kinds.insert(combiner_kind(&rep));
        }
        assert!(
            !kinds.contains("concat"),
            "table.concat must never reassemble fragments, got {kinds:?}"
        );
        assert!(
            kinds.contains("reverse") && kinds.contains("dotdot"),
            "both surviving combiners must appear, got {kinds:?}"
        );
    }

    #[test]
    fn c22_fragments_not_adjacent_final_order() {
        let s = "VectorToWorldSpace";
        for seed in 0u64..160 {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            let rep = fx.try_fragment_literal(&format!("{s:?}")).unwrap();
            for l in &str_leaves(&rep) {
                assert!(
                    l.len() < s.len(),
                    "no readable leaf may be the whole string (seed={seed})"
                );
            }
            assert_eq!(
                eval(&rep),
                s.as_bytes(),
                "value must stay exact (seed={seed})"
            );
        }
    }

    #[test]
    fn c22_use_site_binding() {
        let mut fx = Fragmenter {
            seed: 0xC22,
            counter: 0,
            heavy: false,
            skip_hot_callbacks: false,
            selective: false,
            loop_depth: 0,
            budget: usize::MAX,
            stats: FragStats::default(),
        };
        let a = format!(
            "{:?}",
            fx.try_fragment_literal(&format!("{:?}", "Invalid Service:"))
                .unwrap()
        );
        let b = format!(
            "{:?}",
            fx.try_fragment_literal(&format!("{:?}", "Invalid Service:"))
                .unwrap()
        );
        assert_ne!(
            a, b,
            "same string at distinct sites must materialize differently (per-occurrence salt)"
        );
    }

    #[test]
    fn c22_url_reassembly_not_trivial() {
        let url = "https://basil-key-worker.heroin-9c6.workers.dev/basil-key";
        let mut kinds = std::collections::HashSet::new();
        for seed in 0u64..120 {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            let rep = fx.try_fragment_literal(&format!("{url:?}")).unwrap();
            assert_eq!(
                eval(&rep),
                url.as_bytes(),
                "URL must reassemble exactly (seed={seed})"
            );
            for l in str_leaves(&rep) {
                assert!(
                    l.len() < url.len(),
                    "no whole-URL readable leaf (seed={seed})"
                );
            }
            let src = format!("{rep:?}");
            assert!(
                !src.contains("\"concat\"") && !src.contains("\"char\""),
                "no hookable assembler may appear (seed={seed})"
            );
            kinds.insert(combiner_kind(&rep));
        }
        assert!(
            kinds.len() >= 2,
            "URL materialization must vary its shape across seeds, got {kinds:?}"
        );
    }

    #[test]
    fn c22_heavy_decoys_present() {
        let is_decoy = |rep: &Expr| matches!(rep, Expr::Index { base, .. } if matches!(&**base, Expr::Table(_)));
        let mut heavy_decoys = 0;
        for seed in 0u64..60 {
            let mut fxn = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            assert!(
                !is_decoy(
                    &fxn.try_fragment_literal(&format!("{:?}", "hydroxide"))
                        .unwrap()
                ),
                "normal must not decoy-wrap (seed={seed})"
            );
            let mut fxh = Fragmenter {
                seed,
                counter: 0,
                heavy: true,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            if is_decoy(
                &fxh.try_fragment_literal(&format!("{:?}", "hydroxide"))
                    .unwrap(),
            ) {
                heavy_decoys += 1;
            }
        }
        assert!(
            heavy_decoys >= 10,
            "heavy must add decoy wrappers, got {heavy_decoys}/60"
        );
    }

    #[test]
    fn c22_same_seed_deterministic() {
        let run = || {
            let mut fx = Fragmenter {
                seed: 0x5151,
                counter: 0,
                heavy: true,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            format!(
                "{:?}",
                fx.try_fragment_literal(&format!("{:?}", "modified stuff:"))
                    .unwrap()
            )
        };
        assert_eq!(run(), run(), "same seed/settings must be deterministic");
    }

    #[test]
    fn c22_different_seed_changes_layout() {
        let run = |seed: u64| {
            let mut fx = Fragmenter {
                seed,
                counter: 0,
                heavy: false,
                skip_hot_callbacks: false,
                selective: false,
                loop_depth: 0,
                budget: usize::MAX,
                stats: FragStats::default(),
            };
            format!(
                "{:?}",
                fx.try_fragment_literal(&format!("{:?}", "modified stuff:"))
                    .unwrap()
            )
        };
        let shapes: std::collections::HashSet<String> = (0u64..24).map(run).collect();
        assert!(
            shapes.len() >= 16,
            "different seeds must vary layout, got {}",
            shapes.len()
        );
    }

    #[test]
    fn scoped_pass_leaves_annotated_hot_callback_subtrees_intact() {
        let src = "local uis = game:GetService(\"UserInputService\")\nuis.InputBegan:Connect(function()\n  local s = \"hydroxide\"\n  return s\nend)\nlocal cold = function()\n  return \"kaleidoscope\"\nend\nreturn cold\n";
        let mut annotated = frontend::lower_str(src).unwrap();
        ir::hot_callbacks::annotate(&mut annotated);

        let mut all = annotated.clone();
        fragment_strings_scoped(&mut all, 0xABCD, false, false);
        let all_out = ir::emit(&all);
        assert!(
            !all_out.contains("hydroxide"),
            "unscoped pass must fragment the hot callback"
        );
        assert!(
            !all_out.contains("kaleidoscope"),
            "unscoped pass must fragment cold code"
        );

        let mut scoped = annotated.clone();
        fragment_strings_scoped(&mut scoped, 0xABCD, false, true);
        let scoped_out = ir::emit(&scoped);
        assert!(
            scoped_out.contains("hydroxide"),
            "the annotated Connect callback must stay unfragmented: {scoped_out}"
        );
        assert!(
            !scoped_out.contains("kaleidoscope"),
            "cold code outside hot callbacks must still be fragmented: {scoped_out}"
        );
    }

    #[test]
    fn full_module_value_and_field_fragmented() {
        let src = "local t = {}\nt.Players = \"hydroxide\"\nreturn t.Players\n";
        let mut m = frontend::lower_str(src).unwrap();
        fragment_strings(&mut m, 0xABCD, false);
        let out = ir::emit(&m);
        assert!(
            !out.contains("hydroxide"),
            "value string must not survive whole: {out}"
        );
        assert!(
            !out.contains("Players"),
            "field key must not survive whole: {out}"
        );
    }

    fn sel_emit(src: &str, seed: u64, budget: usize) -> (String, FragStats) {
        let mut m = frontend::lower_str(src).unwrap();
        let st = fragment_strings_selective(&mut m, seed, false, false, budget);
        (ir::emit(&m), st)
    }

    #[test]
    fn selective_skips_syntactic_loop_sites_and_fragments_cold() {
        let cases = [
            ("numloopAAAA", "for i=1,3 do local a = \"numloopAAAA\" end"),
            (
                "genloopBBBB",
                "for _,v in ipairs({1}) do local b = \"genloopBBBB\" end",
            ),
            ("whilecondCCCC", "while (\"whilecondCCCC\") == nil do end"),
            ("repuntilDDDD", "repeat until (\"repuntilDDDD\") ~= nil"),
            (
                "nestloopEEEE",
                "for i=1,3 do local f = function() return \"nestloopEEEE\" end end",
            ),
        ];
        for seed in [1u64, 3, 7] {
            for (needle, src) in cases {
                let (out, st) = sel_emit(src, seed, usize::MAX);
                assert!(
                    out.contains(needle),
                    "seed={seed} loop-resident {needle} must stay whole (skipped): {out}"
                );
                assert!(
                    st.skipped_hot >= 1 && st.selected == 0,
                    "seed={seed} {needle}: expected skipped_hot, got {st:?}"
                );
            }
        }

        for seed in [1u64, 3, 7] {
            let (out, st) = sel_emit("local y = \"coldtoplevelZZZZ\"\nreturn y", seed, usize::MAX);
            assert!(
                !out.contains("coldtoplevelZZZZ"),
                "seed={seed} cold literal must fragment: {out}"
            );
            assert!(
                st.selected == 1,
                "seed={seed} cold: expected selected==1, got {st:?}"
            );
        }
    }

    #[test]
    fn selective_misses_non_syntactic_hotness() {
        let f = "local function g() return \"calledinloopFFFF\" end\nfor i=1,3 do g() end";
        let g = "local function rec(n) if n<=0 then return \"recstringGGGG\" end return rec(n-1) end\nreturn rec(3)";
        for (needle, src) in [("calledinloopFFFF", f), ("recstringGGGG", g)] {
            let (out, st) = sel_emit(src, 1, usize::MAX);
            assert!(
                !out.contains(needle),
                "{needle} at loop_depth 0 is fragmented (non-syntactic hotness undetected): {out}"
            );
            assert!(
                st.selected >= 1,
                "{needle}: expected fragmented, got {st:?}"
            );
        }
    }

    #[test]
    fn selective_budget_is_enforced_and_later_strings_stay_atomic() {
        let mut src = String::new();
        for i in 0..40 {
            src.push_str(&format!("local v{i} = \"budget_string_number_{i:04}\"\n"));
        }
        let budget = 10usize;
        let (_out, st) = sel_emit(&src, 1, budget);
        assert!(
            st.fragments as usize <= budget,
            "fragments {} must be <= budget {budget}",
            st.fragments
        );
        assert!(
            st.skipped_budget >= 1,
            "some eligible strings must be skipped once budget exhausts: {st:?}"
        );
        assert!(
            (st.selected as usize) < 40,
            "not all strings selected under a small budget: {st:?}"
        );
    }

    #[test]
    fn selective_multiplicity_two_to_four_and_byte_exact() {
        let mut all = Vec::new();
        for seed in 0u64..40 {
            for s in TARGETS {
                let mut fx = Fragmenter {
                    seed,
                    counter: 0,
                    heavy: false,
                    skip_hot_callbacks: false,
                    selective: true,
                    loop_depth: 0,
                    budget: usize::MAX,
                    stats: FragStats::default(),
                };
                let rep = fx
                    .try_fragment_literal(&format!("{s:?}"))
                    .expect("cold high-value fragments");
                let n = fx.stats.multiplicity[0];
                assert!(
                    (2..=4).contains(&n),
                    "selective multiplicity 2-4, got {n} (seed={seed} s={s:?})"
                );
                assert_eq!(
                    eval(&rep),
                    s.as_bytes(),
                    "byte-exact reconstruction seed={seed} s={s:?}"
                );
                all.push(n);
            }
        }
        all.sort_unstable();
        let mean = all.iter().sum::<usize>() as f64 / all.len() as f64;
        let p50 = all[all.len() / 2];
        let p95 = all[all.len() * 95 / 100];
        let min = *all.first().unwrap();
        let max = *all.last().unwrap();
        println!(
            "SELECTIVE_MULTIPLICITY n={} min={min} mean={mean:.2} p50={p50} p95={p95} max={max}",
            all.len()
        );
        assert!(
            min >= 2 && max <= 4,
            "multiplicity range [2,4]: min={min} mean={mean:.2} p50={p50} p95={p95} max={max}"
        );
    }
}
