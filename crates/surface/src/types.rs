use crate::rng::{Rng, DOMAIN_TYPES};
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TypeNoiseMode {
    #[default]
    Off,
    Insane,
}

impl TypeNoiseMode {
    pub fn is_on(self) -> bool {
        matches!(self, TypeNoiseMode::Insane)
    }
}

pub const MAX_DEPTH: u32 = 5;
pub const MAX_NODES: u32 = 28;
pub const MAX_GENERIC_PARAMS: usize = 3;
pub const MAX_ALIASES: usize = 32;
pub const MAX_TOTAL_BYTES: usize = 12288;
pub const PER_REGION_CAP: usize = 4;

const BUILTINS: [&str; 6] = ["number", "string", "boolean", "any", "nil", "thread"];
const TYPEOF_GLOBALS: [&str; 4] = ["string", "table", "math", "coroutine"];
const NAME_LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const ALIAS_PREFIX: &str = "_Tf";

pub fn source_has_type_noise(s: &str) -> bool {
    s.contains("type _Tf")
}

enum TypeExpr {
    Name(String),
    Optional(Box<TypeExpr>),
    Union(Vec<TypeExpr>),
    Intersection(Vec<TypeExpr>),
    Array(Box<TypeExpr>),
    Table(Vec<(String, TypeExpr)>),
    IndexSig(Box<TypeExpr>, Box<TypeExpr>),
    Function {
        params: Vec<TypeExpr>,
        variadic: Option<Box<TypeExpr>>,
        ret: Box<TypeExpr>,
    },
    Generic(String, Vec<TypeExpr>),
    Typeof(String),
}

impl TypeExpr {
    fn is_atomic(&self) -> bool {
        matches!(
            self,
            TypeExpr::Name(_)
                | TypeExpr::Generic(_, _)
                | TypeExpr::Typeof(_)
                | TypeExpr::Array(_)
                | TypeExpr::Table(_)
                | TypeExpr::IndexSig(_, _)
        )
    }

    fn write_full(&self, out: &mut String) {
        match self {
            TypeExpr::Name(n) => out.push_str(n),
            TypeExpr::Typeof(g) => {
                out.push_str("typeof(");
                out.push_str(g);
                out.push(')');
            }
            TypeExpr::Optional(t) => {
                t.write_atom(out);
                out.push('?');
            }
            TypeExpr::Union(parts) => {
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 {
                        out.push_str(" | ");
                    }
                    p.write_atom(out);
                }
            }
            TypeExpr::Intersection(parts) => {
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 {
                        out.push_str(" & ");
                    }
                    p.write_atom(out);
                }
            }
            TypeExpr::Array(t) => {
                out.push_str("{ ");
                t.write_full(out);
                out.push_str(" }");
            }
            TypeExpr::Table(fields) => {
                out.push_str("{ ");
                for (i, (k, t)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(k);
                    out.push_str(": ");
                    t.write_full(out);
                }
                out.push_str(" }");
            }
            TypeExpr::IndexSig(k, v) => {
                out.push_str("{ [");
                k.write_full(out);
                out.push_str("]: ");
                v.write_full(out);
                out.push_str(" }");
            }
            TypeExpr::Function {
                params,
                variadic,
                ret,
            } => {
                out.push('(');
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    p.write_full(out);
                }
                if let Some(v) = variadic {
                    if !params.is_empty() {
                        out.push_str(", ");
                    }
                    out.push_str("...");
                    v.write_full(out);
                }
                out.push_str(") -> ");
                ret.write_atom(out);
            }
            TypeExpr::Generic(name, args) => {
                out.push_str(name);
                out.push('<');
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    a.write_full(out);
                }
                out.push('>');
            }
        }
    }

    fn write_atom(&self, out: &mut String) {
        if self.is_atomic() {
            self.write_full(out);
        } else {
            out.push('(');
            self.write_full(out);
            out.push(')');
        }
    }
}

pub struct TypeInk {
    rng: Rng,
    counter: u32,
    aliases_made: usize,
    bytes_made: usize,
    region_counts: HashMap<&'static str, usize>,
    pub log: Vec<(&'static str, String)>,
}

impl TypeInk {
    pub fn new(seed: u64) -> TypeInk {
        TypeInk {
            rng: Rng::new(seed ^ DOMAIN_TYPES),
            counter: 0,
            aliases_made: 0,
            bytes_made: 0,
            region_counts: HashMap::new(),
            log: Vec::new(),
        }
    }

    pub fn aliases_made(&self) -> usize {
        self.aliases_made
    }

    pub fn regions_used(&self) -> usize {
        self.region_counts.len()
    }

    pub fn aliases(&mut self, region: &'static str, want: usize) -> String {
        if self.aliases_made >= MAX_ALIASES || self.bytes_made >= MAX_TOTAL_BYTES {
            return String::new();
        }
        let n = want
            .min(PER_REGION_CAP)
            .min(MAX_ALIASES - self.aliases_made);
        let mut pool: Vec<(String, usize)> = BUILTINS.iter().map(|b| (b.to_string(), 0)).collect();
        let mut out = String::new();
        for _ in 0..n {
            if self.bytes_made >= MAX_TOTAL_BYTES {
                break;
            }
            let name = self.fresh_name();
            let gcount = self.rng.below((MAX_GENERIC_PARAMS + 1) as u64) as usize;
            let gparams: Vec<String> = (0..gcount).map(|i| format!("T{i}")).collect();
            let mut body_pool = pool.clone();
            for g in &gparams {
                body_pool.push((g.clone(), 0));
            }
            let mut budget = MAX_NODES;
            let body = self.build(&body_pool, 0, &mut budget);
            let mut printed = String::new();
            body.write_full(&mut printed);
            let decl = if gparams.is_empty() {
                format!("type {name} = {printed}\n")
            } else {
                format!("type {name}<{}> = {printed}\n", gparams.join(", "))
            };
            self.bytes_made += decl.len();
            out.push_str(&decl);
            pool.push((name.clone(), gcount));
            self.aliases_made += 1;
            *self.region_counts.entry(region).or_insert(0) += 1;
            self.log.push((region, name));
        }
        out
    }

    fn fresh_name(&mut self) -> String {
        let mut tag = String::with_capacity(4);
        for _ in 0..4 {
            let i = self.rng.below(NAME_LETTERS.len() as u64) as usize;
            tag.push(NAME_LETTERS[i] as char);
        }
        let name = format!("{ALIAS_PREFIX}{tag}{}", self.counter);
        self.counter += 1;
        name
    }

    fn leaf(&mut self, pool: &[(String, usize)]) -> TypeExpr {
        if self.rng.below(5) == 0 {
            let g = TYPEOF_GLOBALS[self.rng.below(TYPEOF_GLOBALS.len() as u64) as usize];
            return TypeExpr::Typeof(g.to_string());
        }
        let (name, arity) = pool[self.rng.below(pool.len() as u64) as usize].clone();
        if arity == 0 {
            TypeExpr::Name(name)
        } else {
            let args = (0..arity).map(|_| self.leaf_name(pool)).collect();
            TypeExpr::Generic(name, args)
        }
    }

    fn leaf_name(&mut self, pool: &[(String, usize)]) -> TypeExpr {
        let zero: Vec<&(String, usize)> = pool.iter().filter(|(_, a)| *a == 0).collect();
        let (name, _) = zero[self.rng.below(zero.len() as u64) as usize].clone();
        TypeExpr::Name(name)
    }

    fn build(&mut self, pool: &[(String, usize)], depth: u32, budget: &mut u32) -> TypeExpr {
        if depth >= MAX_DEPTH || *budget == 0 {
            return self.leaf(pool);
        }
        *budget -= 1;
        match self.rng.below(9) {
            0 => TypeExpr::Optional(Box::new(self.build(pool, depth + 1, budget))),
            1 => {
                let k = 2 + self.rng.below(2) as usize;
                TypeExpr::Union(
                    (0..k)
                        .map(|_| self.build(pool, depth + 1, budget))
                        .collect(),
                )
            }
            2 => {
                let k = 2 + self.rng.below(2) as usize;
                TypeExpr::Intersection(
                    (0..k)
                        .map(|_| self.build(pool, depth + 1, budget))
                        .collect(),
                )
            }
            3 => TypeExpr::Array(Box::new(self.build(pool, depth + 1, budget))),
            4 => {
                let k = 1 + self.rng.below(3) as usize;
                let fields = (0..k)
                    .map(|i| (format!("f{i}"), self.build(pool, depth + 1, budget)))
                    .collect();
                TypeExpr::Table(fields)
            }
            5 => TypeExpr::IndexSig(
                Box::new(self.leaf_name(pool)),
                Box::new(self.build(pool, depth + 1, budget)),
            ),
            6 => {
                let k = self.rng.below(3) as usize;
                let params = (0..k)
                    .map(|_| self.build(pool, depth + 1, budget))
                    .collect();
                let variadic = if self.rng.below(2) == 0 {
                    Some(Box::new(self.leaf(pool)))
                } else {
                    None
                };
                TypeExpr::Function {
                    params,
                    variadic,
                    ret: Box::new(self.build(pool, depth + 1, budget)),
                }
            }
            _ => self.leaf(pool),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(ink: &mut TypeInk) -> String {
        let mut s = String::new();
        for r in ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"] {
            s.push_str(&ink.aliases(r, 3));
        }
        s
    }

    #[test]
    fn deterministic_for_a_seed() {
        let mut a = TypeInk::new(42);
        let mut b = TypeInk::new(42);
        assert_eq!(all(&mut a), all(&mut b));
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = TypeInk::new(1);
        let mut b = TypeInk::new(2);
        assert_ne!(all(&mut a), all(&mut b));
    }

    #[test]
    fn respects_alias_and_byte_budgets() {
        let mut ink = TypeInk::new(7);
        for i in 0..100 {
            let r: &'static str = Box::leak(format!("R{i}").into_boxed_str());
            ink.aliases(r, 4);
        }
        assert!(ink.aliases_made() <= MAX_ALIASES, "alias cap");
        assert!(
            ink.bytes_made <= MAX_TOTAL_BYTES + 512,
            "byte budget near cap"
        );
    }

    #[test]
    fn per_region_cap_enforced() {
        let mut ink = TypeInk::new(9);
        let out = ink.aliases("one", 1000);
        let count = out.matches("type ").count();
        assert!(count <= PER_REGION_CAP, "per-region cap: {count}");
    }

    #[test]
    fn every_alias_is_a_type_statement_and_balanced() {
        let mut ink = TypeInk::new(314);
        let out = all(&mut ink);
        assert!(out.contains("type "));
        for line in out.lines() {
            assert!(line.starts_with("type "), "line is a type alias: {line}");
            let cleaned = line.replace("->", "");
            let opens = cleaned.matches(['(', '{', '<']).count();
            let closes = cleaned.matches([')', '}', '>']).count();
            assert_eq!(opens, closes, "balanced delimiters: {line}");
        }
    }

    #[test]
    fn regions_tracked() {
        let mut ink = TypeInk::new(55);
        all(&mut ink);
        assert_eq!(ink.regions_used(), 8);
        assert_eq!(ink.log.len(), ink.aliases_made());
    }
}
