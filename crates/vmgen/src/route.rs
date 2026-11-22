use std::collections::HashSet;

use crate::rng::Rng;

const SCHEME_SALT: u64 = 0x4833_524F_5554_4533;

const RSALT_DOMAIN: u32 = 0x9E37_79B9;

pub(crate) fn derive_rsalt(g: &[u32; 8]) -> u32 {
    g[0] ^ g[3].rotate_left(11) ^ g[6].rotate_left(19) ^ RSALT_DOMAIN
}

const ARITH: &[&str] = &["+", "-", "*", "/", "%", "^", "//", ".."];
const COMPARE: &[&str] = &["==", "~=", "<", "<=", ">", ">="];
const UNARY: &[(&str, &str)] = &[("neg", "-x"), ("not", "not x"), ("len", "#x")];
const PRED: &[(&str, &str)] = &[("truthy", "not not x"), ("falsy", "not x")];

const BIN_NAMES: [&str; 4] = ["or2a", "or2b", "or2c", "or2d"];
const UN_NAME: &str = "or1a";

pub(crate) fn un_key(prefix: &str) -> &'static str {
    match prefix {
        "-" => "neg",
        "not " => "not",
        "#" => "len",
        _ => unreachable!("unknown unary prefix"),
    }
}

struct Shard {
    name: &'static str,
    params: &'static str,
    rot: u32,
    arms: Vec<(u32, String)>,
    else_expr: String,
    topo: u8,
}

pub(crate) struct RouteScheme {
    shards: Vec<Shard>,
    assign: Vec<(&'static str, usize, u32)>,
    rsalt: u32,
    seed: u64,
}

fn fresh(rng: &mut Rng, used: &mut HashSet<u32>) -> u32 {
    loop {
        let c = rng.next() as u32;
        if c != 0 && used.insert(c) {
            return c;
        }
    }
}

impl RouteScheme {
    pub(crate) fn new(seed: u64, rsalt: u32) -> Self {
        let mut rng = Rng::new(seed ^ SCHEME_SALT);
        let mut used: HashSet<u32> = HashSet::new();

        let bin_exprs: Vec<(&'static str, String)> = ARITH
            .iter()
            .chain(COMPARE.iter())
            .map(|op| (*op, format!("x {op} y")))
            .collect();
        let un_exprs: Vec<(&'static str, String)> = UNARY
            .iter()
            .chain(PRED.iter())
            .map(|(k, e)| (*k, e.to_string()))
            .collect();

        let mut order: Vec<usize> = (0..bin_exprs.len()).collect();
        rng.shuffle(&mut order);
        let nbin = 2 + rng.below(3) as usize;

        let mut shards: Vec<Shard> = Vec::new();
        let mut assign: Vec<(&'static str, usize, u32)> = Vec::new();

        let total = order.len();
        let base = total / nbin;
        let rem = total % nbin;
        let mut lo = 0usize;
        for si in 0..nbin {
            let len = base + if si < rem { 1 } else { 0 };
            let chunk = &order[lo..lo + len];
            lo += len;
            let mut arms: Vec<(u32, String)> = Vec::new();
            for &ki in chunk.iter() {
                let (key, expr) = &bin_exprs[ki];
                let t = fresh(&mut rng, &mut used);
                assign.push((key, si, t));
                arms.push((t, expr.clone()));
            }
            let decoy_count = rng.below(2);
            for _ in 0..=decoy_count {
                let e = &bin_exprs[rng.below(bin_exprs.len() as u64) as usize].1;
                arms.push((fresh(&mut rng, &mut used), e.clone()));
            }
            rng.shuffle(&mut arms);
            let rot = 1 + rng.below(31) as u32;
            let else_expr = bin_exprs[rng.below(bin_exprs.len() as u64) as usize]
                .1
                .clone();
            let topo = rng.below(2) as u8;
            shards.push(Shard {
                name: BIN_NAMES[si],
                params: "x, y",
                rot,
                arms,
                else_expr,
                topo,
            });
        }
        debug_assert_eq!(
            lo, total,
            "binary route partition must cover every op exactly once"
        );

        let si = shards.len();
        let mut arms: Vec<(u32, String)> = Vec::new();
        for (key, expr) in &un_exprs {
            let t = fresh(&mut rng, &mut used);
            assign.push((key, si, t));
            arms.push((t, expr.clone()));
        }
        let decoy_count = rng.below(2);
        for _ in 0..=decoy_count {
            let e = &un_exprs[rng.below(un_exprs.len() as u64) as usize].1;
            arms.push((fresh(&mut rng, &mut used), e.clone()));
        }
        rng.shuffle(&mut arms);
        let rot = 1 + rng.below(31) as u32;
        let else_expr = un_exprs[rng.below(un_exprs.len() as u64) as usize]
            .1
            .clone();
        let topo = rng.below(2) as u8;
        shards.push(Shard {
            name: UN_NAME,
            params: "x",
            rot,
            arms,
            else_expr,
            topo,
        });

        RouteScheme {
            shards,
            assign,
            rsalt,
            seed,
        }
    }

    pub(crate) fn route(&self, key: &str) -> (&'static str, u32) {
        let &(_, si, real) = self
            .assign
            .iter()
            .find(|(k, _, _)| *k == key)
            .expect("route key");
        let sh = &self.shards[si];
        (sh.name, (real ^ self.rsalt).rotate_right(sh.rot))
    }

    pub(crate) fn helpers(&self) -> String {
        let mut s = String::new();
        for sh in &self.shards {
            s.push_str(&format!(
                "local function {}(m, {})\nlocal r = bxor(lrotate(m, {}), RSALT)\n",
                sh.name, sh.params, sh.rot
            ));
            if sh.topo == 1 && sh.arms.len() >= 2 {
                let mid = sh.arms.len() / 2;
                for group in [&sh.arms[..mid], &sh.arms[mid..]] {
                    for (i, (tok, expr)) in group.iter().enumerate() {
                        let kw = if i == 0 { "if" } else { "elseif" };
                        s.push_str(&format!("{kw} r == {tok} then return {expr}\n"));
                    }
                    s.push_str("end\n");
                }
                s.push_str(&format!("return {}\nend\n", sh.else_expr));
            } else {
                for (i, (tok, expr)) in sh.arms.iter().enumerate() {
                    let kw = if i == 0 { "if" } else { "elseif" };
                    s.push_str(&format!("{kw} r == {tok} then return {expr}\n"));
                }
                s.push_str(&format!("else return {}\nend\nend\n", sh.else_expr));
            }
        }
        let mut hrng = Rng::new(self.seed ^ 0x_484C_5052_5F53_5447);
        s.push_str(match hrng.below(2) {
            0 => "local function h_g(k)\nreturn genv[k]\nend\n",
            _ => "local function h_g(k)\nlocal _v = genv[k]\nreturn _v\nend\n",
        });
        s.push_str(match hrng.below(2) {
            0 => "local function h_gs(k, v)\ngenv[k] = v\nend\n",
            _ => "local function h_gs(k, v)\nlocal _x = v\ngenv[k] = _x\nend\n",
        });
        s.push_str(match hrng.below(2) {
            0 => "local function h_self(o, k)\nreturn o[k], o\nend\n",
            _ => "local function h_self(o, k)\nlocal _m = o[k]\nreturn _m, o\nend\n",
        });
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_bin(key: &str) -> bool {
        ARITH.contains(&key) || COMPARE.contains(&key)
    }

    #[test]
    fn shards_cover_every_op() {
        let mut widths = HashSet::new();
        for seed in 0..96u64 {
            let rs = RouteScheme::new(seed, 0x1357_9BDF);
            let nbin = rs.shards.len() - 1;
            widths.insert(nbin);
            assert!(
                (2..=4).contains(&nbin),
                "seed {seed}: {nbin} binary shards outside [2,4]"
            );
            for op in ARITH.iter().chain(COMPARE.iter()) {
                let hits = rs.assign.iter().filter(|(k, _, _)| k == op).count();
                assert_eq!(
                    hits, 1,
                    "seed {seed}: binary op {op} assigned {hits}x (must be exactly once)"
                );
            }
            for (k, _, _) in &rs.assign {
                if is_bin(k) {
                    continue;
                }
                assert_eq!(
                    rs.assign.iter().filter(|(j, _, _)| j == k).count(),
                    1,
                    "seed {seed}: unary {k} once"
                );
            }
            for si in 0..nbin {
                let held = rs
                    .assign
                    .iter()
                    .filter(|(k, s, _)| *s == si && is_bin(k))
                    .count();
                assert!(
                    held < ARITH.len() + COMPARE.len(),
                    "seed {seed}: shard {si} holds every binary op"
                );
                assert!(
                    held >= 1,
                    "seed {seed}: shard {si} empty (partition must be non-degenerate)"
                );
            }
        }
        assert!(
            widths.len() >= 2,
            "binary shard count must vary across seeds: {widths:?}"
        );
    }

    #[test]
    fn topology_is_deterministic() {
        let helpers: Vec<String> = (0..48u64)
            .map(|s| RouteScheme::new(s, 0x9E37_79B9).helpers())
            .collect();
        let uniq: HashSet<&String> = helpers.iter().collect();
        assert!(
            uniq.len() >= 8,
            "route helper bodies must diversify: {} distinct",
            uniq.len()
        );
        for h in &helpers {
            assert!(
                h.contains("bxor(lrotate(m,"),
                "every shard keeps the RSALT-masked decode"
            );
            assert!(h.contains("local function or1a("), "unary shard preserved");
        }
        assert_eq!(
            RouteScheme::new(21, 0x1122).helpers(),
            RouteScheme::new(21, 0x1122).helpers(),
            "route helpers deterministic per (seed, rsalt)"
        );
    }
}
