use std::collections::HashSet;

use bytecode::encoding::Encoding;
use bytecode::kepoch::KepochMode;
use bytecode::opcode::Opcode;

use crate::litgen;
use crate::model::{self, HANDLERS};
use crate::rng::Rng;
use crate::route::RouteScheme;

pub(crate) const BAD_OP: &str = "dead = true return";

fn direct(body: &str) -> String {
    if crate::inline_access::enabled() {
        crate::inline_access::rewrite(body)
    } else {
        body.to_string()
    }
}

pub const RECORD_SLOT_KEYS: [&str; 11] = [
    "KOP", "KA", "KB", "KC", "KOPS", "KIS", "KIX", "KOPEN", "KR", "KIDX", "KV",
];

#[cfg(test)]
pub fn generate(
    enc: &Encoding,
    seed: u64,
    rsalt: u32,
    used: &HashSet<Opcode>,
    hard_dispatch: bool,
    surface: bool,
    kmode: KepochMode,
    prof: bool,
    uh: bool,
    gen_cat: &bytecode::gensuper::GenCatalogue,
) -> (String, String, String, String) {
    generate_profiled(
        enc,
        seed,
        rsalt,
        used,
        hard_dispatch,
        surface,
        kmode,
        prof,
        uh,
        gen_cat,
    )
}

pub fn generate_profiled(
    enc: &Encoding,
    seed: u64,
    rsalt: u32,
    used: &HashSet<Opcode>,
    hard_dispatch: bool,
    surface: bool,
    kmode: KepochMode,
    prof: bool,
    uh: bool,
    gen_cat: &bytecode::gensuper::GenCatalogue,
) -> (String, String, String, String) {
    let mut rng = Rng::new(seed);

    let scheme = RouteScheme::new(seed, rsalt);
    let mut bodies: Vec<(u8, String)> = HANDLERS
        .iter()
        .filter(|h| used.contains(&h.op))
        .map(|h| {
            let body = model::mutate(&h.body, &mut rng, &scheme, uh);
            (
                enc.phys(h.op),
                direct(&crate::kepoch::wrap(h.op, &body, kmode, seed)),
            )
        })
        .collect();
    for (sop, _) in bytecode::superop::CATALOGUE {
        if used.contains(sop) {
            let body = if *sop == bytecode::opcode::Opcode::FlatStateEq {
                model::flat_state_eq_body(&mut rng, &scheme, prof)
            } else {
                model::super_body(*sop, &mut rng, &scheme, uh)
            };
            bodies.push((enc.phys(*sop), direct(&body)));
        }
    }
    if used.contains(&bytecode::opcode::Opcode::GenSuper) {
        let mut arms = String::new();
        for (i, topo) in gen_cat.slots.iter().enumerate() {
            let body = crate::gensuper::gen_topo_body(topo).unwrap_or_else(|| BAD_OP.to_string());
            let kw = if i == 0 { "if" } else { "elseif" };
            arms.push_str(&format!("{kw} a == {i} then\n{body}\n"));
        }
        if arms.is_empty() {
            arms.push_str("do end");
        } else {
            arms.push_str("end");
        }
        bodies.push((enc.phys(bytecode::opcode::Opcode::GenSuper), direct(&arms)));
    }

    for (syn, base) in bytecode::opcode::SYNONYMS {
        if used.contains(syn) {
            let base_body = &HANDLERS
                .iter()
                .find(|h| h.op == *base)
                .expect("synonym base handler")
                .body;
            let body = model::mutate(base_body, &mut rng, &scheme, uh);
            bodies.push((
                enc.phys(*syn),
                direct(&crate::kepoch::wrap(*syn, &body, kmode, seed)),
            ));
        }
    }
    let (mut entries, route_of, prefix): (Vec<(u8, &str)>, Option<[u8; 256]>, String) =
        if hard_dispatch {
            let concretes: Vec<u8> = bodies.iter().map(|(c, _)| *c).collect();
            let mut routes = concretes.clone();
            rng.shuffle(&mut routes);
            let mut route_of = [0u8; 256];
            for (&c, &r) in concretes.iter().zip(routes.iter()) {
                route_of[c as usize] = r;
            }
            let entries = bodies
                .iter()
                .map(|(c, b)| (route_of[*c as usize], b.as_str()))
                .collect();
            (entries, Some(route_of), "op = ROUTE[op]\n".to_string())
        } else {
            let entries = bodies.iter().map(|(v, b)| (*v, b.as_str())).collect();
            (entries, None, String::new())
        };
    entries.sort_by_key(|e| e.0);

    let route_decls = match route_of {
        None => String::new(),
        Some(route_of) => {
            let mut concretes: Vec<u8> = bodies.iter().map(|(c, _)| *c).collect();
            concretes.sort_unstable();
            if surface {
                let mut rrng = Rng::new(seed ^ 0x_524F_5554_4534_41);
                let mut pairs: Vec<(u8, u8)> = concretes
                    .iter()
                    .map(|&c| (c, route_of[c as usize]))
                    .collect();
                rrng.shuffle(&mut pairs);
                let lines: Vec<String> = pairs
                    .iter()
                    .map(|&(c, r)| {
                        format!(
                            "ROUTE[{}] = {}",
                            litgen::num_lit(c, &mut rrng),
                            litgen::num_lit(r, &mut rrng)
                        )
                    })
                    .collect();
                format!("local ROUTE = {{}}\n{}", lines.join("\n"))
            } else {
                let items: Vec<String> = concretes
                    .iter()
                    .map(|&c| format!("[{c}] = {}", route_of[c as usize]))
                    .collect();
                format!("local ROUTE = {{ {} }}", items.join(", "))
            }
        }
    };

    let mut record_keys: Vec<&str> = RECORD_SLOT_KEYS.to_vec();
    if crate::kepoch::on(kmode) {
        record_keys.push(crate::kepoch::SLOT);
    }
    let mut krng = Rng::new(seed ^ 0x_4B4F_505F_534C_5400);
    let mut kvals: Vec<u8> = vec![1, 2, 3, 4];
    krng.shuffle(&mut kvals);
    while kvals.len() < record_keys.len() {
        let v = (krng.below(250) + 5) as u8;
        if !kvals.contains(&v) {
            kvals.push(v);
        }
    }
    let mut kdecl: Vec<(String, String)> = record_keys
        .iter()
        .zip(kvals.iter())
        .map(|(k, &v)| (k.to_string(), litgen::num_lit(v, &mut krng)))
        .collect();
    krng.shuffle(&mut kdecl);
    let key_decls = format!(
        "local {} = {}",
        kdecl
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        kdecl
            .iter()
            .map(|(_, e)| e.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let names: Option<std::collections::HashMap<u8, String>>;
    let label_decls;
    if surface {
        let mut srng = Rng::new(seed ^ 0x_4C55_5241_5346_4345);
        let mut vals: Vec<u8> = entries.iter().map(|e| e.0).collect();
        vals.sort_unstable();
        vals.dedup();
        names = Some(
            vals.iter()
                .enumerate()
                .map(|(i, &v)| (v, format!("dl{i}")))
                .collect(),
        );
        let mut labels: Vec<(String, String)> = vals
            .iter()
            .enumerate()
            .map(|(i, &v)| (format!("dl{i}"), litgen::num_lit(v, &mut srng)))
            .collect();
        srng.shuffle(&mut labels);
        label_decls = format!(
            "local {} = {}",
            labels
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            labels
                .iter()
                .map(|(_, e)| e.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        names = None;
        label_decls = String::new();
    }
    let render = |v: u8| -> String {
        match &names {
            Some(m) => m[&v].clone(),
            None => format!("{v}"),
        }
    };

    let tree = emit(&entries, &mut rng, &render);
    (
        key_decls,
        label_decls,
        route_decls,
        format!("{prefix}{tree}"),
    )
}

fn emit(entries: &[(u8, &str)], rng: &mut Rng, render: &dyn Fn(u8) -> String) -> String {
    let n = entries.len();
    if n <= 1 || (n <= 3 && rng.below(2) == 0) {
        return leaf(entries, rng, render);
    }
    match rng.below(if n >= 5 { 4 } else { 2 }) {
        0 => peel(entries, rng, render),
        1 => range_split(entries, rng, render),
        2 => bisect(entries, rng, render),
        _ => bucket(entries, rng, render),
    }
}

fn peel(entries: &[(u8, &str)], rng: &mut Rng, render: &dyn Fn(u8) -> String) -> String {
    let n = entries.len();
    let idx = rng.below(n as u64) as usize;
    let (val, body) = entries[idx];
    let rest: Vec<(u8, &str)> = entries
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != idx)
        .map(|(_, e)| *e)
        .collect();
    format!(
        "if op == {} then\n{body}\nelse\n{}\nend",
        render(val),
        emit(&rest, rng, render)
    )
}

fn range_split(entries: &[(u8, &str)], rng: &mut Rng, render: &dyn Fn(u8) -> String) -> String {
    let n = entries.len();
    let k = 2 + rng.below((n.min(6) - 1) as u64) as usize;
    let sizes = partition(n, k, rng);
    let mut groups: Vec<&[(u8, &str)]> = Vec::with_capacity(k);
    let mut off = 0;
    for s in &sizes {
        groups.push(&entries[off..off + s]);
        off += s;
    }
    let mut out = String::new();
    for i in 0..k {
        if i == 0 {
            out.push_str(&format!(
                "if op < {} then\n{}\n",
                render(groups[1][0].0),
                emit(groups[0], rng, render)
            ));
        } else if i < k - 1 {
            out.push_str(&format!(
                "elseif op < {} then\n{}\n",
                render(groups[i + 1][0].0),
                emit(groups[i], rng, render)
            ));
        } else {
            out.push_str(&format!("else\n{}\nend", emit(groups[i], rng, render)));
        }
    }
    out
}

fn bisect(entries: &[(u8, &str)], rng: &mut Rng, render: &dyn Fn(u8) -> String) -> String {
    let n = entries.len();
    let base = n / 2;
    let mid = if n >= 6 {
        base + (rng.below(3) as usize).saturating_sub(1)
    } else {
        base
    };
    let mid = mid.clamp(1, n - 1);
    format!(
        "if op < {} then\n{}\nelse\n{}\nend",
        render(entries[mid].0),
        emit(&entries[..mid], rng, render),
        emit(&entries[mid..], rng, render)
    )
}

fn bucket(entries: &[(u8, &str)], rng: &mut Rng, render: &dyn Fn(u8) -> String) -> String {
    let n = entries.len();
    let b = ((n + 6) / 7).clamp(3, 8).min(n);
    let sizes = partition(n, b, rng);
    let mut groups: Vec<&[(u8, &str)]> = Vec::with_capacity(b);
    let mut off = 0;
    for s in &sizes {
        groups.push(&entries[off..off + s]);
        off += s;
    }
    let mut out = String::new();
    for i in 0..b {
        if i == 0 {
            out.push_str(&format!(
                "if op < {} then\n{}\n",
                render(groups[1][0].0),
                leaf(groups[0], rng, render)
            ));
        } else if i < b - 1 {
            out.push_str(&format!(
                "elseif op < {} then\n{}\n",
                render(groups[i + 1][0].0),
                leaf(groups[i], rng, render)
            ));
        } else {
            out.push_str(&format!("else\n{}\nend", leaf(groups[i], rng, render)));
        }
    }
    out
}

fn leaf(entries: &[(u8, &str)], rng: &mut Rng, render: &dyn Fn(u8) -> String) -> String {
    let mut order = entries.to_vec();
    rng.shuffle(&mut order);
    let mut out = String::new();
    for (i, (val, body)) in order.iter().enumerate() {
        let kw = if i == 0 { "if" } else { "elseif" };
        out.push_str(&format!("{kw} op == {} then\n{body}\n", render(*val)));
    }
    out.push_str(&format!("else\n{BAD_OP}\nend"));
    out
}

fn partition(n: usize, k: usize, rng: &mut Rng) -> Vec<usize> {
    let mut sizes = vec![1usize; k];
    for _ in 0..(n - k) {
        let i = rng.below(k as u64) as usize;
        sizes[i] += 1;
    }
    sizes
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecode::opcode::ALL;

    fn all_ops() -> HashSet<Opcode> {
        ALL.iter().map(|(op, _)| *op).collect()
    }

    #[test]
    fn every_opcode_routes_exactly_once() {
        let enc = Encoding::from_seed(123);
        let used = all_ops();
        let (early, labels, route, d) = generate(
            &enc,
            123,
            0,
            &used,
            false,
            false,
            KepochMode::Off,
            false,
            false,
            &bytecode::gensuper::GenCatalogue::default(),
        );
        assert!(
            route.is_empty(),
            "no route decls when surface/hard_dispatch off"
        );
        assert!(labels.is_empty(), "no dl label decls when surface off");
        assert!(
            early.contains("KOP") && early.contains("KOPS"),
            "instruction-slot keys always declared: {early}"
        );
        for h in HANDLERS {
            let needle = format!("op == {} then", enc.phys(h.op));
            assert_eq!(
                d.matches(&needle).count(),
                1,
                "opcode {:?} not routed exactly once",
                h.op
            );
        }
        for (sop, _) in bytecode::superop::CATALOGUE {
            let needle = format!("op == {} then", enc.phys(*sop));
            assert_eq!(
                d.matches(&needle).count(),
                1,
                "super-op {sop:?} not routed exactly once"
            );
        }
        for (syn, _) in bytecode::opcode::SYNONYMS {
            let needle = format!("op == {} then", enc.phys(*syn));
            assert_eq!(
                d.matches(&needle).count(),
                1,
                "synonym {syn:?} not routed exactly once"
            );
        }
        let gp = format!("op == {} then", enc.phys(Opcode::GenSuper));
        assert_eq!(
            d.matches(&gp).count(),
            1,
            "GenSuper not routed exactly once"
        );
        assert_eq!(
            HANDLERS.len()
                + bytecode::superop::CATALOGUE.len()
                + bytecode::opcode::SYNONYMS.len()
                + 1,
            ALL.len()
        );
    }

    #[test]
    fn only_used_ops_are_emitted() {
        let enc = Encoding::from_seed(1);
        let mut used = HashSet::new();
        used.insert(Opcode::Move);
        used.insert(Opcode::Return);
        let (_, _, _, d) = generate(
            &enc,
            1,
            0,
            &used,
            false,
            false,
            KepochMode::Off,
            false,
            false,
            &bytecode::gensuper::GenCatalogue::default(),
        );
        assert_eq!(
            d.matches("op == ").count(),
            2,
            "dispatch must route only the used ops"
        );
    }

    #[test]
    fn hard_dispatch_routes_via_table_not_raw_opcode() {
        let enc = Encoding::from_seed(9);
        let used = all_ops();
        let (_early, _lbl, rt, d) = generate(
            &enc,
            9,
            0,
            &used,
            true,
            false,
            KepochMode::Off,
            false,
            false,
            &bytecode::gensuper::GenCatalogue::default(),
        );
        assert!(
            rt.starts_with("local ROUTE = {"),
            "route table emitted (clean literal when not surface)"
        );
        assert!(
            d.starts_with("op = ROUTE[op]"),
            "dispatch maps op through ROUTE first"
        );
        for (op, _) in ALL {
            assert_eq!(
                rt.matches(&format!("[{}] =", enc.phys(*op))).count(),
                1,
                "ROUTE[{op:?}]"
            );
        }
        assert_eq!(
            generate(
                &enc,
                9,
                0,
                &used,
                true,
                false,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            ),
            generate(
                &enc,
                9,
                0,
                &used,
                true,
                false,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            ),
            "deterministic"
        );
        assert_ne!(
            generate(
                &enc,
                9,
                0,
                &used,
                true,
                false,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            )
            .2,
            generate(
                &enc,
                10,
                0,
                &used,
                true,
                false,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            )
            .2,
            "per-seed routes"
        );
    }

    #[test]
    fn surface_lowers_dispatch_labels_to_symbolic_locals() {
        let enc = Encoding::from_seed(9);
        let used = all_ops();
        let (early, labels, route, d) = generate(
            &enc,
            9,
            0,
            &used,
            true,
            true,
            KepochMode::Off,
            false,
            false,
            &bytecode::gensuper::GenCatalogue::default(),
        );
        assert!(
            labels.starts_with("local ") && labels.contains("dl0"),
            "dl label decl emitted separately (for the makeClosure IIFE)"
        );
        assert!(
            early.starts_with("local ") && early.contains("KOP") && !early.contains("dl0"),
            "record keys emitted in the outer scope, not merged with dl labels"
        );
        assert!(
            !early.contains("KOP, KA, KB, KC, KOPS"),
            "instruction keys must not be a clean five-key tuple"
        );
        assert!(
            route.contains("ROUTE[") && !route.contains("= { ["),
            "route table is constructed, not a clean literal"
        );
        let clean = d
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                (t.starts_with("if op == ")
                    || t.starts_with("elseif op == ")
                    || t.starts_with("if op < ")
                    || t.starts_with("elseif op < "))
                    && t.split_whitespace().nth(3).is_some_and(|w| {
                        w.trim_end_matches(" then")
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_digit())
                    })
            })
            .count();
        assert_eq!(
            clean, 0,
            "no clean decimal route label should remain in surface mode"
        );
        assert!(
            d.contains("op == dl") || d.contains("op < dl"),
            "tree branches on symbolic labels"
        );
        assert_eq!(
            generate(
                &enc,
                9,
                0,
                &used,
                true,
                true,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            ),
            generate(
                &enc,
                9,
                0,
                &used,
                true,
                true,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            ),
            "deterministic"
        );
        assert_ne!(
            generate(
                &enc,
                9,
                0,
                &used,
                true,
                true,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            )
            .1,
            generate(
                &enc,
                11,
                0,
                &used,
                true,
                true,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            )
            .1,
            "per-seed labels"
        );
        let skel = |s: String| {
            s.lines()
                .filter(|l| {
                    l.trim_start().starts_with("if ") || l.trim_start().starts_with("elseif ")
                })
                .count()
        };
        assert_eq!(
            skel(
                generate(
                    &enc,
                    9,
                    0,
                    &used,
                    true,
                    true,
                    KepochMode::Off,
                    false,
                    false,
                    &bytecode::gensuper::GenCatalogue::default()
                )
                .3
            ),
            skel(
                generate(
                    &enc,
                    9,
                    0,
                    &used,
                    true,
                    false,
                    KepochMode::Off,
                    false,
                    false,
                    &bytecode::gensuper::GenCatalogue::default()
                )
                .3
            )
        );
    }

    fn branch_skeleton(d: &str) -> String {
        d.lines()
            .filter_map(|l| {
                let t = l.trim_start();
                if t.starts_with("if op < ") {
                    Some('L')
                } else if t.starts_with("elseif op < ") {
                    Some('l')
                } else if t.starts_with("if op == ") {
                    Some('E')
                } else if t.starts_with("elseif op == ") {
                    Some('e')
                } else if t == "else" {
                    Some('X')
                } else if t == "end" {
                    Some('D')
                } else {
                    None
                }
            })
            .collect()
    }

    fn phys_labels(d: &str) -> std::collections::BTreeSet<u8> {
        d.match_indices("op == ")
            .filter_map(|(i, _)| d[i + 6..].split(|c: char| !c.is_ascii_digit()).next())
            .filter_map(|s| s.parse::<u8>().ok())
            .collect()
    }

    #[test]
    fn dispatch_topology_diversifies_without_fake_or_unreachable_cases() {
        let n = 12u64;
        let trees: Vec<String> = (0..n)
            .map(|s| {
                generate(
                    &Encoding::from_seed(s),
                    s,
                    0,
                    &all_ops(),
                    false,
                    false,
                    KepochMode::Off,
                    false,
                    false,
                    &bytecode::gensuper::GenCatalogue::default(),
                )
                .3
            })
            .collect();
        let skels: Vec<String> = trees.iter().map(|d| branch_skeleton(d)).collect();
        let uniq: HashSet<&String> = skels.iter().collect();
        assert!(
            uniq.len() >= 10,
            "dispatch topology collapses: only {} unique branch skeletons across {n} seeds",
            uniq.len()
        );
        let lens: HashSet<usize> = skels.iter().map(|s| s.len()).collect();
        assert!(
            lens.len() >= 5,
            "branch-skeleton shapes must vary in size across seeds: {} distinct sizes",
            lens.len()
        );

        let enc = Encoding::from_seed(0);
        let real: std::collections::BTreeSet<u8> = HANDLERS
            .iter()
            .map(|h| enc.phys(h.op))
            .chain(
                bytecode::superop::CATALOGUE
                    .iter()
                    .map(|(s, _)| enc.phys(*s)),
            )
            .chain(bytecode::opcode::SYNONYMS.iter().map(|(s, _)| enc.phys(*s)))
            .chain(std::iter::once(enc.phys(Opcode::GenSuper)))
            .collect();
        let (_, _, _, d0) = generate(
            &enc,
            0,
            0,
            &all_ops(),
            false,
            false,
            KepochMode::Off,
            false,
            false,
            &bytecode::gensuper::GenCatalogue::default(),
        );
        assert_eq!(
            phys_labels(&d0),
            real,
            "every dispatch case is a real opcode id; no fabricated/unreachable cases"
        );
        assert!(
            d0.contains(BAD_OP),
            "fail-closed fallthrough is the only sink"
        );
        let assigned: HashSet<u8> = (0..n)
            .map(|s| Encoding::from_seed(s).phys(Opcode::Move))
            .collect();
        assert!(
            assigned.len() > 1,
            "physical opcode-id assignment varies across seeds"
        );
    }

    #[test]
    fn deterministic_and_varies_structurally() {
        let enc = Encoding::from_seed(5);
        let used = all_ops();
        assert_eq!(
            generate(
                &enc,
                5,
                0,
                &used,
                false,
                false,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            ),
            generate(
                &enc,
                5,
                0,
                &used,
                false,
                false,
                KepochMode::Off,
                false,
                false,
                &bytecode::gensuper::GenCatalogue::default()
            )
        );
        let skel = |s: String| {
            s.lines()
                .filter(|l| l.starts_with("if op") || l.starts_with("elseif op"))
                .collect::<Vec<_>>()
                .join("|")
        };
        assert_ne!(
            skel(
                generate(
                    &enc,
                    5,
                    0,
                    &used,
                    false,
                    false,
                    KepochMode::Off,
                    false,
                    false,
                    &bytecode::gensuper::GenCatalogue::default()
                )
                .3
            ),
            skel(
                generate(
                    &enc,
                    6,
                    0,
                    &used,
                    false,
                    false,
                    KepochMode::Off,
                    false,
                    false,
                    &bytecode::gensuper::GenCatalogue::default()
                )
                .3
            )
        );
    }
}
