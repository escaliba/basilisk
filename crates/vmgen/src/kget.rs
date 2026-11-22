use std::collections::HashSet;

use crate::rng::Rng;

fn skeleton(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push('S');
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push('N');
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push('I');
        } else if c.is_ascii_whitespace() {
            i += 1;
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}

fn accessor(name: &str, rng: &mut Rng, d1: bool, state_b: bool) -> String {
    let cache_variant = rng.below(3);
    let use_idx = rng.below(2) == 0;
    let idx = if use_idx { "idx" } else { "i - 1" };
    let stage_tok = rng.below(2) == 0;
    let ce_ep = "bxor(kc[-2] or 0, kc[-1] or 0)";
    let d1_ep = if state_b {
        "bxor(fmix(kc[-4]), kc[-10] or 0)"
    } else {
        "kc[-4]"
    };
    let ep_expr: String = if d1 {
        format!("((i <= (kc[-5] or 0)) and {d1_ep} or ({ce_ep}))")
    } else {
        ce_ep.to_string()
    };
    let use_ep = rng.below(2) == 0;
    let ep: String = if d1 || use_ep {
        "ep".to_string()
    } else {
        ep_expr.clone()
    };
    let cache = if d1 {
        match cache_variant {
            0 => "local hit = mc[i]\nif hit ~= nil and ms[i] == ep then\nreturn hit\nend",
            1 => "if mc[i] ~= nil and ms[i] == ep then\nreturn mc[i]\nend",
            _ => "local cv = mc[i]\nif cv ~= nil and ms[i] == ep then\nreturn cv\nend",
        }
    } else {
        match cache_variant {
            0 => "local hit = kc[i]\nif hit ~= nil then\nreturn hit\nend",
            1 => "if kc[i] ~= nil then\nreturn kc[i]\nend",
            _ => "local cv = kc[i]\nif cv ~= nil then\nreturn cv\nend",
        }
    };
    let extract = match rng.below(3) {
        0 => "local t1, t2, t3, t4, t5, t6, t7, t8 = byte(plain, 1, 8)\nlocal slo = t1 + t2 * 256 + t3 * 65536 + t4 * 16777216\nlocal shi = t5 + t6 * 256 + t7 * 65536 + t8 * 16777216".to_string(),
        1 => "local slo = byte(plain, 1) + byte(plain, 2) * 256 + byte(plain, 3) * 65536 + byte(plain, 4) * 16777216\nlocal shi = byte(plain, 5) + byte(plain, 6) * 256 + byte(plain, 7) * 65536 + byte(plain, 8) * 16777216".to_string(),
        _ => "local slo, shi = unpacks(\"<I4I4\", plain)".to_string(),
    };
    let tag = format!("local clo, chi = keyedTag(pkey, {idx}, site, sub(plain, 9))");
    let stage6 = match rng.below(2) {
        0 => format!("{extract}\n{tag}"),
        _ => format!("{tag}\n{extract}"),
    };
    let compare = match rng.below(4) {
        0 => "clo ~= slo or chi ~= shi",
        1 => "slo ~= clo or shi ~= chi",
        2 => "chi ~= shi or clo ~= slo",
        _ => "shi ~= chi or slo ~= clo",
    };
    let pn = if rng.below(2) == 0 { "poison" } else { "pz" };
    let (p1a, p1b) = if rng.below(2) == 0 {
        ("clo", "slo")
    } else {
        ("slo", "clo")
    };
    let (p2a, p2b) = if rng.below(2) == 0 {
        ("chi", "shi")
    } else {
        ("shi", "chi")
    };
    let type_form = rng.below(2);
    let str_test = if type_form == 0 {
        "byte(plain, 9) == 1"
    } else {
        "1 == byte(plain, 9)"
    };
    let dense_test = if type_form == 0 {
        "byte(plain, 9) == 2"
    } else {
        "2 == byte(plain, 9)"
    };
    let bump = if rng.below(2) == 0 {
        "kc[0] = (kc[0] or 0) + 1"
    } else {
        "kc[0] = 1 + (kc[0] or 0)"
    };
    let flush_keep = if d1 {
        "k ~= -1 and k ~= -2 and k ~= -3 and k ~= -4 and k ~= -5"
    } else {
        "k ~= -1 and k ~= -2 and k ~= -3"
    };

    let mut out = format!("local function {name}(consts, i, pkey, kc, ktok)\n");
    if d1 {
        out.push_str(&format!(
            "local mc = kc[-6]\nlocal ms = kc[-9]\nlocal ep = {ep_expr}\n"
        ));
    }
    out.push_str(&format!("{cache}\n"));
    if use_idx {
        out.push_str("local idx = i - 1\n");
    }
    if stage_tok {
        out.push_str(&format!(
            "local rt = ktok and ktok[i] or 0\nlocal site = psite(rt, kc[-3], {idx})\n"
        ));
    } else {
        out.push_str(&format!(
            "local site = psite(ktok and ktok[i] or 0, kc[-3], {idx})\n"
        ));
    }
    if !d1 && use_ep {
        out.push_str(&format!("local ep = {ep_expr}\n"));
    }
    out.push_str(&format!(
        "local plain = streamXor(pkey, {{ {idx}, {ep}, site }}, consts[i])\n"
    ));
    out.push_str(&stage6);
    out.push('\n');
    out.push_str(&format!(
        "if {compare} then\ndead = true\nlocal {pn} = bxor({p1a}, {p1b})\nif {pn} == 0 then {pn} = bxor({p2a}, {p2b}) end\nkc[-1] = {pn}\nreturn 0\nend\n"
    ));
    let store_tail = if d1 {
        format!(
            "if {str_test} then\nreturn sub(plain, 10)\nend\nlocal _v\nif {dense_test} then\n_v = dvar(plain)\nelse\n_v = (unpacks(sD, plain, 10))\nend\nlocal mo = kc[-7]\nlocal mp = kc[-8]\nlocal old = mo[mp]\nif old ~= nil then mc[old] = nil ms[old] = nil end\nmo[mp] = i\nkc[-8] = (mp % KMCAP) + 1\nmc[i] = _v\nms[i] = ep\nreturn _v\nend"
        )
    } else {
        format!(
            "if {str_test} then\nreturn sub(plain, 10)\nend\nif (kc[0] or 0) >= KCAP then\nfor k in pairs(kc) do\nif {flush_keep} then\nkc[k] = nil\nend\nend\nend\nif {dense_test} then\nkc[i] = dvar(plain)\nelse\nkc[i] = (unpacks(sD, plain, 10))\nend\n{bump}\nreturn kc[i]\nend"
        )
    };
    out.push_str(&store_tail);
    out
}

pub fn generate(seed: u64, d1: bool, state_b: bool) -> (String, String) {
    let mut rng = Rng::new(seed ^ 0x_4B47_4E44_4546);
    let n = 3 + rng.below(3) as usize;
    let mut defs: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    while names.len() < n {
        let name = format!("kg{}", names.len() + 1);
        let body = accessor(&name, &mut rng, d1, state_b);
        if seen.insert(skeleton(&body)) {
            defs.push(body);
            names.push(name);
        }
    }
    rng.shuffle(&mut names);
    let dvar = "local function dvar(p, u, m, q, b)\nu, m, q = 0, 1, 10\nwhile true do\nb = byte(p, q)\nq = q + 1\nu = u + (b % 128) * m\nif b < 128 then break end\nm = m * 128\nend\nif u % 2 == 0 then return u // 2 end\nreturn -((u + 1) // 2)\nend";
    let prefix = if d1 { "local KMCAP = 32\n" } else { "" };
    (
        format!("{prefix}{dvar}\n{}", defs.join("\n")),
        names.join(", "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_accessor_is_independent_and_shapes_are_distinct() {
        let mut all_skeletons: HashSet<String> = HashSet::new();
        for seed in 0..64u64 {
            let mut rng = Rng::new(seed ^ 0x_4B47_4E44_4546);
            let n = 3 + rng.below(3) as usize;
            let mut per_build: HashSet<String> = HashSet::new();
            for k in 0..n {
                let body = accessor(&format!("kg{}", k + 1), &mut rng, false, false);
                assert_eq!(
                    body.matches("streamXor(pkey").count(),
                    1,
                    "one decrypt per accessor: {body}"
                );
                assert_eq!(
                    body.matches("keyedTag(pkey").count(),
                    1,
                    "one keyed tag per accessor"
                );
                assert_eq!(
                    body.matches("psite(").count(),
                    1,
                    "one site patch per accessor"
                );
                assert!(!body.contains("kget"), "no forwarding to a central kget");
                assert!(
                    body.contains("kc[-1] =") && body.contains("dead = true"),
                    "poison + fail-closed present"
                );
                assert!(
                    body.contains("k ~= -1 and k ~= -2 and k ~= -3"),
                    "metadata slots preserved in evict"
                );
                per_build.insert(skeleton(&body));
            }
            assert!(
                per_build.len() >= 3,
                "at least 3 distinct accessor skeletons per build (seed {seed}): {}",
                per_build.len()
            );
            all_skeletons.extend(per_build);
        }
        assert!(
            all_skeletons.len() >= 5,
            "at least 5 distinct accessor skeletons across seeds: {}",
            all_skeletons.len()
        );
    }

    #[test]
    fn non_d1_emits_no_metadata_cache() {
        for seed in 0..48u64 {
            let (defs, _) = generate(seed, false, false);
            assert!(
                !defs.contains("KMCAP"),
                "non-D1 must not emit the metadata cache (seed {seed})"
            );
            assert!(
                !defs.contains("kc[-6]"),
                "non-D1 must not touch slot -6 (seed {seed})"
            );
            assert!(
                !defs.contains("kc[-7]") && !defs.contains("kc[-8]"),
                "non-D1 must not use ring slots (seed {seed})"
            );
        }
    }

    #[test]
    fn d1_number_consts_use_separate_bounded_cache_not_kcap_flush() {
        for seed in 0..48u64 {
            let mut rng = Rng::new(seed ^ 0x_4B47_4E44_4546);
            let n = 3 + rng.below(3) as usize;
            for k in 0..n {
                let body = accessor(&format!("kg{}", k + 1), &mut rng, true, false);
                assert_eq!(
                    body.matches("streamXor(pkey").count(),
                    1,
                    "one decrypt per accessor (D1)"
                );
                assert_eq!(
                    body.matches("keyedTag(pkey").count(),
                    1,
                    "one keyed tag per accessor (D1)"
                );
                assert!(
                    body.contains("kc[-1] =") && body.contains("dead = true"),
                    "D1 fail-closed preserved"
                );
                assert!(
                    body.contains("local mc = kc[-6]"),
                    "D1 uses the separate metadata cache"
                );
                assert!(
                    body.contains("local ms = kc[-9]"),
                    "D1 tracks the qualifying block state"
                );
                assert!(
                    body.contains("and ms[i] == ep"),
                    "D1 warm reuse is state-qualified"
                );
                assert!(
                    body.contains("ms[i] = ep"),
                    "D1 populate records the authenticated block state"
                );
                assert!(
                    !body.contains("kc[i] = dvar(plain)"),
                    "D1 numbers must NOT store into the KCAP cache"
                );
                assert!(
                    !body.contains(">= KCAP"),
                    "D1 accessor must not run the KCAP full-flush"
                );
                assert!(
                    !body.contains("kc[0] ="),
                    "D1 accessor must not bump the ordinary KCAP counter"
                );
                assert!(
                    body.contains("kc[-8] = (mp % KMCAP) + 1"),
                    "D1 uses a bounded ring index"
                );
                assert!(
                    body.contains("if old ~= nil then mc[old] = nil ms[old] = nil end"),
                    "D1 evicts value+state on ring overwrite (bounded)"
                );
            }
            let (defs, _) = generate(seed, true, false);
            assert!(
                defs.contains("local KMCAP = 32"),
                "D1 emits the bounded capacity (seed {seed})"
            );
        }
    }
}
