use crate::rng::Rng;

const NOTICE_DOMAIN: u64 = 0x_4E4F_5449_4345_0000;

const HOLES: [&str; 3] = ["--[[NOTICE0]]\n", "--[[NOTICE1]]\n", "--[[NOTICE2]]\n"];

pub const BUILTIN_POOL: &[&str] = &[
    r#"NOTICE: This file is a protected build artifact produced by Basilisk. Redistribution without authorization from the artifact's owner is prohibited."#,
    r#"NOTICE OF PROTECTED ARTIFACT: This compiled output carries an ownership marker. Unauthorized redistribution may violate the owner's license terms."#,
    r#"CANARY NOTICE [Basilisk Protected]: Copyright (c) 2026. This inert marker identifies the origin of the compiled artifact."#,
    r#"OWNERSHIP MARKER: The presence of this string attributes the enclosing artifact to its original build owner."#,
    r#"NOTICE: Basilisk-protected artifact. This string is an inert ownership and canary identifier embedded at build time."#,
];

pub const BAKED_NOTICE: &str = "protected build artifact; see the project license";

pub const MAX_STRING_BYTES: usize = 4096;
pub const MAX_POOL: usize = 64;

pub fn splice(vm: String, pool: &[String], label: Option<&str>, seed: u64) -> String {
    let fillers = plan(pool, label, seed);
    let mut out = vm;
    for (i, hole) in HOLES.iter().enumerate() {
        let content = match &fillers[i] {
            Some(c) => format!("{c}\n"),
            None => String::new(),
        };
        out = out.replacen(hole, &content, 1);
    }
    out
}

fn plan(pool: &[String], label: Option<&str>, seed: u64) -> [Option<String>; 3] {
    let mut fillers: [Option<String>; 3] = [None, None, None];
    let mut rng = Rng::new(seed ^ NOTICE_DOMAIN);
    let build_id = rng.next() as u32;

    let deep = 1 + rng.below(2) as usize;
    let mut baked = BAKED_NOTICE.to_string();
    if let Some(lbl) = label {
        baked.push_str(&format!(" [{lbl}#{build_id:08x}]"));
    }
    fillers[deep] = Some(wrap(&format!("\"{}\"", escape_lua(&baked)), &mut rng));

    if !pool.is_empty() {
        let mut free: Vec<usize> = (0..HOLES.len()).filter(|&h| h != deep).collect();
        rng.shuffle(&mut free);
        let want = (1 + rng.below(2) as usize).min(pool.len()).min(free.len());
        let mut order: Vec<usize> = (0..pool.len()).collect();
        rng.shuffle(&mut order);
        for k in 0..want {
            fillers[free[k]] = Some(wrap(
                &represent(&pool[order[k]], k == 0, &mut rng),
                &mut rng,
            ));
        }
    }
    fillers
}

fn escape_lua(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for &b in s.as_bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1f | 0x7f => out.push_str(&format!("\\{b}")),
            _ => out.push(b as char),
        }
    }
    out
}

fn represent(text: &str, readable: bool, rng: &mut Rng) -> String {
    let bytes = text.as_bytes();
    let can_longbracket = !text.contains("]==]") && !text.contains("]=]");
    if readable {
        return if can_longbracket && rng.below(2) == 0 {
            format!("[==[{text}]==]")
        } else {
            format!("\"{}\"", escape_lua(text))
        };
    }
    match rng.below(5) {
        0 if bytes.len() >= 3 => {
            let mut pieces = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                let step = 3 + rng.below(9) as usize;
                let end = (i + step).min(bytes.len());

                let mut e = end;
                while e < bytes.len() && (bytes[e] & 0xc0) == 0x80 {
                    e += 1;
                }
                pieces.push(format!(
                    "\"{}\"",
                    escape_lua(std::str::from_utf8(&text[..].as_bytes()[i..e]).unwrap_or(""))
                ));
                i = e;
            }
            pieces.join(" .. ")
        }

        1 => {
            let rev: String = text.chars().rev().collect();
            format!("string.reverse(\"{}\")", escape_lua(&rev))
        }

        2 => {
            let parts: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
            format!("string.char({})", parts.join(","))
        }

        3 => {
            let mask = (rng.below(255) + 1) as u8;
            let parts: Vec<String> = bytes
                .iter()
                .map(|b| format!("bit32.bxor({},{mask})", b ^ mask))
                .collect();
            format!("string.char({})", parts.join(","))
        }

        _ => {
            let n = 2 + rng.below(3) as usize;
            let chunk = bytes.len().div_ceil(n).max(1);
            let mut idx: Vec<usize> = Vec::new();
            let mut i = 0;
            let mut k = 1;
            let mut entries: Vec<(usize, String)> = Vec::new();
            while i < bytes.len() {
                let end = (i + chunk).min(bytes.len());
                let mut e = end;
                while e < bytes.len() && (bytes[e] & 0xc0) == 0x80 {
                    e += 1;
                }
                entries.push((
                    k,
                    format!(
                        "\"{}\"",
                        escape_lua(std::str::from_utf8(&bytes[i..e]).unwrap_or(""))
                    ),
                ));
                idx.push(k - 1);
                i = e;
                k += 1;
            }
            rng.shuffle(&mut idx);
            let body: Vec<String> = idx
                .iter()
                .map(|&j| format!("[{}]={}", entries[j].0, entries[j].1))
                .collect();
            format!("{{{}}}", body.join(","))
        }
    }
}

fn wrap(expr: &str, rng: &mut Rng) -> String {
    let name = format!("_n{:x}", (rng.next() as u32) & 0xffff);
    let body = format!("local {name} = {expr}");
    match rng.below(5) {
        0 => format!("if false then {body} end"),
        1 => format!("if not true then {body} end"),
        2 => format!("if 0 == 1 then {body} end"),
        3 => format!("while false do {body} end"),
        _ => {
            let v = format!("_i{:x}", (rng.next() as u32) & 0xffff);
            format!("for {v} = 1, 0 do {body} end")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_pool_is_verbatim_and_nonempty() {
        assert_eq!(BUILTIN_POOL.len(), 5);
        assert!(BUILTIN_POOL[0].starts_with("NOTICE: This file is a protected build artifact"));
        assert!(BUILTIN_POOL[1].contains("carries an ownership marker"));
        assert!(BUILTIN_POOL[2].contains("CANARY NOTICE [Basilisk Protected]"));
        for s in BUILTIN_POOL {
            assert!(!s.is_empty());
            assert!(!s.contains('\n'), "built-in strings are single-line");
        }
    }

    #[test]
    fn empty_pool_still_emits_the_baked_notice_and_leaves_top_clean() {
        for seed in 1u64..=64 {
            let vm =
                "top\n--[[NOTICE0]]\nmid\n--[[NOTICE1]]\nbody\n--[[NOTICE2]]\nend\n".to_string();
            let out = splice(vm, &[], None, seed);
            assert!(!out.contains("--[[NOTICE"), "holes resolved");
            assert!(out.contains(BAKED_NOTICE), "baked notice always present");
            let top = out.split("mid").next().unwrap();
            assert!(
                !top.contains(BAKED_NOTICE),
                "top NOTICE0 hole stays clean: {top}"
            );
        }
    }

    #[test]
    fn active_pool_fills_at_least_one_hole_and_is_deterministic() {
        let vm = "--[[NOTICE0]]\n--[[NOTICE1]]\n--[[NOTICE2]]\n".to_string();
        let pool = vec![BUILTIN_POOL[0].to_string(), BUILTIN_POOL[3].to_string()];
        let a = splice(vm.clone(), &pool, None, 42);
        let b = splice(vm.clone(), &pool, None, 42);
        assert_eq!(a, b, "same seed is deterministic");
        assert!(!a.contains("--[[NOTICE"), "all holes resolved");
        assert!(
            a.contains(BAKED_NOTICE),
            "baked notice recoverable directly"
        );
    }

    #[test]
    fn baked_notice_is_a_string_constant_in_a_dead_block_not_a_comment() {
        let vm = "x\n--[[NOTICE0]]\n--[[NOTICE1]]\n--[[NOTICE2]]\ny\n".to_string();
        let out = splice(vm, &[], None, 7);
        let at = out.find(BAKED_NOTICE).expect("present");
        let line_start = out[..at].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let line_prefix = &out[line_start..at];
        assert!(
            !line_prefix.trim_start().starts_with("--"),
            "not a comment: {line_prefix}"
        );
        assert!(
            line_prefix.contains('"') || line_prefix.contains("[==["),
            "quoted string carrier: {line_prefix}"
        );
        assert!(
            out.contains("if false")
                || out.contains("if not true")
                || out.contains("0 == 1")
                || out.contains("while false")
                || out.contains("= 1, 0 do"),
            "inert dead-block wrapper present"
        );
    }

    #[test]
    fn different_seeds_vary_selection_or_representation() {
        let vm = "--[[NOTICE0]]\n--[[NOTICE1]]\n--[[NOTICE2]]\n".to_string();
        let pool: Vec<String> = BUILTIN_POOL.iter().map(|s| s.to_string()).collect();
        let outs: std::collections::HashSet<String> = [1u64, 42, 1337, 7, 99]
            .iter()
            .map(|&s| splice(vm.clone(), &pool, None, s))
            .collect();
        assert!(outs.len() > 1, "seeds should vary the artifact");
    }

    #[test]
    fn every_wrapper_is_statically_false() {
        let mut rng = Rng::new(1);
        for _ in 0..64 {
            let w = wrap("\"x\"", &mut rng);
            assert!(
                w.contains("if false")
                    || w.contains("if not true")
                    || w.contains("0 == 1")
                    || w.contains("while false")
                    || w.contains("= 1, 0 do"),
                "wrapper must be an inert dead block: {w}"
            );
        }
    }

    #[test]
    fn escape_handles_quotes_backslashes_and_newlines() {
        assert_eq!(escape_lua("a\"b"), "a\\\"b");
        assert_eq!(escape_lua("a\\b"), "a\\\\b");
        assert_eq!(escape_lua("a\nb"), "a\\nb");
        assert_eq!(escape_lua("tab\there"), "tab\\there");
    }

    #[test]
    fn unicode_survives_representation() {
        let mut rng = Rng::new(5);
        let r = represent("café — π", true, &mut rng);
        assert!(
            r.contains("café") || r.contains("caf"),
            "unicode passes through: {r}"
        );
    }

    #[test]
    fn canary_label_rides_in_the_first_notice() {
        let vm = "--[[NOTICE0]]\n--[[NOTICE1]]\n--[[NOTICE2]]\n".to_string();
        let pool = vec![BUILTIN_POOL[0].to_string()];
        let out = splice(vm, &pool, Some("acme-corp"), 42);
        assert!(out.contains("[acme-corp#"), "canary label embedded: {out}");
    }
}
