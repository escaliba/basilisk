use std::collections::{BTreeSet, HashMap, HashSet};

use crate::rng::Rng;

const KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then", "true", "until", "while", "continue",
];

const FREE_GLOBALS: &[&str] = &["os"];

const RESERVED: &[&str] = &[
    "table",
    "string",
    "bit32",
    "getfenv",
    "select",
    "pairs",
    "error",
    "tostring",
    "type",
    "op",
    "pcall",
    "getgenv",
    "a",
    "b",
    "c",
    "inStack",
    "index",
    "open",
    "r",
    "idx",
    "ops",
    "os",
    "print",
    "next",
    "getmetatable",
];

#[derive(Clone)]
enum Unit {
    Ident(String, bool),
    Raw(String),
    Gap,
    Directive(String),
}

pub fn minify(src: &str, seed: u64, surface: bool) -> String {
    minify_impl(src, Some(seed), surface, false)
}

pub fn minify_lph(src: &str, seed: u64, surface: bool) -> String {
    minify_impl(src, Some(seed), surface, true)
}

pub fn minify_native(src: &str) -> String {
    minify_impl(src, None, false, false)
}

fn minify_impl(src: &str, seed: Option<u64>, surface: bool, lph: bool) -> String {
    let (units, originals, mut renameable) = tokenize(src, surface);
    let units = match seed {
        Some(s) => {
            let units = pack_locals(units);
            let (units, mut tables) = if lph {
                hoist_aggressive(units, s)
            } else {
                let (u, t) = hoist_cold_helpers(units, s);
                (u, t.into_iter().collect::<Vec<_>>())
            };
            let units = if lph {
                let (u, scratch) = scratch_functions(units, s);
                tables.extend(scratch);
                u
            } else {
                units
            };
            for t in tables {
                renameable.insert(t);
            }
            units
        }
        None => units,
    };
    let map: HashMap<&str, String> = match seed {
        Some(s) => {
            let names = generate_names(s, &originals, renameable.len());
            renameable.iter().map(|s| s.as_str()).zip(names).collect()
        }
        None => HashMap::new(),
    };

    let mut out = String::with_capacity(src.len());
    let mut last: Option<char> = None;
    for (idx, u) in units.iter().enumerate() {
        match u {
            Unit::Directive(d) => {
                if last.is_some() && last != Some('\n') {
                    out.push('\n');
                }
                out.push_str(d);
                out.push('\n');
                last = Some('\n');
            }
            Unit::Gap => {
                let next = units[idx + 1..].iter().find_map(|u| first_char(u, &map));
                if let (Some(a), Some(b)) = (last, next) {
                    if a != '\n' && b != '\n' && needs_space(a, b) {
                        out.push(' ');
                        last = Some(' ');
                    }
                }
            }
            Unit::Ident(name, field) => {
                let rename = if *field { None } else { map.get(name.as_str()) };
                let s = rename.map(|s| s.as_str()).unwrap_or(name);
                out.push_str(s);
                last = s.chars().last();
            }
            Unit::Raw(s) => {
                out.push_str(s);
                last = s.chars().last();
            }
        }
    }
    out
}

fn pack_locals(units: Vec<Unit>) -> Vec<Unit> {
    let n = units.len();
    let mut out: Vec<Unit> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        if is_kw(&units[i], "local") {
            if let Some((members, end)) = collect_run(&units, i) {
                if members.len() >= 2 {
                    out.push(Unit::Ident("local".into(), false));
                    out.push(Unit::Gap);
                    for (k, m) in members.iter().enumerate() {
                        if k > 0 {
                            out.push(Unit::Raw(",".into()));
                        }
                        out.push(Unit::Ident(m.name.clone(), false));
                    }
                    out.push(Unit::Raw("=".into()));
                    for (k, m) in members.iter().enumerate() {
                        if k > 0 {
                            out.push(Unit::Raw(",".into()));
                        }
                        out.extend(m.rhs.iter().cloned());
                    }
                    out.push(Unit::Gap);
                    i = end;
                    continue;
                }
                out.extend(units[i..end].iter().cloned());
                i = end;
                continue;
            }
        }
        out.push(units[i].clone());
        i += 1;
    }
    out
}

struct LocalMember {
    name: String,
    rhs: Vec<Unit>,
}

fn collect_run(units: &[Unit], start: usize) -> Option<(Vec<LocalMember>, usize)> {
    let n = units.len();
    let mut members: Vec<LocalMember> = Vec::new();
    let mut declared: Vec<String> = Vec::new();
    let mut pos = start;
    loop {
        if !(pos < n && is_kw(&units[pos], "local")) {
            break;
        }
        let after_local = next_sig(units, pos + 1);
        let name = match units.get(after_local) {
            Some(Unit::Ident(nm, false)) if !KEYWORDS.contains(&nm.as_str()) => nm.clone(),
            _ => break,
        };
        let after_name = next_sig(units, after_local + 1);
        if !(after_name < n && is_raw(&units[after_name], "=")) {
            break;
        }
        let rhs_start = next_sig(units, after_name + 1);
        let rhs_end = match parse_full_rhs(units, rhs_start) {
            Some(e) => e,
            None => break,
        };
        let rhs: Vec<Unit> = units[rhs_start..rhs_end].to_vec();
        let nx = next_sig(units, rhs_end);
        if nx < n && is_continuer(&units[nx]) {
            break;
        }
        if rhs_refs_any(&rhs, &declared) {
            break;
        }
        if rhs_refs_any(&rhs, std::slice::from_ref(&name)) {
            break;
        }
        declared.push(name.clone());
        members.push(LocalMember { name, rhs });
        pos = nx;
        if !(pos < n && is_kw(&units[pos], "local")) {
            break;
        }
    }
    if members.is_empty() {
        None
    } else {
        Some((members, pos))
    }
}

fn match_delim(units: &[Unit], open: usize, o: &str, c: &str) -> Option<usize> {
    let n = units.len();
    let mut depth = 0i32;
    let mut i = open;
    while i < n {
        if let Unit::Raw(s) = &units[i] {
            if s == o {
                depth += 1;
            } else if s == c {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
        }
        i += 1;
    }
    None
}

fn parse_full_rhs(units: &[Unit], start: usize) -> Option<usize> {
    let n = units.len();
    let mut cur = start;
    loop {
        loop {
            let s = next_sig(units, cur);
            if s >= n {
                return None;
            }
            match &units[s] {
                Unit::Ident(nm, false) if nm == "not" => cur = s + 1,
                Unit::Raw(r) if matches!(r.as_str(), "-" | "#" | "~") => cur = s + 1,
                _ => break,
            }
        }
        let s = next_sig(units, cur);
        if s >= n {
            return None;
        }
        match &units[s] {
            Unit::Raw(r) if r == "(" => cur = match_delim(units, s, "(", ")")?,
            Unit::Raw(r) if r == "{" => cur = match_delim(units, s, "{", "}")?,
            Unit::Raw(r) if r.starts_with('"') || r.starts_with('\'') => cur = s + 1,
            Unit::Raw(r) if matches!(r.chars().next(), Some(ch) if ch.is_ascii_digit()) => {
                cur = s + 1
            }
            Unit::Raw(r) if r == "..." => cur = s + 1,
            Unit::Ident(nm, false) if matches!(nm.as_str(), "true" | "false" | "nil") => {
                cur = s + 1
            }
            Unit::Ident(nm, false) if !KEYWORDS.contains(&nm.as_str()) => cur = s + 1,
            _ => return None,
        }
        loop {
            let s = next_sig(units, cur);
            if s >= n {
                break;
            }
            match &units[s] {
                Unit::Raw(r) if r == "." => {
                    let f = next_sig(units, s + 1);
                    if matches!(units.get(f), Some(Unit::Ident(_, _))) {
                        cur = f + 1;
                    } else {
                        return None;
                    }
                }
                Unit::Raw(r) if r == ":" => {
                    let f = next_sig(units, s + 1);
                    if matches!(units.get(f), Some(Unit::Ident(_, _))) {
                        let a = next_sig(units, f + 1);
                        match units.get(a) {
                            Some(Unit::Raw(x)) if x == "(" => {
                                cur = match_delim(units, a, "(", ")")?
                            }
                            _ => return None,
                        }
                    } else {
                        return None;
                    }
                }
                Unit::Raw(r) if r == "[" => cur = match_delim(units, s, "[", "]")?,
                Unit::Raw(r) if r == "(" => cur = match_delim(units, s, "(", ")")?,
                _ => break,
            }
        }
        let s = next_sig(units, cur);
        if s >= n {
            break;
        }
        let binop = match &units[s] {
            Unit::Ident(nm, false) => matches!(nm.as_str(), "and" | "or"),
            Unit::Raw(r) => matches!(
                r.as_str(),
                "+" | "-"
                    | "*"
                    | "/"
                    | "//"
                    | "%"
                    | "^"
                    | ".."
                    | "=="
                    | "~="
                    | "<"
                    | ">"
                    | "<="
                    | ">="
                    | "&"
                    | "|"
                    | "~"
                    | "<<"
                    | ">>"
            ),
            _ => false,
        };
        if binop {
            cur = s + 1;
            continue;
        }
        break;
    }
    Some(cur)
}

const COLD_HOIST: &[&str] = &[
    "b85dec",
    "buildinvmap",
    "checksum",
    "deriveGenKey",
    "deserialize",
    "envProbe",
    "structKey",
    "opmask",
    "opmask2",
    "_pdg",
    "ktoks",
    "ksite",
    "icat",
    "ipatch",
    "h_g",
    "h_gs",
    "h_self",
    "key8",
    "decodeRange",
    "decodeProto",
    "ipatchRange",
    "ktokRange",
    "_vpgpage",
    "_vpg",
    "ensurePages",
    "wireDigest",
];

fn depth_delta(u: &Unit) -> i32 {
    match u {
        Unit::Ident(nm, false) => match nm.as_str() {
            "function" | "do" | "if" | "repeat" => 1,
            "end" | "until" => -1,
            _ => 0,
        },
        _ => 0,
    }
}

fn hoist_cold_helpers(units: Vec<Unit>, seed: u64) -> (Vec<Unit>, Option<String>) {
    let n = units.len();
    let mut present: Vec<String> = Vec::new();
    let mut depth = 0i32;
    for i in 0..n {
        if depth == 1 && is_kw(&units[i], "local") {
            let f = next_sig(&units, i + 1);
            if f < n && is_kw(&units[f], "function") {
                let g = next_sig(&units, f + 1);
                if let Some(Unit::Ident(name, false)) = units.get(g) {
                    if COLD_HOIST.contains(&name.as_str()) && !present.iter().any(|p| p == name) {
                        present.push(name.clone());
                    }
                }
            }
        }
        depth += depth_delta(&units[i]);
    }
    if present.is_empty() {
        return (units, None);
    }
    let mut rng = Rng::new(seed ^ 0x_484F_4953_545F);
    let base = 3 + rng.below(97) as usize;
    let mut slots: Vec<usize> = (0..present.len()).map(|k| base + k * 2).collect();
    for k in (1..slots.len()).rev() {
        let j = rng.below((k + 1) as u64) as usize;
        slots.swap(k, j);
    }
    let slot_of: HashMap<&str, usize> = present.iter().map(|s| s.as_str()).zip(slots).collect();
    let table = "_HOISTTBL";
    let emit_index = |out: &mut Vec<Unit>, slot: usize| {
        out.push(Unit::Ident(table.to_string(), false));
        out.push(Unit::Raw("[".into()));
        out.push(Unit::Raw(slot.to_string()));
        out.push(Unit::Raw("]".into()));
    };
    let mut out: Vec<Unit> = Vec::with_capacity(n + present.len() * 6 + 8);
    let mut depth = 0i32;
    let mut i = 0;
    while i < n {
        if depth == 1 && is_kw(&units[i], "local") {
            let f = next_sig(&units, i + 1);
            if f < n && is_kw(&units[f], "function") {
                let g = next_sig(&units, f + 1);
                if let Some(Unit::Ident(name, false)) = units.get(g) {
                    if let Some(&slot) = slot_of.get(name.as_str()) {
                        emit_index(&mut out, slot);
                        out.push(Unit::Raw("=".into()));
                        out.push(Unit::Ident("function".into(), false));
                        depth += 1;
                        i = g + 1;
                        continue;
                    }
                }
            }
        }
        match &units[i] {
            Unit::Ident(name, false) if slot_of.contains_key(name.as_str()) => {
                emit_index(&mut out, slot_of[name.as_str()]);
            }
            u => out.push(u.clone()),
        }
        depth += depth_delta(&units[i]);
        i += 1;
    }
    if let Some(fi) = out.iter().position(|u| is_kw(u, "function")) {
        let pi = next_sig(&out, fi + 1);
        if let Some(close) = match_delim(&out, pi, "(", ")") {
            let decl = vec![
                Unit::Ident("local".into(), false),
                Unit::Gap,
                Unit::Ident(table.to_string(), false),
                Unit::Raw("=".into()),
                Unit::Raw("{".into()),
                Unit::Raw("}".into()),
                Unit::Gap,
            ];
            out.splice(close..close, decl);
        }
    }
    (out, Some(table.to_string()))
}

fn hoist_aggressive(units: Vec<Unit>, seed: u64) -> (Vec<Unit>, Vec<String>) {
    let (u, t) = hoist_cold_helpers(units, seed);
    (u, t.into_iter().collect())
}

fn decl_names(units: &[Unit], local_idx: usize) -> (Vec<String>, bool, usize) {
    let n = units.len();
    let f = next_sig(units, local_idx + 1);
    if f < n && is_kw(&units[f], "function") {
        let g = next_sig(units, f + 1);
        if let Some(Unit::Ident(nm, false)) = units.get(g) {
            return (vec![nm.clone()], true, f);
        }
        return (vec![], true, f);
    }
    let mut names = Vec::new();
    let mut j = local_idx + 1;
    loop {
        let s = next_sig(units, j);
        match units.get(s) {
            Some(Unit::Ident(nm, false)) if !KEYWORDS.contains(&nm.as_str()) => {
                names.push(nm.clone());
                let c = next_sig(units, s + 1);
                if c < n && is_raw(&units[c], ",") {
                    j = c + 1;
                    continue;
                }
                return (names, false, s + 1);
            }
            _ => return (names, false, j),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum FrameKind {
    Func,
    Block,
    Repeat,
    Loop,
}

struct Frame {
    kind: FrameKind,
    func_fid: usize,
    decls: HashSet<String>,
}

fn scratch_functions(units: Vec<Unit>, seed: u64) -> (Vec<Unit>, Vec<String>) {
    let n = units.len();

    let mut fid_ctr = 0usize;
    let mut stack: Vec<Frame> = vec![Frame {
        kind: FrameKind::Func,
        func_fid: 0,
        decls: HashSet::new(),
    }];
    let mut declared: HashMap<usize, HashSet<String>> = HashMap::new();
    let mut bad: HashMap<usize, HashSet<String>> = HashMap::new();
    let mut stmts: Vec<(usize, Vec<String>)> = Vec::new();
    let mut ref_owner: HashMap<usize, (usize, String)> = HashMap::new();
    let mut decl_in_loop: HashSet<(usize, String)> = HashSet::new();
    declared.insert(0, HashSet::new());
    let cur_fid = |st: &[Frame]| st.last().map(|f| f.func_fid).unwrap_or(0);
    let in_loop = |st: &[Frame]| {
        for fr in st.iter().rev() {
            if fr.kind == FrameKind::Loop || fr.kind == FrameKind::Repeat {
                return true;
            }
            if fr.kind == FrameKind::Func {
                return false;
            }
        }
        false
    };
    let introduce = |st: &mut Vec<Frame>, name: &str, bad: &mut HashMap<usize, HashSet<String>>| {
        let fid = st.last().unwrap().func_fid;
        let mut shadow = false;
        for fr in st.iter().rev() {
            if fr.decls.contains(name) {
                shadow = true;
                break;
            }
            if fr.kind == FrameKind::Func {
                break;
            }
        }
        if shadow {
            bad.entry(fid).or_default().insert(name.to_string());
        }
        st.last_mut().unwrap().decls.insert(name.to_string());
    };
    let mut i = 0;
    let mut pending_for_vars: Option<Vec<String>> = None;
    let mut pending_loop = false;
    let mut brace = 0i32;
    let mut local_fn_pending = false;
    while i < n {
        if is_raw(&units[i], "{") {
            brace += 1;
        } else if is_raw(&units[i], "}") {
            brace -= 1;
        }
        if is_kw(&units[i], "function") {
            if !local_fn_pending {
                let bn_idx = next_sig(&units, i + 1);
                if let Some(Unit::Ident(bn, false)) = units.get(bn_idx) {
                    bad.entry(cur_fid(&stack)).or_default().insert(bn.clone());
                }
            }
            local_fn_pending = false;
            let mut k = i + 1;
            while k < n && !is_raw(&units[k], "(") {
                k += 1;
            }
            fid_ctr += 1;
            let nf = fid_ctr;
            declared.insert(nf, HashSet::new());
            let mut params: Vec<String> = Vec::new();
            let close = match_delim(&units, k, "(", ")").unwrap_or(k + 1);
            let mut j = k + 1;
            while j + 1 < close {
                if let Unit::Ident(nm, false) = &units[j] {
                    if !KEYWORDS.contains(&nm.as_str()) {
                        params.push(nm.clone());
                    }
                }
                j += 1;
            }
            stack.push(Frame {
                kind: FrameKind::Func,
                func_fid: nf,
                decls: HashSet::new(),
            });
            for p in &params {
                introduce(&mut stack, p, &mut bad);

                bad.entry(nf).or_default().insert(p.clone());
            }
            i = close;
            continue;
        }
        if is_kw(&units[i], "local") {
            let (names, isfn, after) = decl_names(&units, i);
            let fid = cur_fid(&stack);

            let bare = !isfn && {
                let s = next_sig(&units, after);
                !(s < n && is_raw(&units[s], "="))
            };

            let self_ref: HashSet<String> = if isfn || bare {
                HashSet::new()
            } else {
                let mut s = HashSet::new();
                let eq = next_sig(&units, after);
                if eq < n && is_raw(&units[eq], "=") {
                    let nameset: HashSet<&str> = names.iter().map(|x| x.as_str()).collect();
                    let mut vstart = eq + 1;
                    loop {
                        match parse_full_rhs(&units, vstart) {
                            Some(vend) => {
                                let vb = next_sig(&units, vstart);
                                if vend > vb {
                                    for u in &units[vb..vend] {
                                        if let Unit::Ident(nm, false) = u {
                                            if nameset.contains(nm.as_str()) {
                                                s.insert(nm.clone());
                                            }
                                        }
                                    }
                                }
                                let nx = next_sig(&units, vend);
                                if nx < n && is_raw(&units[nx], ",") {
                                    vstart = nx + 1;
                                    continue;
                                }
                                break;
                            }
                            None => {
                                for nm in &names {
                                    s.insert(nm.clone());
                                }
                                break;
                            }
                        }
                    }
                }
                s
            };
            let il = in_loop(&stack);
            for nm in &names {
                declared.entry(fid).or_default().insert(nm.clone());
                introduce(&mut stack, nm, &mut bad);
                if bare || nm == "_HOISTTBL" || self_ref.contains(nm) {
                    bad.entry(fid).or_default().insert(nm.clone());
                }
                if il {
                    decl_in_loop.insert((fid, nm.clone()));
                }
            }
            stmts.push((fid, names));
            local_fn_pending = isfn;
            i = after;
            continue;
        }
        if is_kw(&units[i], "for") {
            let mut names = Vec::new();
            let mut j = i + 1;
            loop {
                let s = next_sig(&units, j);
                match units.get(s) {
                    Some(Unit::Ident(nm, false)) if !KEYWORDS.contains(&nm.as_str()) => {
                        names.push(nm.clone());
                        let c = next_sig(&units, s + 1);
                        if c < n && is_raw(&units[c], ",") {
                            j = c + 1;
                            continue;
                        }
                        break;
                    }
                    _ => break,
                }
            }
            pending_for_vars = Some(names);
            pending_loop = true;
            i += 1;
            continue;
        }
        if is_kw(&units[i], "while") {
            pending_loop = true;
            i += 1;
            continue;
        }
        if is_kw(&units[i], "do") {
            let kind = if pending_loop {
                FrameKind::Loop
            } else {
                FrameKind::Block
            };
            pending_loop = false;
            let fid = cur_fid(&stack);
            stack.push(Frame {
                kind,
                func_fid: fid,
                decls: HashSet::new(),
            });
            if let Some(vars) = pending_for_vars.take() {
                for v in &vars {
                    introduce(&mut stack, v, &mut bad);

                    bad.entry(fid).or_default().insert(v.clone());
                }
            }
            i += 1;
            continue;
        }
        if is_kw(&units[i], "then") {
            let fid = cur_fid(&stack);
            stack.push(Frame {
                kind: FrameKind::Block,
                func_fid: fid,
                decls: HashSet::new(),
            });
            i += 1;
            continue;
        }
        if is_kw(&units[i], "repeat") {
            let fid = cur_fid(&stack);
            stack.push(Frame {
                kind: FrameKind::Repeat,
                func_fid: fid,
                decls: HashSet::new(),
            });
            i += 1;
            continue;
        }
        if is_kw(&units[i], "else") {
            if stack.len() > 1 && stack.last().unwrap().kind != FrameKind::Func {
                stack.pop();
            }
            let fid = cur_fid(&stack);
            stack.push(Frame {
                kind: FrameKind::Block,
                func_fid: fid,
                decls: HashSet::new(),
            });
            i += 1;
            continue;
        }
        if is_kw(&units[i], "elseif") {
            if stack.len() > 1 && stack.last().unwrap().kind != FrameKind::Func {
                stack.pop();
            }
            i += 1;
            continue;
        }
        if is_kw(&units[i], "end") || is_kw(&units[i], "until") {
            if stack.len() > 1 {
                let fr = stack.pop().unwrap();
                if fr.kind == FrameKind::Repeat {
                    for nm in fr.decls {
                        bad.entry(fr.func_fid).or_default().insert(nm);
                    }
                }
            }
            i += 1;
            continue;
        }
        if let Unit::Ident(nm, false) = &units[i] {
            let is_table_key = brace > 0 && {
                let s = next_sig(&units, i + 1);
                s < n && is_raw(&units[s], "=")
            };
            if !KEYWORDS.contains(&nm.as_str()) && !is_table_key {
                let cur = cur_fid(&stack);
                let mut owner = None;
                for fr in stack.iter().rev() {
                    if fr.decls.contains(nm) {
                        owner = Some(fr.func_fid);
                        break;
                    }
                }
                if let Some(o) = owner {
                    ref_owner.insert(i, (o, nm.clone()));
                    if o != cur && decl_in_loop.contains(&(o, nm.clone())) {
                        bad.entry(o).or_default().insert(nm.clone());
                    }
                }
            }
        }
        i += 1;
    }
    let hot_fids: Vec<usize> = declared.keys().copied().collect();
    for fid in hot_fids {
        let e = bad.entry(fid).or_default();
        for h in ["pc", "inst", "op", "a", "top", "R"] {
            e.insert(h.to_string());
        }
    }

    loop {
        let mut changed = false;
        for (fid, names) in &stmts {
            let has_bad = names
                .iter()
                .any(|nm| bad.get(fid).map(|b| b.contains(nm)).unwrap_or(false));
            if has_bad {
                let e = bad.entry(*fid).or_default();
                for nm in names {
                    if e.insert(nm.clone()) {
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut tableizable: HashMap<usize, HashSet<String>> = HashMap::new();
    for (fid, names) in &stmts {
        if names
            .iter()
            .any(|nm| bad.get(fid).map(|b| b.contains(nm)).unwrap_or(false))
        {
            continue;
        }
        let e = tableizable.entry(*fid).or_default();
        for nm in names {
            e.insert(nm.clone());
        }
    }

    let mut stmt_count: HashMap<usize, usize> = HashMap::new();
    for (fid, names) in &stmts {
        if names.iter().all(|nm| {
            tableizable
                .get(fid)
                .map(|t| t.contains(nm))
                .unwrap_or(false)
        }) && !names.is_empty()
        {
            *stmt_count.entry(*fid).or_default() += 1;
        }
    }
    let mut slot_of: HashMap<(usize, String), usize> = HashMap::new();
    let mut sentinel_of: HashMap<usize, String> = HashMap::new();
    let mut scratch_fids: HashSet<usize> = HashSet::new();
    for (fid, names) in &tableizable {
        if stmt_count.get(fid).copied().unwrap_or(0) < 2 {
            continue;
        }
        scratch_fids.insert(*fid);
        sentinel_of.insert(*fid, format!("_SCR_{fid}"));
        let base = 1 + (seed ^ (*fid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) % 61;
        let mut sorted: Vec<&String> = names.iter().collect();
        sorted.sort();
        for (k, nm) in sorted.into_iter().enumerate() {
            slot_of.insert((*fid, nm.clone()), base as usize + k);
        }
    }
    if scratch_fids.is_empty() {
        return (units, Vec::new());
    }

    let mut out: Vec<Unit> = Vec::with_capacity(n + scratch_fids.len() * 8);
    let emit_slot = |out: &mut Vec<Unit>, table: &str, slot: usize| {
        out.push(Unit::Ident(table.to_string(), false));
        out.push(Unit::Raw("[".into()));
        out.push(Unit::Raw(slot.to_string()));
        out.push(Unit::Raw("]".into()));
    };
    let emit_decl = |out: &mut Vec<Unit>, table: &str| {
        out.push(Unit::Ident("local".into(), false));
        out.push(Unit::Gap);
        out.push(Unit::Ident(table.to_string(), false));
        out.push(Unit::Raw("=".into()));
        out.push(Unit::Raw("{".into()));
        out.push(Unit::Raw("}".into()));
        out.push(Unit::Gap);
    };
    let mut fid_ctr2 = 0usize;
    let mut stack2: Vec<usize> = vec![0];
    let cur2 = |st: &[usize]| *st.last().unwrap();
    let mut i = 0;
    while i < n {
        if is_kw(&units[i], "function") {
            let mut k = i + 1;
            while k < n && !is_raw(&units[k], "(") {
                k += 1;
            }
            fid_ctr2 += 1;
            let nf = fid_ctr2;
            let close = match_delim(&units, k, "(", ")").unwrap_or(k + 1);
            for u in &units[i..close] {
                out.push(u.clone());
            }
            if let Some(t) = sentinel_of.get(&nf) {
                emit_decl(&mut out, t);
            }
            stack2.push(nf);
            i = close;
            continue;
        }
        if is_kw(&units[i], "local") {
            let (names, isfn, after) = decl_names(&units, i);
            let fid = cur2(&stack2);
            let all_tbl = !names.is_empty()
                && names
                    .iter()
                    .all(|nm| slot_of.contains_key(&(fid, nm.clone())));
            if scratch_fids.contains(&fid) && all_tbl {
                let table = sentinel_of[&fid].clone();
                if isfn {
                    let slot = slot_of[&(fid, names[0].clone())];
                    emit_slot(&mut out, &table, slot);
                    out.push(Unit::Raw("=".into()));
                    let mut k = after + 1;
                    while k < n && !is_raw(&units[k], "(") {
                        k += 1;
                    }
                    fid_ctr2 += 1;
                    let nf = fid_ctr2;
                    let close = match_delim(&units, k, "(", ")").unwrap_or(k + 1);
                    out.push(Unit::Ident("function".into(), false));
                    for u in &units[k..close] {
                        out.push(u.clone());
                    }
                    if let Some(t) = sentinel_of.get(&nf) {
                        emit_decl(&mut out, t);
                    }
                    stack2.push(nf);
                    i = close;
                    continue;
                } else {
                    for (idx, nm) in names.iter().enumerate() {
                        if idx > 0 {
                            out.push(Unit::Raw(",".into()));
                        }
                        emit_slot(&mut out, &table, slot_of[&(fid, nm.clone())]);
                    }
                    i = after;
                    continue;
                }
            }

            for u in &units[i..after] {
                out.push(u.clone());
            }
            i = after;
            continue;
        }
        if is_kw(&units[i], "for") {
            out.push(units[i].clone());
            i += 1;
            continue;
        }
        if is_kw(&units[i], "do") {
            stack2.push(cur2(&stack2));
            out.push(units[i].clone());
            i += 1;
            continue;
        }
        if is_kw(&units[i], "then") || is_kw(&units[i], "repeat") {
            stack2.push(cur2(&stack2));
            out.push(units[i].clone());
            i += 1;
            continue;
        }
        if is_kw(&units[i], "else") {
            if stack2.len() > 1 {
                stack2.pop();
            }
            stack2.push(cur2(&stack2));
            out.push(units[i].clone());
            i += 1;
            continue;
        }
        if is_kw(&units[i], "elseif") {
            if stack2.len() > 1 {
                stack2.pop();
            }
            out.push(units[i].clone());
            i += 1;
            continue;
        }
        if is_kw(&units[i], "end") || is_kw(&units[i], "until") {
            if stack2.len() > 1 {
                stack2.pop();
            }
            out.push(units[i].clone());
            i += 1;
            continue;
        }
        if let Unit::Ident(_, false) = &units[i] {
            if let Some((owner, name)) = ref_owner.get(&i) {
                if let Some(&slot) = slot_of.get(&(*owner, name.clone())) {
                    emit_slot(&mut out, &sentinel_of[owner], slot);
                    i += 1;
                    continue;
                }
            }
        }
        out.push(units[i].clone());
        i += 1;
    }
    let mut sentinels: Vec<String> = sentinel_of.values().cloned().collect();
    sentinels.sort();
    (out, sentinels)
}

fn is_continuer(u: &Unit) -> bool {
    match u {
        Unit::Ident(name, false) => name == "and" || name == "or",
        Unit::Raw(s) => {
            matches!(
                s.as_str(),
                "." | "["
                    | "("
                    | "{"
                    | ":"
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "//"
                    | "%"
                    | "^"
                    | "#"
                    | ".."
                    | "<"
                    | ">"
                    | "<="
                    | ">="
                    | "=="
                    | "~="
                    | "&"
                    | "|"
                    | "~"
                    | "<<"
                    | ">>"
            ) || s.starts_with('"')
                || s.starts_with('\'')
        }
        _ => false,
    }
}

fn rhs_refs_any(rhs: &[Unit], declared: &[String]) -> bool {
    rhs.iter()
        .any(|u| matches!(u, Unit::Ident(name, false) if declared.iter().any(|d| d == name)))
}

fn next_sig(units: &[Unit], mut i: usize) -> usize {
    while i < units.len() && matches!(units[i], Unit::Gap) {
        i += 1;
    }
    i
}

fn is_kw(u: &Unit, kw: &str) -> bool {
    matches!(u, Unit::Ident(name, false) if name == kw)
}

fn is_raw(u: &Unit, s: &str) -> bool {
    matches!(u, Unit::Raw(r) if r == s)
}

fn first_char(u: &Unit, map: &HashMap<&str, String>) -> Option<char> {
    match u {
        Unit::Ident(name, field) => {
            let s = if *field {
                name.as_str()
            } else {
                map.get(name.as_str()).map(|x| x.as_str()).unwrap_or(name)
            };
            s.chars().next()
        }
        Unit::Raw(s) => s.chars().next(),
        Unit::Directive(_) => Some('\n'),
        Unit::Gap => None,
    }
}

pub(crate) fn needs_space(a: char, b: char) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    (word(a) && word(b))
        || (a == '-' && b == '-')
        || (a == '[' && b == '[')
        || (a.is_ascii_digit() && b == '.')
}

pub(crate) fn append_sep(out: &mut String, frag: &str) {
    if let (Some(a), Some(b)) = (out.chars().last(), frag.chars().next()) {
        if needs_space(a, b) {
            out.push(' ');
        }
    }
    out.push_str(frag);
}

pub(crate) fn guard_edges(prev: Option<char>, next: Option<char>, rep: &str) -> String {
    let mut r = String::with_capacity(rep.len() + 2);
    if let (Some(a), Some(b)) = (prev, rep.chars().next()) {
        if needs_space(a, b) {
            r.push(' ');
        }
    }
    r.push_str(rep);
    if let (Some(a), Some(b)) = (rep.chars().last(), next) {
        if needs_space(a, b) {
            r.push(' ');
        }
    }
    r
}

fn tokenize(src: &str, _surface: bool) -> (Vec<Unit>, HashSet<String>, BTreeSet<String>) {
    let b = src.as_bytes();
    let n = b.len();
    let mut units = Vec::new();
    let mut originals = HashSet::new();
    let mut renameable = BTreeSet::new();
    let mut i = 0;

    let mut after_dot = false;

    let push_gap = |units: &mut Vec<Unit>| {
        if !matches!(units.last(), Some(Unit::Gap)) {
            units.push(Unit::Gap);
        }
    };

    while i < n {
        let c = b[i];
        if c == b'-' && i + 2 < n && b[i + 1] == b'-' && b[i + 2] == b'!' {
            let start = i;
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            units.push(Unit::Directive(src[start..i].to_string()));
            continue;
        }
        if c == b'-' && i + 3 < n && b[i + 1] == b'-' && b[i + 2] == b'[' && b[i + 3] == b'[' {
            i += 4;
            while i + 1 < n && !(b[i] == b']' && b[i + 1] == b']') {
                i += 1;
            }
            i = (i + 2).min(n);
            push_gap(&mut units);
            continue;
        }
        if c == b'-' && i + 1 < n && b[i + 1] == b'-' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            push_gap(&mut units);
            continue;
        }
        if c.is_ascii_whitespace() {
            while i < n && b[i].is_ascii_whitespace() {
                i += 1;
            }
            push_gap(&mut units);
            continue;
        }
        if c == b'"' || c == b'\'' {
            let start = i;
            i += 1;
            while i < n {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == c {
                    i += 1;
                    break;
                }
                i += 1;
            }
            units.push(Unit::Raw(src[start..i.min(n)].to_string()));
            after_dot = false;
            continue;
        }

        if c == b'[' {
            let mut j = i + 1;
            while j < n && b[j] == b'=' {
                j += 1;
            }
            if j < n && b[j] == b'[' {
                let level = j - i - 1;
                let start = i;
                i = j + 1;
                while i < n {
                    if b[i] == b']' {
                        let mut k = i + 1;
                        let mut eqs = 0;
                        while k < n && b[k] == b'=' {
                            k += 1;
                            eqs += 1;
                        }
                        if eqs == level && k < n && b[k] == b']' {
                            i = k + 1;
                            break;
                        }
                    }
                    i += 1;
                }
                units.push(Unit::Raw(src[start..i.min(n)].to_string()));
                after_dot = false;
                continue;
            }
        }
        if c.is_ascii_digit() {
            let start = i;
            i += 1;
            while i < n
                && (b[i] == b'_'
                    || b[i].is_ascii_alphanumeric()
                    || (b[i] == b'.' && !(i + 1 < n && b[i + 1] == b'.')))
            {
                i += 1;
            }
            units.push(Unit::Raw(src[start..i].to_string()));
            after_dot = false;
            continue;
        }
        if c == b'_' || c.is_ascii_alphabetic() {
            let start = i;
            i += 1;
            while i < n && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            if &src[start..i] == "type" && !after_dot {
                let mut j = i;
                while j < n && (b[j] == b' ' || b[j] == b'\t') {
                    j += 1;
                }
                if j < n && (b[j] == b'_' || b[j].is_ascii_alphabetic()) {
                    while i < n && b[i] != b'\n' {
                        i += 1;
                    }
                    units.push(Unit::Raw(src[start..i].to_string()));
                    after_dot = false;
                    continue;
                }
            }
            let name = src[start..i].to_string();
            let field = after_dot;
            originals.insert(name.clone());
            units.push(Unit::Ident(name, field));
            after_dot = false;
            continue;
        }
        if c == b'.' {
            if i + 2 < n && b[i + 1] == b'.' && b[i + 2] == b'.' {
                units.push(Unit::Raw("...".into()));
                i += 3;
            } else if i + 1 < n && b[i + 1] == b'.' {
                units.push(Unit::Raw("..".into()));
                i += 2;
            } else {
                units.push(Unit::Raw(".".into()));
                i += 1;
                after_dot = true;
                continue;
            }
            after_dot = false;
            continue;
        }
        if c == b':' {
            if i + 1 < n && b[i + 1] == b':' {
                units.push(Unit::Raw("::".into()));
                i += 2;
                after_dot = false;
            } else {
                units.push(Unit::Raw(":".into()));
                i += 1;
                after_dot = true;
            }
            continue;
        }
        if (c == b'=' || c == b'~' || c == b'<' || c == b'>') && i + 1 < n && b[i + 1] == b'=' {
            units.push(Unit::Raw(src[i..i + 2].to_string()));
            i += 2;
            after_dot = false;
            continue;
        }
        units.push(Unit::Raw((c as char).to_string()));
        i += 1;
        after_dot = false;
    }

    mark_constructor_keys(&mut units);
    for u in &units {
        if let Unit::Ident(name, false) = u {
            let slot_renamed = matches!(
                name.as_str(),
                "op" | "a" | "b" | "c" | "ops" | "inStack" | "index" | "open" | "idx" | "r"
            );
            if !KEYWORDS.contains(&name.as_str())
                && (!RESERVED.contains(&name.as_str()) || slot_renamed)
            {
                renameable.insert(name.clone());
            }
        }
    }
    (units, originals, renameable)
}

fn mark_constructor_keys(units: &mut [Unit]) {
    let n = units.len();
    let mut depth = 0i32;
    let mut prev: Option<usize> = None;
    let mut keys: Vec<usize> = Vec::new();
    for i in 0..n {
        match &units[i] {
            Unit::Gap | Unit::Directive(_) => continue,
            Unit::Raw(s) if s == "{" => depth += 1,
            Unit::Raw(s) if s == "}" => depth -= 1,
            Unit::Ident(_, false) if depth >= 1 => {
                let after_key_start = matches!(prev, Some(p)
                    if is_raw(&units[p], "{") || is_raw(&units[p], ",") || is_raw(&units[p], ";"));
                let j = next_sig(units, i + 1);
                if after_key_start && units.get(j).is_some_and(|u| is_raw(u, "=")) {
                    keys.push(i);
                }
            }
            _ => {}
        }
        prev = Some(i);
    }
    for i in keys {
        if let Unit::Ident(_, field) = &mut units[i] {
            *field = true;
        }
    }
}

fn generate_names(seed: u64, originals: &HashSet<String>, count: usize) -> Vec<String> {
    let alpha: Vec<u8> = (b'a'..=b'z').chain(b'A'..=b'Z').collect();
    let mut cands: Vec<String> = Vec::new();
    let accept = |s: String, cands: &mut Vec<String>| {
        if !KEYWORDS.contains(&s.as_str()) && !originals.contains(&s) {
            cands.push(s);
        }
    };
    for &x in &alpha {
        for &y in &alpha {
            accept(format!("{}{}", x as char, y as char), &mut cands);
        }
    }
    if cands.len() < count + FREE_GLOBALS.len() {
        for &x in &alpha {
            for &y in &alpha {
                for &z in &alpha {
                    accept(
                        format!("{}{}{}", x as char, y as char, z as char),
                        &mut cands,
                    );
                }
            }
        }
    }
    let mut rng = Rng::new(seed);
    rng.shuffle(&mut cands);
    cands.retain(|s| !FREE_GLOBALS.contains(&s.as_str()));
    cands.truncate(count);
    cands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renames_locals_strips_comments_keeps_fields_keys_keywords() {
        let src = "--!nocheck\nlocal makeClosure = 1 -- secret\nlocal t = { code = makeClosure }\nreturn t.code";
        let out = minify(src, 7, false);
        assert!(out.starts_with("--!nocheck\n"), "directive preserved");
        assert!(!out.contains("makeClosure"), "local renamed");
        assert!(!out.contains("secret"), "comment stripped");
        assert!(out.contains(".code"), "field access name kept verbatim");
        assert!(
            out.contains("code="),
            "constructor key kept verbatim (now space-packed)"
        );
        assert!(
            out.contains("return "),
            "keyword kept, with the required word-boundary space"
        );
        assert!(
            !out.contains(" = "),
            "tighter packing: no spaces around `=`"
        );
    }

    #[test]
    fn deterministic_per_seed_and_varies() {
        let src = "local alpha = 1 local beta = alpha + 1 return beta";
        assert_eq!(minify(src, 1, false), minify(src, 1, false));
        assert_ne!(minify(src, 1, false), minify(src, 2, false));
    }

    #[test]
    fn longbracket_level1_survives_verbatim() {
        let out = minify("local P = dec([=[ab!c=d ]=]) return P", 3, false);
        assert!(
            out.contains("[=[ab!c=d ]=]"),
            "level-1 long-bracket kept verbatim: {out}"
        );
    }

    #[test]
    fn longbracket_level2_survives_verbatim() {
        let out = minify("local P = dec([==[xY9-_[a ]==]) return P", 3, false);
        assert!(
            out.contains("[==[xY9-_[a ]==]"),
            "level-2 long-bracket kept verbatim: {out}"
        );
    }

    #[test]
    fn longbracket_inner_lower_level_close_does_not_terminate() {
        let out = minify("local P = dec([==[a]=]b]==]) return P", 3, false);
        assert!(
            out.contains("[==[a]=]b]==]"),
            "inner ]=] must not close a level-2 string: {out}"
        );
    }

    #[test]
    fn indexing_not_misread_as_longbracket() {
        let out = minify("local t = {} t[1] = 5 return t[1]", 3, false);
        assert!(
            !out.contains("[1] = 5") || out.contains("t[1]"),
            "t[1] indexing intact: {out}"
        );

        assert!(
            out.matches("[1]").count() >= 2,
            "both t[1] indexings preserved: {out}"
        );
    }

    #[test]
    fn block_comment_still_stripped() {
        let out = minify("local x = 1 --[[ secret comment ]] return x", 3, false);
        assert!(
            !out.contains("secret"),
            "--[[ ]] block comment stripped: {out}"
        );
    }

    #[test]
    fn native_preserves_globals_and_strips_comments() {
        let src = "function(x, ...)\n  -- secret\n  local t = { ... }\n  return print(game, Vector3.new(x)), #t\nend";
        let out = minify_native(src);
        for g in ["print", "game", "Vector3", "new"] {
            assert!(
                out.contains(g),
                "global `{g}` must survive native minify: {out}"
            );
        }
        assert!(!out.contains("secret"), "comment must be stripped: {out}");
        assert!(
            out.contains("function("),
            "still valid function source: {out}"
        );
    }

    #[test]
    fn native_minify_does_not_rename_locals() {
        let out = minify_native("function() local mySpecialName = 1 return mySpecialName end");
        assert!(
            out.contains("mySpecialName"),
            "native minify must not rename locals: {out}"
        );
    }

    #[test]
    fn append_sep_separates_only_glue_boundaries() {
        for (a, b, sep_expected) in [
            ("x=256", "return y", true),
            ("v=3", "do end", true),
            ("t=5", "or z", true),
            ("q=7", "if a then end", true),
            ("f()", "return x", false),
            ("a,", "b", false),
            ("k]", "end", false),
        ] {
            let mut out = a.to_string();
            append_sep(&mut out, b);
            assert_eq!(
                out,
                format!("{a}{}{b}", if sep_expected { " " } else { "" }),
                "a={a:?} b={b:?}"
            );
        }
    }

    #[test]
    fn guard_edges_guards_both_sides_without_gluing() {
        assert_eq!(
            guard_edges(Some(')'), Some('r'), "(1 + 2) % 256"),
            "(1 + 2) % 256 "
        );
        assert_eq!(
            guard_edges(Some('7'), Some(';'), "bxor(1, 2)"),
            " bxor(1, 2)"
        );
        assert_eq!(
            guard_edges(Some(';'), Some(';'), "local a = 1"),
            "local a = 1"
        );
        assert_eq!(guard_edges(None, None, "local a = 1"), "local a = 1");
    }

    #[test]
    fn executor_environment_lookup_survives_rename_minification() {
        let out = minify(
            r#"local genv=getgenv() genv["BASIL_RHT_RESET"]=function() end"#,
            7,
            false,
        );
        assert!(
            out.contains("getgenv()"),
            "executor environment lookup renamed: {out}"
        );
        assert!(out.contains(r#"["BASIL_RHT_RESET"]="#));
    }

    #[test]
    fn generated_names_never_shadow_free_globals() {
        let empty = std::collections::HashSet::new();
        for seed in 0..256u64 {
            let names = generate_names(seed, &empty, 4000);
            for g in FREE_GLOBALS {
                assert!(
                    !names.iter().any(|n| n.as_str() == *g),
                    "seed {seed} generated a local named {g:?} which would shadow the global"
                );
            }
        }
    }
}
