use pipeline::{SurfaceVolume, TargetProfile};

const LADDER_THRESHOLD: usize = 24;

fn strip_lua(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let long_bracket = |start: usize| -> Option<usize> {
        let mut j = start + 1;
        let mut eq = 0;
        while j < n && b[j] == b'=' {
            eq += 1;
            j += 1;
        }
        if j < n && b[j] == b'[' {
            let mut k = j + 1;
            while k < n {
                if b[k] == b']' {
                    let mut m = k + 1;
                    let mut e2 = 0;
                    while m < n && b[m] == b'=' {
                        e2 += 1;
                        m += 1;
                    }
                    if e2 == eq && m < n && b[m] == b']' {
                        return Some(m + 1);
                    }
                }
                k += 1;
            }
            return Some(n);
        }
        None
    };
    let mut out = String::with_capacity(n);
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c == b'-' && i + 1 < n && b[i + 1] == b'-' {
            if i + 2 < n && b[i + 2] == b'[' {
                if let Some(e) = long_bracket(i + 2) {
                    out.push(' ');
                    i = e;
                    continue;
                }
            }
            let mut k = i;
            while k < n && b[k] != b'\n' {
                k += 1;
            }
            out.push(' ');
            i = k;
            continue;
        }
        if c == b'"' || c == b'\'' {
            let q = c;
            let mut k = i + 1;
            while k < n && b[k] != q {
                k += if b[k] == b'\\' { 2 } else { 1 };
            }
            out.push_str("\"\"");
            i = k + 1;
            continue;
        }
        if c == b'[' {
            if let Some(e) = long_bracket(i) {
                out.push(' ');
                i = e;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

enum Tok {
    Word(String),
    Num(String),
    EqEq,
    Other,
}

fn lex(src: &str) -> Vec<Tok> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let s = i;
            while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(Tok::Word(src[s..i].to_string()));
            continue;
        }
        if c.is_ascii_digit() {
            let s = i;
            i += 1;
            while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                i += 1;
            }
            out.push(Tok::Num(src[s..i].to_string()));
            continue;
        }
        if c == b'=' && i + 1 < n && b[i + 1] == b'=' {
            out.push(Tok::EqEq);
            i += 2;
            continue;
        }
        out.push(Tok::Other);
        i += 1;
    }
    out
}

fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "and"
            | "break"
            | "do"
            | "else"
            | "elseif"
            | "end"
            | "false"
            | "for"
            | "function"
            | "if"
            | "in"
            | "local"
            | "nil"
            | "not"
            | "or"
            | "repeat"
            | "return"
            | "then"
            | "true"
            | "until"
            | "while"
    )
}

fn scan_arm(toks: &[Tok], i: &mut usize) -> Option<(String, String)> {
    let mut j = *i + 1;
    let mut found = None;
    while j < toks.len() {
        if let Tok::Word(w) = &toks[j] {
            if w == "then" {
                break;
            }
        }
        if found.is_none() && j + 2 < toks.len() {
            if let Tok::EqEq = toks[j + 1] {
                match (&toks[j], &toks[j + 2]) {
                    (Tok::Word(a), Tok::Num(lit)) if !is_keyword(a) => {
                        found = Some((a.clone(), lit.clone()))
                    }
                    (Tok::Num(lit), Tok::Word(a)) if !is_keyword(a) => {
                        found = Some((a.clone(), lit.clone()))
                    }
                    _ => {}
                }
            }
        }
        j += 1;
    }
    *i = j;
    found
}

fn run_len(arms: &[Option<(String, String)>]) -> usize {
    let mut best = 0;
    let mut run = 0;
    let mut cur: Option<&str> = None;
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for a in arms {
        match a {
            Some((w, lit)) => {
                if cur == Some(w.as_str()) && !seen.contains(lit.as_str()) {
                    run += 1;
                    seen.insert(lit.as_str());
                } else {
                    cur = Some(w.as_str());
                    seen.clear();
                    seen.insert(lit.as_str());
                    run = 1;
                }
                best = best.max(run);
            }
            None => {
                cur = None;
                seen.clear();
                run = 0;
            }
        }
    }
    best
}

fn longest_equality_ladder(src: &str) -> usize {
    let toks = lex(&strip_lua(src));
    struct Frame {
        kind: u8,
        arms: Vec<Option<(String, String)>>,
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut pending_loop = false;
    let mut best = 0;
    let mut i = 0;
    while i < toks.len() {
        if let Tok::Word(w) = &toks[i] {
            match w.as_str() {
                "if" => {
                    let arm = scan_arm(&toks, &mut i);
                    stack.push(Frame {
                        kind: 1,
                        arms: vec![arm],
                    });
                }
                "elseif" => {
                    let arm = scan_arm(&toks, &mut i);
                    if let Some(f) = stack.last_mut() {
                        if f.kind == 1 {
                            f.arms.push(arm);
                        }
                    }
                }
                "else" => {
                    if let Some(f) = stack.last_mut() {
                        if f.kind == 1 {
                            f.arms.push(None);
                        }
                    }
                }
                "for" | "while" => {
                    stack.push(Frame {
                        kind: 0,
                        arms: Vec::new(),
                    });
                    pending_loop = true;
                }
                "function" => stack.push(Frame {
                    kind: 0,
                    arms: Vec::new(),
                }),
                "repeat" => stack.push(Frame {
                    kind: 2,
                    arms: Vec::new(),
                }),
                "do" => {
                    if pending_loop {
                        pending_loop = false;
                    } else {
                        stack.push(Frame {
                            kind: 0,
                            arms: Vec::new(),
                        });
                    }
                }
                "until" => {
                    if matches!(stack.last(), Some(f) if f.kind == 2) {
                        stack.pop();
                    }
                }
                "end" => {
                    if let Some(f) = stack.pop() {
                        if f.kind == 1 {
                            best = best.max(run_len(&f.arms));
                        }
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    best
}

const RICH: &str = r##"
local function acc(a, b, c) local s = a * 3 + b - c % 5 if s > b then return s else return b + 1 end end
local function build(n)
    local t = {}
    for i = 1, n do t[i] = acc(i, i * 2, i + 1) end
    return t
end
local function reduce(t)
    local s, p = 0, 1
    for _, v in ipairs(t) do s = s + v; if v % 2 == 0 then p = p * 2 else p = p + v end end
    return s, p
end
local meta = setmetatable({}, { __index = function(_, k) return #tostring(k) end })
local function mix(...)
    local n = select("#", ...)
    local acc2 = 0
    for i = 1, n do acc2 = acc2 + (select(i, ...) or 0) end
    return acc2, n
end
local data = build(24)
local s, p = reduce(data)
local m = mix(s, p, meta.zzz, #data)
local out = ("%d/%d/%d"):format(s % 100, p % 100, m % 100)
if s > 50 then out = out .. "!" elseif s > 10 then out = out .. "?" else out = out .. "." end
local co = coroutine.wrap(function() for i = 1, 5 do coroutine.yield(i * i) end end)
local cs = 0
for i = 1, 5 do cs = cs + co() end
return out, cs
"##;

fn art(
    seed: u64,
    hard: bool,
    surface: bool,
    heavy: SurfaceVolume,
    aggressive: bool,
    profile: TargetProfile,
    lph: bool,
) -> String {
    pipeline::virtualize_full_prof(
        RICH,
        seed,
        true,
        true,
        true,
        true,
        true,
        false,
        profile == TargetProfile::Executor,
        hard,
        surface,
        heavy,
        aggressive,
        pipeline::SensitiveOpts::default(),
        profile,
        false,
        lph,
    )
    .expect("virtualize")
}

fn moonsec_ladder(arms: usize, reversed: bool) -> String {
    let mut s = String::from("while true do\n");
    for k in 1..=arms {
        let kw = if k == 1 { "if" } else { "elseif" };
        if reversed {
            s.push_str(&format!("{kw} {k} == op then f{k}()\n"));
        } else {
            s.push_str(&format!("{kw} op == {k} then f{k}()\n"));
        }
    }
    s.push_str("else g() end\nend\n");
    s
}

#[test]
fn dispatch_ladder_scanner_detects_moonsec_style_ladder() {
    let eight = "while true do\nif op == 1 then a()\nelseif op == 2 then a()\nelseif op == 3 then a()\nelseif op == 4 then a()\nelseif op == 5 then a()\nelseif op == 6 then a()\nelseif op == 7 then a()\nelseif op == 8 then a()\nend\nend\n";
    assert_eq!(
        longest_equality_ladder(eight),
        8,
        "exact 8-arm ladder count"
    );

    let big = moonsec_ladder(40, false);
    assert!(
        longest_equality_ladder(&big) >= LADDER_THRESHOLD,
        "40-arm ladder must trip the guard"
    );
    let rev = moonsec_ladder(30, true);
    assert!(
        longest_equality_ladder(&rev) >= LADDER_THRESHOLD,
        "reversed `<int> == op` ladder must also trip the guard"
    );
}

#[test]
fn dispatch_ladder_scanner_ignores_small_numeric_conditionals() {
    assert_eq!(longest_equality_ladder("if x == 5 then f() end"), 1);
    assert_eq!(
        longest_equality_ladder(
            "if x == 1 then f() elseif x == 2 then g() elseif x == 3 then h() end"
        ),
        3
    );

    assert_eq!(
        longest_equality_ladder(
            "if a == 1 then f() elseif b == 2 then g() elseif a == 3 then h() end"
        ),
        1
    );

    assert!(longest_equality_ladder("if tag == 1 then elseif tag == 2 then elseif tag == 3 then elseif tag == 4 then elseif tag == 5 then end") < LADDER_THRESHOLD);
}

#[test]
fn dispatch_ladder_scanner_ignores_while_true_without_ladder() {
    assert_eq!(
        longest_equality_ladder("while true do local x = f() if x then break end end"),
        0
    );
    assert_eq!(longest_equality_ladder("while true do step() end"), 0);

    assert_eq!(
        longest_equality_ladder("while true do if op < 10 then a() else b() end end"),
        0
    );
}

#[test]
fn dispatch_ladder_scanner_accepts_table_or_computed_dispatch() {
    assert_eq!(
        longest_equality_ladder("local t = {} while true do t[op](a, b) end"),
        0
    );
    assert_eq!(
        longest_equality_ladder("while true do dispatch[op](state) end"),
        0
    );

    let tree = "while true do if op < 20 then if op == 3 then a() elseif op == 7 then b() else c() end else if op == 40 then d() else e() end end end";
    assert!(longest_equality_ladder(tree) < LADDER_THRESHOLD);
}

#[test]
fn release_surface_has_no_clear_opcode_equality_ladder() {
    let seeds = [1u64, 3, 13, 31, 42, 99, 65535, 305419896];
    let configs: [(&str, bool, bool, SurfaceVolume, bool, TargetProfile, bool); 4] = [
        (
            "cli-default",
            false,
            false,
            SurfaceVolume::Off,
            false,
            TargetProfile::CliTest,
            false,
        ),
        (
            "cli-poly-hard",
            true,
            false,
            SurfaceVolume::Off,
            true,
            TargetProfile::CliTest,
            false,
        ),
        (
            "cli-heavy",
            false,
            false,
            SurfaceVolume::Medium,
            false,
            TargetProfile::CliTest,
            false,
        ),
        (
            "executor-release",
            true,
            true,
            SurfaceVolume::Off,
            true,
            TargetProfile::Executor,
            true,
        ),
    ];
    let mut worst = 0;
    for (name, hard, surface, heavy, aggr, profile, lph) in configs {
        for seed in seeds {
            let a = art(seed, hard, surface, heavy, aggr, profile, lph);
            let run = longest_equality_ladder(&a);
            worst = worst.max(run);
            assert!(
                run < LADDER_THRESHOLD,
                "{name} seed {seed}: opcode equality ladder run {run} >= threshold {LADDER_THRESHOLD} (MoonSec-style dispatch surface regression)"
            );
        }
    }
    assert!(
        worst > 0,
        "expected some equality-dispatch structure in generated artifacts"
    );
}
