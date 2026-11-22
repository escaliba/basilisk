use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellFamily {
    Iife,
    TableEntry,
    HelperLauncher,
    SetMeta,
}

impl ShellFamily {
    pub fn id(self) -> &'static str {
        match self {
            ShellFamily::Iife => "iife",
            ShellFamily::TableEntry => "table-entry",
            ShellFamily::HelperLauncher => "helper-launcher",
            ShellFamily::SetMeta => "setmeta",
        }
    }
}

const BUILTINS: [&str; 10] = [
    "table.unpack",
    "table.pack",
    "string.sub",
    "string.unpack",
    "string.byte",
    "string.char",
    "table.concat",
    "select",
    "pairs",
    "tostring",
];
const N: usize = 10;
const CLOSE: &str = "end)(table.unpack";
const SHELL_DOMAIN: u64 = 0x_5348_454C_4C5F_4632;

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn upto(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.upto(i + 1);
            v.swap(i, j);
        }
    }
}

pub fn select(seed: u64, surface: bool) -> ShellFamily {
    select_with(seed, surface, None)
}

pub fn select_with(seed: u64, surface: bool, requested: Option<ShellFamily>) -> ShellFamily {
    if !surface {
        return ShellFamily::Iife;
    }
    if let Some(f) = std::env::var_os("BASIL_SHELL_FAMILY") {
        match f.to_str() {
            Some("iife") => return ShellFamily::Iife,
            Some("table-entry") => return ShellFamily::TableEntry,
            Some("helper-launcher") => return ShellFamily::HelperLauncher,
            Some("setmeta") => return ShellFamily::SetMeta,
            _ => {}
        }
    }
    if let Some(f) = requested {
        return f;
    }
    match mix(seed ^ SHELL_DOMAIN) % 10 {
        0..=3 => ShellFamily::SetMeta,
        4..=6 => ShellFamily::HelperLauncher,
        7..=8 => ShellFamily::TableEntry,
        _ => ShellFamily::Iife,
    }
}

fn permutation(rng: &mut Rng, n: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.upto(i + 1);
        v.swap(i, j);
    }
    v
}

fn distinct_keys(rng: &mut Rng, count: usize) -> Vec<u64> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let k = 1 + rng.next() % 9000;
        if seen.insert(k) {
            out.push(k);
        }
    }
    out
}

pub fn wrap(vm: String, seed: u64, surface: bool) -> String {
    wrap_with(vm, seed, surface, None)
}

pub fn wrap_with(vm: String, seed: u64, surface: bool, requested: Option<ShellFamily>) -> String {
    if !surface {
        return vm;
    }
    wrap_family(vm, select_with(seed, surface, requested), seed)
}

fn wrap_family(vm: String, family: ShellFamily, seed: u64) -> String {
    match try_wrap(&vm, family, seed) {
        Some(out) => out,
        None => vm,
    }
}

fn split_open(vm: &str) -> Option<(usize, &'static str)> {
    for pat in ["return(function", "return (function"] {
        if let Some(i) = vm.find(pat) {
            return Some((i, pat));
        }
    }
    None
}

fn ident(rng: &mut Rng) -> String {
    let up = b"QZJXVWYUKF";
    let an = b"abcdefghijklmnopqrstuvwxyz0123456789";
    format!(
        "{}{}{}",
        up[rng.upto(up.len())] as char,
        an[rng.upto(an.len())] as char,
        an[rng.upto(an.len())] as char
    )
}

fn pfx(seed: u64, domain: u64) -> char {
    const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    C[(mix(seed ^ domain) % C.len() as u64) as usize] as char
}

fn compose_setmeta(pnames: &[&str], body: &str, prefix: &str, trailing: &str, seed: u64) -> String {
    let mut rng = Rng(mix(seed ^ SHELL_DOMAIN ^ 0x_5345_544D_4554_4132));
    let selfp = format!(
        "_{}{}",
        pfx(seed, 0x_5345_4C46_5F53_4C50),
        rng.next() % 100000
    );
    let mut order = permutation(&mut rng, N);
    rng.shuffle(&mut order);

    let mut n_arg = rng.upto(4);
    let mut n_group = [0usize, 2, 3][rng.upto(3)];
    let mut n_record = [0usize, 2][rng.upto(2)];
    let mut n_sec = [0usize, 2, 3][rng.upto(3)];
    let mut n_str = rng.upto(3);
    while n_arg + n_group + n_record + n_sec + n_str > N - 1 {
        if n_sec > 0 {
            n_sec = 0;
        } else if n_group > 0 {
            n_group = 0;
        } else if n_record > 0 {
            n_record = 0;
        } else if n_str > 0 {
            n_str -= 1;
        } else if n_arg > 0 {
            n_arg -= 1;
        } else {
            break;
        }
    }

    let mut cur = order.iter().copied();
    let take = |cur: &mut dyn Iterator<Item = usize>, n: usize| -> Vec<usize> {
        (0..n).filter_map(|_| cur.next()).collect()
    };
    let g_group = take(&mut cur, n_group);
    let g_record = take(&mut cur, n_record);
    let g_sec = take(&mut cur, n_sec);
    let g_str = take(&mut cur, n_str);
    let g_arg = take(&mut cur, n_arg);
    let g_num: Vec<usize> = cur.collect();

    let mut used_keys: HashSet<u64> = HashSet::new();
    let fresh_key = |rng: &mut Rng, used: &mut HashSet<u64>| -> u64 {
        loop {
            let k = 1 + rng.next() % 9000;
            if used.insert(k) {
                return k;
            }
        }
    };

    let mut members: Vec<String> = Vec::new();
    let mut prelude: Vec<String> = Vec::new();

    for &i in &g_num {
        let k = fresh_key(&mut rng, &mut used_keys);
        members.push(format!("[{k}]={}", BUILTINS[i]));
        prelude.push(format!("local {}={selfp}[{k}]", pnames[i]));
    }
    for &i in &g_str {
        let name = ident(&mut rng);
        members.push(format!("{name}={}", BUILTINS[i]));
        prelude.push(format!("local {}={selfp}.{name}", pnames[i]));
    }
    if !g_sec.is_empty() {
        let field = ident(&mut rng);
        let mut inner: Vec<String> = Vec::new();
        for &i in &g_sec {
            let k = fresh_key(&mut rng, &mut used_keys);
            inner.push(format!("[{k}]={}", BUILTINS[i]));
            prelude.push(format!("local {}={selfp}.{field}[{k}]", pnames[i]));
        }
        members.push(format!("{field}={{{}}}", inner.join(",")));
    }
    if !g_group.is_empty() {
        let k = fresh_key(&mut rng, &mut used_keys);
        let rets = g_group
            .iter()
            .map(|&i| BUILTINS[i])
            .collect::<Vec<_>>()
            .join(",");
        let lhs = g_group
            .iter()
            .map(|&i| pnames[i])
            .collect::<Vec<_>>()
            .join(",");
        members.push(format!("[{k}]=function() return {rets} end"));
        prelude.push(format!("local {lhs}={selfp}[{k}]()"));
    }
    if !g_record.is_empty() {
        let k = fresh_key(&mut rng, &mut used_keys);
        let vals = g_record
            .iter()
            .map(|&i| BUILTINS[i])
            .collect::<Vec<_>>()
            .join(",");
        members.push(format!("[{k}]={{{vals}}}"));
        let lhs = g_record
            .iter()
            .map(|&i| pnames[i])
            .collect::<Vec<_>>()
            .join(",");
        let rhs = (1..=g_record.len())
            .map(|n| format!("{selfp}[{k}][{n}]"))
            .collect::<Vec<_>>()
            .join(",");
        prelude.push(format!("local {lhs}={rhs}"));
    }

    rng.shuffle(&mut members);
    let sig: Vec<&str> = g_arg.iter().map(|&i| pnames[i]).collect();
    let ar: Vec<&str> = g_arg.iter().map(|&i| BUILTINS[i]).collect();
    let sig_s = if sig.is_empty() {
        String::new()
    } else {
        format!("{},", sig.join(","))
    };
    let ar_s = if ar.is_empty() {
        String::new()
    } else {
        format!("{},", ar.join(","))
    };
    let pre = if prelude.is_empty() {
        String::new()
    } else {
        format!("{};", prelude.join(" "))
    };

    format!(
        "{prefix}return setmetatable({{{}}},{{__call=function({selfp},{sig_s}...){pre}{body}end}})({ar_s}...){trailing}",
        members.join(",")
    )
}

fn try_wrap(vm: &str, family: ShellFamily, seed: u64) -> Option<String> {
    let (open_at, open_pat) = split_open(vm)?;
    let pl_open = open_at + open_pat.len();
    if vm.as_bytes().get(pl_open) != Some(&b'(') {
        return None;
    }
    let pl_close = vm[pl_open + 1..].find(')')? + pl_open + 1;
    let params: Vec<&str> = vm[pl_open + 1..pl_close]
        .split(',')
        .map(|s| s.trim())
        .collect();
    if params.len() != N + 1 || params[N] != "..." {
        return None;
    }
    let pnames: Vec<&str> = params[..N].to_vec();
    let body_start = pl_close + 1;
    let close_at = vm.rfind(CLOSE)?;
    if close_at < body_start {
        return None;
    }
    let body = &vm[body_start..close_at];
    let args_open = close_at + "end)(".len();
    let args_close = vm[args_open..].find(')')? + args_open;
    let trailing = &vm[args_close + 1..];
    let prefix = &vm[..open_at];

    if family == ShellFamily::SetMeta {
        return Some(compose_setmeta(&pnames, body, prefix, trailing, seed));
    }

    let mut rng = Rng(mix(seed ^ SHELL_DOMAIN ^ 0x_A5A5_5A5A_C3C3_3C3C));
    let perm = permutation(&mut rng, N);

    let hoist: Vec<usize> = if family == ShellFamily::Iife {
        Vec::new()
    } else {
        let count = 2 + rng.upto(4);
        perm.iter().copied().take(count).collect()
    };
    let hoist_set: HashSet<usize> = hoist.iter().copied().collect();
    let keys = distinct_keys(&mut rng, hoist.len());
    let entry = format!(
        "_{}{}",
        pfx(seed, 0x_454E_5452_595F_454C),
        rng.next() % 100000
    );
    let selfp = format!(
        "_{}{}",
        pfx(seed, 0x_5345_4C46_5F53_4C50),
        rng.next() % 100000
    );

    let sig_params: Vec<&str> = perm
        .iter()
        .filter(|i| !hoist_set.contains(i))
        .map(|&i| pnames[i])
        .collect();
    let call_args: Vec<&str> = perm
        .iter()
        .filter(|i| !hoist_set.contains(i))
        .map(|&i| BUILTINS[i])
        .collect();

    let members: String = hoist
        .iter()
        .zip(&keys)
        .map(|(&i, k)| format!("[{k}]={},", BUILTINS[i]))
        .collect();
    let prelude: String = if hoist.is_empty() {
        String::new()
    } else {
        let lhs = hoist
            .iter()
            .map(|&i| pnames[i])
            .collect::<Vec<_>>()
            .join(",");
        let rhs = keys
            .iter()
            .map(|k| format!("{selfp}[{k}]"))
            .collect::<Vec<_>>()
            .join(",");
        format!("local {lhs}={rhs};")
    };

    let out = match family {
        ShellFamily::Iife => {
            let ps = perm
                .iter()
                .map(|&i| pnames[i])
                .collect::<Vec<_>>()
                .join(",");
            let ar = perm
                .iter()
                .map(|&i| BUILTINS[i])
                .collect::<Vec<_>>()
                .join(",");
            format!("{prefix}return(function({ps},...){body}end)({ar},...){trailing}")
        }
        ShellFamily::TableEntry => {
            let sig = sig_params.join(",");
            let ar = call_args.join(",");
            format!(
                "{prefix}return({{{members}{entry}=function({selfp},{sig},...){prelude}{body}end}}):{entry}({ar},...){trailing}"
            )
        }
        ShellFamily::HelperLauncher => {
            let sig = sig_params.join(",");
            let ar = call_args.join(",");
            format!(
                "{prefix}return(function(_T,...) return _T:{entry}(...) end)({{{members}{entry}=function({selfp},{sig},...){prelude}{body}end}},{ar},...){trailing}"
            )
        }
        ShellFamily::SetMeta => unreachable!("SetMeta is composed via compose_setmeta"),
    };
    Some(out)
}

pub fn helper_field_count(family: ShellFamily, seed: u64) -> usize {
    if family == ShellFamily::Iife {
        return 0;
    }
    let mut rng = Rng(mix(seed ^ SHELL_DOMAIN ^ 0x_A5A5_5A5A_C3C3_3C3C));
    let _ = permutation(&mut rng, N);
    let count = 2 + rng.upto(4);
    count + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        let ps = "u0,u1,u2,u3,u4,u5,u6,select,pairs,tostring";
        let args = BUILTINS.join(",");
        format!("return(function({ps},...)local s=u4(\"x\") return s end)({args},...)")
    }

    const DOTTED: [&str; 7] = [
        "table.unpack",
        "table.pack",
        "string.sub",
        "string.unpack",
        "string.byte",
        "string.char",
        "table.concat",
    ];

    #[test]
    fn weighting_reaches_all_families_including_setmeta() {
        let mut c = std::collections::HashMap::new();
        for s in 0u64..500 {
            *c.entry(select(s, true).id()).or_insert(0) += 1;
        }
        assert!(
            c["setmeta"] > 0 && c["helper-launcher"] > 0 && c["table-entry"] > 0 && c["iife"] > 0,
            "all four families reachable in the weighted default: {c:?}"
        );
        assert!(
            c["setmeta"] > c["helper-launcher"]
                && c["helper-launcher"] > c["table-entry"]
                && c["table-entry"] > c["iife"],
            "setmeta > helper-launcher > table-entry > iife: {c:?}"
        );
    }

    #[test]
    fn table_entry_has_multiple_real_members() {
        let out = wrap_family(sample(), ShellFamily::TableEntry, 42);
        let members = out.matches("]=").count();
        assert!(members >= 2, "at least 2 hoisted builtin members: {out}");
        assert!(out.starts_with("return({["), "table opener: {}", &out[..40]);
        assert!(
            out.contains("}):_"),
            "method call on the table literal: {}",
            &out[..80.min(out.len())]
        );
        assert!(out.ends_with(",...)"), "call ends with varargs: {out}");
        for &b in &DOTTED {
            assert!(out.contains(b), "builtin {b} present");
        }
    }

    #[test]
    fn helper_launcher_dispatches_and_has_members() {
        let out = wrap_family(sample(), ShellFamily::HelperLauncher, 7);
        assert!(
            out.starts_with("return(function(_T,...) return _T:_"),
            "launcher: {}",
            &out[..60]
        );
        assert!(out.matches("]=").count() >= 2, "members: {out}");
    }

    #[test]
    fn setmeta_is_setmetatable_rooted_and_eager() {
        for seed in [42u64, 7, 1337, 99, 2024, 305419896] {
            let out = wrap_family(sample(), ShellFamily::SetMeta, seed);
            assert!(
                out.starts_with("return setmetatable({"),
                "setmetatable-rooted: {}",
                &out[..40.min(out.len())]
            );
            assert!(
                out.contains("},{__call=function(_"),
                "metatable __call entry: {out}"
            );
            assert!(
                out.contains("end})("),
                "eager call on the setmetatable result: {out}"
            );
            for &b in &DOTTED {
                assert_eq!(
                    out.matches(b).count(),
                    1,
                    "builtin {b} owned exactly once (seed {seed}): {out}"
                );
            }
        }
    }

    #[test]
    fn setmeta_root_topology_varies_and_uses_nonprimitive_members() {
        let mut numeric_field_counts = std::collections::HashSet::new();
        let mut group = 0;
        for seed in 0u64..96 {
            let out = wrap_family(sample(), ShellFamily::SetMeta, seed);
            numeric_field_counts.insert(out.matches("]=").count());
            if out.contains("=function() return ") {
                group += 1;
            }
        }
        assert!(
            numeric_field_counts.len() >= 3,
            "root topology must vary: {numeric_field_counts:?}"
        );
        assert!(
            group > 0,
            "group-helper closures must appear as root members on some builds"
        );
    }

    #[test]
    fn weighted_default_is_diverse_and_reaches_setmeta() {
        let mut seen = std::collections::HashSet::new();
        for s in 0u64..2000 {
            seen.insert(select(s, true).id());
        }
        assert!(
            seen.contains("setmeta"),
            "setmeta reachable in the weighted default: {seen:?}"
        );
        assert!(
            seen.len() >= 4,
            "weighted default stays diverse, not one universal root: {seen:?}"
        );
        assert_eq!(
            select(1, false).id(),
            "iife",
            "no surface => no shell family"
        );
    }

    #[test]
    fn requested_override_wins_over_weighting() {
        for s in 0u64..64 {
            assert_eq!(
                select_with(s, true, Some(ShellFamily::SetMeta)).id(),
                "setmeta"
            );
            assert_eq!(select_with(s, true, Some(ShellFamily::Iife)).id(), "iife");
        }
        assert_eq!(
            select_with(1, false, Some(ShellFamily::SetMeta)).id(),
            "iife",
            "no surface => no shell family"
        );
    }

    #[test]
    fn builtin_order_is_permuted_and_deterministic() {
        assert_eq!(
            wrap_family(sample(), ShellFamily::Iife, 3),
            wrap_family(sample(), ShellFamily::Iife, 3)
        );
        let a = wrap_family(sample(), ShellFamily::Iife, 3);
        let b = wrap_family(sample(), ShellFamily::Iife, 4);
        assert_ne!(a, b, "different seeds permute differently");

        assert!(
            !a.contains("table.unpack,table.pack,string.sub,string.unpack,string.byte"),
            "tuple broken: {a}"
        );
    }

    #[test]
    fn every_builtin_used_once_no_dead_fields() {
        for fam in [
            ShellFamily::Iife,
            ShellFamily::TableEntry,
            ShellFamily::HelperLauncher,
            ShellFamily::SetMeta,
        ] {
            let out = wrap_family(sample(), fam, 99);
            for &b in &DOTTED {
                assert_eq!(
                    out.matches(b).count(),
                    1,
                    "{b} appears exactly once in {:?}",
                    fam
                );
            }
        }
    }

    #[test]
    fn prelude_terminated_for_call_prefixed_body() {
        let ps = "u0,u1,u2,u3,u4,u5,u6,select,pairs,tostring";
        let args = BUILTINS.join(",");
        let vm = format!("return(function({ps},...)(\"hi\");print(u4)end)({args},...)");
        let out = wrap_family(vm, ShellFamily::TableEntry, 42);
        assert!(
            out.contains("];(\"hi\")"),
            "prelude `;`-terminated before a call-prefixed body: {out}"
        );
        assert!(
            !out.contains("] (\"hi\")"),
            "no space-separated ambiguous-call seam: {out}"
        );
    }

    #[test]
    fn iife_unchanged_without_surface() {
        assert_eq!(wrap(sample(), 42, false), sample());
    }

    #[test]
    fn missing_boundary_is_safe() {
        let s = "print('no shell here')".to_string();
        assert_eq!(wrap_family(s.clone(), ShellFamily::TableEntry, 1), s);
        let bad = "return(function(a,b,c)end)(x,y)".to_string();
        assert_eq!(
            wrap_family(bad.clone(), ShellFamily::TableEntry, 1),
            bad,
            "wrong param count -> untouched"
        );
    }
}
