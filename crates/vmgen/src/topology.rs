use crate::rng::Rng;

const DOMAIN: u64 = 0x_544F_504F_4C4F_4759;

const SAFE_COLD: &[&str] = &[
    "checksum",
    "structKey",
    "key8",
    "mpk",
    "cep",
    "wireDigest",
    "_wmR",
    "_lcR",
];

pub(crate) fn replace_word_in_code(src: &str, word: &str, repl: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = String::with_capacity(n + 64);
    let mut i = 0usize;
    let long_open = |j: usize| -> i64 {
        if b.get(j) != Some(&b'[') {
            return -1;
        }
        let mut k = j + 1;
        let mut eq = 0i64;
        while k < n && b[k] == b'=' {
            eq += 1;
            k += 1;
        }
        if k < n && b[k] == b'[' {
            eq
        } else {
            -1
        }
    };
    while i < n {
        let c = b[i];

        if c == b'-' && i + 1 < n && b[i + 1] == b'-' {
            out.push_str("--");
            let mut j = i + 2;
            let lvl = long_open(j);
            if lvl >= 0 {
                let close = format!("]{}]", "=".repeat(lvl as usize));
                let e = src[j..]
                    .find(&close)
                    .map(|p| j + p + close.len())
                    .unwrap_or(n);
                out.push_str(&src[j..e]);
                i = e;
            } else {
                while j < n && b[j] != b'\n' {
                    j += 1;
                }
                out.push_str(&src[i + 2..j]);
                i = j;
            }
            continue;
        }

        let lvl = long_open(i);
        if lvl >= 0 {
            let open = format!("[{}[", "=".repeat(lvl as usize));
            let close = format!("]{}]", "=".repeat(lvl as usize));
            let start = i;
            let after_open = i + open.len();
            let e = src[after_open..]
                .find(&close)
                .map(|p| after_open + p + close.len())
                .unwrap_or(n);
            out.push_str(&src[start..e]);
            i = e;
            continue;
        }

        if c == b'"' || c == b'\'' {
            let q = c;
            out.push(q as char);
            let mut j = i + 1;
            while j < n {
                if b[j] == b'\\' {
                    out.push(b[j] as char);
                    if j + 1 < n {
                        out.push(b[j + 1] as char);
                    }
                    j += 2;
                    continue;
                }
                out.push(b[j] as char);
                if b[j] == q {
                    j += 1;
                    break;
                }
                j += 1;
            }
            i = j;
            continue;
        }

        if src[i..].starts_with(word) {
            let before_ok = i == 0 || (!is_id(b[i - 1]) && b[i - 1] != b'.');
            let after = i + word.len();
            let after_ok = after >= n || !is_id(b[after]);
            if before_ok && after_ok {
                out.push_str(repl);
                i = after;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

fn distinct_keys(rng: &mut Rng, count: usize) -> Vec<u64> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let k = 1 + rng.below(9000);
        if seen.insert(k) {
            out.push(k);
        }
    }
    out
}

pub fn apply(mut src: String, seed: u64) -> String {
    let mut rng = Rng::new(seed ^ DOMAIN);
    let mut pool: Vec<&str> = SAFE_COLD
        .iter()
        .copied()
        .filter(|h| src.matches(&format!("local function {h}(")).count() == 1)
        .collect();
    if pool.is_empty() {
        return src;
    }
    rng.shuffle(&mut pool);
    let want = 2 + rng.below(4) as usize;
    let k = want.min(pool.len());
    let chosen: Vec<&str> = pool[..k].to_vec();

    let ntables = 1 + rng.below(2) as usize;
    let tnames: Vec<String> = (0..ntables)
        .map(|_| format!("_S{}", 10 + rng.below(88000)))
        .collect();
    let decls: String = tnames
        .iter()
        .map(|t| format!("local {t}={{}}"))
        .collect::<Vec<_>>()
        .join(" ");
    let anchor = "local genv = getfenv(1)\n";
    if !src.contains(anchor) {
        return src;
    }
    src = src.replacen(anchor, &format!("{anchor}{decls}\n"), 1);

    let keys = distinct_keys(&mut rng, chosen.len());
    for (h, key) in chosen.iter().zip(&keys) {
        let from_decl = format!("local function {h}(");
        let t = &tnames[rng.below(ntables as u64) as usize];
        let slot = format!("{t}[{key}]");
        src = src.replacen(&from_decl, &format!("{slot}=function("), 1);
        src = replace_word_in_code(&src, h, &slot);
    }
    src
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_string_and_comment_regions() {
        let s = "local cep = 1\nlocal x = cep + 1\nlocal s = \"cep here\"\nlocal l = [==[ cep )cep( ]==]\n-- cep comment\n";
        let out = replace_word_in_code(s, "cep", "_S1.cep");
        assert!(
            out.contains("local _S1.cep = 1") || out.contains("_S1.cep + 1"),
            "code refs rewritten: {out}"
        );
        assert!(
            out.contains("\"cep here\""),
            "string literal untouched: {out}"
        );
        assert!(
            out.contains("[==[ cep )cep( ]==]"),
            "long-bracket blob untouched: {out}"
        );
        assert!(out.contains("-- cep comment"), "comment untouched: {out}");
    }

    #[test]
    fn not_after_dot_and_word_boundary() {
        let s = "cep foo.cep bar cept cep2 xcep";
        let out = replace_word_in_code(s, "cep", "T.cep");
        assert!(
            out.starts_with("T.cep foo.cep"),
            "leading rewritten, after-dot skipped: {out}"
        );
        assert!(
            out.contains("cept") && out.contains("cep2") && out.contains("xcep"),
            "no substring hits: {out}"
        );
        assert_eq!(out.matches("T.cep").count(), 1);
    }

    #[test]
    fn relocation_moves_decl_and_calls_deterministically() {
        let vm = "local genv = getfenv(1)\nlocal function checksum(s) return s end\nlocal a = checksum(1)\nlocal b = checksum(2)\nlocal p = [==[ checksum )checksum( ]==]\n";
        let a = apply(vm.to_string(), 42);
        let b = apply(vm.to_string(), 42);
        assert_eq!(a, b, "deterministic per seed");
        assert!(
            a.contains("]=function(s) return s end"),
            "decl became a numeric table slot: {a}"
        );
        assert!(
            !a.contains("local function checksum("),
            "flat decl removed: {a}"
        );
        assert!(
            !a.contains(".checksum"),
            "helper name not leaked as a field: {a}"
        );
        assert!(
            a.contains("[==[ checksum )checksum( ]==]"),
            "payload-like blob preserved verbatim: {a}"
        );
    }

    #[test]
    fn different_seeds_differ() {
        let vm = "local genv = getfenv(1)\nlocal function checksum(s) return s end\nlocal function structKey(d) return d end\nlocal function key8(w) return w end\nlocal function mpk(a) return a end\nlocal function cep(a) return a end\nlocal function wireDigest(a) return a end\nlocal a = checksum(structKey(key8(mpk(cep(wireDigest(1))))))\n";
        let mut shapes = std::collections::HashSet::new();
        for s in 0u64..24 {
            shapes.insert(apply(vm.to_string(), s));
        }
        assert!(
            shapes.len() >= 12,
            "seeds should vary relocation, got {}",
            shapes.len()
        );
    }
}
