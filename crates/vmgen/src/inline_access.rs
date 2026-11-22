const READ: &str = "rg";
const WRITE: &str = "rs";

pub fn enabled() -> bool {
    std::env::var("BASIL_DIRECT_WRITES").ok().as_deref() == Some("1")
}

pub fn rewrite(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'"' || b[i] == b'\'' {
            let q = b[i];
            out.push(b[i] as char);
            i += 1;
            while i < b.len() {
                out.push(b[i] as char);
                if b[i] == b'\\' && i + 1 < b.len() {
                    out.push(b[i + 1] as char);
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if let Some((name, args, end)) = call_at(body, i) {
            let rewritten: Vec<String> = args.iter().map(|a| rewrite(a.trim())).collect();
            match (name, rewritten.len()) {
                (READ, 2) => {
                    out.push_str(&format!("{}[{}]", rewritten[0], rewritten[1]));
                    i = end;
                    continue;
                }
                (WRITE, 3) => {
                    out.push_str(&format!(
                        "{}[{}] = {}",
                        rewritten[0], rewritten[1], rewritten[2]
                    ));
                    i = end;
                    continue;
                }
                _ => {}
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn call_at(s: &str, i: usize) -> Option<(&'static str, Vec<String>, usize)> {
    let b = s.as_bytes();
    let name = if s[i..].starts_with("rg(") {
        READ
    } else if s[i..].starts_with("rs(") {
        WRITE
    } else {
        return None;
    };
    if i > 0 {
        let p = b[i - 1];
        if p.is_ascii_alphanumeric() || p == b'_' || p == b'.' || p == b':' {
            return None;
        }
    }
    let open = i + 2;
    let mut depth = 0i32;
    let mut j = open;
    let mut start = open + 1;
    let mut args: Vec<String> = Vec::new();
    while j < b.len() {
        match b[j] {
            b'"' | b'\'' => {
                let q = b[j];
                j += 1;
                while j < b.len() && b[j] != q {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 && b[j] == b')' {
                    args.push(s[start..j].to_string());
                    return Some((name, args, j + 1));
                }
            }
            b',' if depth == 1 => {
                args.push(s[start..j].to_string());
                start = j + 1;
            }
            _ => {}
        }
        j += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_write_becomes_a_direct_assignment() {
        assert_eq!(rewrite("rs(R, a, rg(R, inst.b))"), "R[a] = R[inst.b]");
    }

    #[test]
    fn nested_reads_inside_a_write_all_lower() {
        assert_eq!(
            rewrite("rs(R, a, add(m, rg(R, inst.b), rg(R, inst.c)))"),
            "R[a] = add(m, R[inst.b], R[inst.c])"
        );
    }

    #[test]
    fn table_writes_and_reads_lower_too() {
        assert_eq!(rewrite("rs(_u, _w, _v)"), "_u[_w] = _v");
        assert_eq!(rewrite("rg(_u, _w)"), "_u[_w]");
    }

    #[test]
    fn composite_interface_indices_survive() {
        assert_eq!(
            rewrite("rs(R, inst.ops[3], rg(_t0, _t1))"),
            "R[inst.ops[3]] = _t0[_t1]"
        );
    }

    #[test]
    fn identifiers_ending_in_the_helper_name_are_untouched() {
        assert_eq!(rewrite("xrs(R, a, 1)"), "xrs(R, a, 1)");
        assert_eq!(rewrite("t.rg(R, a)"), "t.rg(R, a)");
    }

    #[test]
    fn string_literals_are_not_rewritten() {
        assert_eq!(rewrite("h_g(\"rs(R, a, b)\")"), "h_g(\"rs(R, a, b)\")");
    }

    #[test]
    fn a_rewritten_body_keeps_no_helper_call() {
        let src = "local _u = rg(R, inst.b)\nlocal _w = rg(R, inst.c)\nrs(R, a, rg(_u, _w))";
        let out = rewrite(src);
        assert!(!out.contains("rg("), "{out}");
        assert!(!out.contains("rs("), "{out}");
        assert_eq!(
            out,
            "local _u = R[inst.b]\nlocal _w = R[inst.c]\nR[a] = _u[_w]"
        );
    }

    #[test]
    fn multi_argument_helpers_are_left_alone() {
        assert_eq!(rewrite("rs(R, a)"), "rs(R, a)");
        assert_eq!(rewrite("rg(R, a, b)"), "rg(R, a, b)");
    }
}
