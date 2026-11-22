use ir::{Block, Expr, Field, InterpPart, LastStmt, Module, Stmt};

pub fn obfuscate_natives(module: &mut Module, seed: u64) {
    for (i, native) in module.natives.iter_mut().enumerate() {
        let mut rng = seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x2545_F491_4F6C_DD1D;
        rewrite_block(&mut native.block, &mut rng);
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn rewrite_block(block: &mut Block, rng: &mut u64) {
    for stmt in block.stmts.iter_mut() {
        rewrite_stmt(stmt, rng);
    }
    if let Some(LastStmt::Return(exprs)) = block.last.as_mut() {
        for e in exprs.iter_mut() {
            rewrite_expr(e, rng);
        }
    }
}

fn rewrite_stmt(stmt: &mut Stmt, rng: &mut u64) {
    match stmt {
        Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| rewrite_expr(e, rng)),
        Stmt::Assign { targets, exprs } => targets
            .iter_mut()
            .chain(exprs)
            .for_each(|e| rewrite_expr(e, rng)),
        Stmt::Compound { target, value, .. } => {
            rewrite_expr(target, rng);
            rewrite_expr(value, rng);
        }
        Stmt::Call(e) => rewrite_expr(e, rng),
        Stmt::Do(b) => rewrite_block(b, rng),
        Stmt::While { cond, body } => {
            rewrite_expr(cond, rng);
            rewrite_block(body, rng);
        }
        Stmt::Repeat { body, until } => {
            rewrite_block(body, rng);
            rewrite_expr(until, rng);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            rewrite_expr(start, rng);
            rewrite_expr(end, rng);
            if let Some(s) = step {
                rewrite_expr(s, rng);
            }
            rewrite_block(body, rng);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter_mut().for_each(|e| rewrite_expr(e, rng));
            rewrite_block(body, rng);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            rewrite_expr(cond, rng);
            rewrite_block(body, rng);
            for (c, b) in else_ifs {
                rewrite_expr(c, rng);
                rewrite_block(b, rng);
            }
            if let Some(b) = otherwise {
                rewrite_block(b, rng);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            rewrite_block(&mut body.block, rng)
        }
    }
}

fn rewrite_expr(expr: &mut Expr, rng: &mut u64) {
    match expr {
        Expr::Str(text) => {
            if let Some(bytes) = decode(text) {
                *text = encode(&bytes, rng);
            }
        }
        Expr::Function(body) => rewrite_block(&mut body.block, rng),
        Expr::Call { func, args, .. } => {
            rewrite_expr(func, rng);
            args.iter_mut().for_each(|a| rewrite_expr(a, rng));
        }
        Expr::MethodCall { base, args, .. } => {
            rewrite_expr(base, rng);
            args.iter_mut().for_each(|a| rewrite_expr(a, rng));
        }
        Expr::Field { base, .. } => rewrite_expr(base, rng),
        Expr::Index { base, key } => {
            rewrite_expr(base, rng);
            rewrite_expr(key, rng);
        }
        Expr::Paren(x) | Expr::Unop { expr: x, .. } => rewrite_expr(x, rng),
        Expr::Binop { lhs, rhs, .. } => {
            rewrite_expr(lhs, rng);
            rewrite_expr(rhs, rng);
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    Field::Positional(v) => rewrite_expr(v, rng),
                    Field::Named { value, .. } => rewrite_expr(value, rng),
                    Field::Keyed { key, value } => {
                        rewrite_expr(key, rng);
                        rewrite_expr(value, rng);
                    }
                }
            }
        }
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            rewrite_expr(cond, rng);
            rewrite_expr(then, rng);
            for (c, v) in else_ifs {
                rewrite_expr(c, rng);
                rewrite_expr(v, rng);
            }
            rewrite_expr(otherwise, rng);
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(e) = p {
                    rewrite_expr(e, rng);
                }
            }
        }
        _ => {}
    }
}

fn hexval(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        _ => None,
    }
}

fn push_utf8(out: &mut Vec<u8>, cp: u32) {
    if let Some(c) = char::from_u32(cp) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
}

fn decode(lit: &str) -> Option<Vec<u8>> {
    let b = lit.as_bytes();
    if b.is_empty() {
        return None;
    }
    if b[0] == b'[' {
        let mut i = 1;
        let mut eq = 0;
        while i < b.len() && b[i] == b'=' {
            eq += 1;
            i += 1;
        }
        if i >= b.len() || b[i] != b'[' {
            return None;
        }
        let open_end = i + 1;
        let close_len = eq + 2;
        if b.len() < open_end + close_len {
            return None;
        }
        let mut content = &b[open_end..b.len() - close_len];
        if content.first() == Some(&b'\n') {
            content = &content[1..];
        } else if content.starts_with(b"\r\n") {
            content = &content[2..];
        }
        return Some(content.to_vec());
    }
    let quote = b[0];
    if (quote != b'"' && quote != b'\'') || b.len() < 2 || b[b.len() - 1] != quote {
        return None;
    }
    let inner = &b[1..b.len() - 1];
    let mut out = Vec::new();
    let mut i = 0;
    while i < inner.len() {
        let c = inner[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let e = *inner.get(i)?;
        match e {
            b'n' => {
                out.push(b'\n');
                i += 1;
            }
            b't' => {
                out.push(b'\t');
                i += 1;
            }
            b'r' => {
                out.push(b'\r');
                i += 1;
            }
            b'a' => {
                out.push(7);
                i += 1;
            }
            b'b' => {
                out.push(8);
                i += 1;
            }
            b'f' => {
                out.push(12);
                i += 1;
            }
            b'v' => {
                out.push(11);
                i += 1;
            }
            b'\\' => {
                out.push(b'\\');
                i += 1;
            }
            b'"' => {
                out.push(b'"');
                i += 1;
            }
            b'\'' => {
                out.push(b'\'');
                i += 1;
            }
            b'\n' => {
                out.push(b'\n');
                i += 1;
            }
            b'\r' => {
                out.push(b'\n');
                i += 1;
                if inner.get(i) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'x' => {
                let hi = hexval(*inner.get(i + 1)?)?;
                let lo = hexval(*inner.get(i + 2)?)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'z' => {
                i += 1;
                while i < inner.len() && inner[i].is_ascii_whitespace() {
                    i += 1;
                }
            }
            b'u' => {
                if inner.get(i + 1) != Some(&b'{') {
                    return None;
                }
                let mut j = i + 2;
                let mut cp: u32 = 0;
                while j < inner.len() && inner[j] != b'}' {
                    cp = cp.checked_mul(16)?.checked_add(hexval(inner[j])?)?;
                    j += 1;
                }
                if inner.get(j) != Some(&b'}') {
                    return None;
                }
                push_utf8(&mut out, cp);
                i = j + 1;
            }
            d if d.is_ascii_digit() => {
                let mut val = (d - b'0') as u32;
                let mut k = 1;
                while k < 3 && inner.get(i + k).is_some_and(|c| c.is_ascii_digit()) {
                    val = val * 10 + (inner[i + k] - b'0') as u32;
                    k += 1;
                }
                if val > 255 {
                    return None;
                }
                out.push(val as u8);
                i += k;
            }
            _ => return None,
        }
    }
    Some(out)
}

fn encode(bytes: &[u8], rng: &mut u64) -> String {
    let mut s = String::with_capacity(bytes.len() * 3 + 2);
    s.push('"');
    let mut raw_run = 0u32;
    let max_raw = 2 + (splitmix64(rng) % 2) as u32;
    for &byte in bytes {
        let printable = (0x20..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\';
        let keep_raw = printable && raw_run < max_raw && splitmix64(rng) % 100 < 42;
        if keep_raw {
            s.push(byte as char);
            raw_run += 1;
            continue;
        }
        raw_run = 0;
        let forms = if byte < 0x80 { 3 } else { 2 };
        match splitmix64(rng) % forms {
            0 => s.push_str(&format!("\\{byte:03}")),
            1 => s.push_str(&format!("\\x{byte:02x}")),
            _ => s.push_str(&format!("\\u{{{byte:x}}}")),
        }
    }
    s.push('"');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(bytes: &[u8], seed: u64) -> Vec<u8> {
        let mut rng = seed;
        let lit = encode(bytes, &mut rng);
        decode(&lit).expect("encoded literal must decode")
    }

    #[test]
    fn byte_exact_across_cases_and_seeds() {
        let cases: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"HumanoidRootPart".to_vec(),
            b"a\"b'c\\d".to_vec(),
            vec![0, 1, 2, 9, 10, 13, 27, 127, 128, 200, 255],
            "héllo🙂".as_bytes().to_vec(),
            b"ends with digits 123".to_vec(),
            b"tab\tnewline\nnul\0end".to_vec(),
        ];
        for seed in [1u64, 42, 1337, 20260808] {
            for c in &cases {
                assert_eq!(&roundtrip(c, seed), c, "seed {seed} case {c:?}");
            }
        }
    }

    #[test]
    fn decodes_existing_source_forms() {
        assert_eq!(decode("\"HumanoidRootPart\"").unwrap(), b"HumanoidRootPart");
        assert_eq!(decode("'ab\\ncd'").unwrap(), b"ab\ncd");
        assert_eq!(decode("\"\\72\\u{6f}\\x21\"").unwrap(), b"Ho!");
        assert_eq!(decode("[[raw\nlong]]").unwrap(), b"raw\nlong");
        assert_eq!(decode("[==[a]]b]==]").unwrap(), b"a]]b");
        assert_eq!(decode("\"a\\z   \n b\"").unwrap(), b"ab");
    }

    #[test]
    fn clear_literal_broken_up() {
        let mut rng = 20260808u64;
        let lit = encode(b"HumanoidRootPart", &mut rng);
        assert!(
            !lit.contains("HumanoidRootPart"),
            "clear literal must not survive: {lit}"
        );
        assert_eq!(decode(&lit).unwrap(), b"HumanoidRootPart");
    }

    #[test]
    fn deterministic_per_seed() {
        let enc = |seed: u64| {
            let mut r = seed;
            encode(b"HumanoidRootPart", &mut r)
        };
        assert_eq!(enc(7), enc(7));
        assert_ne!(enc(7), enc(8));
    }
}
