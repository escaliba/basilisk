pub fn decode_number(text: &str) -> Option<f64> {
    let cleaned: String = text.chars().filter(|&c| c != '_').collect();
    let lower = cleaned.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok().map(|v| v as f64);
    }
    if let Some(bin) = lower.strip_prefix("0b") {
        return u64::from_str_radix(bin, 2).ok().map(|v| v as f64);
    }
    let normalized = if cleaned.starts_with('.') {
        format!("0{cleaned}")
    } else {
        cleaned
    };
    normalized.parse::<f64>().ok()
}

pub fn decode_string(text: &str) -> Option<Vec<u8>> {
    match text.as_bytes().first()? {
        b'"' | b'\'' => decode_escapes(&text[1..text.len() - 1]),
        b'[' => decode_long(text.as_bytes()),
        _ => None,
    }
}

pub fn decode_interp_chunk(chunk: &str) -> Option<Vec<u8>> {
    decode_escapes(chunk)
}

fn decode_escapes(inner: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    let mut buf = [0u8; 4];
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next()? {
            'a' => out.push(7),
            'b' => out.push(8),
            'f' => out.push(12),
            'n' => out.push(b'\n'),
            'r' => out.push(b'\r'),
            't' => out.push(b'\t'),
            'v' => out.push(11),
            '\\' => out.push(b'\\'),
            '"' => out.push(b'"'),
            '\'' => out.push(b'\''),
            '`' => out.push(b'`'),
            '{' => out.push(b'{'),
            '}' => out.push(b'}'),
            '\n' => out.push(b'\n'),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(b'\n');
            }
            'x' => {
                let hi = chars.next()?.to_digit(16)?;
                let lo = chars.next()?.to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
            }
            'z' => {
                while let Some(&w) = chars.peek() {
                    if w.is_whitespace() {
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            'u' => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut cp = 0u32;
                loop {
                    let h = chars.next()?;
                    if h == '}' {
                        break;
                    }
                    cp = cp.checked_mul(16)?.checked_add(h.to_digit(16)?)?;
                }
                out.extend_from_slice(char::from_u32(cp)?.encode_utf8(&mut buf).as_bytes());
            }
            d if d.is_ascii_digit() => {
                let mut val = d.to_digit(10)?;
                for _ in 0..2 {
                    match chars.peek() {
                        Some(&n) if n.is_ascii_digit() => {
                            val = val * 10 + n.to_digit(10)?;
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if val > 255 {
                    return None;
                }
                out.push(val as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

fn decode_long(bytes: &[u8]) -> Option<Vec<u8>> {
    if *bytes.first()? != b'[' {
        return None;
    }
    let mut i = 1;
    let mut level = 0;
    while bytes.get(i) == Some(&b'=') {
        level += 1;
        i += 1;
    }
    if bytes.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    let close = level + 2;
    if bytes.len() < i + close {
        return None;
    }
    let content = &bytes[i..bytes.len() - close];
    let content = if content.first() == Some(&b'\n') {
        &content[1..]
    } else if content.starts_with(b"\r\n") {
        &content[2..]
    } else {
        content
    };
    Some(content.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::approx_constant)]
    fn numbers() {
        assert_eq!(decode_number("42"), Some(42.0));
        assert_eq!(decode_number("0xFF"), Some(255.0));
        assert_eq!(decode_number("0xDEADBEEF"), Some(3735928559.0));
        assert_eq!(decode_number("0b1010"), Some(10.0));
        assert_eq!(decode_number("0b1111_0000"), Some(240.0));
        assert_eq!(decode_number("1_000_000"), Some(1000000.0));
        assert_eq!(decode_number("3.141_592"), Some(3.141592));
        assert_eq!(decode_number("0xFF_FF"), Some(65535.0));
        assert_eq!(decode_number("1e3"), Some(1000.0));
        assert_eq!(decode_number("2.5e-2"), Some(0.025));
        assert_eq!(decode_number("1E2"), Some(100.0));
        assert_eq!(decode_number(".25"), Some(0.25));
        assert_eq!(decode_number("100.0"), Some(100.0));
    }

    #[test]
    fn strings() {
        assert_eq!(decode_string("\"double\""), Some(b"double".to_vec()));
        assert_eq!(decode_string("'single'"), Some(b"single".to_vec()));
        assert_eq!(decode_string("\"tab\\tend\""), Some(b"tab\tend".to_vec()));
        assert_eq!(decode_string("\"q\\\"in\""), Some(b"q\"in".to_vec()));
        assert_eq!(decode_string("\"\\u{48}\\u{49}\""), Some(b"HI".to_vec()));
        assert_eq!(decode_string("\"\\65\\66\""), Some(b"AB".to_vec()));
        assert_eq!(decode_string("[[plain]]"), Some(b"plain".to_vec()));
        assert_eq!(decode_string("[==[a]==b]==]"), Some(b"a]==b".to_vec()));
    }
}
