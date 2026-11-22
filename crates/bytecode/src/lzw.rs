use std::collections::HashMap;

const FREEZE: u32 = 1 << 16;

pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_le_bytes().to_vec();
    if data.is_empty() {
        return out;
    }
    let mut dict: HashMap<Vec<u8>, u32> = (0..256u32).map(|i| (vec![i as u8], i)).collect();
    let mut next_code = 256u32;
    let mut width = 9u32;
    let mut codes: Vec<(u32, u32)> = Vec::new();
    let mut w: Vec<u8> = Vec::new();
    for &c in data {
        let mut wc = w.clone();
        wc.push(c);
        if dict.contains_key(&wc) {
            w = wc;
        } else {
            codes.push((dict[&w], width));
            if next_code < FREEZE {
                dict.insert(wc, next_code);
                next_code += 1;
                if next_code == (1 << width) && width < 16 {
                    width += 1;
                }
            }
            w = vec![c];
        }
    }
    codes.push((dict[&w], width));

    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for (code, cw) in codes {
        acc |= (code as u64) << bits;
        bits += cw;
        while bits >= 8 {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 {
        out.push((acc & 0xFF) as u8);
    }
    out
}

fn read_code(data: &[u8], width: u32, acc: &mut u64, bits: &mut u32, pos: &mut usize) -> u32 {
    while *bits < width {
        *acc |= (data[*pos] as u64) << *bits;
        *pos += 1;
        *bits += 8;
    }
    let code = (*acc & ((1u64 << width) - 1)) as u32;
    *acc >>= width;
    *bits -= width;
    code
}

pub fn decompress(data: &[u8]) -> Vec<u8> {
    if data.len() < 4 {
        return Vec::new();
    }
    let origlen = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if origlen == 0 {
        return Vec::new();
    }
    let mut dict: Vec<Vec<u8>> = (0..256u32).map(|i| vec![i as u8]).collect();
    let mut next_code = 256u32;
    let mut width = 9u32;
    let (mut acc, mut bits, mut pos) = (0u64, 0u32, 4usize);

    let prev_code = read_code(data, width, &mut acc, &mut bits, &mut pos);
    let mut prev = prev_code as usize;
    let mut out: Vec<u8> = dict[prev].clone();
    while out.len() < origlen {
        let code = read_code(data, width, &mut acc, &mut bits, &mut pos) as usize;
        let entry: Vec<u8> = if code < dict.len() {
            dict[code].clone()
        } else {
            let mut e = dict[prev].clone();
            e.push(dict[prev][0]);
            e
        };
        out.extend_from_slice(&entry);
        if next_code < FREEZE {
            let mut ne = dict[prev].clone();
            ne.push(entry[0]);
            dict.push(ne);
            next_code += 1;
            if next_code == (1 << width) - 1 && width < 16 {
                width += 1;
            }
        }
        prev = code;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x: u32 = 0x1234_5678;
        while v.len() < n {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let b = (x >> 16) as u8;
            if b < 80 {
                let run = (b as usize % 40) + 5;
                let rb = (x >> 8) as u8;
                for _ in 0..run {
                    v.push(rb);
                }
            } else {
                v.push(b);
            }
        }
        v.truncate(n);
        v
    }

    #[test]
    fn round_trips_edges_and_large() {
        for case in [
            vec![],
            vec![0u8],
            vec![255u8],
            vec![7u8; 1000],
            b"abcabcabcabc".to_vec(),
        ] {
            assert_eq!(decompress(&compress(&case)), case, "len {}", case.len());
        }

        let big = pseudo(300_000);
        let comp = compress(&big);
        assert_eq!(decompress(&comp), big, "large round-trip");
        assert!(comp.len() < big.len(), "should compress the redundant part");
    }
}
