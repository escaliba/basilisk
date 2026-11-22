pub const NFAM: usize = 4;
const NLOGOP: usize = 8;

fn xs32(mut x: u32) -> u32 {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}
fn fmix_local(mut h: u32, c1: u32, c2: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(c1);
    h ^= h >> 15;
    h = h.wrapping_mul(c2);
    h ^= h >> 16;
    h
}

pub fn gen_program(mk: u32, pid: u32, commitment: u32) -> Vec<u32> {
    let mut s = (mk ^ pid.rotate_left(13) ^ commitment) | 1;
    s = xs32(s);
    let n = 8 + (s % 17) as usize;
    let mut prog = Vec::with_capacity(n);
    for _ in 0..n {
        s = xs32(s);
        let logical = (s >> 3) % NLOGOP as u32;
        s = xs32(s);
        let operand = s & 0x0000_FFFF;
        prog.push((logical << 24) | operand);
    }
    prog
}

pub fn op_unit(logical: u32, operand: u32) -> (u8, Option<u32>) {
    let (sel, big) = match logical {
        0 => (0, Some(operand & 0xFFFF)),
        1 => (operand % 4, None),
        2 => (operand & 31, None),
        3 => (operand & 3, None),
        4 => (operand & 3, None),
        5 => (0, None),
        6 => (operand & 3, None),
        _ => (0, Some(operand & 0xFFFF)),
    };
    (((logical << 5) | sel) as u8, big)
}

pub fn activation_output(
    mk: u32,
    mapkey: u32,
    pid: u32,
    commitment: u32,
    probes: &[u32; NFAM],
    lexical_ticket: u32,
) -> u32 {
    let (c1, c2) = (mk | 1, mapkey | 1);
    let base = fmix_local(fmix_local(pid, c1, c2) ^ commitment, c1, c2);
    let mut acc = fmix_local(
        base ^ probes[(pid as usize) % NFAM] ^ lexical_ticket,
        c1,
        c2,
    );
    let mut r = [0u32; 4];
    for &word in &gen_program(mk, pid, commitment) {
        let operand = word & 0x00FF_FFFF;
        match (word >> 24) & 7 {
            0 => acc = fmix_local(acc.wrapping_add(operand), c1, c2),
            1 => acc ^= probes[(operand as usize) % NFAM],
            2 => acc = acc.rotate_left(operand & 31),
            3 => acc = acc.wrapping_add(r[(operand as usize) & 3]),
            4 => r[(operand as usize) & 3] = acc,
            5 => acc = fmix_local(acc, c1, c2),
            6 => acc ^= r[(operand as usize) & 3],
            _ => acc = fmix_local(acc ^ (operand | 1), c1, c2),
        }
    }
    acc
}

pub const ACT_RUNTIME_LUAU: &str = "\
local function actOutput(pid, commitment, data, apos, alen, probes, lexTicket)\n\
\tif not data then return 0 end\n\
\tlocal imap = buildinvmap(pid)\n\
\tlocal base = fmix(bxor(fmix(pid), commitment))\n\
\tlocal acc = fmix(bxor(base, probes[pid % 4 + 1], lexTicket))\n\
\tlocal r0, r1, r2, r3 = 0, 0, 0, 0\n\
\tlocal pos = apos\n\
\tfor i = 1, alen do\n\
\t\tlocal raw = byte(data, pos)\n\
\t\tif not raw then break end\n\
\t\tlocal unit = imap[bxor(raw, opmask(pid, i))]\n\
\t\tpos = pos + 1\n\
\t\tlocal op = rshift(unit, 5)\n\
\t\tlocal v = band(unit, 31)\n\
\t\tif op == 0 or op == 7 then\n\
\t\t\tlocal result, mul, j = 0, 1, 0\n\
\t\t\twhile true do\n\
\t\t\t\tlocal b = byte(data, pos)\n\
\t\t\t\tif not b then break end\n\
\t\t\t\tpos = pos + 1\n\
\t\t\t\tresult = result + bxor(b % 128, opmask2(pid, i, 0, j)) * mul\n\
\t\t\t\tif b < 128 then break end\n\
\t\t\t\tmul = mul * 128\n\
\t\t\t\tj = j + 1\n\
\t\t\tend\n\
\t\t\tif result % 2 == 0 then v = result // 2 else v = -((result + 1) // 2) end\n\
\t\tend\n\
\t\tif op == 0 then acc = fmix((acc + v) % 0x100000000)\n\
\t\telseif op == 1 then acc = bxor(acc, probes[v % 4 + 1])\n\
\t\telseif op == 2 then acc = lrotate(acc, band(v, 31))\n\
\t\telseif op == 3 then local k = band(v, 3) acc = (acc + (k == 0 and r0 or k == 1 and r1 or k == 2 and r2 or r3)) % 0x100000000\n\
\t\telseif op == 4 then local k = band(v, 3) if k == 0 then r0 = acc elseif k == 1 then r1 = acc elseif k == 2 then r2 = acc else r3 = acc end\n\
\t\telseif op == 5 then acc = fmix(acc)\n\
\t\telseif op == 6 then local k = band(v, 3) acc = bxor(acc, k == 0 and r0 or k == 1 and r1 or k == 2 and r2 or r3)\n\
\t\telse acc = fmix(bxor(acc, bor(v, 1))) end\n\
\tend\n\
\treturn acc\n\
end\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn run_from_stored(
        mk: u32,
        mapkey: u32,
        pid: u32,
        commitment: u32,
        probes: &[u32; NFAM],
        lex: u32,
    ) -> u32 {
        let (c1, c2) = (mk | 1, mapkey | 1);
        let base = fmix_local(fmix_local(pid, c1, c2) ^ commitment, c1, c2);
        let mut acc = fmix_local(base ^ probes[(pid as usize) % NFAM] ^ lex, c1, c2);
        let mut r = [0u32; 4];
        for &word in &gen_program(mk, pid, commitment) {
            let logical = (word >> 24) & 7;
            let operand = word & 0xFFFF;
            let (unit, big) = op_unit(logical, operand);
            let op = (unit >> 5) as u32;
            let sel = (unit & 31) as u32;
            let v = if op == 0 || op == 7 {
                big.unwrap()
            } else {
                sel
            };
            match op {
                0 => acc = fmix_local(acc.wrapping_add(v), c1, c2),
                1 => acc ^= probes[(v as usize) % NFAM],
                2 => acc = acc.rotate_left(v & 31),
                3 => acc = acc.wrapping_add(r[(v & 3) as usize]),
                4 => r[(v & 3) as usize] = acc,
                5 => acc = fmix_local(acc, c1, c2),
                6 => acc ^= r[(v & 3) as usize],
                _ => acc = fmix_local(acc ^ (v | 1), c1, c2),
            }
        }
        acc
    }

    #[test]
    fn stored_program_reconstructs_activation_output() {
        for b in 0..24u32 {
            let mk = xs32(b.wrapping_mul(0x9E37_79B9) | 1);
            let mapkey = xs32(b.wrapping_mul(0x85EB_CA6B) | 1);
            for i in 0..48u32 {
                let pid = xs32(b ^ i.wrapping_mul(0x1000_0001)) & 0x1F_FFFF;
                let commitment = xs32(b ^ i ^ 0xC0DE);
                let lex = xs32(b ^ i ^ 0x71C);
                let mut probes = [0u32; NFAM];
                for (k, p) in probes.iter_mut().enumerate() {
                    *p = xs32(b ^ i ^ (k as u32).wrapping_shl(8) ^ 0x51ED);
                }
                assert_eq!(
                    run_from_stored(mk, mapkey, pid, commitment, &probes, lex),
                    activation_output(mk, mapkey, pid, commitment, &probes, lex),
                    "stored/packed program must reconstruct the fold (build {b}, i {i})"
                );
            }
        }
    }

    #[test]
    fn programs_are_structurally_diverse() {
        let mk = 0x9E37_79B9u32;
        let mut lengths = HashSet::new();
        let mut sequences = HashSet::new();
        for pid in 0..1176u32 {
            let prog = gen_program(mk, pid, pid.wrapping_mul(2654435761));
            lengths.insert(prog.len());
            sequences.insert(
                prog.iter()
                    .map(|w| ((w >> 24) & 7) as u8)
                    .collect::<Vec<u8>>(),
            );
        }
        assert!(
            lengths.len() >= 8,
            "program lengths span the 8..=24 range: {}",
            lengths.len()
        );
        assert!(
            sequences.len() >= 1150,
            "op sequences are essentially per-proto unique: {}",
            sequences.len()
        );
    }

    #[test]
    fn wrong_probe_families_change_the_activation_output() {
        let probes = [1u32, 2, 3, 4];
        let wrong = [0x1000_0001u32, 0x2000_0002, 0x3000_0003, 0x4000_0004];
        let (mut p_changed, mut l_changed) = (0u32, 0u32);
        for pid in 0..64u32 {
            if activation_output(0x1234, 0x5678, pid, 0xABCD, &probes, 0x11)
                != activation_output(0x1234, 0x5678, pid, 0xABCD, &wrong, 0x11)
            {
                p_changed += 1;
            }
            if activation_output(0x1234, 0x5678, pid, 0xABCD, &probes, 0x11)
                != activation_output(0x1234, 0x5678, pid, 0xABCD, &probes, 0x22)
            {
                l_changed += 1;
            }
        }
        assert!(
            p_changed >= 48,
            "probe families participate in most activation outputs: {p_changed}/64"
        );
        assert!(
            l_changed >= 48,
            "lexical ticket participates in most activation outputs: {l_changed}/64"
        );
    }
}
