use bytecode::actvm;
use bytecode::crypt;

fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

struct BuildParams {
    mk: u32,
    esk_sj: [u32; 8],
    esk_ej: [u32; 8],
    esk_qk: [u32; 8],
}

fn build_params(seed: u64) -> BuildParams {
    let mk = crypt::opmask_key(seed);
    let mapkey = crypt::mapkey(seed);
    let mut envdig = [0u32; 8];
    for (k, e) in envdig.iter_mut().enumerate() {
        *e = splitmix(seed ^ (k as u64).wrapping_shl(40) ^ 0xE7D1) as u32;
    }
    BuildParams {
        mk,
        esk_sj: crypt::struct_key(&envdig, mk),
        esk_ej: crypt::struct_key(&envdig, mk.rotate_left(16) ^ mapkey),
        esk_qk: crypt::struct_key(&envdig, mapkey),
    }
}

fn mapkey_of(seed: u64) -> u32 {
    crypt::mapkey(seed)
}

fn masked_svarint(out: &mut Vec<u8>, v: i64, base: u32, esk: &[u32; 8], pid: u32, pc: u32) {
    let mut u = ((v << 1) ^ (v >> 63)) as u64;
    let mut j = 0u32;
    loop {
        let data = (u & 0x7F) as u8;
        u >>= 7;
        let masked = data ^ crypt::opmask2_byte(base, esk, pid, pc, 0, j);
        if u != 0 {
            out.push(masked | 0x80);
            j += 1;
        } else {
            out.push(masked);
            break;
        }
    }
}

fn imap_of(pmap: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (k, &p) in pmap.iter().enumerate() {
        inv[p as usize] = k as u8;
    }
    inv
}

fn encode(logical: &[(u32, u32)], p: &BuildParams, mapkey: u32, pid: u32) -> Vec<u8> {
    let pmap = crypt::proto_opmap(mapkey, &p.esk_qk, pid);
    let mut out = Vec::new();
    for (i0, &(op, operand)) in logical.iter().enumerate() {
        let i = i0 as u32 + 1;
        let (unit, big) = actvm::op_unit(op, operand);
        out.push(pmap[unit as usize] ^ crypt::opmask_byte(p.mk, &p.esk_sj, pid, i));
        if let Some(v) = big {
            masked_svarint(&mut out, v as i64, p.mk, &p.esk_ej, pid, i);
        }
    }
    out
}

fn decode(bytes: &[u8], p: &BuildParams, mapkey: u32, pid: u32, n: usize) -> Vec<(u32, u32)> {
    let imap = imap_of(&crypt::proto_opmap(mapkey, &p.esk_qk, pid));
    let mut out = Vec::new();
    let mut pos = 0usize;
    for i0 in 0..n {
        let i = i0 as u32 + 1;
        let Some(&raw) = bytes.get(pos) else { break };
        pos += 1;
        let unit = imap[(raw ^ crypt::opmask_byte(p.mk, &p.esk_sj, pid, i)) as usize] as u32;
        let op = unit >> 5;
        let mut v = unit & 31;
        if op == 0 || op == 7 {
            let mut result = 0u64;
            let mut j = 0u32;
            loop {
                let Some(&b) = bytes.get(pos) else { break };
                pos += 1;
                result |= ((b ^ crypt::opmask2_byte(p.mk, &p.esk_ej, pid, i, 0, j)) as u64 & 0x7F)
                    << (7 * j);
                if b < 128 {
                    break;
                }
                j += 1;
            }
            v = (result >> 1) as u32;
        }
        out.push((op, v));
    }
    out
}

fn logical_program(seed: u64, pid: u32) -> Vec<(u32, u32)> {
    actvm::gen_program(crypt::opmask_key(seed), pid, splitmix(seed ^ 0xC0DE) as u32)
        .iter()
        .map(|&w| {
            let op = (w >> 24) & 7;
            let (unit, big) = actvm::op_unit(op, w & 0xFFFF);
            (op, big.unwrap_or((unit & 31) as u32))
        })
        .collect()
}

#[test]
fn physical_representation_differs_materially_across_builds() {
    let seeds = [0x1111u64, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666];
    let pids = [3u32, 41, 258, 977];

    let mut total_byte_diff = 0.0f64;
    let mut pairs = 0u32;
    let mut phys_id_diff_builds = 0u32;

    for &pid in &pids {
        let logical = logical_program(0xF1DD, pid);
        let encs: Vec<(u64, Vec<u8>)> = seeds
            .iter()
            .map(|&s| (s, encode(&logical, &build_params(s), mapkey_of(s), pid)))
            .collect();

        for &(sa, ref a) in &encs {
            for &(sb, ref b) in &encs {
                if sa >= sb {
                    continue;
                }
                let self_dec = decode(a, &build_params(sa), mapkey_of(sa), pid, logical.len());
                assert_eq!(
                    self_dec, logical,
                    "own-params decode must roundtrip (seed {sa:#x}, pid {pid})"
                );

                let len = a.len().min(b.len());
                let diff = (0..len).filter(|&k| a[k] != b[k]).count() as f64 / len as f64;
                total_byte_diff += diff;
                pairs += 1;
            }
        }
        let unit_bytes = |s: u64| -> Vec<u8> {
            let p = build_params(s);
            let pmap = crypt::proto_opmap(mapkey_of(s), &p.esk_qk, pid);
            (0u32..8)
                .map(|l| pmap[((l << 5) & 0xFF) as usize])
                .collect()
        };
        if unit_bytes(seeds[0]) != unit_bytes(seeds[1]) {
            phys_id_diff_builds += 1;
        }
    }

    let avg = total_byte_diff / pairs as f64;
    println!("CROSSBUILD avg_byte_diff={avg:.3} pairs={pairs} phys_id_diff_pids={phys_id_diff_builds}/{}", pids.len());
    assert!(
        avg > 0.5,
        "stored physical bytes must differ materially across builds (avg diff {avg:.3})"
    );
    assert_eq!(
        phys_id_diff_builds,
        pids.len() as u32,
        "per-build physical opcode identity must differ for every proto"
    );
}

#[test]
fn build_a_normalizer_does_not_parse_build_b() {
    let seed_a = 0xA1A1u64;
    let seed_b = 0xB2B2u64;
    let pids = [5u32, 77, 611];

    let mut mis_total = 0.0f64;
    for &pid in &pids {
        let logical = logical_program(0x5EED, pid);
        let bytes_b = encode(&logical, &build_params(seed_b), mapkey_of(seed_b), pid);
        let own = decode(
            &bytes_b,
            &build_params(seed_b),
            mapkey_of(seed_b),
            pid,
            logical.len(),
        );
        assert_eq!(
            own, logical,
            "build B self-decode must roundtrip (pid {pid})"
        );
        let foreign = decode(
            &bytes_b,
            &build_params(seed_a),
            mapkey_of(seed_a),
            pid,
            logical.len(),
        );
        let mism = (0..logical.len())
            .filter(|&k| foreign.get(k) != own.get(k))
            .count() as f64
            / logical.len() as f64;
        mis_total += mism;
    }
    let avg = mis_total / pids.len() as f64;
    println!("CROSSBUILD_REUSE avg_op_mismatch_A_on_B={avg:.3}");
    assert!(
        avg > 0.6,
        "a Build-A normalizer must mis-decode most ops of a Build-B artifact (got {avg:.3})"
    );
}
