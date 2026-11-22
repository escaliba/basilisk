use std::io::Write;
use std::process::Command;

use bytecode::actvm;
use bytecode::crypt;

fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn luau_u32_array(v: &[u32]) -> String {
    format!(
        "{{{}}}",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
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

fn luau_bytes(bytes: &[u8]) -> String {
    let mut s = String::from("\"");
    for &b in bytes {
        s.push_str(&format!("\\{b:03}"));
    }
    s.push('"');
    s
}

#[test]
fn build_and_runtime_activation_output_is_bit_identical() {
    let Some(luau) = which_luau() else {
        eprintln!("skipping: luau CLI not found on PATH");
        return;
    };

    let mut cases = String::new();
    let mut n_cases = 0u32;
    for b in 0..12u64 {
        let mk = splitmix(b ^ 0x4D4B_5345_4544) as u32;
        let mapkey = splitmix(b ^ 0x5AA5) as u32;
        let dom_sj = mk;
        let dom_qk = mapkey;
        let dom_ej = mk.rotate_left(16) ^ mapkey;
        for i in 0..40u64 {
            let mut envdig = [0u32; 8];
            for (k, e) in envdig.iter_mut().enumerate() {
                *e = splitmix(b ^ i ^ (k as u64).wrapping_shl(48) ^ 0xE7D1) as u32;
            }
            let esk_sj = crypt::struct_key(&envdig, dom_sj);
            let esk_qk = crypt::struct_key(&envdig, dom_qk);
            let esk_ej = crypt::struct_key(&envdig, dom_ej);
            let pid = (splitmix(b ^ i.wrapping_mul(0x1_0000_0001)) & 0x1F_FFFF) as u32;
            let pmap = crypt::proto_opmap(mapkey, &esk_qk, pid);
            let commitment = splitmix(b ^ i ^ 0xC0DE) as u32;
            let lex = splitmix(b ^ i ^ 0x71C) as u32;
            let probes = [
                envdig[0] ^ envdig[4],
                envdig[1] ^ envdig[5],
                envdig[2] ^ envdig[6],
                envdig[3] ^ envdig[7],
            ];
            let exp = actvm::activation_output(mk, mapkey, pid, commitment, &probes, lex);

            let prog = actvm::gen_program(mk, pid, commitment);
            let mut stream = Vec::new();
            for (i0, &word) in prog.iter().enumerate() {
                let op_i = i0 as u32 + 1;
                let logical = (word >> 24) & 7;
                let operand = word & 0xFFFF;
                let (unit, big) = actvm::op_unit(logical, operand);
                stream.push(pmap[unit as usize] ^ crypt::opmask_byte(mk, &esk_sj, pid, op_i));
                if let Some(v) = big {
                    masked_svarint(&mut stream, v as i64, mk, &esk_ej, pid, op_i);
                }
            }

            cases.push_str(&format!(
                "{{mk={},mapkey={},pid={},commit={},lex={},alen={},exp={},data={},sksj={},skqk={},skej={},probes={}}},\n",
                mk,
                mapkey,
                pid,
                commitment,
                lex,
                prog.len(),
                exp,
                luau_bytes(&stream),
                luau_u32_array(&esk_sj),
                luau_u32_array(&esk_qk),
                luau_u32_array(&esk_ej),
                luau_u32_array(&probes),
            ));
            n_cases += 1;
        }
    }

    let harness = format!(
        "local bxor,band,rshift,lshift,lrotate,bor = bit32.bxor,bit32.band,bit32.rshift,bit32.lshift,bit32.lrotate,bit32.bor\n\
         local byte = string.byte\n\
         local MK, MAPKEY, FM1, FM2, SK_SJ, SK_QK, SK_EJ\n\
         local function fmix(h)\n\
         \th = bxor(h, rshift(h, 16))\n\
         \th = ((h % 65536) * FM1 + ((h // 65536) * FM1 % 65536) * 65536) % 0x100000000\n\
         \th = bxor(h, rshift(h, 15))\n\
         \th = ((h % 65536) * FM2 + ((h // 65536) * FM2 % 65536) * 65536) % 0x100000000\n\
         \th = bxor(h, rshift(h, 16))\n\
         \treturn h\n\
         end\n\
         local function opmask(pid, i)\n\
         \tlocal h = bxor(MK, SK_SJ[band(i, 7) + 1], lrotate(pid, 13))\n\
         \th = bxor(h, lrotate(i, 7))\n\
         \th = bxor(h, rshift(h, 11))\n\
         \th = bxor(lrotate(h, 5), i)\n\
         \th = bxor(h, rshift(h, 6))\n\
         \treturn band(rshift(h, 3), 0xFF)\n\
         end\n\
         local function opmask2(pid, i, slot, j)\n\
         \tlocal h = bxor(MK, SK_EJ[band(i + slot, 7) + 1], lrotate(pid, 13), lrotate(i, 7), lrotate(slot, 3), lrotate(j, 19))\n\
         \th = bxor(h, rshift(h, 15))\n\
         \th = lrotate(h, 13)\n\
         \th = bxor(h, rshift(h, 11))\n\
         \th = lrotate(h, 7)\n\
         \th = bxor(h, rshift(h, 17))\n\
         \tlocal f = bxor(h, rshift(h, 10), rshift(h, 20))\n\
         \treturn band(f, 0x7F)\n\
         end\n\
         local function pmix(pid, i)\n\
         \tlocal h = bxor(MAPKEY, SK_QK[band(i, 7) + 1], lrotate(pid, 13), lrotate(i, 21))\n\
         \th = bxor(h, rshift(h, 16))\n\
         \th = lrotate(h, 13)\n\
         \th = bxor(h, rshift(h, 11))\n\
         \th = lrotate(h, 7)\n\
         \th = bxor(h, rshift(h, 17))\n\
         \treturn h\n\
         end\n\
         local function buildinvmap(pid)\n\
         \tlocal perm = {{}}\n\
         \tfor k = 0, 255 do perm[k] = k end\n\
         \tfor i = 255, 1, -1 do\n\
         \t\tlocal j = pmix(pid, i) % (i + 1)\n\
         \t\tperm[i], perm[j] = perm[j], perm[i]\n\
         \tend\n\
         \tlocal inv = {{}}\n\
         \tfor k = 0, 255 do inv[perm[k]] = k end\n\
         \treturn inv\n\
         end\n\
         {rt}\
         local cases = {{\n{cases}}}\n\
         local ok, bad = 0, 0\n\
         for _, c in ipairs(cases) do\n\
         \tMK, MAPKEY = c.mk, c.mapkey\n\
         \tFM1 = c.mk - c.mk % 2 + 1\n\
         \tFM2 = c.mapkey - c.mapkey % 2 + 1\n\
         \tSK_SJ, SK_QK, SK_EJ = c.sksj, c.skqk, c.skej\n\
         \tif actOutput(c.pid, c.commit, c.data, 1, c.alen, c.probes, c.lex) == c.exp then ok = ok + 1 else bad = bad + 1 end\n\
         end\n\
         print(string.format(\"ACTVM_DIFF ok=%d bad=%d\", ok, bad))\n",
        rt = actvm::ACT_RUNTIME_LUAU,
        cases = cases,
    );

    let path =
        std::env::temp_dir().join(format!("basilisk_actvm_diff_{}.luau", std::process::id()));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(harness.as_bytes())
        .unwrap();
    let out = Command::new(&luau).arg(&path).output().expect("run luau");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "luau failed: {stderr}\n{stdout}");
    assert!(
        stdout.contains(&format!("ACTVM_DIFF ok={n_cases} bad=0")),
        "stored activation-program decode mismatch across {n_cases} programs: {stdout}{stderr}"
    );
}

fn which_luau() -> Option<String> {
    for c in ["luau", "/opt/homebrew/bin/luau", "/usr/local/bin/luau"] {
        if Command::new(c)
            .arg("--help")
            .output()
            .map(|o| o.status.success() || !o.stdout.is_empty())
            .unwrap_or(false)
        {
            return Some(c.to_string());
        }
    }
    None
}
