use crate::crypt;
use crate::encoding::Encoding;
use crate::opcode::{self, Opcode, OperandRole};
use crate::proto::Proto;
use crate::superop;

const SEC_CODE: u8 = 2;
const SEC_PROTOS: u8 = 5;

pub struct ProtoStreamParams {
    pub base: u32,
    pub esk_sj: [u32; 8],
    pub esk_ej: [u32; 8],
    pub pmap_inv: [u8; 256],
    pub ipk: u32,
    pub spk: u32,
    pub cfk: u32,
    pub order: [u8; 3],
    pub maskperm: [u8; 3],
    pub gmode: u8,
}

impl ProtoStreamParams {
    pub fn derive(
        pid: u32,
        seed: u64,
        envdig: &[u32; 8],
        genkey: &[u32; 8],
        enc: &Encoding,
    ) -> Self {
        let base = crypt::opmask_key(seed);
        let (dom_sj, dom_qk, dom_ej) = crypt::struct_domains(seed);
        let esk_sj = crypt::struct_key(envdig, dom_sj);
        let esk_ej = crypt::struct_key(envdig, dom_ej);
        let pmap = crypt::proto_opmap(crypt::mapkey(seed), &crypt::struct_key(envdig, dom_qk), pid);
        let mut pmap_inv = [0u8; 256];
        for (k, &p) in pmap.iter().enumerate() {
            pmap_inv[p as usize] = k as u8;
        }
        let ipk = crypt::instr_patch_key(genkey, pid, crypt::instr_patch_domain(seed));
        let spk = crypt::instr_patch_key(genkey, pid, crypt::sidecar_patch_domain(seed));
        let cfk = crypt::instr_patch_key(genkey, pid, crypt::controlflow_patch_domain(seed));
        let _ = enc;
        ProtoStreamParams {
            base,
            esk_sj,
            esk_ej,
            pmap_inv,
            ipk,
            spk,
            cfk,
            order: crypt::oplayout_perm(seed, pid),
            maskperm: crypt::oplayout_maskperm(seed, pid),
            gmode: crypt::oplayout_gmode(seed, pid),
        }
    }
}

fn phys_to_opcode(enc: &Encoding) -> [Option<Opcode>; 256] {
    let mut table: [Option<Opcode>; 256] = [None; 256];
    for &(op, _) in opcode::ALL {
        table[enc.phys(op) as usize] = Some(op);
    }
    table
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, String> {
        let b = *self.data.get(self.pos).ok_or("stream: unexpected end")?;
        self.pos += 1;
        Ok(b)
    }

    fn uvarint(&mut self) -> Result<u64, String> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err("stream: varint too long".into());
            }
        }
    }

    fn uvarint_masked(
        &mut self,
        base: u32,
        esk: &[u32; 8],
        pid: u32,
        fidx: u32,
    ) -> Result<u64, String> {
        let mut result = 0u64;
        let mut shift = 0u32;
        let mut j = 0u32;
        loop {
            let b = self.u8()?;
            let data = (b & 0x7f) ^ crypt::opmask2_byte(base, esk, pid, fidx, 0, j);
            result |= (data as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            j += 1;
            if shift >= 64 {
                return Err("stream: masked varint too long".into());
            }
        }
    }

    fn svarint_masked(
        &mut self,
        base: u32,
        esk: &[u32; 8],
        pid: u32,
        pc: u32,
        slot: u32,
    ) -> Result<i64, String> {
        let mut u = 0u64;
        let mut shift = 0u32;
        let mut j = 0u32;
        loop {
            let b = self.u8()?;
            let data = (b & 0x7f) ^ crypt::opmask2_byte(base, esk, pid, pc, slot, j);
            u |= (data as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            j += 1;
            if shift >= 64 {
                return Err("stream: masked varint too long".into());
            }
        }
        Ok(((u >> 1) as i64) ^ -((u & 1) as i64))
    }
}

pub fn streaming_proto_digest(
    code_section: &[u8],
    p: &ProtoStreamParams,
    phys_map: &[Option<Opcode>; 256],
    pid: u32,
    patch_instrs: bool,
) -> Result<u32, String> {
    let mut c = Cursor {
        data: code_section,
        pos: 0,
    };
    let n = c.uvarint()?;
    let mut h: u32 = 0x9E37_79B9;
    for i in 0..n {
        let pc = i as u32 + 1;
        let permuted = c.u8()? ^ crypt::opmask_byte(p.base, &p.esk_sj, pid, pc);
        let phys = p.pmap_inv[permuted as usize];
        let op = phys_map[phys as usize].ok_or("stream: opcode byte maps to no opcode")?;
        h = h.rotate_left(7) ^ phys as u32;
        if crate::opcode::is_gensuper(op) {
            let _slot = c.svarint_masked(p.base, &p.esk_ej, pid, pc, 0)?;
            let _nlive = c.svarint_masked(p.base, &p.esk_ej, pid, pc, 1)?;
            let _nconst = c.svarint_masked(p.base, &p.esk_ej, pid, pc, 2)?;
            let len = c.svarint_masked(p.base, &p.esk_ej, pid, pc, 3)?;
            if !(0..=4096).contains(&len) {
                return Err("stream: gensuper interface length out of range".into());
            }

            for k in 0..len as usize {
                let o = c.svarint_masked(p.base, &p.esk_ej, pid, pc, (k + 4) as u32)?;
                h = h.rotate_left(5) ^ o as u32;
            }
        } else if superop::is_super(op) {
            let cnt = superop::operand_count(op);
            let mut recovered = vec![0i64; cnt];
            for phys in 0..cnt {
                let lslot = if p.gmode & 1 != 0 {
                    cnt - 1 - phys
                } else {
                    phys
                };
                let ser = c.svarint_masked(p.base, &p.esk_ej, pid, pc, phys as u32)?;
                let mut v = ser;
                if patch_instrs && opcode::patch_sidecar_role(op, lslot) != OperandRole::None {
                    let sid = crypt::SIDECAR_SLOT_BASE + lslot as u32;
                    if crypt::instr_patch_selected(p.spk, pc, sid) {
                        v -= crypt::instr_patch_delta(p.spk, pc, sid) as i64;
                    }
                }
                recovered[lslot] = v;
            }
            for &v in &recovered {
                h = h.rotate_left(5) ^ v as u32;
            }
        } else {
            let ser_mask = opcode::operand_serialized(op);
            let mut recovered = [0i64; 3];
            for slot in 0..3 {
                let logical = p.order[slot] as usize;
                if ser_mask[logical] {
                    let ser =
                        c.svarint_masked(p.base, &p.esk_ej, pid, pc, p.maskperm[slot] as u32)?;
                    let mut v = ser;
                    if patch_instrs {
                        if opcode::patch_cf_role(op, logical) != OperandRole::None {
                            let cid = crypt::CONTROLFLOW_SLOT_BASE + logical as u32;
                            if crypt::instr_patch_selected(p.cfk, pc, cid) {
                                v -= crypt::instr_patch_delta(p.cfk, pc, cid) as i64;
                            }
                        } else if opcode::patch_role(op, logical) != OperandRole::None
                            && crypt::instr_patch_selected(p.ipk, pc, logical as u32)
                        {
                            v -= crypt::instr_patch_delta(p.ipk, pc, logical as u32) as i64;
                        }
                    }
                    recovered[logical] = v;
                }
            }
            h = h.rotate_left(5) ^ if ser_mask[0] { recovered[0] as u32 } else { 0 };
            h = h.rotate_left(5) ^ if ser_mask[1] { recovered[1] as u32 } else { 0 };
            h = h.rotate_left(5) ^ if ser_mask[2] { recovered[2] as u32 } else { 0 };
        }
    }
    Ok(h)
}

fn collect_source(proto: &Proto, next_pid: &mut u32, out: &mut Vec<(u32, Proto)>) {
    let pid = *next_pid;
    *next_pid += 1;
    out.push((pid, proto.clone()));
    for child in &proto.protos {
        collect_source(child, next_pid, out);
    }
}

fn collect_serialized_codes(
    c: &mut Cursor,
    next_pid: &mut u32,
    out: &mut Vec<(u32, Vec<u8>)>,
    seed: u64,
    envdig: &[u32; 8],
    framing: bool,
) -> Result<(), String> {
    let pid = *next_pid;
    *next_pid += 1;
    let nsec = c.u8()?;
    let fam = crypt::framing_family(seed);
    let fbase = crypt::opmask_key(seed);
    let fsk = crypt::framing_key(seed, envdig);
    let mut fstate = crypt::framing_chain_root(seed, pid);
    let mut code: Option<Vec<u8>> = None;
    for _ in 0..nsec {
        let (tag, len) = if !framing {
            (c.u8()?, c.uvarint()? as usize)
        } else if fam == 0 {
            let t = c.u8()?;
            (t, c.uvarint_masked(fbase, &fsk, pid, fstate)? as usize)
        } else {
            let l = c.uvarint_masked(fbase, &fsk, pid, fstate)? as usize;
            (c.u8()?, l)
        };
        let start = c.pos;
        let end = start
            .checked_add(len)
            .ok_or("stream: section length overflow")?;
        if tag == SEC_CODE {
            code = Some(
                c.data
                    .get(start..end)
                    .ok_or("stream: code section out of range")?
                    .to_vec(),
            );
            c.pos = end;
        } else if tag == SEC_PROTOS {
            let count = c.uvarint()?;
            for _ in 0..count {
                collect_serialized_codes(c, next_pid, out, seed, envdig, framing)?;
            }
            c.pos = end;
        } else {
            c.pos = end;
        }
        if framing {
            fstate = crypt::framing_chain_step(seed, fstate, tag as u32, len as u64);
        }
    }
    if framing {
        let _ = c.uvarint_masked(fbase, &fsk, pid, fstate)?;
    }
    out.push((pid, code.ok_or("stream: proto missing CODE section")?));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_serialized_digests(
    main: &Proto,
    serialized: &[u8],
    salt_len: usize,
    seed: u64,
    envdig: &[u32; 8],
    genkey: &[u32; 8],
    enc: &Encoding,
    patch_instrs: bool,
    kmode: crate::kepoch::KepochMode,
    framing: bool,
) -> Result<usize, String> {
    let mut src: Vec<(u32, Proto)> = Vec::new();
    let mut spid = 0u32;
    collect_source(main, &mut spid, &mut src);

    let mut ser: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut c = Cursor {
        data: serialized,
        pos: salt_len,
    };
    let mut cpid = 0u32;
    collect_serialized_codes(&mut c, &mut cpid, &mut ser, seed, envdig, framing)?;

    if src.len() != ser.len() {
        return Err(format!(
            "stream: proto count mismatch (source {} vs serialized {})",
            src.len(),
            ser.len()
        ));
    }
    src.sort_by_key(|(pid, _)| *pid);
    ser.sort_by_key(|(pid, _)| *pid);

    let phys_map = phys_to_opcode(enc);
    for ((spid, proto), (cpid2, code)) in src.iter().zip(ser.iter()) {
        if spid != cpid2 {
            return Err(format!(
                "stream: pid alignment mismatch ({spid} vs {cpid2})"
            ));
        }
        let pid = *spid;
        let tokenized = crate::kepoch::tokenize_code(proto, pid, seed, kmode);
        let reference = crypt::proto_code_digest(&tokenized, enc);
        let params = ProtoStreamParams::derive(pid, seed, envdig, genkey, enc);
        let got = streaming_proto_digest(code, &params, &phys_map, pid, patch_instrs)?;
        if got != reference {
            return Err(format!(
                "stream: DIGEST MISMATCH at pid {pid}: streaming=0x{got:08X} reference=0x{reference:08X} (seed {seed}, patch {patch_instrs}, kmode {kmode:?})"
            ));
        }
    }
    Ok(src.len())
}
