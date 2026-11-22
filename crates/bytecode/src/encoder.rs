use crate::encoding::Encoding;
use crate::format::{FormatConfig, ProtoEncodingMode};
use crate::inst::Inst;
use crate::proto::{Const, Proto, UpvalDesc};
use crate::{crypt, opcode};

const VERSION: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RootPaging {
    Paged,
    Unpaged,
}

const SEC_PARAMS: u8 = 1;
const SEC_CODE: u8 = 2;
const SEC_CONSTS: u8 = 3;
const SEC_UPVALS: u8 = 4;
const SEC_PROTOS: u8 = 5;
const SEC_LINEINFO: u8 = 6;
const SEC_FRAME_CONST_EXCLUDE: u8 = 7;
const SEC_ACT: u8 = 8;

const K_NUMBER: u8 = 0;
const K_STRING: u8 = 1;

const AEAD_TAG_BYTES: usize = 8;
const RAW_NUMBER_BLOB: usize = AEAD_TAG_BYTES + 1 + 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionStats {
    pub raw_total_bytes: usize,
    pub code_bytes: usize,
    pub const_bytes: usize,
    pub number_const_bytes: usize,
    pub string_const_bytes: usize,
    pub other_const_bytes: usize,
    pub upvalue_bytes: usize,
    pub proto_meta_bytes: usize,
    pub child_proto_bytes: usize,
    pub lineinfo_bytes: usize,
    pub section_header_bytes: usize,
    pub aead_tag_bytes: usize,
    pub const_count: usize,
    pub number_const_raw_count: usize,
    pub number_const_dense_count: usize,
    pub number_const_raw_bytes: usize,
    pub number_const_dense_bytes: usize,
    pub number_const_dense_saved_bytes: usize,
    pub kepoch_wide_skips: usize,
    pub code_opcode_bytes: usize,
    pub code_operand_bytes: usize,
    pub code_dead_operand_bytes: usize,
    pub code_dead_operand_count: usize,
    pub code_live_operand_bytes: usize,
    pub code_arity_saved_bytes: usize,
    pub act_program_bytes: usize,
}

fn uvarint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

fn svarint_len(v: i64) -> usize {
    uvarint_len(((v << 1) ^ (v >> 63)) as u64)
}

fn write_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn write_svarint(out: &mut Vec<u8>, v: i64) {
    write_uvarint(out, ((v << 1) ^ (v >> 63)) as u64);
}

fn write_svarint_masked(
    out: &mut Vec<u8>,
    v: i64,
    base: u32,
    esk: &[u32; 8],
    pid: u32,
    pc: u32,
    slot: u32,
) {
    let mut u = ((v << 1) ^ (v >> 63)) as u64;
    let mut j = 0u32;
    loop {
        let data = (u & 0x7F) as u8;
        u >>= 7;
        let masked = data ^ crypt::opmask2_byte(base, esk, pid, pc, slot, j);
        if u != 0 {
            out.push(masked | 0x80);
            j += 1;
        } else {
            out.push(masked);
            break;
        }
    }
}

fn write_uvarint_masked(
    out: &mut Vec<u8>,
    mut v: u64,
    fbase: u32,
    fsk: &[u32; 8],
    pid: u32,
    fidx: u32,
) {
    let mut j = 0u32;
    loop {
        let data = (v & 0x7F) as u8;
        v >>= 7;
        let masked = data ^ crypt::opmask2_byte(fbase, fsk, pid, fidx, 0, j);
        if v != 0 {
            out.push(masked | 0x80);
            j += 1;
        } else {
            out.push(masked);
            break;
        }
    }
}

#[cfg(test)]
fn read_uvarint_masked(
    data: &[u8],
    pos: &mut usize,
    fbase: u32,
    fsk: &[u32; 8],
    pid: u32,
    fidx: u32,
) -> u64 {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut j = 0u32;
    loop {
        let b = data[*pos];
        *pos += 1;
        result |= (((b & 0x7F) ^ crypt::opmask2_byte(fbase, fsk, pid, fidx, 0, j)) as u64) << shift;
        if b < 0x80 {
            break;
        }
        shift += 7;
        j += 1;
    }
    result
}

pub fn serialize(main: &Proto) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(VERSION);
    out.push(0);
    write_proto(&mut out, main);
    out
}

fn write_proto(out: &mut Vec<u8>, proto: &Proto) {
    let mut params = Vec::new();
    params.push(proto.num_params);
    params.push(proto.is_vararg as u8);
    write_uvarint(&mut params, proto.max_stack as u64);

    let mut code = Vec::new();
    write_uvarint(&mut code, proto.code.len() as u64);
    for inst in &proto.code {
        code.push(opcode::concrete(inst.op));
        if opcode::is_gensuper(inst.op) {
            write_svarint(&mut code, inst.a as i64);
            write_svarint(&mut code, inst.b as i64);
            write_svarint(&mut code, inst.c as i64);
            write_svarint(&mut code, inst.ops.len() as i64);
            for &o in &inst.ops {
                write_svarint(&mut code, o as i64);
            }
        } else if crate::superop::is_super(inst.op) {
            for &o in &inst.ops {
                write_svarint(&mut code, o as i64);
            }
        } else {
            write_svarint(&mut code, inst.a as i64);
            write_svarint(&mut code, inst.b as i64);
            write_svarint(&mut code, inst.c as i64);
        }
    }

    let mut consts = Vec::new();
    write_uvarint(&mut consts, proto.consts.len() as u64);
    for k in &proto.consts {
        match k {
            Const::Number(n) | Const::FlatBlockId(n) => {
                consts.push(K_NUMBER);
                consts.extend_from_slice(&n.to_le_bytes());
            }
            Const::Str(bytes) => {
                consts.push(K_STRING);
                write_uvarint(&mut consts, bytes.len() as u64);
                consts.extend_from_slice(bytes);
            }
        }
    }

    let mut upvals = Vec::new();
    write_uvarint(&mut upvals, proto.upvals.len() as u64);
    for u in &proto.upvals {
        upvals.push(u.in_stack as u8);
        write_uvarint(&mut upvals, u.index as u64);
    }

    let mut protos = Vec::new();
    write_uvarint(&mut protos, proto.protos.len() as u64);
    for child in &proto.protos {
        write_proto(&mut protos, child);
    }

    let mut lines = Vec::new();
    write_uvarint(&mut lines, proto.line_info.len() as u64);
    for l in &proto.line_info {
        write_uvarint(&mut lines, *l as u64);
    }

    let sections = [
        (SEC_PARAMS, params),
        (SEC_CODE, code),
        (SEC_CONSTS, consts),
        (SEC_UPVALS, upvals),
        (SEC_PROTOS, protos),
        (SEC_LINEINFO, lines),
    ];
    out.push(sections.len() as u8);
    for (tag, data) in sections {
        out.push(tag);
        write_uvarint(out, data.len() as u64);
        out.extend_from_slice(&data);
    }
}

pub fn serialize_encrypted(
    main: &Proto,
    seed: u64,
    enc: &Encoding,
    anti_envlog: bool,
    profile: crypt::TargetProfile,
    canary: bool,
    line_info: bool,
    kmode: crate::kepoch::KepochMode,
) -> Vec<u8> {
    let fmt = FormatConfig::layout(line_info, kmode, false, false, false, false, false);
    serialize_encrypted_full(main, seed, enc, anti_envlog, profile, canary, &fmt, None)
}

pub fn serialize_encrypted_frame_probe(
    main: &Proto,
    seed: u64,
    enc: &Encoding,
    anti_envlog: bool,
    profile: crypt::TargetProfile,
    canary: bool,
    line_info: bool,
    kmode: crate::kepoch::KepochMode,
) -> Vec<u8> {
    let fmt = FormatConfig::layout(line_info, kmode, true, false, false, false, false);
    serialize_encrypted_full(main, seed, enc, anti_envlog, profile, canary, &fmt, None)
}

pub fn serialize_encrypted_measured(
    main: &Proto,
    seed: u64,
    enc: &Encoding,
    anti_envlog: bool,
    profile: crypt::TargetProfile,
    canary: bool,
    line_info: bool,
    kmode: crate::kepoch::KepochMode,
    stats: Option<&mut SectionStats>,
) -> Vec<u8> {
    let fmt = FormatConfig::layout(line_info, kmode, false, false, false, false, false);
    serialize_encrypted_full(main, seed, enc, anti_envlog, profile, canary, &fmt, stats)
}

pub fn serialize_encrypted_measured_frame_probe(
    main: &Proto,
    seed: u64,
    enc: &Encoding,
    anti_envlog: bool,
    profile: crypt::TargetProfile,
    canary: bool,
    line_info: bool,
    kmode: crate::kepoch::KepochMode,
    stats: Option<&mut SectionStats>,
) -> Vec<u8> {
    let fmt = FormatConfig::layout(line_info, kmode, true, false, false, false, false);
    serialize_encrypted_full(main, seed, enc, anti_envlog, profile, canary, &fmt, stats)
}

#[allow(clippy::too_many_arguments)]
pub fn const_sec_family(seed: u64, on: bool) -> u8 {
    if !on {
        return 0;
    }
    let mut x = seed ^ 0x_5345_4D46_414D_3031;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    (x & 1) as u8
}

pub fn instr_family(seed: u64, on: bool) -> u8 {
    if !on {
        return 0;
    }
    let mut x = seed ^ 0x_494E_5354_4652_4D31;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    (x & 1) as u8
}

pub fn state_family(seed: u64, on: bool) -> u8 {
    if !on {
        return 0;
    }
    let mut x = seed ^ 0x_5354_4154_454D_3031;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    (x & 1) as u8
}

pub fn serialize_encrypted_full(
    main: &Proto,
    seed: u64,
    enc: &Encoding,
    anti_envlog: bool,
    profile: crypt::TargetProfile,
    canary: bool,
    fmt: &FormatConfig,
    mut stats: Option<&mut SectionStats>,
) -> Vec<u8> {
    let salt = derive_salt(seed);
    let envdig = crypt::env_fingerprint_digest(seed, profile);
    let genkey = crypt::gen_key(
        &salt,
        crypt::code_digest(main, enc),
        &envdig,
        &compute_probes(seed, anti_envlog, profile, canary),
    );

    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    if let Some(s) = stats.as_deref_mut() {
        s.section_header_bytes += salt.len();
    }
    let mut pid = 0u32;
    let probed;
    let main = if main.consts.is_empty() {
        let mut m = main.clone();
        m.consts.push(Const::Number(0.0));
        probed = m;
        &probed
    } else {
        main
    };
    write_proto_enc(
        &mut out,
        main,
        &genkey,
        &mut pid,
        enc,
        seed,
        &envdig,
        fmt,
        ProtoEncodingMode::PagedRoot {
            activation_ticket: crypt::activation_root(&genkey, seed),
        },
        stats.as_deref_mut(),
    );
    if let Some(s) = stats.as_deref_mut() {
        s.raw_total_bytes = out.len();
    }
    out
}

fn compute_probes(
    seed: u64,
    anti_envlog: bool,
    profile: crypt::TargetProfile,
    canary: bool,
) -> Vec<u32> {
    let probe = crypt::env_fingerprint_term(seed, profile);
    let mut probes = if !anti_envlog {
        vec![probe]
    } else {
        let outer = crypt::dt_trap(seed).expected();
        let inner = crypt::path2d_trap(seed).expected();
        crypt::fold_order(seed)
            .iter()
            .map(|t| match t {
                crypt::FoldTerm::Probe => probe,
                crypt::FoldTerm::Outer => outer,
                crypt::FoldTerm::Inner => inner,
            })
            .collect()
    };

    if canary {
        probes.push(crypt::canary_salt(seed));
    }
    probes
}

pub fn payload_genkey(
    main: &Proto,
    seed: u64,
    enc: &Encoding,
    anti_envlog: bool,
    profile: crypt::TargetProfile,
    canary: bool,
) -> [u32; 8] {
    crypt::gen_key(
        &derive_salt(seed),
        crypt::code_digest(main, enc),
        &crypt::env_fingerprint_digest(seed, profile),
        &compute_probes(seed, anti_envlog, profile, canary),
    )
}

pub fn serialize_inner(
    proto: &Proto,
    genkey: &[u32; 8],
    enc: &Encoding,
    seed: u64,
    envdig: &[u32; 8],
    fmt: &FormatConfig,
) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    let mut pid = 0u32;
    write_proto_enc(
        &mut out,
        proto,
        genkey,
        &mut pid,
        enc,
        seed,
        envdig,
        fmt,
        ProtoEncodingMode::SealedInner,
        None,
    );

    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

pub fn payload_salt(seed: u64) -> [u8; 12] {
    derive_salt(seed)
}

fn section_order(seed: u64, pid: u32) -> [usize; 6] {
    let mut s = seed ^ (pid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x_5345_435F_4F52;
    let mut next = || {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut idx = [0usize, 1, 2, 3, 4, 5];
    for i in (1..6).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        idx.swap(i, j);
    }
    let code = idx.iter().position(|&x| x == 1).unwrap();
    let protos = idx.iter().position(|&x| x == 4).unwrap();
    if code > protos {
        idx.swap(code, protos);
    }
    idx
}

fn derive_salt(seed: u64) -> [u8; 12] {
    let mut x = seed;
    let mut next = || {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut salt = [0u8; 12];
    salt[0..8].copy_from_slice(&next().to_le_bytes());
    salt[8..12].copy_from_slice(&next().to_le_bytes()[0..4]);
    salt
}

fn write_proto_enc(
    out: &mut Vec<u8>,
    proto: &Proto,
    genkey: &[u32; 8],
    pid: &mut u32,
    enc: &Encoding,
    seed: u64,
    envdig: &[u32; 8],
    fmt: &FormatConfig,
    mode: ProtoEncodingMode,
    mut stats: Option<&mut SectionStats>,
) {
    let this_pid = *pid;
    let patch_instrs = mode.patch_instrs();
    let line_info = fmt.line_info;
    let kmode = mode.kmode(fmt);
    let frame_const_probe = fmt.frame_const_probe;
    let paging = mode.paging();
    let parent_ticket = mode.parent_ticket();
    let framing = fmt.framing;
    let sem_family = fmt.sem_family;
    let instr_family_on = fmt.instr_family;
    let state_family_on = fmt.state_family;

    let this_ticket = match parent_ticket {
        Some(pt) => crypt::activation_ticket(pt, this_pid, &crypt::activation_sk(envdig), seed),
        None => 0,
    };
    let child_ticket = parent_ticket.map(|_| this_ticket);
    if let Some(s) = stats.as_deref_mut() {
        s.kepoch_wide_skips += crate::kepoch::wide_operand_count(proto, this_pid, seed, kmode);
    }
    let mut tokenized = crate::kepoch::tokenize_code(proto, this_pid, seed, kmode);
    let d1_data: Option<(crate::blockstate::BlockState, Vec<usize>)> = if tokenized.d1.is_some() {
        let rb = tokenized.d1.as_ref().unwrap().record_block.clone();
        let mut edges: Vec<(usize, usize)> = Vec::new();
        for inst in &tokenized.code {
            if let Some(crate::inst::Prov::BStateEdge(p, s)) = inst.prov {
                edges.push((p as usize, s as usize));
            }
        }
        let nblocks = 1 + edges
            .iter()
            .flat_map(|&(p, s)| [p, s])
            .chain(rb.iter().copied())
            .max()
            .unwrap_or(0);
        let bs = crate::blockstate::solve_edges(nblocks, &edges, genkey, seed, this_pid);
        for inst in tokenized.code.iter_mut() {
            if let Some(crate::inst::Prov::BStateEdge(p, s)) = inst.prov {
                inst.a = bs
                    .edge_corr
                    .get(&(p as usize, s as usize))
                    .copied()
                    .unwrap_or(0) as i32;
            }
        }
        Some((bs, rb))
    } else {
        None
    };
    let proto = &tokenized;
    let ipk = crypt::instr_patch_key(genkey, this_pid, crypt::instr_patch_domain(seed));
    let spk = crypt::instr_patch_key(genkey, this_pid, crypt::sidecar_patch_domain(seed));
    let cfk = crypt::instr_patch_key(genkey, this_pid, crypt::controlflow_patch_domain(seed));
    *pid += 1;

    let order = crypt::oplayout_perm(seed, this_pid);
    let mperm = crypt::oplayout_maskperm(seed, this_pid);
    let gmode = crypt::oplayout_gmode(seed, this_pid);
    let fbase = crypt::opmask_key(seed);
    let fsk = crypt::framing_key(seed, envdig);
    let mut params = Vec::new();
    write_uvarint_masked(
        &mut params,
        proto.num_params as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_NUMPARAMS,
    );
    write_uvarint_masked(
        &mut params,
        proto.is_vararg as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_VARARG,
    );
    write_uvarint_masked(
        &mut params,
        proto.max_stack as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_MAXSTACK,
    );
    write_uvarint_masked(
        &mut params,
        order[0] as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_OPLAYOUT,
    );
    write_uvarint_masked(
        &mut params,
        order[1] as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_OPLAYOUT + 1,
    );
    write_uvarint_masked(
        &mut params,
        order[2] as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_OPLAYOUT + 2,
    );
    write_uvarint_masked(
        &mut params,
        mperm[0] as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_MASKPERM,
    );
    write_uvarint_masked(
        &mut params,
        mperm[1] as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_MASKPERM + 1,
    );
    write_uvarint_masked(
        &mut params,
        mperm[2] as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_MASKPERM + 2,
    );
    write_uvarint_masked(
        &mut params,
        gmode as u64,
        fbase,
        &fsk,
        this_pid,
        crypt::FR_GMODE,
    );

    let mut code = Vec::new();
    write_uvarint(&mut code, proto.code.len() as u64);

    let base = crypt::opmask_key(seed);
    let (dom_sj, dom_qk, dom_ej) = crypt::struct_domains(seed);
    let esk_sj = crypt::struct_key(envdig, dom_sj);
    let esk_ej = crypt::struct_key(envdig, dom_ej);

    let pmap = crypt::proto_opmap(
        crypt::mapkey(seed),
        &crypt::struct_key(envdig, dom_qk),
        this_pid,
    );
    let (mut m_opcode, mut m_operand, mut m_dead, mut m_deadc) = (0usize, 0usize, 0usize, 0usize);
    let (mut m_live, mut m_saved) = (0usize, 0usize);
    for (pc0, inst) in proto.code.iter().enumerate() {
        let pc = pc0 as u32 + 1;
        code.push(
            pmap[enc.phys(inst.op) as usize] ^ crypt::opmask_byte(base, &esk_sj, this_pid, pc),
        );
        m_opcode += 1;
        if crate::opcode::is_gensuper(inst.op) {
            let before = code.len();
            write_svarint_masked(&mut code, inst.a as i64, base, &esk_ej, this_pid, pc, 0);
            write_svarint_masked(&mut code, inst.b as i64, base, &esk_ej, this_pid, pc, 1);
            write_svarint_masked(&mut code, inst.c as i64, base, &esk_ej, this_pid, pc, 2);
            write_svarint_masked(
                &mut code,
                inst.ops.len() as i64,
                base,
                &esk_ej,
                this_pid,
                pc,
                3,
            );
            for (k, &o) in inst.ops.iter().enumerate() {
                write_svarint_masked(
                    &mut code,
                    o as i64,
                    base,
                    &esk_ej,
                    this_pid,
                    pc,
                    (k + 4) as u32,
                );
            }
            let w = code.len() - before;
            m_operand += w;
            m_live += w;
        } else if crate::superop::is_super(inst.op) {
            let n = inst.ops.len();
            for phys in 0..n {
                let lslot = if gmode & 1 != 0 { n - 1 - phys } else { phys };
                let mut v = inst.ops[lslot] as i64;
                if patch_instrs
                    && opcode::patch_sidecar_role(inst.op, lslot) != opcode::OperandRole::None
                {
                    let sid = crypt::SIDECAR_SLOT_BASE + lslot as u32;
                    if crypt::instr_patch_selected(spk, pc, sid) {
                        v += crypt::instr_patch_delta(spk, pc, sid) as i64;
                    }
                }
                let before = code.len();
                write_svarint_masked(&mut code, v, base, &esk_ej, this_pid, pc, phys as u32);
                let w = code.len() - before;
                m_operand += w;
                m_live += w;
            }
        } else {
            let ops = [inst.a, inst.b, inst.c];
            let mut ser = [ops[0] as i64, ops[1] as i64, ops[2] as i64];
            if patch_instrs {
                for (pi, s) in ser.iter_mut().enumerate() {
                    if opcode::patch_cf_role(inst.op, pi) != opcode::OperandRole::None {
                        if instr_family(seed, instr_family_on) == 1 {
                            *s += pc as i64 + 1;
                        }
                        let cid = crypt::CONTROLFLOW_SLOT_BASE + pi as u32;
                        if crypt::instr_patch_selected(cfk, pc, cid) {
                            *s += crypt::instr_patch_delta(cfk, pc, cid) as i64;
                        }
                    } else if opcode::patch_role(inst.op, pi) != opcode::OperandRole::None
                        && crypt::instr_patch_selected(ipk, pc, pi as u32)
                    {
                        *s += crypt::instr_patch_delta(ipk, pc, pi as u32) as i64;
                    }
                }
            }
            let live = opcode::operand_live(inst.op);
            let ser_mask = opcode::operand_serialized(inst.op);
            for (slot, &physidx) in order.iter().enumerate() {
                let logical = physidx as usize;
                let v = ser[logical];
                if ser_mask[logical] {
                    let before = code.len();
                    write_svarint_masked(
                        &mut code,
                        v,
                        base,
                        &esk_ej,
                        this_pid,
                        pc,
                        mperm[slot] as u32,
                    );
                    let w = code.len() - before;
                    m_operand += w;
                    if live[logical] {
                        m_live += w;
                    } else {
                        m_dead += w;
                        m_deadc += 1;
                    }
                } else {
                    m_saved += svarint_len(v);
                }
            }
        }
    }
    if let Some(s) = stats.as_deref_mut() {
        s.code_opcode_bytes += m_opcode;
        s.code_operand_bytes += m_operand;
        s.code_dead_operand_bytes += m_dead;
        s.code_dead_operand_count += m_deadc;
        s.code_live_operand_bytes += m_live;
        s.code_arity_saved_bytes += m_saved;
    }

    let n_instrs = proto.code.len();
    let traps = crypt::vm_traps_active() && matches!(paging, RootPaging::Paged);
    let tp = crypt::trap_params(seed);
    let mut cexp: Vec<u32> = Vec::new();
    let mut tacc = crypt::trap_seed(&tp, genkey, this_pid);
    for page in 0..crypt::page_count(n_instrs) {
        let pd = crypt::page_semantic_digest(proto, enc, page * crypt::PAGE_SIZE, crypt::PAGE_SIZE);
        code.extend_from_slice(&pd.to_le_bytes());
        if traps {
            tacc = crypt::trap_page_fold(&tp, tacc, pd, (page + 1) as u32);
            cexp.push(tacc);
        }
    }
    for e in &cexp {
        code.extend_from_slice(&e.to_le_bytes());
    }

    let ups: Vec<(bool, u32)> = proto
        .upvals
        .iter()
        .map(|u| (u.in_stack, u.index as u32))
        .collect();
    let wire_dg = crypt::fold_proto_framing(
        crypt::wire_proto_digest(&code, this_pid, seed, envdig),
        proto.num_params as u32,
        proto.is_vararg,
        proto.max_stack as u32,
        &ups,
        seed,
    );
    let key_dg = match paging {
        RootPaging::Paged => crypt::root_key_dg(wire_dg, this_pid, genkey),
        RootPaging::Unpaged => crypt::combined_code_digest(
            crypt::proto_code_digest(proto, enc),
            wire_dg,
            this_pid,
            seed,
            genkey,
        ),
    };
    let pkey = crypt::proto_key(genkey, this_pid, key_dg);

    let (act_ticket, act_section) = if parent_ticket.is_some() {
        let probes = [
            envdig[0] ^ envdig[4],
            envdig[1] ^ envdig[5],
            envdig[2] ^ envdig[6],
            envdig[3] ^ envdig[7],
        ];
        let mk = crypt::opmask_key(seed);
        let prog = crate::actvm::gen_program(mk, this_pid, key_dg);
        let mut act = Vec::new();
        write_uvarint_masked(
            &mut act,
            prog.len() as u64,
            fbase,
            &fsk,
            this_pid,
            crypt::FR_ACTLEN,
        );
        for (i0, &word) in prog.iter().enumerate() {
            let i = i0 as u32 + 1;
            let logical = (word >> 24) & 7;
            let operand = word & 0xFFFF;
            let (unit, big) = crate::actvm::op_unit(logical, operand);
            act.push(pmap[unit as usize] ^ crypt::opmask_byte(base, &esk_sj, this_pid, i));
            if let Some(v) = big {
                write_svarint_masked(&mut act, v as i64, base, &esk_ej, this_pid, i, 0);
            }
        }
        let ticket = crate::actvm::activation_output(
            mk,
            crypt::mapkey(seed),
            this_pid,
            key_dg,
            &probes,
            this_ticket,
        );
        (ticket, Some(act))
    } else {
        (0, None)
    };
    let cepoch = crypt::const_epoch(genkey, this_pid, key_dg, act_ticket);

    let mut site = vec![0u32; proto.consts.len()];
    for (pos, inst) in proto.code.iter().enumerate() {
        let co = enc.phys(inst.op) as u32;
        let tok = crypt::const_site_token((pos + 1) as u32, co);
        let mut bind = |ci: usize| {
            if ci < site.len() && site[ci] == 0 {
                site[ci] = tok;
            }
        };
        if crate::opcode::is_gensuper(inst.op) {
            let lo = inst.b.max(0) as usize;
            let hi = lo + inst.c.max(0) as usize;
            for k in lo..hi {
                if let Some(&ci) = inst.ops.get(k) {
                    bind(ci as usize);
                }
            }
        } else if crate::superop::is_super(inst.op) {
            for slot in opcode::super_const_slots(inst.op) {
                bind(inst.ops[slot - 1] as usize);
            }
        } else if let Some(s) = opcode::const_slot(inst.op) {
            bind(match s {
                opcode::KSlot::B => inst.b,
                opcode::KSlot::C => inst.c,
            } as usize);
        }
    }

    let mpk = crypt::metadata_patch_key(genkey, this_pid, key_dg, cepoch);
    for (i, s) in site.iter_mut().enumerate() {
        *s = crypt::patch_site(*s, mpk, i as u32);
    }

    let fam = const_sec_family(seed, sem_family);
    let mut consts = Vec::new();
    write_uvarint(&mut consts, proto.consts.len() as u64);
    if d1_data.is_some() || fmt.d1 {
        let rb_len = d1_data.as_ref().map(|(_, rb)| rb.len()).unwrap_or(0);
        write_uvarint(&mut consts, rb_len as u64);
    }
    let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(proto.consts.len());
    let state_b = state_family(seed, state_family_on) == 1;
    for (i, k) in proto.consts.iter().enumerate() {
        let ep = match &d1_data {
            Some((bs, rb)) if i < rb.len() => {
                if state_b {
                    crypt::block_state_transition(bs.bstate[rb[i]], this_ticket, seed)
                } else {
                    bs.bstate[rb[i]]
                }
            }
            _ => cepoch,
        };
        let blob = crypt::encrypt_const(&pkey, i as u32, ep, site[i], k);
        if let Some(s) = stats.as_deref_mut() {
            let per = uvarint_len(blob.len() as u64) + blob.len();
            match k {
                Const::Number(n) | Const::FlatBlockId(n) => {
                    s.number_const_bytes += per;
                    if crypt::is_dense_i53_number(*n).is_some() {
                        s.number_const_dense_count += 1;
                        s.number_const_dense_bytes += per;
                        let raw_per = uvarint_len(RAW_NUMBER_BLOB as u64) + RAW_NUMBER_BLOB;
                        s.number_const_dense_saved_bytes += raw_per.saturating_sub(per);
                    } else {
                        s.number_const_raw_count += 1;
                        s.number_const_raw_bytes += per;
                    }
                }
                Const::Str(_) => s.string_const_bytes += per,
            }
            s.aead_tag_bytes += AEAD_TAG_BYTES;
            s.const_count += 1;
        }
        blobs.push(blob);
    }
    if fam == 1 {
        for b in &blobs {
            write_uvarint(&mut consts, b.len() as u64);
        }
        for b in &blobs {
            consts.extend_from_slice(b);
        }
    } else {
        for b in &blobs {
            write_uvarint(&mut consts, b.len() as u64);
            consts.extend_from_slice(b);
        }
    }

    let mut upvals = Vec::new();
    write_uvarint(&mut upvals, proto.upvals.len() as u64);
    for (ui, u) in proto.upvals.iter().enumerate() {
        let fidx = crypt::FR_UPVAL_BASE + 2 * ui as u32;
        write_uvarint_masked(&mut upvals, u.in_stack as u64, fbase, &fsk, this_pid, fidx);
        write_uvarint_masked(&mut upvals, u.index as u64, fbase, &fsk, this_pid, fidx + 1);
    }

    let mut protos = Vec::new();
    write_uvarint(&mut protos, proto.protos.len() as u64);
    for child in &proto.protos {
        write_proto_enc(
            &mut protos,
            child,
            genkey,
            pid,
            enc,
            seed,
            envdig,
            fmt,
            mode.child(child_ticket),
            stats.as_deref_mut(),
        );
    }

    let mut lines = Vec::new();
    write_uvarint(&mut lines, proto.line_info.len() as u64);
    for l in &proto.line_info {
        write_uvarint(&mut lines, *l as u64);
    }

    let mut frame_const_exclude = Vec::new();
    let excluded: Vec<usize> = proto
        .consts
        .iter()
        .enumerate()
        .filter_map(|(i, c)| matches!(c, Const::FlatBlockId(_)).then_some(i + 1))
        .collect();
    write_uvarint(&mut frame_const_exclude, excluded.len() as u64);
    for i in excluded {
        write_uvarint(&mut frame_const_exclude, i as u64);
    }

    let sections = [
        (SEC_PARAMS, params),
        (SEC_CODE, code),
        (SEC_CONSTS, consts),
        (SEC_UPVALS, upvals),
        (SEC_PROTOS, protos),
        (SEC_LINEINFO, lines),
    ];
    let emit: Vec<usize> = section_order(seed, this_pid)
        .into_iter()
        .filter(|&i| line_info || sections[i].0 != SEC_LINEINFO)
        .collect();
    let mut ordered: Vec<(u8, &[u8])> = emit
        .iter()
        .map(|&i| (sections[i].0, sections[i].1.as_slice()))
        .collect();
    if frame_const_probe {
        ordered.push((SEC_FRAME_CONST_EXCLUDE, frame_const_exclude.as_slice()));
    }
    if let Some(act) = &act_section {
        ordered.push((SEC_ACT, act.as_slice()));
    }
    out.push(ordered.len() as u8);
    if framing {
        let fam = crypt::framing_family(seed);
        let mut fstate = crypt::framing_chain_root(seed, this_pid);
        for &(tag, data) in &ordered {
            if fam == 0 {
                out.push(tag);
                write_uvarint_masked(out, data.len() as u64, fbase, &fsk, this_pid, fstate);
            } else {
                write_uvarint_masked(out, data.len() as u64, fbase, &fsk, this_pid, fstate);
                out.push(tag);
            }
            out.extend_from_slice(data);
            fstate = crypt::framing_chain_step(seed, fstate, tag as u32, data.len() as u64);
        }
        let trailer = crypt::framing_chain_trailer(seed, fstate);
        write_uvarint_masked(out, trailer as u64, fbase, &fsk, this_pid, fstate);
    } else {
        for &(tag, data) in &ordered {
            out.push(tag);
            write_uvarint(out, data.len() as u64);
            out.extend_from_slice(data);
        }
    }
    if let Some(act) = &act_section {
        if let Some(s) = stats.as_deref_mut() {
            s.act_program_bytes += act.len();
            s.section_header_bytes += 1 + uvarint_len(act.len() as u64);
        }
    }

    if let Some(s) = stats.as_deref_mut() {
        s.proto_meta_bytes += sections[0].1.len();
        s.code_bytes += sections[1].1.len();
        s.const_bytes += sections[2].1.len();
        s.upvalue_bytes += sections[3].1.len();
        if line_info {
            s.lineinfo_bytes += sections[5].1.len();
        }
        s.other_const_bytes += uvarint_len(proto.consts.len() as u64);
        let mut framing = 1 + uvarint_len(proto.protos.len() as u64);
        for &i in emit.iter() {
            framing += 1 + uvarint_len(sections[i].1.len() as u64);
        }
        if frame_const_probe {
            framing +=
                1 + uvarint_len(frame_const_exclude.len() as u64) + frame_const_exclude.len();
        }
        s.section_header_bytes += framing;
        if this_pid == 0 {
            s.child_proto_bytes = sections[4].1.len();
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("length overflow")?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or("unexpected end of input")?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn uvarint(&mut self) -> Result<u64, String> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err("varint too long".into());
            }
        }
    }
    fn svarint(&mut self) -> Result<i32, String> {
        let u = self.uvarint()?;
        Ok(((u >> 1) as i64 ^ -((u & 1) as i64)) as i32)
    }
    fn f64(&mut self) -> Result<f64, String> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

pub fn deserialize(data: &[u8]) -> Result<Proto, String> {
    let mut r = Reader { data, pos: 0 };
    let version = r.u8()?;
    if version != VERSION {
        return Err(format!("unsupported format version {version}"));
    }
    r.u8()?;
    read_proto(&mut r)
}

fn read_proto(r: &mut Reader) -> Result<Proto, String> {
    let mut proto = Proto::default();
    let nsections = r.u8()?;
    for _ in 0..nsections {
        let tag = r.u8()?;
        let len = r.uvarint()? as usize;
        let end = r.pos.checked_add(len).ok_or("section length overflow")?;
        match tag {
            SEC_PARAMS => {
                proto.num_params = r.u8()?;
                proto.is_vararg = r.u8()? != 0;
                proto.max_stack = r.uvarint()? as u16;
            }
            SEC_CODE => {
                let n = r.uvarint()?;
                for _ in 0..n {
                    let op = opcode::from_concrete(r.u8()?).ok_or("unknown opcode")?;
                    if opcode::is_gensuper(op) {
                        let slot = r.svarint()?;
                        let nlive = r.svarint()?;
                        let nconst = r.svarint()?;
                        let len = r.svarint()?;
                        if !(0..=4096).contains(&len) {
                            return Err("gensuper interface length out of range".into());
                        }
                        if nlive < 0 || nconst < 0 || nlive + nconst > len {
                            return Err("gensuper interface counts inconsistent with length".into());
                        }
                        let mut ops = Vec::with_capacity(len as usize);
                        for _ in 0..len {
                            ops.push(r.svarint()?);
                        }
                        proto.code.push(Inst {
                            op,
                            a: slot,
                            b: nlive,
                            c: nconst,
                            ops,
                            prov: None,
                        });
                        continue;
                    }
                    let cnt = crate::superop::operand_count(op);
                    if cnt == 3 {
                        proto
                            .code
                            .push(Inst::new(op, r.svarint()?, r.svarint()?, r.svarint()?));
                    } else {
                        let mut ops = Vec::with_capacity(cnt);
                        for _ in 0..cnt {
                            ops.push(r.svarint()?);
                        }
                        proto.code.push(Inst::super_op(op, ops));
                    }
                }
            }
            SEC_CONSTS => {
                let n = r.uvarint()?;
                for _ in 0..n {
                    match r.u8()? {
                        K_NUMBER => proto.consts.push(Const::Number(r.f64()?)),
                        K_STRING => {
                            let len = r.uvarint()? as usize;
                            proto.consts.push(Const::Str(r.take(len)?.to_vec()));
                        }
                        other => return Err(format!("unknown constant tag {other}")),
                    }
                }
            }
            SEC_UPVALS => {
                let n = r.uvarint()?;
                for _ in 0..n {
                    proto.upvals.push(UpvalDesc {
                        in_stack: r.u8()? != 0,
                        index: r.uvarint()? as u16,
                    });
                }
            }
            SEC_PROTOS => {
                let n = r.uvarint()?;
                for _ in 0..n {
                    proto.protos.push(read_proto(r)?);
                }
            }
            SEC_LINEINFO => {
                let n = r.uvarint()?;
                for _ in 0..n {
                    proto.line_info.push(r.uvarint()? as u32);
                }
            }
            _ => {}
        }
        r.pos = end;
    }
    Ok(proto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::Opcode;
    use crate::proto::Proto;

    fn read_uvarint(data: &[u8], pos: &mut usize) -> u64 {
        let mut v = 0u64;
        let mut sh = 0u32;
        loop {
            let Some(&b) = data.get(*pos) else {
                return v;
            };
            *pos += 1;
            if sh < 64 {
                v |= ((b & 0x7f) as u64) << sh;
            }
            if b < 0x80 || sh >= 64 {
                return v;
            }
            sh += 7;
        }
    }

    fn layout(blobs: &[Vec<u8>], directory: bool) -> Vec<u8> {
        let mut out = Vec::new();
        write_uvarint(&mut out, blobs.len() as u64);
        if directory {
            for b in blobs {
                write_uvarint(&mut out, b.len() as u64);
            }
            for b in blobs {
                out.extend_from_slice(b);
            }
        } else {
            for b in blobs {
                write_uvarint(&mut out, b.len() as u64);
                out.extend_from_slice(b);
            }
        }
        out
    }

    fn read_streamed(data: &[u8]) -> Vec<Vec<u8>> {
        let mut pos = 0usize;
        let n = read_uvarint(data, &mut pos) as usize;
        let mut out = Vec::new();
        for _ in 0..n {
            if pos >= data.len() {
                break;
            }
            let len = read_uvarint(data, &mut pos) as usize;
            let end = (pos + len).min(data.len());
            out.push(data[pos..end].to_vec());
            pos = end;
        }
        out
    }

    #[test]
    fn instr_family_is_off_stable_and_seed_split() {
        for seed in 0..64u64 {
            assert_eq!(instr_family(seed, false), 0, "OFF is always REL");
        }
        let ones = (0..256u64).filter(|&s| instr_family(s, true) == 1).count();
        assert!(
            (64..192).contains(&ones),
            "ON splits seeds across both branch-target families: {ones}/256"
        );
    }

    #[test]
    fn state_family_is_off_stable_and_seed_split() {
        for seed in 0..64u64 {
            assert_eq!(
                state_family(seed, false),
                0,
                "OFF is always the single-recurrence state model"
            );
        }
        let ones = (0..256u64).filter(|&s| state_family(s, true) == 1).count();
        assert!(
            (64..192).contains(&ones),
            "ON splits seeds across both state models: {ones}/256"
        );
    }

    #[test]
    fn state_families_bind_constant_eligibility_to_different_state() {
        let seed = 0xC0FFEEu64;
        let (m1, m2) = crypt::block_state_mix(seed);
        let bstate = crypt::fmix32(0x1234_5678, m1, m2);
        let lineage = 0x9ABC_DEF0u32;
        let family_a_ep = bstate;
        let family_b_ep = crypt::block_state_transition(bstate, lineage, seed);
        assert_ne!(
            family_a_ep, family_b_ep,
            "the composite state binds a different ep than the CFG-only state"
        );
        assert_ne!(
            family_b_ep,
            crypt::block_state_transition(bstate, 0, seed),
            "the lineage genuinely enters the composite ep"
        );
    }

    #[test]
    fn rel_and_abs_branch_target_families_do_not_transfer() {
        let rel_model = |encoded: i64, i: i64| (i + 1) + encoded;
        for &(i, t) in &[(3i64, 9i64), (7, 2), (10, 10), (0, 5), (20, 4)] {
            let rel_encoded = t - (i + 1);
            let abs_encoded = t;
            assert_eq!(
                rel_model(rel_encoded, i),
                t,
                "REL model recovers REL build target"
            );
            if i + 1 != 0 {
                assert_ne!(
                    rel_model(abs_encoded, i),
                    t,
                    "REL model must mis-recover ABS build target"
                );
            }
        }
    }

    #[test]
    fn const_sec_family_is_off_stable_and_seed_split() {
        for seed in 0..64u64 {
            assert_eq!(const_sec_family(seed, false), 0, "OFF is always STREAMED");
        }
        let ones = (0..256u64)
            .filter(|&s| const_sec_family(s, true) == 1)
            .count();
        assert!(
            (64..192).contains(&ones),
            "ON splits seeds across both families: {ones}/256"
        );
    }

    #[test]
    fn streamed_and_directory_grammars_do_not_transfer() {
        let blobs: Vec<Vec<u8>> = vec![
            vec![0xAA; 3],
            vec![0xBB; 5],
            vec![0xCC; 1],
            vec![0xDD; 7],
            vec![0xEE; 2],
        ];
        let streamed = layout(&blobs, false);
        let directory = layout(&blobs, true);
        assert_ne!(streamed, directory, "the two grammars differ");
        assert_eq!(
            streamed.len(),
            directory.len(),
            "same section length (framing-neutral)"
        );
        assert_eq!(
            read_streamed(&streamed),
            blobs,
            "STREAMED model parses STREAMED build"
        );
        assert_ne!(
            read_streamed(&directory),
            blobs,
            "STREAMED model must mis-parse DIRECTORY build"
        );
    }

    #[test]
    fn section_order_is_valid_pinned_and_per_build_varied() {
        for seed in 0..200u64 {
            for pid in 0..6u32 {
                let o = section_order(seed, pid);
                let mut sorted = o;
                sorted.sort_unstable();
                assert_eq!(
                    sorted,
                    [0, 1, 2, 3, 4, 5],
                    "not a permutation (seed {seed}, pid {pid})"
                );
                let code = o.iter().position(|&x| x == 1).unwrap();
                let protos = o.iter().position(|&x| x == 4).unwrap();
                assert!(
                    code < protos,
                    "SEC_CODE must precede SEC_PROTOS (seed {seed}, pid {pid}): {o:?}"
                );
            }
        }
        assert_eq!(section_order(12345, 2), section_order(12345, 2));
        let orders: std::collections::HashSet<_> =
            [0xB451115Cu64, 0x1, 0xDEADBEEF, 0xA5A55A5A, 0x12345678]
                .iter()
                .map(|&s| section_order(s, 0))
                .collect();
        assert!(
            orders.len() > 1,
            "section order must vary across builds (W3 irregularity)"
        );
    }

    #[test]
    fn super_op_operands_round_trip() {
        for (sop, subs) in crate::superop::CATALOGUE {
            let cnt = 3 * subs.len();
            assert_eq!(crate::superop::operand_count(*sop), cnt);
            let ops: Vec<i32> = (0..cnt as i32).map(|i| i * 9 - 7).collect();
            let mut proto = Proto::default();
            proto.code.push(Inst::new(Opcode::Move, 1, 2, 0));
            proto.code.push(Inst::super_op(*sop, ops.clone()));
            proto.code.push(Inst::new(Opcode::Return, 0, 1, 0));
            let back = deserialize(&serialize(&proto)).expect("deserialize");
            assert_eq!(back.code.len(), 3, "{sop:?}");
            assert_eq!(back.code[1].op, *sop);
            assert_eq!(
                back.code[1].ops, ops,
                "super-op {sop:?} operands must round-trip"
            );
            assert_eq!(back.code[0].op, Opcode::Move);
            assert_eq!((back.code[0].a, back.code[0].b), (1, 2));
        }
    }

    #[test]
    fn gensuper_round_trips_self_describing_interface() {
        let mut proto = Proto::default();
        proto.code.push(Inst::new(Opcode::Move, 1, 2, 0));
        proto.code.push(Inst {
            op: Opcode::GenSuper,
            a: 7,
            b: 0,
            c: 0,
            ops: vec![3, 5, 9, 2],
            prov: None,
        });
        proto.code.push(Inst::new(Opcode::Return, 0, 1, 0));
        let back = deserialize(&serialize(&proto)).expect("deserialize");
        assert_eq!(back.code.len(), 3);
        assert_eq!(back.code[1].op, Opcode::GenSuper);
        assert_eq!(back.code[1].a, 7, "slot round-trips");
        assert_eq!(
            back.code[1].ops,
            vec![3, 5, 9, 2],
            "self-describing interface round-trips"
        );
        assert_eq!(back.code[0].op, Opcode::Move);
        assert_eq!(back.code[2].op, Opcode::Return);
    }

    fn rt_u(v: u64) -> u64 {
        let mut buf = Vec::new();
        write_uvarint(&mut buf, v);
        Reader { data: &buf, pos: 0 }.uvarint().unwrap()
    }
    fn rt_s(v: i32) -> i32 {
        let mut buf = Vec::new();
        write_svarint(&mut buf, v as i64);
        Reader { data: &buf, pos: 0 }.svarint().unwrap()
    }

    fn sample_proto() -> Proto {
        Proto {
            num_params: 1,
            is_vararg: false,
            max_stack: 4,
            code: vec![
                Inst::new(Opcode::GetUpval, 0, 0, 0),
                Inst::new(Opcode::Return, 0, 2, 0),
            ],
            consts: vec![Const::Number(7.5), Const::Str(b"OK:".to_vec())],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        }
    }

    #[test]
    fn encfunc_inner_body_seals_and_round_trips_through_aead() {
        let seed = 0xABCD_1234u64;
        let enc = crate::encoding::Encoding::from_seed(seed);
        let genkey = payload_genkey(
            &sample_proto(),
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
        );
        let envdig = crypt::env_fingerprint_digest(seed, crypt::TargetProfile::CliTest);
        let body = serialize_inner(
            &sample_proto(),
            &genkey,
            &enc,
            seed,
            &envdig,
            &FormatConfig::layout(
                true,
                crate::kepoch::KepochMode::Off,
                false,
                false,
                false,
                false,
                false,
            ),
        );
        assert!(body.len() > 12, "inner body = 12-byte salt + proto");
        assert_eq!(
            &body[0..12],
            &[0u8; 12],
            "12-byte synthetic salt prefix for deserialize reuse"
        );
        assert_eq!(
            body[12], 6,
            "proto starts with the section count the VM reader expects"
        );
        let key = crate::aead::parse_hex_key(&"ab".repeat(32)).unwrap();
        let nonce = [9u8; 12];
        let ad = b"v1|id0|salt";
        let blob = crate::aead::seal(&key, &nonce, ad, &body);
        assert_eq!(
            crate::aead::open(&key, ad, &blob).as_deref(),
            Some(&body[..])
        );
        assert_eq!(
            serialize_inner(
                &sample_proto(),
                &genkey,
                &enc,
                seed,
                &envdig,
                &FormatConfig::layout(
                    true,
                    crate::kepoch::KepochMode::Off,
                    false,
                    false,
                    false,
                    false,
                    false
                )
            ),
            body
        );
        assert_eq!(
            payload_genkey(
                &sample_proto(),
                seed,
                &enc,
                false,
                crypt::TargetProfile::CliTest,
                false
            ),
            genkey
        );
        assert_ne!(genkey, [0u32; 8]);
    }

    #[test]
    fn encfunc_inner_body_varies_with_seed() {
        let p = sample_proto();
        let mk = |seed: u64| {
            let enc = crate::encoding::Encoding::from_seed(seed);
            let envdig = crypt::env_fingerprint_digest(seed, crypt::TargetProfile::CliTest);
            serialize_inner(
                &p,
                &payload_genkey(&p, seed, &enc, false, crypt::TargetProfile::CliTest, false),
                &enc,
                seed,
                &envdig,
                &FormatConfig::layout(
                    true,
                    crate::kepoch::KepochMode::Off,
                    false,
                    false,
                    false,
                    false,
                    false,
                ),
            )
        };
        assert_ne!(
            mk(1),
            mk(2),
            "different seeds must produce different inner bodies"
        );
    }

    fn nested_sample() -> Proto {
        let child = Proto {
            num_params: 0,
            is_vararg: true,
            max_stack: 3,
            code: vec![
                Inst::new(Opcode::GetUpval, 0, 0, 0),
                Inst::new(Opcode::Return, 0, 1, 0),
            ],
            consts: vec![Const::Str(b"child-const".to_vec())],
            upvals: vec![UpvalDesc {
                in_stack: true,
                index: 0,
            }],
            protos: vec![],
            line_info: vec![3, 3, 4],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        Proto {
            num_params: 2,
            is_vararg: false,
            max_stack: 6,
            code: vec![
                Inst::new(Opcode::GetUpval, 0, 0, 0),
                Inst::new(Opcode::Move, 1, 0, 0),
                Inst::new(Opcode::Return, 0, 2, 0),
            ],
            consts: vec![
                Const::Number(3.5),
                Const::Str(b"root".to_vec()),
                Const::Number(9.0),
            ],
            upvals: vec![UpvalDesc {
                in_stack: false,
                index: 2,
            }],
            protos: vec![child],
            line_info: vec![1, 1, 2],
            hot_callback: None,
            stable_id: None,
            d1: None,
        }
    }

    #[test]
    fn variable_arity_elides_dead_operands_from_bytes_and_digest() {
        use crate::kepoch::KepochMode;
        let enc = crate::encoding::Encoding::from_seed(0x1234_5678);
        let mv = |c: i32| Proto {
            num_params: 0,
            is_vararg: false,
            max_stack: 8,
            code: vec![Inst::new(Opcode::Move, 1, 2, c)],
            consts: vec![],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        assert_eq!(
            crypt::proto_code_digest(&mv(0), &enc),
            crypt::proto_code_digest(&mv(9), &enc),
            "a change to Move's handler-dead c operand must not move the code digest"
        );
        let s0 = serialize_encrypted(
            &mv(0),
            7,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            KepochMode::Off,
        );
        let s9 = serialize_encrypted(
            &mv(9),
            7,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            KepochMode::Off,
        );
        assert_eq!(
            s0, s9,
            "the dead c operand is not serialized, so its value cannot change the bytes"
        );

        let arith = Proto {
            code: vec![Inst::new(Opcode::Add, 1, 2, 3)],
            ..mv(0)
        };
        let mut sa = SectionStats::default();
        let _ = serialize_encrypted_measured(
            &arith,
            7,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            KepochMode::Off,
            Some(&mut sa),
        );
        assert_eq!(
            sa.code_arity_saved_bytes, 0,
            "a 3-live op elides nothing: {sa:?}"
        );

        let mut sm = SectionStats::default();
        let _ = serialize_encrypted_measured(
            &mv(9),
            7,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            KepochMode::Off,
            Some(&mut sm),
        );
        assert!(
            sm.code_arity_saved_bytes > 0,
            "a 2-live op elides its dead operand: {sm:?}"
        );
        assert_eq!(
            sm.code_dead_operand_bytes, 0,
            "Move is not a decoy op — no emitted handler-dead operands: {sm:?}"
        );
    }

    #[test]
    fn section_stats_partition_and_measured_is_byte_identical() {
        for &line_info in &[true, false] {
            for seed in [1u64, 0xDEAD_BEEF, 0xB451_115C, 42, 0xA5A5_5A5A] {
                let enc = crate::encoding::Encoding::from_seed(seed);
                let p = nested_sample();
                let plain = serialize_encrypted(
                    &p,
                    seed,
                    &enc,
                    false,
                    crypt::TargetProfile::CliTest,
                    false,
                    line_info,
                    crate::kepoch::KepochMode::Off,
                );
                let mut s = SectionStats::default();
                let measured = serialize_encrypted_measured(
                    &p,
                    seed,
                    &enc,
                    false,
                    crypt::TargetProfile::CliTest,
                    false,
                    line_info,
                    crate::kepoch::KepochMode::Off,
                    Some(&mut s),
                );
                assert_eq!(plain, measured, "measured serialization must be byte-identical (seed {seed}, line_info {line_info})");
                assert_eq!(
                    s.raw_total_bytes,
                    measured.len(),
                    "raw_total must equal output length"
                );

                let partition = s.section_header_bytes
                    + s.code_bytes
                    + s.const_bytes
                    + s.upvalue_bytes
                    + s.proto_meta_bytes
                    + s.lineinfo_bytes
                    + s.act_program_bytes;
                assert_eq!(
                    s.raw_total_bytes, partition,
                    "flat partition must sum to raw total (seed {seed}, line_info {line_info})"
                );

                assert_eq!(
                    s.const_bytes,
                    s.number_const_bytes + s.string_const_bytes + s.other_const_bytes,
                    "const sub-partition must sum to const_bytes (seed {seed})"
                );

                let mut fs = SectionStats::default();
                let framed = serialize_encrypted_measured_frame_probe(
                    &p,
                    seed,
                    &enc,
                    false,
                    crypt::TargetProfile::CliTest,
                    false,
                    line_info,
                    crate::kepoch::KepochMode::Off,
                    Some(&mut fs),
                );
                assert_eq!(
                    fs.raw_total_bytes,
                    framed.len(),
                    "frame-probe raw_total must equal output length"
                );
                let framed_partition = fs.section_header_bytes
                    + fs.code_bytes
                    + fs.const_bytes
                    + fs.upvalue_bytes
                    + fs.proto_meta_bytes
                    + fs.lineinfo_bytes
                    + fs.act_program_bytes;
                assert_eq!(
                    fs.raw_total_bytes, framed_partition,
                    "frame-probe flat partition must sum to raw total (seed {seed}, line_info {line_info})"
                );
                assert_eq!(
                    fs.const_bytes,
                    fs.number_const_bytes + fs.string_const_bytes + fs.other_const_bytes,
                    "frame-probe const sub-partition must sum to const_bytes (seed {seed})"
                );
                assert!(
                    fs.raw_total_bytes > s.raw_total_bytes,
                    "frame probe emits an extra section per proto"
                );

                assert_eq!(s.const_count, 4, "root 3 consts + child 1 const");
                assert_eq!(
                    s.aead_tag_bytes,
                    s.const_count * 8,
                    "8-byte keyed tag per constant"
                );

                assert_eq!(
                    s.number_const_dense_count, 1,
                    "9.0 is integer-valued → dense"
                );
                assert_eq!(s.number_const_raw_count, 1, "3.5 is non-integer → raw f64");
                assert_eq!(
                    s.number_const_bytes,
                    s.number_const_raw_bytes + s.number_const_dense_bytes,
                    "number-const bytes split into raw + dense (seed {seed})"
                );
                assert!(
                    s.number_const_dense_saved_bytes > 0,
                    "encoding 9.0 dense saves vs raw f64"
                );

                assert!(
                    s.child_proto_bytes > 0,
                    "nested proto section must be non-empty"
                );
                assert!(
                    s.child_proto_bytes < s.raw_total_bytes,
                    "child proto bytes are a proper subset"
                );

                if line_info {
                    assert!(s.lineinfo_bytes > 0, "line info emitted");
                } else {
                    assert_eq!(s.lineinfo_bytes, 0, "line info suppressed");
                }
            }
        }
    }

    fn serialized_const_count(out: &[u8]) -> u64 {
        let read_uv = |b: &[u8]| -> (u64, usize) {
            let (mut v, mut shift, mut i) = (0u64, 0u32, 0usize);
            loop {
                let x = b[i];
                v |= ((x & 0x7f) as u64) << shift;
                i += 1;
                if x < 0x80 {
                    break;
                }
                shift += 7;
            }
            (v, i)
        };
        let mut p = 12;
        let nsec = out[p];
        p += 1;
        for _ in 0..nsec {
            let tag = out[p];
            p += 1;
            let (len, adv) = read_uv(&out[p..]);
            p += adv;
            if tag == SEC_CONSTS {
                return read_uv(&out[p..]).0;
            }
            p += len as usize;
        }
        0
    }

    #[test]
    fn zero_const_main_gets_one_sentinel() {
        let seed = 0x2B_u64;
        let enc = crate::encoding::Encoding::from_seed(seed);
        let mut empty = sample_proto();
        empty.consts.clear();
        empty.code.clear();
        let out = serialize_encrypted(
            &empty,
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            true,
            crate::kepoch::KepochMode::Off,
        );
        assert_eq!(
            serialized_const_count(&out),
            1,
            "a 0-const main proto gets exactly one sentinel constant for the pre-dispatch probe"
        );
        let two = serialize_encrypted(
            &sample_proto(),
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            true,
            crate::kepoch::KepochMode::Off,
        );
        assert_eq!(
            serialized_const_count(&two),
            2,
            "a proto with constants is unchanged (no sentinel added)"
        );
    }

    fn section_tags(out: &[u8]) -> Vec<u8> {
        let read_uv = |b: &[u8]| -> (u64, usize) {
            let (mut v, mut shift, mut i) = (0u64, 0u32, 0usize);
            loop {
                let x = b[i];
                v |= ((x & 0x7f) as u64) << shift;
                i += 1;
                if x < 0x80 {
                    break;
                }
                shift += 7;
            }
            (v, i)
        };
        let mut p = 12;
        let nsec = out[p];
        p += 1;
        let mut tags = Vec::new();
        for _ in 0..nsec {
            let tag = out[p];
            p += 1;
            let (len, adv) = read_uv(&out[p..]);
            p += adv + len as usize;
            tags.push(tag);
        }
        tags
    }

    #[test]
    fn line_info_off_drops_the_line_info_section() {
        let seed = 0x77u64;
        let enc = crate::encoding::Encoding::from_seed(seed);
        let on = serialize_encrypted(
            &sample_proto(),
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            true,
            crate::kepoch::KepochMode::Off,
        );
        let off = serialize_encrypted(
            &sample_proto(),
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            crate::kepoch::KepochMode::Off,
        );
        let on_tags = section_tags(&on);
        let off_tags = section_tags(&off);
        assert!(
            on_tags.contains(&SEC_LINEINFO),
            "on must emit the line-info section (current behavior)"
        );
        assert!(
            !off_tags.contains(&SEC_LINEINFO),
            "off must drop the line-info section"
        );
        assert_eq!(
            on_tags.len(),
            off_tags.len() + 1,
            "off has exactly one fewer section"
        );
        assert!(off.len() < on.len(), "off payload is smaller");
        let on_without_li: Vec<u8> = on_tags
            .iter()
            .copied()
            .filter(|&t| t != SEC_LINEINFO)
            .collect();
        assert_eq!(
            on_without_li, off_tags,
            "off keeps the other sections in the same per-build order"
        );
    }

    #[test]
    fn flat_block_provenance_is_byte_neutral_without_the_probe() {
        let seed = 0x9911u64;
        let enc = crate::encoding::Encoding::from_seed(seed);
        let ordinary = sample_proto();
        let mut routed = ordinary.clone();
        routed.consts[0] = Const::FlatBlockId(7.5);
        assert_eq!(serialize(&ordinary), serialize(&routed));
        assert_eq!(
            serialize_encrypted(
                &ordinary,
                seed,
                &enc,
                false,
                crypt::TargetProfile::CliTest,
                false,
                false,
                crate::kepoch::KepochMode::Aggressive
            ),
            serialize_encrypted(
                &routed,
                seed,
                &enc,
                false,
                crypt::TargetProfile::CliTest,
                false,
                false,
                crate::kepoch::KepochMode::Aggressive
            ),
        );
        let probe = serialize_encrypted_frame_probe(
            &routed,
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            crate::kepoch::KepochMode::Aggressive,
        );
        assert!(section_tags(&probe).contains(&SEC_FRAME_CONST_EXCLUDE));
        assert!(!section_tags(&serialize_encrypted(
            &routed,
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            crate::kepoch::KepochMode::Aggressive
        ))
        .contains(&SEC_FRAME_CONST_EXCLUDE));
    }

    #[test]
    fn varint_round_trips_byte_perfect() {
        for v in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            assert_eq!(rt_u(v), v, "uvarint {v}");
        }
        for v in [0i32, -1, 1, -2, 2, 63, -64, 1000, -1000, i32::MIN, i32::MAX] {
            assert_eq!(rt_s(v), v, "svarint {v}");
        }
        let one_byte = |v: i64| {
            let mut b = Vec::new();
            write_svarint(&mut b, v);
            b.len()
        };
        assert_eq!(one_byte(-1), 1, "-1 sentinel must be 1 byte");
        assert_eq!(one_byte(5), 1, "small positive must be 1 byte");
        assert_eq!(one_byte(63), 1, "register-range value must be 1 byte");
    }

    fn fenv(seed: u64) -> [u32; 8] {
        crypt::env_fingerprint_digest(seed, crypt::TargetProfile::CliTest)
    }

    #[test]
    fn framing_uvarint_mask_round_trips_and_is_size_neutral() {
        for seed in [1u64, 42, 1337, 0xDEAD_BEEF, 0xA5A5_5A5A] {
            let fbase = crypt::opmask_key(seed);
            let fsk = crypt::framing_key(seed, &fenv(seed));
            for pid in [0u32, 1, 7, 42] {
                for &fidx in &[
                    crypt::FR_NUMPARAMS,
                    crypt::FR_VARARG,
                    crypt::FR_MAXSTACK,
                    crypt::FR_UPVAL_BASE,
                    crypt::FR_UPVAL_BASE + 6,
                ] {
                    for &v in &[0u64, 1, 2, 127, 128, 255, 256, 16383, 16384, 65535, 100000] {
                        let mut buf = Vec::new();
                        write_uvarint_masked(&mut buf, v, fbase, &fsk, pid, fidx);
                        let mut plain = Vec::new();
                        write_uvarint(&mut plain, v);
                        assert_eq!(
                            buf.len(),
                            plain.len(),
                            "masked uvarint size-neutral (v={v})"
                        );
                        let mut pos = 0usize;
                        assert_eq!(
                            read_uvarint_masked(&buf, &mut pos, fbase, &fsk, pid, fidx),
                            v,
                            "round-trip v={v} seed={seed} pid={pid} fidx={fidx}"
                        );
                        assert_eq!(pos, buf.len(), "reader consumes exactly the masked bytes");
                    }
                }
            }
        }
    }

    #[test]
    fn framing_mask_varies_across_seeds_and_positions() {
        let enc_v = |seed: u64, pid: u32, fidx: u32, v: u64| {
            let mut b = Vec::new();
            write_uvarint_masked(
                &mut b,
                v,
                crypt::opmask_key(seed),
                &crypt::framing_key(seed, &fenv(seed)),
                pid,
                fidx,
            );
            b
        };
        let across_seeds: std::collections::HashSet<_> = (1..24u64)
            .map(|s| enc_v(s, 0, crypt::FR_NUMPARAMS, 2))
            .collect();
        assert!(
            across_seeds.len() > 1,
            "framing bytes must vary across seeds for an identical value"
        );
        let across_slots: std::collections::HashSet<_> = (0..12u32)
            .map(|i| enc_v(7, 3, crypt::FR_UPVAL_BASE + 2 * i, 1))
            .collect();
        assert!(
            across_slots.len() > 1,
            "identical descriptor at different capture slots must not all mask identically"
        );

        assert_eq!(
            enc_v(99, 4, crypt::FR_MAXSTACK, 250),
            enc_v(99, 4, crypt::FR_MAXSTACK, 250),
            "framing mask is deterministic"
        );
    }

    #[test]
    fn sec_params_and_upvals_bytes_are_masked_not_plaintext() {
        use crate::kepoch::KepochMode;
        let enc = crate::encoding::Encoding::from_seed(1);
        let seed = 0xC0FF_EE11u64;
        let mut p = sample_proto();
        p.num_params = 3;
        p.is_vararg = true;
        p.max_stack = 40;
        p.upvals = vec![
            UpvalDesc {
                in_stack: true,
                index: 5,
            },
            UpvalDesc {
                in_stack: false,
                index: 12,
            },
        ];
        let out = serialize_encrypted(
            &p,
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            KepochMode::Off,
        );
        let read_uv = |b: &[u8], pos: &mut usize| -> u64 {
            let (mut v, mut s) = (0u64, 0u32);
            loop {
                let x = b[*pos];
                *pos += 1;
                v |= ((x & 0x7f) as u64) << s;
                if x < 0x80 {
                    break;
                }
                s += 7;
            }
            v
        };
        let mut pos = 12usize;
        let nsec = out[pos];
        pos += 1;
        let (mut params, mut upvals) = (None, None);
        for _ in 0..nsec {
            let tag = out[pos];
            pos += 1;
            let len = read_uv(&out, &mut pos) as usize;
            if tag == SEC_PARAMS {
                params = Some(out[pos..pos + len].to_vec());
            } else if tag == SEC_UPVALS {
                upvals = Some(out[pos..pos + len].to_vec());
            }
            pos += len;
        }
        let pb = params.expect("SEC_PARAMS present");

        let perm = crypt::oplayout_perm(seed, 0);
        let mperm = crypt::oplayout_maskperm(seed, 0);
        let gmode = crypt::oplayout_gmode(seed, 0);
        let mut plain = Vec::new();
        write_uvarint(&mut plain, 3);
        write_uvarint(&mut plain, 1);
        write_uvarint(&mut plain, 40);
        write_uvarint(&mut plain, perm[0] as u64);
        write_uvarint(&mut plain, perm[1] as u64);
        write_uvarint(&mut plain, perm[2] as u64);
        write_uvarint(&mut plain, mperm[0] as u64);
        write_uvarint(&mut plain, mperm[1] as u64);
        write_uvarint(&mut plain, mperm[2] as u64);
        write_uvarint(&mut plain, gmode as u64);
        assert_eq!(
            pb.len(),
            plain.len(),
            "SEC_PARAMS byte length is unchanged for these (realistic, <128) values"
        );
        assert_ne!(pb, plain, "SEC_PARAMS must be masked, not the plaintext (num_params,is_vararg,max_stack) encoding");

        let fbase = crypt::opmask_key(seed);
        let fsk = crypt::framing_key(seed, &fenv(seed));
        let mut mp = 0usize;
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_NUMPARAMS),
            3,
            "num_params"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_VARARG),
            1,
            "is_vararg"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_MAXSTACK),
            40,
            "max_stack"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_OPLAYOUT),
            perm[0] as u64,
            "oplayout0"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_OPLAYOUT + 1),
            perm[1] as u64,
            "oplayout1"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_OPLAYOUT + 2),
            perm[2] as u64,
            "oplayout2"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_MASKPERM),
            mperm[0] as u64,
            "maskperm0"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_MASKPERM + 1),
            mperm[1] as u64,
            "maskperm1"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_MASKPERM + 2),
            mperm[2] as u64,
            "maskperm2"
        );
        assert_eq!(
            read_uvarint_masked(&pb, &mut mp, fbase, &fsk, 0, crypt::FR_GMODE),
            gmode as u64,
            "gmode"
        );
        let ub = upvals.expect("SEC_UPVALS present");
        let mut up = 0usize;
        assert_eq!(
            read_uv(&ub, &mut up),
            2,
            "upval count stays plain (a count, not a scalar)"
        );
        for (ui, (want_in, want_idx)) in [(1u64, 5u64), (0, 12)].into_iter().enumerate() {
            let fidx = crypt::FR_UPVAL_BASE + 2 * ui as u32;
            assert_eq!(
                read_uvarint_masked(&ub, &mut up, fbase, &fsk, 0, fidx),
                want_in,
                "in_stack {ui}"
            );
            assert_eq!(
                read_uvarint_masked(&ub, &mut up, fbase, &fsk, 0, fidx + 1),
                want_idx,
                "index {ui}"
            );
        }
    }

    #[test]
    fn framing_size_is_neutral_below_128_and_documented_above() {
        use crate::kepoch::KepochMode;
        let enc = crate::encoding::Encoding::from_seed(3);
        let sec_params_len = |np: u8| -> usize {
            let mut p = sample_proto();
            p.num_params = np;
            let out = serialize_encrypted(
                &p,
                5,
                &enc,
                false,
                crypt::TargetProfile::CliTest,
                false,
                false,
                KepochMode::Off,
            );
            let mut pos = 12usize;
            let nsec = out[pos];
            pos += 1;
            let mut found = 0;
            for _ in 0..nsec {
                let tag = out[pos];
                pos += 1;
                let (mut len, mut s) = (0usize, 0u32);
                loop {
                    let x = out[pos];
                    pos += 1;
                    len |= ((x & 0x7f) as usize) << s;
                    if x < 0x80 {
                        break;
                    }
                    s += 7;
                }
                if tag == SEC_PARAMS {
                    found = len;
                }
                pos += len;
            }
            found
        };

        let base = sec_params_len(1);
        for np in [0u8, 63, 127] {
            assert_eq!(
                sec_params_len(np),
                base,
                "num_params={np} (<128): SEC_PARAMS length unchanged (size-neutral)"
            );
        }
        assert_eq!(
            sec_params_len(128),
            base + 1,
            "num_params>=128 is a 2-byte masked uvarint (documented +1)"
        );
    }

    #[test]
    fn a_flipped_framing_byte_decodes_to_a_valid_alternate_not_garbage() {
        use crate::kepoch::KepochMode;
        let enc = crate::encoding::Encoding::from_seed(2);
        let seed = 0x_F00D_5EEDu64;
        let mut p = sample_proto();
        p.num_params = 2;
        p.is_vararg = false;
        p.max_stack = 20;
        p.upvals = vec![UpvalDesc {
            in_stack: true,
            index: 4,
        }];
        let mut out = serialize_encrypted(
            &p,
            seed,
            &enc,
            false,
            crypt::TargetProfile::CliTest,
            false,
            false,
            KepochMode::Off,
        );
        let mut pos = 12usize;
        let nsec = out[pos];
        pos += 1;
        let mut params_start = None;
        for _ in 0..nsec {
            let tag = out[pos];
            pos += 1;
            let (mut len, mut s) = (0usize, 0u32);
            loop {
                let x = out[pos];
                pos += 1;
                len |= ((x & 0x7f) as usize) << s;
                if x < 0x80 {
                    break;
                }
                s += 7;
            }
            if tag == SEC_PARAMS {
                params_start = Some(pos);
            }
            pos += len;
        }
        let start = params_start.expect("SEC_PARAMS present");
        let fbase = crypt::opmask_key(seed);
        let fsk = crypt::framing_key(seed, &fenv(seed));
        let mut rp = start;
        let np_before = read_uvarint_masked(&out, &mut rp, fbase, &fsk, 0, crypt::FR_NUMPARAMS);
        assert_eq!(np_before, 2, "num_params reads back honest");
        assert_eq!(
            out[start] & 0x80,
            0,
            "num_params<128 masks to a single byte (continuation clear)"
        );
        out[start] ^= 0x01;
        let mut rp2 = start;
        let np_after = read_uvarint_masked(&out, &mut rp2, fbase, &fsk, 0, crypt::FR_NUMPARAMS);
        assert_ne!(
            np_after, np_before,
            "a single-byte flip decodes to a different value"
        );
        assert!(
            np_after < 128 && rp2 == start + 1,
            "still a well-formed single-byte value: a valid alternate, not malformed"
        );
    }

    #[test]
    fn framing_domain_is_disjoint_from_existing_domains() {
        for seed in 0..1000u64 {
            let (sj, qk, ej) = crypt::struct_domains(seed);
            let fr = crypt::framing_domain(seed);
            assert!(
                fr != sj && fr != qk && fr != ej,
                "framing domain collides with an existing domain at seed {seed}"
            );
        }
    }
}
