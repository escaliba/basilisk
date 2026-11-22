use crate::encoding::Encoding;
use crate::proto::{Const, Proto};

pub const FIXED: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x9e37_79b9,
    0x7f4a_7c15,
    0xbf58_476d,
    0x1ce4_e5b9,
    0x94d0_49bb,
    0x1331_11eb,
];

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn block(key: &[u32; 8], nonce: &[u32; 3], counter: u32) -> [u32; 16] {
    let mut s = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        counter,
        nonce[0],
        nonce[1],
        nonce[2],
    ];
    let init = s;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 {
        s[i] = s[i].wrapping_add(init[i]);
    }
    s
}

fn key8(b: [u32; 16]) -> [u32; 8] {
    b[0..8].try_into().unwrap()
}

fn stream_xor(key: &[u32; 8], nonce: &[u32; 3], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (c, chunk) in data.chunks(64).enumerate() {
        let words = block(key, nonce, c as u32);
        let mut ks = [0u8; 64];
        for i in 0..16 {
            ks[4 * i..4 * i + 4].copy_from_slice(&words[i].to_le_bytes());
        }
        for (j, &d) in chunk.iter().enumerate() {
            out.push(d ^ ks[j]);
        }
    }
    out
}

pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let k: [u32; 8] =
        std::array::from_fn(|i| u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap()));
    let n: [u32; 3] =
        std::array::from_fn(|i| u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap()));
    stream_xor(&k, &n, data)
}

fn salt_words(salt: &[u8; 12]) -> [u32; 3] {
    [
        u32::from_le_bytes(salt[0..4].try_into().unwrap()),
        u32::from_le_bytes(salt[4..8].try_into().unwrap()),
        u32::from_le_bytes(salt[8..12].try_into().unwrap()),
    ]
}

pub fn code_digest(main: &Proto, enc: &Encoding) -> u32 {
    fn go(h: &mut u32, p: &Proto, enc: &Encoding) {
        for inst in &p.code {
            *h = h.rotate_left(7) ^ enc.phys(inst.op) as u32;
        }
        for c in &p.protos {
            go(h, c, enc);
        }
    }
    let mut h: u32 = 0x9E37_79B9;
    go(&mut h, main, enc);
    h
}

pub fn gen_key(salt: &[u8; 12], digest: u32, env_digest: &[u32; 8], probes: &[u32]) -> [u32; 8] {
    let mut counter = digest;
    for &p in probes {
        counter = counter.rotate_left(5) ^ p;
    }

    // env digest binds key
    let key: [u32; 8] = std::array::from_fn(|i| FIXED[i] ^ env_digest[i]);
    key8(block(&key, &salt_words(salt), counter))
}

thread_local! {
    static VM_TRAPS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub struct VmTrapsGuard {
    _priv: (),
}

impl Drop for VmTrapsGuard {
    fn drop(&mut self) {
        VM_TRAPS.with(|c| c.set(false));
    }
}

#[must_use = "bind the guard to the build scope"]
pub fn scoped_vm_traps(on: bool) -> VmTrapsGuard {
    VM_TRAPS.with(|c| c.set(on));
    VmTrapsGuard { _priv: () }
}

pub fn vm_traps_active() -> bool {
    VM_TRAPS.with(|c| c.get())
}

pub const TRAP_CANARY_DOMAIN: u32 = 0x_5456_4331;
pub const TRAP_SEED_DOMAIN: u32 = 0x_5456_5330;

#[derive(Clone, Copy)]
pub struct TrapParams {
    pub r1: u32,
    pub r2: u32,
    pub r3: u32,
    pub cr: u32,
    pub pr: u32,
    pub cdom: u32,
    pub sdom: u32,
}

pub fn trap_params(seed: u64) -> TrapParams {
    let mut s = seed ^ 0x_5452_4150_5f50_524d;
    let mut nx = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let rot = |v: u64| 1 + (v % 31) as u32;
    let r1 = rot(nx());
    let r2 = rot(nx());
    let r3 = rot(nx());
    let cr = rot(nx());
    let pr = rot(nx());
    let cdom = TRAP_CANARY_DOMAIN ^ nx() as u32;
    let sdom = TRAP_SEED_DOMAIN ^ nx() as u32;
    TrapParams {
        r1,
        r2,
        r3,
        cr,
        pr,
        cdom,
        sdom,
    }
}

pub fn trap_mix(p: &TrapParams, x: u32) -> u32 {
    let a = x ^ x.rotate_left(p.r1);
    let b = a.wrapping_add(a.rotate_left(p.r2));
    b ^ b.rotate_left(p.r3)
}

pub fn trap_canary(p: &TrapParams, genkey: &[u32; 8], pid: u32) -> u32 {
    trap_mix(p, genkey[2] ^ pid.rotate_left(p.cr) ^ p.cdom)
}

pub fn trap_seed(p: &TrapParams, genkey: &[u32; 8], pid: u32) -> u32 {
    trap_mix(p, genkey[5] ^ pid.rotate_left(p.pr) ^ p.sdom)
}

pub fn trap_page_fold(p: &TrapParams, acc: u32, page_digest: u32, k: u32) -> u32 {
    trap_mix(p, acc ^ page_digest).wrapping_add(k)
}

pub fn env_nonce(seed: u64) -> [u32; 3] {
    let mut z = seed ^ 0x_4259_5445_4e56_4e30;
    std::array::from_fn(|_| {
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) as u32
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TargetProfile {
    #[default]
    CliTest,
    Executor,
    Studio,
    RobloxClient,
    RobloxServer,
}

impl TargetProfile {
    fn has_gui_host(self) -> bool {
        matches!(
            self,
            TargetProfile::Executor | TargetProfile::Studio | TargetProfile::RobloxClient
        )
    }

    pub fn runservice_methods(self) -> &'static [(&'static [u8], &'static [u8])] {
        match self {
            TargetProfile::CliTest => &[],
            TargetProfile::Executor => &[(b"IsStudio", b"false"), (b"IsClient", b"true")],
            TargetProfile::Studio => &[
                (b"IsStudio", b"true"),
                (b"IsClient", b"true"),
                (b"IsServer", b"false"),
            ],
            TargetProfile::RobloxClient => &[
                (b"IsStudio", b"false"),
                (b"IsClient", b"true"),
                (b"IsServer", b"false"),
            ],
            TargetProfile::RobloxServer => &[
                (b"IsStudio", b"false"),
                (b"IsClient", b"false"),
                (b"IsServer", b"true"),
            ],
        }
    }
}

pub const PATH2D_TRAPS: &[(&[(i32, i32)], u32)] = &[
    (&[(0, 0), (300, 400)], 500),
    (&[(10, 20), (510, 1220)], 1300),
    (&[(0, 0), (300, 400), (600, 800)], 1000),
];

pub fn at2_trap_vals(profile: TargetProfile) -> Vec<u32> {
    let mut v = Vec::new();
    if profile == TargetProfile::CliTest {
        return v;
    }
    for ex in [b"Instance".as_slice(), b"Instance", b"Players", b"true"] {
        v.push(checksum(ex));
    }
    v.push(checksum(b"[C]"));
    v.push(checksum(b"[C]"));
    v.push(checksum(&[0xC3, 0xA9]));
    v.push(checksum(&[0x65, 0xCC, 0x81]));
    v.push(checksum(b"DataModel"));
    if profile.has_gui_host() {
        for (_, len) in PATH2D_TRAPS {
            v.push(*len);
        }
    }
    for (_, ex) in profile.runservice_methods() {
        v.push(checksum(ex));
    }
    v
}

fn env_vals(seed: u64, profile: TargetProfile) -> Vec<u32> {
    let mut vals: Vec<u32> = Vec::new();
    vals.push(checksum(b"number_format"));
    for (_, ex) in ENVFP_NUM {
        vals.push(checksum(ex));
    }
    vals.push(checksum(b"behavior_error_shape"));
    for (_, ex) in ENVFP_ERR {
        vals.push(checksum(ex));
    }
    vals.push(checksum(b"debug_info_s"));
    let cc = checksum(PROBE_EXPECTED);
    for _ in probe_set(seed) {
        vals.push(cc);
    }
    vals.extend(at2_trap_vals(profile));
    vals
}

pub fn env_fingerprint_digest(seed: u64, profile: TargetProfile) -> [u32; 8] {
    let vals = env_vals(seed, profile);
    let mut lanes = [0u32; 8];
    for (j, &v) in vals.iter().enumerate() {
        lanes[j % 8] = lanes[j % 8].rotate_left(5) ^ v;
    }
    key8(block(&lanes, &env_nonce(seed), 0))
}

pub fn struct_key(digest: &[u32; 8], dom: u32) -> [u32; 8] {
    let mut acc = dom;
    for i in 0..8usize {
        acc = (acc ^ digest[i]).rotate_left(7);
        acc = acc.wrapping_add(digest[(i + 5) & 7]);
    }
    let mut out = [0u32; 8];
    for i in 0..8usize {
        acc = (acc ^ dom.wrapping_add(i as u32)).rotate_left(11);
        acc = acc.wrapping_add(digest[i]);
        acc ^= acc >> 15;
        out[i] = acc;
    }
    out
}

pub fn struct_domains(seed: u64) -> (u32, u32, u32) {
    let mk = opmask_key(seed);
    let mp = mapkey(seed);
    (mk, mp, mk.rotate_left(16) ^ mp)
}

pub fn framing_domain(seed: u64) -> u32 {
    opmask_key(seed).rotate_left(5) ^ mapkey(seed).rotate_left(19)
}

pub fn framing_key(seed: u64, envdig: &[u32; 8]) -> [u32; 8] {
    struct_key(envdig, framing_domain(seed))
}

pub const FR_NUMPARAMS: u32 = 1;
pub const FR_VARARG: u32 = 2;
pub const FR_MAXSTACK: u32 = 3;
pub const FR_UPVAL_BASE: u32 = 8;
pub const FR_ACTLEN: u32 = 0xAC;
pub const FR_OPLAYOUT: u32 = 0xA0;
pub const FR_MASKPERM: u32 = 0xA3;
pub const FR_GMODE: u32 = 0xA6;

const OPLAYOUTS: [[u8; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

pub fn oplayout_perm(seed: u64, pid: u32) -> [u8; 3] {
    let (c1, c2) = (opmask_key(seed) | 1, mapkey(seed) | 1);
    OPLAYOUTS[(fmix32(pid ^ 0x4F50_4C59, c1, c2) % 6) as usize]
}

pub fn oplayout_maskperm(seed: u64, pid: u32) -> [u8; 3] {
    let (c1, c2) = (opmask_key(seed) | 1, mapkey(seed) | 1);
    OPLAYOUTS[(fmix32(pid ^ 0x4D50_524D, c1, c2) % 6) as usize]
}

pub fn oplayout_gmode(seed: u64, pid: u32) -> u8 {
    let (c1, c2) = (opmask_key(seed) | 1, mapkey(seed) | 1);
    (fmix32(pid ^ 0x474D_4F44, c1, c2) & 1) as u8
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DtTrap {
    Vec3Mag(i32, i32, i32),
    CFrameSumX(i32, i32, i32, i32, i32, i32),

    Path2DLen(&'static [(i32, i32)]),
}

const DT_POOL: &[DtTrap] = &[
    DtTrap::Vec3Mag(3, 4, 0),
    DtTrap::Vec3Mag(0, 6, 8),
    DtTrap::Vec3Mag(5, 0, 12),
    DtTrap::Vec3Mag(8, 15, 0),
    DtTrap::Vec3Mag(9, 12, 20),
    DtTrap::Vec3Mag(2, 3, 6),
    DtTrap::CFrameSumX(1, 2, 3, 4, 5, 6),
    DtTrap::CFrameSumX(7, 0, 0, 3, 0, 0),
];

const PATH2D_POOL: &[DtTrap] = &[
    DtTrap::Path2DLen(&[(0, 0), (300, 400)]),
    DtTrap::Path2DLen(&[(0, 0), (600, 800)]),
    DtTrap::Path2DLen(&[(0, 0), (500, 1200)]),
    DtTrap::Path2DLen(&[(0, 0), (800, 1500)]),
    DtTrap::Path2DLen(&[(0, 0), (900, 1200)]),
    DtTrap::Path2DLen(&[(0, 0), (700, 2400)]),
];

impl DtTrap {
    pub fn expected(self) -> u32 {
        match self {
            DtTrap::Vec3Mag(x, y, z) => ((x * x + y * y + z * z) as f64).sqrt() as u32,
            DtTrap::CFrameSumX(a, _, _, d, _, _) => (a + d) as u32,
            DtTrap::Path2DLen(pts) => {
                let sum: f64 = pts
                    .windows(2)
                    .map(|w| {
                        let (dx, dy) = ((w[1].0 - w[0].0) as f64, (w[1].1 - w[0].1) as f64);
                        (dx * dx + dy * dy).sqrt()
                    })
                    .sum();
                sum.round() as u32
            }
        }
    }
}

fn dt_mix(seed: u64) -> u64 {
    let mut h = seed ^ 0x_D1B5_4A32_D192_ED03;
    h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h >> 31;
    h
}

pub fn dt_trap(seed: u64) -> DtTrap {
    DT_POOL[(dt_mix(seed) as usize) % DT_POOL.len()]
}

pub fn path2d_trap(seed: u64) -> DtTrap {
    PATH2D_POOL[(dt_mix(seed.rotate_left(17)) as usize) % PATH2D_POOL.len()]
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FoldTerm {
    Probe,
    Outer,
    Inner,
}

pub fn fold_order(seed: u64) -> [FoldTerm; 3] {
    let mut order = [FoldTerm::Probe, FoldTerm::Outer, FoldTerm::Inner];
    let mut h = dt_mix(seed ^ 0x_F01D_0173_AC11_5E22);
    for i in (1..3).rev() {
        let j = (h % (i as u64 + 1)) as usize;
        order.swap(i, j);
        h = dt_mix(h);
    }
    order
}

const PROBE_POOL: &[&str] = &[
    "pcall",
    "select",
    "tostring",
    "type",
    "pairs",
    "ipairs",
    "next",
    "error",
    "tonumber",
    "assert",
    "setmetatable",
    "getmetatable",
    "rawget",
    "rawequal",
    "rawset",
];

pub const PROBE_EXPECTED: &[u8] = b"[C]";

pub fn probe_set(seed: u64) -> Vec<&'static str> {
    let mut h = seed ^ 0x_9E37_79B9_7F4A_7C15;
    h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    h ^= h >> 31;
    let mut set = vec!["print"];
    for (i, &name) in PROBE_POOL.iter().enumerate() {
        if (h >> i) & 1 == 1 {
            set.push(name);
        }
    }
    set
}

pub fn probe_counter_term(seed: u64) -> u32 {
    let cc = checksum(PROBE_EXPECTED);
    probe_set(seed)
        .iter()
        .fold(0u32, |p, _| p.rotate_left(5) ^ cc)
}

pub fn canary_salt(seed: u64) -> u32 {
    let mut h = 0x811c_9dc5u32 ^ (seed as u32) ^ ((seed >> 32) as u32).rotate_left(16);
    h = h.rotate_left(13).wrapping_mul(0x9e37_79b9);
    h ^= h >> 15;
    h | 1
}

pub fn opmask_key(seed: u64) -> u32 {
    let mut z = seed ^ 0x_4259_5445_3141_4B00;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) as u32) | 1
}

pub fn opmask_byte(base: u32, esk: &[u32; 8], pid: u32, pc: u32) -> u8 {
    let mut h = base ^ esk[(pc & 7) as usize] ^ pid.rotate_left(13);
    h ^= pc.rotate_left(7);
    h ^= h >> 11;
    h = h.rotate_left(5) ^ pc;
    h ^= h >> 6;
    (h >> 3) as u8
}

pub fn opmask2_byte(base: u32, esk: &[u32; 8], pid: u32, pc: u32, slot: u32, j: u32) -> u8 {
    let mut h = base
        ^ esk[(pc.wrapping_add(slot) & 7) as usize]
        ^ pid.rotate_left(13)
        ^ pc.rotate_left(7)
        ^ slot.rotate_left(3)
        ^ j.rotate_left(19);
    h ^= h >> 15;
    h = h.rotate_left(13);
    h ^= h >> 11;
    h = h.rotate_left(7);
    h ^= h >> 17;
    let f = h ^ (h >> 10) ^ (h >> 20);
    (f & 0x7F) as u8
}

pub fn mapkey(seed: u64) -> u32 {
    let mut z = seed ^ 0x_4259_5445_3144_4B00;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) as u32) | 1
}

fn pmix(key: u32, esk: &[u32; 8], pid: u32, i: u32) -> u32 {
    let mut h = key ^ esk[(i & 7) as usize] ^ pid.rotate_left(13) ^ i.rotate_left(21);
    h ^= h >> 16;
    h = h.rotate_left(13);
    h ^= h >> 11;
    h = h.rotate_left(7);
    h ^= h >> 17;
    h
}

pub fn proto_opmap(key: u32, esk: &[u32; 8], pid: u32) -> [u8; 256] {
    let mut perm = [0u8; 256];
    for (k, p) in perm.iter_mut().enumerate() {
        *p = k as u8;
    }
    for i in (1..256usize).rev() {
        let j = (pmix(key, esk, pid, i as u32) % (i as u32 + 1)) as usize;
        perm.swap(i, j);
    }
    perm
}

pub const ENVFP_NUM: &[(&str, &[u8])] = &[
    ("1/0", b"inf"),
    ("-1/0", b"-inf"),
    ("0/0", b"nan"),
    ("0.1+0.2", b"0.30000000000000004"),
    ("1/3", b"0.3333333333333333"),
    ("2^53", b"9007199254740992"),
    ("2^63", b"9223372036854776000"),
];

pub const ENVFP_ERR: &[(&str, &[u8])] = &[
    (
        "return nil + nil",
        b"attempt to perform arithmetic (add) on nil",
    ),
    ("local x return x.y", b"attempt to index nil with 'y'"),
    ("return ({}) < ({})", b"attempt to compare table < table"),
];

pub fn env_fingerprint_term(seed: u64, profile: TargetProfile) -> u32 {
    env_vals(seed, profile)
        .iter()
        .fold(0u32, |p, &x| p.rotate_left(5) ^ x)
}

pub const PAGE_SIZE: usize = 512;

fn fold_inst(mut h: u32, inst: &crate::inst::Inst, enc: &Encoding) -> u32 {
    h = h.rotate_left(7) ^ enc.phys(inst.op) as u32;

    if crate::superop::is_super(inst.op) || crate::opcode::is_gensuper(inst.op) {
        for &o in &inst.ops {
            h = h.rotate_left(5) ^ o as u32;
        }
    } else {
        let ser = crate::opcode::operand_serialized(inst.op);
        h = h.rotate_left(5) ^ if ser[0] { inst.a as u32 } else { 0 };
        h = h.rotate_left(5) ^ if ser[1] { inst.b as u32 } else { 0 };
        h = h.rotate_left(5) ^ if ser[2] { inst.c as u32 } else { 0 };
    }
    h
}

pub fn proto_code_digest(proto: &Proto, enc: &Encoding) -> u32 {
    let mut h: u32 = 0x9E37_79B9;
    for inst in &proto.code {
        h = fold_inst(h, inst, enc);
    }
    h
}

pub fn page_semantic_digest(proto: &Proto, enc: &Encoding, base: usize, count: usize) -> u32 {
    let mut h: u32 = 0x9E37_79B9;
    for inst in proto.code.iter().skip(base).take(count) {
        h = fold_inst(h, inst, enc);
    }
    h
}

pub fn page_count(n: usize) -> usize {
    n.div_ceil(PAGE_SIZE)
}

pub fn wire_proto_digest(code_section: &[u8], pid: u32, seed: u64, envdig: &[u32; 8]) -> u32 {
    let mut h: u32 = opmask_key(seed);
    h = h.rotate_left(7) ^ pid;
    h = h.rotate_left(7) ^ mapkey(seed);
    for w in struct_key(envdig, struct_domains(seed).2) {
        h = h.rotate_left(7) ^ w;
    }
    for &b in code_section {
        h = h.rotate_left(5) ^ b as u32;
    }
    h ^= h >> 15;
    h
}

pub fn combined_code_digest(
    code_dg: u32,
    wire_dg: u32,
    pid: u32,
    seed: u64,
    gen: &[u32; 8],
) -> u32 {
    code_dg ^ wire_dg.rotate_left(opmask_key(seed) & 31) ^ gen[4].rotate_left(pid & 31)
}

pub fn root_key_dg(wire_dg: u32, pid: u32, gen: &[u32; 8]) -> u32 {
    wire_dg ^ gen[4].rotate_left(pid & 31)
}

pub fn framing_digest_domain(seed: u64) -> u32 {
    opmask_key(seed).rotate_left(11) ^ mapkey(seed).rotate_left(23)
}

pub(crate) fn fmix32(mut h: u32, c1: u32, c2: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(c1);
    h ^= h >> 15;
    h = h.wrapping_mul(c2);
    h ^= h >> 16;
    h
}

pub fn fold_proto_framing(
    wire_dg: u32,
    num_params: u32,
    is_vararg: bool,
    max_stack: u32,
    upvals: &[(bool, u32)],
    seed: u64,
) -> u32 {
    let c1 = opmask_key(seed) | 1;
    let c2 = mapkey(seed) | 1;
    let mut h = wire_dg ^ framing_digest_domain(seed);
    h = fmix32(h.wrapping_add(num_params), c1, c2);
    h = fmix32(h.wrapping_add(u32::from(is_vararg)), c1, c2);
    h = fmix32(h.wrapping_add(max_stack), c1, c2);
    h = fmix32(h.wrapping_add(upvals.len() as u32), c1, c2);
    for (i, &(in_stack, index)) in upvals.iter().enumerate() {
        h = fmix32(h.wrapping_add(i as u32), c1, c2);
        h = fmix32(h.wrapping_add(u32::from(in_stack)), c1, c2);
        h = fmix32(h.wrapping_add(index), c1, c2);
    }
    h
}

pub fn framing_family(seed: u64) -> u32 {
    (opmask_key(seed) ^ mapkey(seed).rotate_left(16)) & 1
}

pub fn framing_chain_root(seed: u64, pid: u32) -> u32 {
    let c1 = opmask_key(seed) | 1;
    let c2 = mapkey(seed) | 1;
    let root = opmask_key(seed).rotate_left(7) ^ mapkey(seed).rotate_left(13);
    let seed_in = if framing_family(seed) == 0 {
        pid
    } else {
        pid.rotate_left(11)
    };
    fmix32(seed_in ^ root, c1, c2)
}

pub fn framing_chain_step(seed: u64, state: u32, tag: u32, len: u64) -> u32 {
    let c1 = opmask_key(seed) | 1;
    let c2 = mapkey(seed) | 1;
    let l = len as u32;
    if framing_family(seed) == 0 {
        fmix32(
            state.wrapping_add(l).wrapping_add(tag.rotate_left(16)),
            c1,
            c2,
        )
    } else {
        fmix32(state.rotate_left((tag & 15) + 1) ^ l, c1, c2)
    }
}

pub fn framing_chain_trailer(seed: u64, state: u32) -> u32 {
    let c1 = opmask_key(seed) | 1;
    let c2 = mapkey(seed) | 1;
    let dom = opmask_key(seed).rotate_left(19) ^ mapkey(seed).rotate_left(5);
    fmix32(state ^ dom, c1, c2)
}

pub fn proto_key(gen: &[u32; 8], pid: u32, code_dg: u32) -> [u32; 8] {
    key8(block(gen, &[pid, code_dg, 0], 0))
}

pub fn const_epoch(gen: &[u32; 8], pid: u32, code_dg: u32, ticket: u32) -> u32 {
    let mut e = gen[2].rotate_left(9) ^ pid;
    e = e.rotate_left(13) ^ code_dg;
    e = e.rotate_left(7) ^ gen[5];
    (e.rotate_left(11) ^ gen[1]) ^ ticket
}

pub const ACT_DOMAIN: u32 = 0x_4143_5456;
pub const ACT_ROOT_DOMAIN: u32 = 0x_4143_5452;

pub fn activation_sk(envdig: &[u32; 8]) -> [u32; 8] {
    struct_key(envdig, ACT_DOMAIN)
}

fn host_probe(sk_act: &[u32; 8], pid: u32, c1: u32, c2: u32) -> u32 {
    fmix32(sk_act[(pid & 7) as usize] ^ pid.rotate_left(13), c1, c2)
}

pub fn activation_root(genkey: &[u32; 8], seed: u64) -> u32 {
    let (c1, c2) = (opmask_key(seed) | 1, mapkey(seed) | 1);
    fmix32(genkey[0] ^ ACT_ROOT_DOMAIN, c1, c2)
}

pub fn activation_ticket(parent: u32, pid: u32, sk_act: &[u32; 8], seed: u64) -> u32 {
    let (c1, c2) = (opmask_key(seed) | 1, mapkey(seed) | 1);
    let mut t = fmix32((parent ^ ACT_DOMAIN).wrapping_add(pid), c1, c2);
    t = fmix32(t ^ host_probe(sk_act, pid, c1, c2), c1, c2);
    t
}

pub fn metadata_patch_key(gen: &[u32; 8], pid: u32, code_dg: u32, epoch: u32) -> u32 {
    let mut k = gen[1] ^ pid;
    k = k.rotate_left(7) ^ code_dg;
    k = k.rotate_left(11) ^ epoch;
    k.rotate_left(13) ^ gen[6]
}

pub fn patch_site(raw: u32, pk: u32, i: u32) -> u32 {
    let rot = (pk ^ i) & 31;
    let mut t = (raw ^ pk).rotate_left(rot);
    t = t.rotate_left(11) ^ (pk ^ i.rotate_left(13));
    t.rotate_left(5) ^ pk
}

pub fn block_state_mix(seed: u64) -> (u32, u32) {
    (opmask_key(seed) | 1, mapkey(seed) | 1)
}

pub fn block_state_act_nonce(genkey: &[u32; 8], seed: u64, pid: u32) -> u32 {
    let (m1, m2) = block_state_mix(seed);
    fmix32(genkey[4] ^ pid.rotate_left(11), m1, m2)
}

pub fn block_state_root(proto_key: &[u32; 8], act_nonce: u32, seed: u64) -> u32 {
    let (m1, m2) = block_state_mix(seed);
    fmix32(proto_key[3] ^ act_nonce, m1, m2)
}

pub fn block_state_transition(prev: u32, corr: u32, seed: u64) -> u32 {
    let (m1, m2) = block_state_mix(seed);
    fmix32(prev, m1, m2) ^ corr
}

pub fn block_edge_correction(target: u32, pred: u32, seed: u64) -> u32 {
    let (m1, m2) = block_state_mix(seed);
    target ^ fmix32(pred, m1, m2)
}

pub fn block_tree_corr(seed: u64, pid: u32, pred_block: u32, succ_block: u32) -> u32 {
    let (m1, m2) = block_state_mix(seed);
    fmix32(
        fmix32(pid ^ pred_block.rotate_left(7), m1, m2).wrapping_add(succ_block.rotate_left(13)),
        m2,
        m1,
    )
}

pub fn d1_root(genkey: &[u32; 8], seed: u64, pid: u32) -> u32 {
    let (m1, m2) = block_state_mix(seed);
    let act = block_state_act_nonce(genkey, seed, pid);
    fmix32(genkey[3].wrapping_add(pid) ^ act, m1, m2)
}

pub fn instr_patch_domain(seed: u64) -> u32 {
    let mut z = seed ^ 0x_4953_4841_5244_0000;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) as u32) | 1
}

pub const SIDECAR_SLOT_BASE: u32 = 16;

pub fn sidecar_patch_domain(seed: u64) -> u32 {
    let mut z = seed ^ 0x_5349_4443_4152_0000;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) as u32) | 1
}

pub const CONTROLFLOW_SLOT_BASE: u32 = 64;

pub fn controlflow_patch_domain(seed: u64) -> u32 {
    let mut z = seed ^ 0x_4346_4C4F_5750_0000;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) as u32) | 1
}

pub fn instr_patch_key(gen: &[u32; 8], pid: u32, dom: u32) -> u32 {
    let mut k = gen[3] ^ pid;
    k = k.rotate_left(9) ^ dom;
    k.rotate_left(13) ^ gen[7]
}

fn instr_patch_mix(pk: u32, pc: u32, slot: u32) -> u32 {
    let mut h = pk ^ pc.rotate_left(5) ^ pk.rotate_left(slot * 11 + 5);
    h ^= h >> 16;
    h = h.wrapping_add(h << 3);
    h ^= h >> 11;
    h = h.rotate_left(13);
    h = h.wrapping_add(pk);
    h ^= h >> 15;
    h = h.wrapping_add(h << 7);
    h ^= h >> 17;
    h
}

pub fn instr_patch_selected(pk: u32, pc: u32, slot: u32) -> bool {
    let h = instr_patch_mix(pk, pc, slot);
    let f = h ^ (h >> 7) ^ (h >> 14) ^ (h >> 21) ^ (h >> 28);
    f & 3 == 0
}

pub fn instr_patch_delta(pk: u32, pc: u32, slot: u32) -> u32 {
    1 + ((instr_patch_mix(pk, pc, slot) >> 4) & 1023)
}

pub fn checksum(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for &b in bytes {
        h = h.rotate_left(5) ^ b as u32;
    }
    h
}

pub fn const_site_token(position: u32, concrete_op: u32) -> u32 {
    let mut t: u32 = 0x811C_9DC5;
    t = t.rotate_left(7) ^ position;
    t = t.rotate_left(5) ^ concrete_op;
    if t == 0 {
        0x9E37_79B9
    } else {
        t
    }
}

pub fn keyed_tag(pkey: &[u32; 8], index: u32, site: u32, body: &[u8]) -> [u8; 8] {
    let mut h1 = pkey[0] ^ index;
    let mut h2 = pkey[1] ^ site;
    for &b in body {
        h1 = (h1.rotate_left(5) ^ b as u32).wrapping_add(pkey[2]);
        h2 = (h2.rotate_left(7) ^ b as u32).wrapping_add(pkey[3]);
    }
    h1 ^= pkey[6];
    h2 ^= pkey[7];
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&h1.to_le_bytes());
    out[4..8].copy_from_slice(&h2.to_le_bytes());
    out
}

pub const CBODY_NUMBER: u8 = 0;
pub const CBODY_STRING: u8 = 1;
pub const CBODY_NUMBER_DENSE: u8 = 2;

const DENSE_INT_MAX: f64 = 4_503_599_627_370_496.0;

pub fn is_dense_i53_number(n: f64) -> Option<i64> {
    if !n.is_finite() || n.fract() != 0.0 {
        return None;
    }
    if n == 0.0 && n.is_sign_negative() {
        return None;
    }
    if n.abs() > DENSE_INT_MAX {
        return None;
    }
    let i = n as i64;
    (i as f64 == n).then_some(i)
}

fn push_zigzag(out: &mut Vec<u8>, v: i64) {
    let mut u = ((v << 1) ^ (v >> 63)) as u64;
    loop {
        if u < 0x80 {
            out.push(u as u8);
            return;
        }
        out.push((u as u8 & 0x7f) | 0x80);
        u >>= 7;
    }
}

pub fn encrypt_const(pkey: &[u32; 8], index: u32, epoch: u32, site: u32, c: &Const) -> Vec<u8> {
    let mut body = Vec::new();
    match c {
        Const::Number(n) | Const::FlatBlockId(n) => {
            if let Some(i) = is_dense_i53_number(*n) {
                body.push(CBODY_NUMBER_DENSE);
                push_zigzag(&mut body, i);
            } else {
                body.push(CBODY_NUMBER);
                body.extend_from_slice(&n.to_le_bytes());
            }
        }
        Const::Str(s) => {
            body.push(CBODY_STRING);
            body.extend_from_slice(s);
        }
    }
    let mut plain = keyed_tag(pkey, index, site, &body).to_vec();
    plain.extend_from_slice(&body);
    stream_xor(pkey, &[index, epoch, site], &plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inst::Inst;
    use crate::opcode::Opcode;
    use crate::proto::Proto;

    fn c1_proto() -> Proto {
        Proto {
            num_params: 1,
            is_vararg: false,
            max_stack: 4,
            code: vec![
                Inst::new(Opcode::LoadK, 0, 0, 0),
                Inst::new(Opcode::Return, 0, 2, 0),
            ],
            consts: vec![Const::Str(b"hydroxide".to_vec())],
            upvals: vec![],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        }
    }

    fn decrypt_passes(pkey: &[u32; 8], index: u32, blob: &[u8]) -> bool {
        let plain = stream_xor(pkey, &[index, 0, 0], blob);
        if plain.len() < 8 {
            return false;
        }
        keyed_tag(pkey, index, 0, &plain[8..]) == plain[0..8]
    }

    #[test]
    fn c1_proto_code_digest_is_deterministic_and_code_sensitive() {
        let enc = crate::encoding::Encoding::from_seed(7);
        let base = c1_proto();
        let d = proto_code_digest(&base, &enc);
        assert_eq!(
            d,
            proto_code_digest(&base, &enc),
            "digest must be deterministic"
        );
        let mut op_changed = c1_proto();
        op_changed.code[1] = Inst::new(Opcode::GetUpval, 0, 2, 0);
        assert_ne!(
            proto_code_digest(&op_changed, &enc),
            d,
            "an opcode change must move the digest"
        );
        let mut operand_changed = c1_proto();
        operand_changed.code[0].b = 1;
        assert_ne!(
            proto_code_digest(&operand_changed, &enc),
            d,
            "an operand change must move the digest"
        );
    }

    #[test]
    fn fold_proto_framing_is_deterministic_and_field_sensitive() {
        let seed = 0xC0FF_EE42u64;
        let wire = 0x1234_5678u32;
        let ups = [(true, 5u32), (false, 12)];
        let base = fold_proto_framing(wire, 2, false, 20, &ups, seed);
        assert_eq!(
            base,
            fold_proto_framing(wire, 2, false, 20, &ups, seed),
            "deterministic"
        );
        assert_ne!(
            fold_proto_framing(wire, 3, false, 20, &ups, seed),
            base,
            "num_params 2->3"
        );
        assert_ne!(
            fold_proto_framing(wire, 2, true, 20, &ups, seed),
            base,
            "is_vararg false->true"
        );
        assert_ne!(
            fold_proto_framing(wire, 2, false, 21, &ups, seed),
            base,
            "max_stack 20->21"
        );
        assert_ne!(
            fold_proto_framing(wire, 2, false, 20, &ups[..1], seed),
            base,
            "upval count 2->1"
        );
        let flip_in = [(false, 5u32), (false, 12)];
        assert_ne!(
            fold_proto_framing(wire, 2, false, 20, &flip_in, seed),
            base,
            "upval[0].in_stack true->false"
        );
        let bump_idx = [(true, 6u32), (false, 12)];
        assert_ne!(
            fold_proto_framing(wire, 2, false, 20, &bump_idx, seed),
            base,
            "upval[0].index 5->6"
        );
        let reordered = [(false, 12u32), (true, 5)];
        assert_ne!(
            fold_proto_framing(wire, 2, false, 20, &reordered, seed),
            base,
            "upval order is positional"
        );
    }

    #[test]
    fn fold_proto_framing_binds_to_wire_and_seed() {
        let ups = [(true, 1u32)];
        assert_ne!(
            fold_proto_framing(1, 2, false, 20, &ups, 7),
            fold_proto_framing(2, 2, false, 20, &ups, 7),
            "different wire_dg base moves the digest"
        );
        assert_ne!(
            fold_proto_framing(1, 2, false, 20, &ups, 7),
            fold_proto_framing(1, 2, false, 20, &ups, 8),
            "different seed moves the framing domain"
        );
    }

    #[test]
    fn framing_digest_domain_is_disjoint_from_every_other_domain() {
        for seed in 0..2000u64 {
            let (sj, qk, ej) = struct_domains(seed);
            let fmask = framing_domain(seed);
            let fdg = framing_digest_domain(seed);
            assert!(
                fdg != sj && fdg != qk && fdg != ej && fdg != fmask,
                "framing digest domain collides at seed {seed}"
            );
        }
    }

    #[test]
    fn fold_proto_framing_matches_the_vm_template_arithmetic() {
        fn add32(a: u32, b: u32) -> u32 {
            ((a as u64 + b as u64) % 0x1_0000_0000) as u32
        }
        fn luau_mul(h: u32, c: u32) -> u32 {
            let hl = (h % 65536) as u64;
            let hh = (h / 65536) as u64;
            let c64 = c as u64;
            ((hl * c64 + ((hh * c64) % 65536) * 65536) % 0x1_0000_0000) as u32
        }
        fn luau_fmix(mut h: u32, fm1: u32, fm2: u32) -> u32 {
            h ^= h >> 16;
            h = luau_mul(h, fm1);
            h ^= h >> 15;
            h = luau_mul(h, fm2);
            h ^= h >> 16;
            h
        }
        fn luau_mirror(
            wire: u32,
            np: u32,
            vararg: bool,
            ms: u32,
            ups: &[(bool, u32)],
            seed: u64,
        ) -> u32 {
            let mk = opmask_key(seed);
            let mp = mapkey(seed);
            let fm1 = mk - mk % 2 + 1;
            let fm2 = mp - mp % 2 + 1;
            let mut h = wire ^ (mk.rotate_left(11) ^ mp.rotate_left(23));
            h = luau_fmix(add32(h, np), fm1, fm2);
            h = luau_fmix(add32(h, if vararg { 1 } else { 0 }), fm1, fm2);
            h = luau_fmix(add32(h, ms), fm1, fm2);
            h = luau_fmix(add32(h, ups.len() as u32), fm1, fm2);
            for (i, &(instk, idx)) in ups.iter().enumerate() {
                h = luau_fmix(add32(h, i as u32), fm1, fm2);
                h = luau_fmix(add32(h, if instk { 1 } else { 0 }), fm1, fm2);
                h = luau_fmix(add32(h, idx), fm1, fm2);
            }
            h
        }
        for seed in [1u64, 42, 1337, 0xDEAD_BEEF] {
            let cases: [(u32, bool, u32, &[(bool, u32)]); 3] = [
                (0, false, 1, &[]),
                (2, true, 20, &[(true, 3), (false, 7)]),
                (5, false, 200, &[(false, 0), (true, 255), (true, 1)]),
            ];
            for (np, vg, ms, ups) in cases {
                let wire = 0x1234_5678u32 ^ seed as u32;
                assert_eq!(
                    fold_proto_framing(wire, np, vg, ms, ups, seed),
                    luau_mirror(wire, np, vg, ms, ups, seed),
                    "Rust helper must equal the inlined VM-template fold arithmetic"
                );
            }
        }
    }

    #[test]
    fn fold_has_no_secret_independent_field_kernel() {
        let deltas: [u32; 8] = [
            128,
            128u32.wrapping_neg(),
            32,
            32u32.wrapping_neg(),
            16384,
            16384u32.wrapping_neg(),
            64,
            1,
        ];
        for seed in [1u64, 42, 1337, 0xC0FF_EE] {
            for &wire in &[0u32, 0x1234_5678, 0x9E37_79B9, 0xFFFF_FFFF] {
                for &ms in &[20u32, 200] {
                    let base = fold_proto_framing(wire, 2, false, ms, &[], seed);
                    for &d in &deltas {
                        assert_ne!(
                            base,
                            fold_proto_framing(wire, 2, true, ms.wrapping_add(d), &[], seed),
                            "vararg flip + max_stack additive compensator d={d} (ms={ms}) must not collide"
                        );
                        assert_ne!(
                            base,
                            fold_proto_framing(wire, 2, true, ms ^ d, &[], seed),
                            "vararg flip + max_stack xor compensator d={d} (ms={ms}) must not collide"
                        );
                        assert_ne!(
                            base,
                            fold_proto_framing(wire, 2 + 1, false, ms.wrapping_add(d), &[], seed),
                            "num_params + max_stack additive compensator d={d} (ms={ms}) must not collide"
                        );
                    }
                }
                let u_base = fold_proto_framing(wire, 1, false, 8, &[(true, 3)], seed);
                for &d in &deltas {
                    assert_ne!(
                        u_base,
                        fold_proto_framing(
                            wire,
                            1,
                            false,
                            8,
                            &[(false, 3u32.wrapping_add(d))],
                            seed
                        ),
                        "upval in_stack flip + index compensator d={d} must not collide"
                    );
                }
            }
        }
    }

    #[test]
    fn valid_alternate_framing_fails_the_constant_seal() {
        let seed = 0x_5EED_1234u64;
        let genkey = [
            0x1111_1111u32,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x5555_5555,
            0x6666_6666,
            0x7777_7777,
            0x8888_8888,
        ];
        let wire = 0xABCD_1234u32;
        let ups: [(bool, u32); 2] = [(true, 3), (false, 7)];
        let k = Const::Str(b"authenticated-framing".to_vec());
        let seal = |np, vg, ms, u: &[(bool, u32)]| -> (Vec<u8>, [u32; 8], u32, u32) {
            let kdg = fold_proto_framing(wire, np, vg, ms, u, seed);
            let pkey = proto_key(&genkey, 0, kdg);
            let epoch = const_epoch(&genkey, 0, kdg, 0);
            let site = patch_site(
                const_site_token(1, 5),
                metadata_patch_key(&genkey, 0, kdg, epoch),
                0,
            );
            (encrypt_const(&pkey, 0, epoch, site, &k), pkey, epoch, site)
        };
        let opens = |blob: &[u8], pkey: &[u32; 8], epoch: u32, site: u32| -> bool {
            let plain = stream_xor(pkey, &[0, epoch, site], blob);
            plain.len() >= 8 && keyed_tag(pkey, 0, site, &plain[8..]) == plain[0..8]
        };
        let (blob, pk_h, ep_h, st_h) = seal(2, false, 20, &ups);
        assert!(
            opens(&blob, &pk_h, ep_h, st_h),
            "honest framing opens its own sealed constant"
        );
        let alts: [(u32, bool, u32, &[(bool, u32)]); 6] = [
            (3, false, 20, &ups),
            (2, true, 20, &ups),
            (2, false, 21, &ups),
            (2, false, 20, &ups[..1]),
            (2, false, 20, &[(false, 3), (false, 7)]),
            (2, false, 20, &[(true, 4), (false, 7)]),
        ];
        for (np, vg, ms, u) in alts {
            let (_b, pk, ep, st) = seal(np, vg, ms, u);
            assert!(
                !opens(&blob, &pk, ep, st),
                "valid-alternate framing (np={np},vararg={vg},ms={ms},upvals={}) must fail the honest seal",
                u.len()
            );
        }
    }

    #[test]
    fn proto_code_digest_folds_the_physical_opcode_not_the_concrete() {
        let enc = crate::encoding::Encoding::from_seed(0xABCD_1234);
        let op = crate::opcode::ALL
            .iter()
            .map(|(o, _)| *o)
            .find(|o| !crate::superop::is_super(*o) && enc.phys(*o) != enc.concrete(*o))
            .expect("some non-super opcode is physically remapped");
        let mut proto = c1_proto();
        proto.code = vec![Inst::new(op, 1, 2, 3); 3];
        let got = proto_code_digest(&proto, &enc);
        let ser = crate::opcode::operand_serialized(op);
        let fold = |opval: u32| {
            let mut h: u32 = 0x9E37_79B9;
            for _ in 0..3 {
                h = h.rotate_left(7) ^ opval;
                h = h.rotate_left(5) ^ if ser[0] { 1u32 } else { 0 };
                h = h.rotate_left(5) ^ if ser[1] { 2u32 } else { 0 };
                h = h.rotate_left(5) ^ if ser[2] { 3u32 } else { 0 };
            }
            h
        };
        assert_eq!(
            got,
            fold(enc.phys(op) as u32),
            "_pdg binds the physical (remapped) opcode id"
        );
        assert_ne!(
            got,
            fold(enc.concrete(op) as u32),
            "_pdg does not bind the pre-remap concrete id"
        );
    }

    #[test]
    fn c1_constants_are_bound_to_the_code_digest() {
        let enc = crate::encoding::Encoding::from_seed(7);
        let proto = c1_proto();
        let genkey = gen_key(&[5u8; 12], 0xC0FFEE, &[0u32; 8], &[]);
        let pid = 0u32;
        let cdg = proto_code_digest(&proto, &enc);
        assert_ne!(cdg, 0, "sample proto has a non-trivial code digest");

        let bound = proto_key(&genkey, pid, cdg);
        let blind = proto_key(&genkey, pid, 0);
        assert_ne!(bound, blind, "code digest must change the proto key");

        let blob = encrypt_const(&bound, 0, 0, 0, &proto.consts[0]);
        assert!(
            decrypt_passes(&bound, 0, &blob),
            "the code-bound key must decrypt its own constant"
        );
        assert!(
            !decrypt_passes(&blind, 0, &blob),
            "a code-blind key must fail the integrity check (no bulk decrypt-all)"
        );
    }

    #[test]
    fn c1_1_site_token_is_position_and_opcode_sensitive_and_nonzero() {
        assert_ne!(
            const_site_token(1, 5),
            const_site_token(2, 5),
            "position must move the token"
        );
        assert_ne!(
            const_site_token(3, 5),
            const_site_token(3, 6),
            "opcode must move the token"
        );

        for p in 0..256u32 {
            for op in 0..80u32 {
                assert_ne!(const_site_token(p, op), 0);
            }
        }
    }

    #[test]
    fn c1_1_use_site_token_binds_the_constant() {
        let enc = Encoding::from_seed(0xC11);
        let proto = c1_proto();
        let pkey = proto_key(
            &gen_key(&[5u8; 12], proto_code_digest(&proto, &enc), &[0u32; 8], &[]),
            0,
            7,
        );
        let site = const_site_token(3, 12);
        assert_ne!(site, 0, "a real use-site token is never zero");
        let blob = encrypt_const(&pkey, 0, 0, site, &proto.consts[0]);

        assert!(
            !decrypt_passes(&pkey, 0, &blob),
            "a site-blind decrypt-all must fail the keyed tag"
        );

        let plain = stream_xor(&pkey, &[0, 0, site], &blob);
        assert_eq!(keyed_tag(&pkey, 0, site, &plain[8..]), plain[0..8]);
    }

    #[test]
    fn frame_epoch_binds_the_constant_and_a_flat_pool_model_fails() {
        let gen = gen_key(&[9u8; 12], 0xABCD, &[3u32; 8], &[7]);
        let (e0, e1, e2) = (
            const_epoch(&gen, 0, 0x1234, 0),
            const_epoch(&gen, 1, 0x1234, 0),
            const_epoch(&gen, 0, 0x5678, 0),
        );
        assert_ne!(e0, 0, "per-proto constant epoch is non-trivial");
        assert!(
            e0 != e1 && e0 != e2,
            "epoch varies by proto id and code digest"
        );
        let pkey = proto_key(&gen, 0, 0x1234);
        let site = const_site_token(4, 20);
        let blob = encrypt_const(
            &pkey,
            3,
            e0,
            site,
            &Const::Str(b"normal-vm-constant".to_vec()),
        );
        let flat = stream_xor(&pkey, &[3, 0, site], &blob);
        assert_ne!(
            keyed_tag(&pkey, 3, site, &flat[8..]),
            flat[0..8],
            "flat pool-index decrypt (captured pkey, no per-frame epoch) must fail closed"
        );
        let live = stream_xor(&pkey, &[3, e0, site], &blob);
        assert_eq!(
            keyed_tag(&pkey, 3, site, &live[8..]),
            live[0..8],
            "correct frame epoch verifies"
        );
    }

    #[test]
    fn activation_ticket_binds_the_const_epoch() {
        let gen = gen_key(&[9u8; 12], 0xABCD, &[3u32; 8], &[7]);

        assert_eq!(
            const_epoch(&gen, 3, 0xBEEF, 0),
            (const_epoch(&gen, 3, 0xBEEF, 0))
        );
        assert_ne!(
            const_epoch(&gen, 3, 0xBEEF, 0),
            const_epoch(&gen, 3, 0xBEEF, 0x1111_2222)
        );
        assert_ne!(
            const_epoch(&gen, 3, 0xBEEF, 1),
            const_epoch(&gen, 3, 0xBEEF, 2),
            "distinct tickets => distinct epochs"
        );
    }

    #[test]
    fn activation_ticket_is_lexical_and_one_way() {
        let envdig = [9u32, 8, 7, 6, 5, 4, 3, 2];
        let sk = activation_sk(&envdig);
        let seed = 0xDEAD_BEEFu64;
        let root = activation_root(&[1, 2, 3, 4, 5, 6, 7, 8], seed);
        let t_a = activation_ticket(root, 1, &sk, seed);
        let t_b = activation_ticket(root, 2, &sk, seed);
        let t_c = activation_ticket(t_a, 3, &sk, seed);
        assert_ne!(t_a, t_b, "siblings get distinct tickets");
        assert_ne!(
            t_c,
            activation_ticket(t_b, 3, &sk, seed),
            "same pid under different parents differs"
        );

        assert_ne!(
            activation_ticket(t_a, 2, &sk, seed),
            t_b,
            "capturing t_a does not let you derive sibling t_b"
        );
    }

    #[test]
    fn phase13_activation_tickets_are_statically_reconstructable() {
        let seed = 0x2026_0809u64;

        let envdig = env_fingerprint_digest(seed, TargetProfile::Executor);
        let genkey = gen_key(&[9u8; 12], 0xABCD, &envdig, &[7]);
        let sk = activation_sk(&envdig);

        let dfs = || {
            let t_root = activation_ticket(activation_root(&genkey, seed), 0, &sk, seed);
            let t_a = activation_ticket(t_root, 1, &sk, seed);
            let t_c = activation_ticket(t_a, 2, &sk, seed);
            let t_b = activation_ticket(t_root, 3, &sk, seed);
            (t_root, t_a, t_c, t_b)
        };

        assert_eq!(
            dfs(),
            dfs(),
            "tickets are a pure function of (seed, profile, genkey, tree)"
        );
        let (_t_root, _t_a, t_c, _t_b) = dfs();

        let cep_c_static = const_epoch(&genkey, 2, 0xC0DE, t_c);

        let t_c_again = activation_ticket(
            activation_ticket(
                activation_ticket(activation_root(&genkey, seed), 0, &sk, seed),
                1,
                &sk,
                seed,
            ),
            2,
            &sk,
            seed,
        );
        assert_eq!(cep_c_static, const_epoch(&genkey, 2, 0xC0DE, t_c_again),
            "a cold proto's ticketed constant epoch is reconstructable purely statically from the root");
    }

    #[test]
    fn site_token_patch_stage_is_required() {
        let gen = gen_key(&[9u8; 12], 0xABCD, &[3u32; 8], &[7]);
        let (pid, code_dg) = (0u32, 0x1234u32);
        let epoch = const_epoch(&gen, pid, code_dg, 0);
        let pkey = proto_key(&gen, pid, code_dg);
        let raw = const_site_token(4, 20);
        let pk = metadata_patch_key(&gen, pid, code_dg, epoch);
        let patched = patch_site(raw, pk, 3);
        assert_ne!(pk, 0, "patch key is non-trivial");
        assert_ne!(
            patched, raw,
            "the patch stage transforms the raw site token"
        );
        assert_ne!(
            patch_site(raw, pk, 4),
            patched,
            "the patch is per-constant-index"
        );
        let blob = encrypt_const(
            &pkey,
            3,
            epoch,
            patched,
            &Const::Str(b"normal-constant".to_vec()),
        );
        let no_patch = stream_xor(&pkey, &[3, epoch, raw], &blob);
        assert_ne!(
            keyed_tag(&pkey, 3, raw, &no_patch[8..]),
            no_patch[0..8],
            "raw deserialized site token (patch stage skipped) must fail closed"
        );
        let ok = stream_xor(&pkey, &[3, epoch, patched], &blob);
        assert_eq!(
            keyed_tag(&pkey, 3, patched, &ok[8..]),
            ok[0..8],
            "patched site token verifies"
        );
    }

    #[test]
    fn instr_shard_patch_is_keyed_and_invertible_and_bounded() {
        let gen = gen_key(&[9u8; 12], 0xABCD, &[3u32; 8], &[7]);
        let dom = instr_patch_domain(0xACE1);
        assert!(dom != 0, "domain constant is non-trivial");
        let k0 = instr_patch_key(&gen, 0, dom);
        let k1 = instr_patch_key(&gen, 1, dom);
        let g2 = gen_key(&[9u8; 12], 0xABCD, &[3u32; 8], &[8]);
        assert!(k0 != 0 && k0 != k1, "patch key non-trivial and per-proto");
        assert_ne!(
            instr_patch_key(&g2, 0, dom),
            k0,
            "patch key varies with the gen-key"
        );
        assert_ne!(
            instr_patch_key(&gen, 0, instr_patch_domain(0xBEEF)),
            k0,
            "patch key varies with the build domain"
        );

        for slot in 0..3u32 {
            for &a in &[0i64, 1, 7, 31, 200, 255] {
                for pc in 1..40u32 {
                    if instr_patch_selected(k0, pc, slot) {
                        let d = instr_patch_delta(k0, pc, slot) as i64;
                        assert!((1..=1024).contains(&d), "delta bounded");
                        let ser = a + d;
                        assert_ne!(
                            ser, a,
                            "a selected operand's stored value differs from the real value"
                        );
                        assert_eq!(ser - d, a, "the VM inverse recovers the exact operand");
                    }
                }
            }
        }

        let n = 200u32;
        for slot in 0..3u32 {
            let selected = (1..=n)
                .filter(|&pc| instr_patch_selected(k0, pc, slot))
                .count();
            assert!(selected > 0 && (selected as f64) < 0.5 * n as f64, "slot {slot} keyed selection is a bounded fraction, not the whole stream: {selected}/{n}");
        }
        let set = |pk: u32, slot: u32| -> std::collections::HashSet<u32> {
            (1..=n)
                .filter(|&pc| instr_patch_selected(pk, pc, slot))
                .collect()
        };
        assert_ne!(
            set(k0, 0),
            set(k1, 0),
            "the selected set varies across protos/builds"
        );
        assert_ne!(
            set(k0, 0),
            set(k0, 1),
            "slot A and slot B use independent selection streams"
        );
        assert_ne!(
            set(k0, 1),
            set(k0, 2),
            "slot B and slot C use independent selection streams"
        );
        let deltas =
            |slot: u32| -> Vec<u32> { (1..=n).map(|pc| instr_patch_delta(k0, pc, slot)).collect() };
        assert_ne!(
            deltas(0),
            deltas(1),
            "per-slot delta streams differ (A vs B)"
        );
        assert_ne!(
            deltas(1),
            deltas(2),
            "per-slot delta streams differ (B vs C)"
        );
    }

    #[test]
    fn instr_shard_prepatch_operand_fails_the_constant_key_schedule() {
        let enc = crate::encoding::Encoding::from_seed(0x15A0);
        let gen = gen_key(
            &[2u8; 12],
            0x1234,
            &env_fingerprint_digest(0x15A0, TargetProfile::CliTest),
            &[],
        );
        let dom = instr_patch_domain(0x15A0);
        let pk = instr_patch_key(&gen, 0, dom);
        let pc = (1..200u32)
            .find(|&pc| instr_patch_selected(pk, pc, 1))
            .expect("some pc is B-selected");
        let real_b = 1i32;
        let db = instr_patch_delta(pk, pc, 1) as i32;
        assert!(db > 0, "B delta is positive");

        let mut real = c1_proto();
        real.code = vec![Inst::new(Opcode::LoadK, 0, real_b, 0); pc as usize];
        real.code.push(Inst::new(Opcode::Return, 0, 1, 0));
        let mut prepatch = real.clone();
        prepatch.code[pc as usize - 1] = Inst::new(Opcode::LoadK, 0, real_b + db, 0);

        let real_dg = proto_code_digest(&real, &enc);
        let prepatch_dg = proto_code_digest(&prepatch, &enc);
        assert_ne!(
            real_dg, prepatch_dg,
            "digest over the pre-patch B (const-index) operand differs from the real digest"
        );

        let blob = encrypt_const(&proto_key(&gen, 0, real_dg), 0, 0, 0, &real.consts[0]);
        assert!(
            decrypt_passes(&proto_key(&gen, 0, real_dg), 0, &blob),
            "the repaired (real) digest yields the key that verifies"
        );
        assert!(
            !decrypt_passes(&proto_key(&gen, 0, prepatch_dg), 0, &blob),
            "using the pre-patch B operand desyncs the proto key and fails closed"
        );
    }

    #[test]
    fn prepatch_operand_fails_key_schedule() {
        let enc = crate::encoding::Encoding::from_seed(0x15A0);
        let gen = gen_key(
            &[2u8; 12],
            0x1234,
            &env_fingerprint_digest(0x15A0, TargetProfile::CliTest),
            &[],
        );
        let dom = instr_patch_domain(0x15A0);
        let pk = instr_patch_key(&gen, 0, dom);
        let pc = (1..200u32)
            .find(|&pc| instr_patch_selected(pk, pc, 1))
            .expect("some pc is B-selected");
        let real_b = 0i32;
        let db = instr_patch_delta(pk, pc, 1) as i32;

        let mut real = c1_proto();
        real.code = vec![Inst::new(Opcode::SetGlobal, 0, real_b, 0); pc as usize];
        real.code.push(Inst::new(Opcode::Return, 0, 1, 0));
        let mut prepatch = real.clone();
        prepatch.code[pc as usize - 1] = Inst::new(Opcode::SetGlobal, 0, real_b + db, 0);

        let real_dg = proto_code_digest(&real, &enc);
        let prepatch_dg = proto_code_digest(&prepatch, &enc);
        assert_ne!(real_dg, prepatch_dg, "digest over the pre-patch SETGLOBAL B (global-name const index) differs from the real digest");

        let blob = encrypt_const(&proto_key(&gen, 0, real_dg), 0, 0, 0, &real.consts[0]);
        assert!(
            decrypt_passes(&proto_key(&gen, 0, real_dg), 0, &blob),
            "the repaired SETGLOBAL digest yields the key that verifies"
        );
        assert!(
            !decrypt_passes(&proto_key(&gen, 0, prepatch_dg), 0, &blob),
            "the pre-patch SETGLOBAL B desyncs the proto key and fails closed"
        );
    }

    #[test]
    fn superop_sidecar_prepatch_operand_fails_the_constant_key_schedule() {
        let enc = crate::encoding::Encoding::from_seed(0x15A0);
        let gen = gen_key(
            &[2u8; 12],
            0x1234,
            &env_fingerprint_digest(0x15A0, TargetProfile::CliTest),
            &[],
        );
        let spk = instr_patch_key(&gen, 0, sidecar_patch_domain(0x15A0));

        let sid = SIDECAR_SLOT_BASE + 1;
        let pc = (1..400u32)
            .find(|&pc| instr_patch_selected(spk, pc, sid))
            .expect("some pc is sidecar-selected");
        let d = instr_patch_delta(spk, pc, sid) as i32;
        assert!(d > 0, "sidecar delta is positive");

        let real_ops = vec![0i32, 0, 0, 1, 0, 0];
        let mut real = c1_proto();
        real.code = vec![Inst::super_op(Opcode::Super5, real_ops.clone()); pc as usize];
        real.code.push(Inst::new(Opcode::Return, 0, 1, 0));
        let mut pp_ops = real_ops;
        pp_ops[1] += d;
        let mut prepatch = real.clone();
        prepatch.code[pc as usize - 1] = Inst::super_op(Opcode::Super5, pp_ops);

        let real_dg = proto_code_digest(&real, &enc);
        let prepatch_dg = proto_code_digest(&prepatch, &enc);
        assert_ne!(real_dg, prepatch_dg, "digest over the pre-patch super-op sidecar (const-index) operand differs from the real digest");

        let blob = encrypt_const(&proto_key(&gen, 0, real_dg), 0, 0, 0, &real.consts[0]);
        assert!(
            decrypt_passes(&proto_key(&gen, 0, real_dg), 0, &blob),
            "the repaired sidecar digest yields the key that verifies"
        );
        assert!(
            !decrypt_passes(&proto_key(&gen, 0, prepatch_dg), 0, &blob),
            "the pre-patch sidecar operand desyncs the proto key and fails closed"
        );
    }

    #[test]
    fn sidecar_patch_stream_is_domain_separated_from_abc() {
        assert_ne!(
            instr_patch_domain(0x999),
            sidecar_patch_domain(0x999),
            "sidecar domain differs from A/B/C domain"
        );
        let gen = [0x1111_1111u32, 2, 3, 4, 5, 6, 7, 0x8888_8888];
        let ipk = instr_patch_key(&gen, 3, instr_patch_domain(0x999));
        let spk = instr_patch_key(&gen, 3, sidecar_patch_domain(0x999));
        assert_ne!(
            ipk, spk,
            "sidecar patch key differs from the A/B/C patch key"
        );
        let same = (1..200u32)
            .filter(|&pc| {
                instr_patch_delta(spk, pc, SIDECAR_SLOT_BASE) == instr_patch_delta(ipk, pc, 0)
            })
            .count();
        assert!(
            same < 60,
            "sidecar slot-16 and A/B/C slot-0 delta streams are not identical ({same}/199 equal)"
        );
        let sel = (1..200u32)
            .filter(|&pc| instr_patch_selected(spk, pc, SIDECAR_SLOT_BASE))
            .count();
        assert!(
            sel > 0 && sel < 100,
            "sidecar selection is bounded and non-empty ({sel}/199)"
        );
    }

    #[test]
    fn controlflow_prepatch_offset_desyncs_key_and_round_trips_signed() {
        let enc = crate::encoding::Encoding::from_seed(0x15A0);
        let gen = gen_key(
            &[2u8; 12],
            0x1234,
            &env_fingerprint_digest(0x15A0, TargetProfile::CliTest),
            &[],
        );
        let cfk = instr_patch_key(&gen, 0, controlflow_patch_domain(0x15A0));

        let sid = CONTROLFLOW_SLOT_BASE;
        let pc = (1..400u32)
            .find(|&pc| instr_patch_selected(cfk, pc, sid))
            .expect("some pc is CF-A-selected");
        let d = instr_patch_delta(cfk, pc, sid) as i64;
        assert!(d > 0, "control-flow delta is positive");

        for real in [-4096i64, -1000, -13, -1, 0, 1, 13, 1000, 4096] {
            assert_eq!(
                (real + d) - d,
                real,
                "additive control-flow repair round-trips for real offset {real}"
            );
        }

        let real_off = -1i32;
        let mut real = c1_proto();
        real.code = vec![Inst::new(Opcode::Jmp, real_off, 0, 0); pc as usize];
        real.code.push(Inst::new(Opcode::Return, 0, 1, 0));
        let mut prepatch = real.clone();
        prepatch.code[pc as usize - 1] = Inst::new(Opcode::Jmp, real_off + d as i32, 0, 0);

        let real_dg = proto_code_digest(&real, &enc);
        let prepatch_dg = proto_code_digest(&prepatch, &enc);
        assert_ne!(
            real_dg, prepatch_dg,
            "digest over the pre-patch JMP slot-A offset differs from the real digest"
        );

        let blob = encrypt_const(&proto_key(&gen, 0, real_dg), 0, 0, 0, &real.consts[0]);
        assert!(
            decrypt_passes(&proto_key(&gen, 0, real_dg), 0, &blob),
            "the repaired (real) offset digest yields the key that verifies"
        );
        assert!(
            !decrypt_passes(&proto_key(&gen, 0, prepatch_dg), 0, &blob),
            "the pre-patch JMP offset desyncs the proto key and fails closed"
        );
    }

    #[test]
    fn controlflow_patch_stream_is_domain_separated_from_abc_and_sidecar() {
        let s = 0x999u64;
        assert_ne!(
            controlflow_patch_domain(s),
            instr_patch_domain(s),
            "CF domain differs from the A/B/C domain"
        );
        assert_ne!(
            controlflow_patch_domain(s),
            sidecar_patch_domain(s),
            "CF domain differs from the sidecar domain"
        );
        let gen = [0x1111_1111u32, 2, 3, 4, 5, 6, 7, 0x8888_8888];
        let ipk = instr_patch_key(&gen, 3, instr_patch_domain(s));
        let spk = instr_patch_key(&gen, 3, sidecar_patch_domain(s));
        let cfk = instr_patch_key(&gen, 3, controlflow_patch_domain(s));
        assert_ne!(cfk, ipk, "CF patch key differs from the A/B/C patch key");
        assert_ne!(cfk, spk, "CF patch key differs from the sidecar patch key");
        let sel = (1..200u32)
            .filter(|&pc| instr_patch_selected(cfk, pc, CONTROLFLOW_SLOT_BASE))
            .count();
        assert!(
            sel > 0 && sel < 100,
            "CF selection is bounded and non-empty ({sel}/199)"
        );
        let same = (1..200u32)
            .filter(|&pc| {
                instr_patch_delta(cfk, pc, CONTROLFLOW_SLOT_BASE) == instr_patch_delta(ipk, pc, 0)
            })
            .count();
        assert!(
            same < 60,
            "CF slot-64 and A/B/C slot-0 delta streams are not identical ({same}/199 equal)"
        );
        assert_ne!(
            instr_patch_key(&gen, 3, controlflow_patch_domain(0xABCD)),
            cfk,
            "CF patch key varies with the build domain"
        );
    }

    #[test]
    fn c1_2_debug_info_all_C_not_sufficient() {
        for seed in [0u64, 1, 305419896, 0x_DEAD_BEEF, u64::MAX] {
            assert_ne!(
                env_fingerprint_term(seed, TargetProfile::CliTest),
                probe_counter_term(seed),
                "env fingerprint must fold material beyond the predictable [C] debug.info term"
            );
        }
    }

    #[test]
    fn c1_2_behavioral_fingerprint_axes_each_contribute() {
        let seed = 305419896u64;
        let full = env_fingerprint_term(seed, TargetProfile::CliTest);
        let fold = |p: u32, x: u32| p.rotate_left(5) ^ x;
        let mut without_num = 0u32;
        without_num = fold(without_num, checksum(b"behavior_error_shape"));
        for (_, ex) in ENVFP_ERR {
            without_num = fold(without_num, checksum(ex));
        }
        without_num = fold(without_num, checksum(b"debug_info_s"));
        let cc = checksum(PROBE_EXPECTED);
        for _ in probe_set(seed) {
            without_num = fold(without_num, cc);
        }
        assert_ne!(
            full, without_num,
            "number-format axis must contribute to the fingerprint"
        );
        let mut without_err = 0u32;
        without_err = fold(without_err, checksum(b"number_format"));
        for (_, ex) in ENVFP_NUM {
            without_err = fold(without_err, checksum(ex));
        }
        without_err = fold(without_err, checksum(b"debug_info_s"));
        for _ in probe_set(seed) {
            without_err = fold(without_err, cc);
        }
        assert_ne!(
            full, without_err,
            "error-shape axis must contribute to the fingerprint"
        );
        assert!(ENVFP_NUM.iter().any(|(_, b)| *b == b"0.30000000000000004"));
        assert!(ENVFP_NUM.iter().any(|(_, b)| *b == b"nan"));
    }

    #[test]
    fn c1_2_h4_rsalt_changes_with_genkey() {
        let salt = derive_salt_for_test(305419896);
        let dg = 0x1357_9BDFu32;
        let g_new = gen_key(
            &salt,
            dg,
            &env_fingerprint_digest(305419896, TargetProfile::CliTest),
            &[],
        );
        let g_old = gen_key(&salt, dg, &[0u32; 8], &[probe_counter_term(305419896)]);
        assert_ne!(g_new, g_old, "F1 wide env-digest gen-key (and thus H4 RSALT) must differ from the old counter-folded key");
    }

    fn derive_salt_for_test(seed: u64) -> [u8; 12] {
        let mut s = [0u8; 12];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (seed >> (i % 8 * 8)) as u8 ^ (i as u8);
        }
        s
    }

    #[test]
    fn integrity_accumulator_is_identity_at_zero_and_poisons_when_nonzero() {
        let pkey = proto_key(&gen_key(&[1u8; 12], 0x1234, &[0u32; 8], &[]), 3, 0);
        let plain = b"a representative string constant".to_vec();
        let ct = stream_xor(&pkey, &[5, 0, 0], &plain);
        assert_eq!(
            stream_xor(&pkey, &[5, 0, 0], &ct),
            plain,
            "acc=0 must round-trip (happy-path identity)"
        );
        assert_ne!(
            stream_xor(&pkey, &[5, 7, 0], &ct),
            plain,
            "a nonzero accumulator must garble the decrypt"
        );
        assert_ne!(
            stream_xor(&pkey, &[5, 0xDEAD_BEEF, 0], &ct),
            plain,
            "any poison value cascades to garbage"
        );
    }

    #[test]
    fn rfc8439_block() {
        let key: [u32; 8] = std::array::from_fn(|i| {
            u32::from_le_bytes([
                (4 * i) as u8,
                (4 * i + 1) as u8,
                (4 * i + 2) as u8,
                (4 * i + 3) as u8,
            ])
        });
        let nonce = [0x0900_0000u32, 0x4a00_0000, 0x0000_0000];
        let out = block(&key, &nonce, 1);
        let mut bytes = [0u8; 64];
        for i in 0..16 {
            bytes[4 * i..4 * i + 4].copy_from_slice(&out[i].to_le_bytes());
        }
        let expected: [u8; 16] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4,
        ];
        assert_eq!(&bytes[0..16], &expected);
    }

    #[test]
    fn probe_set_always_has_print_is_deterministic_and_varies() {
        assert_eq!(probe_set(5), probe_set(5), "deterministic per seed");
        assert!(
            probe_set(5).contains(&"print"),
            "print is always probed (the keystone hook)"
        );
        let sets: std::collections::HashSet<Vec<&str>> = (0..32u64).map(probe_set).collect();
        assert!(sets.len() > 1, "the probe set must vary across seeds");
        let cc = checksum(PROBE_EXPECTED);
        let manual = probe_set(7).iter().fold(0u32, |p, _| p.rotate_left(5) ^ cc);
        assert_eq!(probe_counter_term(7), manual);
    }

    #[test]
    fn dt_trap_expected_values_are_integer_exact() {
        assert_eq!(DtTrap::Vec3Mag(3, 4, 0).expected(), 5);
        assert_eq!(DtTrap::Vec3Mag(0, 6, 8).expected(), 10);
        assert_eq!(DtTrap::Vec3Mag(5, 0, 12).expected(), 13);
        assert_eq!(DtTrap::Vec3Mag(8, 15, 0).expected(), 17);
        assert_eq!(DtTrap::Vec3Mag(9, 12, 20).expected(), 25);
        assert_eq!(DtTrap::Vec3Mag(2, 3, 6).expected(), 7);
        assert_eq!(DtTrap::CFrameSumX(1, 2, 3, 4, 5, 6).expected(), 5);
        assert_eq!(DtTrap::CFrameSumX(7, 0, 0, 3, 0, 0).expected(), 10);
        for &t in DT_POOL {
            if let DtTrap::Vec3Mag(x, y, z) = t {
                let s = x * x + y * y + z * z;
                let r = t.expected() as i32;
                assert_eq!(r * r, s, "{t:?} magnitude must be integer-exact");
            }
        }
        assert_eq!(dt_trap(7), dt_trap(7), "deterministic per seed");
    }

    #[test]
    fn path2d_trap_lengths_are_integer_exact() {
        assert_eq!(DtTrap::Path2DLen(&[(0, 0), (300, 400)]).expected(), 500);
        assert_eq!(DtTrap::Path2DLen(&[(0, 0), (600, 800)]).expected(), 1000);
        assert_eq!(DtTrap::Path2DLen(&[(0, 0), (500, 1200)]).expected(), 1300);
        assert_eq!(DtTrap::Path2DLen(&[(0, 0), (800, 1500)]).expected(), 1700);
        assert_eq!(DtTrap::Path2DLen(&[(0, 0), (900, 1200)]).expected(), 1500);
        assert_eq!(DtTrap::Path2DLen(&[(0, 0), (700, 2400)]).expected(), 2500);
        for &t in PATH2D_POOL {
            if let DtTrap::Path2DLen(pts) = t {
                let sq: i32 = pts
                    .windows(2)
                    .map(|w| (w[1].0 - w[0].0).pow(2) + (w[1].1 - w[0].1).pow(2))
                    .sum();
                let r = t.expected() as i32;
                assert_eq!(
                    r * r,
                    sq,
                    "{t:?} length must be integer-exact (single segment)"
                );
            } else {
                panic!("PATH2D_POOL must contain only Path2DLen entries");
            }
        }
        assert_eq!(path2d_trap(7), path2d_trap(7), "deterministic per seed");
        assert!(
            matches!(path2d_trap(123), DtTrap::Path2DLen(_)),
            "inner trap is Path2D"
        );
    }

    #[test]
    fn fold_order_is_a_seeded_permutation_of_all_three_terms() {
        use FoldTerm::*;
        for seed in 0..300u64 {
            let o = fold_order(seed);
            assert!(
                o.contains(&Probe) && o.contains(&Outer) && o.contains(&Inner),
                "all 3 terms present"
            );
        }
        assert_eq!(fold_order(42), fold_order(42), "deterministic per seed");
        let orders: std::collections::HashSet<_> = (0..50u64).map(fold_order).collect();
        assert!(orders.len() > 1, "fold order must vary across builds");
    }

    #[test]
    fn const_round_trips() {
        let gen = gen_key(&[7; 12], 0xdead_beef, &[0u32; 8], &[]);
        let pkey = proto_key(&gen, 3, 0);
        let c = Const::Str(b"hello\x00\xff".to_vec());
        let blob = encrypt_const(&pkey, 5, 0, 0, &c);
        let plain = stream_xor(&pkey, &[5, 0, 0], &blob);
        assert_eq!(keyed_tag(&pkey, 5, 0, &plain[8..]), plain[0..8]);
        assert_eq!(plain[8], 1);
        assert_eq!(&plain[9..], b"hello\x00\xff");
    }

    #[test]
    fn f1_no_single_u32_env_gate() {
        let ed = env_fingerprint_digest(7, TargetProfile::CliTest);
        assert_ne!(ed, [0u32; 8], "env digest must be non-trivial");
        assert!(
            ed.iter().any(|&w| w != ed[0]),
            "env digest words must not be identical"
        );
        let salt = [1u8; 12];
        let dg = 0xABCD_1234u32;
        let base = gen_key(&salt, dg, &ed, &[]);
        for i in 0..8 {
            let mut e2 = ed;
            e2[i] ^= 1;
            assert_ne!(
                gen_key(&salt, dg, &e2, &[]),
                base,
                "env-digest word {i} must affect the gen-key"
            );
        }
    }

    #[test]
    fn at2_cli_profile_skips_roblox_datatype_traps() {
        assert!(
            at2_trap_vals(TargetProfile::CliTest).is_empty(),
            "cli-test bakes NO Roblox traps"
        );

        for seed in [0u64, 7, 305419896] {
            let bare = {
                let mut vals = vec![checksum(b"number_format")];
                for (_, ex) in ENVFP_NUM {
                    vals.push(checksum(ex));
                }
                vals.push(checksum(b"behavior_error_shape"));
                for (_, ex) in ENVFP_ERR {
                    vals.push(checksum(ex));
                }
                vals.push(checksum(b"debug_info_s"));
                let cc = checksum(PROBE_EXPECTED);
                for _ in probe_set(seed) {
                    vals.push(cc);
                }
                vals
            };
            assert_eq!(
                env_vals(seed, TargetProfile::CliTest),
                bare,
                "cli-test env vals must be C1.2-only"
            );
        }
    }

    #[test]
    fn at2_trap_values_affect_wide_env_digest() {
        let s = 305419896u64;
        let cli = env_fingerprint_digest(s, TargetProfile::CliTest);
        for p in [
            TargetProfile::Executor,
            TargetProfile::Studio,
            TargetProfile::RobloxClient,
            TargetProfile::RobloxServer,
        ] {
            assert_ne!(
                env_fingerprint_digest(s, p),
                cli,
                "profile {p:?} must change the wide env digest"
            );
        }
    }

    #[test]
    fn at2_no_trap_only_counter_fold() {
        let s = 7u64;
        assert_ne!(
            env_fingerprint_digest(s, TargetProfile::Executor),
            env_fingerprint_digest(s, TargetProfile::CliTest),
            "AT2 traps must feed the wide 256-bit digest (key material), not only the counter"
        );
    }

    #[test]
    fn at2_wrong_trap_value_breaks_constant_decrypt() {
        let enc = Encoding::from_seed(0xA72);
        let proto = c1_proto();
        let cdg = proto_code_digest(&proto, &enc);
        let right = proto_key(
            &gen_key(
                &[2u8; 12],
                cdg,
                &env_fingerprint_digest(0xA72, TargetProfile::Executor),
                &[],
            ),
            0,
            5,
        );
        let wrong = proto_key(
            &gen_key(
                &[2u8; 12],
                cdg,
                &env_fingerprint_digest(0xA72, TargetProfile::CliTest),
                &[],
            ),
            0,
            5,
        );
        let blob = encrypt_const(&right, 0, 0, 5, &proto.consts[0]);
        let plain = stream_xor(&right, &[0, 0, 5], &blob);
        assert_eq!(
            keyed_tag(&right, 0, 5, &plain[8..]),
            plain[0..8],
            "right env key decrypts"
        );
        let bad = stream_xor(&wrong, &[0, 0, 5], &blob);
        assert_ne!(
            keyed_tag(&wrong, 0, 5, &bad[8..]),
            bad[0..8],
            "wrong trap value (wrong env) must fail the keyed tag"
        );
    }

    #[test]
    fn at2_executor_profile_does_not_fold_isserver() {
        let m = TargetProfile::Executor.runservice_methods();
        assert!(
            !m.iter().any(|(name, _)| *name == b"IsServer"),
            "executor must NOT fold IsServer"
        );
        assert!(TargetProfile::RobloxServer
            .runservice_methods()
            .iter()
            .any(|(n, e)| *n == b"IsServer" && *e == b"true"));
        assert!(TargetProfile::RobloxClient
            .runservice_methods()
            .iter()
            .any(|(n, e)| *n == b"IsServer" && *e == b"false"));
    }

    #[test]
    fn at2_executor_profile_folds_isstudio_false_isclient_true() {
        assert_eq!(
            TargetProfile::Executor.runservice_methods(),
            &[
                (b"IsStudio".as_slice(), b"false".as_slice()),
                (b"IsClient", b"true")
            ],
            "executor RunService coupling is exactly IsStudio=false + IsClient=true"
        );
    }

    #[test]
    fn at2_executor_probe_expected_values_match_macsploit() {
        let vals = at2_trap_vals(TargetProfile::Executor);
        assert_eq!(
            vals.len(),
            14,
            "executor folds 14 trap values (IsServer dropped, DataModel added)"
        );
        assert!(vals.contains(&checksum(b"Instance")) && vals.contains(&checksum(b"Players")));
        assert!(vals.contains(&checksum(b"true")) && vals.contains(&checksum(b"false")));
        assert!(
            vals.contains(&checksum(b"DataModel")),
            "Stats().Parent.ClassName (DataModel) folded"
        );
        for len in [500u32, 1300, 1000] {
            assert!(vals.contains(&len), "Path2D length {len} folded");
        }
    }

    #[test]
    fn at2_studio_profile_isstudio_expected() {
        let s = 1u64;
        assert_ne!(
            env_fingerprint_digest(s, TargetProfile::Studio),
            env_fingerprint_digest(s, TargetProfile::Executor),
            "studio (IsStudio=true) digest must differ from executor (IsStudio=false)"
        );
    }

    #[test]
    fn at2_path2d_getlength_exact() {
        for (pts, len) in PATH2D_TRAPS {
            let sum: f64 = pts
                .windows(2)
                .map(|w| {
                    let (dx, dy) = ((w[1].0 - w[0].0) as f64, (w[1].1 - w[0].1) as f64);
                    (dx * dx + dy * dy).sqrt()
                })
                .sum();
            assert_eq!(
                sum.round() as u32,
                *len,
                "Path2D trap {pts:?} length must be {len}"
            );
        }
        let lens: Vec<u32> = PATH2D_TRAPS.iter().map(|(_, l)| *l).collect();
        assert_eq!(lens, vec![500, 1300, 1000]);
    }

    #[test]
    fn at2_lockcurrentposition_not_required() {
        assert_eq!(
            PATH2D_TRAPS.len(),
            3,
            "trap pool is the three straight-segment GetLength traps"
        );
    }

    #[test]
    fn at2_typeof_players_check_noise_only_or_key_coupled() {
        let vals = at2_trap_vals(TargetProfile::Executor);
        assert!(
            vals.contains(&checksum(b"Instance")) && vals.contains(&checksum(b"Players")),
            "Players identity values are folded"
        );
    }

    #[test]
    fn at2_trap_value_folds_into_f1_env_digest() {
        let salt = [5u8; 12];
        let dg = 0x1357_9BDFu32;
        let base = env_fingerprint_digest(305419896, TargetProfile::CliTest);
        let key = gen_key(&salt, dg, &base, &[]);
        for i in 0..8 {
            let mut tampered = base;
            tampered[i] ^= 1;
            assert_ne!(
                gen_key(&salt, dg, &tampered, &[]),
                key,
                "env-trap word {i} must change the gen-key (fail closed)"
            );
        }
    }

    #[test]
    fn f1_no_unkeyed_fnv_oracle() {
        let body = b"\x01a representative constant body".to_vec();
        let pk_a = proto_key(&gen_key(&[1u8; 12], 5, &[0u32; 8], &[]), 0, 9);
        let pk_b = proto_key(&gen_key(&[2u8; 12], 6, &[0u32; 8], &[]), 0, 9);
        assert_ne!(
            keyed_tag(&pk_a, 3, 4, &body),
            keyed_tag(&pk_b, 3, 4, &body),
            "tag must depend on the key"
        );
        assert_ne!(
            &keyed_tag(&pk_a, 3, 4, &body)[0..4],
            &checksum(&body).to_le_bytes()[..],
            "the tag must not be the unkeyed FNV-32 of the body (no free oracle)"
        );
    }

    #[test]
    fn f1_keyed_tag_wrong_key_fails_closed() {
        let enc = Encoding::from_seed(0xF1);
        let proto = c1_proto();
        let cdg = proto_code_digest(&proto, &enc);
        let pkey = proto_key(
            &gen_key(
                &[3u8; 12],
                cdg,
                &env_fingerprint_digest(0xF1, TargetProfile::CliTest),
                &[],
            ),
            0,
            7,
        );
        let wrong = proto_key(
            &gen_key(
                &[3u8; 12],
                cdg,
                &env_fingerprint_digest(0xF2, TargetProfile::CliTest),
                &[],
            ),
            0,
            7,
        );
        let blob = encrypt_const(&pkey, 0, 0, 0, &proto.consts[0]);
        assert!(
            decrypt_passes(&pkey, 0, &blob),
            "the right key must pass the keyed tag"
        );
        assert!(
            !decrypt_passes(&wrong, 0, &blob),
            "a wrong (wide-env) key must fail the keyed tag, no plaintext"
        );
    }

    #[test]
    fn f1_keyed_tag_tamper_fails_closed() {
        let pkey = proto_key(&gen_key(&[4u8; 12], 0x99, &[0u32; 8], &[]), 0, 7);
        let blob = encrypt_const(&pkey, 0, 0, 0, &Const::Str(b"sensitive-constant".to_vec()));
        assert!(
            decrypt_passes(&pkey, 0, &blob),
            "untampered blob must verify"
        );
        let mut t_body = blob.clone();
        let last = t_body.len() - 1;
        t_body[last] ^= 1;
        assert!(
            !decrypt_passes(&pkey, 0, &t_body),
            "a flipped body byte must fail the keyed tag"
        );
        let mut t_tag = blob.clone();
        t_tag[0] ^= 1;
        assert!(
            !decrypt_passes(&pkey, 0, &t_tag),
            "a flipped tag byte must fail closed"
        );
    }

    #[test]
    fn f1_old_32bit_bruteforce_harness_fails() {
        let salt = [9u8; 12];
        let dg = 0x1234_5678u32;
        let ed = env_fingerprint_digest(7, TargetProfile::CliTest);
        assert_ne!(
            ed, [0u32; 8],
            "non-zero digest ⇒ block key != FIXED ⇒ old key-fixed brute space misses"
        );
        let real = gen_key(&salt, dg, &ed, &[]);
        for guess in [0u32, 1, dg, 0xDEAD_BEEF, u32::MAX, ed[0], ed[7]] {
            let old_style = gen_key(&salt, dg, &[0u32; 8], &[guess]);
            assert_ne!(
                old_style, real,
                "no single-u32 (counter-folded, key=FIXED) model reproduces the F1 gen-key"
            );
        }
    }

    fn read_zigzag(b: &[u8]) -> (i64, usize) {
        let mut u = 0u64;
        let mut shift = 0u32;
        let mut i = 0usize;
        loop {
            let x = b[i];
            u |= ((x & 0x7f) as u64) << shift;
            i += 1;
            if x < 0x80 {
                break;
            }
            shift += 7;
        }
        (((u >> 1) as i64) ^ -((u & 1) as i64), i)
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn dense_i53_rule_accepts_safe_integers_and_rejects_unsafe() {
        for (n, want) in [
            (0.0f64, 0i64),
            (1.0, 1),
            (-1.0, -1),
            (42.0, 42),
            (-42.0, -42),
            (255.0, 255),
            (256.0, 256),
            (65535.0, 65535),
            (4294967296.0, 4294967296),
            (4503599627370496.0, 4503599627370496),
            (-4503599627370496.0, -4503599627370496),
        ] {
            assert_eq!(is_dense_i53_number(n), Some(want), "{n} must encode dense");
        }
        for n in [
            f64::NAN,
            -f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.0,
            0.5,
            3.14,
            -0.25,
            1e18,
            9007199254740992.0,
            -9007199254740992.0,
            4503599627370497.0,
        ] {
            assert_eq!(is_dense_i53_number(n), None, "{n} must stay raw f64");
        }
    }

    #[test]
    fn push_zigzag_roundtrips_and_stays_compact() {
        for v in [
            0i64,
            1,
            -1,
            2,
            -2,
            63,
            64,
            127,
            128,
            -128,
            255,
            256,
            4294967296,
            -4294967296,
            4503599627370496,
            -4503599627370496,
        ] {
            let mut buf = Vec::new();
            push_zigzag(&mut buf, v);
            let (got, n) = read_zigzag(&buf);
            assert_eq!(got, v, "zigzag roundtrip {v}");
            assert_eq!(
                n,
                buf.len(),
                "reader consumes exactly what the writer produced for {v}"
            );
        }
        for v in [0i64, 1, -1] {
            let mut b = Vec::new();
            push_zigzag(&mut b, v);
            assert_eq!(b.len(), 1, "small int {v} is one byte");
        }
        let mut bmax = Vec::new();
        push_zigzag(&mut bmax, 4503599627370496);
        assert!(
            bmax.len() <= 8,
            "2^52 varint never exceeds the 8 raw f64 bytes (len {})",
            bmax.len()
        );
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn encrypt_const_dense_is_shorter_seals_and_decodes() {
        let pkey = [0x11u32, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let dense = encrypt_const(&pkey, 0, 0, 0, &Const::Number(7.0));
        let raw = encrypt_const(&pkey, 0, 0, 0, &Const::Number(3.14159));
        assert_eq!(dense.len(), 10, "8 tag + 1 type + 1 varint");
        assert_eq!(raw.len(), 17, "8 tag + 1 type + 8 f64");
        assert!(dense.len() < raw.len());

        let plain = stream_xor(&pkey, &[0, 0, 0], &dense);
        assert_eq!(
            keyed_tag(&pkey, 0, 0, &plain[8..]),
            plain[0..8],
            "dense const tag verifies"
        );
        assert_eq!(plain[8], CBODY_NUMBER_DENSE);
        assert_eq!(read_zigzag(&plain[9..]).0 as f64, 7.0);

        let rplain = stream_xor(&pkey, &[0, 0, 0], &raw);
        assert_eq!(rplain[8], CBODY_NUMBER);
        assert_eq!(
            f64::from_le_bytes(rplain[9..17].try_into().unwrap()),
            3.14159
        );
    }

    #[test]
    fn dense_const_body_tamper_fails_closed() {
        let pkey = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let mut blob = encrypt_const(&pkey, 0, 0, 0, &Const::Number(1234.0));
        blob[9] ^= 0x01;
        let plain = stream_xor(&pkey, &[0, 0, 0], &blob);
        assert_ne!(
            keyed_tag(&pkey, 0, 0, &plain[8..]),
            plain[0..8],
            "tampering the dense body must fail the keyed tag"
        );
    }

    #[test]
    fn negative_zero_and_specials_round_trip_as_raw_bytes() {
        let pkey = [9u32, 8, 7, 6, 5, 4, 3, 2];
        for n in [-0.0f64, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.5] {
            let blob = encrypt_const(&pkey, 0, 0, 0, &Const::Number(n));
            let plain = stream_xor(&pkey, &[0, 0, 0], &blob);
            assert_eq!(plain[8], CBODY_NUMBER, "{n} must serialize as raw f64");
            let got = f64::from_le_bytes(plain[9..17].try_into().unwrap());
            assert_eq!(
                got.to_bits(),
                n.to_bits(),
                "{n} raw bytes preserved exactly (bit pattern)"
            );
        }
    }
}
