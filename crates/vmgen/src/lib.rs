use std::collections::HashSet;

use bytecode::encoding::Encoding;
use bytecode::format::FormatConfig;
use bytecode::opcode::Opcode;

mod bitalias;
mod cold_decoder;
mod constdiv;
mod dispatch;
pub mod gensuper;
mod heavy_surface;
mod inline_access;
mod kepoch;
mod kget;
mod litgen;
mod minify;
mod mixer;
mod model;
pub mod notices;
mod numlit;
mod packer;
mod poly;
mod precheck;
mod rng;
mod route;
pub mod shell_family;
pub mod shellprobe;
mod topology;
mod varint;
pub mod word_carrier;
pub use bytecode::kepoch::KepochMode;
pub use heavy_surface::SurfaceVolume;
pub use minify::{minify, minify_lph, minify_native};
pub use poly::PolyStream;

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
pub enum FrameConstReuseMode {
    #[default]
    Off,
    Control,
    Strings,
    Numbers,
    All,
}

impl FrameConstReuseMode {
    pub fn enabled(self) -> bool {
        self != Self::Off
    }

    fn literal(self) -> u8 {
        match self {
            Self::Off | Self::Control => 0,
            Self::Strings => 1,
            Self::Numbers => 2,
            Self::All => 3,
        }
    }
}

pub fn kepoch_mode(poly: PolyStream) -> KepochMode {
    match poly {
        PolyStream::Off => KepochMode::Off,
        PolyStream::Conservative => KepochMode::Conservative,
        PolyStream::Aggressive => KepochMode::Aggressive,
    }
}

const TEMPLATE: &str = include_str!("../../../runtime/vm_template.luau");

const NATIVE_SENTINEL: &str = "@@BASIL_NATIVE@@";

fn native_sentinel_literal() -> String {
    format!("{NATIVE_SENTINEL:?}")
}

#[allow(clippy::too_many_arguments)]
pub fn generate(
    enc: &Encoding,
    payload: &[u8],
    seed: u64,
    genkey: &[u32; 8],
    used: &HashSet<Opcode>,
    compress: bool,
    native_count: usize,
    blob_count: usize,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    intrinsic_ids: &HashSet<u32>,
    profile: bytecode::crypt::TargetProfile,
    canary: bool,
    poly: PolyStream,
    runtime_profile_markers: bool,
) -> String {
    generate_frame_const_reuse(
        enc,
        payload,
        seed,
        genkey,
        used,
        compress,
        native_count,
        blob_count,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        intrinsic_ids,
        profile,
        canary,
        poly,
        runtime_profile_markers,
        FrameConstReuseMode::Off,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn generate_frame_const_reuse(
    enc: &Encoding,
    payload: &[u8],
    seed: u64,
    genkey: &[u32; 8],
    used: &HashSet<Opcode>,
    compress: bool,
    native_count: usize,
    blob_count: usize,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    intrinsic_ids: &HashSet<u32>,
    profile: bytecode::crypt::TargetProfile,
    canary: bool,
    poly: PolyStream,
    runtime_profile_markers: bool,
    frame_const_reuse: FrameConstReuseMode,
) -> String {
    generate_frame_const_reuse_impl(
        enc,
        payload,
        seed,
        genkey,
        used,
        compress,
        native_count,
        blob_count,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        intrinsic_ids,
        profile,
        canary,
        poly,
        runtime_profile_markers,
        frame_const_reuse,
        false,
        false,
        &[],
        &FormatConfig::layout(
            false,
            bytecode::kepoch::KepochMode::Off,
            false,
            false,
            false,
            false,
            false,
        ),
        &bytecode::gensuper::GenCatalogue::default(),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn ty_prefix(
    region: &'static str,
    tink: &mut Option<surface::types::TypeInk>,
    want: usize,
    content: &str,
) -> String {
    match tink {
        Some(t) => format!("{}{content}", t.aliases(region, want)),
        None => content.to_string(),
    }
}

pub fn generate_shell_probe(
    enc: &Encoding,
    payload: &[u8],
    seed: u64,
    genkey: &[u32; 8],
    used: &HashSet<Opcode>,
    compress: bool,
    native_count: usize,
    blob_count: usize,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    intrinsic_ids: &HashSet<u32>,
    profile: bytecode::crypt::TargetProfile,
    canary: bool,
    poly: PolyStream,
    runtime_profile_markers: bool,
    frame_const_reuse: FrameConstReuseMode,
    shell_probe: bool,
    underscore_hex: bool,
    precheck_expected: &[Vec<i64>],
    fmt: &FormatConfig,
    gen_cat: &bytecode::gensuper::GenCatalogue,
    surface_plan: Option<&surface::SurfacePlan>,
) -> String {
    generate_frame_const_reuse_impl(
        enc,
        payload,
        seed,
        genkey,
        used,
        compress,
        native_count,
        blob_count,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        intrinsic_ids,
        profile,
        canary,
        poly,
        runtime_profile_markers,
        frame_const_reuse,
        shell_probe,
        underscore_hex,
        precheck_expected,
        fmt,
        gen_cat,
        surface_plan,
    )
}

#[allow(clippy::too_many_arguments)]
fn const_section_reader(seed: u64, sem_family: bool) -> String {
    if bytecode::encoder::const_sec_family(seed, sem_family) == 1 {
        "local consts = proto[2] local ln = {} for i = 1, n do ln[i] = vu() end for i = 1, n do consts[i] = rawbytes(ln[i]) end".to_string()
    } else {
        "local consts = proto[2] for i = 1, n do consts[i] = rawbytes(vu()) end".to_string()
    }
}

fn generate_frame_const_reuse_impl(
    enc: &Encoding,
    payload: &[u8],
    seed: u64,
    genkey: &[u32; 8],
    used: &HashSet<Opcode>,
    compress: bool,
    native_count: usize,
    blob_count: usize,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    intrinsic_ids: &HashSet<u32>,
    profile: bytecode::crypt::TargetProfile,
    canary: bool,
    poly: PolyStream,
    runtime_profile_markers: bool,
    frame_const_reuse: FrameConstReuseMode,
    shell_probe: bool,
    underscore_hex: bool,
    precheck_expected: &[Vec<i64>],
    fmt: &FormatConfig,
    gen_cat: &bytecode::gensuper::GenCatalogue,
    surface_plan: Option<&surface::SurfacePlan>,
) -> String {
    let framing = fmt.framing;
    let sem_family = fmt.sem_family;
    let instr_family_on = fmt.instr_family;
    let state_family_on = fmt.state_family;
    let uh = underscore_hex;
    let _sp = shellprobe::emit(seed, shell_probe);
    let _pc = precheck::emit(precheck_expected, seed);

    let rsalt = route::derive_rsalt(genkey);
    let kmode = kepoch_mode(poly);
    let (fop, fa, fb, fc, fops) = ("[KOP]", "[KA]", "[KB]", "[KC]", "[KOPS]");
    let ki = kepoch::decode_init(seed, kmode);
    let mut drng = crate::rng::Rng::new(seed ^ 0x_4452_4F52_4732_36);
    let dr_scatter = drng.below(2);
    let dr_list = drng.below(2);
    let reads = if dr_scatter == 0 {
        let slot = |p: usize| {
            format!(
            "if L{p} == 0 then oa = vsm(proto[5], i, M{p}) elseif L{p} == 1 and LIVEB[op] then ob = vsm(proto[5], i, M{p}) elseif L{p} == 2 and LIVEC[op] then oc = vsm(proto[5], i, M{p}) end\n\t\t\t\t\t\t"
        )
        };
        format!("{}{}{}", slot(0), slot(1), slot(2))
    } else {
        let rd = |p: usize| {
            format!(
            "local v{p} = 0\n\t\t\t\t\t\tif L{p} == 0 or (L{p} == 1 and LIVEB[op]) or (L{p} == 2 and LIVEC[op]) then v{p} = vsm(proto[5], i, M{p}) end\n\t\t\t\t\t\t"
        )
        };
        let sc = |p: usize| {
            format!(
            "if L{p} == 0 then oa = v{p} elseif L{p} == 1 then ob = v{p} else oc = v{p} end\n\t\t\t\t\t\t"
        )
        };
        format!("{}{}{}{}{}{}", rd(0), rd(1), rd(2), sc(0), sc(1), sc(2))
    };
    let super_read = if dr_list == 0 {
        "if GM == 0 then for j = 1, m do so[j] = vsm(proto[5], i, j - 1) end else for j = 1, m do so[m - j + 1] = vsm(proto[5], i, j - 1) end end"
    } else {
        "for j = 1, m do local d = vsm(proto[5], i, j - 1) if GM == 0 then so[j] = d else so[m - j + 1] = d end end"
    };
    let decode_core = format!(
        "local m = SUPER[op]\n\t\t\t\t\tif m then\n\t\t\t\t\t\tlocal so = {{}}\n\t\t\t\t\t\t{super_read}\n\t\t\t\t\t\tcode[i] = {{ {fop} = op, {fops} = so }}\n\t\t\t\t\telse\n\t\t\t\t\t\tlocal oa, ob, oc = 0, 0, 0\n\t\t\t\t\t\t{reads}code[i] = {{ {fop} = op, {fa} = oa, {fb} = ob, {fc} = oc }}{ki}\n\t\t\t\t\tend"
    );

    let decode = if used.contains(&Opcode::GenSuper) {
        let gp = enc.phys(Opcode::GenSuper);
        format!(
            "if op == {gp} then\n\t\t\t\t\t\tlocal gslot = vsm(proto[5], i, 0)\n\t\t\t\t\t\tlocal gnl = vsm(proto[5], i, 1)\n\t\t\t\t\t\tlocal gnc = vsm(proto[5], i, 2)\n\t\t\t\t\t\tlocal glen = vsm(proto[5], i, 3)\n\t\t\t\t\t\tlocal so = {{}}\n\t\t\t\t\t\tfor j = 1, glen do so[j] = vsm(proto[5], i, j + 3) end\n\t\t\t\t\t\tcode[i] = {{ {fop} = op, {fa} = gslot, {fb} = gnl, {fc} = gnc, {fops} = so }}\n\t\t\t\t\telse\n\t\t\t\t\t{decode_core}\n\t\t\t\t\tend"
        )
    } else {
        decode_core
    };
    let used_super: Vec<(u8, usize)> = bytecode::superop::CATALOGUE
        .iter()
        .filter(|(sop, _)| used.contains(sop))
        .map(|(sop, subs)| (enc.phys(*sop), 3 * subs.len()))
        .collect();
    let (mut lb, mut lc): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
    for (op, _) in bytecode::opcode::ALL {
        if !used.contains(op) || bytecode::superop::is_super(*op) {
            continue;
        }
        let ser = bytecode::opcode::operand_serialized(*op);
        if ser[1] {
            lb.push(enc.phys(*op));
        }
        if ser[2] {
            lc.push(enc.phys(*op));
        }
    }
    let mut ink = surface_plan.and_then(|p| surface::meme::MemeInk::new(p, 4));
    if let Some(k) = ink.as_mut() {
        k.expect_sites("OpcodeMeta", used_super.len() * 2 + lb.len() + lc.len());
    }
    let mut tink = surface_plan.and_then(|p| {
        p.types
            .is_on()
            .then(|| surface::types::TypeInk::new(p.seed))
    });
    let pgsz_inner = bytecode::crypt::PAGE_SIZE.to_string();
    let pgsz_expr = ink
        .as_mut()
        .and_then(|k| k.wrap("Paging", &pgsz_inner))
        .unwrap_or(pgsz_inner);
    let super_table = {
        if surface {
            let mut srng = crate::rng::Rng::new(seed ^ 0x_5350_5552_4341_4D);
            let mut e = used_super.clone();
            srng.shuffle(&mut e);
            let mut lines: Vec<String> = Vec::with_capacity(e.len());
            for &(c, n) in &e {
                let ki = litgen::num_lit(c, &mut srng);
                let key = ink
                    .as_mut()
                    .and_then(|k| k.wrap("OpcodeMeta", &ki))
                    .unwrap_or(ki);
                let vi = litgen::num_lit(n as u8, &mut srng);
                let val = ink
                    .as_mut()
                    .and_then(|k| k.wrap("OpcodeMeta", &vi))
                    .unwrap_or(vi);
                lines.push(format!("SUPER[{key}] = {val}"));
            }
            format!("local SUPER = {{}}\n{}", lines.join("\n"))
        } else {
            let mut entries: Vec<String> = Vec::with_capacity(used_super.len());
            for &(c, n) in &used_super {
                let ki = c.to_string();
                let key = ink
                    .as_mut()
                    .and_then(|k| k.wrap("OpcodeMeta", &ki))
                    .unwrap_or(ki);
                let vi = n.to_string();
                let val = ink
                    .as_mut()
                    .and_then(|k| k.wrap("OpcodeMeta", &vi))
                    .unwrap_or(vi);
                entries.push(format!("[{key}] = {val}"));
            }
            format!("local SUPER = {{ {} }}", entries.join(", "))
        }
    };
    let arity_tables = {
        if surface {
            let mut srng = crate::rng::Rng::new(seed ^ 0x_4152_4954_594C_4956);
            srng.shuffle(&mut lb);
            srng.shuffle(&mut lc);
            let emit = |t: &[u8],
                        name: &str,
                        srng: &mut crate::rng::Rng,
                        ink: &mut Option<surface::meme::MemeInk>|
             -> String {
                let mut out: Vec<String> = Vec::with_capacity(t.len());
                for &c in t {
                    let ki = litgen::num_lit(c, srng);
                    let key = ink
                        .as_mut()
                        .and_then(|k| k.wrap("OpcodeMeta", &ki))
                        .unwrap_or(ki);
                    out.push(format!("{name}[{key}] = true"));
                }
                out.join("\n")
            };
            let lbs = emit(&lb, "LIVEB", &mut srng, &mut ink);
            let lcs = emit(&lc, "LIVEC", &mut srng, &mut ink);
            format!("local LIVEB = {{}}\nlocal LIVEC = {{}}\n{lbs}\n{lcs}")
        } else {
            let emit = |t: &[u8], ink: &mut Option<surface::meme::MemeInk>| -> String {
                let mut out: Vec<String> = Vec::with_capacity(t.len());
                for &c in t {
                    let ki = c.to_string();
                    let key = ink
                        .as_mut()
                        .and_then(|k| k.wrap("OpcodeMeta", &ki))
                        .unwrap_or(ki);
                    out.push(format!("[{key}] = true"));
                }
                out.join(", ")
            };
            let lbs = emit(&lb, &mut ink);
            let lcs = emit(&lc, &mut ink);
            format!("local LIVEB = {{ {lbs} }}\nlocal LIVEC = {{ {lcs} }}")
        }
    };
    let super_table = format!("{super_table}\n{arity_tables}");
    let decompress_decl = if compress { DECOMPRESS_LUAU } else { "" };
    let payload_bytes = if compress {
        bytecode::lzw::compress(payload)
    } else {
        payload.to_vec()
    };
    let payload_wrap: (&str, &str) = if compress { ("lzwdec(", ")") } else { ("", "") };
    let rgcontainer_decl = String::new();
    let vm_traps = bytecode::crypt::vm_traps_active();
    let tp = bytecode::crypt::trap_params(seed);
    let traphelpers_decl = if vm_traps {
        trap_helpers(&tp)
    } else {
        String::new()
    };
    let trapscexp_decl = if vm_traps {
        "if isRoot then\n\t\t\t\t\tlocal rem = sectionEnd - pos\n\t\t\t\t\tif rem == 4 * np then\n\t\t\t\t\t\tlocal cx = {}\n\t\t\t\t\t\tfor pi = 1, np do\n\t\t\t\t\t\t\tcx[pi] = u32()\n\t\t\t\t\t\tend\n\t\t\t\t\t\tproto[28] = cx\n\t\t\t\t\telseif rem ~= 0 then\n\t\t\t\t\t\tdead = true\n\t\t\t\t\t\treturn\n\t\t\t\t\tend\n\t\t\t\tend".to_string()
    } else {
        String::new()
    };
    let trapspage_decl = if vm_traps {
        "local ce = proto[28]\n\t\tif ce then\n\t\t\tlocal acc = proto[29]\n\t\t\tif acc == nil then\n\t\t\t\tacc = _tseed(proto[5])\n\t\t\tend\n\t\t\tacc = _tfold(acc, proto[15][K], K)\n\t\t\tproto[29] = acc\n\t\t\tif acc ~= ce[K] then\n\t\t\t\tdead = true\n\t\t\t\treturn\n\t\t\tend\n\t\tend".to_string()
    } else {
        String::new()
    };
    let trapsframe_decl = if vm_traps {
        "if _tv[1] ~= _tcan(proto[5]) then\n\t\t\t\t\tdead = true\n\t\t\t\t\treturn\n\t\t\t\tend"
            .to_string()
    } else {
        String::new()
    };
    let (surface_preamble, surface_anchors, payload_decl) = emit_payload_decl(
        &payload_bytes,
        payload_wrap,
        seed,
        heavy != SurfaceVolume::Off,
        surface_plan,
        &mut ink,
    );
    let b85dec_s = if blob_count > 0 {
        b85dec_decl(seed)
    } else {
        String::new()
    };
    let ds_varint = varint::Family::for_seed(seed, 0x_4445_5300);
    let varint_defs = ds_varint.deserialize_defs();
    let skipv_s = ds_varint.skipv_def();
    let dr_vsm = varint::Family::for_seed(seed, 0x_4452_5601).decoderange_vsm();
    let structkey_s = varint::structkey_def(seed);
    let mixer_fam = mixer::Family::for_seed(seed, 0x_4F50_4D4B);
    let opmask_s = mixer_fam.opmask_def();
    let opmask2_s = mixer_fam.opmask2_def();
    let streamxor_s = mixer::streamxor_def(seed);
    let native_decl = if native_count > 0 {
        format!("local NATIVE = {}", native_sentinel_literal())
    } else {
        String::new()
    };
    let encfunc_decl = if blob_count > 0 {
        encfunc_machinery(seed, kmode != KepochMode::Off, fmt)
    } else {
        String::new()
    };
    let intrinsic_decl = intrinsic_catalog(seed, intrinsic_ids, heavy != SurfaceVolume::Off);
    let (early_decls, label_decls, route_decls, dispatch_body) = dispatch::generate_profiled(
        enc,
        seed,
        rsalt,
        used,
        hard_dispatch,
        surface,
        kmode,
        runtime_profile_markers,
        uh,
        gen_cat,
    );
    let dispatch_body = dispatch_body
        .replace("inst.ops", "inst[KOPS]")
        .replace("inst.b", "inst[KB]")
        .replace("inst.c", "inst[KC]");
    let inst_head = if runtime_profile_markers {
        "local op = inst[KOP]\nlocal a = inst[KA]\nPROF_N = PROF_N + 1\nPROF_OP[op] = (PROF_OP[op] or 0) + 1\nPROF_CD = PROF_CD - 1\nif PROF_CD == 0 then _profsnap(\"snap\") PROF_CD = PROF_SNAP end".to_string()
    } else {
        "local op = inst[KOP]\nlocal a = inst[KA]".to_string()
    };
    let super_count = bytecode::superop::CATALOGUE
        .iter()
        .filter(|(s, _)| used.contains(s))
        .count() as u32;
    let meta = [used.len() as u32, super_count, used.len() as u32];
    let [hv_early, hv_decode, hv_route, hv_helper, hv_post] =
        heavy_surface::chunks(seed, heavy, &meta);

    let flags = (compress as u64)
        | ((hard_dispatch as u64) << 1)
        | ((surface as u64) << 2)
        | ((anti_envlog as u64) << 3)
        | ((heavy as u64) << 5);
    let fp = build_fingerprint(payload, seed, profile, flags);
    let mut trng = crate::rng::Rng::new(fp ^ 0x_5347_3154_4D50_4C00);
    let cc = [
        hide_u32(0x61707865, &mut trng, uh),
        hide_u32(0x3320646e, &mut trng, uh),
        hide_u32(0x79622d32, &mut trng, uh),
        hide_u32(0x6b206574, &mut trng, uh),
    ];
    let digest_i = hide_u32(0x9E3779B9, &mut trng, uh);
    let digest_c = ink
        .as_mut()
        .and_then(|k| k.wrap("HashSetup", &digest_i))
        .unwrap_or(digest_i);
    let rsalt_i = hide_u32(2654435769, &mut trng, uh);
    let rsalt_c = ink
        .as_mut()
        .and_then(|k| k.wrap("HashSetup", &rsalt_i))
        .unwrap_or(rsalt_i);
    let checksum_i = hide_u32(0x811C9DC5, &mut trng, uh);
    let checksum_c = ink
        .as_mut()
        .and_then(|k| k.wrap("HashSetup", &checksum_i))
        .unwrap_or(checksum_i);
    let mk_inner = plain_u32(bytecode::crypt::opmask_key(seed), &mut trng, uh);
    let mk_expr = ink
        .as_mut()
        .and_then(|k| k.wrap("MaskSetup", &mk_inner))
        .unwrap_or(mk_inner);
    let mapkey_inner = plain_u32(bytecode::crypt::mapkey(seed), &mut trng, uh);
    let mapkey_expr = ink
        .as_mut()
        .and_then(|k| k.wrap("MaskSetup", &mapkey_inner))
        .unwrap_or(mapkey_inner);
    let actdom_i = hide_u32(bytecode::crypt::ACT_DOMAIN, &mut trng, uh);
    let actdom_expr = ink
        .as_mut()
        .and_then(|k| k.wrap("Activation", &actdom_i))
        .unwrap_or(actdom_i);
    let actrootdom_i = hide_u32(bytecode::crypt::ACT_ROOT_DOMAIN, &mut trng, uh);
    let actrootdom_expr = ink
        .as_mut()
        .and_then(|k| k.wrap("Activation", &actrootdom_i))
        .unwrap_or(actrootdom_i);
    let (lc1_decl, lc1_fold) = lc1_canary(seed, fp, canary, uh);
    let d1 = used.contains(&bytecode::opcode::Opcode::BStateStep);
    let state_b = d1 && bytecode::encoder::state_family(seed, state_family_on) == 1;
    let (kget_defs, kget_route_list) = kget::generate(seed, d1, state_b);
    let (poly_table, poly_stmt) = poly::emit(enc, seed, used, poly, surface);
    let closure_hoisted = if frame_const_reuse.enabled() {
        format!("{CLOSURE_HOISTED}, kx, fcm")
    } else {
        CLOSURE_HOISTED.to_string()
    };
    let frame_head = "return function(...)";
    let frame_tail = "";
    let (gsskip_pre, gsskip_post) = if used.contains(&Opcode::GenSuper) {
        let gp = enc.phys(Opcode::GenSuper);
        (
            format!("if op == {gp} then skipv() skipv() skipv() local _gl = vsm(proto[5], i, 3) for _ = 1, _gl do skipv() end else "),
            " end".to_string(),
        )
    } else {
        (String::new(), String::new())
    };
    let accessors = "local function rg(t, i)\n\treturn t[i]\nend\n\nlocal function rs(t, i, v)\n\tt[i] = v\nend\n";
    let template: &str = if inline_access::enabled() {
        Box::leak(TEMPLATE.replace(accessors, "").into_boxed_str())
    } else {
        TEMPLATE
    };
    let mut __vm = template
        .replace("--[[GSSKIP_PRE]]", &gsskip_pre)
        .replace("--[[GSSKIP_POST]]", &gsskip_post)
        .replace("--[[VMFUNCHEAD]]", "return function(proto, upvals)")
        .replace("local function streamXor(key, nonce, data)", PRIVATE_BYTETAB)
        .replace("out[ki] = char(R % 256, (R // 256) % 256, (R // 65536) % 256, R // 16777216)", PRIVATE_WORD_CHUNK)
        .replace("out[ki] = char(bxor(byte(data, oi), band(rshift(word, b * 8), 0xFF)))", PRIVATE_TAIL_BYTE)
        .replace("\treturn concat(out)\nend", PRIVATE_REDUCE)
        .replace("--[[VMFRAMEHEAD]]", frame_head)
        .replace("\t--[[VMFRAMETAIL]]\n", frame_tail)
        .replace("--[[OPMASKKEY]]", &format!("local MK = {mk_expr}"))
        .replace("--[[MAPKEY]]", &format!("local MAPKEY = {mapkey_expr}"))
        .replace("--[[ACTDOMS]]", &ty_prefix("ActivationTypes", &mut tink, 3, &format!("local ACTDOM, ACTROOTDOM = {actdom_expr}, {actrootdom_expr}")))
        .replace("--[[PAGESIZE]]", &format!("local PGSZ = {pgsz_expr}"))
        .replace("--[[B85DEC]]", &b85dec_s)
        .replace("--[[VARINTS]]", &varint_defs)
        .replace("--[[SKIPV]]", &skipv_s)
        .replace("--[[DR_VSM]]", &dr_vsm)
        .replace("--[[STRUCTKEY]]", &ty_prefix("StructTypes", &mut tink, 3, &structkey_s))
        .replace("--[[OPMASK]]", &opmask_s)
        .replace("--[[OPMASK2]]", &opmask2_s)
        .replace("--[[STREAMXOR]]", &streamxor_s)
        .replace("--[[PDG]]", &pdg_helper(fop, fa, fb, fc, fops, fp, uh))
        .replace("--[[VPG]]", &vpg_helper(fop, fa, fb, fc, fops, fp, uh))
        .replace("--[[KSITE]]", &ksite_helper(fop, fb, fc, fops, used, enc, fp, uh))
        .replace("--[[KGETDEFS]]", &ty_prefix("KeyGetTypes", &mut tink, 3, &kget_defs))
        .replace("--[[KGETROUTE]]", &kget_route_list)
        .replace("--[[D1KREAD]]", if d1 { "proto[27] = vu()" } else { "" })
        .replace("--[[CONSTSEC]]", &const_section_reader(seed, sem_family))
        .replace("--[[ISHARD]]", &ishard_decl(enc, used, seed, fp, uh, instr_family_on))
        .replace("--[[OPROUTE]]", &ty_prefix("RouteTypes", &mut tink, 3, &route::RouteScheme::new(seed, rsalt).helpers()))
        .replace("--[[UVACCESS]]", &uv_access(seed))
        .replace("return makeClosure(mainProto, {})()", &root_entry(seed))
        .replace("--[[CLOSURE_SETUP]]", &format!("local {closure_hoisted}\n\t\tlocal ready = false"))
        .replace("--[[FIRSTCALL]]", &format!("if not ready then\n\t\t\tif proto[16] then\n{}\n\t\t\telse\n\t\t\tdecodeProto(proto)\n{}\n\t\t\tend\n\t\t\tready = true\n\t\tend", closure_setup_paged(seed, frame_const_reuse.enabled()), closure_setup(seed, frame_const_reuse.enabled())))
        .replace("--[[FRAME_INIT]]", &{
            let mut fi = frame_init(seed, d1, state_b);
            if used.contains(&bytecode::opcode::Opcode::FlatStateEq) {


                fi.push_str("\n\t\t\tlocal fbm = {}");
            }
            if used.contains(&bytecode::opcode::Opcode::MApplyReset) || used.contains(&bytecode::opcode::Opcode::MApplyFold) {
                fi.push_str("\n\t\t\tlocal sel = 0");
            }
            if frame_const_reuse.enabled() {
                fi.push_str("\n");
                fi.push_str(&frame_const_reuse_frame(runtime_profile_markers));
            }
            if vm_traps {
                fi.push_str("\n\t\t\tlocal _tv = { _tcan(proto[5]) }");
            }
            fi
        })
        .replace("--[[TRAPHELPERS]]", &traphelpers_decl)
        .replace("--[[TRAPSCEXP]]", &trapscexp_decl)
        .replace("--[[TRAPSPAGE]]", &trapspage_decl)
        .replace("--[[TRAPSFRAME]]", &trapsframe_decl)
        .replace("--[[ICAT]]", &intrinsic_decl)
        .replace("--[[BITALIAS]]", &{
            let mut br = crate::rng::Rng::new(seed ^ 0x_4249_5441_4C49_4153);
            let mut pairs = [("band", "band"), ("bxor", "bxor"), ("lrotate", "lrotate"), ("rshift", "rshift"), ("lshift", "lshift"), ("bor", "bor")];
            br.shuffle(&mut pairs);
            bitalias::emit(&mut br, &pairs)
        })
        .replace("--[[ACTVM]]", bytecode::actvm::ACT_RUNTIME_LUAU)
        .replace("--[[CRYPTO]]", &ty_prefix("CryptoTypes", &mut tink, 3, &crypto_decls(fp, uh)))
        .replace(
            "local x0, x1, x2, x3 = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574",
            &format!("local x0, x1, x2, x3 = {}, {}, {}, {}", cc[0], cc[1], cc[2], cc[3]),
        )
        .replace("local digest = 0x9E3779B9", &format!("local digest = {digest_c}"))
        .replace("lrotate(genkey[7], 19), 2654435769)", &format!("lrotate(genkey[7], 19), {rsalt_c})"))
        .replace("local h = 0x811C9DC5", &format!("local h = {checksum_c}"))
        .replace("--[[STRINGS]]", &obscured_strings(seed, heavy != SurfaceVolume::Off))
        .replace("--[[DECOMPRESS]]", decompress_decl)
        .replace("--[[HEAVY_EARLY]]", &hv_early)
        .replace("--[[INSTKEYS]]", &early_decls)
        .replace("--[[DISPATCHLABELS]]", &label_decls)
        .replace("--[[HEAVY_DECODE]]", &hv_decode)
        .replace("--[[ROUTETABLE]]", &route_decls)
        .replace("--[[HEAVY_ROUTE]]", &hv_route)
        .replace("--[[SUPER]]", &ty_prefix("OpcodeTypes", &mut tink, 3, &super_table))
        .replace("--[[POLYTABLE]]", &poly_table)
        .replace("--[[KEPOCHDEFS]]", &kepoch::defs(seed, kmode))
        .replace("--[[HEAVY_HELPER]]", &hv_helper)
        .replace("--[[NATIVE]]", &ty_prefix("NativeTypes", &mut tink, 3, &native_decl))
        .replace("--[[ENCFUNC]]", &ty_prefix("EncTypes", &mut tink, 3, &encfunc_decl))
        .replace("--[[ENVPROBE]]", &env_probe(seed, profile, fp, uh, &mut ink))
        .replace("--[[LC1CANARY]]", &lc1_decl)
        .replace("--[[PROBEFOLD]]", &probe_fold(seed, anti_envlog))
        .replace("--[[SHELLPROBEDECL]]\n", &if _sp.decl.is_empty() { String::new() } else { format!("{}\n", _sp.decl) })
        .replace("\t--[[SHELLPROBEFOLD]]\n", &if _sp.fold.is_empty() { String::new() } else { format!("\t{}\n", _sp.fold) })
        .replace("--[[SHELLPROBESET]]\n", &if _sp.set.is_empty() { String::new() } else { format!("{}\n", _sp.set) })
        .replace("--[[SHELLPROBESINK]]\n", &if _sp.sink.is_empty() { String::new() } else { format!("{}\n", _sp.sink) })
        .replace("--[[PRECHECKDECL]]\n", &if _pc.decl.is_empty() { String::new() } else { format!("{}\n", _pc.decl) })
        .replace("\t--[[PRECHECKFOLD]]\n", &if _pc.fold.is_empty() { String::new() } else { format!("\t{}\n", _pc.fold) })
        .replace("--[[PRECHECKTABLE]]\n", &if _pc.table.is_empty() { String::new() } else { format!("{}\n", _pc.table) })
        .replace("--[[PRECHECKSET]]\n", &if _pc.set.is_empty() { String::new() } else { format!("{}\n", _pc.set) })
        .replace("--[[LC1FOLD]]", &lc1_fold)
        .replace("--[[DECODE]]", &decode)
        .replace("--[[INSTHEAD]]", &inst_head)
        .replace("--[[DISPATCH]]", &dispatch_body)
        .replace("--[[POLYSTREAM]]", &poly_stmt)
        .replace("--[[HEAVY_POST]]", &hv_post)
        .replace("--[[RGCONTAINER]]\n", &rgcontainer_decl)
        .replace("--[[SURFACE_PREAMBLE]]\n", &surface_preamble)
        .replace("--[[PAYLOAD]]", &payload_decl);
    for (i, chunk) in surface_anchors.iter().enumerate() {
        let hole = format!("--[[SURFACE_MEME_{:02}]]\n", i + 1);
        let repl = if chunk.is_empty() {
            String::new()
        } else {
            format!("{}\n", chunk.trim_end_matches('\n'))
        };
        __vm = __vm.replace(&hole, &repl);
    }
    if std::env::var_os("BASIL_MEME_AUDIT").is_some() {
        if let Some(k) = ink.as_ref() {
            for (region, meme) in &k.log {
                eprintln!("MEME_REGION\t{region}\t{meme}");
            }
        }
    }
    if std::env::var_os("BASIL_TYPE_AUDIT").is_some() {
        if let Some(t) = tink.as_ref() {
            for (region, alias) in &t.log {
                eprintln!("TYPE_REGION\t{region}\t{alias}");
            }
        }
    }
    let __vm = if frame_const_reuse.enabled() {
        let vm = inject_frame_const_section(__vm);
        vm.replacen(
            "local KCAP = 8",
            &format!(
                "local KCAP = 8\nlocal FCRM = {}",
                frame_const_reuse.literal()
            ),
            1,
        )
    } else {
        __vm
    };
    let __vm = if runtime_profile_markers {
        if frame_const_reuse.enabled() {
            inject_frame_const_profiler_markers(__vm)
        } else {
            inject_profiler_markers(__vm)
        }
    } else {
        __vm
    };
    let __vm = if framing {
        inject_framing(__vm, seed)
    } else {
        __vm
    };
    let __vm = topology::apply(__vm, seed);
    constdiv::apply(__vm, seed)
}

fn emit_payload_decl(
    payload_bytes: &[u8],
    wrap: (&str, &str),
    seed: u64,
    heavy: bool,
    plan: Option<&surface::SurfacePlan>,
    ink: &mut Option<surface::meme::MemeInk>,
) -> (String, Vec<String>, String) {
    let empty = || vec![String::new(); surface::ANCHOR_COUNT];
    match plan {
        None => (
            String::new(),
            empty(),
            packer::Plan::for_seed(seed, heavy).emit(payload_bytes, wrap, ink),
        ),
        Some(p) if p.is_off() => (
            String::new(),
            empty(),
            packer::Plan::for_seed(seed, heavy).emit(payload_bytes, wrap, ink),
        ),
        Some(p) => {
            let packed = packer::Plan::for_seed(seed, heavy).emit(payload_bytes, wrap, ink);
            let (carrier_pre, decl) = if p.theme == surface::UnicodeTheme::None {
                (String::new(), packed)
            } else {
                surface::decorate_payload(&packed, p, None)
            };
            (carrier_pre, empty(), decl)
        }
    }
}

fn inject_framing(vm: String, seed: u64) -> String {
    let root_dom = "bxor(lrotate(MK, 7), lrotate(MAPKEY, 13))";
    let trail_dom = "bxor(lrotate(MK, 19), lrotate(MAPKEY, 5))";
    let (root, step, hdr_read) = if bytecode::crypt::framing_family(seed) == 0 {
        (
            format!("fmix(bxor(proto[5], {root_dom}))"),
            "fmix((fstate + (len % 0x100000000) + lrotate(tag, 16)) % 0x100000000)".to_string(),
            "\t\t\tlocal tag = u8()\n\t\t\tlocal len = fvu(proto[5], fstate)".to_string(),
        )
    } else {
        (
            format!("fmix(bxor(lrotate(proto[5], 11), {root_dom}))"),
            "fmix(bxor(lrotate(fstate, band(tag, 15) + 1), len % 0x100000000))".to_string(),
            "\t\t\tlocal len = fvu(proto[5], fstate)\n\t\t\tlocal tag = u8()".to_string(),
        )
    };
    let mut vm = vm.replacen(
        "\t\tlocal nsec = u8()",
        &format!("\t\tlocal fstate = {root}\n\t\tlocal nsec = u8()"),
        1,
    );
    vm = vm.replacen(
        "\t\t\tlocal tag = u8()\n\t\t\tlocal len = vu()",
        &hdr_read,
        1,
    );
    vm = vm.replacen(
        "\t\t\tpos = sectionEnd",
        &format!("\t\t\tpos = sectionEnd\n\t\t\tfstate = {step}"),
        1,
    );
    vm = vm.replacen(
        "\t\tproto[14] = bxor(proto[14], bxor(lrotate(MK, 11), lrotate(MAPKEY, 23)))",
        &format!("\t\tif fvu(proto[5], fstate) ~= fmix(bxor(fstate, {trail_dom})) then dead = true return proto end\n\t\tproto[14] = bxor(proto[14], bxor(lrotate(MK, 11), lrotate(MAPKEY, 23)))"),
        1,
    );
    vm
}

fn inject_frame_const_section(vm: String) -> String {
    let needle = "\t\t\tend\n\t\t\tpos = sectionEnd";
    assert!(vm.contains(needle));
    vm.replacen(
        needle,
        "\t\t\telseif tag == 7 then\n\t\t\t\tlocal n = vu()\n\t\t\t\tlocal x = {}\n\t\t\t\tfor i = 1, n do x[vu()] = true end\n\t\t\t\tproto[19] = x\n\t\t\tend\n\t\t\tpos = sectionEnd",
        1,
    )
}

fn inject_profiler_markers(vm: String) -> String {
    let hdr = "local _pt0 = os.clock()\nlocal function _prof(l) print(\"BASIL_PROF \" .. l .. \" \" .. string.format(\"%.5f\", os.clock() - _pt0)) end\n_prof(\"load_start\")\nlocal PROF_OP = {}\nlocal PROF_N = 0\nlocal PROF_DEC = 0\nlocal PROF_FSE_N = 0\nlocal PROF_FSE_HIT = 0\nlocal PROF_FSE_MISS = 0\nlocal PROF_SNAP = 2000000\nlocal PROF_CD = PROF_SNAP\nlocal function _profsnap(tag)\n\tlocal t = {}\n\tfor o, c in pairs(PROF_OP) do t[#t + 1] = o .. \"=\" .. c end\n\ttable.sort(t)\n\tprint(\"BASIL_EXEC \" .. tag .. \" t=\" .. string.format(\"%.3f\", os.clock() - _pt0) .. \" n=\" .. PROF_N .. \" dec=\" .. PROF_DEC .. \" fse=\" .. PROF_FSE_N .. \" fhit=\" .. PROF_FSE_HIT .. \" fmiss=\" .. PROF_FSE_MISS .. \" \" .. table.concat(t, \" \"))\nend\nlocal function _profreset() PROF_N = 0 PROF_DEC = 0 PROF_FSE_N = 0 PROF_FSE_HIT = 0 PROF_FSE_MISS = 0 PROF_OP = {} PROF_CD = PROF_SNAP _prof(\"reset\") end\nlocal _pg = getgenv and getgenv() or _G\nif _pg then _pg.BASIL_PROF_RESET = _profreset _pg.BASIL_PROF_SNAP = function() _profsnap(\"manual\") end end\nlocal dead = false\n";
    vm.replacen("local dead = false\n", hdr, 1)
        .replacen(
            "SK_SJ = structKey(ENVDIG, MK)",
            "_prof(\"payload_ready\")\n\tSK_SJ = structKey(ENVDIG, MK)",
            1,
        )
        .replacen(
            "pcall(deserialize, PAYLOAD)\n",
            "pcall(deserialize, PAYLOAD)\n\t_prof(\"deserialize_done\")\n",
            1,
        )
        .replacen(
            "genkey = deriveGenKey(saltWords, digest)",
            "genkey = deriveGenKey(saltWords, digest)\n\t_prof(\"genkey_derived\")",
            1,
        )
        .replacen(
            "local last = fromIdx + count - 1",
            "PROF_DEC = PROF_DEC + count\n\tlocal last = fromIdx + count - 1",
            1,
        )
        .replacen(
            "makeClosure(mainProto, {})",
            "(function() _prof(\"root_start\") PROF_N = 0 PROF_DEC = 0 PROF_FSE_N = 0 PROF_FSE_HIT = 0 PROF_FSE_MISS = 0 PROF_OP = {} PROF_CD = PROF_SNAP local _rc = makeClosure(mainProto, {}) return function(...) local _r = _rc(...) _prof(\"root_return\") _profsnap(\"final\") return _r end end)()",
            1,
        )
}

fn inject_frame_const_profiler_markers(vm: String) -> String {
    let hdr = r#"local _pt0 = os.clock()
local function _prof(l) print("BASIL_PROF " .. l .. " " .. string.format("%.5f", os.clock() - _pt0)) end
_prof("load_start")
local PROF_OP = {}
local PROF_N = 0
local PROF_DEC = 0
local PROF_FSE_N = 0
local PROF_FSE_HIT = 0
local PROF_FSE_MISS = 0
local PROF_KCALL = 0
local PROF_KSHIT = 0
local PROF_KNHIT = 0
local PROF_KSMISS = 0
local PROF_KNMISS = 0
local PROF_KCHIT = 0
local PROF_KNAUTH = 0
local PROF_KSAUTH = 0
local PROF_KB1 = 0
local PROF_KB2 = 0
local PROF_KB3 = 0
local PROF_KB4 = 0
local PROF_KNBYTES = 0
local PROF_KSBYTES = 0
local PROF_KFLUSH = 0
local PROF_KSINS = 0
local PROF_KNINS = 0
local PROF_KFAIL = 0
local PROF_KFRAME = 0
local PROF_KMAX = 0
local PROF_SNAP = 2000000
local PROF_CD = PROF_SNAP
local function _profclear()
	PROF_N = 0 PROF_DEC = 0 PROF_FSE_N = 0 PROF_FSE_HIT = 0 PROF_FSE_MISS = 0 PROF_OP = {} PROF_CD = PROF_SNAP
	PROF_KCALL = 0 PROF_KSHIT = 0 PROF_KNHIT = 0 PROF_KSMISS = 0 PROF_KNMISS = 0 PROF_KCHIT = 0
	PROF_KNAUTH = 0 PROF_KSAUTH = 0 PROF_KB1 = 0 PROF_KB2 = 0 PROF_KB3 = 0 PROF_KB4 = 0
	PROF_KNBYTES = 0 PROF_KSBYTES = 0 PROF_KFLUSH = 0 PROF_KSINS = 0 PROF_KNINS = 0 PROF_KFAIL = 0 PROF_KFRAME = 0 PROF_KMAX = 0
end
local function _profsnap(tag)
	local t = {}
	for o, c in pairs(PROF_OP) do t[#t + 1] = o .. "=" .. c end
	table.sort(t)
	print("BASIL_EXEC " .. tag .. " t=" .. string.format("%.3f", os.clock() - _pt0) .. " n=" .. PROF_N .. " dec=" .. PROF_DEC .. " fse=" .. PROF_FSE_N .. " fhit=" .. PROF_FSE_HIT .. " fmiss=" .. PROF_FSE_MISS .. " kcall=" .. PROF_KCALL .. " kshit=" .. PROF_KSHIT .. " knhit=" .. PROF_KNHIT .. " ksmiss=" .. PROF_KSMISS .. " knmiss=" .. PROF_KNMISS .. " kchit=" .. PROF_KCHIT .. " knauth=" .. PROF_KNAUTH .. " ksauth=" .. PROF_KSAUTH .. " kb1=" .. PROF_KB1 .. " kb2=" .. PROF_KB2 .. " kb3=" .. PROF_KB3 .. " kb4p=" .. PROF_KB4 .. " knbytes=" .. PROF_KNBYTES .. " ksbytes=" .. PROF_KSBYTES .. " kflush=" .. PROF_KFLUSH .. " ksins=" .. PROF_KSINS .. " knins=" .. PROF_KNINS .. " kfail=" .. PROF_KFAIL .. " frames=" .. PROF_KFRAME .. " kmax=" .. PROF_KMAX .. " " .. table.concat(t, " "))
end
local function _profreset() _profclear() _prof("reset") end
local _pg
if getgenv then local _okg, _g = pcall(getgenv) if _okg then _pg = _g end end
if not _pg then _pg = _G end
if _pg then pcall(function() _pg.BASIL_PROF_RESET = _profreset _pg.BASIL_PROF_SNAP = function() _profsnap("manual") end end) end
local dead = false
"#;
    vm.replacen("local dead = false\n", hdr, 1)
        .replacen(
            "SK_SJ = structKey(ENVDIG, MK)",
            "_prof(\"payload_ready\")\n\tSK_SJ = structKey(ENVDIG, MK)",
            1,
        )
        .replacen(
            "pcall(deserialize, PAYLOAD)\n",
            "pcall(deserialize, PAYLOAD)\n\t_prof(\"deserialize_done\")\n",
            1,
        )
        .replacen(
            "genkey = deriveGenKey(saltWords, digest)",
            "genkey = deriveGenKey(saltWords, digest)\n\t_prof(\"genkey_derived\")",
            1,
        )
        .replacen(
            "local last = fromIdx + count - 1",
            "PROF_DEC = PROF_DEC + count\n\tlocal last = fromIdx + count - 1",
            1,
        )
        .replacen(
            "makeClosure(mainProto, {})",
            "(function() _prof(\"root_start\") _profclear() local _rc = makeClosure(mainProto, {}) return function(...) local _r = pack(_rc(...)) _prof(\"root_return\") _profsnap(\"final\") return unpack(_r, 1, _r.n) end end)()",
            1,
        )
}

fn root_entry(seed: u64) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_524F_4F54_454E_5452);
    match rng.below(3) {
        0 => "return makeClosure(mainProto, {})()".to_string(),
        1 => "return (makeClosure(mainProto, {}))()".to_string(),
        _ => "return (function() return makeClosure(mainProto, {})() end)()".to_string(),
    }
}

fn uv_access(seed: u64) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_5556_4143_4345_5353);
    let get = match rng.below(4) {
        0 => "local function uvget(uv)\nif uv[KOPEN] then\nreturn uv[KR][uv[KIDX]]\nend\nreturn uv[KV]\nend",
        1 => "local function uvget(uv)\nif not uv[KOPEN] then\nreturn uv[KV]\nend\nreturn uv[KR][uv[KIDX]]\nend",
        2 => "local function uvget(uv)\nif uv[KOPEN] then\nreturn uv[KR][uv[KIDX]]\nelse\nreturn uv[KV]\nend\nend",
        _ => "local function uvget(uv)\nlocal o = uv[KOPEN]\nif o then\nreturn uv[KR][uv[KIDX]]\nend\nreturn uv[KV]\nend",
    };
    let set = match rng.below(3) {
        0 => "local function uvset(uv, val)\nif uv[KOPEN] then\nuv[KR][uv[KIDX]] = val\nelse\nuv[KV] = val\nend\nend",
        1 => "local function uvset(uv, val)\nif not uv[KOPEN] then\nuv[KV] = val\nelse\nuv[KR][uv[KIDX]] = val\nend\nend",
        _ => "local function uvset(uv, val)\nlocal o = uv[KOPEN]\nif o then\nuv[KR][uv[KIDX]] = val\nelse\nuv[KV] = val\nend\nend",
    };
    format!("{get}\n{set}")
}

enum SetupUnit {
    Read(&'static str, String),
    Block(String),
}

fn topo_order(deps: &[&[usize]], rng: &mut crate::rng::Rng) -> Vec<usize> {
    let n = deps.len();
    let mut done = vec![false; n];
    let mut order = Vec::with_capacity(n);
    while order.len() < n {
        let avail: Vec<usize> = (0..n)
            .filter(|&i| !done[i] && deps[i].iter().all(|&d| done[d]))
            .collect();
        let pick = avail[rng.below(avail.len() as u64) as usize];
        done[pick] = true;
        order.push(pick);
    }
    order
}

fn emit_units(order: &[usize], units: &[SetupUnit], rng: &mut crate::rng::Rng) -> String {
    emit_units_mode(order, units, rng, true)
}

fn emit_units_mode(
    order: &[usize],
    units: &[SetupUnit],
    rng: &mut crate::rng::Rng,
    decl: bool,
) -> String {
    let kw = if decl { "local " } else { "" };
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < order.len() {
        match &units[order[i]] {
            SetupUnit::Block(s) => {
                out.push(s.clone());
                i += 1;
            }
            SetupUnit::Read(..) => {
                let start = i;
                while i < order.len() && matches!(units[order[i]], SetupUnit::Read(..)) {
                    i += 1;
                }
                let run: Vec<(&str, &str)> = order[start..i]
                    .iter()
                    .map(|&id| match &units[id] {
                        SetupUnit::Read(n, e) => (*n, e.as_str()),
                        SetupUnit::Block(_) => unreachable!(),
                    })
                    .collect();
                if run.len() >= 2 && rng.below(2) == 0 {
                    let names = run.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
                    let exprs = run.iter().map(|(_, e)| *e).collect::<Vec<_>>().join(", ");
                    out.push(format!("{kw}{names} = {exprs}"));
                } else {
                    for (n, e) in run {
                        out.push(format!("{kw}{n} = {e}"));
                    }
                }
            }
        }
    }
    out.join("\n")
}

const PRIVATE_BYTETAB: &str = "local BYTETAB = {}\nfor _bi = 0, 255 do\n\tBYTETAB[_bi] = char(_bi)\nend\nif BYTETAB[0] ~= \"\\0\" or #BYTETAB[0] ~= 1 or BYTETAB[65] ~= \"A\" or BYTETAB[127] ~= \"\\127\" or BYTETAB[200] ~= \"\\200\" or BYTETAB[255] ~= \"\\255\" then\n\tdead = true\nend\nlocal function streamXor(key, nonce, data)";
const PRIVATE_WORD_CHUNK: &str = "out[ki] = BYTETAB[R % 256] .. BYTETAB[(R // 256) % 256] .. BYTETAB[(R // 65536) % 256] .. BYTETAB[R // 16777216]";
const PRIVATE_TAIL_BYTE: &str =
    "out[ki] = BYTETAB[bxor(byte(data, oi), band(rshift(word, b * 8), 0xFF))]";
const PRIVATE_REDUCE: &str = "	if ki == 0 then
		return \"\"
	end
	local n = ki
	while n > 1 do
		local m = 0
		for i = 1, n - 1, 2 do
			m = m + 1
			out[m] = out[i] .. out[i + 1]
		end
		if n % 2 == 1 then
			m = m + 1
			out[m] = out[n]
		end
		for i = m + 1, n do
			out[i] = nil
		end
		n = m
	end
	local r = out[1]
	out[1] = nil
	return r
end";

const CLOSURE_HOISTED: &str =
    "code, consts, protos, numParams, isVararg, kget, kdg, cdg, ktok, pkey, ce, pk";

fn closure_setup(seed: u64, frame_const_probe: bool) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_434C_4F53_5F53_5450);
    const CODE: usize = 0;
    const G: usize = 6;
    const CE: usize = 9;
    let deps: [&[usize]; 12] = [
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[CODE],
        &[G],
        &[G],
        &[G],
        &[G, CE],
        &[G],
    ];
    let r = bytecode::crypt::opmask_key(seed) & 31;
    let g = match rng.below(3) {
        0 => format!("kdg = proto[9]\nif not kdg then\nipatch(proto)\nkdg = _pdg(code)\nproto[9] = kdg\nend\ncdg = bxor(kdg, lrotate(proto[14], {r}), lrotate(genkey[5], band(proto[5], 31)))"),
        1 => format!("if not proto[9] then\nipatch(proto)\nproto[9] = _pdg(code)\nend\nkdg = proto[9]\ncdg = bxor(kdg, lrotate(proto[14], {r}), lrotate(genkey[5], band(proto[5], 31)))"),
        _ => format!("kdg = proto[9]\nif kdg == nil then\nipatch(proto)\nkdg = _pdg(code)\nproto[9] = kdg\nend\ncdg = bxor(kdg, lrotate(proto[14], {r}), lrotate(genkey[5], band(proto[5], 31)))"),
    };
    let t = match rng.below(3) {
        0 => "ktok = proto[10]\nif not ktok then\nktok = ktoks(code)\nproto[10] = ktok\nend",
        1 => "if not proto[10] then\nproto[10] = ktoks(code)\nend\nktok = proto[10]",
        _ => "ktok = proto[10]\nif ktok == nil then\nktok = ktoks(code)\nproto[10] = ktok\nend",
    };
    let pkey = if rng.below(2) == 0 {
        "pkey = key8(chachaBlock(genkey, { proto[5], cdg, 0 }, 0))".to_string()
    } else {
        "local _nc = { proto[5], cdg, 0 }\npkey = key8(chachaBlock(genkey, _nc, 0))".to_string()
    };
    let units = [
        SetupUnit::Read("code", "proto[1]".to_string()),
        SetupUnit::Read("consts", "proto[2]".to_string()),
        SetupUnit::Read("protos", "proto[4]".to_string()),
        SetupUnit::Read("numParams", "proto[6] or 0".to_string()),
        SetupUnit::Read("isVararg", "proto[7]".to_string()),
        SetupUnit::Block("kget = kroute(proto[5])".to_string()),
        SetupUnit::Block(g.to_string()),
        SetupUnit::Block(t.to_string()),
        SetupUnit::Block(pkey),
        SetupUnit::Block("ce = cep(proto[5], cdg, actOutput(proto[5], cdg, proto[21], proto[22], proto[23], ACTPROBES, proto[20]))".to_string()),
        SetupUnit::Block("pk = mpk(proto[5], cdg, ce)".to_string()),
        SetupUnit::Block("if not proto[18] then\nif not _vpg(code, proto[15]) then\ndead = true\nreturn nil\nend\nproto[18] = true\nend".to_string()),
    ];
    let order = topo_order(&deps, &mut rng);
    let mut out = emit_units_mode(&order, &units, &mut rng, false);
    if frame_const_probe {
        out.push_str("\nkx = proto[19]\nfcm = {}");
    }
    out
}

fn closure_setup_paged(seed: u64, frame_const_probe: bool) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_5041_4745_445F_5354);
    const CDG: usize = 5;
    const CE: usize = 9;
    let deps: [&[usize]; 11] = [
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[CDG],
        &[CDG],
        &[CDG, CE],
    ];
    let pkey = if rng.below(2) == 0 {
        "pkey = key8(chachaBlock(genkey, { proto[5], cdg, 0 }, 0))".to_string()
    } else {
        "local _nc = { proto[5], cdg, 0 }\npkey = key8(chachaBlock(genkey, _nc, 0))".to_string()
    };
    let kt = match rng.below(2) {
        0 => "ktok = proto[10]\nif not ktok then\nktok = {}\nproto[10] = ktok\nend",
        _ => "if not proto[10] then\nproto[10] = {}\nend\nktok = proto[10]",
    };
    let units = [
        SetupUnit::Read("code", "proto[1]".to_string()),
        SetupUnit::Read("consts", "proto[2]".to_string()),
        SetupUnit::Read("protos", "proto[4]".to_string()),
        SetupUnit::Read("numParams", "proto[6] or 0".to_string()),
        SetupUnit::Read("isVararg", "proto[7]".to_string()),
        SetupUnit::Block("cdg = bxor(proto[14], lrotate(genkey[5], band(proto[5], 31)))".to_string()),
        SetupUnit::Block("kget = kroute(proto[5])".to_string()),
        SetupUnit::Block(kt.to_string()),
        SetupUnit::Block(pkey),
        SetupUnit::Block("ce = cep(proto[5], cdg, actOutput(proto[5], cdg, proto[21], proto[22], proto[23], ACTPROBES, proto[20]))".to_string()),
        SetupUnit::Block("pk = mpk(proto[5], cdg, ce)".to_string()),
    ];
    let order = topo_order(&deps, &mut rng);
    let mut out = emit_units_mode(&order, &units, &mut rng, false);
    if frame_const_probe {
        out.push_str("\nkx = proto[19]\nfcm = {}");
    }
    out
}

fn trap_helpers(tp: &bytecode::crypt::TrapParams) -> String {
    format!(
        "local function _tmix(x)\n\tlocal a = bxor(x, lrotate(x, {r1}))\n\tlocal b = (a + lrotate(a, {r2})) % 0x100000000\n\treturn bxor(b, lrotate(b, {r3}))\nend\nlocal function _tseed(pid)\n\treturn _tmix(bxor(bxor(genkey[6], lrotate(pid, {pr})), {sdom}))\nend\nlocal function _tfold(acc, pd, k)\n\treturn (_tmix(bxor(acc, pd)) + k) % 0x100000000\nend\nlocal function _tcan(pid)\n\treturn _tmix(bxor(bxor(genkey[3], lrotate(pid, {cr})), {cdom}))\nend",
        r1 = tp.r1,
        r2 = tp.r2,
        r3 = tp.r3,
        pr = tp.pr,
        cr = tp.cr,
        sdom = tp.sdom,
        cdom = tp.cdom,
    )
}

fn frame_init(seed: u64, d1: bool, state_b: bool) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_4652_414D_455F_494E);
    const FR: usize = 0;
    const FNARGS: usize = 4;
    let deps: [&[usize]; 6] = [&[], &[], &[], &[], &[], &[FR, FNARGS]];
    let kc = match rng.below(3) {
        0 => "local kc = {}\nkc[-2] = ce\nkc[-3] = pk",
        1 => "local kc = {}\nkc[-3] = pk\nkc[-2] = ce",
        _ => "local kc = { [-2] = ce, [-3] = pk }",
    };
    let lineage = if state_b { "\nkc[-10] = proto[20]" } else { "" };
    let kc = if d1 {
        format!("{kc}\nkc[-4] = fmix(bxor((genkey[4] + proto[5]) % 0x100000000, fmix(bxor(genkey[5], lrotate(proto[5], 11)))))\nkc[-5] = proto[27]\nkc[-6] = {{}}\nkc[-7] = {{}}\nkc[-8] = 1\nkc[-9] = {{}}{lineage}")
    } else {
        kc.to_string()
    };
    let copy = match rng.below(3) {
        0 => "for i = 0, numParams - 1 do\nR[i] = args[i + 1]\nend",
        1 => "for i = 1, numParams do\nR[i - 1] = args[i]\nend",
        _ => "for i = numParams - 1, 0, -1 do\nR[i] = args[i + 1]\nend",
    };
    let scopy = match rng.below(2) {
        0 => "for i = 1, numParams do\nR[i - 1] = select(i, ...)\nend",
        _ => "for i = 0, numParams - 1 do\nR[i] = select(i + 1, ...)\nend",
    };
    let clamp = match rng.below(2) {
        0 => "nvar = nargs - numParams\nif nvar < 0 then\nnvar = 0\nend",
        _ => "local _dv = nargs - numParams\nnvar = _dv > 0 and _dv or 0",
    };
    let vloop = match rng.below(2) {
        0 => "for i = 1, nvar do\nvarargs[i] = args[numParams + i]\nend",
        _ => "for i = nvar, 1, -1 do\nvarargs[i] = args[numParams + i]\nend",
    };
    let args_expr = match rng.below(2) {
        0 => "{ ... }",
        _ => "pack(...)",
    };
    let argblock = format!(
        "local varargs, nvar\nif isVararg then\nlocal args = {args_expr}\n{copy}\n{clamp}\nvarargs = {{}}\n{vloop}\nelse\n{scopy}\nend"
    );
    let units = [
        SetupUnit::Read("R", "{}".to_string()),
        SetupUnit::Read("openuv", "{}".to_string()),
        SetupUnit::Read("top", "0".to_string()),
        SetupUnit::Block(kc.to_string()),
        SetupUnit::Read("nargs", "select(sH, ...)".to_string()),
        SetupUnit::Block(argblock),
    ];
    let order = topo_order(&deps, &mut rng);
    emit_units(&order, &units, &mut rng)
}

fn frame_const_reuse_frame(profile: bool) -> String {
    if !profile {
        return "local fraw = kget\nlocal function kget(consts, i, pkey, kc, ktok)\nlocal v = fcm[i]\nif v ~= nil then\nreturn v\nend\nv = fraw(consts, i, pkey, kc, ktok)\nif not dead and kx and not kx[i] then\nlocal t = type(v)\nif ((FCRM == 1 or FCRM == 3) and t == \"string\") or ((FCRM == 2 or FCRM == 3) and t == \"number\") then\nfcm[i] = v\nend\nend\nreturn v\nend".to_string();
    }
    "PROF_KFRAME = PROF_KFRAME + 1\nlocal fcn = 0\nlocal fraw = kget\nlocal function kget(consts, i, pkey, kc, ktok)\nlocal eligible = kx ~= nil and not kx[i]\nif eligible then PROF_KCALL = PROF_KCALL + 1 end\nlocal v = fcm[i]\nif eligible and v ~= nil then\nlocal t = type(v)\nif (FCRM == 1 or FCRM == 3) and t == \"string\" then PROF_KSHIT = PROF_KSHIT + 1 return v end\nif (FCRM == 2 or FCRM == 3) and t == \"number\" then PROF_KNHIT = PROF_KNHIT + 1 return v end\nend\nlocal kh = kc[i] ~= nil\nlocal kn = kc[0] or 0\nlocal d0 = dead\nv = fraw(consts, i, pkey, kc, ktok)\nif dead and not d0 then PROF_KFAIL = PROF_KFAIL + 1 return v end\nlocal t = type(v)\nif t == \"number\" and not kh and kn >= KCAP then PROF_KFLUSH = PROF_KFLUSH + 1 end\nif eligible then\nlocal auth = false\nif t == \"string\" then\nPROF_KSMISS = PROF_KSMISS + 1\nPROF_KSAUTH = PROF_KSAUTH + 1\nPROF_KSBYTES = PROF_KSBYTES + #consts[i]\nauth = true\nelseif t == \"number\" then\nPROF_KNMISS = PROF_KNMISS + 1\nif kh then\nPROF_KCHIT = PROF_KCHIT + 1\nelse\nPROF_KNAUTH = PROF_KNAUTH + 1\nPROF_KNBYTES = PROF_KNBYTES + #consts[i]\nauth = true\nend\nend\nif auth then\nlocal nb = (#consts[i] + 63) // 64\nif nb <= 1 then PROF_KB1 = PROF_KB1 + 1 elseif nb == 2 then PROF_KB2 = PROF_KB2 + 1 elseif nb == 3 then PROF_KB3 = PROF_KB3 + 1 else PROF_KB4 = PROF_KB4 + 1 end\nend\nlocal insert = ((FCRM == 1 or FCRM == 3) and t == \"string\") or ((FCRM == 2 or FCRM == 3) and t == \"number\")\nif insert then\nfcm[i] = v\nfcn = fcn + 1\nif fcn > PROF_KMAX then PROF_KMAX = fcn end\nif t == \"string\" then PROF_KSINS = PROF_KSINS + 1 else PROF_KNINS = PROF_KNINS + 1 end\nend\nend\nreturn v\nend".to_string()
}

fn lc1_canary(seed: u64, fp: u64, canary: bool, uh: bool) -> (String, String) {
    if !canary {
        return (String::new(), String::new());
    }
    let mut rng = crate::rng::Rng::new(fp ^ 0x_4C43_3143_414E_5901);
    let wrapper = lc1_wrapper(bytecode::crypt::canary_salt(seed), &mut rng, uh);
    let mut src = format!(
        "--[[\nbuild padding block\nzxq7f3a90b5e4d28 zxq7f3a90b5e4d28\n]]\nreturn {wrapper}"
    )
    .into_bytes();
    while src.len() % 4 != 0 {
        src.push(b'\n');
    }
    let names = word_carrier::Names {
        byte: "byte",
        char: "char",
        concat: "concat",
        sub: "sub",
        genv: "genv",
    };
    let carrier = word_carrier::emit_expr(&src, seed, 0x_4C43_3144, &names);
    let decl = format!(
        "local LC1SALT=(function()local _ch=char local _pc=genv[_ch(112,99,97,108,108)]local _ty=genv[_ch(116,121,112,101)]local _s={carrier}\nlocal _ld=genv[_ch(108,111,97,100,115,116,114,105,110,103)]or genv[_ch(108,111,97,100)]if _ld and _pc and _ty then local _ok,_fn=_pc(_ld,_s)if _ok and _ty(_fn)==_ch(102,117,110,99,116,105,111,110) then local _o2,_v=_pc(_fn)if _o2 and _ty(_v)==_ch(110,117,109,98,101,114) then return _v end end end return 0 end)()"
    );
    (
        decl,
        "counter = bxor(lrotate(counter, 5), LC1SALT)".to_string(),
    )
}

fn lc1_wrapper(salt: u32, rng: &mut crate::rng::Rng, uh: bool) -> String {
    let v = salt as u64;
    if v < 64 {
        return format!("(function() return {} end)()", derive_u32(salt, rng, uh));
    }
    let p1 = 1 + rng.next() % (v - 2);
    let rem = v - p1;
    let p2 = 1 + rng.next() % (rem - 1);
    let (a, b, c) = (
        derive_u32(p1 as u32, rng, uh),
        derive_u32(p2 as u32, rng, uh),
        derive_u32((rem - p2) as u32, rng, uh),
    );
    match rng.next() % 6 {
        0 => {
            let id = lc1_idents(rng, 6);
            let (key, env, pa, pb, pc, mm) = (&id[0], &id[1], &id[2], &id[3], &id[4], &id[5]);
            let (ks, mo) = (lc1_key(rng), lc1_mod(rng));
            format!(
                "(function(...)local {key}=select(1,...)local {mm}={mo} local {env}=setmetatable({{[{key}]=function({pa},{pb},{pc})return(({pa}+{pb})%{mm}+{pc})%{mm} end}},{{__index=(getfenv and getfenv(1))or _G}})return {env}[{key}]({a},{b},{c})end)(\"{ks}\")"
            )
        }
        1 => {
            let id = lc1_idents(rng, 4);
            let (r, acc, i, mm) = (&id[0], &id[1], &id[2], &id[3]);
            let mo = lc1_mod(rng);
            format!(
                "(function()local {mm}={mo} local {r}={{{a},{b},{c}}}local {acc}=0 for {i}=1,#{r} do {acc}=({acc}+{r}[{i}])%{mm} end return {acc} end)()"
            )
        }
        2 => {
            let id = lc1_idents(rng, 5);
            let (mt, x, y, s, mm) = (&id[0], &id[1], &id[2], &id[3], &id[4]);
            let (k1, mo) = (lc1_key(rng), lc1_mod(rng));
            let mut k2 = lc1_key(rng);
            while k2 == k1 {
                k2 = lc1_key(rng);
            }
            format!(
                "(function()local {mm}={mo} local {mt}={{}} {mt}[\"{k1}\"]=function({x},{y})return({x}+{y})%{mm} end {mt}[\"{k2}\"]=function({x})return {x} end local {s}={mt}[\"{k1}\"]({a},{b}) {s}={mt}[\"{k1}\"]({s},{c})return {mt}[\"{k2}\"]({s})end)()"
            )
        }
        3 => {
            let id = lc1_idents(rng, 4);
            let (op, x, y, s) = (&id[0], &id[1], &id[2], &id[3]);
            let n1 = 1 + rng.next() % 200;
            let mut n2 = 1 + rng.next() % 200;
            while n2 == n1 {
                n2 = 1 + rng.next() % 200;
            }
            let mo = lc1_mod(rng);
            format!(
                "(function()local {op}={{[{n1}]=function({x},{y})return {x}+{y} end,[{n2}]=function({x})return {x}%{mo} end}}local {s}={op}[{n1}]({a},{b}) {s}={op}[{n1}]({s},{c})return {op}[{n2}]({s})end)()"
            )
        }
        4 => {
            let id = lc1_idents(rng, 4);
            let (f, x, y, z) = (&id[0], &id[1], &id[2], &id[3]);
            format!(
                "(function()local {f}=function({x})return function({y},{z})return {x}+{y}+{z} end end return {f}({a})({b},{c})end)()"
            )
        }
        _ => {
            let id = lc1_idents(rng, 5);
            let (ok, val, pa, pb, pc) = (&id[0], &id[1], &id[2], &id[3], &id[4]);
            format!(
                "(function(...)local {ok},{val}=pcall(function(...)local {pa},{pb},{pc}=select(1,...)if type({pa})==\"number\" then return {pa}+{pb}+{pc} end return 0 end,...)if {ok} and type({val})==\"number\" then return {val} end return 0 end)({a},{b},{c})"
            )
        }
    }
}

fn lc1_mod(rng: &mut crate::rng::Rng) -> &'static str {
    [
        "0x100000000",
        "0x1_0000_0000",
        "(0xffffffff+1)",
        "(0xFFFFFFFF+0x1)",
    ][(rng.next() % 4) as usize]
}

fn lc1_ident(rng: &mut crate::rng::Rng) -> String {
    let lo = b"abcdefghijklmnopqrstuvwxyz";
    let up = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let an = b"abcdefghijklmnopqrstuvwxyz0123456789";
    format!(
        "{}{}{}",
        lo[(rng.next() % 26) as usize] as char,
        up[(rng.next() % 26) as usize] as char,
        an[(rng.next() % 36) as usize] as char
    )
}

fn lc1_idents(rng: &mut crate::rng::Rng, n: usize) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    while v.len() < n {
        let id = lc1_ident(rng);
        if !v.contains(&id) {
            v.push(id);
        }
    }
    v
}

fn lc1_key(rng: &mut crate::rng::Rng) -> String {
    let an = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..4 + (rng.next() % 3) as usize)
        .map(|_| an[(rng.next() % 62) as usize] as char)
        .collect()
}

pub use precheck::splice_prechecks;

pub fn splice_natives(vm: String, bodies: &[String]) -> String {
    if bodies.is_empty() {
        return vm;
    }
    let lit = native_sentinel_literal();
    assert_eq!(
        vm.matches(&lit).count(),
        1,
        "native sentinel must appear exactly once"
    );
    vm.replace(&lit, &format!("{{{}}}", bodies.join(",")))
}

fn obscured_strings(seed: u64, heavy: bool) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_5354_5249_4E47);
    if !heavy {
        let sb = litgen::string_lit(b"<B", &mut rng);
        let si = litgen::string_lit(b"<I4", &mut rng);
        let sd = litgen::string_lit(b"<d", &mut rng);
        let sh = litgen::string_lit(b"#", &mut rng);
        return format!("local sB = {sb}\nlocal sI = {si}\nlocal sD = {sd}\nlocal sH = {sh}");
    }
    let pick = |name: &str, s: &[u8], hk: usize, rng: &mut crate::rng::Rng| {
        let a = litgen::string_lit(s, rng);
        let b = litgen::string_lit(s, rng);
        let p = rng.below(2);
        format!("local {name}\nif band(_hs{hk}, 1) == {p} then {name} = {a} else {name} = {b} end")
    };
    [
        pick("sB", b"<B", 0, &mut rng),
        pick("sI", b"<I4", 1, &mut rng),
        pick("sD", b"<d", 2, &mut rng),
        pick("sH", b"#", 3, &mut rng),
    ]
    .join("\n")
}

fn env_probe(
    seed: u64,
    profile: bytecode::crypt::TargetProfile,
    fp: u64,
    uh: bool,
    ink: &mut Option<surface::meme::MemeInk>,
) -> String {
    let mut rng = crate::rng::Rng::new(seed ^ 0x_454E_5650);
    let mut obs = |s: &[u8]| litgen::string_lit(s, &mut rng);
    let cc = bytecode::crypt::checksum;
    let names: Vec<String> = bytecode::crypt::probe_set(seed)
        .iter()
        .map(|n| obs(n.as_bytes()))
        .collect();
    let f = |x: &str| {
        format!(
            "\ttmp = {x}\n\
             \tp = bxor(lrotate(p, 5), tmp)\n\
             \tL[n % 8 + 1] = bxor(lrotate(L[n % 8 + 1], 5), tmp)\n\
             \tn = n + 1\n"
        )
    };
    let num_folds: String = bytecode::crypt::ENVFP_NUM
        .iter()
        .map(|(e, _)| f(&format!("checksum(ts({e}))")))
        .collect();
    let err_folds: String = bytecode::crypt::ENVFP_ERR
        .iter()
        .map(|(b, _)| f(&format!("checksum(es(function() {b} end))")))
        .collect();
    let mut nrng = crate::rng::Rng::new(fp ^ 0x_5347_314E_4F4E_4300);
    let en = bytecode::crypt::env_nonce(seed);
    let n0 = plain_u32(en[0], &mut nrng, uh);
    let n0 = ink
        .as_mut()
        .and_then(|k| k.wrap("EnvProbe", &n0))
        .unwrap_or(n0);
    let n1 = plain_u32(en[1], &mut nrng, uh);
    let n1 = ink
        .as_mut()
        .and_then(|k| k.wrap("EnvProbe", &n1))
        .unwrap_or(n1);
    let n2 = plain_u32(en[2], &mut nrng, uh);
    let n2 = ink
        .as_mut()
        .and_then(|k| k.wrap("EnvProbe", &n2))
        .unwrap_or(n2);
    let env_nonce = format!("{n0}, {n1}, {n2}");

    let at2 = at2_folds(profile, &mut obs, &f);
    format!(
        "local function envProbe()\n\
         \tlocal g = genv\n\
         \tlocal ts = g[{ts}]\n\
         \tlocal p = 0\n\
         \tlocal L = {{ 0, 0, 0, 0, 0, 0, 0, 0 }}\n\
         \tlocal n = 0\n\
         \tlocal tmp\n\
         {dnum_fold}\
         {num_folds}\
         {derr_fold}\
         \tlocal pc = g[{pc}]\n\
         \tlocal sm = g[{str}][{mt}]\n\
         \tlocal function es(f)\n\
         \t\tlocal ok, e = pc(f)\n\
         \t\te = ts(e)\n\
         \t\treturn sm(e, {pat}) or e\n\
         \tend\n\
         {err_folds}\
         {ddbg_fold}\
         \tlocal d = g[{dbg}]\n\
         \tlocal nf = d and d[{info}]\n\
         \tlocal ns = {{ {names} }}\n\
         \tfor i = 1, #ns do\n\
         \t\tlocal r = {cexp}\n\
         \t\tif nf then\n\
         \t\t\tlocal fn = g[ns[i]]\n\
         \t\t\tif fn then r = nf(fn, {sopt}) end\n\
         \t\tend\n\
         \t\ttmp = checksum(r)\n\
         \t\tp = bxor(lrotate(p, 5), tmp)\n\
         \t\tL[n % 8 + 1] = bxor(lrotate(L[n % 8 + 1], 5), tmp)\n\
         \t\tn = n + 1\n\
         \tend\n\
         \tlocal function T(fn) local ok, r = pc(fn) if ok then return r end return nil end\n\
         {at2}\
         \tENVDIG = key8(chachaBlock(L, {{ {env_nonce} }}, 0))\n\
         \treturn p\n\
         end",
        ts = obs(b"tostring"),
        dnum_fold = f(&hide_u32(cc(b"number_format"), &mut nrng, uh)),
        derr_fold = f(&hide_u32(cc(b"behavior_error_shape"), &mut nrng, uh)),
        ddbg_fold = f(&hide_u32(cc(b"debug_info_s"), &mut nrng, uh)),
        pc = obs(b"pcall"),
        str = obs(b"string"),
        mt = obs(b"match"),
        pat = obs(b"attempt.*"),
        dbg = obs(b"debug"),
        info = obs(b"info"),
        names = names.join(", "),
        cexp = obs(b"[C]"),
        sopt = obs(b"s"),
        at2 = at2,
    )
}

fn at2_folds(
    profile: bytecode::crypt::TargetProfile,
    obs: &mut impl FnMut(&[u8]) -> String,
    f: &impl Fn(&str) -> String,
) -> String {
    use bytecode::crypt::TargetProfile as P;
    if profile == P::CliTest {
        return String::new();
    }
    let sent = obs(b"\x00AT2x");
    let mut out = String::new();

    let gm = format!("g[{}]", obs(b"game"));
    let plk = obs(b"Players");
    let gsk = obs(b"GetService");
    let tf = format!("g[{}]", obs(b"typeof"));
    let inst = obs(b"Instance");
    out.push_str(&format!(
        "\tlocal _pl = T(function() return {gm}[{gsk}]({gm}, {plk}) end)\n"
    ));
    out.push_str(&f(&format!(
        "checksum({tf}(T(function() return {gm}[{plk}] end)) or {sent})"
    )));
    out.push_str(&f(&format!("checksum({tf}(_pl) or {sent})")));
    out.push_str(&f(&format!(
        "checksum(T(function() return _pl[{}] end) or {sent})",
        obs(b"ClassName")
    )));
    out.push_str(&f(&format!(
        "checksum(ts(T(function() return _pl[{}](_pl, {inst}) end)) or {sent})",
        obs(b"IsA")
    )));
    let info = obs(b"info");
    let sopt = obs(b"s");
    out.push_str(&f(&format!(
        "checksum(T(function() return g[{}][{info}](pc, {sopt}) end) or {sent})",
        obs(b"debug")
    )));
    out.push_str(&f(&format!(
        "checksum(T(function() return g[{}][{info}](ts, {sopt}) end) or {sent})",
        obs(b"debug")
    )));
    let u8t = format!("g[{}]", obs(b"utf8"));
    out.push_str(&f(&format!(
        "checksum(T(function() return {u8t}[{}]({}) end) or {sent})",
        obs(b"nfcnormalize"),
        obs(b"e\xCC\x81")
    )));
    out.push_str(&f(&format!(
        "checksum(T(function() return {u8t}[{}]({}) end) or {sent})",
        obs(b"nfdnormalize"),
        obs(b"\xC3\xA9")
    )));
    out.push_str(&f(&format!(
        "checksum(T(function() local s = {gm}[{gsk}]({gm}, {}) return s[{}][{}] end) or {sent})",
        obs(b"Stats"),
        obs(b"Parent"),
        obs(b"ClassName")
    )));
    if matches!(profile, P::Executor | P::Studio | P::RobloxClient) {
        let cpn = format!("g[{}][{}]", obs(b"Path2DControlPoint"), obs(b"new"));
        let u2n = format!("g[{}][{}]", obs(b"UDim2"), obs(b"new"));
        let instn = format!("g[{}][{}]", obs(b"Instance"), obs(b"new"));
        let par = obs(b"Parent");
        let scp = obs(b"SetControlPoints");
        let gl = obs(b"GetLength");
        let rnd = format!("g[{}][{}]", obs(b"math"), obs(b"round"));
        let ds = obs(b"Destroy");
        let sgn = obs(b"ScreenGui");
        let frn = obs(b"Frame");
        let p2d = obs(b"Path2D");
        for (pts, _len) in bytecode::crypt::PATH2D_TRAPS {
            let cps: Vec<String> = pts
                .iter()
                .map(|(x, y)| format!("C(U(0, {x}, 0, {y}), Z, Z)"))
                .collect();
            let body = format!(
                "local C = {cpn} local U = {u2n} local Z = U(0,0,0,0) local m = {{{}}} local I = {instn} \
                 local sg = I({sgn}) local fr = I({frn}) fr[{par}] = sg local pp = I({p2d}) pp[{par}] = fr \
                 pp[{scp}](pp, m) local len = {rnd}(pp[{gl}](pp)) pc(sg[{ds}], sg) return len",
                cps.join(", ")
            );
            out.push_str(&f(&format!("(T(function() {body} end) or -1)")));
        }
    }

    let rs = format!(
        "T(function() return {gm}[{gsk}]({gm}, {}) end)",
        obs(b"RunService")
    );
    for (m, _ex) in profile.runservice_methods() {
        out.push_str(&f(&format!(
            "checksum(ts(T(function() local s = {rs} return s[{}](s) end)) or {sent})",
            obs(m)
        )));
    }
    out
}

fn probe_fold(seed: u64, anti_envlog: bool) -> String {
    let fold_a = "counter = bxor(lrotate(counter, 5), envProbe())".to_string();
    if !anti_envlog {
        return fold_a;
    }
    let mut rng = crate::rng::Rng::new(seed ^ 0x_414E_5449);
    let mut obs = |s: &[u8]| litgen::string_lit(s, &mut rng);
    let outer = match bytecode::crypt::dt_trap(seed) {
        bytecode::crypt::DtTrap::Vec3Mag(x, y, z) => format!(
            "g[{v3}][{nw}]({x}, {y}, {z})[{mg}]",
            v3 = obs(b"Vector3"),
            nw = obs(b"new"),
            mg = obs(b"Magnitude"),
        ),
        bytecode::crypt::DtTrap::CFrameSumX(a, b, c, d, e, f) => format!(
            "(g[{cf}][{nw}]({a}, {b}, {c}) * g[{cf}][{nw}]({d}, {e}, {f}))[{xx}]",
            cf = obs(b"CFrame"),
            nw = obs(b"new"),
            xx = obs(b"X"),
        ),
        bytecode::crypt::DtTrap::Path2DLen(_) => unreachable!("Path2D is the inner trap"),
    };

    let inner = match bytecode::crypt::path2d_trap(seed) {
        bytecode::crypt::DtTrap::Path2DLen(pts) => {
            let cps: Vec<String> = pts
                .iter()
                .map(|(x, y)| format!("C(U(0, {x}, 0, {y}), Z, Z)"))
                .collect();
            format!(
                "local C = g[{cp}][{nw}]\nlocal U = g[{u2}][{nw}]\nlocal Z = U(0, 0, 0, 0)\nlocal m = {{{cps}}}\nlocal I = g[{inst}][{nw}]\nlocal sg = I({sgn})\nlocal fr = I({frn})\nfr[{par}] = sg\nlocal pp = I({p2d})\npp[{par}] = fr\npp[{scp}](pp, m)\nlocal len = g[{mth}][{rnd}](pp[{gl}](pp))\ng[{pc}](sg[{ds}], sg)\nreturn len",
                cp = obs(b"Path2DControlPoint"),
                nw = obs(b"new"),
                u2 = obs(b"UDim2"),
                cps = cps.join(", "),
                inst = obs(b"Instance"),
                sgn = obs(b"ScreenGui"),
                frn = obs(b"Frame"),
                par = obs(b"Parent"),
                p2d = obs(b"Path2D"),
                scp = obs(b"SetControlPoints"),
                mth = obs(b"math"),
                rnd = obs(b"round"),
                gl = obs(b"GetLength"),
                pc = obs(b"pcall"),
                ds = obs(b"Destroy"),
            )
        }
        _ => unreachable!("path2d_trap returns Path2DLen"),
    };
    let term = |t: bytecode::crypt::FoldTerm| match t {
        bytecode::crypt::FoldTerm::Probe => "counter = bxor(lrotate(counter, 5), envProbe())",
        bytecode::crypt::FoldTerm::Outer => "counter = bxor(lrotate(counter, 5), dv1)",
        bytecode::crypt::FoldTerm::Inner => "counter = bxor(lrotate(counter, 5), dv2)",
    };
    let order = bytecode::crypt::fold_order(seed);
    format!(
        "local g = genv\nlocal ok1, dv1 = g[{pc}](function() return {outer} end)\ndv1 = (ok1 and g[{tn}](dv1)) or 0\nlocal ok2, dv2 = g[{pc}](function() {inner} end)\ndv2 = (ok2 and g[{tn}](dv2)) or 0\n{f0}\n{f1}\n{f2}",
        pc = obs(b"pcall"),
        tn = obs(b"tonumber"),
        f0 = term(order[0]),
        f1 = term(order[1]),
        f2 = term(order[2]),
    )
}

const BLOBS_SENTINEL: &str = "@@BASIL_BLOBS@@";

fn blobs_sentinel_literal() -> String {
    format!("{BLOBS_SENTINEL:?}")
}

const ECLS_SENTINEL: &str = "@@BASIL_ECLS@@";

fn ecls_sentinel_literal() -> String {
    format!("{ECLS_SENTINEL:?}")
}

pub fn splice_ecls(vm: String, classes: &[u8]) -> String {
    let lit = ecls_sentinel_literal();
    if vm.matches(&lit).count() != 1 {
        return vm;
    }
    let entries: Vec<String> = classes
        .iter()
        .enumerate()
        .filter(|(_, &c)| c != 0)
        .map(|(id, &c)| format!("[{id}] = {c}"))
        .collect();
    vm.replace(&lit, &format!("{{{}}}", entries.join(", ")))
}

const ENCFUNC_LUAU: &str = "local BLOBS = __BLOBSENT__\n\
local makeEncWrapper\n\
do\n\
local ebz = bit32\n\
local rrot, bnot = ebz.rrotate, ebz.bnot\n\
local function _eSha(msg)\n\
\tlocal K = { [0] = 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 }\n\
\tlocal h = { [0] = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }\n\
\tlocal bitlen = #msg * 8\n\
\tmsg = msg .. char(0x80)\n\
\twhile #msg % 64 ~= 56 do msg = msg .. char(0) end\n\
\tmsg = msg .. char(0, 0, 0, 0, band(rshift(bitlen, 24), 255), band(rshift(bitlen, 16), 255), band(rshift(bitlen, 8), 255), band(bitlen, 255))\n\
\tfor base = 1, #msg, 64 do\n\
\t\tlocal w = {}\n\
\t\tfor i = 0, 15 do\n\
\t\t\tlocal p = base + i * 4\n\
\t\t\tw[i] = byte(msg, p) * 16777216 + byte(msg, p + 1) * 65536 + byte(msg, p + 2) * 256 + byte(msg, p + 3)\n\
\t\tend\n\
\t\tfor i = 16, 63 do\n\
\t\t\tlocal x, y = w[i - 15], w[i - 2]\n\
\t\t\tlocal s0 = bxor(bxor(rrot(x, 7), rrot(x, 18)), rshift(x, 3))\n\
\t\t\tlocal s1 = bxor(bxor(rrot(y, 17), rrot(y, 19)), rshift(y, 10))\n\
\t\t\tw[i] = (w[i - 16] + s0 + w[i - 7] + s1) % 0x100000000\n\
\t\tend\n\
\t\tlocal a, b, c, d, e, f, g, hh = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]\n\
\t\tfor i = 0, 63 do\n\
\t\t\tlocal S1 = bxor(bxor(rrot(e, 6), rrot(e, 11)), rrot(e, 25))\n\
\t\t\tlocal ch = bxor(band(e, f), band(bnot(e), g))\n\
\t\t\tlocal t1 = (hh + S1 + ch + K[i] + w[i]) % 0x100000000\n\
\t\t\tlocal S0 = bxor(bxor(rrot(a, 2), rrot(a, 13)), rrot(a, 22))\n\
\t\t\tlocal mj = bxor(bxor(band(a, b), band(a, c)), band(b, c))\n\
\t\t\tlocal t2 = (S0 + mj) % 0x100000000\n\
\t\t\thh = g; g = f; f = e; e = (d + t1) % 0x100000000; d = c; c = b; b = a; a = (t1 + t2) % 0x100000000\n\
\t\tend\n\
\t\th[0] = (h[0] + a) % 0x100000000; h[1] = (h[1] + b) % 0x100000000; h[2] = (h[2] + c) % 0x100000000; h[3] = (h[3] + d) % 0x100000000\n\
\t\th[4] = (h[4] + e) % 0x100000000; h[5] = (h[5] + f) % 0x100000000; h[6] = (h[6] + g) % 0x100000000; h[7] = (h[7] + hh) % 0x100000000\n\
\tend\n\
\tlocal o = {}\n\
\tfor i = 0, 7 do\n\
\t\tlocal v = h[i]\n\
\t\to[i + 1] = char(band(rshift(v, 24), 255), band(rshift(v, 16), 255), band(rshift(v, 8), 255), band(v, 255))\n\
\tend\n\
\treturn concat(o)\n\
end\n\
local function _eHmac(key, msg)\n\
\tlocal ip, op = {}, {}\n\
\tfor i = 1, 64 do\n\
\t\tlocal kb = 0\n\
\t\tif i <= #key then kb = byte(key, i) end\n\
\t\tip[i] = char(bxor(kb, 0x36))\n\
\t\top[i] = char(bxor(kb, 0x5c))\n\
\tend\n\
\treturn _eSha(concat(op) .. _eSha(concat(ip) .. msg))\n\
end\n\
local function _eHv(c)\n\
\tif c >= 48 and c <= 57 then return c - 48 end\n\
\tif c >= 97 and c <= 102 then return c - 87 end\n\
\tif c >= 65 and c <= 70 then return c - 55 end\n\
\treturn nil\n\
end\n\
local function _eHex(s)\n\
\tif #s ~= 64 then return nil end\n\
\tlocal o = {}\n\
\tfor i = 1, 32 do\n\
\t\tlocal hi = _eHv(byte(s, 2 * i - 1))\n\
\t\tlocal lo = _eHv(byte(s, 2 * i))\n\
\t\tif not hi or not lo then return nil end\n\
\t\to[i] = char(hi * 16 + lo)\n\
\tend\n\
\treturn concat(o)\n\
end\n\
local ENCSALT = char(__SALT__)\n\
local SVAD = char(__SVAD__)\n\
local SEEDDOM = char(__SEEDDOM__)\n\
local ECLS = __ECLSSENT__\n\
local function _eKdf(seed)\n\
\tif type(seed) ~= \"number\" or seed * 0 ~= 0 or seed < 0 or seed > 9007199254740991 or seed % 1 ~= 0 then return nil end\n\
\tlocal b = {}\n\
\tlocal s = seed\n\
\tfor i = 1, 8 do b[i] = char(s % 256); s = (s - (s % 256)) / 256 end\n\
\treturn _eSha(SEEDDOM .. concat(b))\n\
end\n\
local function _eOpen(kb, ad, blob)\n\
\tif #blob < 44 then return nil end\n\
\tlocal nonce = sub(blob, 1, 12)\n\
\tlocal ct = sub(blob, 13, #blob - 32)\n\
\tlocal tg = sub(blob, #blob - 31, #blob)\n\
\tlocal mk = _eSha(kb .. char(1))\n\
\tif _eHmac(mk, ad .. nonce .. ct) ~= tg then return nil end\n\
\tlocal kw = {}\n\
\tfor i = 0, 7 do kw[i + 1] = byte(kb, i * 4 + 1) + byte(kb, i * 4 + 2) * 256 + byte(kb, i * 4 + 3) * 65536 + byte(kb, i * 4 + 4) * 16777216 end\n\
\tlocal nw = {}\n\
\tfor i = 0, 2 do nw[i + 1] = byte(nonce, i * 4 + 1) + byte(nonce, i * 4 + 2) * 256 + byte(nonce, i * 4 + 3) * 65536 + byte(nonce, i * 4 + 4) * 16777216 end\n\
\treturn streamXor(kw, nw, ct)\n\
end\n\
local function _eKids(p)\n\
\tlocal kids = p[4]\n\
\tfor i = 1, #kids do\n\
\t\tlocal c = kids[i]\n\
\t\tdecodeProto(c)\n\
--[[ENCKEPCLRC]]\
\t\tc[9] = _pdg(c[1])\n\
\t\t_eKids(c)\n\
\tend\n\
end\n\
local function _eMat(b85, key, id)\n\
\tlocal kb\n\
\tif type(key) == \"number\" then kb = _eKdf(key) else kb = _eHex(tostring(key)) end\n\
\tif not kb then dead = true return nil end\n\
\tlocal ad = SVAD .. char(id % 256, (id // 256) % 256, (id // 65536) % 256, (id // 16777216) % 256) .. ENCSALT .. char(ECLS[id] or 0)\n\
\tlocal pt = _eOpen(kb, ad, b85dec(b85))\n\
\tif not pt then dead = true return nil end\n\
\tlocal want = byte(pt, 1) + byte(pt, 2) * 256 + byte(pt, 3) * 65536 + byte(pt, 4) * 16777216\n\
\tlocal proto = deserialize(sub(pt, 5))\n\
\tproto[16] = nil\n\
\tproto[20] = 0\n\
\tdecodeProto(proto)\n\
--[[ENCKEPCLRP]]\
\tif _pdg(proto[1]) ~= want then dead = true return nil end\n\
\tproto[9] = want\n\
\t_eKids(proto)\n\
\treturn makeClosure(proto, {})\n\
end\n\
function makeEncWrapper(b85, key, id)\n\
\tlocal cache\n\
\treturn function(...)\n\
\t\tif not cache then\n\
\t\t\tcache = _eMat(b85, key, id)\n\
\t\t\tif not cache then return end\n\
\t\tend\n\
\t\treturn cache(...)\n\
\tend\n\
end\n\
end";

const ICAT_DECOY_NAMES: &[&str] = &[
    "RequestAsync",
    "JSONDecode",
    "getgenv",
    "gethui",
    "hookfunction",
    "hookmetamethod",
    "FireServer",
    "WaitForChild",
    "identifyexecutor",
    "getrawmetatable",
    "newcclosure",
    "getconnections",
    "FindFirstChild",
    "protectgui",
];

fn icat_entry(name: &str, id: u32, meth: u8, k0: u32, k1: u32, k2: u32) -> String {
    let bytes: Vec<u8> = name.bytes().collect();
    let enc: Vec<u32> = match meth {
        0 => bytes
            .iter()
            .enumerate()
            .map(|(j, &b)| b as u32 ^ ((k0 + j as u32 * k1) & 0xff))
            .collect(),
        1 => bytes
            .iter()
            .enumerate()
            .map(|(j, &b)| b as u32 ^ ((k0 + id * k2 + j as u32 * k1) & 0xff))
            .collect(),
        _ => bytes
            .iter()
            .rev()
            .enumerate()
            .map(|(r, &b)| b as u32 ^ ((k0 + r as u32 * k1) & 0xff))
            .collect(),
    };
    let body = std::iter::once(meth.to_string())
        .chain(enc.iter().map(|x| x.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

fn intrinsic_catalog(seed: u64, ids: &HashSet<u32>, heavy: bool) -> String {
    if ids.is_empty() {
        return String::new();
    }
    let mut rng = crate::rng::Rng::new(seed ^ 0x_C3C3_1CA7_0000_0001);
    let k0 = (rng.below(255) as u32) | 1;
    let k1 = rng.below(256) as u32;
    let k2 = (rng.below(255) as u32) | 1;
    let mut sorted: Vec<u32> = ids.iter().copied().collect();
    sorted.sort_unstable();
    let max_id = *sorted.iter().max().unwrap();
    let mut order = sorted.clone();
    rng.shuffle(&mut order);
    let mut p = vec![0u32; (max_id + 1) as usize];
    let mut entries: Vec<String> = Vec::with_capacity(order.len());
    for (slot, &id) in order.iter().enumerate() {
        let name = bytecode::intrinsic::name_of(id).expect("used intrinsic id must be in catalog");
        let meth = rng.below(3) as u8;
        entries.push(icat_entry(name, id, meth, k0, k1, k2));
        p[id as usize] = (slot + 1) as u32;
    }
    if heavy {
        let d = 3 + rng.below(4) as usize;
        for _ in 0..d {
            let name = ICAT_DECOY_NAMES[rng.below(ICAT_DECOY_NAMES.len() as u64) as usize];
            let fake_id = rng.below((max_id + 7) as u64) as u32;
            let meth = rng.below(3) as u8;
            entries.push(icat_entry(name, fake_id, meth, k0, k1, k2));
        }
    }
    let pdata = p
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "local ICAT_D={{{data}}}\nlocal ICAT_P={{{pdata}}}\nlocal ICAT_C={{}}\nlocal function icat(id)\n\
         local v=ICAT_C[id]\nif v then return v end\nlocal e=ICAT_D[ICAT_P[id+1]]\nlocal m=e[1]\n\
         if m==0 then\nlocal t={{}}\nfor i=2,#e do local j=i-2 t[j+1]=char(bxor(e[i],({k0}+j*{k1})%256))end\nv=concat(t)\n\
         elseif m==1 then\nv=\"\"\nfor i=2,#e do local j=i-2 v=v..char(bxor(e[i],({k0}+id*{k2}+j*{k1})%256))end\n\
         else\nlocal t={{}}\nlocal L=#e-1\nfor i=2,#e do local r=i-2 t[L-r]=char(bxor(e[i],({k0}+r*{k1})%256))end\nv=concat(t)\nend\n\
         ICAT_C[id]=v\nreturn v\nend",
        data = entries.join(",")
    )
}

fn encfunc_machinery(seed: u64, kepoch_on: bool, fmt: &FormatConfig) -> String {
    let salt = bytecode::encoder::payload_salt(seed);
    let salt_args = salt
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut svad = bytecode::format::SEALED_VALUE_AD_DOMAIN.to_vec();
    svad.extend_from_slice(&fmt.identity_bytes());
    let svad_args = svad
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let dom = bytecode::aead::SEED_KDF_DOMAIN
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let (clr_c, clr_p) = if kepoch_on {
        (
            "\t\tfor _kc = 1, #c[1] do local _ci = c[1][_kc] if _ci then _ci[KEP] = nil end end\n",
            "\tfor _kc = 1, #proto[1] do local _ci = proto[1][_kc] if _ci then _ci[KEP] = nil end end\n",
        )
    } else {
        ("", "")
    };
    ENCFUNC_LUAU
        .replace("__BLOBSENT__", &blobs_sentinel_literal())
        .replace("__ECLSSENT__", &ecls_sentinel_literal())
        .replace("__SALT__", &salt_args)
        .replace("__SVAD__", &svad_args)
        .replace("__SEEDDOM__", &dom)
        .replace("--[[ENCKEPCLRC]]", clr_c)
        .replace("--[[ENCKEPCLRP]]", clr_p)
}

pub fn splice_blobs(vm: String, blobs: &[Vec<u8>]) -> String {
    if blobs.is_empty() {
        return vm;
    }
    let lit = blobs_sentinel_literal();
    assert_eq!(
        vm.matches(&lit).count(),
        1,
        "blobs sentinel must appear exactly once"
    );
    let table: Vec<String> = blobs
        .iter()
        .map(|b| format!("[==[{}]==]", base85(b)))
        .collect();
    vm.replace(&lit, &format!("{{{}}}", table.join(", ")))
}

pub fn randomize_crypto_aliases(src: &str, seed: u64) -> String {
    let aliases = [
        "band", "bxor", "bnot", "rsh", "rrot", "schar", "sfmt", "floor", "byte",
    ];
    let mut rng = crate::rng::Rng::new(seed ^ 0x_4352_5950_414C_53);
    let letters = b"QZJXVWYU";
    let base = letters[rng.below(letters.len() as u64) as usize] as char;
    let mut out = src.to_string();
    for (i, alias) in aliases.iter().enumerate() {
        let repl = format!("{base}{}", i + 1);
        out = replace_word_not_after_dot(&out, alias, &repl);
    }
    out
}

fn replace_word_not_after_dot(s: &str, word: &str, repl: &str) -> String {
    let b = s.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if s[i..].starts_with(word) {
            let before_ok = i == 0 || (!is_id(b[i - 1]) && b[i - 1] != b'.');
            let after = i + word.len();
            let after_ok = after >= b.len() || !is_id(b[after]);
            if before_ok && after_ok {
                out.push_str(repl);
                i = after;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

pub const HASH_HELPER_LUA: &str = "function(s)\n\
\ts = tostring(s)\n\
\tlocal hbz = bit32\n\
\tlocal band, bxor, bnot, rsh, rrot = hbz.band, hbz.bxor, hbz.bnot, hbz.rshift, hbz.rrotate\n\
\tlocal byte, schar, sfmt = string.byte, string.char, string.format\n\
\tlocal K = { [0] = 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 }\n\
\tlocal h = { [0] = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }\n\
\tlocal bitlen = #s * 8\n\
\tlocal msg = s .. schar(0x80)\n\
\twhile #msg % 64 ~= 56 do msg = msg .. schar(0) end\n\
\tmsg = msg .. schar(0, 0, 0, 0, band(rsh(bitlen, 24), 255), band(rsh(bitlen, 16), 255), band(rsh(bitlen, 8), 255), band(bitlen, 255))\n\
\tfor base = 1, #msg, 64 do\n\
\t\tlocal w = {}\n\
\t\tfor i = 0, 15 do\n\
\t\t\tlocal p = base + i * 4\n\
\t\t\tw[i] = byte(msg, p) * 16777216 + byte(msg, p + 1) * 65536 + byte(msg, p + 2) * 256 + byte(msg, p + 3)\n\
\t\tend\n\
\t\tfor i = 16, 63 do\n\
\t\t\tlocal x, y = w[i - 15], w[i - 2]\n\
\t\t\tlocal s0 = bxor(bxor(rrot(x, 7), rrot(x, 18)), rsh(x, 3))\n\
\t\t\tlocal s1 = bxor(bxor(rrot(y, 17), rrot(y, 19)), rsh(y, 10))\n\
\t\t\tw[i] = (w[i - 16] + s0 + w[i - 7] + s1) % 0x100000000\n\
\t\tend\n\
\t\tlocal a, b, c, d, e, f, g, hh = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]\n\
\t\tfor i = 0, 63 do\n\
\t\t\tlocal S1 = bxor(bxor(rrot(e, 6), rrot(e, 11)), rrot(e, 25))\n\
\t\t\tlocal ch = bxor(band(e, f), band(bnot(e), g))\n\
\t\t\tlocal t1 = (hh + S1 + ch + K[i] + w[i]) % 0x100000000\n\
\t\t\tlocal S0 = bxor(bxor(rrot(a, 2), rrot(a, 13)), rrot(a, 22))\n\
\t\t\tlocal maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))\n\
\t\t\tlocal t2 = (S0 + maj) % 0x100000000\n\
\t\t\thh = g; g = f; f = e; e = (d + t1) % 0x100000000; d = c; c = b; b = a; a = (t1 + t2) % 0x100000000\n\
\t\tend\n\
\t\th[0] = (h[0] + a) % 0x100000000; h[1] = (h[1] + b) % 0x100000000; h[2] = (h[2] + c) % 0x100000000; h[3] = (h[3] + d) % 0x100000000\n\
\t\th[4] = (h[4] + e) % 0x100000000; h[5] = (h[5] + f) % 0x100000000; h[6] = (h[6] + g) % 0x100000000; h[7] = (h[7] + hh) % 0x100000000\n\
\tend\n\
\treturn sfmt((\"%08x\"):rep(8), h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])\n\
end";

pub const NOOP_NATIVE: &str = "function() end";

const DECOMPRESS_LUAU: &str = "local function lzwdec(data)\n\
\tlocal origlen = byte(data, 1) + byte(data, 2) * 256 + byte(data, 3) * 65536 + byte(data, 4) * 16777216\n\
\tif origlen == 0 then return \"\" end\n\
\tlocal par, chb, fst = {}, {}, {}\n\
\tfor i = 0, 255 do par[i] = -1 chb[i] = i fst[i] = i end\n\
\tlocal nxt, width, acc, bits, pos = 256, 9, 0, 0, 5\n\
\tlocal function readcode()\n\
\t\twhile bits < width do acc = acc + byte(data, pos) * 2 ^ bits pos = pos + 1 bits = bits + 8 end\n\
\t\tlocal w2 = 2 ^ width\n\
\t\tlocal code = acc % w2\n\
\t\tacc = (acc - code) / w2\n\
\t\tbits = bits - width\n\
\t\treturn code\n\
\tend\n\
\tlocal out, oi, stk = {}, 1, {}\n\
\tlocal prev = readcode()\n\
\tout[1] = char(chb[prev])\n\
\twhile oi < origlen do\n\
\t\tlocal code = readcode()\n\
\t\tlocal walk, fc\n\
\t\tif code < nxt then walk = code fc = fst[code] else walk = prev fc = fst[prev] end\n\
\t\tlocal sp, k = 0, walk\n\
\t\twhile k >= 0 do sp = sp + 1 stk[sp] = chb[k] k = par[k] end\n\
\t\tfor x = sp, 1, -1 do oi = oi + 1 out[oi] = char(stk[x]) end\n\
\t\tif code >= nxt then oi = oi + 1 out[oi] = char(fc) end\n\
\t\tif nxt < 65536 then\n\
\t\t\tpar[nxt] = prev chb[nxt] = fc fst[nxt] = fst[prev]\n\
\t\t\tnxt = nxt + 1\n\
\t\t\tif nxt == 2 ^ width - 1 and width < 16 then width = width + 1 end\n\
\t\tend\n\
\t\tprev = code\n\
\tend\n\
\treturn concat(out)\n\
end";

fn derive_u32(value: u32, rng: &mut crate::rng::Rng, uh: bool) -> String {
    crate::numlit::cold_expr(value, rng, uh)
}

fn is_signature_u32(x: u32) -> bool {
    matches!(
        x,
        0x9E37_79B9 | 0x811C_9DC5 | 0x6170_7865 | 0x3320_646E | 0x7962_2D32 | 0x6B20_6574
    )
}

fn plain_u32(value: u32, rng: &mut crate::rng::Rng, uh: bool) -> String {
    if is_signature_u32(value) {
        return hide_u32(value, rng, uh);
    }
    if rng.next() % 2 == 0 {
        crate::numlit::hex(value, rng, uh)
    } else {
        value.to_string()
    }
}

fn hide_u32(value: u32, rng: &mut crate::rng::Rng, uh: bool) -> String {
    let bad = |x: u32| x == 0 || x == value || is_signature_u32(x);
    if rng.next() % 3 != 0 {
        let mut a = rng.next() as u32;
        while bad(a) || bad(a ^ value) {
            a = rng.next() as u32;
        }
        format!(
            "bxor({}, {})",
            crate::numlit::hex(a, rng, uh),
            crate::numlit::hex(a ^ value, rng, uh)
        )
    } else {
        let r = 1 + (rng.next() % 31) as u32;
        let mut a = rng.next() as u32;
        while bad(a) || bad(a.rotate_left(r) ^ value) {
            a = rng.next() as u32;
        }
        format!(
            "bxor(lrotate({}, {r}), {})",
            crate::numlit::hex(a, rng, uh),
            crate::numlit::hex(a.rotate_left(r) ^ value, rng, uh)
        )
    }
}

fn build_fingerprint(
    payload: &[u8],
    seed: u64,
    profile: bytecode::crypt::TargetProfile,
    flags: u64,
) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |b: u8| {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    payload.iter().for_each(|&b| mix(b));
    seed.to_le_bytes().iter().for_each(|&b| mix(b));
    mix(profile as u8);
    flags.to_le_bytes().iter().for_each(|&b| mix(b));
    h
}

fn crypto_decls(fp: u64, uh: bool) -> String {
    let mut rng = crate::rng::Rng::new(fp ^ 0x_5347_3143_5259_5000);
    let mut emit = |w: &[u32]| {
        w.iter()
            .map(|x| hide_u32(*x, &mut rng, uh))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let fixed = emit(&bytecode::crypt::FIXED);
    format!("local FIXED = {{ {fixed} }}")
}

fn b85dec_decl(seed: u64) -> String {
    let mut fam = cold_decoder::Family::for_domain(seed, 0x_4235_4445_4E43);
    let names = cold_decoder::Names {
        byte: "byte",
        char: "char",
        concat: "concat",
    };
    let (decode, result) = fam.emit(&names, "b85rev", "s");
    format!(
        "local b85rev = {{}}\nfor i = 0, 255 do b85rev[i] = 0 end\nlocal b85i = 0\nfor code = 33, 126 do if code ~= 34 and code ~= 92 and code ~= 93 and b85i < 85 then b85rev[code] = b85i b85i = b85i + 1 end end\nlocal function b85dec(s)\n{decode}\nreturn {result}\nend"
    )
}

fn ishard_decl(
    enc: &Encoding,
    used: &HashSet<Opcode>,
    seed: u64,
    fp: u64,
    uh: bool,
    instr_family_on: bool,
) -> String {
    let mut rng = crate::rng::Rng::new(fp ^ 0x_4953_4841_5244_4C00);
    let idom = plain_u32(bytecode::crypt::instr_patch_domain(seed), &mut rng, uh);
    let sdom = plain_u32(bytecode::crypt::sidecar_patch_domain(seed), &mut rng, uh);
    let cfabs = if bytecode::encoder::instr_family(seed, instr_family_on) == 1 {
        "\t\t\t\t\tlocal kk = KS[s + 1]\n\t\t\t\t\tinst[kk] = inst[kk] - (i + 1)\n"
    } else {
        ""
    };
    let mut entries: Vec<(u8, u8)> = bytecode::opcode::ALL
        .iter()
        .filter(|(op, _)| used.contains(op))
        .filter_map(|(op, _)| {
            let mut mask = 0u8;
            for slot in 0..3usize {
                if bytecode::opcode::patch_role(*op, slot) != bytecode::opcode::OperandRole::None {
                    mask |= 1 << slot;
                }
            }
            (mask != 0).then(|| (enc.phys(*op), mask))
        })
        .collect();
    entries.sort_unstable();
    let set = entries
        .iter()
        .map(|(c, m)| format!("[{c}] = {m}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut sentries: Vec<(u8, u16)> = bytecode::opcode::ALL
        .iter()
        .filter(|(op, _)| used.contains(op) && bytecode::superop::is_super(*op))
        .filter_map(|(op, _)| {
            let mut mask = 0u16;
            for j in 0..bytecode::superop::operand_count(*op) {
                if bytecode::opcode::patch_sidecar_role(*op, j)
                    != bytecode::opcode::OperandRole::None
                {
                    mask |= 1 << j;
                }
            }
            (mask != 0).then(|| (enc.phys(*op), mask))
        })
        .collect();
    sentries.sort_unstable();
    let sset = sentries
        .iter()
        .map(|(c, m)| format!("[{c}] = {m}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sbase = bytecode::crypt::SIDECAR_SLOT_BASE - 1;
    let cdom = plain_u32(
        bytecode::crypt::controlflow_patch_domain(seed),
        &mut rng,
        uh,
    );
    let mut centries: Vec<(u8, u8)> = bytecode::opcode::ALL
        .iter()
        .filter(|(op, _)| used.contains(op))
        .filter_map(|(op, _)| {
            let mut mask = 0u8;
            for slot in 0..3usize {
                if bytecode::opcode::patch_cf_role(*op, slot) != bytecode::opcode::OperandRole::None
                {
                    mask |= 1 << slot;
                }
            }
            (mask != 0).then(|| (enc.phys(*op), mask))
        })
        .collect();
    centries.sort_unstable();
    let cset = centries
        .iter()
        .map(|(c, m)| format!("[{c}] = {m}"))
        .collect::<Vec<_>>()
        .join(", ");
    let cfbase = bytecode::crypt::CONTROLFLOW_SLOT_BASE;
    format!(
        "local IPOK = {{ {set} }}\n\
         local ISOK = {{ {sset} }}\n\
         local CFPOK = {{ {cset} }}\n\
         local function ipatchRange(proto, a, b)\n\
         \tlocal code = proto[1]\n\
         \tlocal pk = bxor(genkey[4], proto[5])\n\
         \tpk = bxor(lrotate(pk, 9), {idom})\n\
         \tpk = bxor(lrotate(pk, 13), genkey[8])\n\
         \tlocal spk = bxor(genkey[4], proto[5])\n\
         \tspk = bxor(lrotate(spk, 9), {sdom})\n\
         \tspk = bxor(lrotate(spk, 13), genkey[8])\n\
         \tlocal cfk = bxor(genkey[4], proto[5])\n\
         \tcfk = bxor(lrotate(cfk, 9), {cdom})\n\
         \tcfk = bxor(lrotate(cfk, 13), genkey[8])\n\
         \tlocal KS = {{ KA, KB, KC }}\n\
         \tfor i = a, b do\n\
         \t\tlocal inst = code[i]\n\
         \t\tlocal m = IPOK[inst[KOP]]\n\
         \t\tif m then\n\
         \t\t\tfor s = 0, 2 do\n\
         \t\t\t\tif band(m, lshift(1, s)) ~= 0 then\n\
         \t\t\t\t\tlocal h = bxor(pk, lrotate(i, 5), lrotate(pk, s * 11 + 5))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 16))\n\
         \t\t\t\t\th = add32(h, lshift(h, 3))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 11))\n\
         \t\t\t\t\th = lrotate(h, 13)\n\
         \t\t\t\t\th = add32(h, pk)\n\
         \t\t\t\t\th = bxor(h, rshift(h, 15))\n\
         \t\t\t\t\th = add32(h, lshift(h, 7))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 17))\n\
         \t\t\t\t\tlocal f = bxor(h, rshift(h, 7), rshift(h, 14), rshift(h, 21), rshift(h, 28))\n\
         \t\t\t\t\tif band(f, 3) == 0 then\n\
         \t\t\t\t\t\tlocal k = KS[s + 1]\n\
         \t\t\t\t\t\tinst[k] = inst[k] - (1 + band(rshift(h, 4), 1023))\n\
         \t\t\t\t\tend\n\
         \t\t\t\tend\n\
         \t\t\tend\n\
         \t\tend\n\
         \t\tlocal sm = ISOK[inst[KOP]]\n\
         \t\tif sm then\n\
         \t\t\tlocal so = inst[KOPS]\n\
         \t\t\tfor j = 1, #so do\n\
         \t\t\t\tif band(sm, lshift(1, j - 1)) ~= 0 then\n\
         \t\t\t\t\tlocal h = bxor(spk, lrotate(i, 5), lrotate(spk, ({sbase} + j) * 11 + 5))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 16))\n\
         \t\t\t\t\th = add32(h, lshift(h, 3))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 11))\n\
         \t\t\t\t\th = lrotate(h, 13)\n\
         \t\t\t\t\th = add32(h, spk)\n\
         \t\t\t\t\th = bxor(h, rshift(h, 15))\n\
         \t\t\t\t\th = add32(h, lshift(h, 7))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 17))\n\
         \t\t\t\t\tlocal f = bxor(h, rshift(h, 7), rshift(h, 14), rshift(h, 21), rshift(h, 28))\n\
         \t\t\t\t\tif band(f, 3) == 0 then\n\
         \t\t\t\t\t\tso[j] = so[j] - (1 + band(rshift(h, 4), 1023))\n\
         \t\t\t\t\tend\n\
         \t\t\t\tend\n\
         \t\t\tend\n\
         \t\tend\n\
         \t\tlocal cm = CFPOK[inst[KOP]]\n\
         \t\tif cm then\n\
         \t\t\tfor s = 0, 2 do\n\
         \t\t\t\tif band(cm, lshift(1, s)) ~= 0 then\n\
         \t\t\t\t\tlocal h = bxor(cfk, lrotate(i, 5), lrotate(cfk, ({cfbase} + s) * 11 + 5))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 16))\n\
         \t\t\t\t\th = add32(h, lshift(h, 3))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 11))\n\
         \t\t\t\t\th = lrotate(h, 13)\n\
         \t\t\t\t\th = add32(h, cfk)\n\
         \t\t\t\t\th = bxor(h, rshift(h, 15))\n\
         \t\t\t\t\th = add32(h, lshift(h, 7))\n\
         \t\t\t\t\th = bxor(h, rshift(h, 17))\n\
         \t\t\t\t\tlocal f = bxor(h, rshift(h, 7), rshift(h, 14), rshift(h, 21), rshift(h, 28))\n\
         \t\t\t\t\tif band(f, 3) == 0 then\n\
         \t\t\t\t\t\tlocal k = KS[s + 1]\n\
         \t\t\t\t\t\tinst[k] = inst[k] - (1 + band(rshift(h, 4), 1023))\n\
         \t\t\t\t\tend\n\
{cfabs}\
         \t\t\t\tend\n\
         \t\t\tend\n\
         \t\tend\n\
         \tend\n\
         end\n\
         local function ipatch(proto)\n\
         \tipatchRange(proto, 1, #proto[1])\n\
         end"
    )
}

fn pdg_helper(fop: &str, fa: &str, fb: &str, fc: &str, fops: &str, fp: u64, uh: bool) -> String {
    let acc = |f: &str| {
        if f.starts_with('[') {
            format!("inst{f}")
        } else {
            format!("inst.{f}")
        }
    };
    let (op, a, b, c, ops) = (acc(fop), acc(fa), acc(fb), acc(fc), acc(fops));
    let mut rng = crate::rng::Rng::new(fp ^ 0x_5347_3150_4447_0000);
    let gr = hide_u32(0x9E3779B9, &mut rng, uh);
    format!(
        "local function _pdg(code)\n\
         \tlocal h = {gr}\n\
         \tfor i = 1, #code do\n\
         \t\tlocal inst = code[i]\n\
         \t\th = bxor(lrotate(h, 7), {op})\n\
         \t\tlocal so = {ops}\n\
         \t\tif so then\n\
         \t\t\tfor j = 1, #so do h = bxor(lrotate(h, 5), so[j] % 0x100000000) end\n\
         \t\telse\n\
         \t\t\th = bxor(lrotate(h, 5), {a} % 0x100000000)\n\
         \t\t\th = bxor(lrotate(h, 5), {b} % 0x100000000)\n\
         \t\t\th = bxor(lrotate(h, 5), {c} % 0x100000000)\n\
         \t\tend\n\
         \tend\n\
         \treturn h\n\
         end"
    )
}

fn vpg_helper(fop: &str, fa: &str, fb: &str, fc: &str, fops: &str, fp: u64, uh: bool) -> String {
    let acc = |f: &str| {
        if f.starts_with('[') {
            format!("inst{f}")
        } else {
            format!("inst.{f}")
        }
    };
    let (op, a, b, c, ops) = (acc(fop), acc(fa), acc(fb), acc(fc), acc(fops));
    let mut rng = crate::rng::Rng::new(fp ^ 0x_5647_5F50_4147_0000);
    let gr = hide_u32(0x9E3779B9, &mut rng, uh);
    let fold = format!(
        "\t\tlocal inst = code[i]\n\
         \t\th = bxor(lrotate(h, 7), {op})\n\
         \t\tlocal so = {ops}\n\
         \t\tif so then\n\
         \t\t\tfor j = 1, #so do h = bxor(lrotate(h, 5), so[j] % 0x100000000) end\n\
         \t\telse\n\
         \t\t\th = bxor(lrotate(h, 5), {a} % 0x100000000)\n\
         \t\t\th = bxor(lrotate(h, 5), {b} % 0x100000000)\n\
         \t\t\th = bxor(lrotate(h, 5), {c} % 0x100000000)\n\
         \t\tend\n\
         \t\ti = i + 1\n"
    );
    format!(
        "local function _vpgpage(code, from, count, expected)\n\
         \tlocal h = {gr}\n\
         \tlocal i = from\n\
         \tlocal e = from + count - 1\n\
         \twhile i <= e do\n\
         {fold}\
         \tend\n\
         \treturn h == expected\n\
         end\n\
         local function _vpg(code, pdg)\n\
         \tlocal nc = #code\n\
         \tlocal pi = 1\n\
         \tlocal i = 1\n\
         \twhile i <= nc do\n\
         \t\tlocal c = PGSZ\n\
         \t\tif i + c - 1 > nc then c = nc - i + 1 end\n\
         \t\tif not _vpgpage(code, i, c, pdg[pi]) then return false end\n\
         \t\ti = i + c\n\
         \t\tpi = pi + 1\n\
         \tend\n\
         \treturn true\n\
         end"
    )
}

fn ksite_helper(
    fop: &str,
    fb: &str,
    fc: &str,
    fops: &str,
    used: &HashSet<Opcode>,
    enc: &Encoding,
    fp: u64,
    uh: bool,
) -> String {
    let acc = |f: &str| {
        if f.starts_with('[') {
            format!("inst{f}")
        } else {
            format!("inst.{f}")
        }
    };
    let (opf, bf, cf, opsf) = (acc(fop), acc(fb), acc(fc), acc(fops));
    let mut rng = crate::rng::Rng::new(fp ^ 0x_5347_314B_5349_5400);
    let fnv = hide_u32(0x811C9DC5, &mut rng, uh);
    let gr = hide_u32(0x9E3779B9, &mut rng, uh);
    let mut super_pats: Vec<Vec<usize>> = Vec::new();
    let mut sel: std::collections::HashMap<usize, u8> = std::collections::HashMap::new();
    let mut maxc = 0usize;
    for (op, _) in bytecode::opcode::ALL {
        if !used.contains(op) {
            continue;
        }
        let c = enc.phys(*op) as usize;
        if bytecode::superop::is_super(*op) {
            let slots = bytecode::opcode::super_const_slots(*op);
            if slots.is_empty() {
                continue;
            }
            let idx = super_pats
                .iter()
                .position(|p| *p == slots)
                .unwrap_or_else(|| {
                    super_pats.push(slots.clone());
                    super_pats.len() - 1
                });
            sel.insert(c, 3 + idx as u8);
            maxc = maxc.max(c);
        } else if let Some(slot) = bytecode::opcode::const_slot(*op) {
            sel.insert(
                c,
                if matches!(slot, bytecode::opcode::KSlot::B) {
                    1
                } else {
                    2
                },
            );
            maxc = maxc.max(c);
        }
    }
    let head = format!(
        "local function ksite(p, op)\n\
         \tlocal t = bxor(lrotate({fnv}, 7), p)\n\
         \tt = bxor(lrotate(t, 5), op)\n\
         \tif t == 0 then t = {gr} end\n\
         \treturn t\n\
         end\n"
    );

    let gs_scan = if used.contains(&Opcode::GenSuper) {
        let gp = enc.phys(Opcode::GenSuper);
        format!(
            "op == {gp} then\n\t\t\tlocal so = {opsf}\n\t\t\tlocal nl = {bf}\n\t\t\tlocal nc = {cf}\n\t\t\tfor j = nl + 1, nl + nc do\n\t\t\t\tlocal ci = so[j] + 1\n\t\t\t\tif not tok[ci] then tok[ci] = ksite(i, op) end\n\t\t\tend\n\t\t"
        )
    } else {
        String::new()
    };
    if sel.is_empty() {
        if gs_scan.is_empty() {
            return format!("{head}local function ktoks(code)\n\treturn {{}}\nend\nlocal function ktokRange(proto, a, b)\nend");
        }
        let inner =
            format!("\t\tlocal inst = code[i]\n\t\tlocal op = {opf}\n\t\tif {gs_scan}end\n");
        return format!(
            "{head}local function ktoks(code)\n\tlocal tok = {{}}\n\tfor i = 1, #code do\n{inner}\tend\n\treturn tok\nend\n\
             local function ktokRange(proto, a, b)\n\tlocal code = proto[1]\n\tlocal tok = proto[10]\n\tfor i = a, b do\n{inner}\tend\nend"
        );
    }
    let kmix = (rng.next() % 20) as u32;
    let rule: String = (0..=maxc)
        .map(|c| {
            let s = sel.get(&c).copied().unwrap_or(0) as u32;
            let xs = ((c as u32).wrapping_mul(7).wrapping_add(kmix)) % 20;
            (71 + ((s + xs) % 20)) as u8 as char
        })
        .collect();
    let krule_names = word_carrier::Names {
        byte: "byte",
        char: "char",
        concat: "concat",
        sub: "sub",
        genv: "genv",
    };
    let krule_lit =
        word_carrier::emit_expr(rule.as_bytes(), rng.next(), 0x_4B52_554C_4531, &krule_names);
    let ksup_s: String = super_pats
        .iter()
        .flat_map(|p| {
            std::iter::once((71 + p.len() as u8) as char)
                .chain(p.iter().map(|&slot| (71 + slot as u8) as char))
        })
        .collect();
    let ktok_gs = if gs_scan.is_empty() {
        "if ".to_string()
    } else {
        format!("if {gs_scan}elseif ")
    };
    let ktok_inner = format!(
        "\t\tlocal inst = code[i]\n\
         \t\tlocal op = {opf}\n\
         \t\t{ktok_gs}op < #KRULE then\n\
         \t\t\tlocal r = (byte(KRULE, op + 1) - 71 - (op * 7 + {kmix}) % 20) % 20\n\
         \t\t\tif r == 1 then\n\
         \t\t\t\tlocal ci = {bf} + 1\n\
         \t\t\t\tif not tok[ci] then tok[ci] = ksite(i, op) end\n\
         \t\t\telseif r == 2 then\n\
         \t\t\t\tlocal ci = {cf} + 1\n\
         \t\t\t\tif not tok[ci] then tok[ci] = ksite(i, op) end\n\
         \t\t\telseif r > 2 then\n\
         \t\t\t\tlocal sl = KSUP[r - 2]\n\
         \t\t\t\tlocal so = {opsf}\n\
         \t\t\t\tfor j = 1, #sl do\n\
         \t\t\t\t\tlocal ci = so[byte(sl, j) - 71] + 1\n\
         \t\t\t\t\tif not tok[ci] then tok[ci] = ksite(i, op) end\n\
         \t\t\t\tend\n\
         \t\t\tend\n\
         \t\tend\n"
    );
    format!(
        "{head}\
         local KRULE = {krule_lit}\n\
         local KSUP_S = \"{ksup_s}\"\n\
         local KSUP = {{}}\n\
         do local p = 1 while p <= #KSUP_S do local ln = byte(KSUP_S, p) - 71 KSUP[#KSUP + 1] = sub(KSUP_S, p + 1, p + ln) p = p + 1 + ln end end\n\
         local function ktoks(code)\n\
         \tlocal tok = {{}}\n\
         \tfor i = 1, #code do\n\
         {ktok_inner}\
         \tend\n\
         \treturn tok\n\
         end\n\
         local function ktokRange(proto, a, b)\n\
         \tlocal code = proto[1]\n\
         \tlocal tok = proto[10]\n\
         \tfor i = a, b do\n\
         {ktok_inner}\
         \tend\n\
         end"
    )
}

const ALPHABET85: &[u8; 85] =
    b"!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghijklmnopqrstuvwx";

fn base85(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(4) * 5);
    for chunk in bytes.chunks(4) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).map_or(0, |&b| b as u32);
        let b2 = chunk.get(2).map_or(0, |&b| b as u32);
        let b3 = chunk.get(3).map_or(0, |&b| b as u32);
        let mut n = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        let mut group = [0u8; 5];
        for slot in group.iter_mut().rev() {
            *slot = ALPHABET85[(n % 85) as usize];
            n /= 85;
        }
        out.extend(group.iter().map(|&c| c as char));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode85(s: &str) -> Vec<u8> {
        let rev = |c: u8| ALPHABET85.iter().position(|&x| x == c).unwrap_or(0) as u64;
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 5 * 4);
        for g in b.chunks(5) {
            if g.len() < 5 {
                break;
            }
            let n = rev(g[0]) * 52_200_625
                + rev(g[1]) * 614_125
                + rev(g[2]) * 7_225
                + rev(g[3]) * 85
                + rev(g[4]);
            out.push((n >> 24 & 255) as u8);
            out.push((n >> 16 & 255) as u8);
            out.push((n >> 8 & 255) as u8);
            out.push((n & 255) as u8);
        }
        out
    }

    #[test]
    fn uv_access_helpers_vary_in_shape_without_leaking_roles() {
        let outs: Vec<String> = (0..24u64).map(uv_access).collect();
        for o in &outs {
            assert!(
                o.contains("local function uvget(uv)"),
                "uvget always present and called by GetUpval"
            );
            assert!(
                o.contains("local function uvset(uv, val)"),
                "uvset always present and called by SetUpval"
            );
            assert!(
                o.contains("uv[KOPEN]") && o.contains("uv[KV]"),
                "numeric-slot upvalue records preserved"
            );
            assert!(
                !o.contains(".open")
                    && !o.contains(".idx")
                    && !o.contains("Upval")
                    && !o.contains("Helper"),
                "no readable role/anchor names leak"
            );
        }
        let uniq: std::collections::HashSet<&String> = outs.iter().collect();
        assert!(
            uniq.len() >= 4,
            "uvget/uvset shapes must diversify across seeds: {} distinct",
            uniq.len()
        );
        assert_eq!(uv_access(7), uv_access(7), "deterministic per seed");
    }

    #[test]
    fn closure_setup_and_frame_diversify_preserving_dependency_order() {
        let setups: Vec<String> = (0..16u64).map(|seed| closure_setup(seed, false)).collect();
        let frames: Vec<String> = (0..16u64)
            .map(|__s| frame_init(__s, false, false))
            .collect();
        for s in &setups {
            assert!(
                s.contains("ipatch(proto)"),
                "first-touch repair call preserved (deobf anchor)"
            );
            assert!(
                s.contains("kget = kroute(proto[5])"),
                "per-proto accessor selection literal preserved (deobf anchor)"
            );
            assert!(
                s.contains("_vpg(code, proto[15])"),
                "child pages semantically verified before execution"
            );
            assert!(
                s.contains("proto[9]") && s.contains("proto[10]"),
                "both first-touch memo guards present"
            );
            assert!(
                s.contains("if not proto[9]")
                    || s.contains("if not kdg")
                    || s.contains("if kdg == nil"),
                "repair guard stays keyed on proto[9] being unset (ENCFUNC pre-set skip contract)"
            );

            let code_def = s.find("proto[1]").expect("code read");
            let ipatch = s.find("ipatch(proto)").expect("repair");
            let pdg = s.find("_pdg(code)").expect("digest");
            let ktoks = s.find("ktoks(code)").expect("tokens");
            let ce = s.find("cep(proto[5], cdg,").expect("epoch");
            let pk = s.find("mpk(proto[5], cdg, ce)").expect("meta key");
            let cha = s.find("chachaBlock(genkey").expect("proto key");
            assert!(
                code_def < pdg && code_def < ktoks,
                "code assigned before it is digested/tokenized"
            );
            assert!(
                ipatch < ktoks,
                "ipatch repairs before ktoks reads the repaired code"
            );
            assert!(
                pdg < ce && pdg < pk && pdg < cha,
                "digest precedes every key/epoch derived from kdg"
            );
            assert!(ce < pk, "epoch precedes the metadata key that consumes it");

            assert_eq!(
                s.matches("ipatch(proto)").count(),
                1,
                "repair emitted once (no double-patch)"
            );
            assert_eq!(s.matches("_pdg(code)").count(), 1, "digest emitted once");
            assert_eq!(
                s.matches("ktoks(code)").count(),
                1,
                "token derivation emitted once"
            );
            assert!(
                !s.contains("for "),
                "setup is straight-line: no constant-materialization loop (no dump seam)"
            );
            for junk in [
                "if true",
                "if false",
                "while true",
                "Setup",
                "Phase",
                "Variant",
                "decrypted",
            ] {
                assert!(
                    !s.contains(junk),
                    "no dead junk / readable phase name / dump seam: {junk:?}"
                );
            }
        }
        for f in &frames {
            assert!(
                f.contains("openuv"),
                "frame preserves the open-upvalue table handlers index"
            );
            assert!(
                f.contains("[-2] = ce") && f.contains("[-3] = pk"),
                "constant epoch/meta slots preserved in kc"
            );
            assert!(
                f.contains("isVararg") && f.contains("varargs"),
                "vararg spill preserved"
            );
            for junk in [
                "if true",
                "if false",
                "while true",
                "Frame",
                "Phase",
                "Variant",
            ] {
                assert!(
                    !f.contains(junk),
                    "no dead junk / readable phase name: {junk:?}"
                );
            }
        }
        let su: std::collections::HashSet<&String> = setups.iter().collect();
        let fu: std::collections::HashSet<&String> = frames.iter().collect();
        assert!(
            su.len() >= 12,
            "setup layout must diversify across seeds: {} distinct",
            su.len()
        );
        assert!(
            fu.len() >= 12,
            "frame layout must diversify across seeds: {} distinct",
            fu.len()
        );
        assert_eq!(
            closure_setup(3, false),
            closure_setup(3, false),
            "setup deterministic per seed"
        );
        assert_eq!(
            frame_init(3, false, false),
            frame_init(3, false, false),
            "frame deterministic per seed"
        );
    }

    #[test]
    fn root_entry_diversifies_stays_tail_call_and_has_no_named_closure_local() {
        let outs: Vec<String> = (0..24u64).map(root_entry).collect();
        let uniq: std::collections::HashSet<&String> = outs.iter().collect();
        assert!(
            uniq.len() >= 2,
            "root entry must vary across seeds: {} distinct",
            uniq.len()
        );
        for o in &outs {
            assert!(
                o.contains("makeClosure(mainProto, {})"),
                "root still builds+invokes the main closure"
            );
            assert!(
                o.trim_start().starts_with("return "),
                "root entry stays a tail return"
            );
            assert!(
                !o.contains("local "),
                "no clean named root-closure local (friend-autopsy seam)"
            );
        }
        assert_eq!(
            root_entry(9),
            root_entry(9),
            "root entry deterministic per seed"
        );
    }

    #[test]
    fn frame_capture_idiom_varies_across_seeds() {
        let frames: Vec<String> = (0..32u64)
            .map(|__s| frame_init(__s, false, false))
            .collect();
        let pack = frames.iter().filter(|f| f.contains("pack(...)")).count();
        assert!(
            pack > 0 && pack < frames.len(),
            "both arg-capture idioms must appear across seeds: pack={pack}/32"
        );
        for f in &frames {
            assert!(
                f.contains("select(sH, ...)"),
                "arg count still comes from select over varargs"
            );
        }
    }

    #[test]
    fn alphabet_is_delimiter_safe() {
        assert_eq!(ALPHABET85.len(), 85);
        assert!(!ALPHABET85
            .iter()
            .any(|&c| c == b']' || c == b'\\' || c == b'"' || c == b'\n'));
        let mut seen = std::collections::HashSet::new();
        assert!(
            ALPHABET85.iter().all(|&c| seen.insert(c)),
            "alphabet chars must be distinct"
        );
    }

    #[test]
    fn base85_round_trips_byte_perfect() {
        for len in [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 100, 257, 1000] {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(37).wrapping_add(11)) as u8)
                .collect();
            let enc = base85(&bytes);
            assert_eq!(enc.len() % 5, 0, "whole 5-char groups (len {len})");
            assert!(
                enc.bytes().all(|c| ALPHABET85.contains(&c)),
                "non-alphabet char (len {len})"
            );
            assert!(
                !enc.bytes()
                    .any(|c| c == b']' || c == b'\\' || c == b'"' || c == b'\n'),
                "excluded delimiter char emitted (len {len})"
            );
            let dec = decode85(&enc);
            assert_eq!(&dec[..len], &bytes[..], "round-trip mismatch at len {len}");
            assert!(dec.len() - len < 4, "pad must be < 4 bytes (len {len})");
        }
    }

    #[test]
    fn is_signature_flags_the_markers() {
        for m in [
            0x9E37_79B9u32,
            0x811C_9DC5,
            0x6170_7865,
            0x3320_646E,
            0x7962_2D32,
            0x6B20_6574,
        ] {
            assert!(is_signature_u32(m), "{m:#x} must be flagged");
        }
        assert!(!is_signature_u32(0x1234_5678));
    }

    #[test]
    fn hide_u32_compact_and_never_leaks_signatures() {
        let vals = [
            0x9E37_79B9u32,
            0x811C_9DC5,
            0x6170_7865,
            0x3320_646E,
            0x7962_2D32,
            0x6B20_6574,
            2_654_435_769,
            0xDEAD_BEEF,
        ];
        for &v in &vals {
            for seed in 0..300u64 {
                let s = hide_u32(v, &mut crate::rng::Rng::new(seed), false);
                let low = s.to_lowercase();
                assert!(
                    !s.contains('+') && !s.contains('-'),
                    "not an arithmetic split: {s}"
                );
                assert!(s.starts_with("bxor("), "compact bxor form: {s}");
                assert!(
                    !low.contains(&format!("{v:x}")) && !s.contains(&v.to_string()),
                    "leaked value {v:#x}: {s}"
                );
                assert!(
                    !low.contains("9e3779b9") && !s.contains("2654435769"),
                    "golden-ratio marker in {s}"
                );
                assert!(!low.contains("811c9dc5"), "FNV marker in {s}");
                for sig in ["61707865", "3320646e", "79622d32", "6b206574"] {
                    assert!(!low.contains(sig), "ChaCha sigma marker {sig} in {s}");
                }
            }
        }
    }

    #[test]
    fn plain_u32_compact_and_disguises_signatures() {
        for seed in 0..128u64 {
            let mut r = crate::rng::Rng::new(seed);
            for &v in &[0x9E37_79B9u32, 0x811C_9DC5, 0x6170_7865] {
                let s = plain_u32(v, &mut r, false);
                let low = s.to_lowercase();
                assert!(
                    !low.contains(&format!("{v:x}")) && !s.contains(&v.to_string()),
                    "plain_u32 leaked signature {v:#x}: {s}"
                );
            }
            let s = plain_u32(0x1234_5678, &mut r, false);
            assert!(
                s == "0x12345678" || s == "305419896",
                "ordinary value is one compact literal: {s}"
            );
            assert!(
                !s.contains('+') && !s.contains('-') && !s.contains("bxor"),
                "ordinary value has no arithmetic/disguise: {s}"
            );
        }
    }

    fn parse_num_t(s: &str) -> usize {
        let s = s.trim();
        if let Some(h) = s.strip_prefix("0x") {
            usize::from_str_radix(&h.replace('_', ""), 16).unwrap()
        } else if let Some(b) = s.strip_prefix("0b") {
            usize::from_str_radix(&b.replace('_', ""), 2).unwrap()
        } else {
            s.replace('_', "").parse().unwrap()
        }
    }

    #[test]
    fn frame_const_reuse_wrapper_has_unambiguous_scalar_only_insertion() {
        let plain = frame_const_reuse_frame(false);
        assert!(
            !plain.contains("local fcm"),
            "fcm is a persistent per-closure cache, not re-created per frame"
        );
        assert!(
            plain.contains("fcm[i]"),
            "wrapper reads/writes the persistent cache"
        );
        assert!(plain.contains("v ~= nil"));
        assert!(plain.contains("not dead and kx and not kx[i]"));
        assert!(plain.contains("t == \"string\""));
        assert!(plain.contains("t == \"number\""));
        assert!(
            !plain.contains("table\"")
                && !plain.contains("function\"")
                && !plain.contains("userdata\"")
        );
        let prof = frame_const_reuse_frame(true);
        assert!(
            !prof.contains("local fcm"),
            "profiler wrapper also uses the persistent cache"
        );
        assert!(prof.find("dead and not d0").unwrap() < prof.find("fcm[i] = v").unwrap());
        for counter in [
            "PROF_KCALL",
            "PROF_KSHIT",
            "PROF_KNHIT",
            "PROF_KSMISS",
            "PROF_KNMISS",
            "PROF_KCHIT",
            "PROF_KNAUTH",
            "PROF_KSAUTH",
            "PROF_KFLUSH",
            "PROF_KSINS",
            "PROF_KNINS",
            "PROF_KFAIL",
            "PROF_KFRAME",
            "PROF_KMAX",
        ] {
            assert!(prof.contains(counter));
        }
    }

    #[test]
    fn persistent_const_cache_is_closure_scoped_not_per_frame() {
        assert!(
            closure_setup(1, true).contains("fcm = {}"),
            "fcm materialization cache initialized once per closure"
        );
        assert!(
            closure_setup_paged(1, true).contains("fcm = {}"),
            "same for the paged closure setup"
        );
        assert!(
            !closure_setup(1, false).contains("fcm = {}"),
            "no persistent cache when frame-const-reuse is off"
        );
        assert!(
            !frame_const_reuse_frame(false).contains("local fcm"),
            "frame init must not reset the persistent cache"
        );
        assert!(!frame_const_reuse_frame(true).contains("local fcm"));
    }
}
