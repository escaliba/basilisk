use std::path::Path;

use anyhow::{anyhow, Context, Result};

pub mod leakscan;

pub use bytecode::crypt::TargetProfile;
pub use bytecode::format::FORMAT_VERSION;
pub use frontend::audit::SensitiveOpts;
pub use passes::semopt::{OptMode as Optimizer, OptReport};
pub use surface::{self, SurfaceConfig, UnicodeTheme as SurfaceTheme};
pub use vmgen::shell_family::ShellFamily;
pub use vmgen::{FrameConstReuseMode, PolyStream, SurfaceVolume};

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Passthrough,
    Roundtrip,
    Virtualize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HotCallbackPolicy {
    Off,
    #[default]
    Report,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum StringFragMode {
    Off,
    Selective,
    #[default]
    Full,
}

pub const SELECTIVE_FRAG_BUDGET: usize = 512;
pub const SEMGROUP_CAPACITY: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PropKeyMode {
    #[default]
    Off,
    Internal,
}

pub struct Config {
    pub seed: u64,
    pub mode: Mode,
    pub flatten: bool,
    pub opaque: bool,
    pub junk: bool,
    pub fuse: bool,
    pub minify: bool,
    pub compress: bool,

    pub anti_envlog: bool,

    pub hard_dispatch: bool,

    pub surface: bool,

    pub heavy: SurfaceVolume,

    pub aggressive: bool,
    pub sensitive: SensitiveOpts,

    pub profile: bytecode::crypt::TargetProfile,

    pub loadstring_canary: bool,

    pub lph_collapse: bool,
    pub line_info: bool,
    pub strip_source_names: bool,
    pub poly_stream: PolyStream,

    pub optimization: u8,

    pub static_env: bool,

    pub runtime_profile_markers: bool,
    pub frame_const_reuse: FrameConstReuseMode,
    pub hot_callback_policy: HotCallbackPolicy,
    pub ablate_fragment: bool,
    pub hot_light: bool,

    pub explicit_optin: bool,
    pub shell_probe: bool,
    pub underscore_hex_numlit: bool,

    pub shell_family: Option<ShellFamily>,

    pub notices: NoticeConfig,
    pub stateful_recovery: bool,
    pub stateful_framing: bool,
    pub string_frag_mode: StringFragMode,
    pub property_key_rename: PropKeyMode,
    pub semantic_family: bool,
    pub instruction_family: bool,
    pub state_family: bool,
    pub microir: bool,
    pub semgroup: bool,
}

#[derive(Clone, Debug, Default)]
pub struct NoticeConfig {
    pub enabled: bool,

    pub custom: Vec<String>,

    pub label: Option<String>,
}

impl NoticeConfig {
    pub fn is_active(&self) -> bool {
        self.enabled || !self.custom.is_empty()
    }

    pub fn resolve_pool(&self) -> Vec<String> {
        let mut pool: Vec<String> = Vec::new();
        if self.enabled {
            pool.extend(vmgen::notices::BUILTIN_POOL.iter().map(|s| s.to_string()));
        }
        pool.extend(self.custom.iter().cloned());
        pool
    }

    pub fn validate(&self) -> Result<()> {
        for (i, s) in self.custom.iter().enumerate() {
            if s.is_empty() {
                return Err(anyhow!(
                    "artifact notice #{} is empty; provide non-empty text",
                    i + 1
                ));
            }
            if s.len() > vmgen::notices::MAX_STRING_BYTES {
                return Err(anyhow!(
                    "artifact notice #{} is {} bytes, over the {}-byte limit",
                    i + 1,
                    s.len(),
                    vmgen::notices::MAX_STRING_BYTES
                ));
            }
        }
        let total = self.resolve_pool().len();
        if total > vmgen::notices::MAX_POOL {
            return Err(anyhow!(
                "artifact notice pool has {total} entries, over the {}-entry limit",
                vmgen::notices::MAX_POOL
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProgressStage {
    Read,
    Lower,
    Transform,
    Encode,
    GenerateVm,
    Minify,
    Write,
    Done,
}

impl ProgressStage {
    pub const ALL: [ProgressStage; 8] = [
        ProgressStage::Read,
        ProgressStage::Lower,
        ProgressStage::Transform,
        ProgressStage::Encode,
        ProgressStage::GenerateVm,
        ProgressStage::Minify,
        ProgressStage::Write,
        ProgressStage::Done,
    ];
    pub const COUNT: usize = Self::ALL.len();

    pub fn index(self) -> usize {
        self as usize
    }

    pub fn label(self) -> &'static str {
        match self {
            ProgressStage::Read => "read input",
            ProgressStage::Lower => "parse/lower",
            ProgressStage::Transform => "transform passes",
            ProgressStage::Encode => "encode payload",
            ProgressStage::GenerateVm => "generate vm",
            ProgressStage::Minify => "minify",
            ProgressStage::Write => "write output",
            ProgressStage::Done => "done",
        }
    }

    pub fn percent(self) -> u32 {
        ((self.index() as u32 + 1) * 100) / Self::COUNT as u32
    }

    pub fn from_index(i: usize) -> ProgressStage {
        Self::ALL.get(i).copied().unwrap_or(ProgressStage::Done)
    }
}

pub struct ProgressEvent {
    pub stage: ProgressStage,
    pub label: &'static str,
    pub current: Option<u64>,
    pub total: Option<u64>,
}

pub type ProgressFn<'a> = dyn FnMut(ProgressEvent) + 'a;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuildStats {
    pub protos: usize,
    pub instructions: usize,
    pub constants: usize,
    pub string_constants: usize,
    pub opcode_kinds: usize,
    pub poly_morphable: usize,
    pub encfuncs: usize,
    pub natives: usize,
    pub compress_requested: bool,
    pub compress_selected: bool,
    pub raw_artifact_bytes: usize,
    pub compressed_artifact_bytes: usize,
    pub serialized_total_bytes: usize,
    pub serialized_code_bytes: usize,
    pub serialized_const_bytes: usize,
    pub serialized_number_const_bytes: usize,
    pub serialized_string_const_bytes: usize,
    pub serialized_other_const_bytes: usize,
    pub serialized_upvalue_bytes: usize,
    pub serialized_proto_meta_bytes: usize,
    pub serialized_lineinfo_bytes: usize,
    pub serialized_section_header_bytes: usize,
    pub serialized_act_program_bytes: usize,
    pub serialized_aead_tag_bytes: usize,
    pub serialized_child_proto_bytes: usize,
    pub serialized_const_count: usize,
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
    pub base85_payload_chars: usize,
    pub base85_overhead_bytes: usize,
    pub root_proto_instructions: usize,
    pub deferred_instructions: usize,
    pub hot_callback_total: usize,
    pub hot_callback_input: usize,
    pub hot_callback_render: usize,
    pub hot_callback_event: usize,
    pub hot_callback_generic: usize,
    pub hot_callback_instructions: usize,
    pub hot_callback_top_instructions: usize,
    pub native_marked_callbacks: usize,
    pub native_marked_input: usize,
    pub native_marked_render: usize,
    pub native_marked_event: usize,
    pub native_marked_generic: usize,
    pub native_total_bytes: usize,
    pub native_literal_bytes: usize,
}

fn keep_compressed(compressed_len: usize, raw_len: usize) -> bool {
    compressed_len < raw_len
}

fn report(progress: &mut Option<&mut ProgressFn<'_>>, stage: ProgressStage) {
    if let Some(cb) = progress.as_deref_mut() {
        cb(ProgressEvent {
            stage,
            label: stage.label(),
            current: None,
            total: None,
        });
    }
}

#[cfg(feature = "compile-gate")]
pub fn luau_compile_gate(artifact: &str) -> Result<()> {
    let lua = mlua::Lua::new();
    match lua
        .load(artifact)
        .set_name("basilisk-artifact")
        .into_function()
    {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!(
            "final Luau compile gate rejected the emitted artifact: {e}"
        )),
    }
}

// no embedded Luau without compile-gate (e.g. wasm)
#[cfg(not(feature = "compile-gate"))]
pub fn luau_compile_gate(_artifact: &str) -> Result<()> {
    Ok(())
}

pub fn run(input: &Path, output: &Path, config: &Config) -> Result<()> {
    run_with_progress(input, output, config, None)
}

pub fn run_with_progress(
    input: &Path,
    output: &Path,
    config: &Config,
    progress: Option<&mut ProgressFn<'_>>,
) -> Result<()> {
    run_inner(
        input,
        output,
        config,
        progress,
        None,
        Optimizer::Off,
        false,
        &surface::SurfaceConfig::default(),
    )
}

pub fn run_capturing_stats(
    input: &Path,
    output: &Path,
    config: &Config,
    progress: Option<&mut ProgressFn<'_>>,
    stats: &mut Option<BuildStats>,
) -> Result<()> {
    let mut collected = BuildStats::default();
    run_inner(
        input,
        output,
        config,
        progress,
        Some(&mut collected),
        Optimizer::Off,
        false,
        &surface::SurfaceConfig::default(),
    )?;
    *stats = Some(collected);
    Ok(())
}

pub fn run_capturing_stats_optimized(
    input: &Path,
    output: &Path,
    config: &Config,
    optimizer: Optimizer,
    progress: Option<&mut ProgressFn<'_>>,
    stats: &mut Option<BuildStats>,
    vm_traps: bool,
    surface: &surface::SurfaceConfig,
) -> Result<()> {
    let mut collected = BuildStats::default();
    run_inner(
        input,
        output,
        config,
        progress,
        Some(&mut collected),
        optimizer,
        vm_traps,
        surface,
    )?;
    *stats = Some(collected);
    Ok(())
}

fn surface_catalog_path() -> std::path::PathBuf {
    match std::env::var("BASIL_MEME_CATALOG") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => std::path::PathBuf::from("assets/meme_strings.toml"),
    }
}

fn run_inner(
    input: &Path,
    output: &Path,
    config: &Config,
    mut progress: Option<&mut ProgressFn<'_>>,
    stats: Option<&mut BuildStats>,
    optimizer: Optimizer,
    vm_traps: bool,
    surface: &surface::SurfaceConfig,
) -> Result<()> {
    report(&mut progress, ProgressStage::Read);
    let source =
        std::fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
    let result = build_artifact(
        source, config, progress, stats, optimizer, vm_traps, surface,
    )?;
    std::fs::write(output, result).with_context(|| format!("writing {}", output.display()))?;
    Ok(())
}

/// Obfuscate `source` and return the artifact text (no filesystem). The string-in/
/// string-out core shared by the CLI build path and the wasm facade.
#[allow(clippy::too_many_arguments)]
pub fn obfuscate_str(
    source: &str,
    config: &Config,
    optimizer: Optimizer,
    vm_traps: bool,
    surface: &surface::SurfaceConfig,
) -> Result<String> {
    build_artifact(
        source.to_string(),
        config,
        None,
        None,
        optimizer,
        vm_traps,
        surface,
    )
}

/// A baseline `Config` with every optional transform off, suitable as a starting point
/// (e.g. the browser playground) before flipping the toggles a caller wants on.
pub fn default_config(seed: u64) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: false,
        junk: false,
        fuse: false,
        minify: false,
        compress: false,
        anti_envlog: false,
        hard_dispatch: false,
        surface: false,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile: TargetProfile::CliTest,
        loadstring_canary: false,
        lph_collapse: false,
        line_info: true,
        strip_source_names: false,
        poly_stream: PolyStream::Off,
        optimization: 1,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: Default::default(),
        hot_callback_policy: Default::default(),
        ablate_fragment: false,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
        shell_family: None,
        notices: NoticeConfig::default(),
        stateful_recovery: false,
        stateful_framing: false,
        string_frag_mode: StringFragMode::Full,
        property_key_rename: PropKeyMode::Off,
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_artifact(
    source: String,
    config: &Config,
    mut progress: Option<&mut ProgressFn<'_>>,
    mut stats: Option<&mut BuildStats>,
    optimizer: Optimizer,
    vm_traps: bool,
    surface: &surface::SurfaceConfig,
) -> Result<String> {
    if config.sensitive.audit {
        eprint!("{}", sensitive_audit(&source)?);
    }
    if config.static_env {
        let names = env_introspection(&source).unwrap_or_default();
        if !names.is_empty() {
            eprintln!(
                "warning: --static-env is set but this script uses {} — Basilisk applies no environment-assuming optimizations in this build, but do not rely on static-env optimizations for a script that swaps function environments",
                names.join("/")
            );
        }
    }
    surface.validate().map_err(|e| anyhow!(e))?;
    let surface_plan = if surface.is_off() {
        None
    } else {
        let catalog = if surface.memes {
            match &surface.meme_strings {
                Some(list) => Some(surface::meme::from_strings(list).map_err(|e| anyhow!(e))?),
                None => Some(surface::meme::load(&surface_catalog_path()).map_err(|e| anyhow!(e))?),
            }
        } else {
            None
        };
        Some(
            surface
                .resolve(config.seed, catalog.as_ref())
                .map_err(|e| anyhow!(e))?,
        )
    };
    let result = match config.mode {
        Mode::Passthrough => source,
        Mode::Roundtrip => roundtrip(&source)?,
        Mode::Virtualize => virtualize_full_line_impl(
            &source,
            config.seed,
            config.flatten,
            config.junk,
            config.opaque,
            config.fuse,
            config.minify,
            config.compress,
            config.anti_envlog,
            config.hard_dispatch,
            config.surface,
            config.heavy,
            if config.aggressive {
                3
            } else {
                config.optimization
            },
            config.sensitive,
            config.profile,
            config.loadstring_canary,
            config.lph_collapse,
            config.line_info,
            config.strip_source_names,
            config.poly_stream,
            config.runtime_profile_markers,
            config.frame_const_reuse,
            config.hot_callback_policy != HotCallbackPolicy::Off,
            config.ablate_fragment,
            config.string_frag_mode,
            config.hot_light,
            config.explicit_optin,
            config.shell_probe,
            config.underscore_hex_numlit,
            config.shell_family,
            &config.notices,
            progress.as_deref_mut(),
            stats.as_deref_mut(),
            optimizer,
            config.stateful_recovery,
            config.stateful_framing,
            config.property_key_rename,
            config.semantic_family,
            config.instruction_family,
            config.state_family,
            config.microir,
            config.semgroup,
            vm_traps,
            surface_plan.as_ref(),
        )?,
    };
    if config.mode == Mode::Virtualize {
        if let Some(plan) = surface_plan.as_ref() {
            if plan.types.is_on() && !surface::types::source_has_type_noise(&result) {
                anyhow::bail!(
                    "surface types: type-noise enabled but no generated type alias survived to the final artifact"
                );
            }
        }
    }
    luau_compile_gate(&result)?;
    report(&mut progress, ProgressStage::Write);
    report(&mut progress, ProgressStage::Done);
    Ok(result)
}

pub fn roundtrip(source: &str) -> Result<String> {
    let module = frontend::lower_str(source)?;
    Ok(ir::emit(&module))
}

#[derive(Debug, Clone)]
pub struct ReviewOutput {
    pub optimized_luau: String,
    pub bytes_before: usize,
    pub bytes_after: usize,
    pub opt_level: u8,
    pub input_sha256: String,
}

pub fn review_source(source: &str, opt_level: u8) -> Result<ReviewOutput> {
    let mut module = frontend::lower_str(source)?;
    frontend::optin::extract(&mut module).map_err(|e| anyhow!("{e}"))?;
    let before = ir::emit(&module);
    passes::optimize_with_level(&mut module, opt_level);
    let after = ir::emit(&module);
    let hex: String = bytecode::sha256::digest(source.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(ReviewOutput {
        bytes_before: before.len(),
        bytes_after: after.len(),
        opt_level,
        input_sha256: hex,
        optimized_luau: after,
    })
}

pub fn env_introspection(source: &str) -> Result<Vec<&'static str>> {
    let module = frontend::lower_str(source)?;
    Ok(frontend::env_audit::scan(&module))
}

pub fn verify_streaming_digests(source: &str, config: &Config) -> Result<usize> {
    let opt_level = if config.aggressive {
        3
    } else {
        config.optimization
    };
    let (mut proto, _natives, _hash, encfuncs, _hot, _) = lower_and_compile(
        source,
        config.seed,
        config.heavy != SurfaceVolume::Off,
        opt_level,
        &config.sensitive,
        config.line_info,
        config.strip_source_names,
        config.surface,
        false,
        config.ablate_fragment,
        config.string_frag_mode,
        config.property_key_rename,
        config.hot_light,
        config.explicit_optin,
        passes::semopt::OptMode::Off,
    )?;
    proto = apply_structural_passes(
        proto,
        config.seed,
        config.flatten,
        config.junk,
        config.opaque,
        config.fuse,
        config.stateful_recovery,
        config.microir,
    );
    if config.semgroup {
        let (p2, _cat) = passes::semgroup::fuse_semgroups(&proto, SEMGROUP_CAPACITY);
        proto = p2;
    }
    let enc = bytecode::encoding::Encoding::from_seed(config.seed);
    let envdig = bytecode::crypt::env_fingerprint_digest(config.seed, config.profile);
    let genkey = bytecode::encoder::payload_genkey(
        &proto,
        config.seed,
        &enc,
        config.anti_envlog,
        config.profile,
        config.loadstring_canary,
    );
    let kmode = vmgen::kepoch_mode(config.poly_stream);
    let fmt = bytecode::format::FormatConfig {
        version: bytecode::format::FORMAT_VERSION,
        line_info: config.line_info,
        kmode,
        frame_const_probe: config.frame_const_reuse.enabled(),
        framing: config.stateful_framing,
        sem_family: config.semantic_family,
        instr_family: config.instruction_family,
        state_family: config.state_family,
        vm_traps: bytecode::crypt::vm_traps_active(),
        d1: config.stateful_recovery,
    };

    let payload = bytecode::encoder::serialize_encrypted_full(
        &proto,
        config.seed,
        &enc,
        config.anti_envlog,
        config.profile,
        config.loadstring_canary,
        &fmt,
        None,
    );
    let mut verified = bytecode::streamdigest::verify_serialized_digests(
        &proto,
        &payload,
        12,
        config.seed,
        &envdig,
        &genkey,
        &enc,
        true,
        kmode,
        config.stateful_framing,
    )
    .map_err(|e| anyhow!("main-tree streaming digest: {e}"))?;

    for (id, ef) in encfuncs.iter().enumerate() {
        let inner = bytecode::compile::compile_func(&ef.body)
            .map_err(|e| anyhow!("ENCFUNC {id} compile: {e}"))?;
        let inner = passes::shuffle_structure(&inner, config.seed);
        let inner_bytes =
            bytecode::encoder::serialize_inner(&inner, &genkey, &enc, config.seed, &envdig, &fmt);
        verified += bytecode::streamdigest::verify_serialized_digests(
            &inner,
            &inner_bytes,
            12,
            config.seed,
            &envdig,
            &genkey,
            &enc,
            false,
            bytecode::kepoch::KepochMode::Off,
            config.stateful_framing,
        )
        .map_err(|e| anyhow!("ENCFUNC {id} inner streaming digest: {e}"))?;
    }
    Ok(verified)
}

fn lower_and_compile(
    source: &str,
    seed: u64,
    heavy: bool,
    opt_level: u8,
    sensitive: &frontend::audit::SensitiveOpts,
    line_info: bool,
    strip_source_names: bool,
    lura_surface: bool,
    detect_hot: bool,
    ablate_fragment: bool,
    string_frag_mode: StringFragMode,
    property_key_rename: PropKeyMode,
    hot_light: bool,
    explicit_optin: bool,
    optimizer: passes::semopt::OptMode,
) -> Result<(
    bytecode::Proto,
    Vec<ir::FuncBody>,
    bool,
    Vec<ir::EncFunc>,
    ir::hot_callbacks::HotSummary,
    Vec<ir::Precheck>,
)> {
    let mut module = frontend::lower_str_opt(source, line_info)?;

    let optin = frontend::optin::extract(&mut module).map_err(|e| anyhow!("{e}"))?;
    if !optin.is_empty() && !explicit_optin {
        return Err(anyhow!(
            "the source contains explicit opt-in markers but --experimental-explicit-optin is not set; \
             refusing to silently ignore them"
        ));
    }

    passes::optimize_with_level(&mut module, opt_level);
    let optreport = passes::semopt::optimize(&mut module, optimizer);
    if !matches!(optimizer, passes::semopt::OptMode::Off) {
        eprintln!(
            "basilisk_optimizer mode={} functions_examined={} const_propagated={} dead_locals_removed={} self_assigns_removed={} string_builders={} passes_run={} ir_ops_before={} ir_ops_after={} ir_ops_removed={}",
            optreport.mode,
            optreport.functions_examined,
            optreport.const_propagated,
            optreport.dead_locals_removed,
            optreport.self_assigns_removed,
            optreport.string_builders,
            optreport.passes_run,
            optreport.ir_ops_before,
            optreport.ir_ops_after,
            optreport.ir_ops_before.saturating_sub(optreport.ir_ops_after),
        );
    }

    if sensitive.any() {
        frontend::audit::scan(&module, sensitive)?;
    }
    let mut module = frontend::macros::expand(module, seed)?;
    frontend::inline::apply(&mut module).map_err(|e| anyhow!("{e}"))?;
    let hot = if detect_hot || hot_light {
        ir::hot_callbacks::annotate(&mut module)
    } else {
        ir::hot_callbacks::HotSummary::default()
    };
    passes::assign_stable_ids(&mut module);

    if explicit_optin && !optin.is_empty() {
        let resolved = frontend::optin::resolve(&module, &optin).map_err(|e| anyhow!("{e}"))?;
        for scan in &resolved.scans {
            let mut owners = [scan.producer, scan.consumer];
            owners.sort();
            frontend::state_cell::apply(&mut module, &scan.scalar, &owners, scan.producer)
                .map_err(|e| anyhow!("explicit private scan: {e}"))?;
            frontend::state_cell::extract_global_native(&mut module, scan.matcher)
                .map_err(|e| anyhow!("explicit private scan matcher: {e}"))?;
        }
        for (_, id, _) in &resolved.leaves {
            frontend::lookup_native::extract_at(&mut module, *id)
                .map_err(|e| anyhow!("explicit native leaf: {e}"))?;
        }
    }
    if strip_source_names {
        frontend::sanitize::strip_source_names(&mut module, seed);
    }
    if matches!(property_key_rename, PropKeyMode::Internal) {
        let st = frontend::tblscramble::rename_internal(&mut module, seed);
        if std::env::var_os("BASIL_PROPKEY_STATS").is_some() {
            eprintln!(
                "basilisk_propkey domains={} renamed_domains={} candidate_keys={} renamed_keys={} skipped_escape={} skipped_dynamic={} skipped_reflective={} skipped_external={} skipped_other={}",
                st.domains, st.renamed_domains, st.candidate_keys, st.renamed_keys,
                st.skipped_escape, st.skipped_dynamic, st.skipped_reflective, st.skipped_external, st.skipped_other
            );
        }
    }

    let frag_mode = if ablate_fragment {
        StringFragMode::Off
    } else {
        string_frag_mode
    };
    match frag_mode {
        StringFragMode::Off => {}
        StringFragMode::Full => {
            passes::fragment_strings_scoped(&mut module, seed, heavy, hot_light)
        }
        StringFragMode::Selective => {
            let _ = passes::fragment_strings_selective(
                &mut module,
                seed,
                heavy,
                hot_light,
                SELECTIVE_FRAG_BUDGET,
            );
        }
    }
    if lura_surface {
        frontend::native_strings::obfuscate_natives(&mut module, seed);
    }
    let hash_helper = module.hash_helper;
    let proto = bytecode::compile(&module).map_err(|e| anyhow!("compile error: {e}"))?;
    Ok((
        proto,
        module.natives,
        hash_helper,
        module.encfuncs,
        hot,
        module.prechecks,
    ))
}

fn apply_structural_passes(
    proto: bytecode::Proto,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    d1: bool,
    microir: bool,
) -> bytecode::Proto {
    let p = apply_structural_passes_before_shuffle(
        proto, seed, flatten, junk, opaque, fuse, d1, microir,
    );
    if d1 {
        p
    } else {
        passes::shuffle_structure(&p, seed)
    }
}

fn apply_structural_passes_before_shuffle(
    mut proto: bytecode::Proto,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    d1: bool,
    microir: bool,
) -> bytecode::Proto {
    if d1 {
        proto = bytecode::blockstate::d1_prepare(&proto);
        proto = passes::flatten_d1(&proto, seed);
        return proto;
    }
    if flatten {
        proto = passes::flatten(&proto, seed);
    }
    if junk {
        proto = passes::junk(&proto, seed);
    }
    if opaque {
        proto = passes::opaque(&proto, seed);
    }

    if flatten {
        proto = passes::flat_fuse(&proto);
    }
    if fuse {
        proto = passes::fuse(&proto, seed);
    }

    proto = passes::synonymize(&proto, seed);
    if microir {
        proto = passes::lower_microir(&proto, seed);
    }

    proto = passes::pad_decoys(&proto, seed);
    proto
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCallbackDetail {
    pub category: ir::HotCat,
    pub instructions: usize,
    pub constants: usize,
    pub string_constants: usize,
}

fn collect_hot_details(p: &bytecode::Proto, out: &mut Vec<HotCallbackDetail>) {
    if let Some(cat) = p.hot_callback {
        out.push(HotCallbackDetail {
            category: cat,
            instructions: p.code.len(),
            constants: p.consts.len(),
            string_constants: p
                .consts
                .iter()
                .filter(|c| matches!(c, bytecode::Const::Str(_)))
                .count(),
        });
    }
    for c in &p.protos {
        collect_hot_details(c, out);
    }
}

pub fn hot_callback_detail(source: &str, config: &Config) -> Result<Vec<HotCallbackDetail>> {
    let (proto, _natives, _hash, _enc, _nm, _) = lower_and_compile(
        source,
        config.seed,
        config.heavy != SurfaceVolume::Off,
        config.optimization,
        &config.sensitive,
        config.line_info,
        config.strip_source_names,
        config.surface,
        true,
        config.ablate_fragment,
        config.string_frag_mode,
        config.property_key_rename,
        config.hot_light,
        config.explicit_optin,
        passes::semopt::OptMode::Off,
    )?;
    let proto = apply_structural_passes(
        proto,
        config.seed,
        config.flatten,
        config.junk,
        config.opaque,
        config.fuse,
        config.stateful_recovery,
        config.microir,
    );
    let mut out = Vec::new();
    collect_hot_details(&proto, &mut out);
    out.sort_by(|a, b| b.instructions.cmp(&a.instructions));
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn virtualize_with(
    source: &str,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    anti_envlog: bool,
) -> Result<String> {
    virtualize_full(
        source,
        seed,
        flatten,
        junk,
        opaque,
        fuse,
        minify,
        compress,
        anti_envlog,
        false,
        false,
        SurfaceVolume::Off,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn virtualize_full(
    source: &str,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
) -> Result<String> {
    virtualize_full_opt(
        source,
        seed,
        flatten,
        junk,
        opaque,
        fuse,
        minify,
        compress,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        false,
    )
}

pub fn sensitive_audit(source: &str) -> Result<String> {
    let module = frontend::lower_str(source)?;
    let opts = frontend::audit::SensitiveOpts {
        audit: true,
        strict: false,
        require_external: false,
    };
    Ok(frontend::audit::scan(&module, &opts)?.render())
}

#[allow(clippy::too_many_arguments)]
pub fn virtualize_full_opt(
    source: &str,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    aggressive: bool,
) -> Result<String> {
    virtualize_full_sens(
        source,
        seed,
        flatten,
        junk,
        opaque,
        fuse,
        minify,
        compress,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        aggressive,
        frontend::audit::SensitiveOpts::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn virtualize_full_sens(
    source: &str,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    aggressive: bool,
    sensitive: frontend::audit::SensitiveOpts,
) -> Result<String> {
    virtualize_full_prof(
        source,
        seed,
        flatten,
        junk,
        opaque,
        fuse,
        minify,
        compress,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        aggressive,
        sensitive,
        bytecode::crypt::TargetProfile::CliTest,
        false,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn virtualize_full_prof(
    source: &str,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    aggressive: bool,
    sensitive: frontend::audit::SensitiveOpts,
    profile: bytecode::crypt::TargetProfile,
    canary: bool,
    lph_collapse: bool,
) -> Result<String> {
    virtualize_full_line(
        source,
        seed,
        flatten,
        junk,
        opaque,
        fuse,
        minify,
        compress,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        aggressive,
        sensitive,
        profile,
        canary,
        lph_collapse,
        true,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn virtualize_full_line(
    source: &str,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    aggressive: bool,
    sensitive: frontend::audit::SensitiveOpts,
    profile: bytecode::crypt::TargetProfile,
    canary: bool,
    lph_collapse: bool,
    line_info: bool,
    strip_source_names: bool,
) -> Result<String> {
    let opt_level = if aggressive { 3 } else { 0 };
    virtualize_full_line_impl(
        source,
        seed,
        flatten,
        junk,
        opaque,
        fuse,
        minify,
        compress,
        anti_envlog,
        hard_dispatch,
        surface,
        heavy,
        opt_level,
        sensitive,
        profile,
        canary,
        lph_collapse,
        line_info,
        strip_source_names,
        PolyStream::Off,
        false,
        FrameConstReuseMode::Off,
        false,
        false,
        StringFragMode::Full,
        false,
        false,
        false,
        false,
        None,
        &NoticeConfig::default(),
        None,
        None,
        passes::semopt::OptMode::Off,
        false,
        false,
        PropKeyMode::Off,
        false,
        false,
        false,
        false,
        false,
        false,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn virtualize_full_line_impl(
    source: &str,
    seed: u64,
    flatten: bool,
    junk: bool,
    opaque: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    anti_envlog: bool,
    hard_dispatch: bool,
    surface: bool,
    heavy: SurfaceVolume,
    opt_level: u8,
    sensitive: frontend::audit::SensitiveOpts,
    profile: bytecode::crypt::TargetProfile,
    canary: bool,
    lph_collapse: bool,
    line_info: bool,
    strip_source_names: bool,
    poly_stream: PolyStream,
    runtime_profile_markers: bool,
    frame_const_reuse: FrameConstReuseMode,
    detect_hot: bool,
    ablate_fragment: bool,
    string_frag_mode: StringFragMode,
    hot_light: bool,
    explicit_optin: bool,
    shell_probe: bool,
    underscore_hex_numlit: bool,
    shell_family: Option<ShellFamily>,
    notices: &NoticeConfig,
    mut progress: Option<&mut ProgressFn<'_>>,
    mut stats: Option<&mut BuildStats>,
    optimizer: passes::semopt::OptMode,
    stateful_recovery: bool,
    stateful_framing: bool,
    property_key_rename: PropKeyMode,
    semantic_family: bool,
    instruction_family: bool,
    state_family: bool,
    microir: bool,
    semgroup: bool,
    vm_traps: bool,
    surface_plan: Option<&surface::SurfacePlan>,
) -> Result<String> {
    notices.validate()?;
    let notice_pool = notices.resolve_pool();
    let notice_label = notices.label.clone();
    report(&mut progress, ProgressStage::Lower);
    let (mut proto, natives, hash_helper, encfuncs, hot, prechecks) = lower_and_compile(
        source,
        seed,
        heavy != SurfaceVolume::Off,
        opt_level,
        &sensitive,
        line_info,
        strip_source_names,
        surface,
        detect_hot && stats.is_some(),
        ablate_fragment,
        string_frag_mode,
        property_key_rename,
        hot_light,
        explicit_optin,
        optimizer,
    )?;
    report(&mut progress, ProgressStage::Transform);
    proto = apply_structural_passes(
        proto,
        seed,
        flatten,
        junk,
        opaque,
        fuse,
        stateful_recovery,
        microir,
    );
    let gen_cat = if semgroup {
        let (p2, cat) = passes::semgroup::fuse_semgroups(&proto, SEMGROUP_CAPACITY);
        proto = p2;
        cat
    } else {
        bytecode::gensuper::GenCatalogue::default()
    };
    report(&mut progress, ProgressStage::Encode);
    let enc = bytecode::encoding::Encoding::from_seed(seed);

    let mut used = used_opcodes(&proto);
    if stateful_recovery {
        used.insert(bytecode::opcode::Opcode::BStateStep);
    }
    let mut intrinsic_ids = used_intrinsics(&proto);
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    let mut blob_classes: Vec<u8> = Vec::new();

    let _vm_traps_guard = bytecode::crypt::scoped_vm_traps(vm_traps);
    let genkey =
        bytecode::encoder::payload_genkey(&proto, seed, &enc, anti_envlog, profile, canary);
    let fmt = bytecode::format::FormatConfig {
        version: bytecode::format::FORMAT_VERSION,
        line_info,
        kmode: vmgen::kepoch_mode(poly_stream),
        frame_const_probe: frame_const_reuse.enabled(),
        framing: stateful_framing,
        sem_family: semantic_family,
        instr_family: instruction_family,
        state_family,
        vm_traps,
        d1: stateful_recovery,
    };
    if !encfuncs.is_empty() {
        let salt = bytecode::encoder::payload_salt(seed);
        let envdig = bytecode::crypt::env_fingerprint_digest(seed, profile);
        for (id, ef) in encfuncs.iter().enumerate() {
            let inner = bytecode::compile::compile_func(&ef.body)
                .map_err(|e| anyhow!("BASIL_ENCFUNC compile error: {e}"))?;

            let inner = passes::shuffle_structure(&inner, seed);
            for op in used_opcodes(&inner) {
                used.insert(op);
            }
            for iid in used_intrinsics(&inner) {
                intrinsic_ids.insert(iid);
            }

            let mut body = bytecode::crypt::proto_code_digest(&inner, &enc)
                .to_le_bytes()
                .to_vec();
            let inner_payload =
                bytecode::encoder::serialize_inner(&inner, &genkey, &enc, seed, &envdig, &fmt);
            body.extend_from_slice(&inner_payload);
            let key = match &ef.key {
                ir::CompileKeySource::Managed { key, .. } => zeroize::Zeroizing::new(*key),
                ir::CompileKeySource::Literal(bytes) => zeroize::Zeroizing::new(*bytes),
            };
            let id32 = id as u32;

            let mut ns = salt.to_vec();
            ns.extend_from_slice(&id32.to_le_bytes());
            ns.extend_from_slice(&bytecode::crypt::code_digest(&inner, &enc).to_le_bytes());
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&bytecode::sha256::digest(&ns)[0..12]);
            let ad = bytecode::format::sealed_value_ad(&fmt, id32, &salt, ef.class);
            blob_classes.push(ef.class);
            blobs.push(bytecode::aead::seal(&key, &nonce, &ad, &body));
        }
    }
    if let Some(st) = stats.as_deref_mut() {
        let endpoints = if poly_stream != PolyStream::Off {
            poly_endpoint_set(&used, &enc)
        } else {
            std::collections::HashSet::new()
        };
        let mut s = BuildStats {
            opcode_kinds: used.len(),
            encfuncs: encfuncs.len(),
            natives: natives.len(),
            ..BuildStats::default()
        };
        accumulate_stats(&proto, &enc, &endpoints, &mut s);
        s.root_proto_instructions = proto.code.len();
        s.deferred_instructions = s.instructions - s.root_proto_instructions;
        s.native_marked_callbacks = hot.native_marked;
        s.native_marked_input = hot.native_marked_input;
        s.native_marked_render = hot.native_marked_render;
        s.native_marked_event = hot.native_marked_event;
        s.native_marked_generic = hot.native_marked_generic;
        *st = s;
    }
    let mut sec = if stats.is_some() {
        Some(bytecode::encoder::SectionStats::default())
    } else {
        None
    };
    let payload = bytecode::encoder::serialize_encrypted_full(
        &proto,
        seed,
        &enc,
        anti_envlog,
        profile,
        canary,
        &fmt,
        sec.as_mut(),
    );
    if let (Some(st), Some(sc)) = (stats.as_deref_mut(), sec.as_ref()) {
        st.serialized_total_bytes = sc.raw_total_bytes;
        st.serialized_code_bytes = sc.code_bytes;
        st.serialized_const_bytes = sc.const_bytes;
        st.serialized_number_const_bytes = sc.number_const_bytes;
        st.serialized_string_const_bytes = sc.string_const_bytes;
        st.serialized_other_const_bytes = sc.other_const_bytes;
        st.serialized_upvalue_bytes = sc.upvalue_bytes;
        st.serialized_proto_meta_bytes = sc.proto_meta_bytes;
        st.serialized_lineinfo_bytes = sc.lineinfo_bytes;
        st.serialized_section_header_bytes = sc.section_header_bytes;
        st.serialized_act_program_bytes = sc.act_program_bytes;
        st.serialized_aead_tag_bytes = sc.aead_tag_bytes;
        st.serialized_child_proto_bytes = sc.child_proto_bytes;
        st.serialized_const_count = sc.const_count;
        st.number_const_raw_count = sc.number_const_raw_count;
        st.number_const_dense_count = sc.number_const_dense_count;
        st.number_const_raw_bytes = sc.number_const_raw_bytes;
        st.number_const_dense_bytes = sc.number_const_dense_bytes;
        st.number_const_dense_saved_bytes = sc.number_const_dense_saved_bytes;
        st.kepoch_wide_skips = sc.kepoch_wide_skips;
        st.code_opcode_bytes = sc.code_opcode_bytes;
        st.code_operand_bytes = sc.code_operand_bytes;
        st.code_dead_operand_bytes = sc.code_dead_operand_bytes;
        st.code_dead_operand_count = sc.code_dead_operand_count;
        st.code_live_operand_bytes = sc.code_live_operand_bytes;
        st.code_arity_saved_bytes = sc.code_arity_saved_bytes;
        st.base85_payload_chars = sc.raw_total_bytes.div_ceil(4) * 5;
        st.base85_overhead_bytes = st.base85_payload_chars - sc.raw_total_bytes;
    }

    let mut native_bodies: Vec<String> = natives
        .iter()
        .map(|fb| vmgen::minify_native(&ir::emit_func(fb)))
        .collect();
    if let Some(st) = stats.as_deref_mut() {
        st.native_total_bytes = native_bodies.iter().map(|b| b.len()).sum();
        st.native_literal_bytes = native_bodies
            .iter()
            .map(|b| native_string_literal_bytes(b))
            .sum();
    }

    if hash_helper {
        let body = vmgen::randomize_crypto_aliases(vmgen::HASH_HELPER_LUA, seed);
        native_bodies.push(vmgen::minify_native(&body));
    }
    let precheck_expected: Vec<Vec<i64>> = prechecks.iter().map(|p| p.expected.clone()).collect();
    let precheck_bodies: Vec<String> = prechecks
        .iter()
        .map(|p| vmgen::minify_native(&ir::emit_func(&p.body)))
        .collect();

    let surface = surface || heavy != SurfaceVolume::Off;
    report(&mut progress, ProgressStage::GenerateVm);
    let assemble = |compress: bool| -> Result<String> {
        let vm = vmgen::generate_shell_probe(
            &enc,
            &payload,
            seed,
            &genkey,
            &used,
            compress,
            native_bodies.len(),
            blobs.len(),
            anti_envlog,
            hard_dispatch,
            surface,
            heavy,
            &intrinsic_ids,
            profile,
            canary,
            poly_stream,
            runtime_profile_markers,
            frame_const_reuse,
            shell_probe,
            underscore_hex_numlit,
            &precheck_expected,
            &fmt,
            &gen_cat,
            surface_plan,
        );

        let vm = vmgen::notices::splice(vm, &notice_pool, notice_label.as_deref(), seed);
        let vm = if minify {
            if lph_collapse {
                vmgen::minify_lph(&vm, seed, surface)
            } else {
                vmgen::minify(&vm, seed, surface)
            }
        } else {
            vm
        };
        let vm = vmgen::splice_natives(vm, &native_bodies);
        let vm = vmgen::splice_prechecks(vm, &precheck_bodies);
        let vm = vmgen::splice_blobs(vm, &blobs);
        let vm = vmgen::splice_ecls(vm, &blob_classes);
        let vm = vmgen::shellprobe::resolve(vm);
        Ok(vmgen::shell_family::wrap_with(
            vm,
            seed,
            surface,
            shell_family,
        ))
    };
    report(&mut progress, ProgressStage::Minify);
    let artifact = if compress {
        let compressed = assemble(true)?;
        let raw = assemble(false)?;
        let selected = keep_compressed(compressed.len(), raw.len());
        if let Some(st) = stats.as_deref_mut() {
            st.compress_requested = true;
            st.compress_selected = selected;
            st.compressed_artifact_bytes = compressed.len();
            st.raw_artifact_bytes = raw.len();
        }
        if selected {
            compressed
        } else {
            raw
        }
    } else {
        assemble(false)?
    };
    Ok(artifact)
}

fn native_string_literal_bytes(src: &str) -> usize {
    let b = src.as_bytes();
    let mut i = 0usize;
    let mut total = 0usize;
    while i < b.len() {
        let q = b[i];
        if q == b'"' || q == b'\'' {
            i += 1;
            while i < b.len() && b[i] != q {
                let step = if b[i] == b'\\' && i + 1 < b.len() {
                    2
                } else {
                    1
                };
                total += step;
                i += step;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    total
}

fn used_opcodes(main: &bytecode::Proto) -> std::collections::HashSet<bytecode::Opcode> {
    fn go(p: &bytecode::Proto, set: &mut std::collections::HashSet<bytecode::Opcode>) {
        for inst in &p.code {
            set.insert(inst.op);
        }
        for c in &p.protos {
            go(c, set);
        }
    }
    let mut set = std::collections::HashSet::new();
    go(main, &mut set);
    set
}

fn poly_endpoint_set(
    used: &std::collections::HashSet<bytecode::Opcode>,
    enc: &bytecode::encoding::Encoding,
) -> std::collections::HashSet<u8> {
    let bases: std::collections::HashSet<bytecode::Opcode> =
        bytecode::opcode::SYNONYMS.iter().map(|(_, b)| *b).collect();
    let mut endpoints = std::collections::HashSet::new();
    for base in bases {
        let mut ids: Vec<u8> = bytecode::opcode::synonyms_of(base)
            .into_iter()
            .filter(|op| used.contains(op))
            .map(|op| enc.phys(op))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() >= 2 {
            endpoints.extend(ids);
        }
    }
    endpoints
}

fn accumulate_stats(
    p: &bytecode::Proto,
    enc: &bytecode::encoding::Encoding,
    endpoints: &std::collections::HashSet<u8>,
    s: &mut BuildStats,
) {
    s.protos += 1;
    s.instructions += p.code.len();
    s.constants += p.consts.len();
    s.string_constants += p
        .consts
        .iter()
        .filter(|c| matches!(c, bytecode::Const::Str(_)))
        .count();
    if let Some(cat) = p.hot_callback {
        s.hot_callback_total += 1;
        s.hot_callback_instructions += p.code.len();
        s.hot_callback_top_instructions = s.hot_callback_top_instructions.max(p.code.len());
        match cat {
            ir::HotCat::Input => s.hot_callback_input += 1,
            ir::HotCat::Render => s.hot_callback_render += 1,
            ir::HotCat::Event => s.hot_callback_event += 1,
            ir::HotCat::Generic => s.hot_callback_generic += 1,
        }
    }
    for inst in &p.code {
        if endpoints.contains(&enc.phys(inst.op)) {
            s.poly_morphable += 1;
        }
    }
    for c in &p.protos {
        accumulate_stats(c, enc, endpoints, s);
    }
}

fn used_intrinsics(main: &bytecode::Proto) -> std::collections::HashSet<u32> {
    fn go(p: &bytecode::Proto, set: &mut std::collections::HashSet<u32>) {
        for inst in &p.code {
            match inst.op {
                bytecode::Opcode::SelfI => {
                    set.insert(inst.c as u32);
                }
                bytecode::Opcode::GetGlobalI => {
                    set.insert(inst.b as u32);
                }
                _ => {}
            }
        }
        for c in &p.protos {
            go(c, set);
        }
    }
    let mut set = std::collections::HashSet::new();
    go(main, &mut set);
    set
}

#[cfg(test)]
mod superop_cov {
    use super::*;
    #[test]
    fn banked_superops_are_emitted_across_corpus() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
        let seeds = [
            0xB451115Cu64,
            0x1,
            0xDEADBEEF,
            0x0F0F0F0F0F0F0F0F,
            0xA5A55A5A,
        ];
        let (mut s8, mut s9, mut b) = (0u32, 0u32, 0u32);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().map_or(true, |e| e != "luau") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            for &seed in &seeds {
                let Ok((mut proto, _, _, _, _, _)) = lower_and_compile(
                    &src,
                    seed,
                    false,
                    0,
                    &frontend::audit::SensitiveOpts::default(),
                    true,
                    false,
                    false,
                    false,
                    false,
                    StringFragMode::Full,
                    PropKeyMode::Off,
                    false,
                    false,
                    passes::semopt::OptMode::Off,
                ) else {
                    continue;
                };
                proto = passes::flatten(&proto, seed);
                proto = passes::junk(&proto, seed);
                proto = passes::opaque(&proto, seed);
                proto = passes::fuse(&proto, seed);
                b += 1;
                let u = used_opcodes(&proto);
                if u.contains(&bytecode::Opcode::Super8) {
                    s8 += 1;
                }
                if u.contains(&bytecode::Opcode::Super9) {
                    s9 += 1;
                }
            }
        }
        assert!(s8 >= 30, "Super8 (Mul,LoadK,LtK) emitted in only {s8}/{b} builds — below the coverage floor (dead-shape guard)");
        assert!(
            s9 >= 30,
            "Super9 (LoadK,LoadK) emitted in only {s9}/{b} builds — below the coverage floor"
        );
    }
}

#[cfg(test)]
mod syn_cov {
    use super::*;
    #[test]
    fn every_synonym_is_emitted_across_corpus() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
        let seeds = [
            0xB451115Cu64,
            0x1,
            0xDEADBEEF,
            0x0F0F0F0F0F0F0F0F,
            0xA5A55A5A,
        ];
        let mut count: std::collections::HashMap<bytecode::Opcode, u32> =
            std::collections::HashMap::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().map_or(true, |e| e != "luau") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            for &seed in &seeds {
                let Ok((mut pr, _, _, _, _, _)) = lower_and_compile(
                    &src,
                    seed,
                    false,
                    0,
                    &frontend::audit::SensitiveOpts::default(),
                    true,
                    false,
                    false,
                    false,
                    false,
                    StringFragMode::Full,
                    PropKeyMode::Off,
                    false,
                    false,
                    passes::semopt::OptMode::Off,
                ) else {
                    continue;
                };
                pr = passes::flatten(&pr, seed);
                pr = passes::junk(&pr, seed);
                pr = passes::opaque(&pr, seed);
                pr = passes::fuse(&pr, seed);
                pr = passes::synonymize(&pr, seed);
                let u = used_opcodes(&pr);
                for (syn, _) in bytecode::opcode::SYNONYMS {
                    if u.contains(syn) {
                        *count.entry(*syn).or_insert(0) += 1;
                    }
                }
            }
        }
        for (syn, _) in bytecode::opcode::SYNONYMS {
            let n = count.get(syn).copied().unwrap_or(0);
            assert!(n >= 50, "synonym {syn:?} emitted in only {n} builds — below the coverage floor (dead-synonym guard)");
        }
    }
}

#[cfg(test)]
mod poly_churn_audit {
    use super::*;
    use std::collections::HashSet;

    fn morphable_endpoints(
        used: &HashSet<bytecode::Opcode>,
        enc: &bytecode::encoding::Encoding,
    ) -> HashSet<u8> {
        let bases: HashSet<bytecode::Opcode> =
            bytecode::opcode::SYNONYMS.iter().map(|(_, b)| *b).collect();
        let mut endpoints = HashSet::new();
        for base in bases {
            let mut ids: Vec<u8> = bytecode::opcode::synonyms_of(base)
                .into_iter()
                .filter(|op| used.contains(op))
                .map(|op| enc.phys(op))
                .collect();
            ids.sort_unstable();
            ids.dedup();
            if ids.len() >= 2 {
                endpoints.extend(ids);
            }
        }
        endpoints
    }

    fn walk(
        p: &bytecode::Proto,
        enc: &bytecode::encoding::Encoding,
        endpoints: &HashSet<u8>,
        tot: &mut u64,
        morph: &mut u64,
    ) {
        for inst in &p.code {
            *tot += 1;
            if endpoints.contains(&enc.phys(inst.op)) {
                *morph += 1;
            }
        }
        for c in &p.protos {
            walk(c, enc, endpoints, tot, morph);
        }
    }

    #[test]
    fn kop_churn_morphable_coverage_holds_across_corpus() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
        let seeds = [
            0xB451115Cu64,
            0x1,
            0xDEADBEEF,
            0x0F0F0F0F0F0F0F0F,
            0xA5A55A5A,
        ];
        let (mut tot, mut morph) = (0u64, 0u64);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().map_or(true, |e| e != "luau") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            for &seed in &seeds {
                let Ok((mut pr, _, _, _, _, _)) = lower_and_compile(
                    &src,
                    seed,
                    false,
                    0,
                    &frontend::audit::SensitiveOpts::default(),
                    true,
                    false,
                    false,
                    false,
                    false,
                    StringFragMode::Full,
                    PropKeyMode::Off,
                    false,
                    false,
                    passes::semopt::OptMode::Off,
                ) else {
                    continue;
                };
                pr = passes::flatten(&pr, seed);
                pr = passes::junk(&pr, seed);
                pr = passes::opaque(&pr, seed);
                pr = passes::fuse(&pr, seed);
                pr = passes::synonymize(&pr, seed);
                let used = used_opcodes(&pr);
                let enc = bytecode::encoding::Encoding::from_seed(seed);
                let endpoints = morphable_endpoints(&used, &enc);
                walk(&pr, &enc, &endpoints, &mut tot, &mut morph);
            }
        }
        let pct = morph * 100 / tot.max(1);
        eprintln!(
            "KOP churn audit: {morph}/{tot} morphable instructions ({pct}%); \
             gated post-run KOP delta ~ conservative {}% subset aggressive {}%",
            pct * 4 / 16,
            pct * 12 / 16
        );
        assert!(tot > 0, "no instructions compiled");
        assert!(
            pct >= 50,
            "morphable KOP coverage {pct}% below the audited floor"
        );
    }
}

#[cfg(test)]
mod kepoch_cov {
    use super::*;
    use bytecode::kepoch;

    fn assign_pids<'a>(
        p: &'a bytecode::proto::Proto,
        next: &mut u32,
        out: &mut Vec<(u32, &'a bytecode::proto::Proto)>,
    ) {
        let pid = *next;
        *next += 1;
        out.push((pid, p));
        for c in &p.protos {
            assign_pids(c, next, out);
        }
    }

    struct Cov {
        builds: u64,
        n_inst: u64,
        n_elig: u64,
        n_sel: u64,
        n_fields: u64,
        n_churn: u64,
        n_fam: [u64; 2],
        churn_fam: [u64; 2],
        fam: std::collections::BTreeMap<String, u64>,
        example: [Option<(i64, i64, i64)>; 2],
    }

    fn measure(mode: kepoch::KepochMode) -> Cov {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
        let seeds = [
            0xB451115Cu64,
            0x1,
            0xDEADBEEF,
            0x0F0F0F0F0F0F0F0F,
            0xA5A55A5A,
        ];
        let mut c = Cov {
            builds: 0,
            n_inst: 0,
            n_elig: 0,
            n_sel: 0,
            n_fields: 0,
            n_churn: 0,
            n_fam: [0, 0],
            churn_fam: [0, 0],
            fam: std::collections::BTreeMap::new(),
            example: [None, None],
        };
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().map_or(true, |e| e != "luau") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            for &seed in &seeds {
                let Ok((mut pr, _, _, _, _, _)) = lower_and_compile(
                    &src,
                    seed,
                    false,
                    0,
                    &frontend::audit::SensitiveOpts::default(),
                    true,
                    false,
                    false,
                    false,
                    false,
                    StringFragMode::Full,
                    PropKeyMode::Off,
                    false,
                    false,
                    passes::semopt::OptMode::Off,
                ) else {
                    continue;
                };
                pr = passes::flatten(&pr, seed);
                pr = passes::junk(&pr, seed);
                pr = passes::opaque(&pr, seed);
                pr = passes::fuse(&pr, seed);
                pr = passes::synonymize(&pr, seed);
                let params = kepoch::params(seed, mode).unwrap();
                let mut next = 0u32;
                let mut protos = Vec::new();
                assign_pids(&pr, &mut next, &mut protos);
                c.builds += 1;
                for (pid, proto) in &protos {
                    for (i0, inst) in proto.code.iter().enumerate() {
                        c.n_inst += 1;
                        if !inst.ops.is_empty() || !kepoch::eligible_family(inst.op) {
                            continue;
                        }
                        c.n_elig += 1;
                        let i = i0 as u32 + 1;
                        if !kepoch::selected(*pid, i, &params) {
                            continue;
                        }
                        c.n_sel += 1;
                        *c.fam.entry(format!("{:?}", inst.op)).or_insert(0) += 1;
                        let fam = kepoch::family_of(inst.op, seed) as usize;
                        let e0 = kepoch::epoch0(*pid, i, &params);
                        let e1 = kepoch::rotate(e0);
                        for slot in kepoch::eligible_slots(inst.op) {
                            let real = match slot {
                                0 => inst.a,
                                1 => inst.b,
                                _ => inst.c,
                            } as i64;
                            if !(0..kepoch::DOMAIN).contains(&real) {
                                continue;
                            }
                            c.n_fields += 1;
                            c.n_fam[fam] += 1;
                            let t0 = kepoch::encode_op(real, inst.op, e0, seed, &params);
                            let t1 = kepoch::encode_op(real, inst.op, e1, seed, &params);
                            assert_eq!(
                                kepoch::decode_op(t0, inst.op, e0, seed, &params),
                                real,
                                "cold token must decode to real at rest epoch"
                            );
                            assert_eq!(
                                kepoch::decode_op(t1, inst.op, e1, seed, &params),
                                real,
                                "token must decode to real after one rotate"
                            );
                            if t0 != t1 {
                                c.n_churn += 1;
                                c.churn_fam[fam] += 1;
                            }
                            if c.example[fam].is_none() {
                                c.example[fam] = Some((real, t0, t1));
                            }
                        }
                    }
                }
            }
        }
        c
    }

    fn report(label: &str, c: &Cov) {
        eprintln!("kepoch {label} coverage over {} builds:", c.builds);
        eprintln!(
            "  eligible-family          = {}  ({:.1}% of all)",
            c.n_elig,
            100.0 * c.n_elig as f64 / c.n_inst as f64
        );
        eprintln!(
            "  selected (tokenized)     = {}  ({:.1}% of all, {:.1}% of eligible)",
            c.n_sel,
            100.0 * c.n_sel as f64 / c.n_inst as f64,
            100.0 * c.n_sel as f64 / c.n_elig as f64
        );
        eprintln!("  tokenized operand fields = {}", c.n_fields);
        eprintln!(
            "  churn on first rotate    = {}  ({:.1}%)",
            c.n_churn,
            100.0 * c.n_churn as f64 / c.n_fields as f64
        );
        eprintln!(
            "  family 0 (additive)      = {} fields ({:.1}%), churn {}",
            c.n_fam[0],
            100.0 * c.n_fam[0] as f64 / c.n_fields as f64,
            c.churn_fam[0]
        );
        eprintln!(
            "  family 1 (xor-mask)      = {} fields ({:.1}%), churn {}",
            c.n_fam[1],
            100.0 * c.n_fam[1] as f64 / c.n_fields as f64,
            c.churn_fam[1]
        );
        if let (Some(a), Some(x)) = (c.example[0], c.example[1]) {
            eprintln!(
                "  example real->t0->t1: family0 {a:?} (add-delta {}), family1 {x:?} (add-delta {})",
                (a.2 - a.1).rem_euclid(256),
                (x.2 - x.1).rem_euclid(256)
            );
        }
    }

    #[test]
    fn kepoch_coverage_and_dump_diff_conservative_vs_aggressive() {
        let cons = measure(kepoch::KepochMode::Conservative);
        let aggr = measure(kepoch::KepochMode::Aggressive);
        report("conservative", &cons);
        report("aggressive", &aggr);

        for (label, c) in [("conservative", &cons), ("aggressive", &aggr)] {
            assert!(
                c.n_sel > 0,
                "{label} must tokenize some register operands across the corpus"
            );
            assert!(
                c.n_fields > 0,
                "{label} must produce tokenized operand fields"
            );
            assert_eq!(c.n_churn, c.n_fields, "{label}: every tokenized operand must visibly differ one execution-state later (dump-then-lift barrier)");
            assert!(
                c.n_fam[0] > 0 && c.n_fam[1] > 0,
                "{label}: both formula families must appear in the corpus (no dead family)"
            );
            assert_eq!(
                c.churn_fam[0], c.n_fam[0],
                "{label}: additive family must churn on every rotate"
            );
            assert_eq!(
                c.churn_fam[1], c.n_fam[1],
                "{label}: xor family must churn on every rotate"
            );
            let minority = c.n_fam[0].min(c.n_fam[1]) as f64 / c.n_fields as f64;
            assert!(minority > 0.05, "{label}: formula family distribution is degenerate (minority {minority:.3} of fields)");
        }
        let cons_frac = cons.n_sel as f64 / cons.n_elig as f64;
        let aggr_frac = aggr.n_sel as f64 / aggr.n_elig as f64;
        assert!(
            cons_frac > 0.02 && cons_frac < 0.30,
            "conservative selection fraction {cons_frac:.3} out of expected band"
        );
        assert!(
            aggr_frac > 0.20 && aggr_frac < 0.55,
            "aggressive selection fraction {aggr_frac:.3} out of expected band"
        );
        assert!(
            aggr.n_sel > cons.n_sel,
            "aggressive must tokenize strictly more instructions than conservative ({} vs {})",
            aggr.n_sel,
            cons.n_sel
        );
        assert!(
            aggr.n_fields > cons.n_fields,
            "aggressive must produce strictly more tokenized fields than conservative ({} vs {})",
            aggr.n_fields,
            cons.n_fields
        );
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    const FIXTURE: &str = "local x = 41\nlocal function f(a) return a + 1 end\nprint(f(x))\n";

    fn test_config(seed: u64) -> Config {
        Config {
            seed,
            mode: Mode::Virtualize,
            flatten: true,
            opaque: true,
            junk: true,
            fuse: true,
            minify: true,
            compress: false,
            anti_envlog: false,
            hard_dispatch: false,
            surface: false,
            heavy: SurfaceVolume::Off,
            aggressive: false,
            sensitive: SensitiveOpts::default(),
            profile: TargetProfile::CliTest,
            loadstring_canary: false,
            lph_collapse: false,
            line_info: true,
            strip_source_names: false,
            poly_stream: PolyStream::Off,
            optimization: 2,
            static_env: false,
            runtime_profile_markers: false,
            frame_const_reuse: Default::default(),
            hot_callback_policy: Default::default(),
            ablate_fragment: false,
            hot_light: false,
            explicit_optin: false,
            shell_probe: false,
            underscore_hex_numlit: false,
            shell_family: None,
            notices: NoticeConfig::default(),
            stateful_recovery: false,
            stateful_framing: false,
            string_frag_mode: StringFragMode::Full,
            property_key_rename: PropKeyMode::Off,
            semantic_family: false,
            instruction_family: false,
            state_family: false,
            microir: false,
            semgroup: false,
        }
    }

    #[test]
    fn progress_callback_keeps_artifact() {
        let base = virtualize_full_line(
            FIXTURE,
            0xABCD,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            SurfaceVolume::Off,
            false,
            SensitiveOpts::default(),
            TargetProfile::CliTest,
            false,
            false,
            true,
            false,
        )
        .unwrap();
        let mut stages = Vec::new();
        let with = {
            let mut cb = |ev: ProgressEvent| stages.push(ev.stage);
            virtualize_full_line_impl(
                FIXTURE,
                0xABCD,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                SurfaceVolume::Off,
                0,
                SensitiveOpts::default(),
                TargetProfile::CliTest,
                false,
                false,
                true,
                false,
                PolyStream::Off,
                false,
                FrameConstReuseMode::Off,
                false,
                false,
                StringFragMode::Full,
                false,
                false,
                false,
                false,
                None,
                &NoticeConfig::default(),
                Some(&mut cb),
                None,
                passes::semopt::OptMode::Off,
                false,
                false,
                PropKeyMode::Off,
                false,
                false,
                false,
                false,
                false,
                false,
                None,
            )
            .unwrap()
        };
        assert_eq!(
            base, with,
            "progress callback must not alter the generated artifact bytes"
        );
        assert_eq!(
            stages,
            vec![
                ProgressStage::Lower,
                ProgressStage::Transform,
                ProgressStage::Encode,
                ProgressStage::GenerateVm,
                ProgressStage::Minify,
            ],
            "inner virtualize stages fire in truthful code order"
        );
    }

    #[test]
    fn capturing_build_stats_does_not_change_the_artifact_and_populates() {
        let call = |stats: Option<&mut BuildStats>| {
            virtualize_full_line_impl(
                FIXTURE,
                0x1234_5678,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                SurfaceVolume::Off,
                0,
                SensitiveOpts::default(),
                TargetProfile::CliTest,
                false,
                false,
                true,
                false,
                PolyStream::Aggressive,
                false,
                FrameConstReuseMode::Off,
                false,
                false,
                StringFragMode::Full,
                false,
                false,
                false,
                false,
                None,
                &NoticeConfig::default(),
                None,
                stats,
                passes::semopt::OptMode::Off,
                false,
                false,
                PropKeyMode::Off,
                false,
                false,
                false,
                false,
                false,
                false,
                None,
            )
            .unwrap()
        };
        let base = call(None);
        let mut stats = BuildStats::default();
        let with = call(Some(&mut stats));
        assert_eq!(
            base, with,
            "capturing stats must not alter the generated artifact bytes"
        );
        assert!(stats.protos >= 1, "at least the root proto: {stats:?}");
        assert!(
            stats.instructions > 0 && stats.opcode_kinds > 0,
            "program stats populate: {stats:?}"
        );
        assert!(
            stats.poly_morphable > 0,
            "aggressive build has morphable instructions: {stats:?}"
        );
        assert!(
            stats.poly_morphable <= stats.instructions,
            "morphable is a subset of instructions"
        );
        assert!(
            stats.string_constants <= stats.constants,
            "string constants are a subset of constants"
        );
    }

    #[test]
    fn poly_off_reports_zero_morphable() {
        let mut stats = BuildStats::default();
        virtualize_full_line_impl(
            FIXTURE,
            0x1234_5678,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            SurfaceVolume::Off,
            0,
            SensitiveOpts::default(),
            TargetProfile::CliTest,
            false,
            false,
            true,
            false,
            PolyStream::Off,
            false,
            FrameConstReuseMode::Off,
            false,
            false,
            StringFragMode::Full,
            false,
            false,
            false,
            false,
            None,
            &NoticeConfig::default(),
            None,
            Some(&mut stats),
            passes::semopt::OptMode::Off,
            false,
            false,
            PropKeyMode::Off,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            stats.poly_morphable, 0,
            "poly off => no morphable churn surface reported"
        );
        assert!(
            stats.instructions > 0,
            "other stats still populate with poly off"
        );
    }

    #[test]
    fn keep_compressed_selects_strictly_smaller_and_ties_go_to_raw() {
        assert!(
            keep_compressed(10, 20),
            "compressed strictly smaller => keep compressed"
        );
        assert!(!keep_compressed(20, 10), "compressed larger => raw");
        assert!(
            !keep_compressed(10, 10),
            "equal size => raw (avoid decompressor surface)"
        );
        assert!(!keep_compressed(0, 0), "degenerate equal => raw");
    }

    fn build_impl(src: &str, seed: u64, compress: bool, stats: Option<&mut BuildStats>) -> String {
        virtualize_full_line_impl(
            src,
            seed,
            false,
            false,
            false,
            false,
            true,
            compress,
            false,
            false,
            false,
            SurfaceVolume::Off,
            1,
            SensitiveOpts::default(),
            TargetProfile::CliTest,
            false,
            false,
            true,
            false,
            PolyStream::Off,
            false,
            FrameConstReuseMode::Off,
            false,
            false,
            StringFragMode::Full,
            false,
            false,
            false,
            false,
            None,
            &NoticeConfig::default(),
            None,
            stats,
            passes::semopt::OptMode::Off,
            false,
            false,
            PropKeyMode::Off,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
        )
        .unwrap()
    }

    #[test]
    fn compress_guard_never_yields_a_larger_artifact_than_compress_off() {
        for seed in [0x1234_5678u64, 0xCAFE_BABE, 1, 7] {
            let with = build_impl(FIXTURE, seed, true, None);
            let without = build_impl(FIXTURE, seed, false, None);
            assert!(
                with.len() <= without.len(),
                "seed={seed:#x}: compress must never inflate past raw"
            );
            assert!(
                with == without || with.len() < without.len(),
                "seed={seed:#x}: either raw fallback (identical) or a strictly-smaller compressed win"
            );
        }
    }

    #[test]
    fn compress_off_is_deterministic_and_untouched_by_the_guard() {
        for seed in [0x1234_5678u64, 7] {
            assert_eq!(
                build_impl(FIXTURE, seed, false, None),
                build_impl(FIXTURE, seed, false, None),
                "compress-off deterministic"
            );
        }
    }

    #[test]
    fn run_with_progress_emits_full_ordered_sequence_and_matches_run() {
        let dir = std::env::temp_dir();
        let input = dir.join("basilisk_progress_in.luau");
        let out_none = dir.join("basilisk_progress_none.luau");
        let out_cb = dir.join("basilisk_progress_cb.luau");
        std::fs::write(&input, FIXTURE).unwrap();
        let config = test_config(0x1234_5678);
        run(&input, &out_none, &config).unwrap();
        let mut stages = Vec::new();
        {
            let mut cb = |ev: ProgressEvent| stages.push(ev.stage);
            run_with_progress(&input, &out_cb, &config, Some(&mut cb)).unwrap();
        }
        assert_eq!(
            stages,
            ProgressStage::ALL.to_vec(),
            "Read first, Done last, in order"
        );
        assert_eq!(
            std::fs::read(&out_none).unwrap(),
            std::fs::read(&out_cb).unwrap(),
            "run and run_with_progress produce byte-identical artifacts"
        );
        let _ = std::fs::remove_file(&input);
        let _ = std::fs::remove_file(&out_none);
        let _ = std::fs::remove_file(&out_cb);
    }

    #[test]
    fn run_capturing_stats_populates_and_matches_run_bytes() {
        let dir = std::env::temp_dir();
        let input = dir.join("basilisk_stats_in.luau");
        let out_run = dir.join("basilisk_stats_run.luau");
        let out_cap = dir.join("basilisk_stats_cap.luau");
        std::fs::write(&input, FIXTURE).unwrap();
        let config = test_config(0x0BAD_F00D);
        run(&input, &out_run, &config).unwrap();
        let mut stats = None;
        run_capturing_stats(&input, &out_cap, &config, None, &mut stats).unwrap();
        assert_eq!(
            std::fs::read(&out_run).unwrap(),
            std::fs::read(&out_cap).unwrap(),
            "run and run_capturing_stats produce byte-identical artifacts"
        );
        let stats = stats.expect("capturing populates the option even when the caller passes None");
        assert!(
            stats.protos >= 1 && stats.instructions > 0 && stats.opcode_kinds > 0,
            "end-to-end stats populate: {stats:?}"
        );
        let _ = std::fs::remove_file(&input);
        let _ = std::fs::remove_file(&out_run);
        let _ = std::fs::remove_file(&out_cap);
    }

    #[test]
    fn serialized_section_stats_partition_and_base85_hold_end_to_end() {
        let dir = std::env::temp_dir();
        let input = dir.join("basilisk_secstats_in.luau");
        let out = dir.join("basilisk_secstats_out.luau");
        std::fs::write(&input, FIXTURE).unwrap();
        let config = test_config(0x51EC_71011);
        let mut stats = None;
        run_capturing_stats(&input, &out, &config, None, &mut stats).unwrap();
        let s = stats.expect("stats populated");

        assert!(
            s.serialized_total_bytes > 0,
            "serialized payload measured: {s:?}"
        );
        let partition = s.serialized_section_header_bytes
            + s.serialized_code_bytes
            + s.serialized_const_bytes
            + s.serialized_upvalue_bytes
            + s.serialized_proto_meta_bytes
            + s.serialized_lineinfo_bytes
            + s.serialized_act_program_bytes;
        assert_eq!(
            s.serialized_total_bytes, partition,
            "flat section partition must sum to the serialized total: {s:?}"
        );

        assert_eq!(
            s.serialized_const_bytes,
            s.serialized_number_const_bytes
                + s.serialized_string_const_bytes
                + s.serialized_other_const_bytes,
            "const sub-partition must sum to const bytes: {s:?}"
        );

        assert!(s.serialized_const_count > 0, "fixture has constants: {s:?}");
        assert_eq!(
            s.serialized_aead_tag_bytes,
            s.serialized_const_count * 8,
            "8-byte keyed tag per constant"
        );
        assert!(
            s.serialized_code_bytes > 0 && s.serialized_child_proto_bytes > 0,
            "code + nested protos measured: {s:?}"
        );

        assert_eq!(
            s.code_opcode_bytes, s.instructions,
            "one opcode byte per instruction across all protos: {s:?}"
        );
        assert!(s.code_operand_bytes > 0, "operands measured: {s:?}");
        assert!(
            s.code_opcode_bytes + s.code_operand_bytes <= s.serialized_code_bytes,
            "opcode + operand bytes fit within the code section (remainder is per-proto framing): {s:?}"
        );
        assert!(
            s.code_arity_saved_bytes > 0,
            "handler-dead operands are elided from the stream (arity saving is active): {s:?}"
        );
        assert!(
            s.code_live_operand_bytes > 0 && s.code_live_operand_bytes <= s.code_operand_bytes,
            "handler-live operand bytes are a positive subset of emitted operand bytes: {s:?}"
        );
        assert_eq!(
            s.code_live_operand_bytes + s.code_dead_operand_bytes,
            s.code_operand_bytes,
            "emitted operands partition into handler-live + handler-dead(decoy): {s:?}"
        );
        assert!(
            s.serialized_lineinfo_bytes > 0,
            "line_info=true emits line data: {s:?}"
        );

        assert_eq!(
            s.base85_payload_chars,
            s.serialized_total_bytes.div_ceil(4) * 5,
            "base85 = 5 chars per 4 bytes"
        );
        assert_eq!(
            s.base85_overhead_bytes,
            s.base85_payload_chars - s.serialized_total_bytes,
            "overhead = chars - raw bytes"
        );
        assert!(
            s.base85_payload_chars < std::fs::read(&out).unwrap().len(),
            "payload literal is a proper subset of the whole artifact"
        );

        let _ = std::fs::remove_file(&input);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn dense_integer_constants_shrink_payload_and_floats_stay_raw() {
        let dir = std::env::temp_dir();
        let cfg = Config {
            flatten: false,
            opaque: false,
            junk: false,
            fuse: false,
            ..test_config(0x0DE_5E15)
        };

        let mut int_src = String::from("local s = 0\n");
        for k in 0..60u32 {
            int_src.push_str(&format!("s = s + {}\n", k * 1000 + 7));
        }
        int_src.push_str("print(s)\n");
        let int_in = dir.join("basilisk_dense_int_in.luau");
        let int_out = dir.join("basilisk_dense_int_out.luau");
        std::fs::write(&int_in, &int_src).unwrap();
        let mut istats = None;
        run_capturing_stats(&int_in, &int_out, &cfg, None, &mut istats).unwrap();
        let i = istats.unwrap();
        assert!(
            i.number_const_dense_count >= 60,
            "all 60 integer literals encode dense: {i:?}"
        );
        assert!(
            i.number_const_dense_count > i.number_const_raw_count,
            "integer-literal script is dense-dominated: {i:?}"
        );
        assert!(
            i.number_const_dense_saved_bytes > 0,
            "dense integers save bytes: {i:?}"
        );
        assert_eq!(
            i.serialized_number_const_bytes,
            i.number_const_raw_bytes + i.number_const_dense_bytes,
            "number-const bytes split into raw + dense"
        );
        assert!(
            i.number_const_dense_bytes < i.number_const_dense_count * 18,
            "each dense const is under the 18-byte raw cost: {i:?}"
        );

        let mut flt_src = String::from("local s = 0.0\n");
        for k in 0..60u32 {
            flt_src.push_str(&format!("s = s + {k}.25\n"));
        }
        flt_src.push_str("print(s)\n");
        let flt_in = dir.join("basilisk_float_only_in.luau");
        let flt_out = dir.join("basilisk_float_only_out.luau");
        std::fs::write(&flt_in, &flt_src).unwrap();
        let mut fstats = None;
        run_capturing_stats(&flt_in, &flt_out, &cfg, None, &mut fstats).unwrap();
        let f = fstats.unwrap();
        assert!(
            f.number_const_raw_count >= 60,
            "all 60 non-integer literals stay raw f64: {f:?}"
        );
        assert!(
            f.number_const_raw_count > f.number_const_dense_count,
            "non-integer script is raw-dominated: {f:?}"
        );
        assert_eq!(
            f.serialized_number_const_bytes,
            f.number_const_raw_bytes + f.number_const_dense_bytes,
            "number-const bytes split into raw + dense"
        );

        let mut fstats2 = None;
        let flt_out2 = dir.join("basilisk_float_only_out2.luau");
        run_capturing_stats(&flt_in, &flt_out2, &cfg, None, &mut fstats2).unwrap();
        assert_eq!(
            std::fs::read(&flt_out).unwrap(),
            std::fs::read(&flt_out2).unwrap(),
            "float-only build is deterministic (raw f64 path untouched)"
        );

        for p in [int_in, int_out, flt_in, flt_out, flt_out2] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn stage_percent_is_coarse_and_monotonic() {
        assert_eq!(ProgressStage::Read.percent(), 12);
        assert_eq!(ProgressStage::Done.percent(), 100);
        let mut last = 0;
        for st in ProgressStage::ALL {
            assert!(st.percent() > last, "coarse percent increases per stage");
            last = st.percent();
            assert_eq!(ProgressStage::from_index(st.index()), st);
        }
    }
}

#[cfg(test)]
mod flat_control_coverage {
    use super::*;
    use bytecode::opcode::Opcode;
    use bytecode::proto::Proto;

    #[derive(Default)]
    struct Cov {
        total: usize,
        loadk: usize,
        eq: usize,
        jmpif: usize,
        jmp: usize,
        disp_units: usize,
        goto_units: usize,
        flat_state_eq: usize,
        flattened_protos: usize,
        max_disp_proto: usize,
        protos: usize,
    }

    fn walk(p: &Proto, c: &mut Cov) {
        c.protos += 1;
        let code = &p.code;
        c.total += code.len();
        for i in &p.code {
            match i.op {
                Opcode::LoadK => c.loadk += 1,
                Opcode::Eq => c.eq += 1,
                Opcode::JmpIf => c.jmpif += 1,
                Opcode::Jmp => c.jmp += 1,
                Opcode::FlatStateEq => c.flat_state_eq += 1,
                _ => {}
            }
        }

        let mut state_reg: Option<i32> = None;
        let mut proto_disp = 0usize;
        let mut i = 0usize;
        while i + 2 < code.len() {
            let (a, b, d) = (&code[i], &code[i + 1], &code[i + 2]);
            if a.op == Opcode::LoadK
                && b.op == Opcode::Eq
                && d.op == Opcode::JmpIf
                && b.a == a.a
                && b.c == a.a
                && d.a == a.a
                && b.b == a.a - 1
            {
                proto_disp += 1;
                state_reg = Some(a.a - 1);
                i += 3;
            } else {
                i += 1;
            }
        }
        c.disp_units += proto_disp;
        c.max_disp_proto = c.max_disp_proto.max(proto_disp);

        if let Some(sr) = state_reg {
            let mut j = 0usize;
            while j + 1 < code.len() {
                if code[j].op == Opcode::LoadK && code[j].a == sr && code[j + 1].op == Opcode::Jmp {
                    c.goto_units += 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            c.flattened_protos += 1;
        }
        for ch in &p.protos {
            walk(ch, c);
        }
    }

    fn pct(n: usize, d: usize) -> f64 {
        if d == 0 {
            0.0
        } else {
            100.0 * n as f64 / d as f64
        }
    }

    #[test]
    #[ignore]
    fn measure_flatten_control_units() {
        std::thread::Builder::new()
            .stack_size(512 * 1024 * 1024)
            .spawn(run_measure)
            .unwrap()
            .join()
            .unwrap();
    }

    fn run_measure() {
        let seed: u64 = 17906244878785717735;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../reference/bench-inputs/real-world");
        let inputs = [
            ("Fates", "fates_admin_main.lua"),
            ("IY", "infinite_yield_source.lua"),
            ("Rogue", "rogue_ui.lua"),
        ];
        let sens = frontend::audit::SensitiveOpts::default();
        println!();
        for (name, file) in inputs {
            let src = std::fs::read_to_string(dir.join(file)).unwrap();
            let (mut proto, ..) = lower_and_compile(
                &src,
                seed,
                false,
                2,
                &sens,
                false,
                true,
                false,
                false,
                false,
                StringFragMode::Full,
                PropKeyMode::Off,
                false,
                false,
                passes::semopt::OptMode::Off,
            )
            .unwrap();
            proto = passes::flatten(&proto, seed);
            proto = passes::junk(&proto, seed);
            proto = passes::opaque(&proto, seed);
            let mut c = Cov::default();
            walk(&proto, &mut c);

            let fused = passes::flat_fuse(&proto);
            let mut fc = Cov::default();
            walk(&fused, &mut fc);

            let disp_instrs = c.disp_units * 3;
            let goto_instrs = c.goto_units * 2;
            let flat_instrs = disp_instrs + goto_instrs;
            let save_state_eq = c.disp_units;
            let save_eq_branch = c.disp_units * 2 + c.goto_units;

            println!("=== {name} ({file}) seed {seed} ===");
            println!(
                "  protos {} (flattened {})  total instrs {}",
                c.protos, c.flattened_protos, c.total
            );
            println!(
                "  RESIDENCY: max block-id memo entries per frame (largest dispatcher) = {}",
                c.max_disp_proto
            );
            println!(
                "  LoadK {} ({:.1}%)  Eq {} ({:.1}%)  JmpIf {} ({:.1}%)  Jmp {} ({:.1}%)",
                c.loadk,
                pct(c.loadk, c.total),
                c.eq,
                pct(c.eq, c.total),
                c.jmpif,
                pct(c.jmpif, c.total),
                c.jmp,
                pct(c.jmp, c.total)
            );
            println!(
                "  dispatcher units {}  ({} instrs, {:.1}% of code)",
                c.disp_units,
                disp_instrs,
                pct(disp_instrs, c.total)
            );
            println!(
                "  goto units {}  ({} instrs, {:.1}% of code)",
                c.goto_units,
                goto_instrs,
                pct(goto_instrs, c.total)
            );
            println!(
                "  flatten-control total {} instrs = {:.1}% of code",
                flat_instrs,
                pct(flat_instrs, c.total)
            );
            println!(
                "  cross-check: dispatcher units / Eq total = {}/{} = {:.1}%",
                c.disp_units,
                c.eq,
                pct(c.disp_units, c.eq)
            );
            println!(
                "  STATIC reduction  FLAT_STATE_EQ(3->2): -{} instrs ({:.1}% of code)",
                save_state_eq,
                pct(save_state_eq, c.total)
            );
            println!(
                "  STATIC reduction  FLAT_EQ_BRANCH(3->1)+goto: -{} instrs ({:.1}% of code)",
                save_eq_branch,
                pct(save_eq_branch, c.total)
            );
            println!("  REALIZED flat_fuse: {} FlatStateEq emitted (vs {} dispatcher units, {:.1}% fused); total instrs {} -> {} (-{}, {:.2}%)",
                fc.flat_state_eq, c.disp_units, pct(fc.flat_state_eq, c.disp_units),
                c.total, fc.total, c.total - fc.total, pct(c.total - fc.total, c.total));
            println!();
        }
    }
}
