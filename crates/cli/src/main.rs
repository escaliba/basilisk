use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use pipeline::{
    Config, Mode, ProgressEvent, ProgressFn, ProgressStage, SurfaceVolume, TargetProfile,
};

mod mem;

#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
enum HeavyBudget {
    Small,
    Medium,
    Large,
}

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
enum ProfileArg {
    #[default]
    CliTest,
    Executor,
    Studio,
    RobloxClient,
    RobloxServer,
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum LineInfoArg {
    On,
    Off,
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum PolyStreamArg {
    Off,
    Conservative,
    Aggressive,
}

#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
enum FrameConstReuseArg {
    Control,
    Strings,
    Numbers,
    All,
}

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
enum HotCallbackPolicyArg {
    Off,
    #[default]
    Report,
}

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
enum SurfaceThemeArg {
    #[default]
    None,
    Ascii,
}

impl From<SurfaceThemeArg> for pipeline::SurfaceTheme {
    fn from(a: SurfaceThemeArg) -> Self {
        use pipeline::SurfaceTheme as T;
        match a {
            SurfaceThemeArg::None => T::None,
            SurfaceThemeArg::Ascii => T::Ascii,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
enum SourceOpt {
    #[default]
    Off,
    Safe,
}

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
enum OptimizerArg {
    #[default]
    Off,
    Safe,
    Experimental,
}

fn resolve_optimizer(arg: OptimizerArg) -> pipeline::Optimizer {
    match arg {
        OptimizerArg::Off => pipeline::Optimizer::Off,
        OptimizerArg::Safe => pipeline::Optimizer::Safe,
        OptimizerArg::Experimental => pipeline::Optimizer::Experimental,
    }
}

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
enum ProgressMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
enum ShellFamilyArg {
    #[default]
    Auto,
    Iife,
    TableEntry,
    HelperLauncher,
    Setmeta,
}

fn resolve_line_info(explicit: Option<LineInfoArg>, profile: ProfileArg) -> bool {
    match explicit {
        Some(LineInfoArg::On) => true,
        Some(LineInfoArg::Off) => false,
        None => matches!(profile, ProfileArg::CliTest | ProfileArg::Studio),
    }
}

fn resolve_poly_stream(
    explicit: Option<PolyStreamArg>,
    profile: ProfileArg,
) -> pipeline::PolyStream {
    match explicit {
        Some(PolyStreamArg::Off) => pipeline::PolyStream::Off,
        Some(PolyStreamArg::Conservative) => pipeline::PolyStream::Conservative,
        Some(PolyStreamArg::Aggressive) => pipeline::PolyStream::Aggressive,
        None if is_release_profile(profile) => pipeline::PolyStream::Aggressive,
        None => pipeline::PolyStream::Off,
    }
}

fn resolve_shell_family(arg: ShellFamilyArg) -> Option<pipeline::ShellFamily> {
    match arg {
        ShellFamilyArg::Auto => None,
        ShellFamilyArg::Iife => Some(pipeline::ShellFamily::Iife),
        ShellFamilyArg::TableEntry => Some(pipeline::ShellFamily::TableEntry),
        ShellFamilyArg::HelperLauncher => Some(pipeline::ShellFamily::HelperLauncher),
        ShellFamilyArg::Setmeta => Some(pipeline::ShellFamily::SetMeta),
    }
}

fn resolve_frame_const_reuse(
    explicit: Option<FrameConstReuseArg>,
    profile: ProfileArg,
) -> pipeline::FrameConstReuseMode {
    match explicit {
        Some(FrameConstReuseArg::Control) => pipeline::FrameConstReuseMode::Control,
        Some(FrameConstReuseArg::Strings) => pipeline::FrameConstReuseMode::Strings,
        Some(FrameConstReuseArg::Numbers) => pipeline::FrameConstReuseMode::Numbers,
        Some(FrameConstReuseArg::All) => pipeline::FrameConstReuseMode::All,
        None if matches!(profile, ProfileArg::Executor) => pipeline::FrameConstReuseMode::All,
        None => pipeline::FrameConstReuseMode::Off,
    }
}

fn resolve_fragment_strings(force_on: bool, force_off: bool, profile: ProfileArg) -> bool {
    if force_on {
        return false;
    }
    force_off || matches!(profile, ProfileArg::Executor)
}

fn is_release_profile(profile: ProfileArg) -> bool {
    matches!(
        profile,
        ProfileArg::Executor | ProfileArg::RobloxClient | ProfileArg::RobloxServer
    )
}

fn production_trio_default(profile: ProfileArg) -> bool {
    matches!(profile, ProfileArg::Executor)
}

fn resolve_optimization(explicit: Option<u8>, profile: ProfileArg) -> u8 {
    match explicit {
        Some(level) => level,
        None if is_release_profile(profile) => 2,
        None => 1,
    }
}

fn resolve_hardening(explicit_on: bool, explicit_off: bool, profile_default: bool) -> bool {
    if explicit_off {
        false
    } else {
        explicit_on || profile_default
    }
}

#[cfg(test)]
fn profile_cli_name(profile: ProfileArg) -> &'static str {
    match profile {
        ProfileArg::CliTest => "cli-test",
        ProfileArg::Executor => "executor",
        ProfileArg::Studio => "studio",
        ProfileArg::RobloxClient => "roblox-client",
        ProfileArg::RobloxServer => "roblox-server",
    }
}

fn profile_to_target(profile: ProfileArg) -> TargetProfile {
    match profile {
        ProfileArg::CliTest => TargetProfile::CliTest,
        ProfileArg::Executor => TargetProfile::Executor,
        ProfileArg::Studio => TargetProfile::Studio,
        ProfileArg::RobloxClient => TargetProfile::RobloxClient,
        ProfileArg::RobloxServer => TargetProfile::RobloxServer,
    }
}

#[derive(Parser, Default, Clone)]
#[command(name = "basilisk", version)]
struct Args {
    input: Option<PathBuf>,

    output: Option<PathBuf>,

    #[arg(long, default_value_t = 0)]
    seed: u64,

    #[arg(long)]
    flatten: bool,

    #[arg(long)]
    opaque: bool,

    #[arg(long)]
    no_opaque: bool,

    #[arg(long)]
    junk: bool,

    #[arg(long)]
    fuse: bool,

    #[arg(long)]
    no_fuse: bool,

    #[arg(long)]
    no_minify: bool,

    #[arg(long)]
    compress: bool,

    #[arg(long)]
    anti_envlog: bool,

    #[arg(long)]
    hard_dispatch: bool,

    #[arg(long)]
    lura_surface: bool,

    #[arg(long, value_enum, num_args = 0..=1, default_missing_value = "medium")]
    basil_heavy: Option<HeavyBudget>,

    #[arg(long)]
    basil_opt_aggressive: bool,

    #[arg(long)]
    sensitive_audit: bool,

    #[arg(long)]
    sensitive_strict: bool,

    #[arg(long)]
    require_external_key: bool,

    #[arg(long)]
    vm_traps: bool,

    #[arg(long, value_enum, default_value_t = SurfaceThemeArg::None)]
    surface_theme: SurfaceThemeArg,

    #[arg(long)]
    surface_memes: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "Explicit per-build meme catalog file (same TOML format as assets/meme_strings.toml). Highest precedence: overrides BASIL_MEME_CATALOG and the default catalog for this build only. Requires --surface-memes."
    )]
    surface_meme_catalog: Option<std::path::PathBuf>,

    #[arg(
        long,
        help = "Weave bounded insane Luau type-annotation noise through the generated VM (OFF unless set; cosmetic parser noise, not a security boundary)."
    )]
    surface_types: bool,

    #[arg(
        long,
        help = "Preview the deterministic meme plan (selected memes, per-meme occurrence counts, carrier placement) for this seed+catalog without producing an artifact. Requires --surface-memes. Pass <INPUT> <OUTPUT> as well to also measure real body-band occupancy from the produced build."
    )]
    surface_meme_preview: bool,

    #[arg(
        long,
        help = "Read-only audit of the meme catalog (entries, unique, duplicates, byte-length stats, invalid/control entries, non-ascii count, total bytes). Does not rewrite the catalog or build anything."
    )]
    surface_meme_audit: bool,

    #[arg(long, value_enum, default_value = "cli-test")]
    target_profile: ProfileArg,

    #[arg(long)]
    no_loadstring_canary: bool,

    #[arg(long)]
    lph_collapse: bool,

    #[arg(
        long,
        conflicts_with = "lph_collapse",
        help = "Opt out of the executor/release default that enables --lph-collapse."
    )]
    no_lph_collapse: bool,

    #[arg(
        long,
        conflicts_with = "lura_surface",
        help = "Opt out of the executor/release default that enables --lura-surface."
    )]
    no_lura_surface: bool,

    #[arg(
        long,
        help = "Strip source identifier names (locals, params, functions, upvalues) from emitted-Luau paths (BASIL_NO_VIRTUALIZE natives, roundtrip). Virtualized code discards names regardless. Default: on for executor/roblox-client/roblox-server, off for cli-test/studio."
    )]
    strip_source_names: bool,

    #[arg(
        long,
        conflicts_with = "strip_source_names",
        help = "Keep source identifier names (opt out of the executor/release default)."
    )]
    no_strip_source_names: bool,

    #[arg(
        long,
        value_enum,
        help = "Original source line info. on: BASIL_LINE returns the source line and the line-info section is emitted. off: BASIL_LINE returns 0 and the line-info section is dropped. Default depends on --target-profile: on for cli-test/studio (dev), off for executor/roblox-client/roblox-server (release)."
    )]
    line_info: Option<LineInfoArg>,

    #[arg(
        long,
        value_enum,
        help = "Polymorphic/self-mutating instruction-stream hardening. off: no morphing. conservative: safest data-op subset. aggressive: wider safe coverage. Raises the bar for one-shot post-setup instruction dumps; does not defeat live tracing. Default: aggressive for executor/roblox-client/roblox-server, off for cli-test/studio."
    )]
    poly_stream: Option<PolyStreamArg>,

    #[arg(
        long,
        value_enum,
        default_value_t = ShellFamilyArg::Auto,
        help = "Generated-shell family. auto: seed-weighted default (iife/table-entry/helper-launcher). setmeta: top-level `return setmetatable(...)` release surface — the Roblox Executor Release wizard default. Only applies in surface mode; env BASIL_SHELL_FAMILY overrides for debugging."
    )]
    shell_family: ShellFamilyArg,

    #[arg(
        long,
        alias = "optimization-level",
        value_name = "LEVEL",
        value_parser = clap::value_parser!(u8).range(0..=3),
        help = "Optimization level 0..3. 0 = no program optimizer; 1 = safe pure-literal folding; 2 = release target, also prunes nil/number/string-literal dead branches; 3 = expert (currently == 2). All levels are semantics-preserving. Default: 1 for cli-test/studio, 2 for executor/roblox. Alias: --optimization-level."
    )]
    optimization: Option<u8>,

    #[arg(
        long,
        value_enum,
        default_value_t = SourceOpt::Off,
        help = "Safe source optimization before virtualization. off (default) = leave --optimization as-is; safe = raise the program optimizer to at least level 2 (semantics-preserving literal folding + literal-condition dead-branch pruning). Independent of target profile; off is byte-identical to base. aggressive is not offered — no sound distinct class beyond safe was found (see docs)."
    )]
    source_opt: SourceOpt,

    #[arg(
        long,
        value_enum,
        default_value_t = OptimizerArg::Off,
        help = "EXPERIMENTAL opt-in semantic optimizer, run on the clean pre-macro IR before virtualization to reduce the work Basilisk lowers. off (default) = byte-identical to no flag. safe = provably-equivalent literal constant propagation, dead pure-local elimination, constant-condition branch folding, and self-assignment removal. experimental = safe plus more ambitious passes (currently aliases safe; see report). Orthogonal to --optimization/--source-opt."
    )]
    optimizer: OptimizerArg,

    #[arg(
        long,
        value_name = "PATH",
        help = "Review mode: write the safe-source-optimized program as readable Luau to PATH and print a deterministic transformation summary, WITHOUT virtualizing. The output is review source (runs equivalently to the input), not a protected artifact; no history record is written. Refuses to overwrite the input path."
    )]
    review_optimizations: Option<PathBuf>,

    #[arg(
        long,
        help = "Assume function environments are stable (no getfenv/setfenv swapping). Enables no environment-assuming optimizations in this build; warns if the script uses getfenv/setfenv. Default off."
    )]
    static_env: bool,

    #[arg(long, conflicts_with = "passthrough")]
    roundtrip: bool,

    #[arg(long)]
    passthrough: bool,

    #[arg(
        long,
        help = "Accepted for compatibility; the CLI is always non-interactive. Missing <INPUT>/<OUTPUT> is an error."
    )]
    no_interactive: bool,

    #[arg(long, value_enum, default_value_t = ProgressMode::Auto, help = "Stage progress for direct CLI runs. auto/never: silent on success (script-stable). always: plain [n/N] stage logs to stderr. The interactive wizard shows its own animated progress regardless.")]
    progress: ProgressMode,

    #[arg(
        long,
        help = "After a direct CLI build, print a machine-readable build-metrics line to stderr (timing, sizes, peak RSS, program/VM counts). Report-only; the generated artifact is byte-identical whether or not this is set."
    )]
    metrics: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "After a direct CLI build, write authoritative non-secret build metadata (format_version, decimal-string build_seed) as JSON to PATH. Report-only; the artifact is byte-identical whether or not this is set."
    )]
    emit_build_metadata: Option<PathBuf>,

    #[arg(
        long,
        help = "Emit coarse startup timing markers into the generated VM (prints BASIL_PROF <label> <seconds> at load_start/payload_ready/deserialize_done/genkey_derived/root_start). Diagnostic opt-in for tuning large-script load time; carries no secrets. Default off; the artifact is NOT byte-identical when set, so leave off for shipping builds."
    )]
    runtime_profile_markers: bool,

    #[arg(long, value_enum, hide = true)]
    experimental_frame_const_reuse: Option<FrameConstReuseArg>,

    #[arg(
        long,
        hide = true,
        help = "Honour explicit BASIL_NATIVE_LEAF / BASIL_PRIVATE_SCAN source markers. Fails closed if a marked binding does not satisfy the full semantic contract."
    )]
    experimental_explicit_optin: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL, executor-compatibility trial only. Folds a debug.info observation of the closure factory into the gen-key epoch, so a wrapper installed before the probe corrupts constant decryption instead of tripping a boolean gate. FRICTION ONLY: patching the baked expected value or replaying a clean observation defeats it, and it is a no-op wherever debug.info is unavailable. Not a tamper-detection or integrity claim."
    )]
    experimental_shell_probe: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL, cosmetic only. Renders generated hexadecimal literals using Luau's underscore-tolerant form (0__X__ff). Anti-beautifier and surface friction ONLY: any real Luau parser folds it to the same integer immediately. Not anti-tamper, not encryption, not semantic protection."
    )]
    experimental_underscore_hex_numlit: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL, in development. Stateful static-recovery hardening (D1): couples constant opening to a runtime semantic block-state recurrence so genkey + proto metadata + constant index no longer suffices for arbitrary constant recovery. Requires flattening; not a cryptographic-secrecy claim. Off by default."
    )]
    experimental_stateful_recovery: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL, in development. Stateful framing hardening: chains serialized section-header lengths through a running per-proto state so sections cannot be located/decoded independently, with a fail-closed framing trailer. Recovery-cost only, not secrecy. Off by default."
    )]
    experimental_stateful_framing: bool,

    #[arg(
        long,
        hide = true,
        help = "Skip the string-fragmentation pass. Default ON for --target-profile executor (the accepted P1 performance profile); use --fragment-strings to force fragmentation back on."
    )]
    experimental_ablate_fragment: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL opt-in Selective string fragmentation: fragment only statically cold strings (outside loops/hot callbacks) under a per-build budget, with fewer fragments per string. Recovery-cost only, not secrecy. Off by default; does not change any profile default."
    )]
    experimental_selective_fragment: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL opt-in internal property-key renaming: consistently rename property names of compiler-proven closed-world local record tables to opaque keys across all statically-known accesses; external/reflective/escaping tables are skipped, not hidden. Semantics-preserving. Recovery-cost only, not secrecy. Off by default; does not change any profile default."
    )]
    experimental_internal_key_rename: bool,

    #[arg(
        long,
        hide = true,
        help = "Semantic metamorphism: the build seed selects among genuinely-different serialized-grammar families (e.g. constant-section layout) so a parser/model learned from one build does not describe another. Load-time only; semantics-preserving. Recovery-cost / cross-build transfer reduction only, not standalone secrecy. Default: on for the executor profile, off for other targets; opt out with --no-semantic-family."
    )]
    experimental_semantic_family: bool,

    #[arg(
        long,
        hide = true,
        conflicts_with = "experimental_semantic_family",
        help = "Opt out of the executor/release default that enables semantic-family metamorphism."
    )]
    no_semantic_family: bool,

    #[arg(
        long,
        hide = true,
        help = "Instruction/operand semantic metamorphism: the build seed selects among genuinely-different branch-target representation families (relative-offset vs absolute-target) resolved at load-time decode, so a control-flow model from one build does not describe another. Semantics-preserving; zero steady-state cost. Recovery-cost / cross-build transfer reduction only, not standalone secrecy. Default: on for the executor profile, off for other targets; opt out with --no-instruction-family."
    )]
    experimental_instruction_family: bool,

    #[arg(
        long,
        hide = true,
        conflicts_with = "experimental_instruction_family",
        help = "Opt out of the executor/release default that enables instruction-family metamorphism."
    )]
    no_instruction_family: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL opt-in state-model semantic metamorphism (requires --experimental-stateful-recovery): the build seed selects among genuinely-different protected-state models — the current single intra-proto CFG block-state, vs a composite that also folds a lexical proto-tree lineage component into per-constant eligibility — so a CFG-only state solver from one build does not reconstruct another. Semantics-preserving; fail-closed on wrong state; near-zero steady-state cost. Recovery-cost / cross-build transfer reduction only, not standalone secrecy. Off by default; does not change any profile default."
    )]
    experimental_state_family: bool,

    #[arg(
        long,
        hide = true,
        help = "EXPERIMENTAL opt-in non-local micro-IR lowering (AddK/SubK/MulK): cold arithmetic-with-constant sites lower in place to shared MApplyReset/MApplyFold micro-ops whose +/-/* meaning is chosen by a per-block selector-state fold, so the source operation is not encoded in one opcode and requires block-local selector dataflow to attribute. Semantics-preserving (Luau operators on raw operands); cold-only. Recovery-cost / first-lift-depth increase only, not standalone secrecy. Off by default; does not change any profile default."
    )]
    experimental_microir: bool,

    #[arg(
        long,
        hide = true,
        help = "Generated-handler fusion (semgroup A): dependency-linked source-op groups fuse into per-build GenSuper units whose internal intermediates are handler-local temporaries and whose interface-only record carries no original opcode list. Semantics-preserving; interface-only serialization; recovery-cost / first-lift-depth increase only, not standalone secrecy. Composes with --experimental-stateful-recovery (fused-group constants bind to D1 block state). Default: on for the executor profile, off for other targets; opt out with --no-semgroup."
    )]
    experimental_semgroup: bool,

    #[arg(
        long,
        hide = true,
        conflicts_with = "experimental_semgroup",
        help = "Opt out of the executor/release default that enables semgroup generated-handler fusion."
    )]
    no_semgroup: bool,

    #[arg(
        long,
        help = "Embed inert ownership/canary notice strings from the built-in owner pool at randomized never-executed shell positions. Default off. Independent of --basil-heavy and --target-profile. Static-reading friction and ownership signalling ONLY — not encryption, not anti-tamper, does not control analysis tools."
    )]
    artifact_notices: bool,

    #[arg(
        long,
        value_name = "TEXT",
        help = "Add an owner-supplied string to the artifact-notice candidate pool. Repeatable. Usable without --artifact-notices. Empty or over-long strings are rejected. Must not contain secrets."
    )]
    artifact_notice: Vec<String>,

    #[arg(
        long,
        value_name = "LABEL",
        help = "Optional non-secret canary label embedded in one selected notice, combined with a deterministic build-local id. Not a key; provides no reliable attribution by itself."
    )]
    artifact_notice_label: Option<String>,

    #[arg(
        long,
        help = "Force the string-fragmentation pass on. Only meaningful for --target-profile executor, where fragmentation is skipped by default because it dominates command-bar latency on large scripts."
    )]
    fragment_strings: bool,

    #[arg(
        long,
        hide = true,
        help = "Diagnostic tier only: leave detected hot-callback subtrees unfragmented."
    )]
    experimental_hot_light: bool,

    #[arg(long, value_enum, default_value_t = HotCallbackPolicyArg::Report, help = "Hot-callback detection policy. report (default): detect likely hot event/input/render callbacks and surface exact per-proto VM instruction counts via --metrics; artifact protection is UNCHANGED and byte-identical. off: skip detection. Neither mode devirtualizes or weakens anything — leaving a hot callback native is explicit user intent via BASIL_NO_VIRTUALIZE.")]
    hot_callback_policy: HotCallbackPolicyArg,
}

struct RunConfig {
    input: PathBuf,
    output: PathBuf,
    config: Config,
    optimizer: pipeline::Optimizer,
    vm_traps: bool,
    surface: pipeline::SurfaceConfig,
}

fn build_run_config(args: &Args) -> Result<RunConfig> {
    let input = args
        .input
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no input file specified"))?;
    let output = args
        .output
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no output file specified"))?;
    let mode = if args.passthrough {
        Mode::Passthrough
    } else if args.roundtrip {
        Mode::Roundtrip
    } else {
        Mode::Virtualize
    };
    let mut optimization = resolve_optimization(args.optimization, args.target_profile);
    if args.source_opt == SourceOpt::Safe {
        optimization = optimization.max(2);
    }
    let config = Config {
        seed: args.seed,
        mode,
        flatten: args.flatten,
        opaque: resolve_hardening(
            args.opaque,
            args.no_opaque,
            is_release_profile(args.target_profile),
        ),
        junk: args.junk,
        fuse: resolve_hardening(
            args.fuse,
            args.no_fuse,
            is_release_profile(args.target_profile),
        ),
        minify: !args.no_minify,
        compress: args.compress,
        anti_envlog: args.anti_envlog,
        hard_dispatch: args.hard_dispatch,
        surface: resolve_hardening(
            args.lura_surface,
            args.no_lura_surface,
            is_release_profile(args.target_profile),
        ),
        heavy: match args.basil_heavy {
            None => SurfaceVolume::Off,
            Some(HeavyBudget::Small) => SurfaceVolume::Small,
            Some(HeavyBudget::Medium) => SurfaceVolume::Medium,
            Some(HeavyBudget::Large) => SurfaceVolume::Large,
        },
        aggressive: args.basil_opt_aggressive || optimization >= 3,
        sensitive: pipeline::SensitiveOpts {
            audit: args.sensitive_audit,
            strict: args.sensitive_strict,
            require_external: args.require_external_key,
        },
        profile: profile_to_target(args.target_profile),
        loadstring_canary: !args.no_loadstring_canary,
        lph_collapse: resolve_hardening(
            args.lph_collapse,
            args.no_lph_collapse,
            is_release_profile(args.target_profile),
        ),
        line_info: resolve_line_info(args.line_info, args.target_profile),
        strip_source_names: resolve_hardening(
            args.strip_source_names,
            args.no_strip_source_names,
            is_release_profile(args.target_profile),
        ),
        poly_stream: resolve_poly_stream(args.poly_stream, args.target_profile),
        optimization,
        static_env: args.static_env,
        runtime_profile_markers: args.runtime_profile_markers,
        frame_const_reuse: resolve_frame_const_reuse(
            args.experimental_frame_const_reuse,
            args.target_profile,
        ),
        ablate_fragment: if args.experimental_selective_fragment {
            false
        } else {
            resolve_fragment_strings(
                args.fragment_strings,
                args.experimental_ablate_fragment,
                args.target_profile,
            )
        },
        string_frag_mode: if args.experimental_selective_fragment {
            pipeline::StringFragMode::Selective
        } else {
            pipeline::StringFragMode::Full
        },
        hot_light: args.experimental_hot_light,
        explicit_optin: args.experimental_explicit_optin,
        shell_probe: args.experimental_shell_probe,
        underscore_hex_numlit: args.experimental_underscore_hex_numlit,
        shell_family: resolve_shell_family(args.shell_family),
        hot_callback_policy: match args.hot_callback_policy {
            HotCallbackPolicyArg::Off => pipeline::HotCallbackPolicy::Off,
            HotCallbackPolicyArg::Report => pipeline::HotCallbackPolicy::Report,
        },
        notices: pipeline::NoticeConfig {
            enabled: args.artifact_notices,
            custom: args.artifact_notice.clone(),
            label: args.artifact_notice_label.clone(),
        },
        stateful_recovery: args.experimental_stateful_recovery,
        stateful_framing: args.experimental_stateful_framing,
        property_key_rename: if args.experimental_internal_key_rename {
            pipeline::PropKeyMode::Internal
        } else {
            pipeline::PropKeyMode::Off
        },
        semantic_family: resolve_hardening(
            args.experimental_semantic_family,
            args.no_semantic_family,
            production_trio_default(args.target_profile),
        ),
        instruction_family: resolve_hardening(
            args.experimental_instruction_family,
            args.no_instruction_family,
            production_trio_default(args.target_profile),
        ),
        state_family: args.experimental_state_family,
        microir: args.experimental_microir,
        semgroup: resolve_hardening(
            args.experimental_semgroup,
            args.no_semgroup,
            production_trio_default(args.target_profile),
        ),
    };
    config.notices.validate()?;
    let surface = pipeline::SurfaceConfig {
        theme: args.surface_theme.into(),
        memes: args.surface_memes,
        meme_strings: resolve_explicit_pool(args)?,
        types: surface_types_mode(args),
    };
    surface.validate().map_err(anyhow::Error::msg)?;
    Ok(RunConfig {
        input,
        output,
        config,
        optimizer: resolve_optimizer(args.optimizer),
        vm_traps: args.vm_traps,
        surface,
    })
}

fn run_obfuscation(
    rc: &RunConfig,
    progress: Option<&mut ProgressFn<'_>>,
) -> Result<pipeline::BuildStats> {
    let mut stats = None;
    pipeline::run_capturing_stats_optimized(
        &rc.input,
        &rc.output,
        &rc.config,
        rc.optimizer,
        progress,
        &mut stats,
        rc.vm_traps,
        &rc.surface,
    )?;
    Ok(stats.unwrap_or_default())
}

fn format_metrics_line(
    elapsed: std::time::Duration,
    input_bytes: u64,
    output_bytes: u64,
    peak_rss: Option<u64>,
    stats: &pipeline::BuildStats,
) -> String {
    let ratio = if input_bytes > 0 {
        output_bytes as f64 / input_bytes as f64
    } else {
        0.0
    };
    let rss = peak_rss
        .map(|b| b.to_string())
        .unwrap_or_else(|| "na".to_string());
    format!(
        "basilisk_metrics elapsed_ms={} input_bytes={input_bytes} output_bytes={output_bytes} ratio={ratio:.4} peak_rss_bytes={rss} protos={} instructions={} constants={} string_constants={} opcode_kinds={} poly_morphable={} encfuncs={} natives={} compress_requested={} compress_selected={} raw_artifact_bytes={} compressed_artifact_bytes={} serialized_total_bytes={} serialized_code_bytes={} serialized_const_bytes={} serialized_number_const_bytes={} serialized_string_const_bytes={} serialized_other_const_bytes={} serialized_upvalue_bytes={} serialized_proto_meta_bytes={} serialized_lineinfo_bytes={} serialized_section_header_bytes={} serialized_aead_tag_bytes={} serialized_child_proto_bytes={} serialized_const_count={} number_const_raw_count={} number_const_dense_count={} number_const_raw_bytes={} number_const_dense_bytes={} number_const_dense_saved_bytes={} kepoch_wide_skips={} code_opcode_bytes={} code_operand_bytes={} code_dead_operand_bytes={} code_dead_operand_count={} code_live_operand_bytes={} code_arity_saved_bytes={} base85_payload_chars={} base85_overhead_bytes={} root_proto_instructions={} deferred_instructions={} hot_callback_total={} hot_callback_input={} hot_callback_render={} hot_callback_event={} hot_callback_generic={} hot_callback_instructions={} hot_callback_top_instructions={} native_marked_callbacks={} native_marked_input={} native_marked_render={} native_marked_event={} native_marked_generic={} native_total_bytes={} native_literal_bytes={}",
        elapsed.as_millis(),
        stats.protos,
        stats.instructions,
        stats.constants,
        stats.string_constants,
        stats.opcode_kinds,
        stats.poly_morphable,
        stats.encfuncs,
        stats.natives,
        stats.compress_requested,
        stats.compress_selected,
        stats.raw_artifact_bytes,
        stats.compressed_artifact_bytes,
        stats.serialized_total_bytes,
        stats.serialized_code_bytes,
        stats.serialized_const_bytes,
        stats.serialized_number_const_bytes,
        stats.serialized_string_const_bytes,
        stats.serialized_other_const_bytes,
        stats.serialized_upvalue_bytes,
        stats.serialized_proto_meta_bytes,
        stats.serialized_lineinfo_bytes,
        stats.serialized_section_header_bytes,
        stats.serialized_aead_tag_bytes,
        stats.serialized_child_proto_bytes,
        stats.serialized_const_count,
        stats.number_const_raw_count,
        stats.number_const_dense_count,
        stats.number_const_raw_bytes,
        stats.number_const_dense_bytes,
        stats.number_const_dense_saved_bytes,
        stats.kepoch_wide_skips,
        stats.code_opcode_bytes,
        stats.code_operand_bytes,
        stats.code_dead_operand_bytes,
        stats.code_dead_operand_count,
        stats.code_live_operand_bytes,
        stats.code_arity_saved_bytes,
        stats.base85_payload_chars,
        stats.base85_overhead_bytes,
        stats.root_proto_instructions,
        stats.deferred_instructions,
        stats.hot_callback_total,
        stats.hot_callback_input,
        stats.hot_callback_render,
        stats.hot_callback_event,
        stats.hot_callback_generic,
        stats.hot_callback_instructions,
        stats.hot_callback_top_instructions,
        stats.native_marked_callbacks,
        stats.native_marked_input,
        stats.native_marked_render,
        stats.native_marked_event,
        stats.native_marked_generic,
        stats.native_total_bytes,
        stats.native_literal_bytes,
    )
}

enum Decision {
    Run,
    Missing,
}

fn decide(has_input: bool, has_output: bool) -> Decision {
    if has_input && has_output {
        Decision::Run
    } else {
        Decision::Missing
    }
}

fn run_review(args: &Args, out_path: &PathBuf) -> Result<()> {
    let input = args
        .input
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--review-optimizations requires an <INPUT> file"))?;
    if *out_path == input {
        return Err(anyhow::anyhow!(
            "--review-optimizations refuses to overwrite the input file; choose a different PATH"
        ));
    }
    let source = std::fs::read_to_string(&input)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", input.display()))?;
    let mut opt_level = resolve_optimization(args.optimization, args.target_profile);
    if args.source_opt == SourceOpt::Safe {
        opt_level = opt_level.max(2);
    }
    let review = pipeline::review_source(&source, opt_level)?;
    let delta = review.bytes_after as i64 - review.bytes_before as i64;
    let header =
        format!(
        "-- basilisk review source — NOT a protected artifact; runs equivalently to the input.\n\
         -- input {} sha256={}\n\
         -- source-opt={} optimizer-level={} canonical-source-bytes {}->{} (delta {})\n\n",
        input.display(),
        review.input_sha256,
        if args.source_opt == SourceOpt::Safe { "safe" } else { "off" },
        review.opt_level,
        review.bytes_before,
        review.bytes_after,
        delta,
    );
    std::fs::write(out_path, format!("{header}{}", review.optimized_luau))
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", out_path.display()))?;
    eprintln!(
        "review source written to {} (not a protected artifact). optimizer-level={} canonical-source-bytes {}->{} (delta {}).",
        out_path.display(),
        review.opt_level,
        review.bytes_before,
        review.bytes_after,
        delta,
    );
    Ok(())
}

const BUILD_WORKER_STACK: usize = 256 * 1024 * 1024;

fn surface_catalog_path() -> std::path::PathBuf {
    match std::env::var("BASIL_MEME_CATALOG") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => std::path::PathBuf::from("assets/meme_strings.toml"),
    }
}

fn resolve_explicit_pool(args: &Args) -> Result<Option<Vec<String>>> {
    match &args.surface_meme_catalog {
        Some(p) => {
            let cat = pipeline::surface::meme::load(p).map_err(anyhow::Error::msg)?;
            Ok(Some(cat.strings))
        }
        None => Ok(None),
    }
}

fn surface_types_mode(args: &Args) -> pipeline::surface::TypeNoiseMode {
    if args.surface_types {
        pipeline::surface::TypeNoiseMode::Insane
    } else {
        pipeline::surface::TypeNoiseMode::Off
    }
}

fn surface_config_from_args(args: &Args) -> Result<pipeline::SurfaceConfig> {
    Ok(pipeline::SurfaceConfig {
        theme: args.surface_theme.into(),
        memes: args.surface_memes,
        meme_strings: resolve_explicit_pool(args)?,
        types: surface_types_mode(args),
    })
}

fn run_surface_meme_audit(args: &Args) -> Result<()> {
    let path = args
        .surface_meme_catalog
        .clone()
        .unwrap_or_else(surface_catalog_path);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading meme catalog {}: {e}", path.display()))?;
    let a = pipeline::surface::meme::audit(&text).map_err(anyhow::Error::msg)?;
    println!("surface meme catalog audit");
    println!("catalog:             {}", path.display());
    println!("entries:             {}", a.entries);
    println!("unique entries:      {}", a.unique);
    println!("duplicates removed:  {}", a.duplicates);
    println!("invalid/control:     {}", a.invalid);
    println!("non-ascii (utf-8):   {}", a.non_ascii);
    println!("shortest (bytes):    {}", a.shortest);
    println!("longest (bytes):     {}", a.longest);
    println!("median (bytes):      {}", a.median);
    println!("total catalog bytes: {}", a.total_bytes);
    Ok(())
}

fn run_surface_meme_preview(args: &Args) -> Result<()> {
    if !args.surface_memes {
        anyhow::bail!("--surface-meme-preview requires --surface-memes");
    }
    let surface = surface_config_from_args(args)?;
    surface.validate().map_err(anyhow::Error::msg)?;
    let (catalog, source) = match &surface.meme_strings {
        Some(list) => (
            pipeline::surface::meme::from_strings(list).map_err(anyhow::Error::msg)?,
            "request".to_string(),
        ),
        None => {
            let path = surface_catalog_path();
            let text = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("reading meme catalog {}: {e}", path.display()))?;
            (
                pipeline::surface::meme::parse(&text).map_err(anyhow::Error::msg)?,
                path.display().to_string(),
            )
        }
    };
    let plan = surface
        .resolve(args.seed, Some(&catalog))
        .map_err(anyhow::Error::msg)?;
    let pv = pipeline::surface::meme::preview(&plan);

    println!("surface meme preview");
    println!("seed: {}", args.seed);
    println!("catalog source: {source}");
    println!("catalog entries: {}", catalog.strings.len());
    println!("selected distinct: {}", pv.distinct.len());
    println!("planned occurrences: {}", pv.total);
    println!();
    for (i, (m, c)) in pv.counts.iter().enumerate() {
        println!("{:>3}. {:<46} {}x", i + 1, format!("{m:?}"), c);
    }
    println!();

    match (&args.input, &args.output) {
        (Some(_), Some(output)) => {
            let rc = build_run_config(args)?;
            std::thread::scope(|s| {
                std::thread::Builder::new()
                    .stack_size(BUILD_WORKER_STACK)
                    .spawn_scoped(s, || run_obfuscation(&rc, None))
                    .expect("spawn build worker")
                    .join()
                    .expect("build worker panicked")
            })?;
            let bytes = std::fs::read(output)
                .map_err(|e| anyhow::anyhow!("reading built artifact {}: {e}", output.display()))?;
            let text = String::from_utf8_lossy(&bytes);
            let distinct: Vec<&str> = pv.distinct.iter().map(|s| s.as_str()).collect();
            let (total, bands) = pipeline::surface::meme::band_distribution(&text, &distinct);
            println!(
                "body bands (measured from the build written to {}):",
                output.display()
            );
            let labels = ["0-20%", "20-40%", "40-60%", "60-80%", "80-100%"];
            for (l, b) in labels.iter().zip(bands.iter()) {
                println!("  {l:<8}{b}");
            }
            println!("  total   {total}");
        }
        _ => {
            println!("planned carrier placement (12 sites, front-light/back-heavy):");
            for (i, c) in pv.slots.iter().enumerate() {
                let name = if i == 0 {
                    "preamble".to_string()
                } else {
                    format!("anchor {i:>2}")
                };
                println!("  {name:<10} {c}");
            }
            println!();
            println!("pass <INPUT> <OUTPUT> with --surface-meme-preview to also measure real body-band occupancy.");
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(review_path) = args.review_optimizations.clone() {
        return run_review(&args, &review_path);
    }
    if args.surface_meme_audit {
        return run_surface_meme_audit(&args);
    }
    if args.surface_meme_preview {
        return run_surface_meme_preview(&args);
    }
    let decision = decide(args.input.is_some(), args.output.is_some());
    match decision {
        Decision::Run => {
            let rc = build_run_config(&args)?;
            let start = std::time::Instant::now();
            let stats = std::thread::scope(|s| {
                std::thread::Builder::new()
                    .stack_size(BUILD_WORKER_STACK)
                    .spawn_scoped(s, || {
                        if matches!(args.progress, ProgressMode::Always) {
                            let mut cb = |ev: ProgressEvent| {
                                eprintln!(
                                    "[{}/{}] {}",
                                    ev.stage.index() + 1,
                                    ProgressStage::COUNT,
                                    ev.label
                                );
                            };
                            run_obfuscation(&rc, Some(&mut cb))
                        } else {
                            run_obfuscation(&rc, None)
                        }
                    })
                    .expect("spawn build worker")
                    .join()
                    .expect("build worker panicked")
            })?;
            if args.metrics {
                let elapsed = start.elapsed();
                let input_bytes = std::fs::metadata(&rc.input).map(|m| m.len()).unwrap_or(0);
                let output_bytes = std::fs::metadata(&rc.output).map(|m| m.len()).unwrap_or(0);
                eprintln!(
                    "{}",
                    format_metrics_line(
                        elapsed,
                        input_bytes,
                        output_bytes,
                        mem::peak_rss_bytes(),
                        &stats
                    )
                );
            }
            if let Some(path) = &args.emit_build_metadata {
                let meta = serde_json::json!({
                    "format_version": pipeline::FORMAT_VERSION,
                    "build_seed": rc.config.seed.to_string(),
                });
                std::fs::write(path, serde_json::to_vec(&meta)?)?;
            }
            Ok(())
        }
        Decision::Missing => {
            eprintln!(
                "error: the following required arguments were not provided:\n  <INPUT>\n  <OUTPUT>\n\nRun `basilisk --help` for usage."
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_line_is_stable_parseable_and_handles_missing_rss() {
        let stats = pipeline::BuildStats {
            protos: 2,
            instructions: 141,
            constants: 38,
            string_constants: 6,
            opcode_kinds: 40,
            poly_morphable: 12,
            encfuncs: 3,
            natives: 1,
            compress_requested: true,
            compress_selected: false,
            raw_artifact_bytes: 25406,
            compressed_artifact_bytes: 25639,
            serialized_total_bytes: 18004,
            serialized_code_bytes: 9001,
            serialized_const_bytes: 6003,
            serialized_number_const_bytes: 2001,
            serialized_string_const_bytes: 3800,
            serialized_other_const_bytes: 202,
            serialized_upvalue_bytes: 500,
            serialized_proto_meta_bytes: 300,
            serialized_lineinfo_bytes: 700,
            serialized_section_header_bytes: 1500,
            serialized_act_program_bytes: 200,
            serialized_aead_tag_bytes: 304,
            serialized_child_proto_bytes: 12000,
            serialized_const_count: 38,
            number_const_raw_count: 4,
            number_const_dense_count: 21,
            number_const_raw_bytes: 72,
            number_const_dense_bytes: 231,
            number_const_dense_saved_bytes: 147,
            kepoch_wide_skips: 6,
            code_opcode_bytes: 271245,
            code_operand_bytes: 1200000,
            code_dead_operand_bytes: 260000,
            code_dead_operand_count: 190000,
            code_live_operand_bytes: 940000,
            code_arity_saved_bytes: 210000,
            base85_payload_chars: 22505,
            base85_overhead_bytes: 4501,
            root_proto_instructions: 12,
            deferred_instructions: 129,
            hot_callback_total: 9,
            hot_callback_input: 2,
            hot_callback_render: 1,
            hot_callback_event: 4,
            hot_callback_generic: 2,
            hot_callback_instructions: 480,
            hot_callback_top_instructions: 120,
            native_marked_callbacks: 3,
            native_marked_input: 1,
            native_marked_render: 1,
            native_marked_event: 1,
            native_marked_generic: 0,
            native_total_bytes: 105824,
            native_literal_bytes: 5357,
        };
        let line = format_metrics_line(
            std::time::Duration::from_millis(470),
            320793,
            2492718,
            Some(153190400),
            &stats,
        );
        assert!(
            line.starts_with("basilisk_metrics "),
            "stable prefix for greppability: {line}"
        );
        for tok in [
            "elapsed_ms=470",
            "input_bytes=320793",
            "output_bytes=2492718",
            "ratio=7.7705",
            "peak_rss_bytes=153190400",
            "protos=2",
            "instructions=141",
            "constants=38",
            "string_constants=6",
            "opcode_kinds=40",
            "poly_morphable=12",
            "encfuncs=3",
            "natives=1",
            "compress_requested=true",
            "compress_selected=false",
            "raw_artifact_bytes=25406",
            "compressed_artifact_bytes=25639",
            "serialized_total_bytes=18004",
            "serialized_code_bytes=9001",
            "serialized_const_bytes=6003",
            "serialized_number_const_bytes=2001",
            "serialized_string_const_bytes=3800",
            "serialized_other_const_bytes=202",
            "serialized_upvalue_bytes=500",
            "serialized_proto_meta_bytes=300",
            "serialized_lineinfo_bytes=700",
            "serialized_section_header_bytes=1500",
            "serialized_aead_tag_bytes=304",
            "serialized_child_proto_bytes=12000",
            "serialized_const_count=38",
            "number_const_raw_count=4",
            "number_const_dense_count=21",
            "number_const_raw_bytes=72",
            "number_const_dense_bytes=231",
            "number_const_dense_saved_bytes=147",
            "kepoch_wide_skips=6",
            "code_opcode_bytes=271245",
            "code_operand_bytes=1200000",
            "code_dead_operand_bytes=260000",
            "code_dead_operand_count=190000",
            "code_live_operand_bytes=940000",
            "code_arity_saved_bytes=210000",
            "base85_payload_chars=22505",
            "base85_overhead_bytes=4501",
            "root_proto_instructions=12",
            "deferred_instructions=129",
            "hot_callback_total=9",
            "hot_callback_input=2",
            "hot_callback_render=1",
            "hot_callback_event=4",
            "hot_callback_generic=2",
            "hot_callback_instructions=480",
            "hot_callback_top_instructions=120",
            "native_marked_callbacks=3",
            "native_marked_input=1",
            "native_marked_render=1",
            "native_marked_event=1",
            "native_marked_generic=0",
            "native_total_bytes=105824",
            "native_literal_bytes=5357",
        ] {
            assert!(line.contains(tok), "metrics line missing `{tok}`: {line}");
        }
        assert!(!line.contains('\n'), "single line");
        let unavailable = format_metrics_line(
            std::time::Duration::from_millis(0),
            0,
            100,
            None,
            &pipeline::BuildStats::default(),
        );
        assert!(
            unavailable.contains("peak_rss_bytes=na"),
            "absent RSS renders as na: {unavailable}"
        );
        assert!(
            unavailable.contains("ratio=0.0000"),
            "zero input => zero ratio, no div-by-zero: {unavailable}"
        );
    }

    #[test]
    fn line_info_default_follows_profile_and_explicit_wins() {
        assert!(
            resolve_line_info(None, ProfileArg::CliTest),
            "cli-test dev default = on"
        );
        assert!(
            resolve_line_info(None, ProfileArg::Studio),
            "studio dev default = on"
        );
        assert!(
            !resolve_line_info(None, ProfileArg::Executor),
            "executor release default = off"
        );
        assert!(
            !resolve_line_info(None, ProfileArg::RobloxClient),
            "roblox-client release default = off"
        );
        assert!(
            !resolve_line_info(None, ProfileArg::RobloxServer),
            "roblox-server release default = off"
        );
        assert!(
            resolve_line_info(Some(LineInfoArg::On), ProfileArg::Executor),
            "explicit on overrides release default"
        );
        assert!(
            !resolve_line_info(Some(LineInfoArg::Off), ProfileArg::CliTest),
            "explicit off overrides dev default"
        );
    }

    #[test]
    fn executor_release_defaults_hardening_and_explicit_off_wins() {
        for p in [
            ProfileArg::Executor,
            ProfileArg::RobloxClient,
            ProfileArg::RobloxServer,
        ] {
            assert!(
                resolve_hardening(false, false, is_release_profile(p)),
                "release profile defaults hardening on"
            );
        }
        for p in [ProfileArg::CliTest, ProfileArg::Studio] {
            assert!(
                !resolve_hardening(false, false, is_release_profile(p)),
                "dev profile stays un-hardened by default"
            );
        }
        assert!(
            !resolve_hardening(false, true, is_release_profile(ProfileArg::Executor)),
            "explicit opt-out wins on release"
        );
        assert!(
            resolve_hardening(true, false, is_release_profile(ProfileArg::CliTest)),
            "explicit on works on dev"
        );
    }

    #[test]
    fn poly_stream_defaults_by_profile() {
        for p in [
            ProfileArg::Executor,
            ProfileArg::RobloxClient,
            ProfileArg::RobloxServer,
        ] {
            assert_eq!(
                resolve_poly_stream(None, p),
                pipeline::PolyStream::Aggressive,
                "release defaults poly-stream aggressive"
            );
        }
        for p in [ProfileArg::CliTest, ProfileArg::Studio] {
            assert_eq!(
                resolve_poly_stream(None, p),
                pipeline::PolyStream::Off,
                "dev defaults poly-stream off"
            );
        }
        assert_eq!(
            resolve_poly_stream(Some(PolyStreamArg::Off), ProfileArg::Executor),
            pipeline::PolyStream::Off,
            "explicit off wins on release"
        );
        assert_eq!(
            resolve_poly_stream(Some(PolyStreamArg::Conservative), ProfileArg::CliTest),
            pipeline::PolyStream::Conservative,
            "explicit conservative wins on dev"
        );
        assert_eq!(
            resolve_poly_stream(Some(PolyStreamArg::Aggressive), ProfileArg::Studio),
            pipeline::PolyStream::Aggressive,
            "explicit aggressive wins on dev"
        );
    }

    #[test]
    fn optimization_defaults_follow_profile_and_explicit_wins() {
        assert_eq!(
            resolve_optimization(None, ProfileArg::CliTest),
            1,
            "cli-test dev default = 1"
        );
        assert_eq!(
            resolve_optimization(None, ProfileArg::Studio),
            1,
            "studio dev default = 1"
        );
        for p in [
            ProfileArg::Executor,
            ProfileArg::RobloxClient,
            ProfileArg::RobloxServer,
        ] {
            assert_eq!(resolve_optimization(None, p), 2, "release default = 2");
        }
        assert_eq!(
            resolve_optimization(Some(0), ProfileArg::Executor),
            0,
            "explicit 0 overrides release default"
        );
        assert_eq!(
            resolve_optimization(Some(3), ProfileArg::CliTest),
            3,
            "explicit 3 overrides dev default"
        );
    }

    #[test]
    fn source_opt_safe_raises_the_optimizer_and_off_is_neutral() {
        let base = Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: ProfileArg::CliTest,
            ..Default::default()
        };
        let off = build_run_config(&base).unwrap().config.optimization;
        assert_eq!(off, 1, "cli-test default optimization is 1; --source-opt off leaves it untouched (byte-identical)");
        let safe = build_run_config(&Args {
            source_opt: SourceOpt::Safe,
            ..base.clone()
        })
        .unwrap()
        .config
        .optimization;
        assert!(
            safe >= 2,
            "--source-opt safe raises the optimizer to >= 2, got {safe}"
        );
    }

    #[test]
    fn optimization_level_three_enables_aggressive_lower_levels_do_not() {
        let mk = |opt: Option<u8>| {
            let args = Args {
                input: Some(PathBuf::from("in.luau")),
                output: Some(PathBuf::from("out.luau")),
                target_profile: ProfileArg::Executor,
                optimization: opt,
                ..Default::default()
            };
            build_run_config(&args).unwrap().config
        };
        assert!(
            !mk(Some(0)).aggressive && !mk(Some(1)).aggressive && !mk(Some(2)).aggressive,
            "levels 0/1/2 do not enable the aggressive optimizer"
        );
        assert!(
            mk(Some(3)).aggressive,
            "level 3 enables the aggressive optimizer"
        );
        assert_eq!(
            mk(None).optimization,
            2,
            "executor default resolves to level 2"
        );
        assert!(
            !mk(None).aggressive,
            "executor default (level 2) leaves the optimizer off (byte-identical baseline)"
        );
        assert!(mk(Some(2)).static_env == false, "static-env off by default");
    }

    #[test]
    fn basil_opt_aggressive_flag_still_forces_aggressive_at_any_level() {
        let args = Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: ProfileArg::Executor,
            optimization: Some(1),
            basil_opt_aggressive: true,
            ..Default::default()
        };
        assert!(
            build_run_config(&args).unwrap().config.aggressive,
            "explicit --basil-opt-aggressive stays independent of level"
        );
    }

    #[test]
    fn optimization_flag_parses_alias_and_rejects_out_of_range() {
        let base = ["basilisk", "in.luau", "out.luau"];
        let parse = |extra: &[&str]| {
            let mut a = base.to_vec();
            a.extend_from_slice(extra);
            Args::try_parse_from(a)
        };
        assert_eq!(
            parse(&["--optimization", "3"]).unwrap().optimization,
            Some(3)
        );
        assert_eq!(
            parse(&["--optimization-level", "0"]).unwrap().optimization,
            Some(0),
            "alias sets the same field"
        );
        assert!(
            parse(&["--optimization", "4"]).is_err(),
            "out-of-range level rejected"
        );
        assert!(
            parse(&["--optimization", "x"]).is_err(),
            "non-numeric level rejected"
        );
        assert!(
            parse(&["--static-env"]).unwrap().static_env,
            "--static-env parses"
        );
        assert!(
            !parse(&[]).unwrap().static_env,
            "static-env off without the flag"
        );
        assert!(
            parse(&["--runtime-profile-markers"])
                .unwrap()
                .runtime_profile_markers,
            "--runtime-profile-markers parses"
        );
        assert!(
            !parse(&[]).unwrap().runtime_profile_markers,
            "runtime-profile-markers off without the flag"
        );
        assert_eq!(
            parse(&["--experimental-frame-const-reuse", "control"])
                .unwrap()
                .experimental_frame_const_reuse,
            Some(FrameConstReuseArg::Control)
        );
        assert_eq!(
            parse(&["--experimental-frame-const-reuse", "strings"])
                .unwrap()
                .experimental_frame_const_reuse,
            Some(FrameConstReuseArg::Strings)
        );
        assert_eq!(
            parse(&["--experimental-frame-const-reuse", "numbers"])
                .unwrap()
                .experimental_frame_const_reuse,
            Some(FrameConstReuseArg::Numbers)
        );
        assert_eq!(
            parse(&["--experimental-frame-const-reuse", "all"])
                .unwrap()
                .experimental_frame_const_reuse,
            Some(FrameConstReuseArg::All)
        );
        assert!(parse(&["--experimental-frame-const-reuse", "off"]).is_err());
    }

    #[test]
    fn runtime_profile_markers_defaults_off_and_wires_into_config() {
        let base = Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: ProfileArg::Executor,
            ..Default::default()
        };
        assert!(
            !build_run_config(&base)
                .unwrap()
                .config
                .runtime_profile_markers,
            "off by default in the resolved config"
        );
        let on = Args {
            runtime_profile_markers: true,
            ..base
        };
        assert!(
            build_run_config(&on)
                .unwrap()
                .config
                .runtime_profile_markers,
            "flag threads into the resolved config"
        );
    }

    #[test]
    fn frame_const_reuse_defaults_off_and_wires_each_hidden_mode() {
        let base = Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            ..Default::default()
        };
        assert_eq!(
            build_run_config(&base).unwrap().config.frame_const_reuse,
            pipeline::FrameConstReuseMode::Off
        );
        for (arg, expected) in [
            (
                FrameConstReuseArg::Control,
                pipeline::FrameConstReuseMode::Control,
            ),
            (
                FrameConstReuseArg::Strings,
                pipeline::FrameConstReuseMode::Strings,
            ),
            (
                FrameConstReuseArg::Numbers,
                pipeline::FrameConstReuseMode::Numbers,
            ),
            (FrameConstReuseArg::All, pipeline::FrameConstReuseMode::All),
        ] {
            let current = Args {
                experimental_frame_const_reuse: Some(arg),
                ..base.clone()
            };
            assert_eq!(
                build_run_config(&current).unwrap().config.frame_const_reuse,
                expected
            );
        }
    }

    #[test]
    fn decide_runs_only_with_both_args_else_errors() {
        assert!(
            matches!(decide(true, true), Decision::Run),
            "both args -> run"
        );
        assert!(
            matches!(decide(false, false), Decision::Missing),
            "no args -> error, never hang"
        );
        assert!(
            matches!(decide(true, false), Decision::Missing),
            "input only -> error"
        );
        assert!(
            matches!(decide(false, true), Decision::Missing),
            "output only -> error"
        );
    }

    #[test]
    fn build_run_config_applies_the_same_resolution_as_the_cli() {
        let args = Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: ProfileArg::Executor,
            flatten: true,
            opaque: true,
            junk: true,
            fuse: true,
            ..Default::default()
        };
        let rc = build_run_config(&args).unwrap();
        assert!(!rc.config.line_info, "executor -> line-info off");
        assert!(rc.config.lph_collapse, "executor -> lph-collapse on");
        assert!(rc.config.surface, "executor -> lura-surface on");
        assert!(
            rc.config.strip_source_names,
            "executor -> strip-source-names on"
        );
        assert_eq!(
            rc.config.poly_stream,
            pipeline::PolyStream::Aggressive,
            "executor -> poly-stream aggressive"
        );
        assert!(rc.config.flatten && rc.config.opaque && rc.config.junk && rc.config.fuse);

        let dev = Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: ProfileArg::CliTest,
            ..Default::default()
        };
        let rc = build_run_config(&dev).unwrap();
        assert!(rc.config.line_info, "cli-test -> line-info on");
        assert!(
            !rc.config.lph_collapse && !rc.config.surface,
            "dev -> no forced hardening"
        );
        assert!(
            !rc.config.strip_source_names,
            "cli-test -> strip-source-names off by default"
        );
        assert_eq!(
            rc.config.poly_stream,
            pipeline::PolyStream::Off,
            "cli-test -> poly-stream off by default"
        );
    }

    #[test]
    fn production_trio_defaults_to_executor_only() {
        use ProfileArg::*;
        let base = |p: ProfileArg| Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: p,
            ..Default::default()
        };
        for (p, on) in [
            (Executor, true),
            (RobloxClient, false),
            (RobloxServer, false),
            (Studio, false),
            (CliTest, false),
        ] {
            let rc = build_run_config(&base(p)).unwrap();
            assert_eq!(rc.config.semgroup, on, "{} semgroup", profile_cli_name(p));
            assert_eq!(
                rc.config.semantic_family,
                on,
                "{} semantic_family",
                profile_cli_name(p)
            );
            assert_eq!(
                rc.config.instruction_family,
                on,
                "{} instruction_family",
                profile_cli_name(p)
            );
            assert!(
                !rc.config.stateful_recovery,
                "{} D1 off by default",
                profile_cli_name(p)
            );
            assert!(
                !rc.config.state_family,
                "{} state-family off by default",
                profile_cli_name(p)
            );
        }

        let mut optin = base(RobloxClient);
        optin.experimental_semgroup = true;
        assert!(
            build_run_config(&optin).unwrap().config.semgroup,
            "explicit opt-in enables the trio on any target"
        );

        let mut optout = base(Executor);
        optout.no_semgroup = true;
        optout.no_semantic_family = true;
        optout.no_instruction_family = true;
        let rc = build_run_config(&optout).unwrap();
        assert!(
            !rc.config.semgroup && !rc.config.semantic_family && !rc.config.instruction_family,
            "opt-out overrides the executor default"
        );
    }

    #[test]
    fn executor_profile_defaults_to_the_accepted_performance_profile() {
        let rc = build_run_config(&Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: ProfileArg::Executor,
            ..Default::default()
        })
        .unwrap();
        let c = &rc.config;

        assert!(!c.flatten, "flatten off");
        assert!(c.ablate_fragment, "string fragmentation off");
        assert_eq!(
            c.frame_const_reuse,
            pipeline::FrameConstReuseMode::All,
            "frame const reuse all"
        );
        assert_eq!(c.optimization, 2, "optimization 2");
        assert!(!c.line_info, "line info off");
        assert!(c.opaque, "opaque on");
        assert!(c.fuse, "fuse on");
        assert!(!c.junk, "junk off");
        assert_eq!(
            c.poly_stream,
            pipeline::PolyStream::Aggressive,
            "aggressive poly-stream"
        );
        assert!(c.lph_collapse, "lph collapse on");
        assert!(c.surface, "lura surface on");
        assert!(c.strip_source_names, "strip source names on");
        assert!(!c.explicit_optin, "explicit opt-in stays off");
    }

    #[test]
    fn the_new_executor_defaults_stay_overridable_and_profile_scoped() {
        let exec = |f: fn(&mut Args)| {
            let mut a = Args {
                input: Some(PathBuf::from("in.luau")),
                output: Some(PathBuf::from("out.luau")),
                target_profile: ProfileArg::Executor,
                ..Default::default()
            };
            f(&mut a);
            build_run_config(&a).unwrap().config
        };
        assert!(
            !exec(|a| a.fragment_strings = true).ablate_fragment,
            "--fragment-strings restores fragmentation"
        );
        assert!(!exec(|a| a.no_opaque = true).opaque, "--no-opaque wins");
        assert!(!exec(|a| a.no_fuse = true).fuse, "--no-fuse wins");
        assert_eq!(
            exec(|a| a.experimental_frame_const_reuse = Some(FrameConstReuseArg::Control))
                .frame_const_reuse,
            pipeline::FrameConstReuseMode::Control,
            "an explicit frame-const-reuse mode wins"
        );
        assert!(
            exec(|a| a.flatten = true).flatten,
            "--flatten still available"
        );

        let dev = build_run_config(&Args {
            input: Some(PathBuf::from("in.luau")),
            output: Some(PathBuf::from("out.luau")),
            target_profile: ProfileArg::CliTest,
            ..Default::default()
        })
        .unwrap()
        .config;
        assert!(
            !dev.ablate_fragment,
            "non-executor profiles keep fragmentation"
        );
        assert_eq!(
            dev.frame_const_reuse,
            pipeline::FrameConstReuseMode::Off,
            "and keep frame const reuse off"
        );
        assert!(
            !dev.opaque && !dev.fuse,
            "and do not silently gain release passes"
        );
    }
}
