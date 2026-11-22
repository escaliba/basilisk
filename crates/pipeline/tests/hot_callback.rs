use std::path::{Path, PathBuf};

use pipeline::{
    BuildStats, Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

const SEED: u64 = 0x_00CA_11BA;

fn unique_tmp(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn cfg(profile: TargetProfile, policy: HotCallbackPolicy) -> Config {
    Config {
        seed: SEED,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: true,
        junk: false,
        fuse: true,
        minify: true,
        compress: false,
        anti_envlog: false,
        hard_dispatch: false,
        surface: false,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: SensitiveOpts::default(),
        profile,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: true,
        strip_source_names: false,
        poly_stream: PolyStream::Off,
        optimization: 0,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: Default::default(),
        hot_callback_policy: policy,
        ablate_fragment: false,
        hot_light: false,
        explicit_optin: false,
        shell_probe: false,
        underscore_hex_numlit: false,
        shell_family: None,
        notices: pipeline::NoticeConfig::default(),
        stateful_recovery: false,
        stateful_framing: false,
        property_key_rename: pipeline::PropKeyMode::Off,
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

fn write(src: &str) -> PathBuf {
    let input = unique_tmp("hc_in");
    std::fs::write(&input, src).unwrap();
    input
}

fn build(input: &Path, cfg: &Config) -> String {
    let output = unique_tmp("hc_out");
    pipeline::run(input, &output, cfg).expect("virtualize");
    let s = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    s
}

fn stats(input: &Path, cfg: &Config) -> BuildStats {
    let output = unique_tmp("hc_stats");
    let mut got: Option<BuildStats> = None;
    pipeline::run_capturing_stats(input, &output, cfg, None, &mut got).expect("virtualize");
    let _ = std::fs::remove_file(&output);
    got.expect("stats captured")
}

const CONNECT_SRC: &str = r#"
local UIS = game:GetService("UserInputService")
local RunService = game:GetService("RunService")
local part = workspace.Part

UIS.InputBegan:Connect(function(input, gpe)
    if input.KeyCode == Enum.KeyCode.E then
        local total = 0
        for i = 1, 100 do total = total + i end
        print(total)
    end
end)

RunService.RenderStepped:Connect(function(dt)
    part.CFrame = part.CFrame * CFrame.new(0, dt, 0)
end)

RunService:BindToRenderStep("spin", 200, function(dt)
    part.Orientation = part.Orientation + Vector3.new(0, dt * 10, 0)
end)

part.Touched:Connect(function(hit)
    if hit.Parent then hit.Parent:Destroy() end
end)

local function helper(x)
    return x * 2
end

button.MouseButton1Click:Connect(function()
    helper(5)
end)
"#;

#[test]
fn detects_and_categorizes_event_input_render_callbacks() {
    let input = write(CONNECT_SRC);
    let s = stats(
        &input,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert_eq!(s.hot_callback_total, 5, "5 connected callbacks detected");
    assert_eq!(s.hot_callback_input, 1, "InputBegan -> Input");
    assert_eq!(
        s.hot_callback_render, 2,
        "RenderStepped + BindToRenderStep -> Render"
    );
    assert_eq!(
        s.hot_callback_event, 2,
        "Touched + MouseButton1Click -> Event"
    );
    assert_eq!(s.hot_callback_generic, 0, "no plain-call callbacks here");
    assert_eq!(s.native_marked_callbacks, 0, "no BASIL_NO_VIRTUALIZE here");
    assert!(
        s.hot_callback_instructions > 0,
        "counts emitted VM instructions inside callbacks"
    );
    assert!(
        s.hot_callback_top_instructions <= s.hot_callback_instructions,
        "top single callback <= total across callbacks"
    );
    let _ = std::fs::remove_file(&input);
}

#[test]
fn does_not_flag_plain_local_helpers() {
    let input = write("local function add(a, b) return a + b end\nlocal x = add(1, 2)\nprint(x)\n");
    let s = stats(
        &input,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert_eq!(
        s.hot_callback_total, 0,
        "a plain local helper is not a hot callback"
    );
    assert_eq!(s.native_marked_callbacks, 0);
    let _ = std::fs::remove_file(&input);
}

#[test]
fn generic_call_argument_callback_is_generic() {
    let input = write(
        "spawn(function() while true do wait() end end)\ntask.spawn(function() print(1) end)\n",
    );
    let s = stats(
        &input,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert_eq!(
        s.hot_callback_total, 2,
        "function args to a call are generic hot candidates"
    );
    assert_eq!(s.hot_callback_generic, 2);
    assert_eq!(
        s.hot_callback_input + s.hot_callback_render + s.hot_callback_event,
        0
    );
    let _ = std::fs::remove_file(&input);
}

#[test]
fn native_marked_callback_counted_separately_not_as_hot() {
    let src = r#"
local RunService = game:GetService("RunService")
RunService.RenderStepped:Connect(BASIL_NO_VIRTUALIZE(function(dt)
    local x = 0
    for i = 1, 50 do x = x + i end
    return x
end))
game:GetService("UserInputService").InputBegan:Connect(function(i) print(i) end)
"#;
    let input = write(src);
    let s = stats(
        &input,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert_eq!(
        s.native_marked_callbacks, 1,
        "the NO_VIRTUALIZE callback is native-marked"
    );
    assert_eq!(
        s.hot_callback_render, 0,
        "native-marked callback is NOT a hot virtualized callback"
    );
    assert_eq!(
        s.hot_callback_total, 1,
        "only the virtualized InputBegan callback is hot"
    );
    assert_eq!(s.hot_callback_input, 1);
    let _ = std::fs::remove_file(&input);
}

#[test]
fn policy_off_disables_detection_but_keeps_artifact() {
    let input = write(CONNECT_SRC);
    let s = stats(&input, &cfg(TargetProfile::CliTest, HotCallbackPolicy::Off));
    assert_eq!(s.hot_callback_total, 0, "policy=off skips detection");
    assert_eq!(
        s.native_marked_callbacks, 0,
        "policy=off does not count native marks either"
    );
    assert!(s.instructions > 0, "the build still happens fully");
    let _ = std::fs::remove_file(&input);
}

#[test]
fn report_and_off_and_capture_are_all_byte_identical() {
    let input = write(CONNECT_SRC);
    for profile in [TargetProfile::CliTest, TargetProfile::Executor] {
        let report = build(&input, &cfg(profile, HotCallbackPolicy::Report));
        let off = build(&input, &cfg(profile, HotCallbackPolicy::Off));
        assert_eq!(
            report, off,
            "{profile:?}: report vs off must be byte-identical (report-only, no devirtualization)"
        );

        let output = unique_tmp("hc_cap");
        let mut got = None;
        pipeline::run_capturing_stats(
            &input,
            &output,
            &cfg(profile, HotCallbackPolicy::Report),
            None,
            &mut got,
        )
        .unwrap();
        let captured = std::fs::read_to_string(&output).unwrap();
        let _ = std::fs::remove_file(&output);
        assert_eq!(
            report, captured,
            "{profile:?}: detection during capture must be byte-identical to plain run"
        );
    }
    let _ = std::fs::remove_file(&input);
}

#[test]
fn categories_stable_across_seeds() {
    let input = write(CONNECT_SRC);
    for seed in [1u64, 2, 7, 0x_DEAD_BEEF, 0x_1234_5678] {
        let mut c = cfg(TargetProfile::CliTest, HotCallbackPolicy::Report);
        c.seed = seed;
        let s = stats(&input, &c);
        assert_eq!(
            (s.hot_callback_total, s.hot_callback_input, s.hot_callback_render, s.hot_callback_event),
            (5, 1, 2, 2),
            "seed {seed:#x}: detection is seed-independent (depends on source shape, not build seed)"
        );
    }
    let _ = std::fs::remove_file(&input);
}

#[test]
fn detail_listing_is_sorted_and_does_not_leak_source_or_labels() {
    let input = write(CONNECT_SRC);
    let src = std::fs::read_to_string(&input).unwrap();
    let c = cfg(TargetProfile::Executor, HotCallbackPolicy::Report);
    let detail = pipeline::hot_callback_detail(&src, &c).expect("detail");
    assert_eq!(detail.len(), 5, "one detail entry per hot callback proto");
    for w in detail.windows(2) {
        assert!(
            w[0].instructions >= w[1].instructions,
            "detail is sorted by instruction count descending"
        );
    }
    let mut cs = c;
    cs.strip_source_names = true;
    let artifact = build(&input, &cs);
    for leak in [
        "InputBegan",
        "RenderStepped",
        "BindToRenderStep",
        "MouseButton1Click",
        "helper",
        "hot_callback",
    ] {
        assert!(
            !artifact.contains(leak),
            "callback label/source `{leak}` must not appear in the emitted artifact"
        );
    }
    let _ = std::fs::remove_file(&input);
}
