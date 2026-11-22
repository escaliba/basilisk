use std::path::{Path, PathBuf};

use pipeline::{
    BuildStats, Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

fn unique_tmp(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    match std::process::Command::new("luau").arg("--help").output() {
        Ok(_) => Some("luau".to_string()),
        Err(_) => None,
    }
}

fn cfg(profile: TargetProfile, policy: HotCallbackPolicy) -> Config {
    Config {
        seed: 0x_5EED_1234,
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
    let input = unique_tmp("ne_in");
    std::fs::write(&input, src).unwrap();
    input
}

fn build(input: &Path, cfg: &Config) -> String {
    let output = unique_tmp("ne_out");
    pipeline::run(input, &output, cfg).expect("virtualize");
    let s = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    s
}

fn stats(input: &Path, cfg: &Config) -> BuildStats {
    let output = unique_tmp("ne_stats");
    let mut got: Option<BuildStats> = None;
    pipeline::run_capturing_stats(input, &output, cfg, None, &mut got).expect("virtualize");
    let _ = std::fs::remove_file(&output);
    got.expect("stats")
}

fn build_err(src: &str, cfg: &Config) -> String {
    let input = write(src);
    let output = unique_tmp("ne_err");
    let err = pipeline::run(&input, &output, cfg).expect_err("build must fail");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    format!("{err:#}")
}

const ROBLOX_NATIVE_SRC: &str = r#"
local RunService = game:GetService("RunService")
RunService.RenderStepped:Connect(BASIL_NO_VIRTUALIZE(function(dt) return dt * 2 end))
game:GetService("RunService"):BindToRenderStep("spin", 200, BASIL_NO_VIRTUALIZE(function(dt) return dt end))
TextBox:GetPropertyChangedSignal("Text"):Connect(BASIL_NO_VIRTUALIZE(function() return true end))
hookmetamethod(game, "__index", BASIL_NO_VIRTUALIZE(function(...) return ... end))
task.spawn(BASIL_NO_VIRTUALIZE(function() return 1 end))
"#;

#[test]
fn native_marked_callbacks_are_categorized() {
    let input = write(ROBLOX_NATIVE_SRC);
    let s = stats(
        &input,
        &cfg(TargetProfile::Executor, HotCallbackPolicy::Report),
    );
    assert_eq!(
        s.native_marked_callbacks, 5,
        "all five NO_VIRTUALIZE wraps counted"
    );
    assert_eq!(
        s.hot_callback_total, 0,
        "native-marked callbacks are never counted as hot virtualized"
    );
    assert_eq!(
        s.native_marked_render, 2,
        "RenderStepped + BindToRenderStep -> Render"
    );
    assert_eq!(
        s.native_marked_input, 1,
        "GetPropertyChangedSignal(\"Text\") -> Input"
    );
    assert_eq!(s.native_marked_event, 0);
    assert_eq!(
        s.native_marked_generic, 2,
        "hookmetamethod arg + task.spawn arg -> Generic"
    );
    assert_eq!(
        s.native_marked_input
            + s.native_marked_render
            + s.native_marked_event
            + s.native_marked_generic,
        s.native_marked_callbacks,
        "category breakdown partitions the native-marked total"
    );
    let _ = std::fs::remove_file(&input);
}

#[test]
fn table_constructor_callbacks_detected_by_field_name() {
    let src = r#"
local w = Lib:Window({
    Callback = function() return 1 end,
    OnClick = function() return 2 end,
    OnChanged = function(v) return v end,
    OnRender = function(dt) return dt end,
    Update = function() return 3 end,
    Handler = function() return 4 end,
    TextChanged = function() return 5 end,
    Title = "not a callback",
    Size = 100,
})
local b = {
    ["Draw"] = function() return 6 end,
    Step = function() return 7 end,
    NotACallback = function() return 8 end,
}
"#;
    let input = write(src);
    let s = stats(
        &input,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert_eq!(
        s.hot_callback_total, 9,
        "9 callback-named fields; Title/Size/NotACallback excluded"
    );
    assert_eq!(s.hot_callback_input, 3, "OnClick + OnChanged + TextChanged");
    assert_eq!(s.hot_callback_render, 4, "OnRender + Update + Draw + Step");
    assert_eq!(s.hot_callback_event, 2, "Callback + Handler");
    assert_eq!(s.hot_callback_generic, 0);
    let _ = std::fs::remove_file(&input);
}

#[test]
fn table_field_detection_is_byte_identical_and_report_only() {
    let src = r#"
local b = { OnClick = function() return 1 end, Render = function() return 2 end, Callback = function() return 3 end }
return b
"#;
    let input = write(src);
    for profile in [TargetProfile::CliTest, TargetProfile::Executor] {
        let report = build(&input, &cfg(profile, HotCallbackPolicy::Report));
        let off = build(&input, &cfg(profile, HotCallbackPolicy::Off));
        assert_eq!(
            report, off,
            "{profile:?}: table-field detection must not change artifact bytes"
        );
    }
    let _ = std::fs::remove_file(&input);
}

#[test]
fn native_wrapped_table_field_counts_native_not_hot() {
    let src = r#"
local b = { OnRender = BASIL_NO_VIRTUALIZE(function(dt) return dt end) }
return b
"#;
    let input = write(src);
    let s = stats(
        &input,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert_eq!(
        s.native_marked_callbacks, 1,
        "the wrapped table-field callback is native-marked"
    );
    assert_eq!(
        s.native_marked_render, 1,
        "OnRender field name gives it the Render category"
    );
    assert_eq!(
        s.hot_callback_total, 0,
        "a native-marked table field is not a hot virtualized callback"
    );
    let _ = std::fs::remove_file(&input);
}

#[test]
fn no_virtualize_pure_function_patterns_run_correctly() {
    let Some(luau) = find_luau() else { return };
    let src = r##"
local f = BASIL_NO_VIRTUALIZE(function(a, b) return a + b end)
print("assign", f(2, 3))
print("immediate", BASIL_NO_VIRTUALIZE(function() return 7 end)())
local function apply(g) return g(10) end
print("arg", apply(BASIL_NO_VIRTUALIZE(function(x) return x * 2 end)))
local v = BASIL_NO_VIRTUALIZE(function(...) return select("#", ...), (...) end)
print("vararg", v(11, 22, 33))
local m = BASIL_NO_VIRTUALIZE(function(a, b) return a, b, a + b end)
print("multiret", m(4, 5))
"##;
    let input = write(src);
    let out = unique_tmp("ne_run");
    pipeline::run(
        &input,
        &out,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    )
    .unwrap();
    let res = std::process::Command::new(&luau)
        .arg(&out)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&res.stdout);
    assert!(stdout.contains("assign\t5"), "params preserved: {stdout}");
    assert!(
        stdout.contains("immediate\t7"),
        "immediate call works: {stdout}"
    );
    assert!(
        stdout.contains("arg\t20"),
        "native as call argument works: {stdout}"
    );
    assert!(
        stdout.contains("vararg\t3\t11"),
        "varargs preserved: {stdout}"
    );
    assert!(
        stdout.contains("multiret\t4\t5\t9"),
        "multiple returns preserved: {stdout}"
    );
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&out);
}

#[test]
fn roblox_style_patterns_virtualize_cleanly() {
    let input = write(ROBLOX_NATIVE_SRC);
    for profile in [TargetProfile::CliTest, TargetProfile::Executor] {
        let art = build(&input, &cfg(profile, HotCallbackPolicy::Report));
        assert!(!art.is_empty(), "{profile:?}: produces an artifact");
    }
    let _ = std::fs::remove_file(&input);
}

#[test]
fn invalid_reference_argument_is_rejected_clearly() {
    let msg = build_err(
        "local function g() return 1 end\nlocal f = BASIL_NO_VIRTUALIZE(g)\nprint(f())\n",
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert!(
        msg.contains("function literal"),
        "clear reference-arg error: {msg}"
    );
    assert!(msg.contains('g'), "names the offending reference: {msg}");
}

#[test]
fn nested_macro_inside_native_is_rejected() {
    let msg = build_err(
        "local f = BASIL_NO_VIRTUALIZE(function() return BASIL_HASH(\"secret\") end)\nprint(f())\n",
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert!(
        msg.contains("BASIL_") && msg.contains("NO_VIRTUALIZE"),
        "nested-macro rejection: {msg}"
    );
}

#[test]
fn native_escape_inside_encfunc_is_rejected() {
    let key = "0".repeat(64);
    let src = format!(
        "local f = BASIL_ENCFUNC(function() BASIL_NO_VIRTUALIZE(function() end)() return 1 end, \"{key}\", getKey())\nprint(f())\n"
    );
    let msg = build_err(
        &src,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    );
    assert!(
        msg.contains("ENCFUNC"),
        "ENCFUNC-nesting rejection mentions ENCFUNC: {msg}"
    );
}

#[test]
fn captured_closures_run_correctly() {
    let Some(luau) = find_luau() else { return };
    let src = r##"
local secret = 42
local snap = BASIL_NO_VIRTUALIZE(function() return secret end)
print("snapshot", snap())

local n = 0
local inc = BASIL_NO_VIRTUALIZE(function() n = n + 1 end)
local get = BASIL_NO_VIRTUALIZE(function() return n end)
inc(); inc(); inc()
print("cell", get(), n)

local box
local reader = BASIL_NO_VIRTUALIZE(function() return box end)
box = "late"
print("post", reader())

local vm = function() n = n + 10 end
vm(); inc()
print("shared", n)
"##;
    let input = write(src);
    let out = unique_tmp("ne_cap");
    pipeline::run(
        &input,
        &out,
        &cfg(TargetProfile::CliTest, HotCallbackPolicy::Report),
    )
    .unwrap();
    let res = std::process::Command::new(&luau)
        .arg(&out)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&res.stdout);
    assert!(
        stdout.contains("snapshot\t42"),
        "snapshot capture: {stdout}"
    );
    assert!(
        stdout.contains("cell\t3\t3"),
        "shared cell VM<->native + sibling aliasing: {stdout}"
    );
    assert!(
        stdout.contains("post\tlate"),
        "post-assignment visible: {stdout}"
    );
    assert!(
        stdout.contains("shared\t14"),
        "VM and native share one binding: {stdout}"
    );
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&out);
}
