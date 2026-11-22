use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use pipeline::{
    Config, FrameConstReuseMode, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};

const SEED: u64 = 0xB451_115C;

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
    Command::new("luau")
        .arg("--help")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn cfg(
    mode: FrameConstReuseMode,
    profile: bool,
    minify: bool,
    seed: u64,
    optimization: u8,
    poly_stream: PolyStream,
) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: true,
        junk: true,
        fuse: true,
        minify,
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
        line_info: false,
        strip_source_names: false,
        poly_stream,
        optimization,
        static_env: false,
        runtime_profile_markers: profile,
        frame_const_reuse: mode,
        hot_callback_policy: HotCallbackPolicy::Report,
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

fn build(source: &str, config: &Config) -> String {
    let input = unique_tmp("frame_const_in");
    let output = unique_tmp("frame_const_out");
    std::fs::write(&input, source).unwrap();
    pipeline::run(&input, &output, config).unwrap();
    let artifact = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(input);
    let _ = std::fs::remove_file(output);
    artifact
}

fn run_text(luau: &str, source: &str, prefix: &str) -> (String, Option<i32>) {
    let path = unique_tmp(prefix);
    std::fs::write(&path, source).unwrap();
    let output = Command::new(luau).arg(&path).output().unwrap();
    let result = (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.code(),
    );
    let _ = std::fs::remove_file(path);
    result
}

fn payload(source: &str) -> &str {
    let open = source.find("[==[").unwrap() + 4;
    let close = source[open..].find("]==]").unwrap() + open;
    &source[open..close]
}

fn normalize_mode(source: &str) -> String {
    [0u8, 1, 2, 3].into_iter().fold(source.to_string(), |s, n| {
        s.replace(&format!("local FCRM = {n}"), "local FCRM = MODE")
    })
}

fn accessor_region(source: &str) -> &str {
    let start = source.find("local function dvar").unwrap();
    let end = source[start..].find("local KGR =").unwrap() + start;
    &source[start..end]
}

fn profiler_counters(stdout: &str) -> HashMap<String, u64> {
    stdout
        .lines()
        .find(|line| line.starts_with("BASIL_EXEC final"))
        .unwrap()
        .split_whitespace()
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            value
                .parse::<u64>()
                .ok()
                .map(|value| (key.to_string(), value))
        })
        .collect()
}

fn semantics_source() -> &'static str {
    r#"
local empty = ""
local bytes = "\000\255A\128"
local long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
local zero = 0
local negzero = -0.0
local dense = 4503599627370496
local frac = 3.141592653589793
local posinf = 1e999
local neginf = -1e999
local nan = 0 / 0
local flag = false
local mt = { __add = function(a, b) return a.v + b.v end, __index = function(_, k) return "idx:" .. k end }
local a = setmetatable({ v = 7 }, mt)
local b = setmetatable({ v = 9 }, mt)
print("scalar", #empty, #bytes, string.byte(bytes, 1, 4), #long, zero, negzero == 0, dense, frac, flag)
print("f64", posinf == math.huge, neginf == -math.huge, nan ~= nan)
print("meta", a + b, a.missing)
local up = 0
local function multi(x, ...)
    up = up + 1
    local p = table.pack(...)
    local s = "frame-value"
    local n = 17
    return x, nil, p.n, p[1], p[2], p[3], s .. s, n + n, up
end
for i = 1, 3 do
    local p = table.pack(multi(i, "x", nil, i + 2))
    print("multi", p.n, p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9])
end
local function rec(n)
    local s = "recursive"
    if n == 0 then return s end
    return s .. ":" .. rec(n - 1)
end
print("rec", rec(4))
local co = coroutine.create(function(x)
    local s = "coroutine"
    coroutine.yield(s .. ":" .. x)
    return s .. ":" .. x .. ":done"
end)
local ok1, y = coroutine.resume(co, 5)
local ok2, z = coroutine.resume(co)
print("co", ok1, y, ok2, z)
local function bad()
    local s = "unwind-marker"
    error(s)
end
local ok3, err = pcall(bad)
print("pcall", ok3, string.find(tostring(err), "unwind-marker", 1, true) ~= nil)
local sum = 0
for i = 1, 5 do
    for _, v in ipairs({ 1, 2, 3 }) do sum = sum + i * v end
end
print("loops", sum)
"#
}

fn profiler_source() -> &'static str {
    r#"
local function probe(k)
    local out = ""
    local n = 0
    for _ = 1, 6 do out = out .. "repeat-string" end
    for _ = 1, 4 do
        n = n + 11
        n = n + 11
        n = n + 22
        n = n + 33
        n = n + 44
        n = n + 55
        n = n + 66
        n = n + 77
        n = n + 88
        n = n + 99
        n = n + 111
    end
    return #out + n + k
end
for i = 1, 4 do print("probe", probe(i)) end
"#
}

fn wide_register_source() -> String {
    let mut source = String::from(
        "local function big(seed)\nlocal function g(...) local t={...} local s=0 for i=1,#t do s=s+t[i] end return s end\n",
    );
    for i in 1..=125u32 {
        source.push_str(&format!("local v{i}=(seed*{i}+{})%251\n", i * i));
    }
    let args = (1..=125u32)
        .map(|i| format!("v{i}"))
        .collect::<Vec<_>>()
        .join(",");
    source.push_str(&format!(
        "return g({args})%1000000\nend\nprint(big(3),big(37),big(200))\n"
    ));
    source
}

#[test]
fn default_path_is_uninstrumented() {
    let source = profiler_source();
    let off = build(
        source,
        &cfg(
            FrameConstReuseMode::Off,
            false,
            false,
            SEED,
            0,
            PolyStream::Aggressive,
        ),
    );
    let modes = [
        FrameConstReuseMode::Control,
        FrameConstReuseMode::Strings,
        FrameConstReuseMode::Numbers,
        FrameConstReuseMode::All,
    ];
    let artifacts = modes
        .into_iter()
        .map(|mode| {
            let first = build(
                source,
                &cfg(mode, false, false, SEED, 0, PolyStream::Aggressive),
            );
            let second = build(
                source,
                &cfg(mode, false, false, SEED, 0, PolyStream::Aggressive),
            );
            assert_eq!(first, second);
            first
        })
        .collect::<Vec<_>>();
    assert!(!off.contains("FCRM"));
    assert!(!off.contains("proto[19]"));
    assert!(!off.contains("local fcm = {}"));
    assert!(!off.contains("PROF_K"));
    assert!(artifacts.iter().all(|a| !a.contains("PROF_K")));
    assert!(artifacts
        .iter()
        .all(|a| payload(a) == payload(&artifacts[0])));
    assert!(artifacts
        .iter()
        .all(|a| normalize_mode(a) == normalize_mode(&artifacts[0])));
    assert_eq!(accessor_region(&off), accessor_region(&artifacts[0]));
    assert!(artifacts[0].contains("local FCRM = 0"));
    assert!(artifacts[1].contains("local FCRM = 1"));
    assert!(artifacts[2].contains("local FCRM = 2"));
    assert!(artifacts[3].contains("local FCRM = 3"));
    assert!(artifacts[0].contains("local function kget(consts, i, pkey, kc, ktok)"));
    assert!(artifacts[0].contains("if not dead and kx and not kx[i] then"));
    assert!(artifacts[0].contains("t == \"string\""));
    assert!(artifacts[0].contains("t == \"number\""));
    assert!(!artifacts[0].contains("t == \"table\""));
    assert!(bytecode::opcode::ALL.len() <= 256);
}

#[test]
fn every_mode_matches_raw_semantics_across_seeds_optimization_and_poly() {
    let Some(luau) = find_luau() else { return };
    let source = semantics_source();
    let raw = run_text(&luau, source, "frame_const_raw");
    for seed in [7u64, SEED] {
        for optimization in [0u8, 2] {
            for poly in [PolyStream::Off, PolyStream::Aggressive] {
                for mode in [
                    FrameConstReuseMode::Control,
                    FrameConstReuseMode::Strings,
                    FrameConstReuseMode::Numbers,
                    FrameConstReuseMode::All,
                ] {
                    let artifact = build(source, &cfg(mode, false, true, seed, optimization, poly));
                    assert_eq!(
                        run_text(&luau, &artifact, "frame_const_virtual"),
                        raw,
                        "seed={seed} optimization={optimization} poly={poly:?} mode={mode:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn profiler_separates_string_redecrypt_numeric_thrash_and_combined_reuse() {
    let Some(luau) = find_luau() else { return };
    let source = profiler_source();
    let mut by_mode = HashMap::new();
    for mode in [
        FrameConstReuseMode::Control,
        FrameConstReuseMode::Strings,
        FrameConstReuseMode::Numbers,
        FrameConstReuseMode::All,
    ] {
        let artifact = build(
            source,
            &cfg(mode, true, true, SEED, 0, PolyStream::Aggressive),
        );
        assert!(artifact.contains("kcall="));
        assert!(artifact.contains("ksbytes="));
        assert!(artifact.contains("knbytes="));
        assert!(artifact.contains("kb4p="));
        let (stdout, code) = run_text(&luau, &artifact, "frame_const_prof");
        assert_eq!(code, Some(0));
        assert!(stdout.contains("probe\t"));
        by_mode.insert(mode, profiler_counters(&stdout));
    }
    let c = &by_mode[&FrameConstReuseMode::Control];
    let s = &by_mode[&FrameConstReuseMode::Strings];
    let n = &by_mode[&FrameConstReuseMode::Numbers];
    let a = &by_mode[&FrameConstReuseMode::All];
    assert_eq!(c["kshit"], 0);
    assert_eq!(c["knhit"], 0);
    assert_eq!(c["ksins"], 0);
    assert_eq!(c["knins"], 0);
    assert_eq!(c["kmax"], 0);
    assert!(c["ksauth"] > 0);
    assert!(c["knauth"] > 0);
    assert!(c["kflush"] > 0);
    assert!(s["kshit"] > 0);
    assert_eq!(s["knhit"], 0);
    assert!(s["ksins"] > 0);
    assert_eq!(s["knins"], 0);
    assert!(n["knhit"] > 0);
    assert_eq!(n["kshit"], 0);
    assert!(n["knins"] > 0);
    assert_eq!(n["ksins"], 0);
    assert!(a["kshit"] > 0 && a["knhit"] > 0);
    assert!(a["ksins"] > 0 && a["knins"] > 0);
    assert_eq!(c["knauth"], s["knauth"]);
    assert_eq!(c["kflush"], s["kflush"]);
    assert_eq!(c["ksauth"], n["ksauth"]);
    assert!(s["ksauth"] < c["ksauth"]);
    assert!(n["knauth"] < c["knauth"]);
    assert_eq!(a["ksauth"], s["ksauth"]);
    assert_eq!(a["knauth"], n["knauth"]);
    assert!(a["frames"] >= 5);
    assert!(a["ksauth"] >= 4);

    assert_eq!(
        a["knauth"], a["knins"],
        "numbers authenticated exactly once, not per frame"
    );
    assert_eq!(
        a["ksauth"], a["ksins"],
        "strings authenticated exactly once, not per frame"
    );
    assert!(
        a["knhit"] > a["knauth"],
        "persistent reuse: number cache hits far exceed authentications"
    );
    assert!(
        a["kshit"] > a["ksauth"],
        "persistent reuse: string cache hits far exceed authentications"
    );
    assert_eq!(a["kfail"], 0);
    assert_eq!(c["kcall"], c["ksmiss"] + c["knmiss"]);
    assert_eq!(
        a["kcall"],
        a["ksmiss"] + a["knmiss"] + a["kshit"] + a["knhit"]
    );
}

#[test]
fn wide_registers_and_streaming_digests_remain_valid() {
    let source = wide_register_source();
    let config = cfg(
        FrameConstReuseMode::All,
        false,
        true,
        SEED,
        0,
        PolyStream::Aggressive,
    );
    let artifact = build(&source, &config);
    assert!(pipeline::verify_streaming_digests(&source, &config).unwrap() >= 1);
    if let Some(luau) = find_luau() {
        assert_eq!(
            run_text(&luau, &artifact, "frame_const_wide_virtual"),
            run_text(&luau, &source, "frame_const_wide_raw")
        );
    }
}

#[test]
fn first_access_tamper_fails_closed_before_diagnostic_insertion() {
    let Some(luau) = find_luau() else { return };
    let source = "local s=\"tamper-first-use\" local n=12345 print(s,s,n,n)\n";
    let artifact = build(
        source,
        &cfg(
            FrameConstReuseMode::All,
            true,
            false,
            SEED,
            0,
            PolyStream::Aggressive,
        ),
    );
    let fail = artifact.find("if dead and not d0 then").unwrap();
    let insert = artifact.find("fcm[i] = v").unwrap();
    assert!(fail < insert);
    let clean = run_text(&luau, &artifact, "frame_const_tamper_clean");
    assert!(clean.0.contains("tamper-first-use"));
    let open = artifact.find("[==[").unwrap() + 4;
    let close = artifact[open..].find("]==]").unwrap() + open;
    let middle = (open + close) / 2;
    let mut bytes = artifact.into_bytes();
    bytes[middle] = if bytes[middle] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    let result = run_text(&luau, &tampered, "frame_const_tamper_bad");
    assert!(!result.0.contains("tamper-first-use"));
}

#[test]
fn profiler_root_wrapper_preserves_multiple_returns_and_nil_holes() {
    let Some(luau) = find_luau() else { return };
    let source = "return \"alpha\", nil, 0, false, \"\"\n";
    let artifact = build(
        source,
        &cfg(
            FrameConstReuseMode::All,
            true,
            false,
            SEED,
            0,
            PolyStream::Off,
        ),
    );
    let quoted = format!("{artifact:?}");
    let wrapper = format!(
        "local f=assert(loadstring({quoted})) local r=table.pack(f()) print(r.n,r[1],r[2],r[3],r[4],#r[5])"
    );
    let (stdout, code) = run_text(&luau, &wrapper, "frame_const_returns");
    assert_eq!(code, Some(0));
    assert!(stdout
        .lines()
        .last()
        .unwrap_or("")
        .contains("5\talpha\tnil\t0\tfalse\t0"));
}

#[test]
fn recursion_coroutine_and_error_activations_keep_frame_memos_separate() {
    let Some(luau) = find_luau() else { return };
    let source = r#"
local function rec(n)
    local s = "activation-string"
    local x = 31337
    local both = s .. s
    local twice = x + x
    if n == 0 then return both, twice end
    local tail, v = rec(n - 1)
    return both .. tail, twice + v
end
local rs, rn = rec(3)
print("recact", #rs, rn)
local co = coroutine.create(function()
    local s = "coroutine-activation"
    local x = 4242
    coroutine.yield(s .. s, x + x)
    return s .. s, x + x
end)
print("yieldact", coroutine.resume(co))
print("resumeact", coroutine.resume(co))
local function boom()
    local s = "error-activation"
    local x = 5151
    local a = s .. s
    local b = x + x
    error(a .. b)
end
for _ = 1, 2 do
    local ok, err = pcall(boom)
    print("erract", ok, string.find(tostring(err), "error-activation", 1, true) ~= nil)
end
"#;
    let artifact = build(
        source,
        &cfg(
            FrameConstReuseMode::All,
            true,
            true,
            SEED,
            0,
            PolyStream::Aggressive,
        ),
    );
    let (stdout, code) = run_text(&luau, &artifact, "frame_const_activations");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("recact\t"));
    assert!(stdout.contains("yieldact\ttrue"));
    assert!(stdout.contains("resumeact\ttrue"));
    assert_eq!(stdout.matches("erract\tfalse\ttrue").count(), 2);
    let counters = profiler_counters(&stdout);
    assert!(counters["frames"] >= 8);
    assert!(counters["ksauth"] >= 7);
    assert!(counters["knauth"] >= 7);
    assert!(counters["kshit"] > 0);
    assert!(counters["knhit"] > 0);
    assert_eq!(counters["kfail"], 0);
}

#[test]
fn frame_exclusion_metadata_does_not_cache_flatten_routing_tokens() {
    let source = "local x=0 for i=1,20 do if i%2==0 then x=x+1 else x=x+2 end end print(x)\n";
    let artifact = build(
        source,
        &cfg(
            FrameConstReuseMode::All,
            false,
            false,
            SEED,
            0,
            PolyStream::Aggressive,
        ),
    );
    assert!(artifact.contains("elseif tag == 7 then"));
    assert!(artifact.contains("proto[19] = x"));
    assert!(artifact.contains("kx and not kx[i]"));
}
