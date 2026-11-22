use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static N: AtomicU64 = AtomicU64::new(0);

const RUN_TIMEOUT: Duration = Duration::from_secs(20);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn require_luau() {
    for tool in ["luau", "luau-compile"] {
        if let Err(e) = Command::new(tool).arg("--help").output() {
            panic!("`{tool}` is required for crash-termination tests ({e})");
        }
    }
}

fn cfg(seed: u64, minify: bool, profile: TargetProfile) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: true,
        junk: false,
        fuse: true,
        minify,
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
        line_info: false,
        strip_source_names: true,
        poly_stream: PolyStream::Off,
        optimization: 1,
        static_env: false,
        runtime_profile_markers: false,
        frame_const_reuse: pipeline::FrameConstReuseMode::Off,
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

fn build_with(src: &str, cfg: Config) -> String {
    let i = tmp("ct_in");
    let o = tmp("ct_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).expect("build succeeds"))
        .unwrap()
        .join()
        .unwrap();
    let out = std::fs::read_to_string(&o).unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn build(src: &str) -> String {
    build_with(src, cfg(42, false, TargetProfile::CliTest))
}

struct Outcome {
    out: String,
    timed_out: bool,
    elapsed: Duration,
}

impl Outcome {
    fn ran(&self, marker: &str) -> bool {
        self.out.contains(marker)
    }
}

fn run_source(src: &str) -> Outcome {
    let p = tmp("ct_run");
    std::fs::write(&p, src).unwrap();
    let started = Instant::now();
    let mut child = Command::new("luau")
        .arg(&p)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn luau");
    let mut timed_out = false;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None => {
                if started.elapsed() > RUN_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    let _ = std::fs::remove_file(&p);
    Outcome {
        out: format!("{out}{err}"),
        timed_out,
        elapsed: started.elapsed(),
    }
}

fn compiles(src: &str) -> bool {
    let p = tmp("ct_cc");
    std::fs::write(&p, src).unwrap();
    let st = Command::new("luau-compile")
        .arg("--binary")
        .arg(&p)
        .output()
        .expect("luau-compile");
    let _ = std::fs::remove_file(&p);
    st.status.success()
}

fn crash_leaves(artifact: &str) -> Vec<(String, String)> {
    const STOP: &str = "dead = true return";
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = artifact[from..].find(STOP) {
        let at = from + rel;
        let body_start = artifact[..at].rfind('\n').map_or(0, |p| p + 1);
        let head_start = artifact[..body_start.saturating_sub(1)]
            .rfind('\n')
            .map_or(0, |p| p + 1);
        let head = artifact[head_start..body_start].trim().to_string();
        let body = artifact[body_start..at + STOP.len()].trim().to_string();
        out.push((head, body));
        from = at + STOP.len();
    }
    out
}

fn opcode_keyed_crash_leaves(artifact: &str) -> Vec<(String, String)> {
    crash_leaves(artifact)
        .into_iter()
        .filter(|(head, body)| head.contains("op ==") && body == "dead = true return")
        .collect()
}

const ROOT: &str =
    "print(\"BEFORE\")\nif 1 ~= 2 then BASIL_CRASH() end\nprint(\"AFTER-SENSITIVE\")\n";

#[test]
fn root_crash_terminates_within_a_bounded_timeout_instead_of_hanging() {
    require_luau();
    let r = run_source(&build(ROOT));
    assert!(
        !r.timed_out,
        "BASIL_CRASH must terminate, not hang (waited {:?})",
        r.elapsed
    );
    assert!(r.ran("BEFORE"), "pre-crash code must run: {}", r.out);
}

#[test]
fn no_code_after_a_root_crash_executes() {
    require_luau();
    let r = run_source(&build(ROOT));
    assert!(
        !r.ran("AFTER-SENSITIVE"),
        "code after BASIL_CRASH must not run: {}",
        r.out
    );
}

#[test]
fn a_three_level_nested_crash_unwinds_every_parent_frame() {
    require_luau();
    let src = "local function l3(x) if x ~= 9 then BASIL_CRASH() end return \"L3\" end\nlocal function l2(x) local r = l3(x) print(\"L2-RESUMED\", r) return \"L2\" end\nlocal function l1(x) local r = l2(x) print(\"L1-RESUMED\", r) return \"L1\" end\nprint(\"BEFORE\")\nprint(\"RESULT\", l1(0))\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out, "must terminate");
    assert!(r.ran("BEFORE"));
    for m in ["L2-RESUMED", "L1-RESUMED", "RESULT", "AFTER-SENSITIVE"] {
        assert!(
            !r.ran(m),
            "parent frame must not resume (`{m}` ran): {}",
            r.out
        );
    }
}

#[test]
fn a_caller_expecting_one_return_cannot_continue() {
    require_luau();
    let src = "local function f(x) if x ~= 9 then BASIL_CRASH() end return \"cap\" end\nprint(\"BEFORE\")\nlocal v = f(0)\nprint(\"GOT\", tostring(v))\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out);
    assert!(
        !r.ran("GOT") && !r.ran("AFTER-SENSITIVE"),
        "must not continue: {}",
        r.out
    );
}

#[test]
fn a_caller_expecting_multiple_returns_cannot_continue() {
    require_luau();
    let src = "local function f(x) if x ~= 9 then BASIL_CRASH() end return 1, 2, 3 end\nprint(\"BEFORE\")\nlocal a, b, c = f(0)\nprint(\"GOT\", tostring(a), tostring(b), tostring(c))\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out);
    assert!(
        !r.ran("GOT") && !r.ran("AFTER-SENSITIVE"),
        "must not continue: {}",
        r.out
    );
}

#[test]
fn a_caller_ignoring_the_return_cannot_continue() {
    require_luau();
    let src = "local function f(x) if x ~= 9 then BASIL_CRASH() end return \"cap\" end\nprint(\"BEFORE\")\nf(0)\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out);
    assert!(!r.ran("AFTER-SENSITIVE"), "must not continue: {}", r.out);
}

#[test]
fn a_crash_inside_a_loop_stops_immediately() {
    require_luau();
    let src = "print(\"BEFORE\")\nfor i = 1, 5 do\n\tif i == 3 then BASIL_CRASH() end\n\tprint(\"ITER\", i)\nend\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out);
    assert!(
        r.ran("ITER\t1") && r.ran("ITER\t2"),
        "iterations before the crash run: {}",
        r.out
    );
    assert!(
        !r.ran("ITER\t3") && !r.ran("ITER\t4"),
        "no iteration after the crash: {}",
        r.out
    );
    assert!(
        !r.ran("AFTER-SENSITIVE"),
        "loop must not complete: {}",
        r.out
    );
}

#[test]
fn pcall_cannot_recover_later_virtualized_execution() {
    require_luau();
    let src = "local function f(x) if x ~= 9 then BASIL_CRASH() end return \"cap\" end\nprint(\"BEFORE\")\nlocal ok, err = pcall(f, 0)\nprint(\"PCALL\", tostring(ok), tostring(err))\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out);
    assert!(
        !r.ran("PCALL"),
        "nothing after the protected call may run: {}",
        r.out
    );
    assert!(
        !r.ran("AFTER-SENSITIVE"),
        "pcall must not permit continuation: {}",
        r.out
    );
}

#[test]
fn xpcall_and_its_handler_cannot_recover_later_virtualized_execution() {
    require_luau();
    let src = "local function f(x) if x ~= 9 then BASIL_CRASH() end return \"cap\" end\nprint(\"BEFORE\")\nlocal ok, v = xpcall(f, function(e) print(\"HANDLER-INVOKED\", tostring(e)) return \"handled\" end, 0)\nprint(\"XPCALL\", tostring(ok), tostring(v))\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out);
    assert!(
        !r.ran("HANDLER-INVOKED"),
        "the xpcall handler must not be invoked: {}",
        r.out
    );
    assert!(
        !r.ran("XPCALL") && !r.ran("AFTER-SENSITIVE"),
        "must not continue: {}",
        r.out
    );
}

#[test]
fn no_host_error_stacktrace_or_source_metadata_is_emitted() {
    require_luau();
    let r = run_source(&build(ROOT));
    for leak in ["stacktrace", "function error", ".luau:", "attempt to"] {
        assert!(
            !r.out.contains(leak),
            "no `{leak}` may appear in failure output: {}",
            r.out
        );
    }
    assert_eq!(r.out.trim(), "BEFORE", "failure must be silent: {}", r.out);
}

#[test]
fn the_host_stays_responsive_and_the_artifact_can_be_run_twice() {
    require_luau();
    let art =
        build("print(\"RR\")\nif 1 ~= 2 then BASIL_CRASH() end\nprint(\"AFTER-SENSITIVE\")\n");
    let escaped = art.replace("]==]", "]==] .. ']==]' .. [==[");
    let driver = format!(
        "local S = [==[\n{escaped}\n]==]\nlocal l = loadstring or load\nl(S)()\nprint(\"ALIVE-1\")\nl(S)()\nprint(\"ALIVE-2\")\nprint(\"RESPONSIVE\", 6 * 7)\n"
    );
    let r = run_source(&driver);
    assert!(!r.timed_out, "the host must not hang");
    assert!(
        r.ran("ALIVE-1") && r.ran("ALIVE-2"),
        "both runs must return control: {}",
        r.out
    );
    assert!(
        r.ran("RESPONSIVE\t42"),
        "the host must still compute: {}",
        r.out
    );
    assert_eq!(
        r.out.matches("RR").count(),
        2,
        "each load runs with a fresh dead state: {}",
        r.out
    );
    assert!(
        !r.ran("AFTER-SENSITIVE"),
        "neither run may continue past the crash: {}",
        r.out
    );
}

#[test]
fn coroutine_crash_terminates_invocation() {
    require_luau();
    let src = "local function f(x) if x ~= 9 then BASIL_CRASH() end return \"ok\" end\nlocal co = coroutine.create(function()\n\tprint(\"CO-IN\")\n\tf(0)\n\tprint(\"CO-AFTER-SENSITIVE\")\nend)\nprint(\"BEFORE\")\nprint(\"RESUME\", coroutine.resume(co))\nprint(\"AFTER-SENSITIVE\")\n";
    let r = run_source(&build(src));
    assert!(!r.timed_out, "must terminate");
    assert!(
        r.ran("BEFORE") && r.ran("CO-IN"),
        "pre-crash code runs: {}",
        r.out
    );
    assert!(
        !r.ran("CO-AFTER-SENSITIVE"),
        "the coroutine must not continue: {}",
        r.out
    );
    assert!(
        !r.ran("RESUME") && !r.ran("AFTER-SENSITIVE"),
        "the contract is the whole virtualized invocation, not one coroutine: {}",
        r.out
    );
}

#[test]
fn every_seed_and_minification_mode_terminates_without_continuing() {
    require_luau();
    for seed in [1u64, 42, 1337] {
        for minify in [true, false] {
            let art = build_with(ROOT, cfg(seed, minify, TargetProfile::CliTest));
            assert!(compiles(&art), "seed {seed} minify={minify}: must compile");
            let r = run_source(&art);
            assert!(!r.timed_out, "seed {seed} minify={minify}: must terminate");
            assert!(r.ran("BEFORE"), "seed {seed} minify={minify}: {}", r.out);
            assert!(
                !r.ran("AFTER-SENSITIVE"),
                "seed {seed} minify={minify}: must not continue: {}",
                r.out
            );
        }
    }
}

#[test]
fn the_executor_target_profile_builds_and_compiles() {
    require_luau();
    let art = build_with(ROOT, cfg(42, true, TargetProfile::Executor));
    assert!(compiles(&art), "executor-profile artifact must compile");
    assert!(
        !art.contains("pc = pc - 1"),
        "the executor profile must not retain the old spin"
    );
}

#[test]
fn an_encfunc_body_containing_crash_still_routes_to_the_shared_handler() {
    require_luau();
    let src = "local KEY = fetchKey()\nlocal sealed = BASIL_ENCFUNC(function()\n\tBASIL_CRASH()\n\treturn \"SEALED\"\nend, \"0000000000000000000000000000000000000000000000000000000000000001\", KEY)\nprint(type(sealed))\n";
    let art = build(src);
    assert!(compiles(&art), "ENCFUNC artifact must compile");
    assert_eq!(
        opcode_keyed_crash_leaves(&art).len(),
        1,
        "exactly one opcode-keyed terminal leaf: the shared Crash handler"
    );
}

#[test]
fn the_generated_handler_is_the_vm_wide_dead_return_path() {
    let art = build(ROOT);
    let leaves = opcode_keyed_crash_leaves(&art);
    assert_eq!(
        leaves.len(),
        1,
        "exactly one opcode-keyed Crash leaf, got {leaves:?}"
    );
    assert_eq!(
        leaves[0].1, "dead = true return",
        "the Crash leaf must be the VM-wide stop"
    );
}

#[test]
fn the_old_spin_body_is_completely_absent() {
    let art = build(ROOT);
    assert!(
        !art.contains("pc = pc - 1"),
        "the pc-decrement spin must be gone"
    );
    assert!(
        !art.contains("genkey = 0"),
        "the decorative genkey corruption must be gone"
    );
    for seed in [1u64, 42, 1337] {
        let a = build_with(ROOT, cfg(seed, false, TargetProfile::CliTest));
        assert!(!a.contains("pc = pc - 1"), "seed {seed}: spin must be gone");
        assert!(
            !a.contains("genkey = 0"),
            "seed {seed}: genkey corruption must be gone"
        );
    }
}

#[test]
fn no_new_host_primitive_is_introduced_by_the_handler() {
    let with = build(ROOT);
    let without = build("print(\"X\")\nprint(\"Y\")\n");
    for prim in ["error(", "warn(", "debug.", "coroutine.", "task."] {
        assert_eq!(
            with.matches(prim).count(),
            without.matches(prim).count(),
            "`{prim}` count must be unchanged by the Crash handler"
        );
    }
}

#[test]
fn a_build_without_crash_emits_no_crash_handler() {
    let art = build("local t = 0\nfor i = 1, 5 do t = t + i end\nprint(t)\n");
    let leaves = opcode_keyed_crash_leaves(&art);
    assert!(
        leaves.is_empty(),
        "no Crash handler may be emitted when the macro is unused, got {leaves:?}"
    );
}

#[test]
fn builds_without_crash_are_deterministic_and_unaffected() {
    let src = "local t = 0\nfor i = 1, 5 do t = t + i end\nprint(t)\n";
    for seed in [1u64, 42, 1337] {
        let a = build_with(src, cfg(seed, true, TargetProfile::CliTest));
        let b = build_with(src, cfg(seed, true, TargetProfile::CliTest));
        assert_eq!(
            a, b,
            "seed {seed}: a build without BASIL_CRASH must be deterministic"
        );
    }
}

#[test]
fn the_macro_syntax_is_unchanged_and_still_direct_call_only() {
    require_luau();
    let art = build(ROOT);
    assert!(compiles(&art), "BASIL_CRASH() must still build and compile");
    assert!(
        !art.contains("BASIL_CRASH"),
        "the macro name must not survive into output"
    );
    let i = tmp("ct_bad");
    let o = tmp("ct_bad_out");
    std::fs::write(&i, "local f = BASIL_CRASH\nprint(f)\n").unwrap();
    let c = cfg(42, true, TargetProfile::CliTest);
    let (a, b) = (i.clone(), o.clone());
    let r = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&a, &b, &c).map_err(|e| e.to_string()))
        .unwrap()
        .join()
        .unwrap();
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    assert!(
        r.is_err(),
        "a bare BASIL_CRASH reference must still be rejected"
    );
}

#[test]
fn patch_resistance_is_unchanged_deleting_the_handler_still_bypasses_it() {
    require_luau();
    let art = build(ROOT);
    let leaves = opcode_keyed_crash_leaves(&art);
    assert_eq!(leaves.len(), 1, "one Crash leaf expected");
    let full = format!("{}\n{}", leaves[0].0, leaves[0].1);
    let at = art.find(&full).expect("leaf present");
    let patched = format!("{}{}\n{}", &art[..at], leaves[0].0, &art[at + full.len()..]);

    let control = run_source(&art);
    assert!(!control.ran("AFTER-SENSITIVE"), "control must fail closed");
    let bypassed = run_source(&patched);
    assert!(
        bypassed.ran("AFTER-SENSITIVE"),
        "THIS FIX IS NOT HARDENING: one handler deletion must still bypass BASIL_CRASH \
         entirely. If this assertion ever fails, the fix has been misrepresented as \
         anti-tamper. Output: {}",
        bypassed.out
    );
}
