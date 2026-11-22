use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, PropKeyMode, SensitiveOpts, SurfaceVolume,
    TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn require_luau() {
    for tool in ["luau", "luau-compile"] {
        if let Err(e) = std::process::Command::new(tool).arg("--help").output() {
            panic!("`{tool}` is required for property-key-rename tests ({e})");
        }
    }
}

fn cfg(seed: u64, key_rename: PropKeyMode) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
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
        profile: TargetProfile::CliTest,
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
        property_key_rename: key_rename,
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

fn build_with(src: &str, cfg: Config) -> Result<String, String> {
    let i = tmp("pk_in");
    let o = tmp("pk_out");
    std::fs::write(&i, src).unwrap();
    let (a, b) = (i.clone(), o.clone());
    let r = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || pipeline::run(&a, &b, &cfg).map_err(|e| e.to_string()))
        .unwrap()
        .join()
        .unwrap();
    let out = r.map(|_| std::fs::read_to_string(&o).unwrap());
    let _ = std::fs::remove_file(&i);
    let _ = std::fs::remove_file(&o);
    out
}

fn luau(path_src: &str) -> String {
    let p = tmp("pk_run");
    std::fs::write(&p, path_src).unwrap();
    let out = std::process::Command::new("luau")
        .arg(&p)
        .output()
        .expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim()
    .to_string()
}

fn compiles(art: &str) -> bool {
    let p = tmp("pk_cc");
    std::fs::write(&p, art).unwrap();
    let st = std::process::Command::new("luau-compile")
        .arg("--binary")
        .arg(&p)
        .output()
        .expect("luau-compile");
    let _ = std::fs::remove_file(&p);
    st.status.success()
}

fn behaviour_preserved_on(src: &str) {
    require_luau();
    let art = build_with(src, cfg(42, PropKeyMode::Internal)).expect("build ON");
    assert!(compiles(&art), "ON artifact must compile:\n{src}");
    assert_eq!(
        luau(&art),
        luau(src),
        "ON behaviour must match plain Luau:\n{src}"
    );
}

const SAFE: &[&str] = &[
    "local r = { a = 1, b = 2 } print(r.a + r.b)",
    "local r = { a = 1 } r.b = r.a + 5 print(r.b)",
    "local r = { x = 1, y = 2, z = 3 } r.x = r.y r.y = r.z print(r.x, r.y, r.z)",
    "local r = { a = 1 } local s = r print(s.a) print(r.a)",
    "local r = { a = 1 } local s = table.clone(r) print(s.a)",
    "local r = { a = 1, b = 2 } function r.f() return r.a + r.b end print(r.f())",
    "local r = { a = 1 } local function g() return r.a end print(g())",
    "local r = { a = 0 } for i = 1, 3 do r.a = r.a + i end print(r.a)",
    "local r = { a = 1, b = 2 } if r.a < r.b then print('lt') else print('ge') end",
    "local r = { ['a'] = 1, ['b'] = 2 } print(r['a'] + r.b)",
    "local outer = { a = 1 } do local inner = { a = 9 } print(inner.a) end print(outer.a)",
    "local r = { count = 0 } local function inc() r.count = r.count + 1 end inc() inc() print(r.count)",
    "local r = { a = 1 } print(#r) print(r.a)",
];

const UNSAFE: &[&str] = &[
    "local r = { a = 1 } return r",
    "local r = { a = 1 } local i = 'a' print(r[i])",
    "local r = { a = 1 } for k, v in pairs(r) do print(k, v) end",
    "local r = { a = 1 } print(rawget(r, 'a'))",
    "local r = { a = 1 } rawset(r, 'b', 2) print(r.b)",
    "local r = { a = 1 } setmetatable(r, { __index = function() return 0 end }) print(r.a)",
    "local r = { a = 1 } print(getmetatable(r)) print(r.a)",
    "local function sink(_x) end local r = { a = 1 } sink(r) print(r.a)",
    "local function f(p) return p.a end print(f({ a = 7 }))",
    "gtbl = { a = 1 } print(gtbl.a)",
    "local r = { __index = function() return 0 end, real = 5 } print(r.real)",
    "local r = { 1, 2, 3 } print(r[1] + r[2])",
];

#[test]
fn safe_closed_world_tables_preserve_behaviour_when_renamed() {
    for s in SAFE {
        behaviour_preserved_on(s);
    }
}

#[test]
fn unsafe_or_ineligible_tables_are_skipped_but_still_correct() {
    for s in UNSAFE {
        behaviour_preserved_on(s);
    }
}

#[test]
fn rename_acts_on_a_closed_domain_and_is_off_neutral_when_ineligible() {
    let safe = "local r = { alpha = 1, beta = 2 } r.gamma = r.alpha + r.beta print(r.gamma)";
    let on = build_with(safe, cfg(9, PropKeyMode::Internal)).unwrap();
    let off = build_with(safe, cfg(9, PropKeyMode::Off)).unwrap();
    assert_ne!(on, off, "renaming a closed domain must change the artifact");

    let none = "local x = 1 local y = 2 print(x + y)";
    let on2 = build_with(none, cfg(9, PropKeyMode::Internal)).unwrap();
    let off2 = build_with(none, cfg(9, PropKeyMode::Off)).unwrap();
    assert_eq!(
        on2, off2,
        "no eligible domain -> ON is byte-identical to OFF"
    );
}

#[test]
fn length_operator_matches_plain_across_seeds() {
    require_luau();
    let cases = [
        "local T = { foo = 1 } print(#T)",
        "local T = { foo = 1, bar = 2, baz = 3 } print(#T)",
        "local T = { a = 1 } T.b = 2 T.c = 3 print(#T) T.d = 4 print(#T)",
        "local T = { a = 1, b = 2, c = 3, d = 4, e = 5 } local n = #T T.f = 6 print(n, #T, T.a + T.f)",
    ];
    for src in cases {
        let plain = luau(src);
        for seed in [0u64, 1, 2, 7, 42, 305419896, 0xBEEF, 0xC0FFEE] {
            let art = build_with(src, cfg(seed, PropKeyMode::Internal)).expect("build ON");
            assert!(compiles(&art), "seed {seed}: artifact must compile:\n{src}");
            assert_eq!(
                luau(&art),
                plain,
                "seed {seed}: #T semantics must match plain:\n{src}"
            );
        }
    }
}

#[test]
fn off_is_deterministic_and_default() {
    let src = "local r = { a = 1, b = 2 } r.c = r.a print(r.c)";
    let a = build_with(src, cfg(5, PropKeyMode::Off)).unwrap();
    let b = build_with(src, cfg(5, PropKeyMode::Off)).unwrap();
    assert_eq!(a, b, "OFF is deterministic");
    assert_eq!(
        cfg(0, PropKeyMode::Off).property_key_rename,
        PropKeyMode::default()
    );
}
