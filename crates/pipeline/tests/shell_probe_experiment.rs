use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

const FIXTURE: &str = "\
local function validateLicence(user)
  if user == \"owner\" then return \"GRANTED\" end
  return \"DENIED\"
end
print(\"BOOT-OK\")
print(\"PROTECTED-BOUNDARY-REACHED\")
print(\"EXPECTED-RESULT \" .. validateLicence(\"owner\"))
";

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn require_luau() {
    if let Err(e) = std::process::Command::new("luau").arg("--help").output() {
        panic!("the `luau` interpreter is required for shell-probe behavioural tests ({e})");
    }
}

fn cfg_mode(seed: u64, shell_probe: bool) -> Config {
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
        shell_probe,
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

fn cfg(seed: u64, shell_probe: bool) -> Config {
    cfg_mode(seed, shell_probe)
}

fn build(cfg: Config) -> String {
    let i = tmp("sp_in");
    let o = tmp("sp_out");
    std::fs::write(&i, FIXTURE).unwrap();
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

fn run(artifact: &str) -> String {
    let p = tmp("sp_run");
    std::fs::write(&p, artifact).unwrap();
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
}

fn locate_factory(art: &str) -> (String, usize) {
    let mut at = 0usize;
    while let Some(rel) = art[at..].find("return function(") {
        let open = at + rel + "return function(".len();
        let close = art[open..].find(')').unwrap() + open;
        let params: Vec<&str> = art[open..close].split(',').map(str::trim).collect();
        if params.len() == 2 && params.iter().all(|p| !p.is_empty() && !p.contains("...")) {
            let tail = &art[close..];
            if let Some(c) = tail.find("return function(...)") {
                if tail[c..(c + 9000).min(tail.len())].contains("while true do") {
                    let name_end = art[..open].rfind("=(function()").unwrap();
                    let name_start = art[..name_end]
                        .rfind(|c: char| !c.is_alphanumeric() && c != '_')
                        .unwrap()
                        + 1;
                    let end = art[name_end..].find("end)()").unwrap() + name_end + "end)()".len();
                    return (art[name_start..name_end].to_string(), end);
                }
            }
        }
        at = open;
    }
    panic!("factory not located");
}

fn wrap_before(art: &str) -> String {
    let (name, at) = locate_factory(art);
    let w = format!(
        "\ndo local __o={name} print(\"PATCH-INSTALLED\") {name}=function(p,u) local f=__o(p,u)\n\
         return function(...) local k=table.pack(f(...))\n\
         print(\"PATCH-FIRED in=\"..tostring((select(1,...)))..\" out=\"..tostring(k[1]))\n\
         return table.unpack(k,1,k.n) end end end\n"
    );
    format!("{}{}{}", &art[..at], w, &art[at..])
}

#[test]
fn flag_off_is_byte_identical_to_the_same_build_without_the_field() {
    let a = build(cfg(42, false));
    let b = build(cfg(42, false));
    assert_eq!(a, b, "flag-off builds are deterministic");
    assert!(
        !a.contains("918273645"),
        "no unresolved probe placeholder may ship"
    );
}

#[test]
fn flag_on_changes_the_artifact_and_still_runs_correctly() {
    require_luau();
    let off = build(cfg(42, false));
    let on = build(cfg(42, true));
    assert_ne!(
        off, on,
        "the probe must actually be emitted when the flag is on"
    );
    assert_eq!(
        run(&on).trim(),
        run(&off).trim(),
        "an untouched probe build must behave exactly like the flag-off build"
    );
    assert!(
        run(&on).contains("EXPECTED-RESULT GRANTED"),
        "no false positive"
    );
}

#[test]
fn the_probe_has_no_false_positive_across_seeds() {
    require_luau();
    for seed in [1u64, 42, 1337] {
        let out = run(&build(cfg(seed, true)));
        assert!(
            out.contains("BOOT-OK"),
            "seed {seed}: untouched build must boot: {out}"
        );
        assert!(
            out.contains("EXPECTED-RESULT GRANTED"),
            "seed {seed}: untouched build must reach its result: {out}"
        );
    }
}

#[test]
fn wrapper_before_probe_fails_closed() {
    require_luau();

    let off = build(cfg(42, false));
    let attacked_off = run(&wrap_before(&off));
    assert!(
        attacked_off.contains("PATCH-INSTALLED"),
        "control: patch installed: {attacked_off}"
    );
    assert!(
        attacked_off.contains("PATCH-FIRED"),
        "control: patch fired: {attacked_off}"
    );
    assert!(
        attacked_off.contains("out=GRANTED"),
        "control: with the flag OFF the wrapper observes the protected return, or this test \
         proves nothing: {attacked_off}"
    );

    let on = build(cfg(42, true));
    let attacked_on = run(&wrap_before(&on));
    assert!(
        attacked_on.contains("PATCH-INSTALLED"),
        "treatment: patch installed: {attacked_on}"
    );
    assert!(
        !attacked_on.contains("EXPECTED-RESULT"),
        "treatment: a wrapper installed before the probe must corrupt the key epoch and stop the \
         build reaching its protected result: {attacked_on}"
    );
    assert!(
        !attacked_on.contains("out=GRANTED"),
        "treatment: the protected return must never be observed: {attacked_on}"
    );
}

#[test]
fn the_probe_is_diversified_across_seeds() {
    let a = build(cfg(1, true));
    let b = build(cfg(42, true));
    let c = build(cfg(1337, true));
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}
