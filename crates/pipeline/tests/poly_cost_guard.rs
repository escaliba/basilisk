use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use pipeline::{Config, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile};

const SEED: u64 = 0x_9017_57EE;
const CONS_SIZE_CEIL: f64 = 1.40;
const AGGR_SIZE_CEIL: f64 = 1.75;

fn cfg(poly: PolyStream) -> Config {
    Config {
        seed: SEED,
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
        loadstring_canary: true,
        lph_collapse: false,
        line_info: true,
        strip_source_names: false,
        poly_stream: poly,
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

fn unique_tmp(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn build_str(input: &Path, poly: PolyStream) -> String {
    let output = unique_tmp("cost_out");
    pipeline::run(input, &output, &cfg(poly))
        .unwrap_or_else(|e| panic!("building {}: {e:#}", input.display()));
    let s = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&output);
    s
}

fn bench_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bench_fixtures");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "luau"))
        .collect();
    files.sort();
    files
}

fn name_of(p: &Path) -> String {
    p.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("?")
        .to_string()
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    match Command::new("luau").arg("--help").output() {
        Ok(_) => Some("luau".to_string()),
        Err(_) => None,
    }
}

#[test]
fn poly_cost_soft_guard_size() {
    eprintln!(
        "{:<28} {:>8} {:>8} {:>7} {:>8} {:>7}",
        "fixture", "off", "cons", "x", "aggr", "x"
    );
    for f in bench_files() {
        let n = name_of(&f);
        let off = build_str(&f, PolyStream::Off).len() as f64;
        let cons = build_str(&f, PolyStream::Conservative).len() as f64;
        let aggr = build_str(&f, PolyStream::Aggressive).len() as f64;
        let (rc, ra) = (cons / off, aggr / off);
        eprintln!("{n:<28} {off:>8.0} {cons:>8.0} {rc:>7.3} {aggr:>8.0} {ra:>7.3}");
        assert!(rc <= CONS_SIZE_CEIL, "{n}: conservative size ratio {rc:.3} exceeds {CONS_SIZE_CEIL} ceiling (poly-stream cost regression)");
        assert!(ra <= AGGR_SIZE_CEIL, "{n}: aggressive size ratio {ra:.3} exceeds {AGGR_SIZE_CEIL} ceiling (poly-stream cost regression)");

        assert!(aggr >= cons * 0.99, "{n}: aggressive artifact {aggr:.0} materially smaller than conservative {cons:.0} — poly selection regressed");
    }
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let m = xs.len() / 2;
    if xs.len() % 2 == 1 {
        xs[m]
    } else {
        (xs[m - 1] + xs[m]) / 2.0
    }
}

fn time_luau(bin: &str, path: &Path, runs: usize) -> (f64, f64) {
    let mut ts = Vec::new();
    for _ in 0..runs {
        let t = Instant::now();
        let out = Command::new(bin).arg(path).output().expect("spawn luau");
        assert!(out.status.success(), "luau failed on {}", path.display());
        ts.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let best = ts.iter().cloned().fold(f64::MAX, f64::min);
    (median(ts), best)
}

#[test]
#[ignore]
fn poly_cost_benchmark_report() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; set LUAU_BIN to run the benchmark");
        return;
    };
    const RUNS: usize = 5;
    eprintln!(
        "{:<26} {:>7} {:>7} {:>7} | {:>8} {:>8} {:>8} | {:>7} {:>7}",
        "fixture", "off ms", "cons", "aggr", "off B", "cons B", "aggr B", "c/off", "a/off"
    );
    for f in bench_files() {
        let n = name_of(&f);
        let raw = {
            let out = Command::new(&luau).arg(&f).output().expect("spawn luau");
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        let mut ms = [0f64; 3];
        let mut by = [0f64; 3];
        for (idx, poly) in [
            PolyStream::Off,
            PolyStream::Conservative,
            PolyStream::Aggressive,
        ]
        .into_iter()
        .enumerate()
        {
            let art = build_str(&f, poly);
            by[idx] = art.len() as f64;
            let p = unique_tmp("cost_run");
            std::fs::write(&p, &art).unwrap();
            let got = {
                let out = Command::new(&luau).arg(&p).output().expect("spawn luau");
                String::from_utf8_lossy(&out.stdout).into_owned()
            };
            assert_eq!(raw, got, "{n}: {poly:?} output differs from raw");
            let (med, _best) = time_luau(&luau, &p, RUNS);
            ms[idx] = med;
            let _ = std::fs::remove_file(&p);
        }
        eprintln!(
            "{n:<26} {:>7.0} {:>7.0} {:>7.0} | {:>8.0} {:>8.0} {:>8.0} | {:>+6.0}% {:>+6.0}%",
            ms[0],
            ms[1],
            ms[2],
            by[0],
            by[1],
            by[2],
            100.0 * (ms[1] - ms[0]) / ms[0],
            100.0 * (ms[2] - ms[0]) / ms[0]
        );
    }
}
