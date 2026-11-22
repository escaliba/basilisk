use std::path::Path;
use std::process::Command;

use pipeline::{SurfaceVolume, TargetProfile};

const RICH: &str = r#"
Acc = 0
Name = "start"
local mt = setmetatable({ n = 0 }, {
    __index = function(self, k) return rawget(self, "n") + #tostring(k) end,
    __newindex = function(self, k, v) rawset(self, k, v * 2 + 1) end,
})
local function counter()
    local n, s = 0, ""
    local function inc(d) n = n + d s = s .. tostring(d) end
    local function get() return n, s end
    return inc, get
end
local inc, get = counter()
local function fib(x) if x < 2 then return x end return fib(x - 1) + fib(x - 2) end
local function sum(...)
    local t = { ... }
    local a = 0
    for i = 1, #t do a = a + t[i] * 3 - 1 end
    return a
end
local obj = {}
function obj:scale(f) self.v = (self.v or 1) * f + 2 return self end
local grid = {}
for i = 1, 12 do
    grid[i] = { id = i, sq = i * i % 7, name = "row" .. i }
    Acc = Acc + grid[i].sq
    mt[i] = i
end
local total, parity = 0, 0
for _, row in ipairs(grid) do
    total = total + row.sq - row.id
    if row.sq > 3 and row.id % 2 == 0 then parity = parity + 1 else parity = parity - 1 end
end
local j = 0
repeat
    j = j + 1
    inc(j)
until j >= 5 or total < 0
Name = Name .. "-" .. tostring(#grid)
local r = obj:scale(4):scale(2).v
local ok, err = pcall(function() return fib(10) + sum(1, 2, 3, 4) end)
return Acc + total + parity + r + (get()) + (ok and err or 0) + mt.z + #Name
"#;

fn strip_lua(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let long_bracket = |start: usize| -> Option<usize> {
        let mut j = start + 1;
        let mut eq = 0;
        while j < n && b[j] == b'=' {
            eq += 1;
            j += 1;
        }
        if j < n && b[j] == b'[' {
            let mut k = j + 1;
            while k < n {
                if b[k] == b']' {
                    let mut m = k + 1;
                    let mut e2 = 0;
                    while m < n && b[m] == b'=' {
                        e2 += 1;
                        m += 1;
                    }
                    if e2 == eq && m < n && b[m] == b']' {
                        return Some(m + 1);
                    }
                }
                k += 1;
            }
            return Some(n);
        }
        None
    };
    let mut out = String::with_capacity(n);
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c == b'-' && i + 1 < n && b[i + 1] == b'-' {
            if i + 2 < n && b[i + 2] == b'[' {
                if let Some(e) = long_bracket(i + 2) {
                    out.push(' ');
                    i = e;
                    continue;
                }
            }
            let mut k = i;
            while k < n && b[k] != b'\n' {
                k += 1;
            }
            out.push(' ');
            i = k;
            continue;
        }
        if c == b'"' || c == b'\'' {
            let q = c;
            let mut k = i + 1;
            while k < n && b[k] != q {
                k += if b[k] == b'\\' { 2 } else { 1 };
            }
            out.push_str("\"\"");
            i = k + 1;
            continue;
        }
        if c == b'[' {
            if let Some(e) = long_bracket(i) {
                out.push(' ');
                i = e;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

fn tokenize(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let mut j = i + 1;
            while j < n && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            out.push(s[i..j].to_string());
            i = j;
        } else if c == b'.' && i + 2 < n && b[i + 1] == b'.' && b[i + 2] == b'.' {
            out.push("...".to_string());
            i += 3;
        } else if matches!(c, b'=' | b',' | b'(' | b')' | b':' | b'.') {
            out.push((c as char).to_string());
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

fn is_ident(t: &str) -> bool {
    t.bytes()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
}
fn is_kw(t: &str) -> bool {
    matches!(
        t,
        "function"
            | "end"
            | "do"
            | "then"
            | "else"
            | "elseif"
            | "repeat"
            | "until"
            | "local"
            | "for"
            | "while"
            | "if"
            | "return"
            | "in"
            | "and"
            | "or"
            | "not"
            | "nil"
            | "true"
            | "false"
    )
}

fn func_peaks(src: &str) -> Vec<usize> {
    let toks = tokenize(&strip_lua(src));
    let n = toks.len();

    let mut stack: Vec<(bool, usize, usize)> = Vec::new();
    let mut peak: Vec<usize> = vec![0];
    stack.push((true, 0, 0));
    let live = |stack: &[(bool, usize, usize)]| -> (usize, usize) {
        let mut tot = 0;
        for s in stack.iter().rev() {
            tot += s.2;
            if s.0 {
                return (s.1, tot);
            }
        }
        (0, tot)
    };
    let mut i = 0;
    while i < n {
        let t = toks[i].as_str();
        if t == "function" {
            let mut k = i + 1;
            while k < n && toks[k] != "(" {
                k += 1;
            }
            let mut params = 0;
            let mut depth = 0;
            let mut k2 = k;
            let mut expect = true;
            while k2 < n {
                match toks[k2].as_str() {
                    "(" => depth += 1,
                    ")" => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    "," if depth == 1 => expect = true,
                    tk if depth == 1 && (tk == "..." || (is_ident(tk) && !is_kw(tk) && expect)) => {
                        params += 1;
                        expect = false;
                    }
                    _ => {}
                }
                k2 += 1;
            }
            let nf = peak.len();
            peak.push(params);
            stack.push((true, nf, params));
            i = k2 + 1;
            continue;
        }
        if t == "local" {
            if i + 1 < n && toks[i + 1] == "function" {
                stack.last_mut().unwrap().2 += 1;
                let (f, tot) = live(&stack);
                peak[f] = peak[f].max(tot);
                i += 1;
                continue;
            }
            let mut j = i + 1;
            let mut names = 0;
            while j < n {
                let tj = toks[j].as_str();
                if tj == "=" {
                    break;
                }
                if matches!(
                    tj,
                    "do" | "then"
                        | "end"
                        | "local"
                        | "function"
                        | "for"
                        | "while"
                        | "if"
                        | "repeat"
                        | "return"
                ) {
                    break;
                }
                if is_ident(tj) {
                    names += 1;
                }
                j += 1;
            }
            stack.last_mut().unwrap().2 += names;
            let (f, tot) = live(&stack);
            peak[f] = peak[f].max(tot);
            i = j;
            continue;
        }
        match t {
            "do" | "then" | "repeat" => stack.push((false, 0, 0)),
            "else" => {
                if stack.len() > 1 && !stack.last().unwrap().0 {
                    stack.pop();
                }
                stack.push((false, 0, 0));
            }
            "elseif" => {
                if stack.len() > 1 && !stack.last().unwrap().0 {
                    stack.pop();
                }
            }
            "end" | "until" => {
                if stack.len() > 1 {
                    stack.pop();
                }
            }
            _ => {}
        }
        i += 1;
    }
    peak
}

fn build(
    seed: u64,
    minify: bool,
    profile: TargetProfile,
    heavy: SurfaceVolume,
    compress: bool,
    wm: bool,
) -> String {
    build_lph(seed, minify, profile, heavy, compress, wm, false)
}

fn build_lph(
    seed: u64,
    minify: bool,
    profile: TargetProfile,
    heavy: SurfaceVolume,
    compress: bool,
    _wm: bool,
    lph: bool,
) -> String {
    pipeline::virtualize_full_prof(
        RICH,
        seed,
        true,
        true,
        true,
        true,
        minify,
        compress,
        profile == TargetProfile::Executor,
        false,
        false,
        heavy,
        false,
        pipeline::SensitiveOpts::default(),
        profile,
        false,
        lph,
    )
    .expect("virtualize")
}

fn build_poly(seed: u64, minify: bool, profile: TargetProfile) -> String {
    use pipeline::{Config, Mode, PolyStream};
    let dir = std::env::temp_dir();
    let tag = format!("{}_{seed:x}", std::process::id());
    let input = dir.join(format!("basilisk_lb_poly_in_{tag}.luau"));
    let output = dir.join(format!("basilisk_lb_poly_out_{tag}.luau"));
    std::fs::write(&input, RICH).unwrap();
    let cfg = Config {
        seed,
        mode: Mode::Virtualize,
        flatten: true,
        opaque: true,
        junk: true,
        fuse: true,
        minify,
        compress: false,
        anti_envlog: profile == TargetProfile::Executor,
        hard_dispatch: false,
        surface: false,
        heavy: SurfaceVolume::Off,
        aggressive: false,
        sensitive: pipeline::SensitiveOpts::default(),
        profile,
        loadstring_canary: true,
        lph_collapse: false,
        line_info: false,
        strip_source_names: false,
        poly_stream: PolyStream::Aggressive,
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
    };
    pipeline::run(&input, &output, &cfg).expect("virtualize poly");
    let s = std::fs::read_to_string(&output).unwrap();
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    s
}

fn max_and_top(src: &str) -> (usize, Vec<usize>) {
    let mut p = func_peaks(src);
    p.sort_unstable_by(|a, b| b.cmp(a));
    (
        p.first().copied().unwrap_or(0),
        p.into_iter().take(6).collect(),
    )
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    for cand in ["luau", "/opt/homebrew/bin/luau", "/usr/local/bin/luau"] {
        if Command::new(cand).arg("--help").output().is_ok() {
            return Some(cand.to_string());
        }
    }
    None
}

fn luau_register_error(luau: &str, artifact: &str, tag: &str) -> Option<String> {
    let path = std::env::temp_dir().join(format!("basilisk_localbudget_{tag}.luau"));
    std::fs::write(&path, artifact).unwrap();
    let out = Command::new(luau).arg(&path).output().ok()?;
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("Out of local registers") || err.contains("exceeded limit") {
        Some(err.lines().next().unwrap_or("").to_string())
    } else {
        None
    }
}

const HARD: usize = 190;
const TARGET: usize = 160;

#[test]
fn generated_artifacts_respect_luau_local_budget() {
    let cases: [(&str, u64, TargetProfile, SurfaceVolume, bool, bool); 5] = [
        (
            "polished",
            0x5A11,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            false,
            false,
        ),
        (
            "executor-wm",
            0x5A12,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            false,
            true,
        ),
        (
            "executor-nowm",
            0x5A13,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            false,
            false,
        ),
        (
            "compress",
            0x5A14,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            true,
            false,
        ),
        (
            "basil-heavy-medium",
            0x5A15,
            TargetProfile::CliTest,
            SurfaceVolume::Medium,
            false,
            false,
        ),
    ];
    let mut worst = 0usize;
    for (name, seed, profile, heavy, compress, wm) in cases {
        let unmin = build(seed, false, profile, heavy, compress, wm);
        let (maxf, top) = max_and_top(&unmin);
        worst = worst.max(maxf);
        let flag = if maxf > TARGET {
            "  (over 160 target)"
        } else {
            ""
        };
        println!("local-budget {name}: max per-function locals = {maxf}, top6 = {top:?}{flag}");
        assert!(maxf <= HARD, "{name}: a generated function has {maxf} live locals (> {HARD} hard budget) — Luau limit is 200");
    }
    println!("local-budget worst across profiles: {worst} (hard {HARD}, target {TARGET})");

    if let Some(luau) = find_luau() {
        for (name, seed, profile, heavy, compress, wm) in cases {
            let min = build(seed, true, profile, heavy, compress, wm);
            if let Some(e) = luau_register_error(&luau, &min, name) {
                panic!("{name} minified artifact overflows Luau local registers: {e}");
            }
        }
        println!("local-budget: all 5 minified profiles compile in Luau with no register overflow");
    } else {
        println!("local-budget: luau not found; scanner-only budget check");
    }
}

#[test]
fn poly_aggressive_respects_luau_local_budget() {
    for (name, seed, profile) in [
        ("poly-executor", 0x5A16u64, TargetProfile::Executor),
        ("poly-clitest", 0x5A17u64, TargetProfile::CliTest),
    ] {
        let unmin = build_poly(seed, false, profile);
        let (maxf, top) = max_and_top(&unmin);
        println!("local-budget {name} (poly aggressive): max per-function locals = {maxf}, top6 = {top:?}");
        assert!(
            maxf <= HARD,
            "{name}: a poly-aggressive function has {maxf} live locals (> {HARD} hard budget)"
        );
    }
    if let Some(luau) = find_luau() {
        let min = build_poly(0x5A16, true, TargetProfile::Executor);
        if let Some(e) = luau_register_error(&luau, &min, "poly") {
            panic!("poly-aggressive minified artifact overflows Luau local registers: {e}");
        }
        println!("local-budget: poly-aggressive minified executor compiles in Luau with no register overflow");
    }
}

fn count_locals(src: &str) -> usize {
    tokenize(&strip_lua(src))
        .iter()
        .filter(|t| t.as_str() == "local")
        .count()
}

const COLLAPSE_SEED: u64 = 23111;
const BASE_POLISHED: usize = 406;
const BASE_EXECUTOR: usize = 449;
const BASE_HEAVY: usize = 1120;

#[test]
fn generated_artifacts_have_collapsed_local_surface() {
    let pol = count_locals(&build(
        COLLAPSE_SEED,
        true,
        TargetProfile::CliTest,
        SurfaceVolume::Off,
        false,
        false,
    ));
    let exec = count_locals(&build(
        COLLAPSE_SEED,
        true,
        TargetProfile::Executor,
        SurfaceVolume::Off,
        false,
        true,
    ));
    let heavy = count_locals(&build(
        COLLAPSE_SEED,
        true,
        TargetProfile::CliTest,
        SurfaceVolume::Medium,
        false,
        false,
    ));
    let pct = |now: usize, base: usize| (base.saturating_sub(now)) * 100 / base;
    println!(
        "collapse: polished {BASE_POLISHED}->{pol} (-{}%) executor {BASE_EXECUTOR}->{exec} (-{}%) heavy {BASE_HEAVY}->{heavy} (-{}%)",
        pct(pol, BASE_POLISHED), pct(exec, BASE_EXECUTOR), pct(heavy, BASE_HEAVY)
    );

    const DECODE_SCAFFOLD_LOCALS: usize = 53;

    assert!(
        heavy * 2 <= BASE_HEAVY,
        "heavy local surface not halved: {heavy} vs base {BASE_HEAVY}"
    );

    assert!(
        exec <= BASE_EXECUTOR * 82 / 100 + DECODE_SCAFFOLD_LOCALS,
        "executor local surface regressed: {exec} vs floor {}",
        BASE_EXECUTOR * 82 / 100 + DECODE_SCAFFOLD_LOCALS
    );
    assert!(
        pol <= BASE_POLISHED * 82 / 100 + DECODE_SCAFFOLD_LOCALS,
        "polished local surface regressed: {pol} vs floor {}",
        BASE_POLISHED * 82 / 100 + DECODE_SCAFFOLD_LOCALS
    );

    for (name, seed, profile, heavy_v, wm) in [
        (
            "polished",
            COLLAPSE_SEED,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            false,
        ),
        (
            "executor",
            COLLAPSE_SEED,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            true,
        ),
        (
            "heavy",
            COLLAPSE_SEED,
            TargetProfile::CliTest,
            SurfaceVolume::Medium,
            false,
        ),
    ] {
        let (maxf, _) = max_and_top(&build(seed, false, profile, heavy_v, false, wm));
        assert!(
            maxf <= HARD,
            "{name}: {maxf} live locals exceeds {HARD} hard budget"
        );
    }
}

#[test]
fn collapsed_surface_uses_private_table_not_readable_anchors() {
    for (profile, heavy, wm) in [
        (TargetProfile::CliTest, SurfaceVolume::Off, false),
        (TargetProfile::Executor, SurfaceVolume::Off, true),
        (TargetProfile::CliTest, SurfaceVolume::Medium, false),
    ] {
        let code = strip_lua(&build(COLLAPSE_SEED, true, profile, heavy, false, wm));

        for anchor in [
            "_HOISTTBL",
            "_hw",
            "_hs0",
            "_hm",
            "Helpers",
            "Constants",
            "Dispatch",
            "KGet",
            "KRoute",
            "Patch",
        ] {
            assert!(
                !code.contains(anchor),
                "{profile:?}/{heavy:?}: collapsed artifact leaks readable anchor `{anchor}`"
            );
        }

        for g in ["_G.", "_ENV.", "getgenv()", "shared.", "getfenv()."] {
            assert!(
                !code.contains(g),
                "{profile:?}/{heavy:?}: collapsed artifact writes helper state to global `{g}`"
            );
        }
    }
}

fn has_decimal_product(s: &str) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'*' {
            let mut l = 0;
            let mut p = i;
            while p > 0 && b[p - 1].is_ascii_digit() {
                p -= 1;
                l += 1;
            }
            let mut r = 0;
            let mut q = i + 1;
            while q < b.len() && b[q].is_ascii_digit() {
                q += 1;
                r += 1;
            }
            if l >= 3 && r >= 3 && (l >= 5 || r >= 5) {
                return true;
            }
        }
    }
    false
}

fn has_paren_decimal_arith_bait(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'(' && b[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j - (i + 1) >= 5 && j < b.len() && (b[j] == b'+' || b[j] == b'-') {
                let mut k = j + 1;
                while k < b.len() && b[k].is_ascii_digit() {
                    k += 1;
                }
                if k - (j + 1) >= 5 {
                    return Some(s[i..k].to_string());
                }
            }
        }
        i += 1;
    }
    None
}

#[test]
fn cold_canary_numeric_surface_is_lowered() {
    for seed in [COLLAPSE_SEED, 1, 2, 7, 100] {
        let art = build(
            seed,
            true,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            false,
            true,
        );
        assert!(
            !art.contains("4294967296"),
            "seed {seed}: plain decimal 2^32 survives in artifact"
        );
        if let Some(bait) = has_paren_decimal_arith_bait(&art) {
            panic!("seed {seed}: parenthesized decimal-arithmetic bait survives: {bait}");
        }
        assert!(
            has_decimal_product(&art),
            "seed {seed}: 2^32 must be lowered to a diversified build-time product"
        );
    }
}

#[test]
fn env_probe_surface_has_no_readable_antienvlog_anchors() {
    let code = strip_lua(&build(
        COLLAPSE_SEED,
        true,
        TargetProfile::Executor,
        SurfaceVolume::Off,
        false,
        true,
    ));
    for anchor in [
        "Stats",
        "Parent",
        "ClassName",
        "DataModel",
        "GetService",
        "RunService",
        "sandbox",
        "envlogger",
        "detect",
    ] {
        assert!(
            !code.contains(anchor),
            "executor artifact leaks readable env-probe anchor `{anchor}`"
        );
    }
}

#[test]
fn startup_crypto_sheds_bit32_field_surface() {
    let assert_clean = |art: &str, ctx: &str| {
        let code = strip_lua(art);
        assert!(
            !code.contains("bit32."),
            "{ctx}: artifact exposes a bit32.<field> literal (xor_loader surface)"
        );
        assert!(
            !code.contains("bxor("),
            "{ctx}: artifact exposes a bxor( call surface"
        );
    };
    for (profile, heavy) in [
        (TargetProfile::CliTest, SurfaceVolume::Off),
        (TargetProfile::Executor, SurfaceVolume::Off),
        (TargetProfile::CliTest, SurfaceVolume::Medium),
    ] {
        let art = build(
            COLLAPSE_SEED,
            true,
            profile,
            heavy,
            false,
            profile == TargetProfile::Executor,
        );
        assert_clean(&art, &format!("{profile:?}/{heavy:?}"));
    }
    let hash_art = pipeline::virtualize_full_prof(
        "local s = tostring(math.floor(os.clock()))\nlocal h = BASIL_HASH(s)\nreturn h\n",
        7,
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
        pipeline::SensitiveOpts::default(),
        TargetProfile::CliTest,
        false,
        false,
    )
    .expect("virtualize hash");
    assert!(
        hash_art.contains("0x428a2f98"),
        "test must actually exercise the runtime SHA helper"
    );
    assert_clean(&hash_art, "runtime-hash-helper");
}

#[test]
fn generated_artifacts_have_lph_style_local_surface() {
    let cases: [(&str, u64, TargetProfile, SurfaceVolume, bool, bool); 5] = [
        (
            "polished",
            0x5B01,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            false,
            false,
        ),
        (
            "executor-wm",
            0x5B02,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            false,
            true,
        ),
        (
            "executor-nowm",
            0x5B03,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            false,
            false,
        ),
        (
            "compress",
            0x5B04,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            true,
            false,
        ),
        (
            "basil-heavy",
            0x5B05,
            TargetProfile::CliTest,
            SurfaceVolume::Medium,
            false,
            false,
        ),
    ];
    let mut worst_local = 0usize;
    let mut worst_peak = 0usize;
    let mut all_stretch = true;
    for (name, seed, profile, heavy, compress, wm) in cases {
        let min = build_lph(seed, true, profile, heavy, compress, wm, true);
        let locals = count_locals(&min);

        let (maxf, top) = max_and_top(&min);
        worst_local = worst_local.max(locals);
        worst_peak = worst_peak.max(maxf);
        all_stretch &= locals < 200;
        let stretch = if locals < 200 { " [<200 stretch]" } else { "" };
        println!("lph-surface {name}: textual local = {locals}{stretch}, max live/function = {maxf}, top6 = {top:?}");
        assert!(
            locals < 250,
            "{name}: lph textual local surface {locals} is not under 250"
        );
        assert!(
            maxf <= HARD,
            "{name}: {maxf} live locals exceeds {HARD} hard budget"
        );

        let code = strip_lua(&min);
        for anchor in [
            "_SCRATCH",
            "_HOISTTBL",
            "_hw",
            "_hs0",
            "Helpers",
            "Constants",
            "Dispatch",
            "KGet",
            "State",
            "_G.",
            "_ENV.",
            "getgenv()",
            "shared.",
        ] {
            assert!(
                !code.contains(anchor),
                "{name}: lph artifact leaks anchor/global `{anchor}`"
            );
        }
    }
    println!("lph-surface worst: textual {worst_local} (<250 hard), max-live {worst_peak} (<={HARD}); all-under-200-stretch={all_stretch}");
    if let Some(luau) = find_luau() {
        for (name, seed, profile, heavy, compress, wm) in cases {
            let min = build_lph(seed, true, profile, heavy, compress, wm, true);
            if let Some(e) = luau_register_error(&luau, &min, &format!("lph_{name}")) {
                panic!("{name} lph artifact overflows Luau local registers: {e}");
            }
        }
        println!("lph-surface: all five lph profiles compile in Luau with no register overflow");
    }
}

#[test]
fn lph_shared_table_value_hoist_reduces_outer_captures() {
    let cases: [(&str, u64, TargetProfile, SurfaceVolume, bool, bool); 5] = [
        (
            "polished",
            0x5C01,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            false,
            false,
        ),
        (
            "executor-wm",
            0x5C02,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            false,
            true,
        ),
        (
            "executor-nowm",
            0x5C03,
            TargetProfile::Executor,
            SurfaceVolume::Off,
            false,
            false,
        ),
        (
            "compress",
            0x5C04,
            TargetProfile::CliTest,
            SurfaceVolume::Off,
            true,
            false,
        ),
        (
            "basil-heavy",
            0x5C05,
            TargetProfile::CliTest,
            SurfaceVolume::Medium,
            false,
            false,
        ),
    ];
    let mut worst_local = 0usize;
    let mut worst_peak = 0usize;
    for (name, seed, profile, heavy, compress, wm) in cases {
        let min = build_lph(seed, true, profile, heavy, compress, wm, true);
        let locals = count_locals(&min);

        let (maxf, top) = max_and_top(&min);
        worst_local = worst_local.max(locals);
        worst_peak = worst_peak.max(maxf);
        let ls = if locals < 120 { " [<120 stretch]" } else { "" };
        let ps = if maxf < 60 { " [<60 stretch]" } else { "" };
        println!("value-hoist {name}: textual local = {locals}{ls}, max live/function = {maxf}{ps}, top6 = {top:?}");
        assert!(
            locals < 150,
            "{name}: value-hoist textual local surface {locals} is not under 150"
        );
        assert!(
            maxf <= 160,
            "{name}: {maxf} live locals exceeds 160 hard budget"
        );
        let code = strip_lua(&min);
        for anchor in [
            "Helpers",
            "Constants",
            "Dispatch",
            "KGet",
            "Patch",
            "State",
            "_SCR_",
            "_HELPERS",
            "_STATE",
            "_SHARED",
            "_HOISTTBL",
            "_G.",
            "_ENV.",
            "getgenv()",
            "shared.",
        ] {
            assert!(
                !code.contains(anchor),
                "{name}: value-hoist artifact leaks anchor/global `{anchor}`"
            );
        }
    }
    println!(
        "value-hoist worst: textual {worst_local} (<150 hard), max-live {worst_peak} (<=160 hard)"
    );

    let a = build_lph(
        0x777,
        true,
        TargetProfile::Executor,
        SurfaceVolume::Off,
        false,
        false,
        true,
    );
    let b = build_lph(
        0x778,
        true,
        TargetProfile::Executor,
        SurfaceVolume::Off,
        false,
        false,
        true,
    );
    assert_ne!(a, b, "value-hoist slot layout must vary across seeds");
    if let Some(luau) = find_luau() {
        for (name, seed, profile, heavy, compress, wm) in cases {
            let min = build_lph(seed, true, profile, heavy, compress, wm, true);
            if let Some(e) = luau_register_error(&luau, &min, &format!("vh_{name}")) {
                panic!("{name} value-hoist artifact overflows Luau local registers: {e}");
            }
        }
        println!("value-hoist: all five profiles compile in Luau with no register overflow");
    }
}

#[test]
fn local_budget_scanner_matches_luau_on_a_known_overflow() {
    let mut body = String::from("local function f(x)\n");
    for i in 0..205 {
        body.push_str(&format!("local v{i} = x + {i}\n"));
    }
    let terms: Vec<String> = (0..205).map(|i| format!("v{i}")).collect();
    body.push_str(&format!("return {}\nend\nreturn f(1)\n", terms.join(" + ")));
    let (maxf, _) = max_and_top(&body);
    assert!(
        maxf >= 205,
        "scanner counts the 205 flat locals (got {maxf})"
    );
    if let Some(luau) = find_luau() {
        assert!(
            luau_register_error(&luau, &body, "overflow205").is_some(),
            "luau rejects 205 flat locals"
        );
    }
}
