use std::process::Command;

fn find_luau() -> Option<String> {
    Command::new("luau")
        .arg("--version")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn run_luau(code: &str) -> String {
    let p = std::env::temp_dir().join(format!("basilisk_optrev_{}.luau", std::process::id()));
    std::fs::write(&p, code).unwrap();
    let o = Command::new("luau").arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const SRC: &str = "local x = 1 + 2 * 3\nif false then print(\"dead\") end\nlocal s = 0\nfor i = 1, 5 do s = s + i end\nprint(x, s)\n";

#[test]
fn review_folds_literals_and_prunes_dead_branches() {
    let r = pipeline::review_source(SRC, 2).expect("review");
    assert!(
        r.optimized_luau.contains("local x = 7"),
        "literal fold expected, got: {}",
        r.optimized_luau
    );
    assert!(
        !r.optimized_luau.contains("dead"),
        "literal-false branch must be pruned at level 2: {}",
        r.optimized_luau
    );
    assert!(
        r.bytes_after < r.bytes_before,
        "optimization should shrink canonical source"
    );
    assert_eq!(r.input_sha256.len(), 64, "input sha256 present");
}

#[test]
fn review_is_deterministic() {
    let a = pipeline::review_source(SRC, 2).unwrap();
    let b = pipeline::review_source(SRC, 2).unwrap();
    assert_eq!(
        a.optimized_luau, b.optimized_luau,
        "review output must be deterministic"
    );
    assert_eq!(
        (a.bytes_before, a.bytes_after),
        (b.bytes_before, b.bytes_after)
    );
}

#[test]
fn review_level_zero_is_a_faithful_reprint() {
    let r = pipeline::review_source(SRC, 0).expect("review");
    assert_eq!(
        r.bytes_before, r.bytes_after,
        "level 0 applies no optimizer"
    );
    assert!(
        r.optimized_luau.contains("1 + 2 * 3") || r.optimized_luau.contains("(1 + (2 * 3))"),
        "unfolded at level 0: {}",
        r.optimized_luau
    );
}

#[test]
fn review_output_runs_equivalently_to_the_input() {
    if find_luau().is_none() {
        return;
    }
    let expect = run_luau(SRC);
    for level in [0u8, 1, 2] {
        let r = pipeline::review_source(SRC, level).unwrap();
        let got = run_luau(&r.optimized_luau);
        assert_eq!(
            expect, got,
            "review source (level {level}) must run equivalently to the input"
        );
    }
}

#[test]
fn review_preserves_macro_calls_as_ordinary_calls() {
    let src = "local rk = BASILISK_RUNTIME_KEY\nlocal f = BASIL_ENCFUNC(function(n) return n + (1 + 1) end, \"00\", rk)\nprint(f(1))\n";
    let r = pipeline::review_source(src, 2).expect("review");
    assert!(
        r.optimized_luau.contains("BASIL_ENCFUNC"),
        "macros stay call-shaped in review (pre-expand): {}",
        r.optimized_luau
    );
    assert!(
        r.optimized_luau.contains("function(n)"),
        "the macro's function-literal body is preserved verbatim"
    );
}

#[test]
fn review_folds_inside_statement_function_bodies() {
    let src = "local function helper() local d = 1 + 1 return d end\nprint(helper())\n";
    let r = pipeline::review_source(src, 2).expect("review");
    assert!(
        r.optimized_luau.contains("local d = 2"),
        "folds inside a local-function body: {}",
        r.optimized_luau
    );
}
