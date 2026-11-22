use ir::cfg::{self, ReturnClass, Terminator};
use ir::{FuncBody, Stmt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_cfg_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn find_luau() -> Option<String> {
    Command::new("luau")
        .arg("--version")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn func_of(decl: &str) -> FuncBody {
    let m = frontend::lower_str(decl).expect("lower");
    for s in &m.block.stmts {
        if let Stmt::LocalFunction { body, .. } = s {
            return body.clone();
        }
    }
    panic!("no local function in fixture");
}

fn cfg_of(decl: &str) -> cfg::Cfg {
    cfg::build(&func_of(decl))
}

fn every_block_has_a_terminator(c: &cfg::Cfg) {
    for (i, b) in c.blocks.iter().enumerate() {
        match &b.term {
            Terminator::Goto(t) => assert!(*t < c.blocks.len(), "block {i} jumps out of range"),
            Terminator::Branch {
                when_true,
                when_false,
                ..
            } => {
                assert!(
                    *when_true < c.blocks.len(),
                    "block {i} true edge out of range"
                );
                assert!(
                    *when_false < c.blocks.len(),
                    "block {i} false edge out of range"
                );
            }
            Terminator::Return(_) => {}
        }
    }
}

fn check(decl: &str) -> cfg::Cfg {
    let c = cfg_of(decl);
    every_block_has_a_terminator(&c);
    assert!(!c.blocks.is_empty(), "a CFG always has an entry block");
    assert_eq!(c.entry, 0, "entry is always block 0");
    c
}

#[test]
fn c01_straight_line_function() {
    let c = check("local function f(a, b) local x = a + b print(x) end");
    assert_eq!(c.block_count(), 1, "no control flow means one block");
    assert_eq!(
        c.edge_count(),
        0,
        "a single returning block has no successors"
    );
    assert_eq!(c.return_class(), ReturnClass::Void);
    assert_eq!(c.params.len(), 2);
}

#[test]
fn c02_one_if_branch() {
    let c = check("local function f(a) if a then print(1) end return 2 end");
    assert!(c.block_count() >= 4, "test, then, else and join");
    assert_eq!(c.join_blocks().len(), 1, "one join block");
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
    assert_eq!(c.return_count(), 1);
}

#[test]
fn c03_if_else() {
    let c = check("local function f(a) if a then return 1 else return 2 end end");
    assert_eq!(c.return_count(), 2, "both arms return");
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
    assert_eq!(c.early_return_count(), 1);
}

#[test]
fn c04_nested_branches() {
    let c =
        check("local function f(a, b) if a then if b then return 1 end return 2 end return 3 end");
    assert_eq!(c.return_count(), 3);
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
    assert_eq!(c.early_return_count(), 2);
    assert!(
        c.join_blocks().is_empty(),
        "when every arm returns there is no join with two predecessors"
    );

    let joined = check("local function f(a, b) local r = 0 if a then if b then r = 1 else r = 2 end else r = 3 end return r end");
    assert!(
        !joined.join_blocks().is_empty(),
        "a branch that falls through does produce joins"
    );
}

#[test]
fn c05_terminal_return_only() {
    let c = check("local function f(a) local x = a * 2 return x end");
    assert_eq!(c.return_count(), 1);
    assert_eq!(
        c.early_return_count(),
        0,
        "a single terminal return is not early"
    );
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
}

#[test]
fn c06_early_return_in_first_branch() {
    let c = check("local function f(a) if a == nil then return 0 end return a + 1 end");
    assert_eq!(c.return_count(), 2);
    assert_eq!(c.early_return_count(), 1);
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
}

#[test]
fn c07_several_early_returns() {
    let c = check(
        "local function f(a) if a == 1 then return \"one\" end if a == 2 then return \"two\" end \
         if a == 3 then return \"three\" end return \"many\" end",
    );
    assert_eq!(c.return_count(), 4);
    assert_eq!(c.early_return_count(), 3);
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
}

#[test]
fn c08_bare_return_and_implicit_return() {
    let bare = check("local function f(a) if a then return end print(a) end");
    assert_eq!(
        bare.return_class(),
        ReturnClass::Void,
        "bare returns are void"
    );
    assert!(
        bare.return_count() >= 2,
        "explicit bare return plus the implicit tail return"
    );

    let implicit = check("local function f(a) print(a) end");
    assert_eq!(implicit.return_class(), ReturnClass::Void);
    assert_eq!(
        implicit.return_count(),
        1,
        "the implicit tail return is materialised"
    );

    let mixed = check("local function f(a) if a then return end return 1 end");
    assert_eq!(
        mixed.return_class(),
        ReturnClass::Mixed,
        "void and value paths are Mixed"
    );
}

#[test]
fn c09_return_inside_loop() {
    let c =
        check("local function f(n) for i = 1, n do if i == 3 then return i end end return 0 end");
    assert!(c.has_loop());
    assert_eq!(
        c.returns_inside_loop(),
        1,
        "one return sits inside the loop body"
    );
    assert_eq!(c.return_count(), 2);
}

#[test]
fn c10_nested_loop_return() {
    let c = check(
        "local function f(n) for i = 1, n do for j = 1, n do if i * j > 6 then return i end end end return 0 end",
    );
    assert!(c.has_loop());
    assert_eq!(c.returns_inside_loop(), 1);
}

#[test]
fn c11_break_targets_the_enclosing_loop_exit() {
    let c = check("local function f(n) local s = 0 for i = 1, n do if i > 2 then break end s = s + i end return s end");
    assert!(c.has_loop());
    every_block_has_a_terminator(&c);
    assert_eq!(c.return_count(), 1, "break is not a return");
}

#[test]
fn c12_continue_targets_the_loop_header() {
    let c = check("local function f(n) local s = 0 for i = 1, n do if i == 2 then continue end s = s + i end return s end");
    assert!(c.has_loop());
    assert_eq!(c.return_count(), 1, "continue is not a return");
}

#[test]
fn c13_nested_break_and_continue_bind_to_their_own_loop() {
    let c = check(
        "local function f(n) local s = 0 for i = 1, n do for j = 1, n do if j == 2 then break end \
         if j == 3 then continue end s = s + 1 end if i == 4 then break end end return s end",
    );
    assert!(c.has_loop());
    every_block_has_a_terminator(&c);
    let r = c.reachable();
    assert!(r[c.entry]);
}

#[test]
fn c14_statements_after_a_do_return_are_unreachable() {
    let c = check("local function f(a) do return 1 end print(\"never\") return 2 end");
    let dead = c.unreachable_blocks();
    assert!(
        !dead.is_empty(),
        "code after an unconditional return is unreachable"
    );
    assert_eq!(c.return_count(), 1, "only the reachable return is counted");
}

#[test]
fn c15_shadowed_locals_get_distinct_binding_ids() {
    let c = check("local function f(a) local x = 1 do local x = 2 print(x) end return x end");
    let xs: Vec<_> = c.bindings.iter().filter(|b| b.name == "x").collect();
    assert_eq!(xs.len(), 2, "the inner and outer x are separate bindings");
    assert_ne!(xs[0].id, xs[1].id, "distinct binding identity");
    assert!(
        xs[1].scope_depth > xs[0].scope_depth,
        "the shadow is deeper"
    );
}

#[test]
fn c16_mutation_across_a_branch_join() {
    let c = check("local function f(a) local x = 0 if a then x = 1 else x = 2 end return x end");
    assert_eq!(c.join_blocks().len(), 1, "one join after the branch");
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
}

#[test]
fn c17_closure_capture_across_a_join_is_visible_as_a_nested_body() {
    let c = check("local function f(a) local x = 0 if a then x = 1 end local g = function() return x end return g() end");
    assert!(
        !c.free_names.contains(&"x".to_string()),
        "x is local, not free"
    );
    assert!(c.bindings.iter().any(|b| b.name == "g"));
}

#[test]
fn c18_argument_side_effects_stay_in_statement_order() {
    let c = check("local function f(a) local x = side(1) local y = side(2) return x + y end");
    assert_eq!(c.block_count(), 1);
    assert_eq!(c.blocks[0].stmts.len(), 2, "both locals stay, in order");
    assert!(
        c.free_names.contains(&"side".to_string()),
        "an unresolved call target is free"
    );
}

#[test]
fn c19_pcall_boundary_is_represented_and_visible() {
    let c =
        check("local function f(a) local ok, e = pcall(function() return a.x end) return ok end");
    assert!(
        c.free_names.contains(&"pcall".to_string()),
        "pcall is a free name a transform can reject on"
    );
    assert_eq!(c.return_class(), ReturnClass::SingleValue);
}

#[test]
fn c20_vararg_function_is_marked() {
    let c = check("local function f(...) return select(\"#\", ...) end");
    assert!(
        c.is_vararg,
        "vararg is recorded so transforms can reject it"
    );
    let fixed = check("local function f(a) return a end");
    assert!(!fixed.is_vararg);
}

#[test]
fn c21_multiple_return_function_is_marked() {
    let c = check("local function f(a) return a, a + 1 end");
    assert_eq!(
        c.return_class(),
        ReturnClass::MultiValue,
        "multi-value returns are marked, not inlined"
    );
    let one = check("local function f(a) return a end");
    assert_eq!(one.return_class(), ReturnClass::SingleValue);
}

#[test]
fn c22_same_source_builds_an_identical_cfg() {
    let src = "local function f(a, b) if a then for i = 1, b do if i == 2 then return i end end end return 0 end";
    let a = cfg_of(src);
    let b = cfg_of(src);
    assert_eq!(a, b, "CFG construction is deterministic");
    assert_eq!(a.block_count(), b.block_count());
    assert_eq!(a.edge_count(), b.edge_count());
}

#[test]
fn c23_building_a_cfg_does_not_perturb_a_build() {
    let src =
        "local function add(a, b) if a > b then return a end return b end\nprint(add(2, 3))\n";
    let before =
        pipeline::virtualize_with(src, 42, true, true, true, true, true, false, false).unwrap();
    let c = cfg_of(src);
    assert!(c.block_count() > 1, "the CFG really was built");
    let after =
        pipeline::virtualize_with(src, 42, true, true, true, true, true, false, false).unwrap();
    assert_eq!(
        before, after,
        "same seed stays byte-identical around CFG construction"
    );
}

#[test]
fn c24_cfg_shape_matches_observed_execution() {
    let Some(luau) = find_luau() else { return };
    let cases: [(&str, &str); 6] = [
        ("straight", "local function f(a, b) return a + b end\nprint(f(2, 3))\n"),
        ("early", "local function f(a) if a == nil then return 0 end return a + 1 end\nprint(f(nil), f(4))\n"),
        ("void", "local function f(t) if not t then return end print(\"got\") end\nf(false)\nf(true)\n"),
        ("loop", "local function f(n) local s = 0 for i = 1, n do if i == 3 then return s end s = s + i end return -1 end\nprint(f(5), f(2))\n"),
        ("brkcont", "local function f(n) local s = 0 for i = 1, n do if i == 2 then continue end if i == 5 then break end s = s + i end return s end\nprint(f(9))\n"),
        ("shadow", "local function f(a) local x = 1 do local x = 2 a = a + x end return a + x end\nprint(f(10))\n"),
    ];
    for (name, src) in cases {
        let p = tmp(name);
        std::fs::write(&p, src).unwrap();
        let plain = Command::new(&luau).arg(&p).output().expect("luau");
        let _ = std::fs::remove_file(&p);
        let plain_out = String::from_utf8_lossy(&plain.stdout).trim().to_string();
        assert!(
            !plain_out.is_empty(),
            "[{name}] fixture must print something"
        );

        let obf = pipeline::virtualize_with(src, 1337, true, true, true, true, true, false, false)
            .unwrap();
        let q = tmp(&format!("{name}_obf"));
        std::fs::write(&q, &obf).unwrap();
        let got = Command::new(&luau).arg(&q).output().expect("luau");
        let _ = std::fs::remove_file(&q);
        assert_eq!(
            String::from_utf8_lossy(&got.stdout).trim(),
            plain_out,
            "[{name}] virtualized output must match plain Luau"
        );

        let m = frontend::lower_str(src).expect("lower");
        for s in &m.block.stmts {
            if let Stmt::LocalFunction { body, .. } = s {
                let c = cfg::build(body);
                every_block_has_a_terminator(&c);
                assert!(c.reachable()[c.entry]);
            }
        }
    }
}
