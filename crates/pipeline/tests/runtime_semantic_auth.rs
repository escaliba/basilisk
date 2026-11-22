use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn find_luau() -> Option<String> {
    if let Ok(b) = std::env::var("LUAU_BIN") {
        return Some(b);
    }
    for c in ["luau", "/opt/homebrew/bin/luau", "/usr/local/bin/luau"] {
        if Command::new(c).arg("--help").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_rsa_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn run_luau(luau: &str, code: &str) -> String {
    let p = tmp();
    std::fs::write(&p, code).unwrap();
    let o = Command::new(luau).arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn build_unminified(src: &str, seed: u64) -> String {
    let s = src.to_string();
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_full_prof(
                &s,
                seed,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Off,
                false,
                pipeline::SensitiveOpts::default(),
                pipeline::TargetProfile::CliTest,
                false,
                false,
            )
            .expect("build")
        })
        .unwrap()
        .join()
        .unwrap()
}

const FIXTURE: &str = r#"
local function mk(base)
  local n = base
  return function()
    n = n + 1
    return tostring(n) .. "!"
  end
end
local a = mk(10)
local b = mk(20)
print(a(), a(), b(), a())
"#;

const CHILD_TICKET: &str = "child[20] = actTicket(proto[20], child[5])";
const ROOT_TICKET: &str = "mainProto[20] = actTicket(actRoot(), 0)";
const CHILD_CTOR: &str = "makeClosure(child, cu)";

fn plain_output(luau: &str) -> String {
    run_luau(luau, FIXTURE)
}

#[test]
fn genuine_artifact_matches_plain() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping runtime_semantic_auth");
        return;
    };
    let plain = plain_output(&luau);
    assert!(plain.contains("13!"), "fixture sanity: {plain}");
    for seed in [1u64, 42, 777] {
        let art = build_unminified(FIXTURE, seed);
        assert_eq!(
            run_luau(&luau, &art),
            plain,
            "genuine artifact diverged (seed {seed})"
        );
    }
}

#[test]
fn corrupted_child_lineage_fails_closed() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping runtime_semantic_auth");
        return;
    };
    let plain = plain_output(&luau);
    for seed in [1u64, 42, 777] {
        let art = build_unminified(FIXTURE, seed);
        assert_eq!(
            art.matches(CHILD_TICKET).count(),
            1,
            "child-lineage seam absent (seed {seed})"
        );
        let tampered = art.replace(
            CHILD_TICKET,
            "child[20] = actTicket(proto[20], child[5]) + 1",
        );
        let out = run_luau(&luau, &tampered);
        assert_ne!(
            out, plain,
            "wrong child lineage still produced correct output (seed {seed})"
        );
        assert!(
            !out.contains("13!"),
            "wrong child lineage was not fail-closed (seed {seed}): {out:?}"
        );
    }
}

#[test]
fn corrupted_root_lineage_fails_closed() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping runtime_semantic_auth");
        return;
    };
    let plain = plain_output(&luau);
    for seed in [1u64, 42, 777] {
        let art = build_unminified(FIXTURE, seed);
        assert_eq!(
            art.matches(ROOT_TICKET).count(),
            1,
            "root-lineage seam absent (seed {seed})"
        );
        let tampered = art.replace(ROOT_TICKET, "mainProto[20] = actTicket(actRoot(), 0) + 1");
        let out = run_luau(&luau, &tampered);
        assert_ne!(
            out, plain,
            "wrong root lineage still produced correct output (seed {seed})"
        );
        assert!(
            !out.contains("13!"),
            "wrong root lineage was not fail-closed (seed {seed}): {out:?}"
        );
    }
}

#[test]
fn cross_proto_constant_key_confusion_fails_closed() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping runtime_semantic_auth");
        return;
    };
    let plain = plain_output(&luau);
    for seed in [1u64, 42, 777] {
        let art = build_unminified(FIXTURE, seed);
        assert_eq!(
            art.matches(CHILD_TICKET).count(),
            1,
            "child-lineage seam absent (seed {seed})"
        );
        let tampered = art.replace(
            CHILD_TICKET,
            "child[20] = actTicket(proto[20], child[5] + 1)",
        );
        let out = run_luau(&luau, &tampered);
        assert_ne!(
            out, plain,
            "neighbouring-proto lineage still produced correct output (seed {seed})"
        );
        assert!(
            !out.contains("13!"),
            "cross-proto lineage was not fail-closed (seed {seed}): {out:?}"
        );
    }
}

#[test]
fn forwarding_wrapper_on_vm_closures_is_not_detected() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping runtime_semantic_auth");
        return;
    };
    let plain = plain_output(&luau);
    for seed in [1u64, 42, 777] {
        let art = build_unminified(FIXTURE, seed);
        assert!(
            art.matches(CHILD_CTOR).count() >= 1,
            "child constructor seam absent (seed {seed})"
        );
        let wrapped = art
            .replacen(
                "local makeClosure",
                "local function _bwrap(fn) return function(...) return fn(...) end end\nlocal makeClosure",
                1,
            )
            .replace(CHILD_CTOR, "_bwrap(makeClosure(child, cu))");
        let out = run_luau(&luau, &wrapped);
        assert_eq!(
            out, plain,
            "forwarding wrapper changed observable behavior (seed {seed}); the documented runtime \
             substitution limitation may have moved — revisit reference/reports",
        );
    }
}
