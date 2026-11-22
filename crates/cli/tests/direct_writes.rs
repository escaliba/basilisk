use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU32 = AtomicU32::new(0);

fn tmpdir() -> PathBuf {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("basil_dw_{}_{}_{}", std::process::id(), nanos, n));
    std::fs::create_dir_all(&d).unwrap();
    d
}

const SRC: &str =
    "local a=0\nfor i=1,9 do a=a+i*2 end\nlocal t={a,a*2,a-1}\nreturn t[1]+t[2]+t[3]\n";

fn build(direct_writes: bool) -> String {
    let dir = tmpdir();
    let inp = dir.join("in.luau");
    let out = dir.join("out.luau");
    std::fs::write(&inp, SRC).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_basilisk"));
    cmd.arg(&inp)
        .arg(&out)
        .arg("--no-interactive")
        .arg("--no-minify")
        .arg("--seed")
        .arg("3");
    cmd.env_remove("BASIL_DIRECT_WRITES");
    if direct_writes {
        cmd.env("BASIL_DIRECT_WRITES", "1");
    }
    let status = cmd.status().expect("spawn basilisk");
    assert!(
        status.success(),
        "basilisk build failed (direct_writes={direct_writes})"
    );
    let art = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    art
}

fn helpers(s: &str) -> (usize, usize) {
    (s.matches("rs(").count(), s.matches("rg(").count())
}

#[test]
fn direct_writes_off_by_default_keeps_register_helpers() {
    let (rs, rg) = helpers(&build(false));
    assert!(
        rs > 0 && rg > 0,
        "default (OFF) build keeps shared register helpers: rs={rs} rg={rg}"
    );
}

#[test]
fn direct_writes_on_emits_a_direct_write_artifact() {
    let off = build(false);
    let on = build(true);
    assert_ne!(off, on, "BASIL_DIRECT_WRITES must change the emitted VM");
    let (ors, org) = helpers(&off);
    let (nrs, nrg) = helpers(&on);
    assert!(
        nrs < ors && nrg < org,
        "direct writes must reduce shared rs/rg helpers: off=({ors},{org}) on=({nrs},{nrg})"
    );
    assert!(
        nrs + nrg < (ors + org) / 2,
        "direct writes should remove most shared helpers: off_sum={}, on_sum={}",
        ors + org,
        nrs + nrg
    );
}
