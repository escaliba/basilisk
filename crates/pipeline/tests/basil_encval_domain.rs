use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const WRONG: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
static N: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_evd_{}_{}.luau",
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

fn build(body: &str, seed: u64) -> Result<String, String> {
    let s = format!("{body}\n");
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_with(&s, seed, true, true, true, true, true, false, false)
                .map_err(|e| format!("{e:#}"))
        })
        .unwrap()
        .join()
        .unwrap()
}

fn run(luau: &str, art: &str, key: &str) -> String {
    let p = tmp();
    let full = format!("BASILISK_RUNTIME_KEY = \"{key}\"\n{art}");
    std::fs::write(&p, &full).unwrap();
    let o = Command::new(luau).arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
    .trim()
    .to_string()
}

fn blob_table(art: &str) -> (usize, usize) {
    let start = art.find("{[==[").expect("blob table");
    let end = start + art[start..].find("]==]}").expect("blob close") + "]==]}".len();
    (start, end)
}

fn graft(host: &str, donor: &str) -> String {
    let (hs, he) = blob_table(host);
    let (ds, de) = blob_table(donor);
    format!("{}{}{}", &host[..hs], &donor[ds..de], &host[he..])
}

const RK: &str = "local rk = BASILISK_RUNTIME_KEY\n";

fn str_donor(m: &str) -> String {
    format!("{RK}local s = BASIL_ENCSTR(\"{m}\", \"{KEY}\", rk)\nprint(s)")
}
fn str_site(m: &str) -> String {
    format!("{RK}local s = BASIL_ENCFUNC(function() return \"{m}\" end, \"{KEY}\", rk)()\nprint(s)")
}
fn buf_donor(m: &str) -> String {
    format!("{RK}local b = BASIL_ENCBUF(\"{m}\", \"{KEY}\", rk)\nprint(buffer.readu8(b, 0))")
}
fn buf_site(m: &str) -> String {
    format!("{RK}local b = BASIL_ENCFUNC(function() return buffer.fromstring(\"{m}\") end, \"{KEY}\", rk)()\nprint(buffer.readu8(b, 0))")
}

#[test]
fn x01_external_encstr_correct_key() {
    let Some(luau) = find_luau() else { return };
    let art = build(&str_donor("EXTSTR-OK"), 305419896).expect("build");
    assert_eq!(run(&luau, &art, KEY), "EXTSTR-OK");
    assert!(
        !run(&luau, &art, WRONG).contains("EXTSTR-OK"),
        "wrong key fails closed"
    );
}

#[test]
fn x02_external_encbuf_correct_key() {
    let Some(luau) = find_luau() else { return };
    let art = build(&buf_donor("Zbytes"), 305419896).expect("build");
    let out = run(&luau, &art, KEY);
    if out.contains("attempt to index") {
        return;
    }
    assert_eq!(out, "90", "correct key materializes buffer ('Z' = 90)");
    assert_ne!(run(&luau, &art, WRONG), "90", "wrong key fails closed");
}

#[test]
fn x03_encstr_blob_into_encfunc_site_fails() {
    let Some(luau) = find_luau() else { return };
    let site = build(&str_site("XCLASS"), 305419896).expect("site");
    let donor = build(&str_donor("XCLASS"), 305419896).expect("donor");
    let (ss, se) = blob_table(&site);
    let (ds, de) = blob_table(&donor);
    assert_ne!(
        &site[ss..se],
        &donor[ds..de],
        "ENCSTR and ENCFUNC blobs must differ (class-tagged AD)"
    );
    let out = run(&luau, &graft(&site, &donor), KEY);
    assert!(
        !out.contains("XCLASS"),
        "ENCSTR blob must not authenticate at an ENCFUNC site; got {out:?}"
    );
}

#[test]
fn x04_encfunc_blob_into_encstr_site_fails() {
    let Some(luau) = find_luau() else { return };
    let site = build(&str_donor("YCLASS"), 305419896).expect("encstr site");
    let donor = build(&str_site("YCLASS"), 305419896).expect("encfunc donor");
    let out = run(&luau, &graft(&site, &donor), KEY);
    assert!(
        !out.contains("YCLASS"),
        "ENCFUNC blob must not authenticate at an ENCSTR site; got {out:?}"
    );
}

#[test]
fn x05_encbuf_blob_into_encfunc_site_fails() {
    let Some(luau) = find_luau() else { return };
    let site = build(&buf_site("Zbytes"), 305419896).expect("site");
    let donor = build(&buf_donor("Zbytes"), 305419896).expect("donor");
    if run(&luau, &site, KEY).contains("attempt to index") {
        return;
    }
    let out = run(&luau, &graft(&site, &donor), KEY);
    assert_ne!(
        out, "90",
        "ENCBUF blob must not authenticate at an ENCFUNC site; got {out:?}"
    );
}

#[test]
fn x06_encstr_blob_into_encbuf_site_fails() {
    let Some(luau) = find_luau() else { return };
    let site = build(&buf_site("Zbytes"), 305419896).expect("encbuf site");
    let donor = build(&str_donor("Zbytes"), 305419896).expect("encstr donor");
    if run(&luau, &site, KEY).contains("attempt to index") {
        return;
    }
    let out = run(&luau, &graft(&site, &donor), KEY);
    assert_ne!(
        out, "90",
        "ENCSTR blob must not authenticate at an ENCBUF site; got {out:?}"
    );
}

#[test]
fn x07_matched_class_graft_succeeds() {
    let Some(luau) = find_luau() else { return };
    let a = build(&str_donor("SAME-CLASS"), 305419896).expect("a");
    let b = build(&str_donor("SAME-CLASS"), 305419896).expect("b");
    assert_eq!(
        run(&luau, &graft(&a, &b), KEY),
        "SAME-CLASS",
        "same-class graft authenticates"
    );
}
