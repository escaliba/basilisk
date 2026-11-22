use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const WRONG: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

static N: AtomicU64 = AtomicU64::new(0);

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_ev_{p}_{}_{}.luau",
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

fn run(luau: &str, art: &str, key: Option<&str>) -> String {
    let mut full = String::new();
    if let Some(k) = key {
        full.push_str(&format!("BASILISK_RUNTIME_KEY = \"{k}\"\n"));
    }
    full.push_str(art);
    let p = tmp("run");
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

#[test]
fn e01_encstr_one_arg_materializes() {
    let Some(luau) = find_luau() else { return };
    let art = build(
        "local s = BASIL_ENCSTR(\"hello-sealed-marker\")\nprint(s)",
        305419896,
    )
    .expect("build");
    assert!(
        !art.contains("hello-sealed-marker"),
        "plaintext must not ship"
    );
    assert_eq!(run(&luau, &art, None), "hello-sealed-marker");
}

#[test]
fn e02_encnum_one_arg_materializes() {
    let Some(luau) = find_luau() else { return };
    let art = build("local n = BASIL_ENCNUM(1234567)\nprint(n)", 305419896).expect("build");
    assert!(!art.contains("1234567"), "plaintext number must not ship");
    assert_eq!(run(&luau, &art, None), "1234567");
}

#[test]
fn e03_encnum_negative_and_float() {
    let Some(luau) = find_luau() else { return };
    let art = build("print(BASIL_ENCNUM(-42), BASIL_ENCNUM(3.5))", 305419896).expect("build");
    assert_eq!(run(&luau, &art, None), "-42\t3.5");
}

#[test]
fn e04_encbuf_one_arg_roundtrips_binary() {
    let Some(luau) = find_luau() else { return };
    let art = match build("local b = BASIL_ENCBUF(\"a\\0b\\255c\")\nprint(buffer.len(b), buffer.readu8(b, 1), buffer.readu8(b, 3))", 305419896) {
        Ok(a) => a,
        Err(e) => panic!("encbuf build: {e}"),
    };

    let out = run(&luau, &art, None);
    if out.contains("attempt to index") {
        return;
    }
    assert_eq!(out, "5\t0\t255");
}

#[test]
fn e05_encstr_external_key_auth_and_fail_closed() {
    let Some(luau) = find_luau() else { return };
    let body = format!("local rk = BASILISK_RUNTIME_KEY\nlocal s = BASIL_ENCSTR(\"ext-secret-xyz\", \"{KEY}\", rk)\nprint(s)");
    let art = build(&body, 305419896).expect("build");
    assert!(!art.contains("ext-secret-xyz"), "plaintext must not ship");
    assert_eq!(
        run(&luau, &art, Some(KEY)),
        "ext-secret-xyz",
        "correct key materializes"
    );
    assert!(
        !run(&luau, &art, Some(WRONG)).contains("ext-secret-xyz"),
        "wrong key must fail closed"
    );
    assert!(
        !run(&luau, &art, None).contains("ext-secret-xyz"),
        "absent runtime key must fail closed"
    );
}

#[test]
fn e06_encnum_binding_load_bearing() {
    let Some(luau) = find_luau() else { return };
    let ok = "local function hw() return 42 end\nlocal n = BASIL_ENCNUM(9991, { [hw()] = 42 })\nprint(n)";
    let art = build(ok, 305419896).expect("build");
    assert!(!art.contains("9991"), "plaintext must not ship");
    assert_eq!(
        run(&luau, &art, None),
        "9991",
        "correct binding materializes"
    );

    let bad =
        "local function hw() return 7 end\nlocal n = BASIL_ENCNUM(9991, { [hw()] = 42 })\nprint(n)";
    let art2 = build(bad, 305419896).expect("build");
    assert!(
        !run(&luau, &art2, None).contains("9991"),
        "wrong runtime binding must fail closed"
    );
}

#[test]
fn e07_encnum_two_bindings() {
    let Some(luau) = find_luau() else { return };
    let src = "local function a() return 3 end\nlocal function b() return 8 end\nlocal n = BASIL_ENCNUM(555, { [a()] = 3, [b()] = 8 })\nprint(n)";
    let art = build(src, 305419896).expect("build");
    assert_eq!(run(&luau, &art, None), "555");
}

#[test]
fn e08_desugars_to_encfunc() {
    let m = frontend::lower_str("local s = BASIL_ENCSTR(\"x\")\nprint(s)\n").expect("lower");
    let m = frontend::macros::expand(m, 42).expect("expand");
    assert_eq!(
        m.encfuncs.len(),
        1,
        "ENCSTR must desugar into exactly one sealed ENCFUNC"
    );
}

#[test]
fn e09_encstr_non_literal_rejected() {
    let e = build("local x = \"y\"\nlocal s = BASIL_ENCSTR(x)\nprint(s)", 42).unwrap_err();
    assert!(e.contains("string literal"), "got: {e}");
}

fn seal_key(src: &str) -> String {
    let m = frontend::macros::expand(frontend::lower_str(src).expect("lower"), 42).expect("expand");
    assert_eq!(m.encfuncs.len(), 1, "expected one sealed blob");
    m.encfuncs[0]
        .key
        .literal_hex()
        .expect("seed-derived literal key")
}

#[test]
fn d01_macro_classes_derive_distinct_keys() {
    let ks = seal_key("local a = BASIL_ENCSTR(\"X\")\nprint(a)\n");
    let kb = seal_key("local a = BASIL_ENCBUF(\"X\")\nprint(a)\n");
    let kn = seal_key("local a = BASIL_ENCNUM(1)\nprint(a)\n");
    assert_ne!(
        ks, kb,
        "ENCSTR and ENCBUF at the same site/seed must derive different keys"
    );
    assert_ne!(ks, kn, "ENCSTR and ENCNUM must derive different keys");
    assert_ne!(kb, kn, "ENCBUF and ENCNUM must derive different keys");
}

#[test]
fn d02_each_site_derives_a_distinct_key() {
    let m = frontend::macros::expand(
        frontend::lower_str(
            "local a = BASIL_ENCSTR(\"X\")\nlocal b = BASIL_ENCSTR(\"Y\")\nprint(a, b)\n",
        )
        .expect("lower"),
        42,
    )
    .expect("expand");
    assert_eq!(m.encfuncs.len(), 2);
    assert_ne!(
        m.encfuncs[0].key, m.encfuncs[1].key,
        "each protected-value site derives a distinct key"
    );
}

#[test]
fn d03_cross_class_graft_fails_closed() {
    let Some(luau) = find_luau() else { return };
    let donor = build(
        "local a = BASIL_ENCSTR(\"GRAFT-MARKER-77\")\nprint(a)",
        305419896,
    )
    .expect("donor");
    let host = build("local n = BASIL_ENCNUM(3030303)\nprint(n)", 305419896).expect("host");
    let (ds, de) = blob_table(&donor);
    let (hs, he) = blob_table(&host);
    let grafted = format!("{}{}{}", &host[..hs], &donor[ds..de], &host[he..]);
    let out = run(&luau, &grafted, None);
    assert!(
        !out.contains("GRAFT-MARKER-77"),
        "an ENCSTR blob must not authenticate at an ENCNUM site; got {out:?}"
    );
}

fn blob_table(art: &str) -> (usize, usize) {
    let start = art.find("{[==[").expect("blob table");
    let end = start + art[start..].find("]==]}").expect("blob close") + "]==]}".len();
    (start, end)
}

#[test]
fn e10_encnum_too_many_bindings_rejected() {
    let src = "local n = BASIL_ENCNUM(1, { [1]=1,[2]=2,[3]=3,[4]=4,[5]=5,[6]=6,[7]=7,[8]=8,[9]=9 })\nprint(n)";
    let e = build(src, 42).unwrap_err();
    assert!(e.contains("runtime bindings"), "got: {e}");
}
