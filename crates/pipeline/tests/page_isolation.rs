use pipeline::{
    Config, HotCallbackPolicy, Mode, PolyStream, SensitiveOpts, SurfaceVolume, TargetProfile,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

const ROOT_ENTRY_VARIANTS: [&str; 3] = [
    "return makeClosure(mainProto, {})()",
    "return (makeClosure(mainProto, {}))()",
    "return (function() return makeClosure(mainProto, {})() end)()",
];

fn tmp(p: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_{p}_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn require_luau() {
    if let Err(e) = std::process::Command::new("luau").arg("--help").output() {
        panic!("the `luau` interpreter is required for page-isolation tests ({e})");
    }
}

fn multipage_source(extra: &str) -> String {
    let mut s = String::from("local acc = 0\n");
    for i in 1..=300 {
        s.push_str(&format!("acc = acc + {i} * 3 - 1\n"));
    }
    s.push_str(extra);
    s.push_str("print(\"PROTECTED-RESULT\", acc)\n");
    s
}

fn cfg(seed: u64) -> Config {
    Config {
        seed,
        mode: Mode::Virtualize,
        flatten: false,
        opaque: false,
        junk: false,
        fuse: true,
        minify: false,
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
        property_key_rename: pipeline::PropKeyMode::Off,
        semantic_family: false,
        instruction_family: false,
        state_family: false,
        microir: false,
        semgroup: false,
        string_frag_mode: pipeline::StringFragMode::Full,
    }
}

fn build(src: &str, cfg: Config) -> String {
    let i = tmp("pi_in");
    let o = tmp("pi_out");
    std::fs::write(&i, src).unwrap();
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
    let p = tmp("pi_run");
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

fn probe(artifact: &str, body: &str) -> String {
    for anchor in ROOT_ENTRY_VARIANTS {
        if artifact.contains(anchor) {
            return run(&artifact.replacen(anchor, &format!("{body}\n{anchor}"), 1));
        }
    }
    panic!("no root-entry anchor found; the probe needs an unminified artifact");
}

fn field(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| l.split_whitespace().find(|t| t.starts_with(key)))
        .unwrap_or_else(|| panic!("`{key}` absent from probe output:\n{out}"))
        .trim_start_matches(key)
        .to_string()
}

const MUTATE: &str = r#"
do
	print("PROBE-INSTALLED")
	local p = mainProto
	local pstarts, pdg = p[16], p[15]
	if not pstarts then print("NOT-PAGED") return end
	print("PAGES=" .. tostring(#pstarts) .. " INSTRS=" .. tostring(p[13]))
	if not p[10] then p[10] = {} end

	decodeRange(p, pstarts[1], 1, PGSZ)
	ipatchRange(p, 1, PGSZ)
	ktokRange(p, 1, PGSZ)

	local function attempt(label, srcPage, dstPage, commitPage)
		local base = (dstPage - 1) * PGSZ
		local cnt = PGSZ
		if base + cnt > p[13] then cnt = p[13] - base end
		local ok = pcall(function() decodeRange(p, pstarts[srcPage], base + 1, cnt) end)
		if not ok then print(label .. "=decode-error") return end
		local ok2 = pcall(function()
			ipatchRange(p, base + 1, base + cnt)
			ktokRange(p, base + 1, base + cnt)
		end)
		if not ok2 then print(label .. "=patch-error") return end
		print(label .. "=" .. tostring(_vpgpage(p[1], base + 1, cnt, pdg[commitPage])))
	end

	attempt("CONTROL", 2, 2, 2)
	attempt("SWAP", 1, 2, 2)
	attempt("REPLAY", 1, 2, 1)
	attempt("RELOCATE", 3, 2, 2)
end
"#;

const SHAPE: &str = r#"
do
	print("PROBE-INSTALLED")
	local function walk(p, label)
		print(label .. " instrs=" .. tostring(p[13])
		      .. " paged=" .. tostring(p[16] ~= nil)
		      .. " pages=" .. tostring(p[16] and #p[16] or 0)
		      .. " commits=" .. tostring(p[15] and #p[15] or 0))
		for i = 1, #p[4] do walk(p[4][i], label .. ".child" .. tostring(i)) end
	end
	walk(mainProto, "ROOT")
	print("PGSZ=" .. tostring(PGSZ))
end
"#;

const MASKS: &str = r#"
do
	print("PROBE-INSTALLED")
	local p = mainProto
	print("OP_P0_I1=" .. tostring(opmask(0, 1)))
	print("OP_P0_I2=" .. tostring(opmask(0, 2)))
	print("OP_P0_I513=" .. tostring(opmask(0, 513)))
	print("OP_P1_I1=" .. tostring(opmask(1, 1)))
	print("OPD_P0_I1=" .. tostring(opmask2(0, 1, 0, 0)))
	print("OPD_P0_I513=" .. tostring(opmask2(0, 513, 0, 0)))
	print("OPD_P1_I1=" .. tostring(opmask2(1, 1, 0, 0)))
	print("PIDROOT=" .. tostring(p[5]))
	local collide = 0
	for i = 1, 512 do
		if opmask(0, i) == opmask(0, i + 512) then collide = collide + 1 end
	end
	print("PAGE1V2_EQUAL_MASKS=" .. tostring(collide) .. "/512")
end
"#;

#[test]
fn a_root_large_enough_for_three_pages_decodes_and_verifies_each_page() {
    require_luau();
    let art = build(&multipage_source(""), cfg(42));
    let out = probe(&art, MUTATE);

    assert!(
        out.contains("PROBE-INSTALLED"),
        "the probe must be installed: {out}"
    );
    assert!(
        !out.contains("NOT-PAGED"),
        "the fixture root must be paged: {out}"
    );
    let pages: usize = field(&out, "PAGES=").parse().unwrap();
    assert!(
        pages >= 3,
        "the fixture must span at least three pages, got {pages}: {out}"
    );
    assert_eq!(
        field(&out, "CONTROL="),
        "true",
        "untouched page 2 must verify: {out}"
    );
    assert!(
        run(&art).contains("PROTECTED-RESULT"),
        "the untouched artifact must still execute its protected result"
    );
}

#[test]
fn a_page_byte_swap_is_rejected_by_semantic_verification() {
    require_luau();
    let out = probe(&build(&multipage_source(""), cfg(42)), MUTATE);
    assert_eq!(
        field(&out, "CONTROL="),
        "true",
        "control must pass or this proves nothing: {out}"
    );
    assert_eq!(
        field(&out, "SWAP="),
        "false",
        "page 1 bytes decoded at page 2's indices must fail verification: {out}"
    );
}

#[test]
fn record_replay_is_rejected() {
    require_luau();
    let out = probe(&build(&multipage_source(""), cfg(42)), MUTATE);
    assert_eq!(field(&out, "CONTROL="), "true", "control must pass: {out}");
    assert_eq!(
        field(&out, "REPLAY="),
        "false",
        "page 1's bytes AND page 1's own commitment must still fail at page 2's indices -- if this \
         ever passes, the mask has become page-local and page replay is live: {out}"
    );
}

#[test]
fn metadata_relocation_of_a_third_page_is_rejected() {
    require_luau();
    let out = probe(&build(&multipage_source(""), cfg(42)), MUTATE);
    assert_eq!(field(&out, "CONTROL="), "true", "control must pass: {out}");
    assert_eq!(
        field(&out, "RELOCATE="),
        "false",
        "page 3 bytes decoded as page 2 must fail verification: {out}"
    );
}

#[test]
fn only_the_root_is_paged_and_children_use_whole_body_commitments() {
    require_luau();
    let src = multipage_source(
        "local function child(x)\n\tlocal s = 0\n\tfor i = 1, 5 do s = s + x * i end\n\treturn s\nend\nacc = acc + child(2)\n",
    );
    let out = probe(&build(&src, cfg(42)), SHAPE);

    assert!(out.contains("PROBE-INSTALLED"), "probe installed: {out}");
    let pgsz: usize = field(&out, "PGSZ=").parse().unwrap();

    let root = out
        .lines()
        .find(|l| l.starts_with("ROOT "))
        .expect("root line");
    let instrs: usize = field(root, "instrs=").parse().unwrap();
    let pages: usize = field(root, "pages=").parse().unwrap();
    assert_eq!(
        field(root, "paged="),
        "true",
        "the root must be paged: {out}"
    );
    assert_eq!(
        pages,
        instrs.div_ceil(pgsz),
        "root page count must match PAGE_SIZE: {out}"
    );
    assert_eq!(
        field(root, "commits="),
        pages.to_string(),
        "one semantic commitment per root page: {out}"
    );

    let child = out
        .lines()
        .find(|l| l.starts_with("ROOT.child"))
        .expect("a child proto");
    assert_eq!(
        field(child, "paged="),
        "false",
        "children must not be paged: {out}"
    );
    assert_eq!(
        field(child, "pages="),
        "0",
        "children have no page table: {out}"
    );
    assert_eq!(
        field(child, "commits="),
        "1",
        "a child carries exactly one whole-body commitment: {out}"
    );
}

#[test]
fn an_encfunc_body_is_unpaged_and_natives_never_enter_the_paging_path() {
    let key = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let src = format!(
        "if not BASIL_OBFUSCATED then BASIL_ENCFUNC = function(f) return f end end\n\
         local rk = _G.K\n\
         local sealed = BASIL_ENCFUNC(function(x) return x * 3 end, \"{key}\", rk)\n\
         local nat = BASIL_NO_VIRTUALIZE(function(y) return y + 1 end)\n\
         {}",
        multipage_source("")
    );
    let art = build(&src, cfg(42));

    let out = probe(&art, SHAPE);
    for line in out.lines().filter(|l| l.starts_with("ROOT")) {
        if line.starts_with("ROOT.") {
            assert_eq!(
                field(line, "paged="),
                "false",
                "no child of the root -- including an ENCFUNC wrapper -- may be paged: {out}"
            );
        }
    }
    assert!(
        art.contains("makeEncWrapper"),
        "the fixture must actually exercise the ENCFUNC path"
    );
    assert!(
        art.contains("proto[16] = nil") || art.contains("proto[16]=nil"),
        "the ENCFUNC materialisation path must clear the page table so a sealed body runs unpaged"
    );
}

#[test]
fn mask_derivation_separates_proto_and_global_instruction_index() {
    require_luau();
    let out = probe(&build(&multipage_source(""), cfg(42)), MASKS);

    assert_ne!(
        field(&out, "OP_P0_I1="),
        field(&out, "OP_P0_I2="),
        "adjacent instruction indices must not share opcode-mask inputs: {out}"
    );
    assert_ne!(
        field(&out, "OP_P0_I1="),
        field(&out, "OP_P1_I1="),
        "proto identity must affect the opcode mask: {out}"
    );
    assert_ne!(
        field(&out, "OPD_P0_I1="),
        field(&out, "OPD_P1_I1="),
        "proto identity must affect the operand mask: {out}"
    );

    let equal: usize = field(&out, "PAGE1V2_EQUAL_MASKS=")
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        equal < 128,
        "pages 1 and 2 must not restart at the same mask position: {equal}/512 indices produced an \
         identical opcode mask, which is what a page-local index would cause: {out}"
    );
}

#[test]
fn mask_material_differs_across_builds_for_the_same_proto_and_index() {
    require_luau();
    let mut op = Vec::new();
    let mut opd = Vec::new();
    for seed in [1u64, 42, 1337] {
        let out = probe(&build(&multipage_source(""), cfg(seed)), MASKS);
        assert_eq!(
            field(&out, "PIDROOT="),
            "0",
            "the root pid is stable across builds: {out}"
        );
        op.push(field(&out, "OP_P0_I1="));
        opd.push(field(&out, "OPD_P0_I1="));
    }
    assert!(
        op[0] != op[1] || op[1] != op[2],
        "opcode masks must differ across builds for the same (pid, index): {op:?}"
    );
    assert!(
        opd[0] != opd[1] || opd[1] != opd[2],
        "operand masks must differ across builds for the same tuple: {opd:?}"
    );
}

#[test]
fn no_page_index_term_or_page_key_exists_in_the_mask_derivation() {
    let vm = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../runtime/vm_template.luau"),
    )
    .expect("vm template readable");

    for seed in [1u64, 2, 7, 20260809] {
        let gen = pipeline::virtualize_with(
            "print(1)", seed, false, false, false, false, false, false, false,
        )
        .expect("virtualize");
        let opmask = gen
            .split("local function opmask(pid, i)")
            .nth(1)
            .and_then(|s| s.split("\nend").next())
            .expect("opmask present");
        let opmask2 = gen
            .split("local function opmask2(pid, i, slot, j)")
            .nth(1)
            .and_then(|s| s.split("\nend").next())
            .expect("opmask2 present");
        for (name, body) in [("opmask", opmask), ("opmask2", opmask2)] {
            assert!(
                !body.contains("PGSZ"),
                "{name} must not take a page-size or page-index term; paging is a range over the \
                 global instruction index, and introducing a page term would change the audited \
                 replay properties (seed {seed})"
            );
            assert!(
                !body.to_lowercase().contains("pagekey")
                    && !body.to_lowercase().contains("page_key"),
                "{name} must not consume a page key; none exists (seed {seed})"
            );
        }
    }
    assert!(
        vm.contains("local function ensurePages(proto, upto)"),
        "the lazy page path must still exist"
    );
    assert!(
        vm.contains("_vpgpage(proto[1], base + 1, count, proto[15][K])"),
        "each page must still be checked against its own semantic commitment on first touch"
    );
    assert!(
        vm.contains("dead = true"),
        "page verification failure must remain fail-closed"
    );
}
