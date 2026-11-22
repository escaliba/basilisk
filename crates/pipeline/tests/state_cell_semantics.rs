use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn find_luau() -> Option<String> {
    Command::new("luau")
        .arg("--help")
        .output()
        .ok()
        .map(|_| "luau".to_string())
}

fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_cellsem_{}_{}.luau",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn run(bin: &str, path: &Path) -> String {
    let o = Command::new(bin).arg(path).output().expect("spawn luau");
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const DRIVER: &str = r#"
local function mkbtn(text) return { Text = text, Visible = false, Class = "TextButton" } end
local function mkother(text) return { Text = text, Visible = false, Class = "Frame" } end

local children = {}
local canvas = { CanvasPosition = 0, CanvasSize = 0 }
local layoutY = 42
local holder = ""

Match = function(name, str)
    str = str:gsub("%W", "%%%1")
    return name:lower():find(str:lower()) and true
end

local function setList(list)
    children = {}
    for _, t in ipairs(list) do children[#children + 1] = t end
end

local function report(tag)
    local vis = {}
    for _, v in ipairs(children) do
        if v.Visible then vis[#vis + 1] = v.Text end
    end
    print(tag, "top=" .. tostring(TOPCMD()), "vis=" .. table.concat(vis, "|"),
          "canvas=" .. tostring(canvas.CanvasSize), "holder=" .. holder)
end

--MODEL--

local function tabComplete()
    if TOPCMD() ~= nil then return "complete:" .. TOPCMD() end
    return "complete:none"
end

setList({ mkbtn("fly"), mkbtn("fling"), mkother("notabutton"), mkbtn("kill") })

IndexContents("zzzz", true, true); report("nomatch")
print("tab", tabComplete())

IndexContents("kill", true, true); report("one")
print("tab", tabComplete())

IndexContents("fl", true, true); report("multi-first")
print("tab", tabComplete())

IndexContents("fling", true, true); report("transition")
print("tab", tabComplete())

IndexContents("zzzz", true, true); report("reset")
print("tab", tabComplete())

IndexContents("fl", false, true); report("boolfalse")

IndexContents("fly\\", true, true); report("trailing-backslash")
IndexContents("!fly", true, true); report("bang-prefix")

local r = IndexContents("fly", true, true)
print("ret", tostring(r))
report("final")
"#;

const ORIGINAL: &str = r#"
local topCommand = nil
function TOPCMD() return topCommand end
IndexContents = function(str, bool, cmdbar, Ianim)
    canvas.CanvasPosition = 0
    local indexnum = 0
    topCommand = nil
    local chunks = {}
    if str:sub(#str, #str) == "\\" then str = "" end
    for w in string.gmatch(str, "[^\\]+") do chunks[#chunks + 1] = w end
    if #chunks > 0 then str = chunks[#chunks] end
    if str:sub(1, 1) == "!" then str = str:sub(2) end
    for i, v in next, children do
        if v.Class == "TextButton" then
            if bool then
                if Match(v.Text, str) then
                    indexnum = indexnum + 1
                    v.Visible = true
                    if topCommand == nil then topCommand = v.Text end
                else
                    v.Visible = false
                end
            else
                v.Visible = true
                if topCommand == nil then topCommand = v.Text end
            end
        end
    end
    canvas.CanvasSize = layoutY
    if indexnum == 0 or string.find(str, " ") then holder = "min" else holder = "max" end
end
"#;

const TRANSFORMED: &str = r#"
local cell = {}
function TOPCMD() return cell[1] end
local function helper(_cell, str, bool, cmdbar, Ianim)
    canvas.CanvasPosition = 0
    local indexnum = 0
    _cell[1] = nil
    local chunks = {}
    if str:sub(#str, #str) == "\\" then str = "" end
    for w in string.gmatch(str, "[^\\]+") do chunks[#chunks + 1] = w end
    if #chunks > 0 then str = chunks[#chunks] end
    if str:sub(1, 1) == "!" then str = str:sub(2) end
    for i, v in next, children do
        if v.Class == "TextButton" then
            if bool then
                if Match(v.Text, str) then
                    indexnum = indexnum + 1
                    v.Visible = true
                    if _cell[1] == nil then _cell[1] = v.Text end
                else
                    v.Visible = false
                end
            else
                v.Visible = true
                if _cell[1] == nil then _cell[1] = v.Text end
            end
        end
    end
    canvas.CanvasSize = layoutY
    if indexnum == 0 or string.find(str, " ") then holder = "min" else holder = "max" end
end
IndexContents = function(str, bool, cmdbar, Ianim)
    return helper(cell, str, bool, cmdbar, Ianim)
end
"#;

fn transcript(luau: &str, model: &str) -> String {
    let script = DRIVER.replace("--MODEL--", model);
    let p = tmp();
    std::fs::write(&p, script).unwrap();
    let out = run(luau, &p);
    let _ = std::fs::remove_file(p);
    out
}

#[test]
fn cell_transform_matches_the_scalar_source_across_the_filtering_matrix() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let original = transcript(&luau, ORIGINAL);
    let transformed = transcript(&luau, TRANSFORMED);

    assert!(
        !original.contains("attempt to"),
        "original model errored:\n{original}"
    );
    assert!(
        !transformed.contains("attempt to"),
        "transformed model errored:\n{transformed}"
    );
    assert_eq!(
        original, transformed,
        "the state-cell shape must be observationally identical to the scalar source"
    );

    for expect in [
        "nomatch\ttop=nil",
        "complete:none",
        "one\ttop=kill",
        "complete:kill",
        "multi-first\ttop=fly",
        "transition\ttop=fling",
        "reset\ttop=nil",
        "ret\tnil",
    ] {
        assert!(
            original.contains(expect),
            "missing `{expect}` in:\n{original}"
        );
    }
}

#[test]
fn writes_are_visible_to_the_reader_before_the_helper_returns() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let probe = r#"
local cell = {}
local seen = {}
local function reader() seen[#seen + 1] = tostring(cell[1]) end
local function helper(_cell, list)
    _cell[1] = nil
    reader()
    for _, v in ipairs(list) do
        if _cell[1] == nil then _cell[1] = v end
        reader()
    end
end
IndexContents = function(list) return helper(cell, list) end
IndexContents({ "a", "b" })
print(table.concat(seen, ","))
print("after=" .. tostring(cell[1]))
"#;
    let p = tmp();
    std::fs::write(&p, probe).unwrap();
    let out = run(&luau, &p);
    let _ = std::fs::remove_file(p);
    assert!(
        out.contains("nil,a,a"),
        "the reader must observe writes during the scan, not only after return:\n{out}"
    );
    assert!(
        out.contains("after=a"),
        "the value persists past return:\n{out}"
    );
}

#[test]
fn virtualized_and_native_match_agree_on_the_filtering_inputs() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let probe = r#"
local function matcher(name, str)
    str = str:gsub("%W", "%%%1")
    return name:lower():find(str:lower()) and true
end
local cases = {
    {"fly","fly"},{"fly","f"},{"fly","FLY"},{"FLY","fly"},{"fly","0000"},
    {"kill all","kill"},{"kill all"," "},{"percent%sign","%"},{"dots.and-dashes","."},
    {"brackets[1]","["},{"plus+star*","+"},{"question?mark","?"},{"paren(open","("},
    {"",""},{"nonmatching","zzzzzzzz"},{"MiXeD CaSe","mixed"},
}
local acc = {}
for _, c in ipairs(cases) do acc[#acc + 1] = tostring(matcher(c[1], c[2])) end
print(table.concat(acc, ","))
"#;
    let p = tmp();
    std::fs::write(&p, probe).unwrap();
    let a = run(&luau, &p);
    let b = run(&luau, &p);
    let _ = std::fs::remove_file(p);
    assert_eq!(a, b, "the matcher is deterministic");
    assert!(!a.contains("attempt to"), "matcher errored:\n{a}");
    assert!(a.contains("true"), "some inputs must match:\n{a}");
}
