use frontend::lookup_native::extract_at;

const FIXTURE_ID: u32 = 230;

const SCAN_STABLE_ID: u32 = 243;
const CALLER_STABLE_ID: u32 = 246;
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
        "basilisk_lookupsem_{}_{}.luau",
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

const HARNESS: &str = r#"
task = { spawn = function(f) f() end }
function wait(t) end

local log = {}
local function say(s) log[#log + 1] = s end

Owner = "me"
cmdHistory = {}
lastCmds = {}
cargs = nil
Cmdbar = { Text = "", IsFocused = function(self) return false end }

local refreshes = 0
function IndexContents(str, bool, cmdbar, Ianim)
    refreshes = refreshes + 1
end

cmds = {
    { ID = "first", NAME = "firstcmd", ALIAS = {}, FUNC = function(a, s) say("exec first") end },
    { ID = "fly", NAME = "fly", ALIAS = { "f", "flight" }, FUNC = function(a, s) say("exec fly " .. tostring(a[1])) end },
    { ID = "kill", NAME = "kill", ALIAS = {}, FUNC = function(a, s) say("exec kill") end },
    { ID = "goto", NAME = "GoTo", ALIAS = { "to", "tp", "TELE" }, FUNC = function(a, s) say("exec goto") end },
    { ID = "last", NAME = "lastcmd", ALIAS = { "lc" }, FUNC = function(a, s) say("exec last") end },
}

customAlias = {
    ["mycmd"] = { ID = "custom", NAME = "custom", ALIAS = {}, FUNC = function(a, s) say("exec custom") end },
}

function FindInTable(tbl, val)
    if tbl == nil then return false end
    for _, v in pairs(tbl) do
        if v == val then return true end
    end
    return false
end

findCmd = function(cmd_name)
    for i, v in pairs(cmds) do
        if v.NAME:lower() == cmd_name:lower() or FindInTable(v.ALIAS, cmd_name:lower()) then
            return v
        end
    end
    return customAlias[cmd_name:lower()]
end

function splitString(str, delim)
    local broken = {}
    if delim == nil then delim = "," end
    for w in string.gmatch(str, "[^" .. delim .. "]+") do
        table.insert(broken, w)
    end
    return broken
end

function execCmd(cmdStr, speaker, store)
    cmdStr = cmdStr:gsub("%s+$", "")
    task.spawn(function()
        local rawCmdStr = cmdStr
        local args = splitString(cmdStr, " ")
        local cmdName = args[1]
        local cmd = findCmd(cmdName)
        if cmd then
            table.remove(args, 1)
            cargs = args
            if store then
                if speaker == Owner then
                    table.insert(cmdHistory, 1, rawCmdStr)
                end
                if #cmdHistory > 30 then table.remove(cmdHistory) end
                lastCmds[cmdName] = cmdStr
            end
            cmd.FUNC(args, speaker)
        end
    end)
end

FocusLost = function(enterpressed)
    if enterpressed then
        execCmd(Cmdbar.Text, Owner, true)
    end
    wait()
    if not Cmdbar:IsFocused() then
        Cmdbar.Text = ""
        IndexContents('', true, false, true)
    end
end

local function lookup(tag, name)
    local sel = findCmd(name)
    say("lookup " .. tag .. " " .. tostring(name) .. " -> " .. tostring(sel and sel.ID))
end

lookup("primary", "fly")
lookup("alias", "f")
lookup("alias2", "flight")
lookup("invalid", "0000")
lookup("first", "firstcmd")
lookup("last", "lastcmd")
lookup("last-alias", "lc")
lookup("case-upper", "FLY")
lookup("case-mixed", "fLy")
lookup("case-name-mixed", "goto")
lookup("case-name-exact", "GoTo")
lookup("multi-alias-1", "to")
lookup("multi-alias-2", "tp")
lookup("stored-upper-alias", "tele")
lookup("stored-upper-alias-exact", "TELE")
lookup("query-case-alias", "TP")
lookup("empty-alias", "kill")
lookup("custom-fallback", "mycmd")
lookup("custom-fallback-case", "MyCmd")
lookup("empty-string", "")

say("helper nil -> " .. tostring(FindInTable(nil, "x")))
say("helper empty -> " .. tostring(FindInTable({}, "x")))
say("helper hit -> " .. tostring(FindInTable({ "a", "b" }, "b")))
say("helper miss -> " .. tostring(FindInTable({ "a", "b" }, "z")))

local function enter(text)
    Cmdbar.Text = text
    FocusLost(true)
    say("enter " .. text
        .. " history=" .. table.concat(cmdHistory, "|"):gsub(" ", "_")
        .. " last=" .. tostring(lastCmds["fly"]):gsub(" ", "_")
        .. " cargs=" .. table.concat(cargs or {}, ",")
        .. " refreshes=" .. tostring(refreshes))
end

enter("fly 1")
enter("f 2")
enter("0000")
enter("TP")
enter("mycmd")
enter("lastcmd")

for i, s in ipairs(log) do print(s) end
"#;

fn lower(src: &'static str) -> ir::Module {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || frontend::lower_str(src).unwrap())
        .expect("spawn parser thread")
        .join()
        .expect("parser thread")
}

fn retag(m: &mut ir::Module) {
    for s in &mut m.block.stmts {
        match s {
            ir::Stmt::Function { name, body } if name.path == vec!["FindInTable".to_string()] => {
                body.stable_id = Some(FIXTURE_ID)
            }
            ir::Stmt::Function { name, body } if name.path == vec!["execCmd".to_string()] => {
                for inner in &mut body.block.stmts {
                    if let ir::Stmt::Call(ir::Expr::Call { args, .. }) = inner {
                        for a in args.iter_mut() {
                            if let ir::Expr::Function(f) = a {
                                f.stable_id = Some(CALLER_STABLE_ID);
                            }
                        }
                    }
                }
            }
            ir::Stmt::Assign { targets, exprs } => {
                for (t, e) in targets.iter().zip(exprs.iter_mut()) {
                    if matches!(t, ir::Expr::Name(n) if n == "findCmd") {
                        if let ir::Expr::Function(f) = e {
                            f.stable_id = Some(SCAN_STABLE_ID);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn model(native: bool) -> String {
    let mut m = lower(HARNESS);
    retag(&mut m);
    if native {
        extract_at(&mut m, FIXTURE_ID).expect("the promoted pass applies to the harness");
    }
    let mut prelude = String::new();
    for (i, n) in m.natives.iter().enumerate() {
        prelude.push_str(&format!("local __NATIVE_{i} = {}\n", ir::emit_func(n)));
    }
    for s in &mut m.block.stmts {
        if let ir::Stmt::Assign { exprs, .. } = s {
            for e in exprs.iter_mut() {
                if let ir::Expr::NativeRef(i) = e {
                    *e = ir::Expr::Name(format!("__NATIVE_{i}"));
                }
            }
        }
    }
    m.natives.clear();
    format!("{prelude}{}", ir::emit(&m))
}

fn transcript(luau: &str, native: bool) -> String {
    let p = tmp();
    std::fs::write(&p, model(native)).unwrap();
    let out = run(luau, &p);
    let _ = std::fs::remove_file(p);
    assert!(
        !out.contains("attempt to"),
        "the model raised a runtime error:\n{out}"
    );
    assert!(
        !out.contains("stack traceback"),
        "the model raised a runtime error:\n{out}"
    );
    out
}

#[test]
fn the_untreated_lookup_path_resolves_every_documented_case() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let base = transcript(&luau, false);

    for expect in [
        "lookup primary fly -> fly",
        "lookup alias f -> fly",
        "lookup alias2 flight -> fly",
        "lookup invalid 0000 -> nil",
        "lookup first firstcmd -> first",
        "lookup last lastcmd -> last",
        "lookup last-alias lc -> last",
        "lookup case-upper FLY -> fly",
        "lookup case-mixed fLy -> fly",
        "lookup case-name-mixed goto -> goto",
        "lookup case-name-exact GoTo -> goto",
        "lookup multi-alias-1 to -> goto",
        "lookup multi-alias-2 tp -> goto",
        "lookup stored-upper-alias tele -> nil",
        "lookup stored-upper-alias-exact TELE -> nil",
        "lookup query-case-alias TP -> goto",
        "lookup empty-alias kill -> kill",
        "lookup custom-fallback mycmd -> custom",
        "lookup custom-fallback-case MyCmd -> custom",
        "helper nil -> false",
        "helper empty -> false",
        "helper hit -> true",
        "helper miss -> false",
        "exec fly 1",
        "exec goto",
        "exec custom",
        "exec last",
    ] {
        assert!(base.contains(expect), "missing `{expect}` in:\n{base}");
    }

    assert_eq!(
        base.matches("exec ").count(),
        5,
        "the invalid command executes nothing:\n{base}"
    );
    assert!(
        base.contains("enter 0000 history=f_2|fly_1"),
        "0000 records no history:\n{base}"
    );
    assert!(
        base.contains("refreshes=6"),
        "every Enter still refreshes:\n{base}"
    );
}

#[test]
fn the_native_helper_changes_nothing_observable() {
    let Some(luau) = find_luau() else {
        eprintln!("luau unavailable; skipping");
        return;
    };
    let base = transcript(&luau, false);
    let native = transcript(&luau, true);
    assert_eq!(
        base, native,
        "lookup results, selected command objects, history, argument publication, command \
         execution and the refresh count must all be unchanged by the native helper"
    );
    assert!(
        !native.contains("BASIL_"),
        "the promoted pass emits no admission:\n{native}"
    );
}

#[test]
fn the_native_body_is_the_real_helper_and_the_scan_stays_virtualized() {
    let mut m = lower(HARNESS);
    retag(&mut m);
    let r = extract_at(&mut m, FIXTURE_ID).unwrap();
    assert_eq!(m.natives.len(), 1, "exactly one body is extracted");
    assert_eq!(r.extracted[0].stable_id, FIXTURE_ID);

    let body = ir::emit_func(&m.natives[0]);
    assert!(
        body.contains("pairs(tbl)"),
        "the helper body is the real one: {body}"
    );
    assert!(
        body.contains("return false"),
        "the nil guard travels with it: {body}"
    );
    assert!(
        !body.contains("BASIL_"),
        "no admission inside the native body: {body}"
    );

    assert!(
        m.block
            .stmts
            .iter()
            .any(|s| matches!(s, ir::Stmt::Assign { targets, exprs }
            if matches!(targets.first(), Some(ir::Expr::Name(n)) if n == "findCmd")
                && matches!(exprs.first(), Some(ir::Expr::Function(_))))),
        "findCmd stays a virtualized function value"
    );
    assert!(
        m.natives
            .iter()
            .all(|n| n.stable_id != Some(SCAN_STABLE_ID) && n.stable_id != Some(CALLER_STABLE_ID)),
        "neither the scan nor the spawned exec body is ever made native"
    );
}
