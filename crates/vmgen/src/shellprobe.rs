use crate::rng::Rng;

const LINE_PLACEHOLDER: &str = "918273645";

pub(crate) struct Probe {
    pub decl: String,
    pub fold: String,
    pub set: String,
    pub sink: String,
}

pub(crate) fn emit(seed: u64, enabled: bool) -> Probe {
    if !enabled {
        return Probe {
            decl: String::new(),
            fold: String::new(),
            set: String::new(),
            sink: String::new(),
        };
    }
    let mut rng = Rng::new(seed ^ 0x_5348_454C_4C50_5242);
    let name = ["SPV", "SPQ", "SPW", "SPZ"][rng.below(4) as usize];
    let rot_fold = 1 + rng.below(15) as u32;
    let rot_mix = 1 + rng.below(15) as u32;
    let np_first = rng.below(2) == 0;
    let d = ["_dbg", "_dv", "_di"][rng.below(3) as usize];
    let f = ["_fi", "_fn", "_fx"][rng.below(3) as usize];

    let np_term = format!("bxor({f}np, 2)");
    let ln_term = format!("lrotate(bxor({f}ln, {LINE_PLACEHOLDER}), {rot_mix})");
    let mixed = if np_first {
        format!("bxor({np_term}, {ln_term})")
    } else {
        format!("bxor({ln_term}, {np_term})")
    };

    let set = format!(
        "{name} = (function()\n\
         \tlocal {d} = genv[\"debug\"]\n\
         \tif type({d}) ~= \"table\" then return 0 end\n\
         \tlocal {f} = {d}[\"info\"]\n\
         \tif type({f}) ~= \"function\" then return 0 end\n\
         \tlocal {f}ok, {f}np = pcall({f}, makeClosure, \"a\")\n\
         \tif not {f}ok or type({f}np) ~= \"number\" then return 0 end\n\
         \tlocal {f}ok2, {f}ln = pcall({f}, makeClosure, \"l\")\n\
         \tif not {f}ok2 or type({f}ln) ~= \"number\" then return 0 end\n\
         \treturn {mixed}\n\
         end)()"
    );

    let sink = String::new();

    Probe {
        decl: format!("local {name} = 0"),
        fold: format!("counter = bxor(counter, lrotate({name}, {rot_fold}))"),
        set,
        sink,
    }
}

pub fn resolve(shell: String) -> String {
    if !shell.contains(LINE_PLACEHOLDER) {
        return shell;
    }
    let Some(line) = factory_line(&shell) else {
        return shell;
    };
    let padded = format!("{line:0>9}");
    if padded.len() != LINE_PLACEHOLDER.len() {
        return shell;
    }
    shell.replacen(LINE_PLACEHOLDER, &padded, 1)
}

fn factory_line(shell: &str) -> Option<usize> {
    let bytes = shell.as_bytes();
    let mut at = 0usize;
    while let Some(rel) = shell[at..].find("return function(") {
        let open = at + rel + "return function(".len();
        let close = shell[open..].find(')')? + open;
        let params = &shell[open..close];
        let parts: Vec<&str> = params.split(',').map(str::trim).collect();
        if parts.len() == 2
            && parts
                .iter()
                .all(|p| !p.is_empty() && !p.contains("...") && !p.contains(' '))
        {
            let tail = &shell[close..];
            if let Some(c) = tail.find("return function(...)") {
                if tail[c..(c + 9000).min(tail.len())].contains("while true do") {
                    return Some(1 + bytes[..open].iter().filter(|&&b| b == b'\n').count());
                }
            }
        }
        at = open;
    }
    None
}
