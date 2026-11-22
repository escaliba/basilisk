use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, PartialEq)]
struct Run {
    stdout: String,
    code: Option<i32>,
}

fn run_luau(bin: &str, path: &Path) -> Run {
    let output = Command::new(bin)
        .arg(path)
        .output()
        .expect("failed to spawn luau");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        code: output.status.code(),
    }
}

fn find_luau() -> Option<String> {
    if let Ok(bin) = std::env::var("LUAU_BIN") {
        return Some(bin);
    }
    match Command::new("luau").arg("--help").output() {
        Ok(_) => Some("luau".to_string()),
        Err(_) => None,
    }
}

fn corpus_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading corpus dir {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "luau"))
        .collect();
    files.sort();
    files
}

#[test]
fn corpus_roundtrips() {
    let files = corpus_files();
    assert!(!files.is_empty(), "no corpus files found");
    let luau = find_luau();

    let mut failures: Vec<String> = Vec::new();
    println!("\n== Basilisk round-trip corpus ==");

    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let source = std::fs::read_to_string(file).unwrap();

        let ir1 = match frontend::lower_str(&source) {
            Ok(module) => module,
            Err(e) => {
                println!("  {name:28} lower:FAIL");
                failures.push(format!("[{name}] lowering source failed: {e}"));
                continue;
            }
        };
        let regenerated = ir::emit(&ir1);
        let ir2 = match frontend::lower_str(&regenerated) {
            Ok(module) => module,
            Err(e) => {
                println!("  {name:28} relower:FAIL");
                failures.push(format!(
                    "[{name}] re-lowering regenerated source failed: {e}\n--- regenerated ---\n{regenerated}"
                ));
                continue;
            }
        };
        let structural = ir1 == ir2;
        if !structural {
            failures.push(format!(
                "[{name}] structural mismatch (emit/lower not stable)\n--- regenerated ---\n{regenerated}\n--- ir(original) ---\n{ir1:#?}\n--- ir(regenerated) ---\n{ir2:#?}"
            ));
        }

        let behavioral = luau.as_ref().map(|bin| {
            let original = run_luau(bin, file);
            let tmp = std::env::temp_dir().join(format!("basilisk_rt_{name}"));
            std::fs::write(&tmp, &regenerated).unwrap();
            let regen = run_luau(bin, &tmp);
            if original != regen {
                failures.push(format!(
                    "[{name}] behavioral mismatch\n--- original ---\n{original:?}\n--- regenerated ---\n{regen:?}\n--- regenerated source ---\n{regenerated}"
                ));
            }
            original == regen
        });

        let s_mark = if structural { "ok" } else { "FAIL" };
        let b_mark = match behavioral {
            Some(true) => "ok",
            Some(false) => "FAIL",
            None => "skip",
        };
        println!("  {name:28} structural:{s_mark:5} behavioral:{b_mark}");
    }

    if luau.is_none() {
        println!("  (luau not found; behavioral layer skipped — set LUAU_BIN to enable)");
    }
    println!(
        "== {} script(s), {} failure(s) ==\n",
        files.len(),
        failures.len()
    );

    assert!(
        failures.is_empty(),
        "round-trip failures:\n\n{}",
        failures.join("\n\n")
    );
}
