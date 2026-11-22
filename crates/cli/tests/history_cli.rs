use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basilisk");

fn scratch(tag: &str, ext: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "basilisk_hist_it_{}_{}_{}.{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        ext
    ))
}

fn run_with_timeout(mut child: std::process::Child, secs: u64) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn direct_cli_run_does_not_write_history() {
    let input = scratch("direct_in", "luau");
    let output = scratch("direct_out", "luau");
    let hist = scratch("direct_hist", "json");
    std::fs::write(&input, "local x = 1\nreturn x\n").unwrap();

    let status = Command::new(BIN)
        .args([
            "--flatten",
            "--opaque",
            "--fuse",
            "--target-profile",
            "executor",
        ])
        .arg(&input)
        .arg(&output)
        .env("BASILISK_HISTORY_FILE", &hist)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = run_with_timeout(status, 60).expect("direct CLI must not hang");

    assert!(status.success(), "direct CLI obfuscation should succeed");
    assert!(
        output.metadata().map(|m| m.len() > 0).unwrap_or(false),
        "direct CLI produced output"
    );
    assert!(
        !hist.exists(),
        "direct (non-wizard) CLI must not write wizard history"
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn non_tty_no_args_exits_without_history_or_hang() {
    let hist = scratch("noarg_hist", "json");
    let child = Command::new(BIN)
        .env("BASILISK_HISTORY_FILE", &hist)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = run_with_timeout(child, 30).expect("no-arg non-TTY must not wait for input");
    assert!(
        !status.success(),
        "no-arg non-TTY should exit non-zero (usage), not run"
    );
    assert!(!hist.exists(), "no-arg non-TTY writes no history");
}
