#[cfg(unix)]
pub fn peak_rss_bytes() -> Option<u64> {
    extern "C" {
        fn getrusage(who: i32, usage: *mut i64) -> i32;
    }
    let mut buf = [0i64; 32];
    let ok = unsafe { getrusage(0, buf.as_mut_ptr()) == 0 };
    if !ok {
        return None;
    }
    let raw = buf[4].max(0) as u64;
    if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        Some(raw)
    } else {
        Some(raw.saturating_mul(1024))
    }
}

#[cfg(not(unix))]
pub fn peak_rss_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peak_rss_is_plausible_or_absent() {
        match peak_rss_bytes() {
            Some(b) => assert!(
                b >= 256 * 1024,
                "peak RSS {b} implausibly small for a running process"
            ),
            None => {}
        }
    }
}
