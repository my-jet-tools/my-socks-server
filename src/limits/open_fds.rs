use std::fs;
use std::io;

/// Number of file descriptors open in this process: the entries of `/proc/self/fd` (Linux)
/// or `/dev/fd` (macOS, BSD). The descriptor used for the listing itself is not counted.
///
/// # Errors
/// Neither directory can be listed.
pub fn count_open_fds() -> io::Result<usize> {
    let entries = fs::read_dir("/proc/self/fd").or_else(|_| fs::read_dir("/dev/fd"))?;
    Ok(entries.count().saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_newly_opened_descriptors() {
        const OPENED: usize = 64;
        // Unit tests share the process; the slack absorbs descriptors that parallel tests
        // close meanwhile. The exact check lives in tests/fd_leak.rs (own process).
        const SLACK: usize = 16;
        let before = count_open_fds().unwrap();
        let files: Vec<fs::File> = (0..OPENED)
            .map(|_| fs::File::open("Cargo.toml").unwrap())
            .collect();
        let after = count_open_fds().unwrap();
        assert!(
            after + SLACK >= before + OPENED,
            "before={before} after={after}"
        );
        drop(files);
    }
}
