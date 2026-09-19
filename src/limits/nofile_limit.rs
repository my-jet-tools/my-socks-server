use std::io;

use rlimit::Resource;

/// `RLIMIT_NOFILE` of the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofileLimit {
    pub soft: u64,
    pub hard: u64,
}

/// Raises the soft `RLIMIT_NOFILE` to the hard limit (on macOS also capped by
/// `kern.maxfilesperproc`) and returns the resulting limits. Never lowers the soft limit.
///
/// # Errors
/// `getrlimit`/`setrlimit` failure.
pub fn raise_nofile_limit() -> io::Result<NofileLimit> {
    let before = current_nofile_limit()?;
    if before.soft < before.hard {
        let raised = rlimit::increase_nofile_limit(u64::MAX)?;
        // On macOS the target is capped by kern.maxfilesperproc, which can be below a soft
        // limit the process already had: put that one back.
        if raised < before.soft {
            Resource::NOFILE.set(before.soft, before.hard)?;
        }
    }
    current_nofile_limit()
}

/// # Errors
/// `getrlimit` failure.
pub fn current_nofile_limit() -> io::Result<NofileLimit> {
    let (soft, hard) = Resource::NOFILE.get()?;
    Ok(NofileLimit { soft, hard })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raises_soft_limit_to_hard_limit() {
        let before = current_nofile_limit().unwrap();
        let after = raise_nofile_limit().unwrap();
        assert!(after.soft >= before.soft);
        assert!(after.soft <= after.hard);
    }
}
