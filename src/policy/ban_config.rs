use std::time::Duration;

/// Brute-force protection: `max_failures` failed authentications within `window` ban the
/// client address for `duration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanConfig {
    /// 0 disables banning.
    pub max_failures: u32,
    pub window: Duration,
    pub duration: Duration,
    /// Upper bound of tracked addresses: keeps memory bounded under a distributed attack.
    pub max_tracked: usize,
}
