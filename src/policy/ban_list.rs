use std::net::IpAddr;
use std::time::Instant;

use parking_lot::Mutex;

use super::BanConfig;
use super::ban_list_inner::BanListInner;

/// Outcome of recording a failed authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureVerdict {
    /// Banning is disabled (`ban_max_failures: 0`).
    Disabled,
    /// Counted; `failures` is the number of failures inside the current window.
    Counted { failures: usize },
    /// The address is banned now (this failure triggered the ban, or it was already banned).
    Banned,
    /// The table is full; this address is not tracked (see [`BanConfig::max_tracked`]).
    Untracked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BanListStats {
    /// Addresses with recent failures or an active ban.
    pub tracked: usize,
    /// Addresses currently banned.
    pub banned: usize,
}

/// In-memory ban list shared by all connections. IPv6 clients are tracked per `/64`.
pub struct BanList {
    inner: Mutex<BanListInner>,
}

impl BanList {
    #[must_use]
    pub fn new(config: BanConfig) -> Self {
        Self {
            inner: Mutex::new(BanListInner::new(config)),
        }
    }

    #[must_use]
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.inner.lock().is_banned(ip, now)
    }

    pub fn record_failure(&self, ip: IpAddr) -> FailureVerdict {
        let now = Instant::now();
        self.inner.lock().record_failure(ip, now)
    }

    /// Forgets expired bans and stale failure counters; returns how many addresses were dropped.
    pub fn purge(&self) -> usize {
        let now = Instant::now();
        self.inner.lock().purge(now)
    }

    #[must_use]
    pub fn stats(&self) -> BanListStats {
        let now = Instant::now();
        self.inner.lock().stats(now)
    }
}
