use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic event counter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn increment(&self) {
        self.add(1);
    }

    pub fn add(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Process-wide counters, written to the log every `stats_interval_sec`.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Connections that passed the whitelist, ban and limit checks.
    pub accepted: Counter,
    /// Dropped right after `accept()`: client not in `client_whitelist`.
    pub rejected_not_whitelisted: Counter,
    /// Dropped right after `accept()`: client address is banned.
    pub rejected_banned: Counter,
    /// Dropped right after `accept()`: `max_connections` reached.
    pub rejected_over_limit: Counter,
    pub auth_failures: Counter,
    /// Requests refused by the destination policy.
    pub denied_by_policy: Counter,
    /// Client → target bytes of closed connections.
    pub bytes_in: Counter,
    /// Target → client bytes of closed connections.
    pub bytes_out: Counter,
}
