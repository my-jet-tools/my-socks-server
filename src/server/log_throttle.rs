use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Lets a repetitive log line through at most once per period (e.g. "connection limit
/// reached" during a flood).
#[derive(Debug)]
pub struct LogThrottle {
    origin: Instant,
    period_ms: u64,
    next_allowed_ms: AtomicU64,
}

impl LogThrottle {
    #[must_use]
    pub fn new(period: Duration) -> Self {
        Self {
            origin: Instant::now(),
            period_ms: u64::try_from(period.as_millis()).unwrap_or(u64::MAX),
            next_allowed_ms: AtomicU64::new(0),
        }
    }

    /// True when the caller should log now.
    #[must_use]
    pub fn allow(&self) -> bool {
        let now_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let next_allowed = self.next_allowed_ms.load(Ordering::Relaxed);
        now_ms >= next_allowed
            && self
                .next_allowed_ms
                .compare_exchange(
                    next_allowed,
                    now_ms.saturating_add(self.period_ms),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_once_per_period() {
        let throttle = LogThrottle::new(Duration::from_secs(3600));
        assert!(throttle.allow());
        assert!(!throttle.allow());
        assert!(!throttle.allow());
    }
}
