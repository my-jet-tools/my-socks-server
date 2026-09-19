use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// Last moment any byte moved through a relayed connection, in either direction.
///
/// Both copy directions share one clock: a connection is idle only when *neither* direction
/// made progress, so a long download with a silent upload direction is not idle.
#[derive(Debug)]
pub struct ActivityClock {
    origin: Instant,
    last_activity_ms: AtomicU64,
}

impl ActivityClock {
    /// Starts counting idle time from now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    /// Records progress.
    pub fn touch(&self) {
        self.last_activity_ms
            .store(as_millis(self.origin.elapsed()), Ordering::Relaxed);
    }

    #[must_use]
    pub fn idle_for(&self) -> Duration {
        let last_activity = Duration::from_millis(self.last_activity_ms.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(last_activity)
    }

    /// Time left until the connection has been idle for `idle_timeout`; zero once it has.
    #[must_use]
    pub fn remaining(&self, idle_timeout: Duration) -> Duration {
        idle_timeout.saturating_sub(self.idle_for())
    }
}

impl Default for ActivityClock {
    fn default() -> Self {
        Self::new()
    }
}

fn as_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn tracks_idle_time() {
        let clock = ActivityClock::new();
        let idle = Duration::from_secs(10);
        assert_eq!(clock.remaining(idle), idle);

        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(clock.idle_for(), Duration::from_secs(4));
        assert_eq!(clock.remaining(idle), Duration::from_secs(6));

        clock.touch();
        assert_eq!(clock.remaining(idle), idle);

        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(clock.remaining(idle), Duration::ZERO);
    }
}
