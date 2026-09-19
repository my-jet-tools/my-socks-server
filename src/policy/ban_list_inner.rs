use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::{BanConfig, BanListStats, FailureVerdict, canonical_ip};

/// While the table is full, a full purge runs at most this often.
const FULL_TABLE_PURGE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct BanEntry {
    /// Failure moments inside the window, oldest first.
    failures: VecDeque<Instant>,
    banned_at: Option<Instant>,
}

/// Ban bookkeeping; time is passed in so the logic is testable without sleeping.
pub(super) struct BanListInner {
    config: BanConfig,
    // std `HashMap` (SipHash, random key) on purpose: the keys are chosen by untrusted
    // clients, so a hash-flooding resistant hasher is required here.
    entries: HashMap<IpAddr, BanEntry>,
    last_full_purge: Option<Instant>,
}

impl BanListInner {
    pub(super) fn new(config: BanConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            last_full_purge: None,
        }
    }

    pub(super) fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        self.entries
            .get(&ban_key(ip))
            .is_some_and(|entry| self.ban_active(entry, now))
    }

    pub(super) fn record_failure(&mut self, ip: IpAddr, now: Instant) -> FailureVerdict {
        if self.config.max_failures == 0 {
            return FailureVerdict::Disabled;
        }
        let key = ban_key(ip);
        if !self.entries.contains_key(&key) && !self.make_room(now) {
            return FailureVerdict::Untracked;
        }
        let config = self.config;
        let entry = self.entries.entry(key).or_default();
        if entry
            .banned_at
            .is_some_and(|at| now.saturating_duration_since(at) < config.duration)
        {
            return FailureVerdict::Banned;
        }
        entry.banned_at = None;
        entry
            .failures
            .retain(|at| now.saturating_duration_since(*at) < config.window);
        entry.failures.push_back(now);
        let threshold = usize::try_from(config.max_failures).unwrap_or(usize::MAX);
        if entry.failures.len() >= threshold {
            entry.failures.clear();
            entry.banned_at = Some(now);
            FailureVerdict::Banned
        } else {
            FailureVerdict::Counted {
                failures: entry.failures.len(),
            }
        }
    }

    pub(super) fn purge(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        let config = self.config;
        self.entries.retain(|_, entry| {
            let banned = entry
                .banned_at
                .is_some_and(|at| now.saturating_duration_since(at) < config.duration);
            let recent_failures = entry
                .failures
                .iter()
                .any(|at| now.saturating_duration_since(*at) < config.window);
            banned || recent_failures
        });
        before.saturating_sub(self.entries.len())
    }

    pub(super) fn stats(&self, now: Instant) -> BanListStats {
        BanListStats {
            tracked: self.entries.len(),
            banned: self
                .entries
                .values()
                .filter(|entry| self.ban_active(entry, now))
                .count(),
        }
    }

    fn ban_active(&self, entry: &BanEntry, now: Instant) -> bool {
        entry
            .banned_at
            .is_some_and(|at| now.saturating_duration_since(at) < self.config.duration)
    }

    /// Whether a new address may be tracked; purges (rate limited) when the table is full.
    fn make_room(&mut self, now: Instant) -> bool {
        if self.entries.len() < self.config.max_tracked {
            return true;
        }
        let purge_due = self
            .last_full_purge
            .is_none_or(|at| now.saturating_duration_since(at) >= FULL_TABLE_PURGE_INTERVAL);
        if purge_due {
            self.last_full_purge = Some(now);
            self.purge(now);
        }
        self.entries.len() < self.config.max_tracked
    }
}

/// IPv6 clients are tracked per /64: one host usually controls a whole /64.
fn ban_key(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 @ IpAddr::V4(_) => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(600);
    const BAN: Duration = Duration::from_secs(3600);

    fn config(max_failures: u32, max_tracked: usize) -> BanConfig {
        BanConfig {
            max_failures,
            window: WINDOW,
            duration: BAN,
            max_tracked,
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn secs(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    #[test]
    fn bans_after_max_failures_within_window() {
        let mut bans = BanListInner::new(config(3, 100));
        let client = ip("203.0.113.5");
        let start = Instant::now();
        assert_eq!(
            bans.record_failure(client, start),
            FailureVerdict::Counted { failures: 1 }
        );
        assert_eq!(
            bans.record_failure(client, start + secs(10)),
            FailureVerdict::Counted { failures: 2 }
        );
        assert!(!bans.is_banned(client, start + secs(10)));
        assert_eq!(
            bans.record_failure(client, start + secs(20)),
            FailureVerdict::Banned
        );
        assert!(bans.is_banned(client, start + secs(20)));
        assert!(bans.is_banned(client, start + secs(19) + BAN));
        assert!(!bans.is_banned(client, start + secs(20) + BAN));
        assert!(!bans.is_banned(ip("203.0.113.6"), start + secs(20)));
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let mut bans = BanListInner::new(config(3, 100));
        let client = ip("203.0.113.5");
        let start = Instant::now();
        bans.record_failure(client, start);
        bans.record_failure(client, start + secs(1));
        assert_eq!(
            bans.record_failure(client, start + WINDOW + secs(1)),
            FailureVerdict::Counted { failures: 1 }
        );
        assert!(!bans.is_banned(client, start + WINDOW + secs(1)));
    }

    #[test]
    fn counting_restarts_after_ban_expires() {
        let mut bans = BanListInner::new(config(2, 100));
        let client = ip("203.0.113.5");
        let start = Instant::now();
        bans.record_failure(client, start);
        assert_eq!(bans.record_failure(client, start), FailureVerdict::Banned);
        assert_eq!(
            bans.record_failure(client, start + secs(5)),
            FailureVerdict::Banned,
            "still banned"
        );
        let after = start + BAN + secs(1);
        assert!(!bans.is_banned(client, after));
        assert_eq!(
            bans.record_failure(client, after),
            FailureVerdict::Counted { failures: 1 }
        );
    }

    #[test]
    fn ipv6_is_tracked_per_slash_64_and_mapped_ipv4_as_ipv4() {
        let mut bans = BanListInner::new(config(2, 100));
        let now = Instant::now();
        bans.record_failure(ip("2001:db8:1:2::1"), now);
        bans.record_failure(ip("2001:db8:1:2:ffff::9"), now);
        assert!(bans.is_banned(ip("2001:db8:1:2::77"), now));
        assert!(!bans.is_banned(ip("2001:db8:1:3::1"), now));

        bans.record_failure(ip("::ffff:198.51.100.1"), now);
        bans.record_failure(ip("198.51.100.1"), now);
        assert!(bans.is_banned(ip("198.51.100.1"), now));
    }

    #[test]
    fn purge_drops_stale_entries_only() {
        let mut bans = BanListInner::new(config(2, 100));
        let start = Instant::now();
        bans.record_failure(ip("192.0.2.1"), start);
        bans.record_failure(ip("192.0.2.2"), start);
        bans.record_failure(ip("192.0.2.2"), start);
        assert_eq!(
            bans.stats(start),
            BanListStats {
                tracked: 2,
                banned: 1
            }
        );

        let later = start + WINDOW + secs(1);
        assert_eq!(bans.purge(later), 1, "stale counter of .1 is dropped");
        assert_eq!(
            bans.stats(later),
            BanListStats {
                tracked: 1,
                banned: 1
            }
        );
        assert_eq!(
            bans.purge(start + BAN + secs(1)),
            1,
            "expired ban is dropped"
        );
        assert_eq!(bans.stats(start + BAN + secs(1)), BanListStats::default());
    }

    #[test]
    fn table_size_is_bounded() {
        let mut bans = BanListInner::new(config(5, 2));
        let now = Instant::now();
        bans.record_failure(ip("192.0.2.1"), now);
        bans.record_failure(ip("192.0.2.2"), now);
        assert_eq!(
            bans.record_failure(ip("192.0.2.3"), now),
            FailureVerdict::Untracked
        );
        assert_eq!(
            bans.record_failure(ip("192.0.2.1"), now),
            FailureVerdict::Counted { failures: 2 },
            "known addresses are still counted"
        );
        let later = now + WINDOW + secs(1);
        assert_eq!(
            bans.record_failure(ip("192.0.2.3"), later),
            FailureVerdict::Counted { failures: 1 },
            "room is made by purging stale entries"
        );
    }

    #[test]
    fn zero_max_failures_disables_banning() {
        let mut bans = BanListInner::new(config(0, 100));
        let now = Instant::now();
        for _ in 0..10 {
            assert_eq!(
                bans.record_failure(ip("192.0.2.1"), now),
                FailureVerdict::Disabled
            );
        }
        assert!(!bans.is_banned(ip("192.0.2.1"), now));
    }
}
