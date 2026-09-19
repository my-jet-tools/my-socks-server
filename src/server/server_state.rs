use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::ServerStats;
use crate::config::ServerConfig;
use crate::policy::BanList;

/// Everything connection tasks share, behind one `Arc`.
pub struct ServerState {
    pub config: ServerConfig,
    pub ban_list: BanList,
    pub stats: ServerStats,
    /// One permit per open client connection, `max_connections` in total.
    pub connection_permits: Arc<Semaphore>,
    /// Cancelled when the shutdown grace period is over: remaining connections close.
    pub force_close: CancellationToken,
    last_connection_id: AtomicU64,
}

impl ServerState {
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        let permits = usize::try_from(config.max_connections).unwrap_or(usize::MAX);
        Self {
            ban_list: BanList::new(config.ban),
            stats: ServerStats::default(),
            connection_permits: Arc::new(Semaphore::new(permits)),
            force_close: CancellationToken::new(),
            last_connection_id: AtomicU64::new(0),
            config,
        }
    }

    #[must_use]
    pub fn next_connection_id(&self) -> u64 {
        self.last_connection_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// Client connections currently open (each one holds a permit).
    #[must_use]
    pub fn active_connections(&self) -> usize {
        let total = usize::try_from(self.config.max_connections).unwrap_or(usize::MAX);
        total.saturating_sub(self.connection_permits.available_permits())
    }
}
