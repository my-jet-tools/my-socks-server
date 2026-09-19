use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use super::ServerState;
use crate::limits::count_open_fds;

/// How often expired bans and stale failure counters are dropped.
pub const BAN_PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// Starts the stats reporter and the ban-list purger; both stop when `stop` is cancelled.
#[must_use]
pub fn spawn_background_tasks(
    state: &Arc<ServerState>,
    stop: &CancellationToken,
) -> Vec<JoinHandle<()>> {
    let reporter = {
        let state = Arc::clone(state);
        let stop = stop.clone();
        tokio::spawn(async move { report_stats(&state, &stop).await })
    };
    let purger = {
        let state = Arc::clone(state);
        let stop = stop.clone();
        tokio::spawn(async move { purge_bans(&state, &stop).await })
    };
    vec![reporter, purger]
}

/// Logs connection counts, free permits, open descriptors and the counters.
pub async fn log_stats(state: &ServerState) {
    let open_fds = match tokio::task::spawn_blocking(count_open_fds).await {
        Ok(Ok(count)) => Some(count),
        Ok(Err(_)) | Err(_) => None,
    };
    let bans = state.ban_list.stats();
    let counters = &state.stats;
    info!(
        active_connections = state.active_connections(),
        free_permits = state.connection_permits.available_permits(),
        open_fds,
        accepted = counters.accepted.get(),
        rejected_not_whitelisted = counters.rejected_not_whitelisted.get(),
        rejected_banned = counters.rejected_banned.get(),
        rejected_over_limit = counters.rejected_over_limit.get(),
        auth_failures = counters.auth_failures.get(),
        denied_by_policy = counters.denied_by_policy.get(),
        bytes_in = counters.bytes_in.get(),
        bytes_out = counters.bytes_out.get(),
        banned_clients = bans.banned,
        tracked_clients = bans.tracked,
        "stats"
    );
}

async fn report_stats(state: &ServerState, stop: &CancellationToken) {
    let mut ticker = ticker(state.config.stats_interval);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = ticker.tick() => log_stats(state).await,
        }
    }
}

async fn purge_bans(state: &ServerState, stop: &CancellationToken) {
    let mut ticker = ticker(BAN_PURGE_INTERVAL);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = ticker.tick() => {
                let purged = state.ban_list.purge();
                if purged > 0 {
                    debug!(purged, "ban list purged");
                }
            }
        }
    }
}

/// Ticks every `period`, the first tick one period from now.
fn ticker(period: Duration) -> Interval {
    let mut ticker = interval_at(Instant::now() + period, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker
}
