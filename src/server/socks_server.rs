use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::{
    ConnectionContext, LogThrottle, ServerState, log_stats, serve_connection,
    spawn_background_tasks,
};
use crate::config::ServerConfig;
use crate::policy::canonical_ip;

/// Pause after a failed `accept()` (`EMFILE`, `ENFILE`, ...) before the next attempt.
pub const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// Time force-closed connections get to write their final log line.
pub const FORCE_CLOSE_WAIT: Duration = Duration::from_secs(1);
const LIMIT_WARNING_PERIOD: Duration = Duration::from_secs(10);

pub struct SocksServer {
    listener: TcpListener,
    state: Arc<ServerState>,
}

impl SocksServer {
    /// # Errors
    /// The listen address cannot be bound.
    pub async fn bind(config: ServerConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen_address).await?;
        Ok(Self {
            listener,
            state: Arc::new(ServerState::new(config)),
        })
    }

    /// # Errors
    /// The socket address cannot be queried.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    #[must_use]
    pub fn state(&self) -> Arc<ServerState> {
        Arc::clone(&self.state)
    }

    /// Serves until `shutdown` completes. Then stops accepting, gives open connections
    /// `shutdown_grace_sec` to finish and closes whatever is left.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let Self { listener, state } = self;
        let stop_background = CancellationToken::new();
        let background = spawn_background_tasks(&state, &stop_background);

        accept_loop(&listener, &state, shutdown).await;
        // Closing the listening socket makes the kernel refuse new connections at once.
        drop(listener);
        drain(&state).await;

        stop_background.cancel();
        for task in background {
            let _ = task.await;
        }
        log_stats(&state).await;
    }
}

/// Runs until `shutdown`; `accept()` errors are logged and retried after a pause, never fatal.
async fn accept_loop(
    listener: &TcpListener,
    state: &Arc<ServerState>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let limit_warning = LogThrottle::new(LIMIT_WARNING_PERIOD);
    loop {
        let accepted = tokio::select! {
            biased;
            () = &mut shutdown => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((client, peer)) => admit(state, client, peer, &limit_warning),
            Err(error) => {
                error!(%error, "accept() failed, retrying in 100 ms");
                tokio::select! {
                    biased;
                    () = &mut shutdown => return,
                    () = sleep(ACCEPT_ERROR_BACKOFF) => {}
                }
            }
        }
    }
}

/// Cheap checks right after `accept()`, before a single byte is read. A rejected socket is
/// dropped here, which closes it immediately.
fn admit(
    state: &Arc<ServerState>,
    client: TcpStream,
    peer: SocketAddr,
    limit_warning: &LogThrottle,
) {
    let peer = SocketAddr::new(canonical_ip(peer.ip()), peer.port());
    if !state.config.client_acl.is_allowed(peer.ip()) {
        state.stats.rejected_not_whitelisted.increment();
        debug!(client = %peer, "dropped: not in client_whitelist");
        return;
    }
    if state.ban_list.is_banned(peer.ip()) {
        state.stats.rejected_banned.increment();
        debug!(client = %peer, "dropped: banned");
        return;
    }
    let Ok(permit) = Arc::clone(&state.connection_permits).try_acquire_owned() else {
        state.stats.rejected_over_limit.increment();
        if limit_warning.allow() {
            warn!(
                max_connections = state.config.max_connections,
                "connection limit reached, dropping new connections"
            );
        }
        return;
    };
    state.stats.accepted.increment();
    let context = ConnectionContext {
        id: state.next_connection_id(),
        peer,
    };
    let state = Arc::clone(state);
    tokio::spawn(async move { serve_connection(&state, client, context, permit).await });
}

async fn drain(state: &ServerState) {
    let grace = state.config.timeouts.shutdown_grace;
    info!(
        active_connections = state.active_connections(),
        grace_sec = grace.as_secs(),
        "shutting down, new connections are refused"
    );
    if wait_for_connections(state, grace).await {
        info!("all connections finished");
        return;
    }
    warn!(
        active_connections = state.active_connections(),
        "grace period is over, closing remaining connections"
    );
    state.force_close.cancel();
    if !wait_for_connections(state, FORCE_CLOSE_WAIT).await {
        warn!(
            active_connections = state.active_connections(),
            "connection tasks did not finish in time"
        );
    }
}

/// True once every permit is back, i.e. no client connection is open.
async fn wait_for_connections(state: &ServerState, limit: Duration) -> bool {
    let all = state.config.max_connections;
    matches!(
        timeout(limit, state.connection_permits.acquire_many(all)).await,
        Ok(Ok(_))
    )
}
