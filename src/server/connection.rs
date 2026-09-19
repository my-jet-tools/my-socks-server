use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tracing::{debug, field, info};

use super::{
    CloseReason, ConnectedTarget, ConnectionContext, ServerState, connect_to_target, handshake,
    send_reply,
};
use crate::limits::tune_tcp_stream;
use crate::relay::{RelayCounters, relay_tcp};
use crate::socks::{Reply, ReplyCode};

/// What is known about a connection; written to the log when it closes.
#[derive(Debug, Default)]
pub struct ConnectionReport {
    pub user: Option<String>,
    /// Target as requested by the client.
    pub target: Option<String>,
    /// Address actually connected to.
    pub target_addr: Option<SocketAddr>,
    pub counters: RelayCounters,
}

/// Serves one accepted client and writes one "connection closed" log line.
///
/// Every phase is bounded by a timeout and `force_close` interrupts it at shutdown, so the
/// task always ends; both sockets are dropped (closed) with it and the permit is released.
pub async fn serve_connection(
    state: &ServerState,
    client: TcpStream,
    context: ConnectionContext,
    permit: OwnedSemaphorePermit,
) {
    let started = Instant::now();
    let mut report = ConnectionReport::default();
    let reason = tokio::select! {
        reason = run_connection(state, client, context, &mut report) => reason,
        () = state.force_close.cancelled() => CloseReason::Shutdown,
    };
    state.stats.bytes_in.add(report.counters.client_to_target);
    state.stats.bytes_out.add(report.counters.target_to_client);
    if matches!(reason, CloseReason::DeniedByPolicy(_)) {
        state.stats.denied_by_policy.increment();
    }
    log_closed(context, &report, &reason, started.elapsed());
    drop(permit);
}

async fn run_connection(
    state: &ServerState,
    mut client: TcpStream,
    context: ConnectionContext,
    report: &mut ConnectionReport,
) -> CloseReason {
    if let Err(error) = tune_tcp_stream(&client) {
        debug!(conn_id = context.id, %error, "cannot tune client socket");
    }
    let timeouts = state.config.timeouts;

    let handshake = handshake(state, &mut client, context, report);
    let target = match timeout(timeouts.handshake, handshake).await {
        Ok(Ok(target)) => target,
        Ok(Err(reason)) => return reason,
        Err(_elapsed) => return CloseReason::HandshakeTimeout,
    };
    report.target = Some(target.to_string());

    let connect = connect_to_target(&state.config.destination_policy, &target);
    let ConnectedTarget {
        stream: mut upstream,
        addr,
    } = match timeout(timeouts.connect, connect).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(error)) => {
            send_reply(&mut client, error.reply_code(), timeouts.handshake).await;
            return error.into();
        }
        Err(_elapsed) => {
            send_reply(&mut client, ReplyCode::HostUnreachable, timeouts.handshake).await;
            return CloseReason::ConnectTimeout;
        }
    };
    report.target_addr = Some(addr);
    if let Err(error) = tune_tcp_stream(&upstream) {
        debug!(conn_id = context.id, %error, "cannot tune target socket");
    }

    let success = Reply::new(ReplyCode::Succeeded).encode();
    match timeout(timeouts.handshake, client.write_all(&success)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return CloseReason::HandshakeIo(error),
        Err(_elapsed) => return CloseReason::HandshakeTimeout,
    }

    relay_tcp(
        &mut client,
        &mut upstream,
        timeouts.idle,
        &mut report.counters,
    )
    .await
    .into()
}

fn log_closed(
    context: ConnectionContext,
    report: &ConnectionReport,
    reason: &CloseReason,
    duration: Duration,
) {
    let detail = reason.detail();
    info!(
        conn_id = context.id,
        client = %context.peer,
        user = report.user.as_deref(),
        target = report.target.as_deref(),
        target_addr = report.target_addr.map(field::display),
        bytes_in = report.counters.client_to_target,
        bytes_out = report.counters.target_to_client,
        duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        reason = reason.code(),
        detail = detail.as_deref(),
        "connection closed"
    );
}
