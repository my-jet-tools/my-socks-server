use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::warn;

use super::{CloseReason, ConnectionReport, ServerState};
use crate::policy::FailureVerdict;
use crate::socks::{
    Command, Greeting, METHOD_USER_PASS, MethodSelection, ProtocolError, Reply, ReplyCode, Request,
    TargetAddr, UserPassRequest, UserPassResponse,
};

/// Identity of a connection in log lines.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionContext {
    pub id: u64,
    /// Client address, IPv4-mapped IPv6 already unwrapped.
    pub peer: SocketAddr,
}

/// Greeting → username/password authentication → request; returns the `CONNECT` target.
/// The caller bounds the whole exchange with `handshake_timeout_sec`.
///
/// # Errors
/// Why the connection must be closed; the client has already been sent the matching answer.
pub async fn handshake(
    state: &ServerState,
    client: &mut TcpStream,
    context: ConnectionContext,
    report: &mut ConnectionReport,
) -> Result<TargetAddr, CloseReason> {
    negotiate_method(client).await?;
    authenticate(state, client, context, report).await?;
    read_connect_request(client, state.config.timeouts.handshake).await
}

/// Best effort: the connection is closed right after an error reply, so a failed write
/// changes nothing.
pub async fn send_reply(client: &mut TcpStream, code: ReplyCode, limit: Duration) {
    let _ = timeout(limit, client.write_all(&Reply::new(code).encode())).await;
}

async fn negotiate_method(client: &mut TcpStream) -> Result<(), CloseReason> {
    let greeting = Greeting::read_from(client).await?;
    if !greeting.offers(METHOD_USER_PASS) {
        // "No authentication" is never accepted, whatever else the client offers.
        let _ = client
            .write_all(&MethodSelection::NO_ACCEPTABLE.encode())
            .await;
        return Err(CloseReason::NoAcceptableAuthMethod);
    }
    let selection = MethodSelection {
        method: METHOD_USER_PASS,
    };
    client
        .write_all(&selection.encode())
        .await
        .map_err(CloseReason::HandshakeIo)
}

async fn authenticate(
    state: &ServerState,
    client: &mut TcpStream,
    context: ConnectionContext,
    report: &mut ConnectionReport,
) -> Result<(), CloseReason> {
    let credentials = UserPassRequest::read_from(client).await?;
    if let Some(user) = state
        .config
        .users
        .verify(&credentials.username, &credentials.password)
    {
        report.user = Some(user.to_owned());
        return client
            .write_all(&UserPassResponse::SUCCESS.encode())
            .await
            .map_err(CloseReason::HandshakeIo);
    }

    state.stats.auth_failures.increment();
    let verdict = state.ban_list.record_failure(context.peer.ip());
    let _ = client.write_all(&UserPassResponse::FAILURE.encode()).await;

    // The username comes from the network: control characters are escaped. Never the password.
    let username = String::from_utf8_lossy(&credentials.username);
    let failures = match verdict {
        FailureVerdict::Counted { failures } => Some(failures),
        FailureVerdict::Banned | FailureVerdict::Disabled | FailureVerdict::Untracked => None,
    };
    warn!(
        conn_id = context.id,
        client = %context.peer,
        username = %username.escape_debug(),
        failures,
        "authentication failed"
    );
    match verdict {
        FailureVerdict::Banned => warn!(
            conn_id = context.id,
            client = %context.peer,
            ban_duration_sec = state.config.ban.duration.as_secs(),
            "client banned after repeated authentication failures"
        ),
        FailureVerdict::Untracked => warn!(
            client = %context.peer,
            "ban table is full, failure not tracked"
        ),
        FailureVerdict::Counted { .. } | FailureVerdict::Disabled => {}
    }
    Err(CloseReason::AuthFailed)
}

async fn read_connect_request(
    client: &mut TcpStream,
    reply_timeout: Duration,
) -> Result<TargetAddr, CloseReason> {
    let request = match Request::read_from(client).await {
        Ok(request) => request,
        Err(ProtocolError::UnsupportedAddressType(address_type)) => {
            send_reply(client, ReplyCode::AddressTypeNotSupported, reply_timeout).await;
            return Err(CloseReason::AddressTypeNotSupported(address_type));
        }
        Err(ProtocolError::InvalidDomain) => {
            send_reply(client, ReplyCode::GeneralFailure, reply_timeout).await;
            return Err(CloseReason::InvalidDomain);
        }
        Err(
            error @ (ProtocolError::Io(_)
            | ProtocolError::UnsupportedVersion(_)
            | ProtocolError::NoMethods
            | ProtocolError::UnsupportedAuthVersion(_)
            | ProtocolError::FieldTooLong),
        ) => return Err(error.into()),
    };
    match request.command {
        Command::Connect => Ok(request.target),
        Command::Bind | Command::UdpAssociate | Command::Unknown(_) => {
            send_reply(client, ReplyCode::CommandNotSupported, reply_timeout).await;
            Err(CloseReason::CommandNotSupported(request.command))
        }
    }
}
