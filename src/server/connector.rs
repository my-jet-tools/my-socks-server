use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpStream, lookup_host};

use super::CloseReason;
use crate::policy::{DenyReason, DestinationPolicy, canonical_ip};
use crate::socks::{ReplyCode, TargetAddr};

/// Upper bound of resolved addresses tried for one request.
pub const MAX_CONNECT_ATTEMPTS: usize = 8;

pub struct ConnectedTarget {
    pub stream: TcpStream,
    /// The address actually connected to.
    pub addr: SocketAddr,
}

#[derive(Debug)]
pub enum ConnectError {
    Denied(DenyReason),
    Resolve(io::Error),
    NoAddresses,
    Connect(io::Error),
}

impl ConnectError {
    /// SOCKS reply for the client.
    #[must_use]
    pub fn reply_code(&self) -> ReplyCode {
        match self {
            Self::Denied(_) => ReplyCode::NotAllowed,
            Self::Resolve(_) | Self::NoAddresses => ReplyCode::HostUnreachable,
            Self::Connect(error) => match error.kind() {
                io::ErrorKind::ConnectionRefused => ReplyCode::ConnectionRefused,
                io::ErrorKind::NetworkUnreachable => ReplyCode::NetworkUnreachable,
                io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => {
                    ReplyCode::HostUnreachable
                }
                // _ => ... io::ErrorKind is non_exhaustive upstream
                _ => ReplyCode::GeneralFailure,
            },
        }
    }
}

impl From<ConnectError> for CloseReason {
    fn from(error: ConnectError) -> Self {
        match error {
            ConnectError::Denied(reason) => Self::DeniedByPolicy(reason),
            ConnectError::Resolve(error) => Self::ResolveFailed(error),
            ConnectError::NoAddresses => Self::ResolvedToNothing,
            ConnectError::Connect(error) => Self::ConnectFailed(error),
        }
    }
}

/// Resolves the target on the server side, runs every resolved address through the
/// destination policy and connects to the first allowed address that answers.
///
/// The policy judges the exact address the socket connects to (IPv4-mapped IPv6 is unwrapped
/// first), so a name resolving — or re-resolving — to an internal address cannot slip past it.
/// The caller bounds the whole call with `connect_timeout_sec`.
///
/// # Errors
/// Every address denied, resolution failure, or no address accepted the connection.
pub async fn connect_to_target(
    policy: &DestinationPolicy,
    target: &TargetAddr,
) -> Result<ConnectedTarget, ConnectError> {
    let resolved: Vec<SocketAddr> = match target {
        TargetAddr::Ip(addr) => vec![*addr],
        TargetAddr::Domain { host, port } => lookup_host((host.as_str(), *port))
            .await
            .map_err(ConnectError::Resolve)?
            .collect(),
    };

    let mut allowed: Vec<SocketAddr> = Vec::with_capacity(resolved.len());
    let mut first_denial = None;
    for addr in resolved {
        let addr = SocketAddr::new(canonical_ip(addr.ip()), addr.port());
        match policy.check(addr) {
            Ok(()) if !allowed.contains(&addr) => allowed.push(addr),
            Ok(()) => {}
            Err(reason) => {
                if first_denial.is_none() {
                    first_denial = Some(reason);
                }
            }
        }
    }
    if allowed.is_empty() {
        return Err(first_denial.map_or(ConnectError::NoAddresses, ConnectError::Denied));
    }

    let mut last_error = None;
    for addr in allowed.into_iter().take(MAX_CONNECT_ATTEMPTS) {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(ConnectedTarget { stream, addr }),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or(ConnectError::NoAddresses, ConnectError::Connect))
}
