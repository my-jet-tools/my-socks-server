use std::io;

use crate::policy::DenyReason;
use crate::relay::RelayEnd;
use crate::socks::{Command, ProtocolError};

/// Why a client connection ended; logged as `reason` (see [`CloseReason::code`]).
#[derive(Debug)]
pub enum CloseReason {
    /// Greeting, authentication and request did not complete within `handshake_timeout_sec`.
    HandshakeTimeout,
    /// The client closed or broke the connection during the handshake.
    HandshakeIo(io::Error),
    /// Not SOCKS5, or malformed SOCKS5.
    Protocol(ProtocolError),
    /// The client did not offer username/password authentication.
    NoAcceptableAuthMethod,
    AuthFailed,
    CommandNotSupported(Command),
    AddressTypeNotSupported(u8),
    InvalidDomain,
    DeniedByPolicy(DenyReason),
    ResolveFailed(io::Error),
    /// The name resolved to no address at all.
    ResolvedToNothing,
    ConnectFailed(io::Error),
    ConnectTimeout,
    /// Both sides closed their direction; the normal end of a proxied connection.
    Completed,
    /// Nothing moved in either direction for `idle_timeout_sec`.
    IdleTimeout,
    ClientError(io::Error),
    TargetError(io::Error),
    /// Still open when the shutdown grace period ended.
    Shutdown,
}

impl CloseReason {
    /// Stable machine-readable name for logs.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::HandshakeTimeout => "handshake_timeout",
            Self::HandshakeIo(_) => "handshake_io_error",
            Self::Protocol(_) => "protocol_error",
            Self::NoAcceptableAuthMethod => "no_acceptable_auth_method",
            Self::AuthFailed => "auth_failed",
            Self::CommandNotSupported(_) => "command_not_supported",
            Self::AddressTypeNotSupported(_) => "address_type_not_supported",
            Self::InvalidDomain => "invalid_domain",
            Self::DeniedByPolicy(_) => "denied_by_policy",
            Self::ResolveFailed(_) => "resolve_failed",
            Self::ResolvedToNothing => "resolved_to_nothing",
            Self::ConnectFailed(_) => "connect_failed",
            Self::ConnectTimeout => "connect_timeout",
            Self::Completed => "completed",
            Self::IdleTimeout => "idle_timeout",
            Self::ClientError(_) => "client_error",
            Self::TargetError(_) => "target_error",
            Self::Shutdown => "shutdown",
        }
    }

    /// Error text or refusal detail, if any.
    #[must_use]
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::HandshakeIo(error)
            | Self::ResolveFailed(error)
            | Self::ConnectFailed(error)
            | Self::ClientError(error)
            | Self::TargetError(error) => Some(error.to_string()),
            Self::Protocol(error) => Some(error.to_string()),
            Self::DeniedByPolicy(reason) => Some(reason.to_string()),
            Self::CommandNotSupported(command) => {
                Some(format!("command {:#04x}", command.as_byte()))
            }
            Self::AddressTypeNotSupported(address_type) => {
                Some(format!("address type {address_type:#04x}"))
            }
            Self::HandshakeTimeout
            | Self::NoAcceptableAuthMethod
            | Self::AuthFailed
            | Self::InvalidDomain
            | Self::ResolvedToNothing
            | Self::ConnectTimeout
            | Self::Completed
            | Self::IdleTimeout
            | Self::Shutdown => None,
        }
    }
}

impl From<ProtocolError> for CloseReason {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::Io(error) => Self::HandshakeIo(error),
            ProtocolError::UnsupportedAddressType(address_type) => {
                Self::AddressTypeNotSupported(address_type)
            }
            ProtocolError::InvalidDomain => Self::InvalidDomain,
            error @ (ProtocolError::UnsupportedVersion(_)
            | ProtocolError::NoMethods
            | ProtocolError::UnsupportedAuthVersion(_)
            | ProtocolError::FieldTooLong) => Self::Protocol(error),
        }
    }
}

impl From<RelayEnd> for CloseReason {
    fn from(end: RelayEnd) -> Self {
        match end {
            RelayEnd::Completed => Self::Completed,
            RelayEnd::IdleTimeout => Self::IdleTimeout,
            RelayEnd::ClientError(error) => Self::ClientError(error),
            RelayEnd::TargetError(error) => Self::TargetError(error),
        }
    }
}
