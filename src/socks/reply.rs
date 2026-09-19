use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{ProtocolError, SOCKS_VERSION, TargetAddr, push_socket_addr};

/// `REP` field of a reply (RFC 1928, section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCode {
    Succeeded,
    GeneralFailure,
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned(u8),
}

impl ReplyCode {
    #[must_use]
    pub fn from_byte(value: u8) -> Self {
        match value {
            0x00 => Self::Succeeded,
            0x01 => Self::GeneralFailure,
            0x02 => Self::NotAllowed,
            0x03 => Self::NetworkUnreachable,
            0x04 => Self::HostUnreachable,
            0x05 => Self::ConnectionRefused,
            0x06 => Self::TtlExpired,
            0x07 => Self::CommandNotSupported,
            0x08 => Self::AddressTypeNotSupported,
            other => Self::Unassigned(other),
        }
    }

    #[must_use]
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
            Self::Unassigned(value) => value,
        }
    }
}

impl fmt::Display for ReplyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Succeeded => "succeeded",
            Self::GeneralFailure => "general SOCKS server failure",
            Self::NotAllowed => "connection not allowed by ruleset",
            Self::NetworkUnreachable => "network unreachable",
            Self::HostUnreachable => "host unreachable",
            Self::ConnectionRefused => "connection refused",
            Self::TtlExpired => "TTL expired",
            Self::CommandNotSupported => "command not supported",
            Self::AddressTypeNotSupported => "address type not supported",
            Self::Unassigned(value) => return write!(f, "unassigned reply code {value:#04x}"),
        };
        f.write_str(text)
    }
}

/// Server reply: `VER | REP | RSV | ATYP | BND.ADDR | BND.PORT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub code: ReplyCode,
    pub bind_addr: SocketAddr,
}

impl Reply {
    /// A reply with the bind address `0.0.0.0:0`. Like `ssh -D`, the server does not disclose the
    /// local address of its outbound socket; clients do not use it for `CONNECT`.
    #[must_use]
    pub fn new(code: ReplyCode) -> Self {
        Self {
            code,
            bind_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(22);
        out.extend_from_slice(&[SOCKS_VERSION, self.code.as_byte(), 0x00]);
        push_socket_addr(&mut out, self.bind_addr);
        out
    }

    /// Reads a reply sent by a server (client side).
    ///
    /// # Errors
    /// I/O failure, a version other than 5 or a malformed bind address.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let mut header = [0; 4];
        reader.read_exact(&mut header).await?;
        let [version, code, _reserved, address_type] = header;
        if version != SOCKS_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let bind_addr = match TargetAddr::read_from(reader, address_type).await? {
            TargetAddr::Ip(addr) => addr,
            TargetAddr::Domain { port, .. } => SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        };
        Ok(Self {
            code: ReplyCode::from_byte(code),
            bind_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_unspecified_bind_address() {
        assert_eq!(
            Reply::new(ReplyCode::NotAllowed).encode(),
            vec![0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn round_trips_ipv6_bind_address() {
        let reply = Reply {
            code: ReplyCode::Succeeded,
            bind_addr: "[2001:db8::2]:1080".parse().unwrap(),
        };
        let bytes = reply.encode();
        let mut input = bytes.as_slice();
        assert_eq!(Reply::read_from(&mut input).await.unwrap(), reply);
    }

    #[test]
    fn reply_codes_round_trip() {
        for byte in 0..=u8::MAX {
            assert_eq!(ReplyCode::from_byte(byte).as_byte(), byte);
        }
        assert_eq!(ReplyCode::from_byte(0x05), ReplyCode::ConnectionRefused);
    }
}
