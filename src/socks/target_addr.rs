use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, ProtocolError, push_socket_addr, push_u8_prefixed,
    read_u8_prefixed,
};

/// Destination requested by the client: `ATYP | DST.ADDR | DST.PORT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    /// Resolved on the server side.
    Domain {
        host: String,
        port: u16,
    },
}

impl TargetAddr {
    /// Reads the address that follows an `ATYP` byte.
    ///
    /// # Errors
    /// I/O failure, an unknown address type or a malformed domain name.
    pub async fn read_from<R: AsyncRead + Unpin>(
        reader: &mut R,
        address_type: u8,
    ) -> Result<Self, ProtocolError> {
        match address_type {
            ATYP_IPV4 => {
                let mut octets = [0; 4];
                reader.read_exact(&mut octets).await?;
                let port = reader.read_u16().await?;
                Ok(Self::Ip(SocketAddr::from((Ipv4Addr::from(octets), port))))
            }
            ATYP_IPV6 => {
                let mut octets = [0; 16];
                reader.read_exact(&mut octets).await?;
                let port = reader.read_u16().await?;
                Ok(Self::Ip(SocketAddr::from((Ipv6Addr::from(octets), port))))
            }
            ATYP_DOMAIN => {
                let raw = read_u8_prefixed(reader).await?;
                let port = reader.read_u16().await?;
                Ok(Self::Domain {
                    host: parse_domain(raw)?,
                    port,
                })
            }
            other => Err(ProtocolError::UnsupportedAddressType(other)),
        }
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    /// Appends `ATYP | ADDR | PORT`.
    ///
    /// # Errors
    /// A domain name longer than 255 bytes.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        match self {
            Self::Ip(addr) => push_socket_addr(out, *addr),
            Self::Domain { host, port } => {
                out.push(ATYP_DOMAIN);
                push_u8_prefixed(out, host.as_bytes())?;
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain { host, port } if host.contains(':') => write!(f, "[{host}]:{port}"),
            Self::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Accepts host names (letters, digits, `-`, `_`, `.`) and IP literals (`:` for IPv6).
/// Anything else is refused before it can reach the resolver or the logs.
fn parse_domain(raw: Vec<u8>) -> Result<String, ProtocolError> {
    let valid = !raw.is_empty()
        && raw
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if !valid {
        return Err(ProtocolError::InvalidDomain);
    }
    String::from_utf8(raw).map_err(|_| ProtocolError::InvalidDomain)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(address_type: u8, bytes: &[u8]) -> Result<TargetAddr, ProtocolError> {
        let mut input = bytes;
        TargetAddr::read_from(&mut input, address_type).await
    }

    #[tokio::test]
    async fn parses_ipv4() {
        let target = parse(ATYP_IPV4, &[192, 0, 2, 7, 0x01, 0xBB]).await.unwrap();
        assert_eq!(target, TargetAddr::Ip("192.0.2.7:443".parse().unwrap()));
    }

    #[tokio::test]
    async fn parses_ipv6() {
        let mut bytes = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        bytes.extend_from_slice(&80_u16.to_be_bytes());
        let target = parse(ATYP_IPV6, &bytes).await.unwrap();
        assert_eq!(target, TargetAddr::Ip("[2001:db8::1]:80".parse().unwrap()));
        assert_eq!(target.to_string(), "[2001:db8::1]:80");
    }

    #[tokio::test]
    async fn parses_domain() {
        let mut bytes = vec![11];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&8080_u16.to_be_bytes());
        let target = parse(ATYP_DOMAIN, &bytes).await.unwrap();
        assert_eq!(
            target,
            TargetAddr::Domain {
                host: "example.com".into(),
                port: 8080
            }
        );
        assert_eq!(target.to_string(), "example.com:8080");
        assert_eq!(target.port(), 8080);
    }

    #[tokio::test]
    async fn rejects_bad_domains() {
        for name in [&b""[..], b"exa mple.com", b"evil\ncom", b"\xff\xfe", b"a/b"] {
            let mut bytes = vec![u8::try_from(name.len()).unwrap()];
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(&80_u16.to_be_bytes());
            assert!(
                matches!(
                    parse(ATYP_DOMAIN, &bytes).await,
                    Err(ProtocolError::InvalidDomain)
                ),
                "{name:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn rejects_unknown_address_type() {
        assert!(matches!(
            parse(0x02, &[0; 6]).await,
            Err(ProtocolError::UnsupportedAddressType(0x02))
        ));
    }

    #[tokio::test]
    async fn round_trips_every_address_type() {
        for target in [
            TargetAddr::Ip("10.1.2.3:22".parse().unwrap()),
            TargetAddr::Ip("[fd00::5]:5432".parse().unwrap()),
            TargetAddr::Domain {
                host: "db.internal".into(),
                port: 5432,
            },
        ] {
            let mut bytes = Vec::new();
            target.encode_into(&mut bytes).unwrap();
            let (address_type, rest) = bytes.split_first().unwrap();
            assert_eq!(parse(*address_type, rest).await.unwrap(), target);
        }
    }
}
