use tokio::io::{AsyncRead, AsyncReadExt};

use super::{CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE, ProtocolError, SOCKS_VERSION, TargetAddr};

/// SOCKS5 command. Only `Connect` is served; the others are answered with
/// "command not supported".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Unknown(u8),
}

impl Command {
    #[must_use]
    pub fn from_byte(value: u8) -> Self {
        match value {
            CMD_CONNECT => Self::Connect,
            CMD_BIND => Self::Bind,
            CMD_UDP_ASSOCIATE => Self::UdpAssociate,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Connect => CMD_CONNECT,
            Self::Bind => CMD_BIND,
            Self::UdpAssociate => CMD_UDP_ASSOCIATE,
            Self::Unknown(value) => value,
        }
    }
}

/// Client request: `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub target: TargetAddr,
}

impl Request {
    /// Reads a request sent by a client. The reserved byte is ignored.
    ///
    /// # Errors
    /// I/O failure, a version other than 5, an unknown address type or a malformed domain.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let mut header = [0; 4];
        reader.read_exact(&mut header).await?;
        let [version, command, _reserved, address_type] = header;
        if version != SOCKS_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let target = TargetAddr::read_from(reader, address_type).await?;
        Ok(Self {
            command: Command::from_byte(command),
            target,
        })
    }

    /// Encodes the request (client side).
    ///
    /// # Errors
    /// A domain name longer than 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = vec![SOCKS_VERSION, self.command.as_byte(), 0x00];
        self.target.encode_into(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_connect_to_ipv4() {
        let mut input: &[u8] = &[0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50];
        let request = Request::read_from(&mut input).await.unwrap();
        assert_eq!(request.command, Command::Connect);
        assert_eq!(
            request.target,
            TargetAddr::Ip("10.0.0.1:80".parse().unwrap())
        );
        assert!(input.is_empty());
    }

    #[tokio::test]
    async fn keeps_unsupported_commands_parseable() {
        for (byte, command) in [
            (0x02, Command::Bind),
            (0x03, Command::UdpAssociate),
            (0x7F, Command::Unknown(0x7F)),
        ] {
            let mut input: &[u8] = &[0x05, byte, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
            assert_eq!(
                Request::read_from(&mut input).await.unwrap().command,
                command
            );
        }
    }

    #[tokio::test]
    async fn rejects_wrong_version() {
        let mut input: &[u8] = &[0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        assert!(matches!(
            Request::read_from(&mut input).await,
            Err(ProtocolError::UnsupportedVersion(0x04))
        ));
    }

    #[tokio::test]
    async fn round_trip_domain_request() {
        let request = Request {
            command: Command::Connect,
            target: TargetAddr::Domain {
                host: "ifconfig.me".into(),
                port: 443,
            },
        };
        let bytes = request.encode().unwrap();
        let mut input = bytes.as_slice();
        assert_eq!(Request::read_from(&mut input).await.unwrap(), request);
    }
}
