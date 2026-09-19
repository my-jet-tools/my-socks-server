use tokio::io::{AsyncRead, AsyncReadExt};

use super::{METHOD_NO_ACCEPTABLE, ProtocolError, SOCKS_VERSION};

/// Client greeting: `VER | NMETHODS | METHODS...` (RFC 1928, section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    pub methods: Vec<u8>,
}

impl Greeting {
    /// Reads a greeting sent by a client.
    ///
    /// # Errors
    /// I/O failure, a version other than 5, or an empty method list.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let version = reader.read_u8().await?;
        if version != SOCKS_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let count = reader.read_u8().await?;
        if count == 0 {
            return Err(ProtocolError::NoMethods);
        }
        let mut methods = vec![0; usize::from(count)];
        reader.read_exact(&mut methods).await?;
        Ok(Self { methods })
    }

    #[must_use]
    pub fn offers(&self, method: u8) -> bool {
        self.methods.contains(&method)
    }

    /// Encodes the greeting (client side).
    ///
    /// # Errors
    /// More than 255 methods.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let count = u8::try_from(self.methods.len()).map_err(|_| ProtocolError::FieldTooLong)?;
        let mut out = Vec::with_capacity(2 + self.methods.len());
        out.push(SOCKS_VERSION);
        out.push(count);
        out.extend_from_slice(&self.methods);
        Ok(out)
    }
}

/// The server's choice of authentication method: `VER | METHOD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSelection {
    pub method: u8,
}

impl MethodSelection {
    pub const NO_ACCEPTABLE: Self = Self {
        method: METHOD_NO_ACCEPTABLE,
    };

    #[must_use]
    pub fn encode(self) -> [u8; 2] {
        [SOCKS_VERSION, self.method]
    }

    /// Reads the server's answer (client side).
    ///
    /// # Errors
    /// I/O failure or a version other than 5.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let version = reader.read_u8().await?;
        if version != SOCKS_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        Ok(Self {
            method: reader.read_u8().await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks::{METHOD_NO_AUTH, METHOD_USER_PASS};

    #[tokio::test]
    async fn parses_greeting() {
        let mut input: &[u8] = &[0x05, 0x02, METHOD_NO_AUTH, METHOD_USER_PASS];
        let greeting = Greeting::read_from(&mut input).await.unwrap();
        assert_eq!(greeting.methods, vec![METHOD_NO_AUTH, METHOD_USER_PASS]);
        assert!(greeting.offers(METHOD_USER_PASS));
        assert!(input.is_empty(), "must not read past the greeting");
    }

    #[tokio::test]
    async fn greeting_round_trip() {
        let greeting = Greeting {
            methods: vec![METHOD_USER_PASS],
        };
        let bytes = greeting.encode().unwrap();
        assert_eq!(bytes, vec![0x05, 0x01, 0x02]);
        let mut input = bytes.as_slice();
        assert_eq!(Greeting::read_from(&mut input).await.unwrap(), greeting);
    }

    #[tokio::test]
    async fn rejects_socks4_and_http() {
        for input in [&[0x04_u8, 0x01, 0x00][..], b"GET / HTTP/1.1\r\n"] {
            let mut input = input;
            assert!(matches!(
                Greeting::read_from(&mut input).await,
                Err(ProtocolError::UnsupportedVersion(_))
            ));
        }
    }

    #[tokio::test]
    async fn rejects_empty_method_list() {
        let mut input: &[u8] = &[0x05, 0x00];
        assert!(matches!(
            Greeting::read_from(&mut input).await,
            Err(ProtocolError::NoMethods)
        ));
    }

    #[tokio::test]
    async fn truncated_greeting_is_io_error() {
        let mut input: &[u8] = &[0x05, 0x03, 0x00];
        assert!(matches!(
            Greeting::read_from(&mut input).await,
            Err(ProtocolError::Io(_))
        ));
    }

    #[tokio::test]
    async fn method_selection_round_trip() {
        let selection = MethodSelection {
            method: METHOD_USER_PASS,
        };
        let bytes = selection.encode();
        assert_eq!(bytes, [0x05, 0x02]);
        let mut input = &bytes[..];
        assert_eq!(
            MethodSelection::read_from(&mut input).await.unwrap(),
            selection
        );
        assert_eq!(MethodSelection::NO_ACCEPTABLE.encode(), [0x05, 0xFF]);
    }
}
