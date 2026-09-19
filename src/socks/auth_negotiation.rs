use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    AUTH_STATUS_FAILURE, AUTH_STATUS_SUCCESS, AUTH_VERSION, ProtocolError, push_u8_prefixed,
    read_u8_prefixed,
};

/// RFC 1929 request: `VER | ULEN | UNAME | PLEN | PASSWD`.
#[derive(Clone, PartialEq, Eq)]
pub struct UserPassRequest {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl fmt::Debug for UserPassRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserPassRequest")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("password", &"<redacted>")
            .finish()
    }
}

impl UserPassRequest {
    /// Reads the sub-negotiation request sent by a client.
    ///
    /// # Errors
    /// I/O failure or a sub-negotiation version other than 1.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let version = reader.read_u8().await?;
        if version != AUTH_VERSION {
            return Err(ProtocolError::UnsupportedAuthVersion(version));
        }
        let username = read_u8_prefixed(reader).await?;
        let password = read_u8_prefixed(reader).await?;
        Ok(Self { username, password })
    }

    /// Encodes the request (client side).
    ///
    /// # Errors
    /// Username or password longer than 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::with_capacity(3 + self.username.len() + self.password.len());
        out.push(AUTH_VERSION);
        push_u8_prefixed(&mut out, &self.username)?;
        push_u8_prefixed(&mut out, &self.password)?;
        Ok(out)
    }
}

/// RFC 1929 response: `VER | STATUS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPassResponse {
    pub status: u8,
}

impl UserPassResponse {
    pub const SUCCESS: Self = Self {
        status: AUTH_STATUS_SUCCESS,
    };
    pub const FAILURE: Self = Self {
        status: AUTH_STATUS_FAILURE,
    };

    #[must_use]
    pub fn is_success(self) -> bool {
        self.status == AUTH_STATUS_SUCCESS
    }

    #[must_use]
    pub fn encode(self) -> [u8; 2] {
        [AUTH_VERSION, self.status]
    }

    /// Reads the server's answer (client side).
    ///
    /// # Errors
    /// I/O failure or a sub-negotiation version other than 1.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let version = reader.read_u8().await?;
        if version != AUTH_VERSION {
            return Err(ProtocolError::UnsupportedAuthVersion(version));
        }
        Ok(Self {
            status: reader.read_u8().await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(username: &str, password: &str) -> UserPassRequest {
        UserPassRequest {
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn parses_request() {
        let mut input: &[u8] = &[0x01, 0x03, b'b', b'o', b'b', 0x02, b'p', b'w'];
        let parsed = UserPassRequest::read_from(&mut input).await.unwrap();
        assert_eq!(parsed, request("bob", "pw"));
        assert!(input.is_empty());
    }

    #[tokio::test]
    async fn request_round_trip() {
        let original = request("alice", "s3cr3t:with:colons");
        let bytes = original.encode().unwrap();
        let mut input = bytes.as_slice();
        assert_eq!(
            UserPassRequest::read_from(&mut input).await.unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn rejects_wrong_sub_negotiation_version() {
        let mut input: &[u8] = &[0x05, 0x01, b'a', 0x01, b'b'];
        assert!(matches!(
            UserPassRequest::read_from(&mut input).await,
            Err(ProtocolError::UnsupportedAuthVersion(0x05))
        ));
    }

    #[tokio::test]
    async fn truncated_password_is_io_error() {
        let mut input: &[u8] = &[0x01, 0x01, b'a', 0x05, b'x'];
        assert!(matches!(
            UserPassRequest::read_from(&mut input).await,
            Err(ProtocolError::Io(_))
        ));
    }

    #[test]
    fn encode_rejects_overlong_fields() {
        let overlong = "x".repeat(256);
        assert!(matches!(
            request(&overlong, "pw").encode(),
            Err(ProtocolError::FieldTooLong)
        ));
        assert!(matches!(
            request("user", &overlong).encode(),
            Err(ProtocolError::FieldTooLong)
        ));
    }

    #[test]
    fn debug_output_redacts_password() {
        let rendered = format!("{:?}", request("alice", "hunter2"));
        assert!(rendered.contains("alice"));
        assert!(!rendered.contains("hunter2"));
    }

    #[tokio::test]
    async fn response_round_trip() {
        assert_eq!(UserPassResponse::SUCCESS.encode(), [0x01, 0x00]);
        assert_eq!(UserPassResponse::FAILURE.encode(), [0x01, 0x01]);
        let bytes = UserPassResponse::FAILURE.encode();
        let mut input = &bytes[..];
        let parsed = UserPassResponse::read_from(&mut input).await.unwrap();
        assert!(!parsed.is_success());
    }
}
