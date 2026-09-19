//! Encoding helpers shared by the message types.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{ATYP_IPV4, ATYP_IPV6, ProtocolError};

/// Reads a field prefixed with its one-byte length.
///
/// # Errors
/// I/O failure (including EOF before the field is complete).
pub async fn read_u8_prefixed<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ProtocolError> {
    let len = reader.read_u8().await?;
    let mut field = vec![0; usize::from(len)];
    reader.read_exact(&mut field).await?;
    Ok(field)
}

/// Appends a field prefixed with its one-byte length.
///
/// # Errors
/// The field is longer than 255 bytes.
pub fn push_u8_prefixed(out: &mut Vec<u8>, field: &[u8]) -> Result<(), ProtocolError> {
    let len = u8::try_from(field.len()).map_err(|_| ProtocolError::FieldTooLong)?;
    out.push(len);
    out.extend_from_slice(field);
    Ok(())
}

/// Appends `ATYP | ADDR | PORT` for an IP socket address.
pub fn push_socket_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(addr) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&addr.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}
