use std::io;

/// Malformed or unsupported SOCKS5 input, or an I/O failure while reading it.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported SOCKS version {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("client offered no authentication methods")]
    NoMethods,
    #[error("unsupported username/password sub-negotiation version {0:#04x}")]
    UnsupportedAuthVersion(u8),
    #[error("unsupported address type {0:#04x}")]
    UnsupportedAddressType(u8),
    #[error("invalid domain name")]
    InvalidDomain,
    #[error("field is longer than 255 bytes")]
    FieldTooLong,
}
