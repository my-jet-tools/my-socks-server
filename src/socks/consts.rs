//! Wire constants of RFC 1928 (SOCKS5) and RFC 1929 (username/password authentication).

/// Protocol version byte of SOCKS5.
pub const SOCKS_VERSION: u8 = 0x05;
/// Version byte of the RFC 1929 username/password sub-negotiation.
pub const AUTH_VERSION: u8 = 0x01;

/// "No authentication required". Offered by clients, never accepted by this server.
pub const METHOD_NO_AUTH: u8 = 0x00;
/// Username/password authentication (RFC 1929).
pub const METHOD_USER_PASS: u8 = 0x02;
/// "No acceptable methods": the server's answer when the client does not offer username/password.
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const AUTH_STATUS_SUCCESS: u8 = 0x00;
pub const AUTH_STATUS_FAILURE: u8 = 0x01;
