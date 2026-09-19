use std::fmt;

use serde::Deserialize;

/// Contents of `~/.mysocksserver` (YAML). Every key except `users` is optional; unknown keys
/// are rejected so a typo cannot silently change the security settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsModel {
    /// `ip:port` to listen on. Default `0.0.0.0:1080`.
    pub listen_address: Option<String>,
    /// Username/password pairs (RFC 1929). At least one.
    pub users: Vec<UserSettingsModel>,
    /// Simultaneous client connections. Default 4096.
    pub max_connections: Option<u32>,
    /// Greeting + authentication + request. Default 10.
    pub handshake_timeout_sec: Option<u64>,
    /// DNS resolution + connect to the target. Default 15.
    pub connect_timeout_sec: Option<u64>,
    /// No traffic in either direction while relaying. Default 300.
    pub idle_timeout_sec: Option<u64>,
    /// Time active connections get after SIGTERM/SIGINT. Default 10.
    pub shutdown_grace_sec: Option<u64>,
    /// Period of the stats log line. Default 60.
    pub stats_interval_sec: Option<u64>,
    /// Client IPs/CIDRs allowed to connect. Empty or missing: anyone.
    pub client_whitelist: Option<Vec<String>>,
    /// Destination ports that are never allowed. Default `[25]`.
    pub blocked_ports: Option<Vec<u16>>,
    /// Open all private networks (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`).
    /// Default false.
    pub allow_internal: Option<bool>,
    /// Internal destinations that are allowed: IP or CIDR, optionally `:port` or
    /// `:port-range` (`[ipv6]:port` for IPv6). The only way to open loopback and link-local.
    pub internal_whitelist: Option<Vec<String>>,
    /// Failed authentications within `ban_window_sec` that ban the client IP. 0 disables.
    /// Default 5.
    pub ban_max_failures: Option<u32>,
    /// Default 600.
    pub ban_window_sec: Option<u64>,
    /// Default 3600.
    pub ban_duration_sec: Option<u64>,
}

impl SettingsModel {
    /// # Errors
    /// Invalid YAML, a value of the wrong type, a missing `users` key or an unknown key.
    pub fn from_yaml(content: &[u8]) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_slice(content)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSettingsModel {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for UserSettingsModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserSettingsModel")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}
