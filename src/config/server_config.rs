use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use super::{ConfigError, SettingsModel, read_settings};
use crate::auth::{UserCredentials, UserStore};
use crate::policy::{BanConfig, ClientAcl, DestinationPolicy, PolicyParseError};

pub const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:1080";
pub const DEFAULT_MAX_CONNECTIONS: u32 = 4096;
pub const MAX_CONNECTIONS_LIMIT: u32 = 1_000_000;
pub const DEFAULT_HANDSHAKE_TIMEOUT_SEC: u64 = 10;
pub const DEFAULT_CONNECT_TIMEOUT_SEC: u64 = 15;
pub const DEFAULT_IDLE_TIMEOUT_SEC: u64 = 300;
pub const DEFAULT_SHUTDOWN_GRACE_SEC: u64 = 10;
pub const DEFAULT_STATS_INTERVAL_SEC: u64 = 60;
pub const DEFAULT_BLOCKED_PORTS: [u16; 1] = [25];
pub const DEFAULT_BAN_MAX_FAILURES: u32 = 5;
pub const DEFAULT_BAN_WINDOW_SEC: u64 = 600;
pub const DEFAULT_BAN_DURATION_SEC: u64 = 3600;
pub const BAN_MAX_TRACKED: usize = 100_000;
/// Upper bound of every `*_sec` setting (one year), far from `Instant` overflow.
pub const MAX_DURATION_SEC: u64 = 365 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Greeting + authentication + request.
    pub handshake: Duration,
    /// DNS resolution + TCP connect to the target.
    pub connect: Duration,
    /// No bytes in either direction while relaying.
    pub idle: Duration,
    /// How long active connections may finish after SIGTERM/SIGINT.
    pub shutdown_grace: Duration,
}

/// Validated settings with defaults applied.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_address: SocketAddr,
    pub users: UserStore,
    pub max_connections: u32,
    pub timeouts: Timeouts,
    pub stats_interval: Duration,
    pub client_acl: ClientAcl,
    pub destination_policy: DestinationPolicy,
    pub ban: BanConfig,
}

impl ServerConfig {
    /// Reads and validates the settings file.
    ///
    /// # Errors
    /// The file cannot be read or parsed, or a value is invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_settings(read_settings(path)?)
    }

    /// # Errors
    /// [`ConfigError::Invalid`] naming the offending key.
    pub fn from_settings(settings: SettingsModel) -> Result<Self, ConfigError> {
        let listen_address = settings
            .listen_address
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN_ADDRESS)
            .parse()
            .map_err(|_| {
                invalid(
                    "listen_address",
                    "expected ip:port, e.g. 0.0.0.0:1080".into(),
                )
            })?;

        let credentials: Vec<UserCredentials> = settings
            .users
            .into_iter()
            .map(|user| UserCredentials {
                username: user.username,
                password: user.password,
            })
            .collect();
        let users =
            UserStore::new(&credentials).map_err(|error| invalid("users", error.to_string()))?;

        let max_connections = settings.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS);
        if !(1..=MAX_CONNECTIONS_LIMIT).contains(&max_connections) {
            return Err(invalid(
                "max_connections",
                format!("must be 1..={MAX_CONNECTIONS_LIMIT}"),
            ));
        }

        let timeouts = Timeouts {
            handshake: seconds(
                "handshake_timeout_sec",
                settings.handshake_timeout_sec,
                DEFAULT_HANDSHAKE_TIMEOUT_SEC,
            )?,
            connect: seconds(
                "connect_timeout_sec",
                settings.connect_timeout_sec,
                DEFAULT_CONNECT_TIMEOUT_SEC,
            )?,
            idle: seconds(
                "idle_timeout_sec",
                settings.idle_timeout_sec,
                DEFAULT_IDLE_TIMEOUT_SEC,
            )?,
            shutdown_grace: seconds(
                "shutdown_grace_sec",
                settings.shutdown_grace_sec,
                DEFAULT_SHUTDOWN_GRACE_SEC,
            )?,
        };
        let stats_interval = seconds(
            "stats_interval_sec",
            settings.stats_interval_sec,
            DEFAULT_STATS_INTERVAL_SEC,
        )?;

        let client_acl = ClientAcl::new(parse_list("client_whitelist", settings.client_whitelist)?);

        let blocked_ports = settings
            .blocked_ports
            .unwrap_or_else(|| DEFAULT_BLOCKED_PORTS.to_vec());
        if blocked_ports.contains(&0) {
            return Err(invalid("blocked_ports", "0 is not a port".into()));
        }
        let destination_policy = DestinationPolicy::new(
            blocked_ports,
            settings.allow_internal.unwrap_or(false),
            parse_list("internal_whitelist", settings.internal_whitelist)?,
        );

        let ban = BanConfig {
            max_failures: settings
                .ban_max_failures
                .unwrap_or(DEFAULT_BAN_MAX_FAILURES),
            window: seconds(
                "ban_window_sec",
                settings.ban_window_sec,
                DEFAULT_BAN_WINDOW_SEC,
            )?,
            duration: seconds(
                "ban_duration_sec",
                settings.ban_duration_sec,
                DEFAULT_BAN_DURATION_SEC,
            )?,
            max_tracked: BAN_MAX_TRACKED,
        };

        Ok(Self {
            listen_address,
            users,
            max_connections,
            timeouts,
            stats_interval,
            client_acl,
            destination_policy,
            ban,
        })
    }
}

fn seconds(key: &'static str, value: Option<u64>, default: u64) -> Result<Duration, ConfigError> {
    let value = value.unwrap_or(default);
    if value == 0 || value > MAX_DURATION_SEC {
        return Err(invalid(
            key,
            format!("must be 1..={MAX_DURATION_SEC} seconds"),
        ));
    }
    Ok(Duration::from_secs(value))
}

fn parse_list<T>(key: &'static str, values: Option<Vec<String>>) -> Result<Vec<T>, ConfigError>
where
    T: FromStr<Err = PolicyParseError>,
{
    values
        .unwrap_or_default()
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error: PolicyParseError| invalid(key, error.to_string()))
        })
        .collect()
}

fn invalid(key: &'static str, reason: String) -> ConfigError {
    ConfigError::Invalid { key, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<ServerConfig, ConfigError> {
        let settings =
            SettingsModel::from_yaml(yaml.as_bytes()).map_err(|error| ConfigError::Parse {
                path: "test.yaml".into(),
                error,
            })?;
        ServerConfig::from_settings(settings)
    }

    fn invalid_key(yaml: &str) -> &'static str {
        match parse(yaml) {
            Err(ConfigError::Invalid { key, .. }) => key,
            other => panic!("expected an invalid key, got {other:?}"),
        }
    }

    const MINIMAL: &str = "users:\n  - username: alice\n    password: secret\n";

    #[test]
    fn minimal_settings_use_defaults() {
        let config = parse(MINIMAL).unwrap();
        assert_eq!(config.listen_address, "0.0.0.0:1080".parse().unwrap());
        assert_eq!(config.max_connections, 4096);
        assert_eq!(config.timeouts.handshake, Duration::from_secs(10));
        assert_eq!(config.timeouts.connect, Duration::from_secs(15));
        assert_eq!(config.timeouts.idle, Duration::from_secs(300));
        assert_eq!(config.timeouts.shutdown_grace, Duration::from_secs(10));
        assert_eq!(config.stats_interval, Duration::from_secs(60));
        assert!(config.client_acl.is_open());
        assert_eq!(config.destination_policy.blocked_ports(), &[25]);
        assert!(!config.destination_policy.allow_internal());
        assert!(config.destination_policy.internal_whitelist().is_empty());
        assert_eq!(config.ban.max_failures, 5);
        assert_eq!(config.ban.window, Duration::from_secs(600));
        assert_eq!(config.ban.duration, Duration::from_secs(3600));
        assert_eq!(config.users.verify(b"alice", b"secret"), Some("alice"));
    }

    #[test]
    fn full_settings_file() {
        let yaml = r#"
listen_address: "[::]:1081"
users:
  - username: alice
    password: "p@ss: with, punctuation"
  - username: bob
    password: second
max_connections: 100
handshake_timeout_sec: 5
connect_timeout_sec: 7
idle_timeout_sec: 60
shutdown_grace_sec: 3
stats_interval_sec: 30
client_whitelist:
  - 203.0.113.10
  - 198.51.100.0/24
blocked_ports: [25, 465]
allow_internal: true
internal_whitelist:
  - 127.0.0.1:8080
  - 10.20.0.0/24:8000-8100
  - "[fd00:1::/64]:443"
ban_max_failures: 3
ban_window_sec: 60
ban_duration_sec: 120
"#;
        let config = parse(yaml).unwrap();
        assert_eq!(config.listen_address, "[::]:1081".parse().unwrap());
        assert_eq!(config.users.len(), 2);
        assert_eq!(
            config.users.verify(b"alice", b"p@ss: with, punctuation"),
            Some("alice")
        );
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.timeouts.idle, Duration::from_secs(60));
        assert_eq!(config.client_acl.networks().len(), 2);
        assert_eq!(config.destination_policy.blocked_ports(), &[25, 465]);
        assert!(config.destination_policy.allow_internal());
        assert_eq!(config.destination_policy.internal_whitelist().len(), 3);
        assert_eq!(config.ban.max_failures, 3);
        assert!(
            config
                .destination_policy
                .check("127.0.0.1:8080".parse().unwrap())
                .is_ok()
        );
    }

    #[test]
    fn empty_blocked_ports_disable_the_default() {
        let config = parse(&format!("{MINIMAL}blocked_ports: []\n")).unwrap();
        assert!(config.destination_policy.blocked_ports().is_empty());
    }

    #[test]
    fn rejects_invalid_values() {
        assert_eq!(invalid_key("users: []\n"), "users");
        assert_eq!(
            invalid_key("users:\n  - username: a\n    password: ''\n"),
            "users"
        );
        assert_eq!(
            invalid_key(&format!("{MINIMAL}listen_address: localhost:1080\n")),
            "listen_address"
        );
        assert_eq!(
            invalid_key(&format!("{MINIMAL}max_connections: 0\n")),
            "max_connections"
        );
        assert_eq!(
            invalid_key(&format!("{MINIMAL}idle_timeout_sec: 0\n")),
            "idle_timeout_sec"
        );
        assert_eq!(
            invalid_key(&format!("{MINIMAL}ban_duration_sec: 99999999999\n")),
            "ban_duration_sec"
        );
        assert_eq!(
            invalid_key(&format!("{MINIMAL}client_whitelist: [10.0.0.0/33]\n")),
            "client_whitelist"
        );
        assert_eq!(
            invalid_key(&format!(
                "{MINIMAL}internal_whitelist: [db.internal:5432]\n"
            )),
            "internal_whitelist"
        );
        assert_eq!(
            invalid_key(&format!("{MINIMAL}blocked_ports: [0]\n")),
            "blocked_ports"
        );
    }

    #[test]
    fn rejects_unknown_and_missing_keys() {
        assert!(matches!(
            parse(&format!("{MINIMAL}alow_internal: true\n")),
            Err(ConfigError::Parse { .. })
        ));
        assert!(matches!(
            parse("listen_address: 0.0.0.0:1080\n"),
            Err(ConfigError::Parse { .. })
        ));
        assert!(matches!(
            parse(&format!("{MINIMAL}max_connections: many\n")),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn error_messages_do_not_leak_passwords() {
        let error = parse("users:\n  - username: alice\n    password: hunter2\n  - username: alice\n    password: hunter3\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("alice"), "{error}");
        assert!(!error.contains("hunter"), "{error}");
    }

    #[test]
    fn example_settings_file_is_valid() {
        let config = parse(include_str!("../../settings.example.yaml")).unwrap();
        assert_eq!(config.client_acl.networks().len(), 2);
        assert_eq!(config.destination_policy.internal_whitelist().len(), 4);
        assert_eq!(config.users.len(), 1);
    }
}
