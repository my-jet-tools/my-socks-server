use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use super::{Cidr, PolicyParseError, PortRange, canonical_ip};

const EXPECTED_FORMAT: &str =
    "expected IP or CIDR with an optional :port or :port-range ([ipv6]:port for IPv6)";

/// One `internal_whitelist` entry: an internal network, optionally narrowed to a port or a
/// port range.
///
/// Accepted forms: `10.0.0.5`, `10.0.0.0/24`, `10.0.0.5:5432`, `10.0.0.0/24:8000-8100`,
/// `fd00::1`, `fd00::/64`, `[fd00::1]:443`, `[fd00::/64]:8000-8100`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalWhitelistEntry {
    pub network: Cidr,
    /// `None` = every port.
    pub ports: Option<PortRange>,
}

impl InternalWhitelistEntry {
    #[must_use]
    pub fn matches(&self, addr: SocketAddr) -> bool {
        self.network.contains(canonical_ip(addr.ip()))
            && self.ports.is_none_or(|ports| ports.contains(addr.port()))
    }
}

impl FromStr for InternalWhitelistEntry {
    type Err = PolicyParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let format_error = || PolicyParseError::new(input, EXPECTED_FORMAT);
        let trimmed = input.trim();
        let (network, ports) = if let Some(bracketed) = trimmed.strip_prefix('[') {
            let (network, rest) = bracketed.split_once(']').ok_or_else(format_error)?;
            let ports = if rest.is_empty() {
                None
            } else {
                Some(rest.strip_prefix(':').ok_or_else(format_error)?)
            };
            (network, ports)
        } else {
            match trimmed.split_once(':') {
                // Exactly one colon: IPv4 with a port. More colons: a bare IPv6 address.
                Some((network, ports)) if !ports.contains(':') => (network, Some(ports)),
                Some(_) | None => (trimmed, None),
            }
        };
        let network = network
            .parse::<Cidr>()
            .map_err(|error| PolicyParseError::new(input, error.reason))?;
        let ports = ports
            .map(str::parse::<PortRange>)
            .transpose()
            .map_err(|error| PolicyParseError::new(input, error.reason))?;
        Ok(Self { network, ports })
    }
}

impl fmt::Display for InternalWhitelistEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ports {
            None => write!(f, "{}", self.network),
            Some(ports) if self.network.network().is_ipv6() => {
                write!(f, "[{}]:{ports}", self.network)
            }
            Some(ports) => write!(f, "{}:{ports}", self.network),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(value: &str) -> InternalWhitelistEntry {
        value.parse().unwrap()
    }

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn parses_all_forms() {
        for (input, rendered) in [
            ("10.0.0.5", "10.0.0.5/32"),
            ("10.0.0.0/24", "10.0.0.0/24"),
            ("10.0.0.5:5432", "10.0.0.5/32:5432"),
            ("10.0.0.0/24:8000-8100", "10.0.0.0/24:8000-8100"),
            ("fd00::1", "fd00::1/128"),
            ("fd00::/64", "fd00::/64"),
            ("[fd00::1]", "fd00::1/128"),
            ("[fd00::1]:443", "[fd00::1/128]:443"),
            ("[fd00::/64]:8000-8100", "[fd00::/64]:8000-8100"),
        ] {
            assert_eq!(entry(input).to_string(), rendered, "{input}");
        }
    }

    #[test]
    fn rejects_malformed_entries() {
        for input in [
            "",
            "10.0.0.5:",
            "10.0.0.5:0",
            "10.0.0.5:70000",
            "10.0.0.5:22-21",
            "[fd00::1",
            "[fd00::1]443",
            "[fd00::1]:",
            "db.internal:5432",
            "10.0.0.0/40",
        ] {
            assert!(
                input.parse::<InternalWhitelistEntry>().is_err(),
                "{input:?} must be rejected"
            );
        }
    }

    #[test]
    fn matches_network_and_ports() {
        let postgres = entry("10.0.0.5:5432");
        assert!(postgres.matches(addr("10.0.0.5:5432")));
        assert!(!postgres.matches(addr("10.0.0.5:22")));
        assert!(!postgres.matches(addr("10.0.0.6:5432")));
        assert!(postgres.matches(addr("[::ffff:10.0.0.5]:5432")));

        let subnet = entry("10.0.0.0/24");
        assert!(subnet.matches(addr("10.0.0.200:22")));
        assert!(!subnet.matches(addr("10.0.1.1:22")));

        let web = entry("[fd00::/64]:8000-8100");
        assert!(web.matches(addr("[fd00::7]:8080")));
        assert!(!web.matches(addr("[fd00::7]:22")));
    }
}
