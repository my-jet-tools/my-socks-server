use std::fmt;
use std::net::SocketAddr;

use super::{InternalWhitelistEntry, IpClass, classify_ip};

/// Why a destination was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Port 0 or a port listed in `blocked_ports`.
    BlockedPort(u16),
    /// Special-purpose address that is never a valid destination.
    ReservedAddress,
    /// Internal address not opened by `allow_internal` or `internal_whitelist`.
    InternalAddress(IpClass),
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockedPort(port) => write!(f, "port {port} is blocked"),
            Self::ReservedAddress => f.write_str("reserved address"),
            Self::InternalAddress(IpClass::Private) => {
                f.write_str("private address (allow_internal or internal_whitelist opens it)")
            }
            Self::InternalAddress(class) => write!(
                f,
                "{} address (only an internal_whitelist entry opens it)",
                class.as_str()
            ),
        }
    }
}

/// Which destinations the proxy may connect to.
///
/// Decisions are made on the address the socket actually connects to, after DNS resolution,
/// so a name that resolves (or re-resolves) to an internal address cannot bypass them.
///
/// | address class                          | allowed when                                   |
/// |----------------------------------------|------------------------------------------------|
/// | public                                 | always                                         |
/// | private (`10/8`, `172.16/12`, ...)     | `allow_internal` or an `internal_whitelist` hit |
/// | loopback, link-local                   | an `internal_whitelist` hit                    |
/// | reserved (`0/8`, multicast, ...)       | never                                          |
///
/// `blocked_ports` apply to every destination, whitelisted ones included.
#[derive(Debug, Clone)]
pub struct DestinationPolicy {
    blocked_ports: Vec<u16>,
    allow_internal: bool,
    internal_whitelist: Vec<InternalWhitelistEntry>,
}

impl DestinationPolicy {
    #[must_use]
    pub fn new(
        blocked_ports: Vec<u16>,
        allow_internal: bool,
        internal_whitelist: Vec<InternalWhitelistEntry>,
    ) -> Self {
        Self {
            blocked_ports,
            allow_internal,
            internal_whitelist,
        }
    }

    /// # Errors
    /// The reason the destination is refused.
    pub fn check(&self, addr: SocketAddr) -> Result<(), DenyReason> {
        let port = addr.port();
        if port == 0 || self.blocked_ports.contains(&port) {
            return Err(DenyReason::BlockedPort(port));
        }
        match classify_ip(addr.ip()) {
            IpClass::Public => Ok(()),
            IpClass::Reserved => Err(DenyReason::ReservedAddress),
            IpClass::Private if self.allow_internal => Ok(()),
            class @ (IpClass::Private | IpClass::LinkLocal | IpClass::Loopback) => {
                if self.is_whitelisted(addr) {
                    Ok(())
                } else {
                    Err(DenyReason::InternalAddress(class))
                }
            }
        }
    }

    fn is_whitelisted(&self, addr: SocketAddr) -> bool {
        self.internal_whitelist
            .iter()
            .any(|entry| entry.matches(addr))
    }

    #[must_use]
    pub fn blocked_ports(&self) -> &[u16] {
        &self.blocked_ports
    }

    #[must_use]
    pub fn allow_internal(&self) -> bool {
        self.allow_internal
    }

    #[must_use]
    pub fn internal_whitelist(&self) -> &[InternalWhitelistEntry] {
        &self.internal_whitelist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow_internal: bool, whitelist: &[&str]) -> DestinationPolicy {
        DestinationPolicy::new(
            vec![25],
            allow_internal,
            whitelist
                .iter()
                .map(|entry| entry.parse().unwrap())
                .collect(),
        )
    }

    fn check(policy: &DestinationPolicy, addr: &str) -> Result<(), DenyReason> {
        policy.check(addr.parse().unwrap())
    }

    #[test]
    fn public_destinations_are_allowed() {
        let policy = policy(false, &[]);
        assert_eq!(check(&policy, "93.184.216.34:443"), Ok(()));
        assert_eq!(check(&policy, "[2606:4700::1111]:443"), Ok(()));
    }

    #[test]
    fn blocked_ports_apply_everywhere() {
        let policy = policy(true, &["127.0.0.1"]);
        assert_eq!(
            check(&policy, "93.184.216.34:25"),
            Err(DenyReason::BlockedPort(25))
        );
        assert_eq!(
            check(&policy, "10.0.0.1:25"),
            Err(DenyReason::BlockedPort(25))
        );
        assert_eq!(
            check(&policy, "127.0.0.1:25"),
            Err(DenyReason::BlockedPort(25))
        );
        assert_eq!(
            check(&policy, "93.184.216.34:0"),
            Err(DenyReason::BlockedPort(0))
        );
    }

    #[test]
    fn internal_destinations_are_denied_by_default() {
        let policy = policy(false, &[]);
        for (addr, class) in [
            ("10.1.2.3:80", IpClass::Private),
            ("192.168.0.1:80", IpClass::Private),
            ("100.64.0.1:80", IpClass::Private),
            ("[fd00::1]:80", IpClass::Private),
            ("127.0.0.1:80", IpClass::Loopback),
            ("[::1]:80", IpClass::Loopback),
            ("[::ffff:127.0.0.1]:80", IpClass::Loopback),
            ("169.254.169.254:80", IpClass::LinkLocal),
            ("[fe80::1]:80", IpClass::LinkLocal),
        ] {
            assert_eq!(
                check(&policy, addr),
                Err(DenyReason::InternalAddress(class)),
                "{addr}"
            );
        }
    }

    #[test]
    fn allow_internal_opens_private_networks_only() {
        let policy = policy(true, &[]);
        assert_eq!(check(&policy, "10.1.2.3:5432"), Ok(()));
        assert_eq!(check(&policy, "172.20.0.1:80"), Ok(()));
        assert_eq!(check(&policy, "[fd00::1]:80"), Ok(()));
        assert_eq!(check(&policy, "[::ffff:192.168.1.1]:80"), Ok(()));
        assert_eq!(
            check(&policy, "127.0.0.1:80"),
            Err(DenyReason::InternalAddress(IpClass::Loopback))
        );
        assert_eq!(
            check(&policy, "169.254.169.254:80"),
            Err(DenyReason::InternalAddress(IpClass::LinkLocal))
        );
    }

    #[test]
    fn whitelist_opens_exactly_the_listed_destinations() {
        let policy = policy(
            false,
            &[
                "10.20.0.5:5432",
                "10.30.0.0/24",
                "127.0.0.1:8080",
                "[fd00:1::/64]:443",
            ],
        );
        assert_eq!(check(&policy, "10.20.0.5:5432"), Ok(()));
        assert_eq!(
            check(&policy, "10.20.0.5:22"),
            Err(DenyReason::InternalAddress(IpClass::Private))
        );
        assert_eq!(check(&policy, "10.30.0.77:22"), Ok(()));
        assert_eq!(
            check(&policy, "10.31.0.1:22"),
            Err(DenyReason::InternalAddress(IpClass::Private))
        );
        assert_eq!(check(&policy, "127.0.0.1:8080"), Ok(()));
        assert_eq!(check(&policy, "[::ffff:127.0.0.1]:8080"), Ok(()));
        assert_eq!(
            check(&policy, "127.0.0.1:22"),
            Err(DenyReason::InternalAddress(IpClass::Loopback))
        );
        assert_eq!(check(&policy, "[fd00:1::9]:443"), Ok(()));
        assert_eq!(
            check(&policy, "[fd00:1::9]:80"),
            Err(DenyReason::InternalAddress(IpClass::Private))
        );
    }

    #[test]
    fn reserved_addresses_cannot_be_whitelisted() {
        let policy = policy(true, &["0.0.0.0/0", "::/0"]);
        for addr in [
            "0.0.0.0:80",
            "224.0.0.1:80",
            "255.255.255.255:80",
            "[::]:80",
            "[::127.0.0.1]:80",
            "[ff02::1]:80",
        ] {
            assert_eq!(
                check(&policy, addr),
                Err(DenyReason::ReservedAddress),
                "{addr}"
            );
        }
        assert_eq!(
            check(&policy, "127.0.0.1:80"),
            Ok(()),
            "0.0.0.0/0 covers loopback"
        );
    }
}
