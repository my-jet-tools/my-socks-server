use std::net::IpAddr;

use super::{Cidr, canonical_ip};

/// `client_whitelist`: when not empty, only clients from these networks may connect;
/// everyone else is dropped right after `accept()`, before any SOCKS byte is read.
#[derive(Debug, Clone, Default)]
pub struct ClientAcl {
    networks: Vec<Cidr>,
}

impl ClientAcl {
    #[must_use]
    pub fn new(networks: Vec<Cidr>) -> Self {
        Self { networks }
    }

    #[must_use]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.networks.is_empty() || self.networks.iter().any(|network| network.contains(ip))
    }

    /// No whitelist: any client may connect.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.networks.is_empty()
    }

    #[must_use]
    pub fn networks(&self) -> &[Cidr] {
        &self.networks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn empty_whitelist_allows_everyone() {
        let acl = ClientAcl::default();
        assert!(acl.is_open());
        assert!(acl.is_allowed(ip("203.0.113.1")));
    }

    #[test]
    fn whitelist_restricts_clients() {
        let acl = ClientAcl::new(vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);
        assert!(acl.is_allowed(ip("203.0.113.77")));
        assert!(
            acl.is_allowed(ip("::ffff:203.0.113.77")),
            "dual-stack listener"
        );
        assert!(acl.is_allowed(ip("2001:db8:1::5")));
        assert!(!acl.is_allowed(ip("198.51.100.1")));
        assert!(!acl.is_allowed(ip("2001:db9::1")));
    }
}
