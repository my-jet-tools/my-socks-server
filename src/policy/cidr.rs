use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::PolicyParseError;

/// An IP network: `10.0.0.0/8`, `fd00::/8`, or a single host (`/32`, `/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Host bits of `addr` are cleared. IPv4-mapped IPv6 networks (`::ffff:a.b.c.d/96+`) are
    /// stored as IPv4, so they match canonicalized addresses. `None` if the prefix is too long.
    #[must_use]
    pub fn new(addr: IpAddr, prefix_len: u8) -> Option<Self> {
        if let IpAddr::V6(v6) = addr
            && prefix_len >= 96
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            return Self::new(IpAddr::V4(v4), prefix_len - 96);
        }
        let network = match addr {
            IpAddr::V4(v4) if prefix_len <= 32 => {
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & v4_mask(prefix_len)))
            }
            IpAddr::V6(v6) if prefix_len <= 128 => {
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & v6_mask(prefix_len)))
            }
            IpAddr::V4(_) | IpAddr::V6(_) => return None,
        };
        Some(Self {
            network,
            prefix_len,
        })
    }

    /// Whether `ip` belongs to the network. Callers pass canonical addresses (see
    /// [`canonical_ip`](super::canonical_ip)); IPv4 never matches an IPv6 network and vice versa.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                (u32::from(ip) & v4_mask(self.prefix_len)) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                (u128::from(ip) & v6_mask(self.prefix_len)) == u128::from(network)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }

    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

fn v4_mask(prefix_len: u8) -> u32 {
    u32::MAX
        .checked_shl(32_u32.saturating_sub(u32::from(prefix_len)))
        .unwrap_or(0)
}

fn v6_mask(prefix_len: u8) -> u128 {
    u128::MAX
        .checked_shl(128_u32.saturating_sub(u32::from(prefix_len)))
        .unwrap_or(0)
}

impl FromStr for Cidr {
    type Err = PolicyParseError;

    /// `a.b.c.d`, `a.b.c.d/n`, `x::y`, `x::y/n`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        let (addr, prefix) = match trimmed.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (trimmed, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| PolicyParseError::new(input, "expected an IP address or CIDR"))?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix {
            None => max_prefix,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max_prefix)
                .ok_or_else(|| PolicyParseError::new(input, "invalid prefix length"))?,
        };
        Self::new(addr, prefix_len)
            .ok_or_else(|| PolicyParseError::new(input, "invalid prefix length"))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(value: &str) -> Cidr {
        value.parse().unwrap()
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn parses_and_normalizes() {
        assert_eq!(cidr("10.1.2.3/8").to_string(), "10.0.0.0/8");
        assert_eq!(cidr("192.0.2.7").to_string(), "192.0.2.7/32");
        assert_eq!(cidr(" fd00::1/8 ").to_string(), "fd00::/8");
        assert_eq!(cidr("2001:db8::1").to_string(), "2001:db8::1/128");
        assert_eq!(cidr("0.0.0.0/0").to_string(), "0.0.0.0/0");
    }

    #[test]
    fn maps_ipv4_mapped_networks_to_ipv4() {
        assert_eq!(cidr("::ffff:10.0.0.0/104").to_string(), "10.0.0.0/8");
        assert!(cidr("::ffff:127.0.0.1").contains(ip("127.0.0.1")));
    }

    #[test]
    fn rejects_invalid_input() {
        for input in [
            "",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "10.0.0",
            "example.com",
            "10.0.0.0/8/8",
        ] {
            assert!(input.parse::<Cidr>().is_err(), "{input:?} must be rejected");
        }
    }

    #[test]
    fn membership() {
        let private = cidr("172.16.0.0/12");
        assert!(private.contains(ip("172.16.0.1")));
        assert!(private.contains(ip("172.31.255.255")));
        assert!(!private.contains(ip("172.32.0.0")));
        assert!(
            !private.contains(ip("::ffff:172.16.0.1")),
            "callers canonicalize"
        );

        assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(!cidr("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(cidr("::/0").contains(ip("2001:db8::1")));

        let host = cidr("10.0.0.5");
        assert!(host.contains(ip("10.0.0.5")));
        assert!(!host.contains(ip("10.0.0.6")));

        let v6 = cidr("fd00:10::/64");
        assert!(v6.contains(ip("fd00:10::abcd")));
        assert!(!v6.contains(ip("fd00:11::1")));
    }
}
