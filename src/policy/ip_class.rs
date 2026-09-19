use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Kind of network an address belongs to, as far as the destination policy is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    /// Globally routable: always allowed (subject to blocked ports).
    Public,
    /// Private networks: `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT),
    /// `fc00::/7` (ULA), `fec0::/10` (deprecated site-local).
    /// Opened by `allow_internal` or `internal_whitelist`.
    Private,
    /// `169.254/16` (including cloud metadata `169.254.169.254`) and `fe80::/10`.
    /// Opened only by `internal_whitelist`.
    LinkLocal,
    /// `127/8` and `::1`: services of the proxy host itself. Opened only by `internal_whitelist`.
    Loopback,
    /// Never a valid destination: `0/8` (Linux connects `0.0.0.0` to localhost), multicast,
    /// `240/4` including broadcast, `::`, deprecated IPv4-compatible `::a.b.c.d`.
    Reserved,
}

impl IpClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::Loopback => "loopback",
            Self::Reserved => "reserved",
        }
    }
}

/// `::ffff:a.b.c.d` becomes `a.b.c.d`; everything else is returned unchanged.
#[must_use]
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Classifies an address; IPv4-mapped IPv6 is judged as the IPv4 address it maps to.
#[must_use]
pub fn classify_ip(ip: IpAddr) -> IpClass {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    let [first, second, _, _] = ip.octets();
    if first == 0 || first >= 224 {
        IpClass::Reserved
    } else if ip.is_loopback() {
        IpClass::Loopback
    } else if ip.is_link_local() {
        IpClass::LinkLocal
    } else if ip.is_private() || (first == 100 && (second & 0xC0) == 64) {
        IpClass::Private
    } else {
        IpClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    let segments = ip.segments();
    if ip.is_loopback() {
        return IpClass::Loopback;
    }
    if segments[..6] == [0; 6] {
        // `::` and IPv4-compatible `::a.b.c.d`, which a SIT tunnel may deliver to IPv4.
        return IpClass::Reserved;
    }
    if let Some(embedded) = embedded_ipv4(segments) {
        // NAT64 and 6to4 addresses reach an IPv4 host: judge that host.
        return classify_v4(embedded);
    }
    let first = segments[0];
    if ip.is_multicast() {
        IpClass::Reserved
    } else if (first & 0xFE00) == 0xFC00 || (first & 0xFFC0) == 0xFEC0 {
        IpClass::Private
    } else if (first & 0xFFC0) == 0xFE80 {
        IpClass::LinkLocal
    } else {
        IpClass::Public
    }
}

/// IPv4 address carried by NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) addresses.
fn embedded_ipv4(segments: [u16; 8]) -> Option<Ipv4Addr> {
    match segments {
        [0x0064, 0xFF9B, 0, 0, 0, 0, high, low] | [0x2002, high, low, ..] => {
            Some(Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(value: &str) -> IpClass {
        classify_ip(value.parse().unwrap())
    }

    #[test]
    fn ipv4_ranges() {
        for (addr, expected) in [
            ("8.8.8.8", IpClass::Public),
            ("1.1.1.1", IpClass::Public),
            ("100.63.255.255", IpClass::Public),
            ("100.128.0.0", IpClass::Public),
            ("172.15.255.255", IpClass::Public),
            ("172.32.0.0", IpClass::Public),
            ("223.255.255.255", IpClass::Public),
            ("10.0.0.1", IpClass::Private),
            ("172.16.0.1", IpClass::Private),
            ("172.31.255.254", IpClass::Private),
            ("192.168.1.1", IpClass::Private),
            ("100.64.0.1", IpClass::Private),
            ("100.127.255.255", IpClass::Private),
            ("169.254.169.254", IpClass::LinkLocal),
            ("127.0.0.1", IpClass::Loopback),
            ("127.255.255.254", IpClass::Loopback),
            ("0.0.0.0", IpClass::Reserved),
            ("0.1.2.3", IpClass::Reserved),
            ("224.0.0.1", IpClass::Reserved),
            ("239.255.255.250", IpClass::Reserved),
            ("240.0.0.1", IpClass::Reserved),
            ("255.255.255.255", IpClass::Reserved),
        ] {
            assert_eq!(class(addr), expected, "{addr}");
        }
    }

    #[test]
    fn ipv6_ranges() {
        for (addr, expected) in [
            ("2001:4860:4860::8888", IpClass::Public),
            ("2606:4700::1111", IpClass::Public),
            ("::1", IpClass::Loopback),
            ("::", IpClass::Reserved),
            ("fc00::1", IpClass::Private),
            ("fd12:3456::1", IpClass::Private),
            ("fec0::1", IpClass::Private),
            ("fe80::1", IpClass::LinkLocal),
            ("febf::1", IpClass::LinkLocal),
            ("ff02::1", IpClass::Reserved),
            ("ff05::2", IpClass::Reserved),
        ] {
            assert_eq!(class(addr), expected, "{addr}");
        }
    }

    #[test]
    fn ipv4_mapped_addresses_are_judged_as_ipv4() {
        assert_eq!(class("::ffff:127.0.0.1"), IpClass::Loopback);
        assert_eq!(class("::ffff:10.0.0.1"), IpClass::Private);
        assert_eq!(class("::ffff:169.254.169.254"), IpClass::LinkLocal);
        assert_eq!(class("::ffff:0.0.0.0"), IpClass::Reserved);
        assert_eq!(class("::ffff:8.8.8.8"), IpClass::Public);
        assert_eq!(
            canonical_ip("::ffff:127.0.0.1".parse().unwrap()),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv4_compatible_addresses_are_reserved() {
        assert_eq!(class("::127.0.0.1"), IpClass::Reserved);
        assert_eq!(class("::8.8.8.8"), IpClass::Reserved);
    }

    #[test]
    fn nat64_and_6to4_follow_the_embedded_ipv4() {
        assert_eq!(class("64:ff9b::7f00:1"), IpClass::Loopback);
        assert_eq!(class("64:ff9b::a00:1"), IpClass::Private);
        assert_eq!(class("64:ff9b::808:808"), IpClass::Public);
        assert_eq!(class("2002:7f00:1::"), IpClass::Loopback);
        assert_eq!(class("2002:a9fe:a9fe::1"), IpClass::LinkLocal);
        assert_eq!(class("2002:808:808::1"), IpClass::Public);
    }
}
