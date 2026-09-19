use std::fmt;
use std::str::FromStr;

use super::PolicyParseError;

/// Inclusive range of TCP ports (`443` or `8000-8100`), never containing port 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    first: u16,
    last: u16,
}

impl PortRange {
    #[must_use]
    pub fn contains(self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

impl FromStr for PortRange {
    type Err = PolicyParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let parse_port = |value: &str| value.trim().parse::<u16>().ok().filter(|port| *port != 0);
        let (first, last) = match input.split_once('-') {
            Some((first, last)) => (parse_port(first), parse_port(last)),
            None => (parse_port(input), parse_port(input)),
        };
        match (first, last) {
            (Some(first), Some(last)) if first <= last => Ok(Self { first, last }),
            _ => Err(PolicyParseError::new(
                input,
                "expected a port 1-65535 or a range like 8000-8100",
            )),
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ports_and_ranges() {
        let single: PortRange = "5432".parse().unwrap();
        assert!(single.contains(5432));
        assert!(!single.contains(5433));
        assert_eq!(single.to_string(), "5432");

        let range: PortRange = "8000-8100".parse().unwrap();
        assert!(range.contains(8000));
        assert!(range.contains(8100));
        assert!(!range.contains(7999));
        assert!(!range.contains(8101));
        assert_eq!(range.to_string(), "8000-8100");
    }

    #[test]
    fn rejects_invalid_ports() {
        for input in ["", "0", "65536", "-1", "80-70", "a", "1-", "-5", "1-2-3"] {
            assert!(
                input.parse::<PortRange>().is_err(),
                "{input:?} must be rejected"
            );
        }
    }
}
