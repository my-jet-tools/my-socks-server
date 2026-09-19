/// A CIDR, port range or whitelist entry that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{input}': {reason}")]
pub struct PolicyParseError {
    pub input: String,
    pub reason: &'static str,
}

impl PolicyParseError {
    #[must_use]
    pub fn new(input: &str, reason: &'static str) -> Self {
        Self {
            input: input.to_owned(),
            reason,
        }
    }
}
