use std::fmt;

/// A proxy user from the settings file.
#[derive(Clone, PartialEq, Eq)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for UserCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}
