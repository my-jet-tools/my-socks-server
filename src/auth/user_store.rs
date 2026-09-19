use std::fmt;

use subtle::ConstantTimeEq;

use super::UserCredentials;

/// Longest username or password RFC 1929 can carry (one length byte).
pub const MAX_CREDENTIAL_LEN: usize = 255;

/// Length byte + up to 255 bytes of value, zero padded.
const BLOCK_LEN: usize = MAX_CREDENTIAL_LEN + 1;

/// Invalid user list in the settings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("at least one user is required")]
    NoUsers,
    #[error("user #{index}: username must be 1..=255 bytes")]
    InvalidUsername { index: usize },
    #[error("user '{username}': password must be 1..=255 bytes")]
    InvalidPassword { username: String },
    #[error("username '{0}' is listed more than once")]
    DuplicateUsername(String),
}

#[derive(Clone)]
struct StoredUser {
    name: String,
    username: [u8; BLOCK_LEN],
    password: [u8; BLOCK_LEN],
}

/// Checks username/password pairs in constant time.
///
/// Every value is kept as a fixed 256-byte block (length byte + zero padding), so each
/// comparison touches the same number of bytes: timing reveals neither where a guess diverges
/// nor the length of a password. Every attempt is compared against all users, so timing does
/// not reveal whether a username exists either.
#[derive(Clone)]
pub struct UserStore {
    users: Vec<StoredUser>,
}

impl UserStore {
    /// # Errors
    /// Empty list, empty or over-long usernames/passwords, duplicate usernames.
    pub fn new(credentials: &[UserCredentials]) -> Result<Self, CredentialError> {
        if credentials.is_empty() {
            return Err(CredentialError::NoUsers);
        }
        let mut users: Vec<StoredUser> = Vec::with_capacity(credentials.len());
        for (index, credential) in credentials.iter().enumerate() {
            let username = to_block(credential.username.as_bytes())
                .ok_or(CredentialError::InvalidUsername { index })?;
            let password = to_block(credential.password.as_bytes()).ok_or_else(|| {
                CredentialError::InvalidPassword {
                    username: credential.username.clone(),
                }
            })?;
            if users.iter().any(|user| user.name == credential.username) {
                return Err(CredentialError::DuplicateUsername(
                    credential.username.clone(),
                ));
            }
            users.push(StoredUser {
                name: credential.username.clone(),
                username,
                password,
            });
        }
        Ok(Self { users })
    }

    /// Returns the username when the pair matches a configured user.
    #[must_use]
    pub fn verify(&self, username: &[u8], password: &[u8]) -> Option<&str> {
        // Empty or over-long input cannot match; it is compared as an all-zero block, which
        // differs from every stored block in the length byte, so the work stays the same.
        let username = to_block(username).unwrap_or([0; BLOCK_LEN]);
        let password = to_block(password).unwrap_or([0; BLOCK_LEN]);
        let mut matched = None;
        for user in &self.users {
            let is_match = user.username.as_slice().ct_eq(username.as_slice())
                & user.password.as_slice().ct_eq(password.as_slice());
            if bool::from(is_match) {
                matched = Some(user.name.as_str());
            }
        }
        matched
    }

    pub fn usernames(&self) -> impl Iterator<Item = &str> {
        self.users.iter().map(|user| user.name.as_str())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.users.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

impl fmt::Debug for UserStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserStore")
            .field("users", &self.usernames().collect::<Vec<_>>())
            .finish()
    }
}

fn to_block(value: &[u8]) -> Option<[u8; BLOCK_LEN]> {
    let len = u8::try_from(value.len()).ok().filter(|len| *len > 0)?;
    let mut block = [0; BLOCK_LEN];
    block[0] = len;
    block[1..=value.len()].copy_from_slice(value);
    Some(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(username: &str, password: &str) -> UserCredentials {
        UserCredentials {
            username: username.into(),
            password: password.into(),
        }
    }

    fn store() -> UserStore {
        UserStore::new(&[user("alice", "correct horse"), user("bob", "b0b")]).unwrap()
    }

    #[test]
    fn accepts_valid_pairs() {
        let store = store();
        assert_eq!(store.verify(b"alice", b"correct horse"), Some("alice"));
        assert_eq!(store.verify(b"bob", b"b0b"), Some("bob"));
    }

    #[test]
    fn rejects_wrong_pairs() {
        let store = store();
        for (username, password) in [
            (&b"alice"[..], &b"correct hors"[..]),
            (b"alice", b"correct horse "),
            (b"alice", b"b0b"),
            (b"bob", b"correct horse"),
            (b"carol", b"b0b"),
            (b"", b""),
            (b"alice", b""),
        ] {
            assert_eq!(store.verify(username, password), None);
        }
    }

    #[test]
    fn rejects_over_long_input() {
        let long = vec![b'a'; 300];
        assert_eq!(store().verify(&long, &long), None);
    }

    #[test]
    fn accepts_maximum_length_values() {
        let long = "p".repeat(MAX_CREDENTIAL_LEN);
        let store = UserStore::new(&[user(&long, &long)]).unwrap();
        assert_eq!(
            store.verify(long.as_bytes(), long.as_bytes()),
            Some(long.as_str())
        );
    }

    #[test]
    fn validates_user_list() {
        assert_eq!(UserStore::new(&[]).err(), Some(CredentialError::NoUsers));
        assert_eq!(
            UserStore::new(&[user("", "x")]).err(),
            Some(CredentialError::InvalidUsername { index: 0 })
        );
        assert!(matches!(
            UserStore::new(&[user("a", "")]).err(),
            Some(CredentialError::InvalidPassword { .. })
        ));
        assert!(matches!(
            UserStore::new(&[user("a", &"x".repeat(256))]).err(),
            Some(CredentialError::InvalidPassword { .. })
        ));
        assert_eq!(
            UserStore::new(&[user("a", "1"), user("a", "2")]).err(),
            Some(CredentialError::DuplicateUsername("a".into()))
        );
    }

    #[test]
    fn debug_output_has_no_passwords() {
        let rendered = format!("{:?}", store());
        assert!(rendered.contains("alice"));
        assert!(!rendered.contains("correct horse"));
        let rendered = format!("{:?}", user("alice", "hunter2"));
        assert!(!rendered.contains("hunter2"));
    }
}
