use std::io;
use std::path::PathBuf;

use super::SETTINGS_FILE_NAME;

/// Settings problem found at startup; the message names the file or the key to fix.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("HOME is not set, cannot locate ~/{SETTINGS_FILE_NAME}")]
    HomeNotSet,
    #[error("cannot read settings file {}: {error}", path.display())]
    Read { path: PathBuf, error: io::Error },
    #[error("invalid settings file {}: {error}", path.display())]
    Parse {
        path: PathBuf,
        error: serde_yaml::Error,
    },
    #[error("invalid setting `{key}`: {reason}")]
    Invalid { key: &'static str, reason: String },
}
