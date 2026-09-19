use std::fs;
use std::path::{Path, PathBuf};

use super::{ConfigError, SettingsModel};

/// Settings file in the home directory, same convention as `~/.mynosqlserver`.
pub const SETTINGS_FILE_NAME: &str = ".mysocksserver";

/// `$HOME/.mysocksserver`.
///
/// # Errors
/// `HOME` is not set.
pub fn settings_file_path() -> Result<PathBuf, ConfigError> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or(ConfigError::HomeNotSet)?;
    Ok(PathBuf::from(home).join(SETTINGS_FILE_NAME))
}

/// Reads and parses the settings file.
///
/// # Errors
/// The file cannot be read, or it is not valid settings YAML.
pub fn read_settings(path: &Path) -> Result<SettingsModel, ConfigError> {
    let content = fs::read(path).map_err(|error| ConfigError::Read {
        path: path.to_path_buf(),
        error,
    })?;
    SettingsModel::from_yaml(&content).map_err(|error| ConfigError::Parse {
        path: path.to_path_buf(),
        error,
    })
}

/// Whether users other than the owner may read the file (it holds passwords).
#[cfg(unix)]
#[must_use]
pub fn is_readable_by_others(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|metadata| (metadata.permissions().mode() & 0o077) != 0)
}
