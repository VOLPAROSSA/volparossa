//! Runtime paths supplied by packaging through bounded environment variables.

use std::{
    env,
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

/// Packaged configuration file.
pub const DEFAULT_CONFIG: &str = "/etc/volparossa/config.yaml";
/// Packaged persistent state directory.
pub const DEFAULT_STATE_DIRECTORY: &str = "/var/lib/volparossa";
/// Group-controlled CLI-to-agent socket.
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/volparossa/control/agent.sock";
/// Root-helper socket, inaccessible to ordinary control users.
pub const DEFAULT_HELPER_SOCKET: &str = "/run/volparossa/helper.sock";
/// Native MPQUIC process socket.
pub const DEFAULT_MPQUIC_SOCKET: &str = "/run/volparossa/native/mpquic.sock";
/// Fixed systemd credential name containing only the identity passphrase.
pub const IDENTITY_CREDENTIAL_NAME: &str = "identity-passphrase";

const DEFAULT_CREDENTIAL_DIRECTORY: &str = "/run/credentials/volparossa-agent.service";
const MAX_PATH_BYTES: usize = 4_096;

/// Every filesystem endpoint used by the unprivileged service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPaths {
    /// Strict YAML configuration.
    pub config: PathBuf,
    /// Private persistent state root.
    pub state_directory: PathBuf,
    /// CLI control socket.
    pub control_socket: PathBuf,
    /// Privileged helper socket.
    pub helper_socket: PathBuf,
    /// Helper-issued process-lifetime cleanup token.
    pub helper_token: PathBuf,
    /// Native MPQUIC socket.
    pub mpquic_socket: PathBuf,
    /// Encrypted permanent identity.
    pub identity: PathBuf,
    /// systemd credential containing the identity passphrase.
    pub identity_credential: PathBuf,
    /// Privacy-minimising `SQLite` peerstore.
    pub peerstore: PathBuf,
    /// Atomic runtime role state.
    pub roles: PathBuf,
    /// Root-provisioned policy trust anchors next to the configuration.
    pub policy_trust: PathBuf,
}

impl AgentPaths {
    /// Loads only documented packaging variables. Secrets are never accepted
    /// through arguments or environment values.
    ///
    /// # Errors
    ///
    /// Returns an error if a packaged environment path is not an absolute, bounded, normal path.
    pub fn from_environment() -> Result<Self, PathError> {
        let config = environment_path("VOLPAROSSA_CONFIG", DEFAULT_CONFIG)?;
        let state_directory =
            environment_path("VOLPAROSSA_STATE_DIRECTORY", DEFAULT_STATE_DIRECTORY)?;
        let control_socket = environment_path("VOLPAROSSA_CONTROL_SOCKET", DEFAULT_CONTROL_SOCKET)?;
        let helper_socket = environment_path("VOLPAROSSA_HELPER_SOCKET", DEFAULT_HELPER_SOCKET)?;
        let mpquic_socket = environment_path("VOLPAROSSA_MPQUIC_SOCKET", DEFAULT_MPQUIC_SOCKET)?;
        let credential_directory = match env::var_os("CREDENTIALS_DIRECTORY") {
            Some(value) => checked_path("CREDENTIALS_DIRECTORY", value.as_os_str())?,
            None => PathBuf::from(DEFAULT_CREDENTIAL_DIRECTORY),
        };
        let helper_parent = helper_socket
            .parent()
            .ok_or(PathError::MissingParent("VOLPAROSSA_HELPER_SOCKET"))?;
        let config_parent = config
            .parent()
            .ok_or(PathError::MissingParent("VOLPAROSSA_CONFIG"))?;
        Ok(Self {
            identity: state_directory.join("identity.key"),
            identity_credential: credential_directory.join(IDENTITY_CREDENTIAL_NAME),
            peerstore: state_directory.join("peers.sqlite3"),
            roles: state_directory.join("roles.json"),
            policy_trust: config_parent.join("policy-maintainers.json"),
            helper_token: helper_parent.join("helper.cleanup-token"),
            config,
            state_directory,
            control_socket,
            helper_socket,
            mpquic_socket,
        })
    }

    /// Validates a caller-constructed path set, primarily for isolated tests.
    ///
    /// # Errors
    ///
    /// Returns an error when any path is not an absolute, bounded, normal path.
    pub fn validate(&self) -> Result<(), PathError> {
        for (name, value) in [
            ("VOLPAROSSA_CONFIG", self.config.as_path()),
            ("VOLPAROSSA_STATE_DIRECTORY", self.state_directory.as_path()),
            ("VOLPAROSSA_CONTROL_SOCKET", self.control_socket.as_path()),
            ("VOLPAROSSA_HELPER_SOCKET", self.helper_socket.as_path()),
            ("VOLPAROSSA_MPQUIC_SOCKET", self.mpquic_socket.as_path()),
            ("identity", self.identity.as_path()),
            ("identity credential", self.identity_credential.as_path()),
            ("peerstore", self.peerstore.as_path()),
            ("roles", self.roles.as_path()),
            ("policy trust", self.policy_trust.as_path()),
            ("helper token", self.helper_token.as_path()),
        ] {
            checked_path(name, value.as_os_str())?;
        }
        Ok(())
    }
}

fn environment_path(name: &'static str, fallback: &str) -> Result<PathBuf, PathError> {
    match env::var_os(name) {
        Some(value) => checked_path(name, value.as_os_str()),
        None => Ok(PathBuf::from(fallback)),
    }
}

fn checked_path(name: &'static str, value: &OsStr) -> Result<PathBuf, PathError> {
    if value.as_bytes().is_empty() || value.as_bytes().len() > MAX_PATH_BYTES {
        return Err(PathError::Invalid(name));
    }
    let path = Path::new(value);
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(PathError::Invalid(name));
    }
    Ok(path.to_owned())
}

/// Invalid packaged path configuration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PathError {
    /// A path was empty, relative, oversized, root, or contained traversal.
    #[error("invalid absolute path in {0}")]
    Invalid(&'static str),
    /// A configured file or socket had no parent.
    #[error("configured path in {0} has no parent")]
    MissingParent(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_absolute_and_separate_privilege_boundaries() {
        let paths = AgentPaths::from_environment().expect("default paths");
        paths.validate().expect("valid paths");
        assert_ne!(paths.control_socket.parent(), paths.helper_socket.parent());
        assert!(paths.identity.ends_with("identity.key"));
        assert!(
            paths
                .identity_credential
                .ends_with(IDENTITY_CREDENTIAL_NAME)
        );
    }

    #[test]
    fn traversal_and_root_are_rejected() {
        assert_eq!(
            checked_path("test", OsStr::new("/tmp/../etc")),
            Err(PathError::Invalid("test"))
        );
        assert_eq!(
            checked_path("test", OsStr::new("/")),
            Err(PathError::Invalid("test"))
        );
    }
}
