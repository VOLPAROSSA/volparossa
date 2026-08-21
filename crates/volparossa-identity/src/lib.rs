//! Permanent node identities and encrypted local key storage.
//!
//! VOLPAROSSA uses one long-lived Ed25519 identity per node. This crate keeps
//! that identity in a small, versioned, authenticated envelope encrypted with a
//! key derived from an operator-supplied passphrase. Files are opened without
//! following symlinks, must be regular single-link files, and must have mode
//! `0600` before any encrypted content is processed.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use libp2p_identity::KeyType;
pub use libp2p_identity::{Keypair, PeerId, PublicKey};
use rand_core::{OsRng, RngCore};
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;
use zeroize::Zeroizing;

/// Required permissions for every persisted identity file.
pub const KEY_FILE_MODE: u32 = 0o600;

/// Smallest accepted passphrase, measured in bytes.
pub const MIN_PASSPHRASE_BYTES: usize = 16;

/// Largest accepted passphrase, measured in bytes.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

/// Maximum encrypted identity-file size accepted from disk.
pub const MAX_KEY_FILE_BYTES: usize = 4096;

const FORMAT_MAGIC: &[u8; 8] = b"VLPIDKEY";
const FORMAT_VERSION: u8 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const LENGTH_BYTES: usize = 4;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = FORMAT_MAGIC.len() + 1 + SALT_BYTES + NONCE_BYTES + LENGTH_BYTES;
const MAX_PRIVATE_KEY_BYTES: usize = 1024;
const DERIVED_KEY_BYTES: usize = 32;

// Argon2's documented default profile: Argon2id v1.3, 19 MiB, two passes,
// one lane. The format version fixes these parameters, preventing an input file
// from selecting attacker-controlled resource costs.
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_LANES: u32 = 1;

/// Errors produced while creating, loading, or rotating a node identity.
///
/// Error messages never contain passphrases, plaintext private-key bytes, or
/// ciphertext contents.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// The passphrase violates the bounded length policy.
    #[error("passphrase length {actual} is outside the allowed range {minimum}..={maximum} bytes")]
    InvalidPassphraseLength {
        /// Supplied length in bytes.
        actual: usize,
        /// Minimum accepted length in bytes.
        minimum: usize,
        /// Maximum accepted length in bytes.
        maximum: usize,
    },

    /// The supplied libp2p key is not an Ed25519 key.
    #[error("VOLPAROSSA node identities must use Ed25519")]
    UnexpectedKeyType,

    /// libp2p rejected private-key serialization.
    #[error("failed to encode the Ed25519 identity")]
    IdentityEncoding,

    /// The Ed25519 identity could not sign a control-plane message.
    #[error("failed to create an Ed25519 identity signature")]
    Signing,

    /// Decrypted key material was not a valid libp2p Ed25519 key.
    #[error("decrypted identity is not a valid Ed25519 key")]
    IdentityDecoding,

    /// The encrypted file has a malformed or non-canonical envelope.
    #[error("invalid encrypted identity format: {reason}")]
    InvalidFormat {
        /// Non-sensitive format failure description.
        reason: &'static str,
    },

    /// The encrypted file uses an unsupported format version.
    #[error("unsupported encrypted identity format version {0}")]
    UnsupportedFormatVersion(u8),

    /// The file is too small or too large to be a valid identity envelope.
    #[error("identity file size {actual} is outside the allowed range {minimum}..={maximum} bytes")]
    InvalidFileSize {
        /// Observed file size.
        actual: u64,
        /// Minimum accepted file size.
        minimum: u64,
        /// Maximum accepted file size.
        maximum: u64,
    },

    /// The path does not identify a regular file opened without symlink traversal.
    #[error("identity path is not a regular file or is a symbolic link: {path}")]
    UnsafeFileType {
        /// Rejected path.
        path: PathBuf,
    },

    /// The file has permissions other than exactly `0600`.
    #[error("identity file has insecure permissions {actual:#06o}; expected 0o600")]
    InsecurePermissions {
        /// Observed Unix permission bits.
        actual: u32,
    },

    /// A hard-linked identity file could retain private material after rotation.
    #[error("identity file has {links} hard links; exactly one is required")]
    MultipleHardLinks {
        /// Observed hard-link count.
        links: u64,
    },

    /// Creating a new identity would overwrite an existing path.
    #[error("identity file already exists: {path}")]
    AlreadyExists {
        /// Existing path.
        path: PathBuf,
    },

    /// The operating system did not provide cryptographically secure randomness.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,

    /// Argon2id key derivation failed.
    #[error("identity key derivation failed")]
    KeyDerivation,

    /// Authenticated encryption failed.
    #[error("identity encryption failed")]
    Encryption,

    /// Authentication failed, covering a wrong passphrase or modified ciphertext.
    #[error("identity decryption or authentication failed")]
    Decryption,

    /// A filesystem operation failed.
    #[error("failed to {operation} at {path}")]
    Io {
        /// Filesystem operation being attempted.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },
}

/// A bounded, zeroizing passphrase for encrypted identity storage.
///
/// The constructor copies the supplied bytes into memory that is zeroed on
/// drop. Callers should separately ensure that their original input buffer is
/// also cleared when it is no longer needed.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    /// Copies a passphrase into zeroizing storage after validating its length.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidPassphraseLength`] when the byte length
    /// is outside the documented bounds.
    pub fn new(passphrase: impl AsRef<[u8]>) -> Result<Self, IdentityError> {
        let bytes = passphrase.as_ref();
        if !(MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&bytes.len()) {
            return Err(IdentityError::InvalidPassphraseLength {
                actual: bytes.len(),
                minimum: MIN_PASSPHRASE_BYTES,
                maximum: MAX_PASSPHRASE_BYTES,
            });
        }

        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Passphrase([REDACTED])")
    }
}

/// A permanent Ed25519 node keypair and its deterministically derived Peer ID.
pub struct Identity {
    keypair: Keypair,
    peer_id: PeerId,
}

impl Identity {
    /// Generates a fresh Ed25519 node identity using libp2p's secure generator.
    #[must_use]
    pub fn generate() -> Self {
        // This constructor is infallible because the generated key type is known.
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        Self { keypair, peer_id }
    }

    /// Wraps an existing libp2p keypair, rejecting every non-Ed25519 key type.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::UnexpectedKeyType`] for a non-Ed25519 keypair.
    pub fn from_keypair(keypair: Keypair) -> Result<Self, IdentityError> {
        if !matches!(keypair.key_type(), KeyType::Ed25519) {
            return Err(IdentityError::UnexpectedKeyType);
        }

        let peer_id = keypair.public().to_peer_id();
        Ok(Self { keypair, peer_id })
    }

    /// Returns the permanent libp2p keypair.
    #[must_use]
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Returns the Peer ID derived from the identity's public key.
    #[must_use]
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Returns the identity's public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Returns the raw 32-byte Ed25519 verification key.
    ///
    /// # Errors
    ///
    /// Returns an unexpected-key-type error if the internal invariant that
    /// this identity is Ed25519 is violated.
    pub fn ed25519_public_key_bytes(&self) -> Result<[u8; 32], IdentityError> {
        self.keypair
            .public()
            .try_into_ed25519()
            .map(|public_key| public_key.to_bytes())
            .map_err(|_| IdentityError::UnexpectedKeyType)
    }

    /// Creates a detached 64-byte Ed25519 signature without exporting secrets.
    ///
    /// # Errors
    ///
    /// Returns a signing error if libp2p refuses to sign or emits a signature
    /// with an invalid length.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        self.keypair
            .sign(message)
            .map_err(|_| IdentityError::Signing)?
            .try_into()
            .map_err(|_| IdentityError::Signing)
    }

    /// Consumes the wrapper and returns the permanent libp2p keypair.
    #[must_use]
    pub fn into_keypair(self) -> Keypair {
        self.keypair
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

/// Filesystem-backed encrypted storage for one permanent node identity.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    path: PathBuf,
}

impl IdentityStore {
    /// Creates a store handle for an exact file path without touching the disk.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the configured encrypted identity-file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Generates and atomically stores a new identity.
    ///
    /// This method never overwrites an existing filesystem entry.
    ///
    /// # Errors
    ///
    /// Returns an error when encryption, secure temporary-file creation, or
    /// atomic persistence fails, including when the target already exists.
    pub fn create(&self, passphrase: &Passphrase) -> Result<Identity, IdentityError> {
        let identity = Identity::generate();
        self.store_new(&identity, passphrase)?;
        Ok(identity)
    }

    /// Atomically stores an existing Ed25519 identity without overwriting.
    ///
    /// # Errors
    ///
    /// Returns an error when encryption or atomic no-clobber persistence fails.
    pub fn store_new(
        &self,
        identity: &Identity,
        passphrase: &Passphrase,
    ) -> Result<(), IdentityError> {
        let encrypted = encrypt_identity(identity, passphrase)?;
        self.persist(encrypted.as_slice(), PersistMode::CreateNew)
    }

    /// Loads and authenticates the encrypted Ed25519 identity.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe file metadata, malformed bounded input,
    /// failed authentication, or invalid decrypted Ed25519 key material.
    pub fn load(&self, passphrase: &Passphrase) -> Result<Identity, IdentityError> {
        let encrypted = read_secure_file(&self.path)?;
        decrypt_identity(encrypted.as_slice(), passphrase)
    }

    /// Manually rotates the permanent identity and optionally its passphrase.
    ///
    /// The existing identity must first authenticate with `current_passphrase`.
    /// The replacement is then atomically persisted with `new_passphrase`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current identity cannot be authenticated or the
    /// newly generated identity cannot be securely persisted.
    pub fn rotate(
        &self,
        current_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> Result<Identity, IdentityError> {
        self.load(current_passphrase)?;

        let replacement = Identity::generate();
        let encrypted = encrypt_identity(&replacement, new_passphrase)?;
        self.persist(encrypted.as_slice(), PersistMode::Replace)?;
        Ok(replacement)
    }

    /// Re-encrypts the same permanent identity under a new passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error if the current identity cannot be authenticated or its
    /// re-encrypted replacement cannot be atomically persisted.
    pub fn change_passphrase(
        &self,
        current_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> Result<Identity, IdentityError> {
        let identity = self.load(current_passphrase)?;
        let encrypted = encrypt_identity(&identity, new_passphrase)?;
        self.persist(encrypted.as_slice(), PersistMode::Replace)?;
        Ok(identity)
    }

    fn persist(&self, encrypted: &[u8], mode: PersistMode) -> Result<(), IdentityError> {
        let parent = parent_directory(&self.path);
        let mut temporary = create_private_temporary_file(parent)?;
        let temporary_path = temporary.path().to_path_buf();

        temporary
            .write_all(encrypted)
            .map_err(|source| io_error("write temporary identity file", &temporary_path, source))?;
        temporary
            .as_file_mut()
            .flush()
            .map_err(|source| io_error("flush temporary identity file", &temporary_path, source))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| io_error("sync temporary identity file", &temporary_path, source))?;

        let persisted = match mode {
            PersistMode::CreateNew => match temporary.persist_noclobber(&self.path) {
                Ok(file) => file,
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(IdentityError::AlreadyExists {
                        path: self.path.clone(),
                    });
                }
                Err(error) => {
                    return Err(io_error(
                        "persist new identity file",
                        &self.path,
                        error.error,
                    ));
                }
            },
            PersistMode::Replace => temporary
                .persist(&self.path)
                .map_err(|error| io_error("replace identity file", &self.path, error.error))?,
        };

        validate_metadata(
            &self.path,
            &persisted.metadata().map_err(|source| {
                io_error("inspect persisted identity file", &self.path, source)
            })?,
        )?;
        persisted
            .sync_all()
            .map_err(|source| io_error("sync persisted identity file", &self.path, source))?;
        drop(persisted);
        sync_directory(parent)
    }
}

#[derive(Clone, Copy)]
enum PersistMode {
    CreateNew,
    Replace,
}

struct ParsedEnvelope<'a> {
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    authenticated_header: &'a [u8],
    ciphertext: &'a [u8],
}

fn encrypt_identity(
    identity: &Identity,
    passphrase: &Passphrase,
) -> Result<Vec<u8>, IdentityError> {
    let plaintext = Zeroizing::new(
        identity
            .keypair
            .to_protobuf_encoding()
            .map_err(|_| IdentityError::IdentityEncoding)?,
    );
    if plaintext.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(IdentityError::IdentityEncoding);
    }

    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    let mut operating_system_rng = OsRng;
    operating_system_rng
        .try_fill_bytes(&mut salt)
        .map_err(|_| IdentityError::RandomnessUnavailable)?;
    operating_system_rng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| IdentityError::RandomnessUnavailable)?;

    let ciphertext_length = plaintext
        .len()
        .checked_add(TAG_BYTES)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(IdentityError::Encryption)?;

    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(FORMAT_MAGIC);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&ciphertext_length.to_be_bytes());
    debug_assert_eq!(header.len(), HEADER_BYTES);

    let key = derive_encryption_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| IdentityError::Encryption)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: header.as_slice(),
            },
        )
        .map_err(|_| IdentityError::Encryption)?;
    if ciphertext.len() != ciphertext_length as usize {
        return Err(IdentityError::Encryption);
    }

    header.extend_from_slice(&ciphertext);
    Ok(header)
}

fn decrypt_identity(encrypted: &[u8], passphrase: &Passphrase) -> Result<Identity, IdentityError> {
    let envelope = parse_envelope(encrypted)?;
    let key = derive_encryption_key(passphrase, &envelope.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| IdentityError::Decryption)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&envelope.nonce),
                Payload {
                    msg: envelope.ciphertext,
                    aad: envelope.authenticated_header,
                },
            )
            .map_err(|_| IdentityError::Decryption)?,
    );

    if plaintext.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(IdentityError::IdentityDecoding);
    }
    let keypair = Keypair::from_protobuf_encoding(plaintext.as_slice())
        .map_err(|_| IdentityError::IdentityDecoding)?;
    Identity::from_keypair(keypair).map_err(|_| IdentityError::IdentityDecoding)
}

fn derive_encryption_key(
    passphrase: &Passphrase,
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; DERIVED_KEY_BYTES]>, IdentityError> {
    let parameters = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(DERIVED_KEY_BYTES),
    )
    .map_err(|_| IdentityError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut key = Zeroizing::new([0_u8; DERIVED_KEY_BYTES]);
    argon2
        .hash_password_into(passphrase.expose(), salt, &mut *key)
        .map_err(|_| IdentityError::KeyDerivation)?;
    Ok(key)
}

fn parse_envelope(encrypted: &[u8]) -> Result<ParsedEnvelope<'_>, IdentityError> {
    let minimum_size = HEADER_BYTES + TAG_BYTES;
    if encrypted.len() < minimum_size || encrypted.len() > MAX_KEY_FILE_BYTES {
        return Err(IdentityError::InvalidFileSize {
            actual: encrypted.len() as u64,
            minimum: minimum_size as u64,
            maximum: MAX_KEY_FILE_BYTES as u64,
        });
    }
    if &encrypted[..FORMAT_MAGIC.len()] != FORMAT_MAGIC {
        return Err(IdentityError::InvalidFormat {
            reason: "incorrect magic value",
        });
    }

    let version_offset = FORMAT_MAGIC.len();
    let version = encrypted[version_offset];
    if version != FORMAT_VERSION {
        return Err(IdentityError::UnsupportedFormatVersion(version));
    }

    let salt_start = version_offset + 1;
    let salt_end = salt_start + SALT_BYTES;
    let nonce_end = salt_end + NONCE_BYTES;
    let length_end = nonce_end + LENGTH_BYTES;
    debug_assert_eq!(length_end, HEADER_BYTES);

    let salt =
        encrypted[salt_start..salt_end]
            .try_into()
            .map_err(|_| IdentityError::InvalidFormat {
                reason: "invalid salt length",
            })?;
    let nonce =
        encrypted[salt_end..nonce_end]
            .try_into()
            .map_err(|_| IdentityError::InvalidFormat {
                reason: "invalid nonce length",
            })?;
    let ciphertext_length =
        u32::from_be_bytes(encrypted[nonce_end..length_end].try_into().map_err(|_| {
            IdentityError::InvalidFormat {
                reason: "invalid ciphertext length field",
            }
        })?) as usize;

    if !(TAG_BYTES..=MAX_PRIVATE_KEY_BYTES + TAG_BYTES).contains(&ciphertext_length) {
        return Err(IdentityError::InvalidFormat {
            reason: "ciphertext length is out of bounds",
        });
    }
    let expected_size =
        HEADER_BYTES
            .checked_add(ciphertext_length)
            .ok_or(IdentityError::InvalidFormat {
                reason: "ciphertext length overflow",
            })?;
    if encrypted.len() != expected_size {
        return Err(IdentityError::InvalidFormat {
            reason: "ciphertext length does not match file size",
        });
    }

    Ok(ParsedEnvelope {
        salt,
        nonce,
        authenticated_header: &encrypted[..HEADER_BYTES],
        ciphertext: &encrypted[HEADER_BYTES..],
    })
}

fn read_secure_file(path: &Path) -> Result<Vec<u8>, IdentityError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(source) if source.raw_os_error() == Some(libc::ELOOP) => {
            return Err(IdentityError::UnsafeFileType {
                path: path.to_path_buf(),
            });
        }
        Err(source) => return Err(io_error("open identity file", path, source)),
    };

    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect identity file", path, source))?;
    validate_metadata(path, &metadata)?;
    let minimum_size = (HEADER_BYTES + TAG_BYTES) as u64;
    if metadata.len() < minimum_size || metadata.len() > MAX_KEY_FILE_BYTES as u64 {
        return Err(IdentityError::InvalidFileSize {
            actual: metadata.len(),
            minimum: minimum_size,
            maximum: MAX_KEY_FILE_BYTES as u64,
        });
    }

    let capacity = usize::try_from(metadata.len()).map_err(|_| IdentityError::InvalidFileSize {
        actual: metadata.len(),
        minimum: minimum_size,
        maximum: MAX_KEY_FILE_BYTES as u64,
    })?;
    let mut encrypted = Vec::with_capacity(capacity);
    file.take(MAX_KEY_FILE_BYTES as u64 + 1)
        .read_to_end(&mut encrypted)
        .map_err(|source| io_error("read identity file", path, source))?;
    if encrypted.len() > MAX_KEY_FILE_BYTES {
        return Err(IdentityError::InvalidFileSize {
            actual: encrypted.len() as u64,
            minimum: minimum_size,
            maximum: MAX_KEY_FILE_BYTES as u64,
        });
    }
    Ok(encrypted)
}

fn validate_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), IdentityError> {
    if !metadata.file_type().is_file() {
        return Err(IdentityError::UnsafeFileType {
            path: path.to_path_buf(),
        });
    }

    let permissions = metadata.permissions().mode() & 0o7777;
    if permissions != KEY_FILE_MODE {
        return Err(IdentityError::InsecurePermissions {
            actual: permissions,
        });
    }
    if metadata.nlink() != 1 {
        return Err(IdentityError::MultipleHardLinks {
            links: metadata.nlink(),
        });
    }
    Ok(())
}

fn create_private_temporary_file(parent: &Path) -> Result<NamedTempFile, IdentityError> {
    let temporary = Builder::new()
        .prefix(".volparossa-identity-")
        .tempfile_in(parent)
        .map_err(|source| io_error("create temporary identity file", parent, source))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(KEY_FILE_MODE))
        .map_err(|source| {
            io_error(
                "set temporary identity permissions",
                temporary.path(),
                source,
            )
        })?;
    Ok(temporary)
}

fn sync_directory(path: &Path) -> Result<(), IdentityError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY);
    let directory = options
        .open(path)
        .map_err(|source| io_error("open identity directory", path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync identity directory", path, source))
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> IdentityError {
    IdentityError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn test_passphrase() -> Passphrase {
        Passphrase::new("correct horse battery staple")
            .expect("the test passphrase satisfies the length policy")
    }

    #[test]
    fn generated_identity_is_ed25519_with_derived_peer_id() {
        let identity = Identity::generate();

        assert!(matches!(identity.keypair().key_type(), KeyType::Ed25519));
        assert_eq!(
            identity.peer_id(),
            &identity.keypair().public().to_peer_id()
        );
    }

    #[test]
    fn identity_signs_without_exporting_private_key_material() {
        let identity = Identity::generate();
        let message = b"volparossa control-plane integration";
        let signature = identity.sign(message).expect("sign test message");
        let raw_public = identity
            .ed25519_public_key_bytes()
            .expect("extract Ed25519 public key");
        let libp2p_public = identity
            .public_key()
            .try_into_ed25519()
            .expect("identity is Ed25519");

        assert_eq!(raw_public, libp2p_public.to_bytes());
        assert!(libp2p_public.verify(message, &signature));
        assert!(!libp2p_public.verify(b"different message", &signature));
    }

    #[test]
    fn passphrase_is_bounded_and_debug_output_is_redacted() {
        assert!(matches!(
            Passphrase::new("too short"),
            Err(IdentityError::InvalidPassphraseLength { .. })
        ));

        let passphrase = test_passphrase();
        assert_eq!(format!("{passphrase:?}"), "Passphrase([REDACTED])");
    }

    #[test]
    fn create_and_load_preserves_identity_and_mode_without_plaintext_key() {
        let directory = tempfile::tempdir().expect("create test directory");
        let store = IdentityStore::new(directory.path().join("identity.key"));
        let passphrase = test_passphrase();
        let identity = store.create(&passphrase).expect("create identity");

        let metadata = fs::metadata(store.path()).expect("read identity metadata");
        assert_eq!(metadata.permissions().mode() & 0o7777, KEY_FILE_MODE);

        let plaintext_key = Zeroizing::new(
            identity
                .keypair()
                .to_protobuf_encoding()
                .expect("encode test identity"),
        );
        let encrypted = fs::read(store.path()).expect("read encrypted identity");
        assert!(
            !encrypted
                .windows(plaintext_key.len())
                .any(|window| window == plaintext_key.as_slice())
        );

        let loaded = store.load(&passphrase).expect("load identity");
        assert_eq!(loaded.peer_id(), identity.peer_id());
    }

    #[test]
    fn creating_twice_never_overwrites_the_first_identity() {
        let directory = tempfile::tempdir().expect("create test directory");
        let store = IdentityStore::new(directory.path().join("identity.key"));
        let passphrase = test_passphrase();
        let identity = store.create(&passphrase).expect("create identity");

        let error = store
            .store_new(&Identity::generate(), &passphrase)
            .expect_err("an existing identity must not be overwritten");
        assert!(matches!(error, IdentityError::AlreadyExists { .. }));
        assert_eq!(
            store.load(&passphrase).expect("load original").peer_id(),
            identity.peer_id()
        );
    }

    #[test]
    fn wrong_passphrase_and_ciphertext_tampering_fail_authentication() {
        let directory = tempfile::tempdir().expect("create test directory");
        let store = IdentityStore::new(directory.path().join("identity.key"));
        let passphrase = test_passphrase();
        store.create(&passphrase).expect("create identity");

        let wrong = Passphrase::new("this is a different passphrase")
            .expect("the wrong passphrase is long enough");
        assert!(matches!(store.load(&wrong), Err(IdentityError::Decryption)));

        let mut encrypted = fs::read(store.path()).expect("read encrypted identity");
        let last = encrypted.last_mut().expect("envelope is not empty");
        *last ^= 0x80;
        fs::write(store.path(), encrypted).expect("tamper with encrypted identity");
        assert!(matches!(
            store.load(&passphrase),
            Err(IdentityError::Decryption)
        ));
    }

    #[test]
    fn insecure_permissions_are_rejected_before_decryption() {
        let directory = tempfile::tempdir().expect("create test directory");
        let store = IdentityStore::new(directory.path().join("identity.key"));
        let passphrase = test_passphrase();
        store.create(&passphrase).expect("create identity");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o640))
            .expect("make permissions insecure");

        assert!(matches!(
            store.load(&passphrase),
            Err(IdentityError::InsecurePermissions { actual: 0o640 })
        ));
    }

    #[test]
    fn symbolic_and_hard_links_are_rejected() {
        let directory = tempfile::tempdir().expect("create test directory");
        let original = IdentityStore::new(directory.path().join("identity.key"));
        let passphrase = test_passphrase();
        original.create(&passphrase).expect("create identity");

        let symbolic_path = directory.path().join("symbolic.key");
        symlink(original.path(), &symbolic_path).expect("create symbolic link");
        let symbolic = IdentityStore::new(symbolic_path);
        assert!(matches!(
            symbolic.load(&passphrase),
            Err(IdentityError::UnsafeFileType { .. })
        ));

        let hard_path = directory.path().join("hard.key");
        fs::hard_link(original.path(), hard_path).expect("create hard link");
        assert!(matches!(
            original.load(&passphrase),
            Err(IdentityError::MultipleHardLinks { links: 2 })
        ));
    }

    #[test]
    fn manual_rotation_requires_old_passphrase_and_changes_peer_id() {
        let directory = tempfile::tempdir().expect("create test directory");
        let store = IdentityStore::new(directory.path().join("identity.key"));
        let old_passphrase = test_passphrase();
        let old_identity = store.create(&old_passphrase).expect("create identity");
        let new_passphrase =
            Passphrase::new("a completely new strong passphrase").expect("new passphrase is valid");

        let replacement = store
            .rotate(&old_passphrase, &new_passphrase)
            .expect("rotate identity");
        assert_ne!(replacement.peer_id(), old_identity.peer_id());
        assert!(matches!(
            store.load(&old_passphrase),
            Err(IdentityError::Decryption)
        ));
        assert_eq!(
            store
                .load(&new_passphrase)
                .expect("load replacement")
                .peer_id(),
            replacement.peer_id()
        );
        assert_eq!(
            fs::metadata(store.path())
                .expect("read replacement metadata")
                .permissions()
                .mode()
                & 0o7777,
            KEY_FILE_MODE
        );
    }

    #[test]
    fn oversized_files_are_rejected_without_unbounded_reads() {
        let directory = tempfile::tempdir().expect("create test directory");
        let store = IdentityStore::new(directory.path().join("identity.key"));
        fs::write(store.path(), vec![0_u8; MAX_KEY_FILE_BYTES + 1])
            .expect("write oversized identity file");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(KEY_FILE_MODE))
            .expect("set private permissions");

        assert!(matches!(
            store.load(&test_passphrase()),
            Err(IdentityError::InvalidFileSize { .. })
        ));
    }
}
