//! Bounded passphrase input that never accepts secrets through process arguments or environment.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail};
use volparossa_identity::{MAX_PASSPHRASE_BYTES, Passphrase};
use zeroize::{Zeroize, Zeroizing};

/// Reads a passphrase from a strict `0600` regular file or a no-echo terminal prompt.
pub fn read_passphrase(path: Option<&Path>, confirm: bool) -> Result<Passphrase> {
    read_passphrase_with_prompts(
        path,
        "VOLPAROSSA identity passphrase: ",
        confirm.then_some("Repeat VOLPAROSSA identity passphrase: "),
    )
}

/// Reads a passphrase using operation-specific no-echo prompts.
pub fn read_passphrase_with_prompts(
    path: Option<&Path>,
    prompt: &str,
    confirmation_prompt: Option<&str>,
) -> Result<Passphrase> {
    let mut secret = match path {
        Some(path) => read_private_file(path)?,
        None => Zeroizing::new(
            rpassword::prompt_password(prompt)
                .context("could not read passphrase from terminal")?,
        ),
    };

    if path.is_none() {
        if let Some(confirmation_prompt) = confirmation_prompt {
            let mut confirmation = Zeroizing::new(
                rpassword::prompt_password(confirmation_prompt)
                    .context("could not read passphrase confirmation")?,
            );
            if secret.as_bytes() != confirmation.as_bytes() {
                secret.zeroize();
                confirmation.zeroize();
                bail!("passphrase confirmation does not match");
            }
        }
    }

    let passphrase = Passphrase::new(secret.as_bytes()).context("invalid passphrase")?;
    secret.zeroize();
    Ok(passphrase)
}

fn read_private_file(path: &Path) -> Result<Zeroizing<String>> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect passphrase file {}", path.display()))?;
    if !path_metadata.file_type().is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.nlink() != 1
    {
        bail!("passphrase file must be one regular, non-linked file");
    }
    if path_metadata.mode() & 0o777 != 0o600 {
        bail!("passphrase file permissions must be exactly 0600");
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("cannot securely open passphrase file {}", path.display()))?;
    let open_metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect open passphrase file {}", path.display()))?;
    if !open_metadata.file_type().is_file() || open_metadata.nlink() != 1 {
        bail!("passphrase file must be one regular, non-linked file");
    }
    if open_metadata.mode() & 0o777 != 0o600 {
        bail!("passphrase file permissions must be exactly 0600");
    }
    if open_metadata.dev() != path_metadata.dev() || open_metadata.ino() != path_metadata.ino() {
        bail!("passphrase file changed while it was being opened");
    }
    let maximum = u64::try_from(MAX_PASSPHRASE_BYTES + 1).expect("small bound");
    if open_metadata.len() == 0 || open_metadata.len() > maximum {
        bail!("passphrase file length is outside the accepted bound");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_BYTES + 1));
    file.by_ref()
        .take(maximum)
        .read_to_end(&mut bytes)
        .context("cannot read passphrase file")?;
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    let value = String::from_utf8(bytes.to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "passphrase file is not UTF-8"))?;
    Ok(Zeroizing::new(value))
}
