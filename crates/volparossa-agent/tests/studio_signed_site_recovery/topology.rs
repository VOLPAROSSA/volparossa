// SPDX-License-Identifier: GPL-3.0-only
use std::{env, fs::DirBuilder, os::unix::fs::DirBuilderExt, path::PathBuf};

use super::{Result, fixture::private_file};

/// Only the opted-in offline synthetic publication may cross to the same runner's KVM proof.
pub(super) fn enabled() -> Result<bool> {
    match env::var_os("VOLPAROSSA_STUDIO_PUBLIC_TOPOLOGY_HANDOFF") {
        None => Ok(false),
        Some(value) if value == "1" => Ok(true),
        Some(_) => Err("topology_mode"),
    }
}

pub(super) fn write_verified(bundle: &[u8], manifest: &[u8]) -> Result<()> {
    let export =
        PathBuf::from(env::var_os("VOLPAROSSA_STUDIO_EXPORT_DIRECTORY").ok_or("export_directory")?);
    if !export.is_absolute() || export.file_name().is_none_or(|name| name != "export") {
        return Err("topology_export_directory");
    }
    let directory = export.with_file_name("signed-topology-input");
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|_| "topology_handoff_directory")?;
    private_file(&directory.join("site.vps"), bundle)?;
    private_file(&directory.join("manifest.bin"), manifest)
}
