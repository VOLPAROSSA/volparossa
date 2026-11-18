// SPDX-License-Identifier: GPL-3.0-only
//! Enumerate regular files once and stream each checked object beneath the original directory.

use std::{
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt as _,
};

use anyhow::{Context as _, Result, bail};
use rustix::fs::{Dir, Mode, OFlags, ResolveFlags, openat, openat2};
use volparossa_content::site::{MAX_SITE_ASSETS, SiteAssetSource};

pub(super) fn collect(root: &File) -> Result<Vec<SiteAssetSource<AssetReader<'_>>>> {
    let mut assets = Vec::new();
    visit(root, root, "", 0, &mut 0, &mut assets)?;
    Ok(assets)
}

fn visit<'a>(
    root: &'a File,
    directory: &File,
    prefix: &str,
    depth: usize,
    entries: &mut usize,
    assets: &mut Vec<SiteAssetSource<AssetReader<'a>>>,
) -> Result<()> {
    if depth > 16 {
        bail!("site directory nesting exceeds 16 levels");
    }
    let mut listing = Dir::read_from(directory)?;
    while let Some(entry) = listing.read() {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .context("site asset name must be UTF-8")?;
        if matches!(name, "." | "..") {
            continue;
        }
        *entries += 1;
        if *entries > 4096 {
            bail!("site directory entry bound exceeded");
        }
        if name.starts_with('.') {
            continue;
        }
        let file = File::from(openat(
            directory,
            entry.file_name(),
            read_flags(),
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        let path = format!("{prefix}/{name}");
        if metadata.is_dir() {
            visit(root, &file, &path, depth + 1, entries, assets)?;
            continue;
        }
        if !metadata.is_file() || assets.len() == MAX_SITE_ASSETS {
            bail!("site requires at most {MAX_SITE_ASSETS} regular assets");
        }
        assets.push(SiteAssetSource {
            content_type: super::media_type(&path).into(),
            length: metadata.len(),
            reader: AssetReader {
                root,
                relative_path: path[1..].to_owned(),
                expected: metadata,
                file: None,
            },
            path,
        });
    }
    Ok(())
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC
}

pub(super) struct AssetReader<'a> {
    root: &'a File,
    relative_path: String,
    expected: Metadata,
    file: Option<File>,
}

impl Read for AssetReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let file = if let Some(file) = &mut self.file {
            file
        } else {
            let file = File::from(openat2(
                self.root,
                self.relative_path.as_str(),
                read_flags(),
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )?);
            verify(&self.expected, &file.metadata()?)?;
            self.file.insert(file)
        };
        let count = file.read(buffer)?;
        // The encoder probes for EOF after the declared length, including empty assets.
        if count == 0 {
            verify(&self.expected, &file.metadata()?)?;
        }
        Ok(count)
    }
}

fn verify(expected: &Metadata, current: &Metadata) -> io::Result<()> {
    if current.is_file()
        && expected.dev() == current.dev()
        && expected.ino() == current.ino()
        && expected.len() == current.len()
        && expected.ctime() == current.ctime()
        && expected.ctime_nsec() == current.ctime_nsec()
        && expected.mtime() == current.mtime()
        && expected.mtime_nsec() == current.mtime_nsec()
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "site asset changed since selection",
        ))
    }
}

#[cfg(test)]
mod tests;
