// SPDX-License-Identifier: GPL-3.0-only
//! Offline owner confirmation in a terminal separate from the editor.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use volparossa_content::site::{SITE_CONTENT_TYPE, SiteBundle};

use crate::content::{Publish, now_seconds, reviewed_input::Input};

pub(in crate::content) fn prepare(
    args: &Publish,
    file: File,
    length: u64,
) -> Result<(Input, u64, u64)> {
    let (input, expires) =
        Input::with_review(file, length, args.expected_input_sha256, |bytes, digest| {
            let expires = args.expiry(now_seconds()?)?;
            confirm(args, bytes, digest, expires)?;
            Ok(expires)
        })?;
    let now = now_seconds()?;
    if expires <= now {
        bail!("site signing authorization expired during review");
    }
    Ok((input, now, expires))
}

fn confirm(args: &Publish, bytes: &[u8], digest: [u8; 32], expires: u64) -> Result<()> {
    if args.content_type != SITE_CONTENT_TYPE {
        bail!("--review-site requires the native site content type");
    }
    let publisher = args
        .expected_publisher_key
        .context("select a publisher key for site review")?;
    let assets = SiteBundle::inspect(bytes)?;
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("open the owner command in a controlling terminal for site review")?;
    let hash = hex::encode(digest);
    writeln!(tty, "Review this offline site signature")?;
    writeln!(tty, "Publisher key  {}", hex::encode(publisher.to_bytes()))?;
    writeln!(tty, "Site name      \"{}\"", args.name.escape_default())?;
    writeln!(tty, "Revision       {}", args.revision)?;
    writeln!(tty, "Expires at     {expires} UTC (Unix seconds)")?;
    writeln!(
        tty,
        "Manifest       {}",
        args.manifest.as_os_str().as_encoded_bytes().escape_ascii()
    )?;
    writeln!(
        tty,
        "Cache          {}",
        args.cache.as_os_str().as_encoded_bytes().escape_ascii()
    )?;
    if args.reuse_cache {
        writeln!(
            tty,
            "Reusing the selected cache allows its older chunks to be evicted under the selected quota."
        )?;
    }
    writeln!(tty, "Bundle SHA-256 {hash}")?;
    writeln!(
        tty,
        "{} bytes in the bundle. {} public assets:",
        bytes.len(),
        assets.len()
    )?;
    for asset in assets {
        writeln!(
            tty,
            "  {}  {} bytes  {}  {}",
            asset.path.escape_default(),
            asset.length,
            asset.content_type,
            hex::encode(Sha256::digest(asset.reader))
        )?;
    }
    writeln!(
        tty,
        "Signing creates a local manifest and cache. Sending the site to peers requires a separate contribution."
    )?;
    let expected = format!("SIGN {}", &hash[..12]);
    write!(tty, "Type {expected} to sign, or press Enter to cancel: ")?;
    tty.flush()?;
    let mut response = Vec::new();
    BufReader::new(tty)
        .take((expected.len() + 2) as u64)
        .read_until(b'\n', &mut response)?;
    if response.strip_suffix(b"\n") != Some(expected.as_bytes()) {
        bail!("owner cancelled site signing");
    }
    Ok(())
}
