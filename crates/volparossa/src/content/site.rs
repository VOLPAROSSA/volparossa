//! Explicit static-site bundles reuse native signatures, names and protected chunk retrieval.

mod viewer;

use std::{
    fs::File,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use rustix::fs::{Dir, Mode, OFlags, open, openat};
use volparossa_content::{
    MAX_OBJECT_BYTES,
    site::{SITE_CONTENT_TYPE, SiteAsset, SiteBundle},
};

use super::{FetchName, Limits, ensure_new_output, output_parent};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Pack regular static files; dotfiles and dot-directories are excluded, symlinks rejected.
    Pack(Pack),
    /// Fetch a named signed website, then expose only its verified assets on a local browser URL.
    Open(Box<Open>),
}

#[derive(Debug, Args)]
pub(crate) struct Pack {
    /// Explicit website directory containing index.html; no symlinks are followed.
    #[arg(long)]
    directory: PathBuf,
    /// New private bundle file; publish it with the reported native content type.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct Open {
    /// Independently trusted native publisher key, not an HTTPS-origin trust anchor.
    #[arg(long, value_parser = super::parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Exact publisher-local site name.
    #[arg(long, value_parser = super::parse_content_name)]
    name: String,
    /// Reject an older signed revision; not proof of a globally latest version.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    min_revision: Option<u64>,
    /// New agent-owned destination cache, or explicitly reopened owned cache.
    #[arg(long)]
    cache: PathBuf,
    #[arg(long)]
    reuse_cache: bool,
    /// Open only the existing complete native cache; no route or provider discovery.
    #[arg(long, requires = "reuse_cache")]
    cache_only: bool,
    /// Maximum local viewer lifetime, also bounded by the original signed publication expiry.
    #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u64).range(1..=86400))]
    lifetime_seconds: u64,
    #[command(flatten)]
    limits: Limits,
}

impl Open {
    fn fetch_args(&self, private_output: PathBuf) -> FetchName {
        FetchName {
            publisher_key: self.publisher_key,
            name: self.name.clone(),
            min_revision: self.min_revision,
            cache: self.cache.clone(),
            reuse_cache: self.reuse_cache,
            cache_only: self.cache_only,
            local_output: private_output,
            limits: Limits {
                quota_bytes: self.limits.quota_bytes,
                max_entries: self.limits.max_entries,
                min_free_bytes: self.limits.min_free_bytes,
            },
        }
    }
}

pub(super) async fn run(command: Command, socket: &Path) -> Result<()> {
    match command {
        Command::Pack(args) => println!("{}", pack(&args)?),
        Command::Open(args) => viewer::run(*args, socket).await?,
    }
    Ok(())
}

fn pack(args: &Pack) -> Result<serde_json::Value> {
    ensure_new_output(&args.output)?;
    let root = File::from(open(
        &args.directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let mut assets = Vec::new();
    collect(&root, "", 0, &mut 0, &mut 0, &mut assets)?;
    let count = assets.len();
    let bytes = SiteBundle::encode(assets)?;
    let mut temporary = tempfile::NamedTempFile::new_in(output_parent(&args.output))?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&args.output)
        .map_err(|error| error.error)?;
    File::open(output_parent(&args.output))?.sync_all()?;
    Ok(serde_json::json!({
        "operation":"site_pack", "assets":count, "bytes":bytes.len(),
        "content_type":SITE_CONTENT_TYPE, "output":args.output,
        "network_published":false, "hidden_entries_excluded":true, "symlinks_followed":false,
    }))
}

fn collect(
    directory: &File,
    prefix: &str,
    depth: usize,
    entries: &mut usize,
    total: &mut u64,
    assets: &mut Vec<SiteAsset>,
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
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        let path = format!("{prefix}/{name}");
        if metadata.is_dir() {
            collect(&file, &path, depth + 1, entries, total, assets)?;
            continue;
        }
        if !metadata.is_file() || assets.len() == 256 {
            bail!("site requires at most 256 regular assets");
        }
        let remaining = MAX_OBJECT_BYTES
            .checked_sub(*total)
            .context("site payload exceeds object limit")?;
        if metadata.len() > remaining {
            bail!("site asset exceeds remaining object limit");
        }
        let mut bytes = Vec::new();
        file.take(remaining + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > remaining {
            bail!("site changed beyond remaining object limit");
        }
        *total += bytes.len() as u64;
        assets.push(SiteAsset {
            content_type: media_type(&path).into(),
            path,
            bytes,
        });
    }
    Ok(())
}

fn media_type(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "json" | "map" => "application/json",
        "txt" => "text/plain",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
    };

    use super::*;

    #[test]
    fn site_cache_only_requires_existing_cache_and_preserves_fetch_mode() {
        use clap::Parser as _;
        let key = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .to_bytes(),
        );
        let base = [
            "volparossa",
            "content",
            "site",
            "open",
            "--publisher-key",
            &key,
            "--name",
            "site",
            "--cache",
            "existing",
        ];
        assert!(crate::Cli::try_parse_from(base.into_iter().chain(["--cache-only"])).is_err());
        let parsed =
            crate::Cli::try_parse_from(base.into_iter().chain(["--cache-only", "--reuse-cache"]))
                .unwrap();
        let crate::CliCommand::Content { command } = parsed.command else {
            panic!("content expected");
        };
        let super::super::Command::Site(Command::Open(args)) = *command else {
            panic!("site open expected");
        };
        let fetch = args.fetch_args(PathBuf::from("private-temporary"));
        assert!(fetch.cache_only && fetch.reuse_cache);
        assert_eq!(fetch.name, "site");
    }

    #[test]
    fn packs_exact_static_assets_without_hidden_files_or_overwriting_output() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("website");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(directory.join("assets")).unwrap();
        fs::create_dir(directory.join(".private")).unwrap();
        fs::write(
            directory.join("index.html"),
            b"<link rel=stylesheet href=/assets/main.css><h1>Site</h1>",
        )
        .unwrap();
        fs::write(directory.join("assets/main.css"), b"h1{color:red}").unwrap();
        fs::write(directory.join("assets/main.js"), b"document.title='site'").unwrap();
        fs::write(directory.join(".env"), b"must not be published").unwrap();
        fs::write(directory.join(".private/secret"), b"must not be published").unwrap();
        let args = Pack {
            directory,
            output: root.path().join("site.vps"),
        };
        let report = pack(&args).unwrap();
        assert_eq!(report["assets"], 3);
        assert_eq!(report["content_type"], SITE_CONTENT_TYPE);
        assert_eq!(report["network_published"], false);
        assert_eq!(
            fs::metadata(&args.output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bytes = fs::read(&args.output).unwrap();
        let bundle = SiteBundle::decode(bytes.clone()).unwrap();
        assert_eq!(bundle.asset_count(), 3);
        assert_eq!(
            bundle.asset("/assets/main.css").unwrap().bytes,
            b"h1{color:red}"
        );
        assert_eq!(
            bundle.asset("/assets/main.js").unwrap().content_type,
            "text/javascript"
        );
        assert!(bundle.asset("/.env").is_none());
        assert!(bundle.asset("/.private/secret").is_none());
        assert!(pack(&args).is_err());
        assert_eq!(fs::read(&args.output).unwrap(), bytes);
    }

    #[test]
    fn rejects_symlinks_and_missing_index_without_publishing_output() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("website");
        fs::create_dir(&directory).unwrap();
        let args = Pack {
            directory,
            output: root.path().join("site.vps"),
        };
        assert!(pack(&args).is_err());
        assert!(!args.output.exists());
        fs::write(args.directory.join("index.html"), b"<h1>Site</h1>").unwrap();
        let secret = root.path().join("outside.txt");
        fs::write(&secret, b"not selected for publication").unwrap();
        symlink(&secret, args.directory.join("linked.txt")).unwrap();
        assert!(pack(&args).is_err());
        assert!(!args.output.exists());
        fs::remove_file(args.directory.join("linked.txt")).unwrap();
        symlink(&args.directory, root.path().join("linked-root")).unwrap();
        assert!(
            pack(&Pack {
                directory: root.path().join("linked-root"),
                output: args.output
            })
            .is_err()
        );
    }
}
