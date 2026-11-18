//! Explicit static-site bundles reuse native signatures, names and protected chunk retrieval.

mod preparation;
mod preview;
mod source;
mod viewer;

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use rustix::fs::{Mode, OFlags, open};
use volparossa_content::site::{SITE_CONTENT_TYPE, SiteBundle};

use super::{FetchName, Limits, ensure_new_output, output_parent};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Pack regular static files; dotfiles and dot-directories are excluded, symlinks rejected.
    Pack(Pack),
    /// Check whether the active local contribution service can deliver this exact signed site.
    Confirm(Confirm),
    /// Fetch a named signed website, then expose only its verified assets on a local browser URL.
    Open(Box<Open>),
    /// Preview exact reviewed local bytes against an independently selected original signed manifest.
    Preview(Box<preview::Preview>),
}

#[derive(Debug, Args)]
pub(crate) struct Pack {
    /// Explicit website directory containing index.html; no symlinks are followed.
    #[arg(long)]
    directory: PathBuf,
    /// New private bundle file; publish it with the reported native content type.
    #[arg(long)]
    output: PathBuf,
    /// Return a bounded review inventory for these exact bytes; grants no publication authority.
    #[arg(long)]
    review_receipt: bool,
}

#[derive(Debug, Args)]
pub(crate) struct Confirm {
    /// Original signed manifest retained by the publisher.
    #[arg(long)]
    manifest: PathBuf,
    /// Independently trusted public key of the named publisher.
    #[arg(long, value_parser = super::parse_publisher_key)]
    publisher_key: VerifyingKey,
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
        Command::Preview(args) => preview::run(*args).await?,
        Command::Confirm(args) => println!("{}", confirm(&args, socket).await?),
    }
    Ok(())
}

async fn confirm(args: &Confirm, socket: &Path) -> Result<serde_json::Value> {
    let bytes = super::read_manifest_bytes(&args.manifest)?;
    let manifest = volparossa_content::SignedManifest::decode(&bytes)?
        .verify(&args.publisher_key, super::now_seconds()?)?;
    if manifest.metadata().content_type != SITE_CONTENT_TYPE || manifest.length() == 0 {
        bail!("expected a signed native site publication");
    }
    super::named_download::confirm_local(&args.publisher_key, &manifest, SITE_CONTENT_TYPE, socket)
        .await?;
    Ok(serde_json::json!({
        "operation": "native_site_confirm",
        "local_registry_read_verified": true,
        "publisher_key": hex::encode(manifest.publisher()),
        "name": manifest.metadata().name,
        "revision": manifest.metadata().revision,
        "manifest_id": hex::encode(manifest.manifest_id()),
        "bytes": manifest.length(),
        "chunks": manifest.chunks().len(),
        "expires_unix_seconds": manifest.validity().expires,
    }))
}

fn pack(args: &Pack) -> Result<serde_json::Value> {
    ensure_new_output(&args.output)?;
    let root = File::from(open(
        &args.directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let assets = source::collect(&root)?;
    let count = assets.len();
    let mut temporary = tempfile::NamedTempFile::new_in(output_parent(&args.output))?;
    let (bytes, receipt) = if args.review_receipt {
        let (bytes, receipt) = preparation::write_to(assets, temporary.as_file_mut())?;
        (bytes, Some(receipt))
    } else {
        (SiteBundle::write_to(assets, temporary.as_file_mut())?, None)
    };
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&args.output)
        .map_err(|error| error.error)?;
    File::open(output_parent(&args.output))?.sync_all()?;
    if let Some(receipt) = receipt {
        return Ok(receipt);
    }
    Ok(serde_json::json!({
        "operation":"site_pack", "assets":count, "bytes":bytes,
        "content_type":SITE_CONTENT_TYPE, "output":args.output,
        "network_published":false, "hidden_entries_excluded":true, "symlinks_followed":false,
    }))
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
            review_receipt: false,
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
            review_receipt: false,
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
                output: args.output,
                review_receipt: false,
            })
            .is_err()
        );
    }
}
