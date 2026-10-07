//! Explicit local TEST adapter; never starts consensus or public networking itself.
#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use std::{
    fs::File,
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};
use volparossa_transaction::{Action, Command, SignedCommand};
use volparossa_transaction_abci::{Application, Error, Genesis, Server};

#[derive(Parser)]
#[command(about = "Owner-private ABCI for fictitious TEST units; no real settlement")]
struct Args {
    #[command(subcommand)]
    command: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Serve private Unix ABCI, with an externally supplied fixed TEST genesis.
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Explicitly sign a TEST reserve; stdout is original signed bytes in hex.
    SignReserve {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        units: u64,
    },
    /// Explicitly authorize crediting a prior TEST reserve's immutable recipient.
    SignCommit {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        reservation: String,
    },
}

#[derive(clap::Args)]
struct SigningArgs {
    #[arg(long)]
    ledger: String,
    /// Owner-private raw32 Ed25519 seed file; never copied into the store.
    #[arg(long)]
    secret_key: PathBuf,
    #[arg(long)]
    operation: String,
    #[arg(long)]
    valid_from: u64,
    #[arg(long)]
    expires: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Error> {
    match args.command {
        Operation::Serve {
            config,
            store,
            socket,
        } => {
            let genesis = Genesis::from_json(&read_private(&config, 16_384)?)?;
            let app = Application::open(&store, genesis)?;
            Server::bind(&socket, app)?
                .serve(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
        }
        Operation::SignReserve {
            signing,
            recipient,
            units,
        } => sign(
            &signing,
            Action::Reserve {
                recipient: decode_id(&recipient)?,
                units,
            },
        ),
        Operation::SignCommit {
            signing,
            reservation,
        } => sign(
            &signing,
            Action::Commit {
                reservation_id: decode_id(&reservation)?,
            },
        ),
    }
}

fn sign(args: &SigningArgs, action: Action) -> Result<(), Error> {
    let mut seed: [u8; 32] = read_private(&args.secret_key, 32)?
        .try_into()
        .map_err(|_| Error::Configuration)?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let mut nonce = [0; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| Error::Configuration)?;
    let bytes = SignedCommand::sign_ordered(
        decode_id(&args.ledger)?,
        &key,
        Command {
            operation_id: decode_id(&args.operation)?,
            payer: key.verifying_key().to_bytes(),
            action,
        },
        args.valid_from,
        args.expires,
        nonce,
    )?
    .encode();
    println!("{}", hex::encode(bytes));
    Ok(())
}

fn decode_id(value: &str) -> Result<[u8; 32], Error> {
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id).map_err(|_| Error::Configuration)?;
    Ok(id)
}

fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    if !path.is_absolute() {
        return Err(Error::Configuration);
    }
    let file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != rustix::process::geteuid().as_raw()
        || info.nlink() != 1
        || info.mode() & 0o777 != 0o600
        || info.len() > limit
    {
        return Err(Error::Configuration);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| Error::Configuration)? > limit {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}
