//! Owner-private Unix sockets; bounded FIFO frames and one serialized application.
use crate::{Application, Error, proto::tendermint::abci};
use prost::Message as _;
use std::{
    fs,
    future::Future,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

/// Maximum encoded request/response bytes, not the upstream two-gigabyte allowance.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
/// `CometBFT` uses consensus, mempool, query and snapshot connections, not unbounded peers.
pub const MAX_CONNECTIONS: usize = 4;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound owner-only socket and application. Dropping removes only this socket's inode.
pub struct Server {
    listener: UnixListener,
    application: Arc<Mutex<Application>>,
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Server {
    /// Bind a new socket below an existing canonical, same-owner mode-0700 directory.
    /// Never deletes an existing socket, follows a socket symlink or listens on TCP.
    ///
    /// # Errors
    /// Rejects unsafe directories/paths, existing sockets and filesystem errors.
    pub fn bind(path: &Path, application: Application) -> Result<Self, Error> {
        let parent = path.parent().ok_or(Error::Configuration)?;
        let metadata = fs::symlink_metadata(parent)?;
        if !path.is_absolute()
            || !metadata.is_dir()
            || parent.canonicalize()? != parent
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(Error::Configuration);
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            listener,
            application: Arc::new(Mutex::new(application)),
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Serve until explicit shutdown or a fatal application/protocol failure.
    /// A failed connection cannot leave other connections mutating a failed app.
    ///
    /// # Errors
    /// Returns the first fatal socket, framing, lifecycle or store error.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
        tokio::pin!(shutdown);
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut connections = JoinSet::new();
        let result = loop {
            tokio::select! {
                () = &mut shutdown => break Ok(()),
                value = connections.join_next(), if !connections.is_empty() => {
                    match value {
                        Some(Ok(Ok(()))) => {},
                        Some(Ok(Err(error))) => break Err(error),
                        _ => break Err(Error::Protocol),
                    }
                },
                incoming = self.listener.accept() => {
                    let (socket, _) = match incoming { Ok(value) => value, Err(error) => break Err(error.into()) };
                    let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else { drop(socket); continue; };
                    if socket.peer_cred()?.uid() != rustix::process::geteuid().as_raw() { drop(socket); continue; }
                    let app = Arc::clone(&self.application);
                    connections.spawn(async move { let _permit = permit; connection(socket, app).await });
                }
            }
        };
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        result
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.file_type().is_socket() && meta.dev() == self.device && meta.ino() == self.inode
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

async fn connection(mut socket: UnixStream, app: Arc<Mutex<Application>>) -> Result<(), Error> {
    while let Some(bytes) = read_frame(&mut socket).await? {
        let request = abci::Request::decode(bytes.as_slice()).map_err(|_| Error::Protocol)?;
        let response = app.lock().await.handle(request);
        match response {
            Ok(value) => write_frame(&mut socket, &value.encode_to_vec()).await?,
            Err(error) => {
                // No database diagnostics, paths, inputs or credentials in the response.
                let value = abci::Response {
                    value: Some(abci::response::Value::Exception(abci::ResponseException {
                        error: error.to_string(),
                    })),
                };
                let _ = write_frame(&mut socket, &value.encode_to_vec()).await;
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Read upstream varint-length framing; idle connections allocate no message buffer.
/// A started frame has a total deadline and cannot allocate above the local bound.
///
/// # Errors
/// Rejects oversized/overflowing lengths, truncation and stalled partial frames.
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Vec<u8>>, Error> {
    let mut first = [0_u8; 1];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut byte = first[0];
        let mut length = 0_u32;
        for index in 0..3 {
            length |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                let length = usize::try_from(length).map_err(|_| Error::Protocol)?;
                if length == 0 || length > MAX_FRAME_BYTES {
                    return Err(Error::Protocol);
                }
                let mut buffer = vec![0; length];
                reader.read_exact(&mut buffer).await?;
                return Ok(Some(buffer));
            }
            if index < 2 {
                byte = reader.read_u8().await?;
            }
        }
        Err(Error::Protocol)
    })
    .await
    .map_err(|_| Error::Protocol)?
}

/// Write and flush one bounded response in FIFO order, including an actual `Flush` response.
///
/// # Errors
/// Rejects empty/oversized payloads, write failures and stalled receivers.
pub async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::Protocol);
    }
    let mut frame = Vec::with_capacity(bytes.len() + 3);
    let mut length = u32::try_from(bytes.len()).map_err(|_| Error::Protocol)?;
    while length >= 128 {
        frame.push(u8::try_from(length & 0x7f).map_err(|_| Error::Protocol)? | 0x80);
        length >>= 7;
    }
    frame.push(u8::try_from(length).map_err(|_| Error::Protocol)?);
    frame.extend_from_slice(bytes);
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_all(&frame).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| Error::Protocol)??;
    Ok(())
}
