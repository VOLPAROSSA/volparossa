use std::{sync::Arc, time::Duration};

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};

use crate::{TcpProxyError, VerifiedMptcpRoute};

/// ALPN identifier for the version-one VOLPAROSSA TCP proxy protocol.
pub const VOLPAROSSA_TCP_ALPN: &[u8] = b"volparossa-tcp/1";

/// TLS stream returned by either the MPTCP client or MPTCP server transport.
pub enum Tls13MptcpStream {
    /// Client side of an authenticated TLS 1.3 session over MPTCP.
    Client(ClientTlsStream<TcpStream>),
    /// Exit side of an authenticated TLS 1.3 session over MPTCP.
    Server(ServerTlsStream<TcpStream>),
}

/// TLS 1.3-only client transport over a helper-acquired route-namespace MPTCP socket.
#[derive(Clone)]
pub struct Tls13MptcpClient {
    connector: TlsConnector,
}

impl Tls13MptcpClient {
    /// Build a standards-verified TLS 1.3 client from independent trust roots.
    ///
    /// # Errors
    ///
    /// Fails closed when no process-level rustls cryptography provider can be
    /// installed or selected.
    pub fn new(root_certificates: RootCertStore) -> Result<Self, TcpProxyError> {
        ensure_crypto_provider()?;
        let mut configuration =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_certificates)
                .with_no_client_auth();
        configuration.alpn_protocols = vec![VOLPAROSSA_TCP_ALPN.to_vec()];
        Ok(Self {
            connector: TlsConnector::from(Arc::new(configuration)),
        })
    }

    /// Completes TLS 1.3 over an already-connected socket owned by the route namespace.
    ///
    /// This is the only client entry point for a socket received through a trusted descriptor
    /// handoff. It repeats the route-validity and genuine-MPTCP checks before any TLS bytes are
    /// exchanged, so a stale route or ordinary TCP descriptor fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an expired route proof, zero handshake timeout, missing genuine MPTCP
    /// negotiation, certificate/name failure, TLS version failure, or timeout.
    pub async fn connect_preconnected(
        &self,
        route: &VerifiedMptcpRoute,
        mptcp: volparossa_mptcp::MptcpStream,
        exit_server_name: ServerName<'static>,
        now_ms: u64,
        handshake_timeout: Duration,
    ) -> Result<Tls13MptcpStream, TcpProxyError> {
        route.ensure_active_at(now_ms)?;
        if handshake_timeout.is_zero() {
            return Err(TcpProxyError::InvalidBinding("TLS handshake timeout"));
        }
        mptcp.require_negotiated()?;
        let stream = mptcp.into_inner();
        let tls = time::timeout(
            handshake_timeout,
            self.connector.connect(exit_server_name, stream),
        )
        .await
        .map_err(|_| TcpProxyError::IdleTimeout)??;
        if tls.get_ref().1.alpn_protocol() != Some(VOLPAROSSA_TCP_ALPN) {
            return Err(TcpProxyError::InvalidBinding("TLS ALPN"));
        }
        Ok(Tls13MptcpStream::Client(tls))
    }
}

/// TLS 1.3-only exit transport for accepted `IPPROTO_MPTCP` streams.
#[derive(Clone)]
pub struct Tls13MptcpServer {
    acceptor: TlsAcceptor,
}

impl Tls13MptcpServer {
    /// Build an exit TLS configuration from its certificate chain and private
    /// key. No client certificate is required because `OPEN_TCP` carries an
    /// independently signed ephemeral client identity.
    ///
    /// # Errors
    ///
    /// Returns a rustls error for an invalid certificate/key pair.
    pub fn new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, TcpProxyError> {
        ensure_crypto_provider()?;
        let mut configuration =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certificate_chain, private_key)?;
        configuration.alpn_protocols = vec![VOLPAROSSA_TCP_ALPN.to_vec()];
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(configuration)),
        })
    }

    /// Complete TLS 1.3 on a stream accepted by
    /// [`volparossa_mptcp::MptcpListener`].
    ///
    /// # Errors
    ///
    /// Returns a handshake I/O error or timeout.
    pub async fn accept(
        &self,
        stream: volparossa_mptcp::MptcpStream,
        handshake_timeout: Duration,
    ) -> Result<Tls13MptcpStream, TcpProxyError> {
        if handshake_timeout.is_zero() {
            return Err(TcpProxyError::InvalidBinding("TLS handshake timeout"));
        }
        stream.require_negotiated()?;
        let tls = time::timeout(handshake_timeout, self.acceptor.accept(stream.into_inner()))
            .await
            .map_err(|_| TcpProxyError::IdleTimeout)??;
        if tls.get_ref().1.alpn_protocol() != Some(VOLPAROSSA_TCP_ALPN) {
            return Err(TcpProxyError::InvalidBinding("TLS ALPN"));
        }
        Ok(Tls13MptcpStream::Server(tls))
    }
}

fn ensure_crypto_provider() -> Result<(), TcpProxyError> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    let _installation = rustls::crypto::ring::default_provider().install_default();
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(TcpProxyError::InvalidBinding(
            "rustls cryptography provider",
        ));
    }
    Ok(())
}

impl AsyncRead for Tls13MptcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Client(stream) => std::pin::Pin::new(stream).poll_read(context, buffer),
            Self::Server(stream) => std::pin::Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for Tls13MptcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Client(stream) => std::pin::Pin::new(stream).poll_write(context, buffer),
            Self::Server(stream) => std::pin::Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Client(stream) => std::pin::Pin::new(stream).poll_flush(context),
            Self::Server(stream) => std::pin::Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Client(stream) => std::pin::Pin::new(stream).poll_shutdown(context),
            Self::Server(stream) => std::pin::Pin::new(stream).poll_shutdown(context),
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::generate_simple_self_signed;
    use rustls::{ProtocolVersion, RootCertStore};
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::{Tls13MptcpClient, Tls13MptcpServer, VOLPAROSSA_TCP_ALPN};

    #[tokio::test]
    async fn configuration_negotiates_only_tls13_and_expected_alpn() {
        let certified =
            generate_simple_self_signed(vec!["exit.volparossa.invalid".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();

        let client = Tls13MptcpClient::new(roots).unwrap();
        let server = Tls13MptcpServer::new(vec![certificate], private_key).unwrap();
        let (client_io, server_io) = duplex(4_096);
        let server_name = ServerName::try_from("exit.volparossa.invalid")
            .unwrap()
            .to_owned();

        let (client_result, server_result) = tokio::join!(
            client.connector.connect(server_name, client_io),
            server.acceptor.accept(server_io),
        );
        let mut client_tls = client_result.unwrap();
        let mut server_tls = server_result.unwrap();
        assert_eq!(
            client_tls.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            server_tls.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            client_tls.get_ref().1.alpn_protocol(),
            Some(VOLPAROSSA_TCP_ALPN)
        );
        assert_eq!(
            server_tls.get_ref().1.alpn_protocol(),
            Some(VOLPAROSSA_TCP_ALPN)
        );

        client_tls.write_all(b"protected").await.unwrap();
        let mut payload = [0_u8; 9];
        server_tls.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"protected");
    }
}
