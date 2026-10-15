//! `TlsCertificates` + `TlsAcceptorBuilder::from_certificates`: an acceptor
//! whose certificates are looked up per handshake. A default certificate is
//! replaced while the acceptor serves (renewal without a restart, an open
//! connection unaffected); certificates are chosen by SNI name and wildcard,
//! and an unmatched name is refused; mismatched keys and bad names are
//! rejected when stored.
#![cfg(feature = "tls")]

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, RuntimeHandle};
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsCertificates,
    TlsConnector, TlsConnectorBuilder,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::sync::Arc;

const SERVER_CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/tls/server.key");
const PEER_CERT: &[u8] = include_bytes!("fixtures/tls/admission_peer.crt");
const PEER_KEY: &[u8] = include_bytes!("fixtures/tls/admission_peer.key");

fn chain(pem: &[u8]) -> CertificateChain {
    CertificateChain::from_pem(pem).expect("chain")
}

fn key(pem: &[u8]) -> PrivateKey {
    PrivateKey::from_pem(pem).expect("key")
}

fn der(pem: &[u8]) -> Vec<u8> {
    Certificate::from_pem(pem).expect("certificate")[0]
        .as_der()
        .to_vec()
}

/// Accepts `connections` connections, each on its own task, which completes
/// the handshake and echoes one message.
async fn serve(
    handle: RuntimeHandle,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    connections: usize,
) {
    for _ in 0..connections {
        let (tcp, _) = listener.accept().await.expect("accept");
        let acceptor = acceptor.clone();
        drop(handle.spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut buf = [0_u8; 5];
            if tls.read_exact(&mut buf).await.is_ok() {
                let _ = tls.write_all(&buf).await;
                let _ = tls.flush().await;
            }
        }));
    }
}

/// Connects, and returns the leaf certificate the server presented with the
/// open stream.
async fn connect(
    connector: &TlsConnector,
    address: SocketAddr,
    name: &str,
) -> Result<(Vec<u8>, asupersync::tls::TlsStream<TcpStream>), String> {
    let tcp = TcpStream::connect(address).await.expect("connect");
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let leaf = tls.peer_leaf_certificate_der().expect("leaf certificate");
    Ok((leaf, tls))
}

async fn echo(tls: &mut asupersync::tls::TlsStream<TcpStream>) {
    tls.write_all(b"hello").await.expect("write");
    tls.flush().await.expect("flush");
    let mut buf = [0_u8; 5];
    tls.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"hello");
}

#[test]
fn the_default_certificate_is_renewed_while_the_acceptor_serves() {
    let certificates =
        TlsCertificates::with_default(chain(SERVER_CERT), key(SERVER_KEY)).expect("store");
    let acceptor = TlsAcceptorBuilder::from_certificates(certificates.clone())
        .build()
        .expect("acceptor");
    // Both fixtures are self-signed for `localhost`; the client trusts both.
    let connector = TlsConnectorBuilder::new()
        .add_root_certificates(Certificate::from_pem(SERVER_CERT).expect("root"))
        .add_root_certificates(Certificate::from_pem(PEER_CERT).expect("root"))
        .build()
        .expect("connector");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = handle.spawn(serve(handle.clone(), listener, acceptor, 2));

        let (leaf, mut before) = connect(&connector, address, "localhost")
            .await
            .expect("first handshake");
        assert_eq!(leaf, der(SERVER_CERT));

        certificates
            .set_default(chain(PEER_CERT), key(PEER_KEY))
            .expect("renew");
        let (leaf, mut after) = connect(&connector, address, "localhost")
            .await
            .expect("handshake after renewal");
        assert_eq!(
            leaf,
            der(PEER_CERT),
            "new handshakes get the renewed certificate"
        );

        // Both connections work; the first keeps its original session.
        echo(&mut before).await;
        echo(&mut after).await;
        server.await;
    });
}

/// Records nothing and accepts any server certificate, so a test can see
/// which certificate the server chose for an arbitrary SNI name.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[test]
fn certificates_are_chosen_by_sni_name_and_wildcard() {
    let certificates = TlsCertificates::new();
    certificates
        .insert("LocalHost", chain(SERVER_CERT), key(SERVER_KEY))
        .expect("insert localhost");
    certificates
        .insert("*.example.test", chain(PEER_CERT), key(PEER_KEY))
        .expect("insert wildcard");
    assert_eq!(certificates.server_names(), ["*.example.test", "localhost"]);
    let acceptor = TlsAcceptorBuilder::from_certificates(certificates.clone())
        .build()
        .expect("acceptor");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    let connector = TlsConnector::new(client);

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = handle.spawn(serve(handle.clone(), listener, acceptor, 6));

        let leaf = |name: &'static str| {
            let connector = connector.clone();
            async move {
                connect(&connector, address, name)
                    .await
                    .map(|(leaf, _)| leaf)
            }
        };
        assert_eq!(leaf("localhost").await.expect("exact"), der(SERVER_CERT));
        assert_eq!(
            leaf("api.example.test").await.expect("wildcard"),
            der(PEER_CERT)
        );
        // A wildcard covers one label, not deeper names; with no default the
        // handshake is refused.
        assert!(leaf("a.b.example.test").await.is_err());

        assert!(certificates.remove("*.EXAMPLE.test"));
        assert!(leaf("api.example.test").await.is_err(), "removed");

        certificates
            .set_default(chain(SERVER_CERT), key(SERVER_KEY))
            .expect("default");
        assert_eq!(
            leaf("unknown.test").await.expect("default certificate"),
            der(SERVER_CERT)
        );
        assert_eq!(leaf("localhost").await.expect("exact"), der(SERVER_CERT));
        server.await;
    });
}

#[test]
fn bad_certificates_and_names_are_rejected_when_stored() {
    let certificates = TlsCertificates::new();
    assert!(
        certificates
            .insert("localhost", chain(SERVER_CERT), key(PEER_KEY))
            .is_err(),
        "the key must belong to the certificate"
    );
    assert!(
        certificates
            .set_default(CertificateChain::new(), key(SERVER_KEY))
            .is_err()
    );
    // A client never sends the last four as SNI: an IP literal, a U-label,
    // and malformed names were stored and then never matched
    // (br-asupersync-7u9x9b).
    for name in [
        "",
        "*.",
        "a.*.test",
        ".",
        "10.0.0.1",
        "bücher.example",
        "api example.test",
        "a..b.example",
    ] {
        assert!(
            certificates
                .insert(name, chain(SERVER_CERT), key(SERVER_KEY))
                .is_err(),
            "{name:?}"
        );
    }
    assert!(certificates.server_names().is_empty());
    assert!(!certificates.has_default());

    assert!(
        TlsAcceptorBuilder::from_certificates(certificates)
            .require_full_chain()
            .build()
            .is_err(),
        "require_full_chain cannot be checked against a table"
    );
}

/// Private keys loaded by the counting provider's key provider.
static KEY_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// ring's key provider, counting the keys it loads.
#[derive(Debug)]
struct CountingKeys;

impl rustls::crypto::KeyProvider for CountingKeys {
    fn load_private_key(
        &self,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        KEY_LOADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(key_der)
    }
}

static COUNTING_KEYS: CountingKeys = CountingKeys;

fn counting_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::CryptoProvider {
        key_provider: &COUNTING_KEYS,
        ..rustls::crypto::ring::default_provider()
    })
}

/// A table loads its keys with its own provider, so its handshakes are signed
/// by it; it used to load them with the default provider whatever the
/// acceptor's `crypto_provider` said (br-asupersync-7u9x9b).
#[test]
fn a_table_loads_its_keys_with_its_own_provider() {
    let provider = counting_provider();
    let table = TlsCertificates::with_crypto_provider(Arc::clone(&provider));
    let before = KEY_LOADS.load(std::sync::atomic::Ordering::SeqCst);
    table
        .set_default(chain(SERVER_CERT), key(SERVER_KEY))
        .expect("store the default certificate");
    assert!(
        KEY_LOADS.load(std::sync::atomic::Ordering::SeqCst) > before,
        "the table's provider loaded the key"
    );
}

/// `build` refuses an acceptor whose provider differs from its table's, and a
/// table with a provider lends it to an acceptor that names none
/// (br-asupersync-7u9x9b).
#[test]
fn an_acceptor_and_its_table_share_one_provider() {
    let provider = counting_provider();
    let table = TlsCertificates::with_crypto_provider(Arc::clone(&provider));
    table
        .set_default(chain(SERVER_CERT), key(SERVER_KEY))
        .expect("store the default certificate");
    assert!(
        TlsAcceptorBuilder::from_certificates(table.clone())
            .crypto_provider(Arc::clone(&provider))
            .build()
            .is_ok(),
        "the same provider builds"
    );
    assert!(
        TlsAcceptorBuilder::from_certificates(table.clone())
            .build()
            .is_ok(),
        "a table with a provider lends it to the acceptor"
    );
    assert!(
        TlsAcceptorBuilder::from_certificates(table)
            .crypto_provider(counting_provider())
            .build()
            .is_err(),
        "another provider is refused"
    );
    let plain = TlsCertificates::with_default(chain(SERVER_CERT), key(SERVER_KEY))
        .expect("a default-provider table");
    assert!(
        TlsAcceptorBuilder::from_certificates(plain)
            .crypto_provider(provider)
            .build()
            .is_err(),
        "a default-provider table next to an explicit provider is refused"
    );
}
