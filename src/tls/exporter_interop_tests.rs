//! Independent OpenSSL exporter checks through public TLS APIs and native TCP.
//!
//! Opt in with `tls-ring,real-service-e2e`. Python 3 and pyOpenSSL >= 25.2 are
//! required on the execution worker; missing tools fail rather than skip tests.

use super::{CertificateChain, PrivateKey, TlsAcceptor, TlsConnector, TlsError};
use crate::cx::Cx;
use crate::io::{AsyncReadExt, AsyncWriteExt};
use crate::net::TcpStream;
use crate::runtime::{RuntimeBuilder, reactor::create_reactor};
use rustls::{CipherSuite, ClientConfig, ServerConfig, SupportedProtocolVersion};
use std::io::{self, BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");
const ALPN: &[u8] = b"asupersync-exporter-test";
const TLS13_SUITES: [(CipherSuite, &str); 3] = [
    (CipherSuite::TLS13_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"),
    (CipherSuite::TLS13_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"),
    (
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_CHACHA20_POLY1305_SHA256",
    ),
];

/// Own exactly the peer process and stdout reader, including panic/timeout paths.
struct OpenSslPeer {
    child: Child,
    output: Option<JoinHandle<io::Result<String>>>,
}

impl OpenSslPeer {
    fn start(rust_client: bool, version: u8, cipher: &str) -> (Self, SocketAddr) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/openssl_exporter_peer.py");
        let child = Command::new("python3")
            .arg("-u")
            .arg(script)
            .arg("--role")
            .arg(if rust_client { "server" } else { "client" })
            .arg("--version")
            .arg(version.to_string())
            .arg("--cipher")
            .arg(cipher)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("OpenSSL interop requires python3 and pyOpenSSL >= 25.2 on the worker");
        let mut peer = Self {
            child,
            output: None,
        };
        let stdout = peer.child.stdout.take().expect("piped peer stdout");
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        peer.output = Some(thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = String::new();
            reader.by_ref().take(256).read_line(&mut ready)?;
            let _ = ready_tx.send(ready);
            let mut tail = String::new();
            reader.take(4097).read_to_string(&mut tail)?;
            if tail.len() > 4096 {
                return Err(io::Error::other("OpenSSL peer output exceeded its bound"));
            }
            Ok(tail)
        }));
        let ready = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("OpenSSL peer did not publish readiness before its deadline");
        let address: SocketAddr = ready
            .trim()
            .strip_prefix("READY ")
            .expect("OpenSSL peer failed before readiness; check its stderr")
            .parse()
            .expect("valid peer socket address");
        assert!(address.is_ipv4() && address.ip().is_loopback());
        (peer, address)
    }

    fn finish(mut self, version: u8, cipher: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll peer process") {
                break status;
            }
            assert!(Instant::now() < deadline, "OpenSSL peer did not exit");
            thread::sleep(Duration::from_millis(5));
        };
        assert!(
            status.success(),
            "OpenSSL peer rejected the exchange: {status}"
        );
        let output = self
            .output
            .take()
            .expect("peer reader")
            .join()
            .expect("peer reader thread")
            .expect("read peer result");
        let protocol = if version == 13 { "TLSv1.3" } else { "TLSv1.2" };
        assert_eq!(output.trim(), format!("OK {protocol} {cipher}"));
    }
}

impl Drop for OpenSslPeer {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(output) = self.output.take() {
            let _ = output.join();
        }
    }
}

fn endpoints(
    version: &'static SupportedProtocolVersion,
    suite: CipherSuite,
) -> (TlsConnector, TlsAcceptor) {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|candidate| candidate.suite() == suite);
    assert_eq!(provider.cipher_suites.len(), 1);
    let provider = Arc::new(provider);
    let chain = CertificateChain::from_pem(CERT)
        .expect("fixture chain")
        .into_inner();
    let key = PrivateKey::from_pem(KEY)
        .expect("fixture key")
        .clone_inner();
    let mut roots = rustls::RootCertStore::empty();
    for cert in &chain {
        roots.add(cert.clone()).expect("fixture trust anchor");
    }
    let mut client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])
        .expect("client protocol")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .expect("server protocol")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server certificate");
    client.alpn_protocols = vec![ALPN.to_vec()];
    server.alpn_protocols.clone_from(&client.alpn_protocols);
    (TlsConnector::new(client), TlsAcceptor::new(server))
}

fn exchange(rust_client: bool, version: u8, suite: CipherSuite, cipher: &str) -> Option<[u8; 32]> {
    let protocol = if version == 13 {
        &rustls::version::TLS13
    } else {
        &rustls::version::TLS12
    };
    let (connector, acceptor) = endpoints(protocol, suite);
    let (peer, address) = OpenSslPeer::start(rust_client, version, cipher);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("native reactor"))
        .build()
        .expect("native runtime");
    let binding = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("native task context");
        crate::time::timeout(cx.now(), Duration::from_secs(15), async {
            // Both TLS roles connect to the helper's ephemeral TCP listener;
            // TLS client/server roles do not depend on TCP connect/accept roles.
            let tcp = TcpStream::connect(address)
                .await
                .expect("connect to OpenSSL");
            let mut tls = if rust_client {
                connector
                    .connect_with_cx(&cx, "localhost", tcp)
                    .await
                    .expect("client TLS")
            } else {
                acceptor
                    .accept_with_cx(&cx, tcp)
                    .await
                    .expect("server TLS")
            };
            assert_eq!(tls.protocol_version(), Some(protocol.version));
            assert_eq!(tls.negotiated_cipher_suite(), Some(suite));
            assert_eq!(tls.alpn_protocol(), Some(ALPN));
            let binding = if version == 13 {
                let binding = tls
                    .tls_exporter_channel_binding()
                    .expect("public exporter");
                assert_eq!(tls.tls_exporter_channel_binding().unwrap(), binding);
                Some(binding)
            } else {
                assert!(matches!(
                    tls.tls_exporter_channel_binding(),
                    Err(TlsError::Configuration(_))
                ));
                None
            };
            let mut frame = [0; 105];
            tls.read_exact(&mut frame)
                .await
                .expect("OpenSSL exporter frame");
            assert_eq!(&frame[..8], b"RFC9266\0");
            assert_eq!(frame[8], version);
            if let Some(binding) = binding {
                assert_eq!(
                    binding.as_slice(),
                    &frame[9..41],
                    "OpenSSL exporter disagreement"
                );
                assert_ne!(binding.as_slice(), &frame[41..73], "wrong-label control");
                assert_ne!(binding.as_slice(), &frame[73..105], "nonempty-context control");
                assert_eq!(tls.tls_exporter_channel_binding().unwrap(), binding);
                let mut ack = [0; 36];
                ack[..4].copy_from_slice(b"BIND");
                // Send our independently derived result, never reflect peer bytes.
                ack[4..].copy_from_slice(&binding);
                tls.write_all(&ack).await.expect("send public binding");
            } else {
                tls.write_all(b"REJECTED")
                    .await
                    .expect("send TLS 1.2 rejection");
            }
            tls.flush_with_cx(&cx)
                .await
                .expect("flush acknowledgement");
            let mut done = [0; 4];
            tls.read_exact(&mut done)
                .await
                .expect("OpenSSL confirmed comparison");
            assert_eq!(&done, b"DONE");
            tls.shutdown_tls_with_cx(&cx)
                .await
                .expect("send close_notify");
            assert_eq!(
                tls.read_with_cx(&cx, &mut [0; 1])
                    .await
                    .expect("peer close_notify"),
                0
            );
            assert!(matches!(
                tls.tls_exporter_channel_binding(),
                Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
            ));
            tls.shutdown_with_cx(&cx).await.expect("shutdown TCP");
            binding
        })
        .await
        .expect("native OpenSSL exchange deadline")
    }));
    peer.finish(version, cipher);
    binding
}

#[test]
fn openssl_server_agrees_with_public_client_exporter() {
    for (suite, cipher) in TLS13_SUITES {
        let first = exchange(true, 13, suite, cipher).expect("TLS 1.3 binding");
        let second = exchange(true, 13, suite, cipher).expect("fresh TLS 1.3 binding");
        assert_ne!(first, second, "separate TLS connections reused a binding");
    }
}

#[test]
fn openssl_client_agrees_with_public_server_exporter() {
    for (suite, cipher) in TLS13_SUITES {
        let first = exchange(false, 13, suite, cipher).expect("TLS 1.3 binding");
        let second = exchange(false, 13, suite, cipher).expect("fresh TLS 1.3 binding");
        assert_ne!(first, second, "separate TLS connections reused a binding");
    }
}

#[test]
fn openssl_tls12_still_exchanges_data_but_public_exporter_is_refused() {
    for rust_client in [true, false] {
        assert!(
            exchange(
                rust_client,
                12,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                "ECDHE-RSA-AES128-GCM-SHA256",
            )
            .is_none()
        );
    }
}
