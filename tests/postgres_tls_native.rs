//! PostgreSQL TLS transport regressions using actual TCP sockets and rustls.
//! The peer speaks the startup protocol; it is not a PostgreSQL backend.
//! Backend coverage remains in postgres_real_server.rs.
#![cfg(all(
    feature = "postgres",
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]
#![allow(clippy::pedantic, clippy::nursery)]

use asupersync::Cx;
use asupersync::database::pool::AsyncConnectionManager;
use asupersync::database::postgres::PgConnectionManager;
use asupersync::database::postgres::{
    PgConnectOptions, PgConnection, PgError, PgTlsOptions, PgTlsVerification,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::tls::Certificate;
use asupersync::types::{CancelKind, Outcome};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const CA: &[u8] = include_bytes!("fixtures/tls/postgres_ca.crt");
const LEAF: &[u8] = include_bytes!("fixtures/tls/postgres_server.crt");
const WRONG_HOST: &[u8] = include_bytes!("fixtures/tls/postgres_wronghost.crt");
const KEY: &[u8] = include_bytes!("fixtures/tls/admission_peer.key");
const WRONG_CA: &[u8] = include_bytes!("fixtures/x509_adversarial/ca.crt");

fn native_runtime(workers: usize) -> asupersync::runtime::Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("reactor"))
        .build()
        .expect("runtime")
}

fn socket(listener: &TcpListener) -> TcpStream {
    let (socket, _) = listener.accept().expect("accept");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}

fn ssl_request(socket: &mut TcpStream) {
    let mut request = [0; 8];
    socket.read_exact(&mut request).expect("SSLRequest");
    assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
}

fn backend_message(stream: &mut impl Write, tag: u8, payload: &[u8]) {
    stream.write_all(&[tag]).unwrap();
    stream
        .write_all(&(u32::try_from(payload.len()).unwrap() + 4).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn frontend_message(stream: &mut impl Read) -> (u8, Vec<u8>) {
    let mut header = [0; 5];
    stream.read_exact(&mut header).expect("frontend message");
    let len = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!((4..=4096).contains(&len));
    let mut payload = vec![0; len - 4];
    stream.read_exact(&mut payload).unwrap();
    (header[0], payload)
}

fn startup(stream: &mut impl Read) -> usize {
    let mut length = [0; 4];
    stream.read_exact(&mut length).expect("encrypted startup");
    let length = u32::from_be_bytes(length) as usize;
    assert!((8..4096).contains(&length));
    let mut message = vec![0; length - 4];
    stream.read_exact(&mut message).unwrap();
    assert_eq!(&message[..4], &[0, 3, 0, 0]);
    assert!(
        message
            .windows(b"tls_user".len())
            .any(|part| part == b"tls_user")
    );
    length
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA-256 of the URL's password; one block is the whole key.
fn salted_password(salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut block = hmac_sha256(b"tls_secret", &[salt, &1_u32.to_be_bytes()].concat());
    let mut salted = block;
    for _ in 1..iterations {
        block = hmac_sha256(b"tls_secret", &block);
        for (byte, next) in salted.iter_mut().zip(block) {
            *byte ^= next;
        }
    }
    salted
}

fn sasl_message(auth_type: u32, body: &[u8]) -> Vec<u8> {
    [&auth_type.to_be_bytes()[..], body].concat()
}

/// Plays the server side of SCRAM-SHA-256 (RFC 5802, RFC 7677). The client
/// refuses cleartext and MD5 passwords, so this is the exchange it completes.
/// The peer advertises no -PLUS mechanism, so over TLS the client must send
/// the `y,,` supported-but-not-used GS2 header. The proof check shows the
/// client derived its answer from the URL's password.
fn authenticate(stream: &mut (impl Read + Write)) {
    const MECHANISM: &[u8] = b"SCRAM-SHA-256\0";
    const SALT: &[u8] = b"asupersync-pg-tls-salt";
    const ITERATIONS: u32 = 4096;

    startup(stream);
    backend_message(stream, b'R', &sasl_message(10, b"SCRAM-SHA-256\0\0"));
    let (tag, initial) = frontend_message(stream);
    assert_eq!(tag, b'p', "SASLInitialResponse");
    let rest = initial
        .strip_prefix(MECHANISM)
        .expect("client selects SCRAM-SHA-256");
    let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
    let client_first = std::str::from_utf8(&rest[4..]).unwrap();
    assert_eq!(client_first.len(), length);
    let client_first_bare = client_first
        .strip_prefix("y,,")
        .expect("TLS without an advertised -PLUS must send the y,, GS2 header");
    let client_nonce = client_first_bare
        .split(',')
        .find_map(|part| part.strip_prefix("r="))
        .expect("client nonce");
    let nonce = format!("{client_nonce}pg-tls-server-nonce");
    let server_first = format!("r={nonce},s={},i={ITERATIONS}", STANDARD.encode(SALT));
    backend_message(stream, b'R', &sasl_message(11, server_first.as_bytes()));

    let (tag, client_final) = frontend_message(stream);
    assert_eq!(tag, b'p', "SASLResponse");
    let client_final = String::from_utf8(client_final).unwrap();
    let (without_proof, proof) = client_final.rsplit_once(",p=").expect("client proof");
    assert_eq!(
        without_proof,
        format!("c={},r={nonce}", STANDARD.encode("y,,"))
    );
    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let salted = salted_password(SALT, ITERATIONS);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key: [u8; 32] = Sha256::digest(client_key).into();
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let expected_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature)
        .map(|(key, signature)| key ^ signature)
        .collect();
    assert_eq!(STANDARD.decode(proof).unwrap(), expected_proof);
    let server_key = hmac_sha256(&salted, b"Server Key");
    let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());
    let server_final = format!("v={}", STANDARD.encode(server_signature));
    backend_message(stream, b'R', &sasl_message(12, server_final.as_bytes()));
    backend_message(stream, b'R', &0_u32.to_be_bytes());
    backend_message(stream, b'K', &[0, 0, 0, 7, 0, 0, 0, 9]);
    backend_message(stream, b'Z', b"I");
}

fn server_config(leaf: &[u8]) -> Arc<rustls::ServerConfig> {
    let certificates = CertificateDer::pem_slice_iter(leaf)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap(),
    )
}

fn trusted_options(mode: PgTlsVerification, wrong_ca: bool) -> PgTlsOptions {
    let roots = Certificate::from_pem(if wrong_ca { WRONG_CA } else { CA }).unwrap();
    PgTlsOptions::new()
        .verification(mode)
        .root_certificate(roots[0].clone())
        .handshake_timeout(Duration::from_secs(3))
}

fn url(port: u16) -> String {
    format!("postgres://tls_user:tls_secret@127.0.0.1:{port}/tls_database?sslmode=require")
}

#[test]
fn private_ca_modes_authenticate_and_close_retained_tls_connections() {
    for workers in [1, 2] {
        for mode in [PgTlsVerification::VerifyFull, PgTlsVerification::VerifyCa] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let (closed_tx, closed_rx) = std::sync::mpsc::channel();
            let server = std::thread::spawn(move || {
                let mut socket = socket(&listener);
                ssl_request(&mut socket);
                socket.write_all(b"S").unwrap();
                // The CA-only success deliberately uses a nonmatching hostname.
                let leaf = if mode == PgTlsVerification::VerifyCa {
                    WRONG_HOST
                } else {
                    LEAF
                };
                let conn = rustls::ServerConnection::new(server_config(leaf)).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, socket);
                authenticate(&mut tls);
                assert_eq!(frontend_message(&mut tls), (b'X', Vec::new()));
                let mut byte = [0];
                let closed = matches!(tls.sock.read(&mut byte), Ok(0));
                closed_tx.send(closed).unwrap();
                assert!(
                    closed,
                    "close must shut down TCP before the client drops its object"
                );
            });
            let runtime = native_runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let connect_url = url(port);
                let outcome = if mode == PgTlsVerification::VerifyFull {
                    // Exercise the public URL path and a real explicit CA file.
                    let root = concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/fixtures/tls/postgres_ca.crt"
                    );
                    let root = root.replace('/', "%2F");
                    PgConnection::connect(
                        &cx,
                        &format!("{connect_url}&sslmode=verify-full&sslrootcert={root}"),
                    )
                    .await
                } else {
                    PgConnection::connect_with_tls_options(
                        &cx,
                        PgConnectOptions::parse(&connect_url).unwrap(),
                        trusted_options(mode, false),
                    )
                    .await
                };
                let mut connection = match outcome {
                    Outcome::Ok(connection) => connection,
                    other => {
                        panic!("private CA connect workers={workers} mode={mode:?}: {other:?}")
                    }
                };
                connection.close().await.unwrap();
                assert!(
                    closed_rx
                        .recv_timeout(Duration::from_secs(2))
                        .expect("retained TLS transport close")
                );
                // Keep the connection alive through the peer's EOF assertion.
                drop(connection);
            });
            server.join().unwrap();
            eprintln!(
                "event=pg_tls_authenticated workers={workers} mode={mode:?} password_encrypted=true retained_socket_closed=true"
            );
        }
    }
}

#[test]
fn private_ca_modes_reject_wrong_authority_and_full_rejects_wrong_host() {
    for workers in [1, 2] {
        for (mode, wrong_ca, wrong_host) in [
            (PgTlsVerification::VerifyFull, true, false),
            (PgTlsVerification::VerifyCa, true, false),
            (PgTlsVerification::VerifyFull, false, true),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let mut socket = socket(&listener);
                ssl_request(&mut socket);
                socket.write_all(b"S").unwrap();
                let config = server_config(if wrong_host { WRONG_HOST } else { LEAF });
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, socket);
                let mut byte = [0];
                // No startup or password bytes may reach an unverified peer.
                assert!(!matches!(tls.read(&mut byte), Ok(n) if n > 0));
            });
            let runtime = native_runtime(workers);
            let outcome = runtime.block_on(async {
                let cx = Cx::current().unwrap();
                PgConnection::connect_with_tls_options(
                    &cx,
                    PgConnectOptions::parse(&url(port)).unwrap(),
                    trusted_options(mode, wrong_ca),
                )
                .await
            });
            match outcome {
                Outcome::Err(PgError::Tls(message)) => {
                    assert!(
                        message.contains("certificate"),
                        "expected certificate verification error: {message}"
                    );
                    eprintln!(
                        "event=pg_tls_rejected workers={workers} mode={mode:?} wrong_ca={wrong_ca} wrong_host={wrong_host} error={message:?}"
                    );
                }
                other => panic!("expected TLS verification error, got {other:?}"),
            }
            server.join().unwrap();
        }
    }
}

#[derive(Default)]
struct PollWitness {
    pending: AtomicBool,
    polls: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StallStage {
    SslResponse,
    TlsHandshake,
    Authentication,
}

fn stalled_exchange(workers: usize, stage: StallStage, cancel: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // A separate explicit Cx prevents the runtime's own task cancellation
    // machinery from supplying the wake that this adapter must register.
    let owner = Cx::for_testing();
    let cancel_owner = owner.clone();
    let witness = Arc::new(PollWitness::default());
    let server_witness = Arc::clone(&witness);
    let (observed_tx, observed_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut socket = socket(&listener);
        ssl_request(&mut socket);
        let mut hello_bytes = 0;
        if stage == StallStage::TlsHandshake {
            socket.write_all(b"S").unwrap();
            let mut header = [0; 5];
            socket
                .read_exact(&mut header)
                .expect("ClientHello record header");
            assert_eq!(header[0], 22, "expected TLS handshake record");
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert!((1..=16384).contains(&len));
            let mut hello = vec![0; len];
            socket.read_exact(&mut hello).unwrap();
            assert_eq!(hello[0], 1, "expected ClientHello");
            hello_bytes = len + 5;
        } else if stage == StallStage::Authentication {
            socket.write_all(b"S").unwrap();
            let mut conn = rustls::ServerConnection::new(server_config(LEAF)).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut socket);
            hello_bytes = startup(&mut tls);
            // The TLS handshake is complete and Startup was encrypted, but
            // this peer never emits AuthenticationRequest or ReadyForQuery.
        }
        // Require an observed Pending poll that stays parked after all peer
        // input has ceased. The peer supplies no wake or application response.
        let wait_until = Instant::now() + Duration::from_secs(1);
        let parked_polls = loop {
            let polls = server_witness.polls.load(Ordering::Acquire);
            std::thread::sleep(Duration::from_millis(20));
            if polls != 0
                && polls == server_witness.polls.load(Ordering::Acquire)
                && server_witness.pending.load(Ordering::Acquire)
            {
                break polls;
            }
            assert!(
                Instant::now() < wait_until,
                "connection did not park after TLS input"
            );
        };
        let triggered = Instant::now();
        if cancel {
            cancel_owner.cancel_with(CancelKind::User, Some("PostgreSQL TLS handshake cancelled"));
        }
        observed_tx
            .send((hello_bytes, parked_polls, triggered))
            .unwrap();
        let mut bytes = [0; 4096];
        loop {
            match socket.read(&mut bytes) {
                Ok(0) => break,
                Ok(_) => {} // A concurrently flushed handshake record is not a peer wake.
                Err(error) => panic!("cancel/timeout did not drop TLS socket: {error}"),
            }
        }
    });
    let runtime = native_runtime(workers);
    let started = Instant::now();
    let result = runtime.block_on(async {
        let options = PgConnectOptions::parse(&url(port)).unwrap();
        let bound = if cancel {
            Duration::from_secs(30)
        } else {
            Duration::from_millis(400)
        };
        let tls = trusted_options(PgTlsVerification::VerifyFull, false)
            .handshake_timeout(if stage == StallStage::Authentication {
                Duration::from_secs(30)
            } else {
                bound
            })
            .connect_timeout(if stage == StallStage::Authentication {
                bound
            } else {
                Duration::from_secs(30)
            });
        let mut connect =
            std::pin::pin!(PgConnection::connect_with_tls_options(&owner, options, tls));
        poll_fn(|task_cx| {
            witness.pending.store(false, Ordering::Release);
            witness.polls.fetch_add(1, Ordering::AcqRel);
            let result = connect.as_mut().poll(task_cx);
            witness
                .pending
                .store(result.is_pending(), Ordering::Release);
            result
        })
        .await
    });
    let finished = Instant::now();
    let (hello_bytes, parked_polls, triggered) =
        observed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let elapsed = finished.duration_since(started);
    assert!(
        finished.duration_since(triggered) < Duration::from_secs(2),
        "parked exchange did not retire promptly: {elapsed:?}"
    );
    if cancel {
        assert!(
            matches!(result, Outcome::Cancelled(ref reason)
            if reason.kind == CancelKind::User && reason.message.as_deref() == Some("PostgreSQL TLS handshake cancelled")),
            "cancel attribution lost: {result:?}"
        );
    } else {
        assert!(
            matches!(result, Outcome::Err(PgError::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut),
            "expected TLS exchange timeout: {result:?}"
        );
        assert!(elapsed >= Duration::from_millis(400));
    }
    server.join().unwrap();
    eprintln!(
        "event=pg_tls_stall_retired workers={workers} stage={stage:?} cancelled={cancel} hello_bytes={hello_bytes} parked_polls={parked_polls} elapsed_ms={} socket_closed=true",
        elapsed.as_millis()
    );
}

#[test]
fn stalled_ssl_response_and_tls_handshake_have_native_deadlines() {
    for workers in [1, 2] {
        for stage in [StallStage::SslResponse, StallStage::TlsHandshake] {
            stalled_exchange(workers, stage, false);
        }
    }
}

#[test]
fn external_owner_cancel_wakes_silent_tls_negotiation() {
    for workers in [1, 2] {
        for stage in [
            StallStage::SslResponse,
            StallStage::TlsHandshake,
            StallStage::Authentication,
        ] {
            stalled_exchange(workers, stage, true);
        }
    }
}

#[test]
fn whole_connect_deadline_includes_silent_postgres_authentication() {
    for workers in [1, 2] {
        stalled_exchange(workers, StallStage::Authentication, false);
    }
}

#[test]
fn pooled_private_ca_policy_survives_idle_reconnect() {
    for workers in [1, 2] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for exchange in 0..2 {
                let mut socket = socket(&listener);
                ssl_request(&mut socket);
                socket.write_all(b"S").unwrap();
                let conn = rustls::ServerConnection::new(server_config(WRONG_HOST)).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, socket);
                authenticate(&mut tls);
                assert_eq!(frontend_message(&mut tls), (b'Q', b"SELECT 1\0".to_vec()));
                if exchange == 1 {
                    backend_message(&mut tls, b'C', b"SELECT 1\0");
                    backend_message(&mut tls, b'Z', b"I");
                    assert_eq!(frontend_message(&mut tls), (b'X', Vec::new()));
                }
                // The first request observes a dropped idle connection. The
                // second connection must reuse the restricted CA-only policy.
            }
        });
        let runtime = native_runtime(workers);
        runtime.block_on(async {
            let cx = Cx::for_testing();
            let options = PgConnectOptions::parse(&url(port)).unwrap();
            let manager = PgConnectionManager::new(options)
                .with_tls_options(trusted_options(PgTlsVerification::VerifyCa, false));
            let mut connection = match manager.connect(&cx).await {
                Outcome::Ok(connection) => connection,
                other => panic!("pooled verified connect: {other:?}"),
            };
            assert!(manager.is_valid(&cx, &mut connection).await);
            assert!(matches!(
                connection.execute_unchecked(&cx, "SELECT 1").await,
                Outcome::Err(_)
            ));
            assert!(matches!(
                connection.execute_unchecked(&cx, "SELECT 1").await,
                Outcome::Ok(1)
            ));
            assert!(manager.is_valid(&cx, &mut connection).await);
            connection.close().await.unwrap();
        });
        server.join().unwrap();
        eprintln!(
            "event=pg_tls_reconnected workers={workers} explicit_ca_retained=true verify_ca_retained=true pool_valid=true"
        );
    }
}

#[test]
fn verified_modes_refuse_plaintext_without_sending_startup() {
    for mode in ["verify-ca", "verify-full"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut socket = socket(&listener);
            ssl_request(&mut socket);
            socket.write_all(b"N").unwrap();
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).unwrap(),
                0,
                "no plaintext startup allowed"
            );
        });
        let runtime = native_runtime(1);
        let result = runtime.block_on(async {
            PgConnection::connect(
                &Cx::current().unwrap(),
                &format!("{}&sslmode={mode}", url(port)),
            )
            .await
        });
        assert!(
            matches!(result, Outcome::Err(PgError::TlsRequired)),
            "TLS refusal must fail: {result:?}"
        );
        server.join().unwrap();
    }
}
