//! Bounded-memory proof for ATP-over-QUIC over real loopback UDP.
//!
//! This mirrors `atp_tcp_bounded_memory`: write a large single file in chunks,
//! transfer it through the public QUIC path, stream-compare the committed bytes,
//! and assert peak RSS growth stays far below the transfer size.

#![cfg(all(feature = "tls", feature = "test-internals"))]

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::atp::transport_quic::native_link::{
    QuicClientTls, QuicServerTls, bind_server_endpoint, receive_on_endpoint,
};
use asupersync::net::atp::transport_quic::{
    QuicConfig, QuicTransportError, ReceiveReport, SendReport, send_path,
};
use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, client_config, server_config};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::SecurityContext;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

const TRANSFER_BYTES: usize = 8 * 1024 * 1024;
const PEAK_RSS_GROWTH_CEILING: u64 = 5 * 1024 * 1024;
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
const HARNESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";

const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlDCCATugAwIBAgIUYOTxo/FMMZjqCnJT+IDmJ2BNux0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAXMRUwEwYDVQQDDAxhdHBxLXRlc3QtY2EwWTATBgcqhkjOPQIB\n\
BggqhkjOPQMBBwNCAASAsNg5paEJFgZwYGu7aCzsZYPyDyjzzcT7fi3O5JHGW0xA\n\
pTqjgqykWTDkyfwdITXWXIfrx2D2+QwoGXOV4OFSo2MwYTAdBgNVHQ4EFgQUG872\n\
eUJJNl9C6SZHmR9sCRNzvtYwHwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNz\n\
vtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\n\
RwAwRAIgFLcs0Qdsy190QfKzpvLj28srfpw6wZ2PURF20N+twm8CIFZMWnG65VsE\n\
WkX8ykcdUfalGtZ1XFOTo+aaWs+3gyI1\n\
-----END CERTIFICATE-----\n";

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_quic_mem_{label}_{}_{nanos}",
        std::process::id()
    ))
}

fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .next()
        .expect("one cert")
        .expect("valid cert pem")
}

fn leaf_key() -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(LEAF_KEY_PEM.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .expect("read key pem")
        .expect("one key")
}

fn client_tls() -> QuicClientTls {
    let alpn = vec![ATP_QUIC_ALPN.to_vec()];
    QuicClientTls {
        server_name: ServerName::try_from("localhost").expect("server name"),
        config: client_config(vec![parse_one_cert(CA_CERT_PEM)], alpn).expect("client config"),
    }
}

fn server_tls() -> QuicServerTls {
    let alpn = vec![ATP_QUIC_ALPN.to_vec()];
    QuicServerTls {
        config: server_config(vec![parse_one_cert(LEAF_CERT_PEM)], leaf_key(), alpn)
            .expect("server config"),
    }
}

fn peak_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn write_payload_streaming(path: &Path, len: usize) {
    let mut file = std::fs::File::create(path).expect("create source payload");
    let mut buf = vec![0u8; 1024 * 1024];
    let mut written = 0usize;
    while written < len {
        let take = buf.len().min(len - written);
        for (j, byte) in buf.iter_mut().enumerate().take(take) {
            *byte = ((written + j) % 251) as u8;
        }
        file.write_all(&buf[..take]).expect("write source chunk");
        written += take;
    }
    file.flush().expect("flush source payload");
}

fn files_are_identical(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    if ma.len() != mb.len() {
        return false;
    }
    let mut fa = std::io::BufReader::new(std::fs::File::open(a).expect("open a"));
    let mut fb = std::io::BufReader::new(std::fs::File::open(b).expect("open b"));
    let mut ba = vec![0u8; 256 * 1024];
    let mut bb = vec![0u8; 256 * 1024];
    loop {
        let na = fa.read(&mut ba).expect("read a");
        let nb = fb.read(&mut bb).expect("read b");
        if na != nb {
            return false;
        }
        if na == 0 {
            return true;
        }
        if ba[..na] != bb[..nb] {
            return false;
        }
    }
}

fn config_pair(seed: u64) -> (QuicConfig, QuicConfig) {
    let mut send = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(seed));
    send.client_tls = Some(client_tls());
    send.symbol_size = 32 * 1024;
    send.max_block_size = 1024 * 1024;
    send.repair_overhead = 1.0;
    send.idle_timeout = TEST_TIMEOUT;
    send.handshake_timeout = TEST_TIMEOUT;
    send.accept_timeout = TEST_TIMEOUT;

    let mut recv = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(seed));
    recv.server_tls = Some(server_tls());
    recv.symbol_size = send.symbol_size;
    recv.max_block_size = send.max_block_size;
    recv.repair_overhead = send.repair_overhead;
    recv.idle_timeout = TEST_TIMEOUT;
    recv.handshake_timeout = TEST_TIMEOUT;
    recv.accept_timeout = TEST_TIMEOUT;
    (send, recv)
}

fn spawn_receiver(
    dest_dir: PathBuf,
    recv_cfg: QuicConfig,
) -> (
    SocketAddr,
    mpsc::Receiver<Result<ReceiveReport, QuicTransportError>>,
    thread::JoinHandle<()>,
) {
    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let (result_tx, result_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread()
            .build()
            .expect("receiver runtime");
        let result = runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap_or_else(Cx::for_testing);
            let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let server_endpoint = bind_server_endpoint(&cx, listen).await?;
            let server_addr = server_endpoint.local_addr();
            addr_tx.send(server_addr).expect("send receiver address");
            receive_on_endpoint(
                &cx,
                server_endpoint,
                &dest_dir,
                &recv_cfg,
                "atp-quic-server",
            )
            .await
        }));
        result_tx.send(result).expect("send receiver result");
    });
    let addr = addr_rx
        .recv_timeout(HARNESS_TIMEOUT)
        .expect("receiver bound address");
    (addr, result_rx, handle)
}

fn spawn_sender(
    addr: SocketAddr,
    source: PathBuf,
    send_cfg: QuicConfig,
) -> (
    mpsc::Receiver<Result<SendReport, QuicTransportError>>,
    thread::JoinHandle<()>,
) {
    let (result_tx, result_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread()
            .build()
            .expect("sender runtime");
        let result = runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap_or_else(Cx::for_testing);
            send_path(&cx, addr, &source, send_cfg, "atp-quic-client").await
        }));
        result_tx.send(result).expect("send sender result");
    });
    (result_rx, handle)
}

fn recv_transfer_result<T>(
    label: &'static str,
    rx: mpsc::Receiver<Result<T, QuicTransportError>>,
) -> Result<T, QuicTransportError> {
    rx.recv_timeout(HARNESS_TIMEOUT)
        .unwrap_or_else(|err| panic!("{label} did not finish within {HARNESS_TIMEOUT:?}: {err}"))
}

#[test]
fn real_udp_quic_large_file_is_byte_identical_and_bounded_memory() {
    let root = unique_tmp("large");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).expect("create src dir");
    std::fs::create_dir_all(&dst_dir).expect("create dst dir");

    let source = src_dir.join("big.bin");
    write_payload_streaming(&source, TRANSFER_BYTES);
    let baseline_rss = peak_rss_bytes();

    let (send_cfg, recv_cfg) = config_pair(0xB05);
    let (addr, recv_rx, receiver) = spawn_receiver(dst_dir.clone(), recv_cfg);
    let (send_rx, sender) = spawn_sender(addr, source.clone(), send_cfg);
    let send = recv_transfer_result("sender", send_rx);
    let recv = recv_transfer_result("receiver", recv_rx);
    sender.join().expect("sender thread");
    receiver.join().expect("receiver thread");

    let (send, recv) = match (send, recv) {
        (Ok(send), Ok(recv)) => (send, recv),
        (send, recv) => panic!("bounded-memory QUIC transfer failed: send={send:?}, recv={recv:?}"),
    };
    let after_rss = peak_rss_bytes();

    assert!(recv.committed);
    assert_eq!(send.bytes_sent, TRANSFER_BYTES as u64);
    assert_eq!(recv.bytes_received, TRANSFER_BYTES as u64);
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);

    let committed = dst_dir.join("big.bin");
    assert!(
        files_are_identical(&source, &committed),
        "committed QUIC payload must match source"
    );

    if let (Some(before), Some(after)) = (baseline_rss, after_rss) {
        let growth = after.saturating_sub(before);
        println!(
            "atp_quic_bounded_memory rss: before_bytes={before} after_bytes={after} \
             growth_bytes={growth} ceiling_bytes={PEAK_RSS_GROWTH_CEILING} \
             transfer_bytes={TRANSFER_BYTES}"
        );
        assert!(
            growth < PEAK_RSS_GROWTH_CEILING,
            "peak RSS grew by {growth} bytes during a {TRANSFER_BYTES}-byte QUIC transfer \
             (before {before}, after {after}, ceiling {PEAK_RSS_GROWTH_CEILING}); \
             transport_quic must stream blocks and staged output instead of buffering the object"
        );
    }

    let _ = root;
}
