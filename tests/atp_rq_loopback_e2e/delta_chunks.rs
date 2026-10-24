//! Native changed-chunk transfer, compatibility, and control-tampering checks.

use super::*;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::FrameType;
use asupersync::net::atp::transport_rq::{
    send_path_with_authenticated_control, send_path_with_delta_chunks,
};
use std::io::Seek as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// The existing bounded RQ manifest uses near-frame-sized fixed chunks.
const CHUNK_BYTES: usize = 1024 * 1024 - 12;
const CONTROL_AUTH_EXTENSION: u16 = 0x5251;
const CHUNKS_OFFER_EXTENSION: u16 = 0x5252;

fn config() -> RqConfig {
    RqConfig {
        enable_delta: true,
        udp_fanout: 1,
        max_transfer_bytes: 16 * 1024 * 1024,
        delta_control_timeout: Duration::from_secs(5),
        accept_timeout: Duration::from_secs(5),
        ..auth_test_config()
    }
}

fn sender(addr: SocketAddr, source: PathBuf, config: RqConfig) -> Result<SendReport, RqError> {
    sender_with_offer(addr, source, config, true)
}

fn sender_with_offer(
    addr: SocketAddr,
    source: PathBuf,
    config: RqConfig,
    offer_delta: bool,
) -> Result<SendReport, RqError> {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .enable_platform_reactor(true)
        .build()
        .expect("delta sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("delta sender context");
        asupersync::time::timeout(
            cx.now(),
            Duration::from_secs(30),
            async {
                if offer_delta {
                    send_path_with_delta_chunks(&cx, addr, &source, config, "sender").await
                } else {
                    send_path_with_authenticated_control(&cx, addr, &source, config, "sender").await
                }
            },
        )
        .await
        .expect("delta sender reaches its terminal result")
    }))
}

fn receiver(
    destination: PathBuf,
) -> (SocketAddr, thread::JoinHandle<Result<ReceiveReport, RqError>>) {
    spawn_receiver_with_options(
        destination,
        config(),
        RqReceiveOptions::new().with_delta_chunks(true),
    )
}

fn payload(chunks: usize, tail: usize) -> Vec<u8> {
    (0..chunks * CHUNK_BYTES + tail)
        .map(|index| {
            let chunk = (index / CHUNK_BYTES) as u32;
            let offset = (index % CHUNK_BYTES) as u32;
            (offset.wrapping_mul(1_664_525).rotate_left(7)
                ^ chunk.wrapping_mul(2_654_435_761)) as u8
        })
        .collect()
}

fn fixture(label: &str, source_bytes: &[u8], baseline: &[u8]) -> (PathBuf, PathBuf) {
    let root = unique_tmp(label);
    let source_dir = root.join("source");
    let destination = root.join("destination");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::create_dir_all(&destination).unwrap();
    let source = source_dir.join("payload.bin");
    std::fs::write(&source, source_bytes).unwrap();
    std::fs::write(destination.join("payload.bin"), baseline).unwrap();
    (source, destination)
}

fn assert_clean_destination(destination: &Path, expected: &[u8]) {
    assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), expected);
    let mut names = std::fs::read_dir(destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("payload.bin")],
        "terminal transfer must retire its private staging directory"
    );
}

fn assert_delta(send: &SendReport, received: &ReceiveReport, transferred: usize) {
    assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
    assert!(received.committed);
    assert_eq!(send.bytes_sent, transferred as u64);
    assert_eq!(send.receipt.bytes_received, transferred as u64);
    assert_eq!(received.bytes_received, transferred as u64);
    assert_eq!(send.symbols_sent, 0);
    assert_eq!(received.symbols_accepted, 0);
    assert_eq!(send.feedback_rounds, 0);
    assert_eq!(received.feedback_rounds, 0);
}

#[test]
fn small_edit_transmits_only_its_changed_chunk() {
    let baseline = payload(3, 16_519);
    let mut updated = baseline.clone();
    updated[CHUNK_BYTES + 71] ^= 0xA5;
    let (source, destination) = fixture("delta_small_edit", &updated, &baseline);
    let (receiver_addr, receive) = receiver(destination.clone());
    let (addr, relay, _, data_payload_bytes) = proxy(receiver_addr, Attack::Pass);
    let sent = sender(addr, source, config()).unwrap();
    let received = receive.join().unwrap().unwrap();
    relay.join().unwrap();
    assert_delta(&sent, &received, CHUNK_BYTES);
    assert!(sent.bytes_sent < updated.len() as u64 / 2);
    let observed = data_payload_bytes.load(Ordering::SeqCst);
    assert!(
        observed >= CHUNK_BYTES && observed < updated.len() / 2,
        "actual ObjectData payloads, including their binary headers, must be smaller than the full object: {observed}"
    );
    assert_clean_destination(&destination, &updated);
}

#[test]
fn append_transmits_only_the_new_tail() {
    let baseline = payload(2, 0);
    let updated = payload(2, 16_519);
    let (source, destination) = fixture("delta_append", &updated, &baseline);
    let (addr, receive) = receiver(destination.clone());
    let sent = sender(addr, source, config()).unwrap();
    let received = receive.join().unwrap().unwrap();
    assert_delta(&sent, &received, 16_519);
    assert_clean_destination(&destination, &updated);
}

#[test]
fn reordered_and_repeated_chunks_reconstruct_at_their_new_offsets() {
    let baseline = payload(3, 0);
    let mut updated = Vec::with_capacity(baseline.len());
    updated.extend_from_slice(&baseline[2 * CHUNK_BYTES..3 * CHUNK_BYTES]);
    updated.extend_from_slice(&baseline[..CHUNK_BYTES]);
    updated.extend_from_slice(&baseline[..CHUNK_BYTES]);
    let (source, destination) = fixture("delta_reordered", &updated, &baseline);
    let (addr, receive) = receiver(destination.clone());
    let sent = sender(addr, source, config()).unwrap();
    let received = receive.join().unwrap().unwrap();
    assert_delta(&sent, &received, 0);
    assert_clean_destination(&destination, &updated);
}

#[derive(Clone)]
enum Attack {
    Pass,
    TamperData,
    InterruptData,
    TamperCompletion,
    StripOffer,
    TamperOffer,
    MutateFile { path: PathBuf, offset: u64, byte: u8 },
}

impl Attack {
    fn target(&self) -> Option<FrameType> {
        match self {
            Self::Pass => None,
            Self::TamperData | Self::InterruptData => Some(FrameType::ObjectData),
            Self::TamperCompletion => Some(FrameType::ObjectComplete),
            Self::StripOffer | Self::TamperOffer => Some(FrameType::ObjectManifest),
            Self::MutateFile { .. } => Some(FrameType::ObjectRequest),
        }
    }
}

fn relay_direction(
    mut from: std::net::TcpStream,
    mut to: std::net::TcpStream,
    attack: Attack,
    observed: &AtomicBool,
    data_payload_bytes: &AtomicUsize,
) {
    let mut codec = AtpFrameCodec::new();
    let mut buffered = BytesMut::new();
    let mut input = [0u8; 8192];
    let result = (|| -> std::io::Result<()> {
        loop {
            while let Some(mut frame) = codec
                .decode(&mut buffered)
                .map_err(std::io::Error::other)?
            {
                if frame.frame_type() == FrameType::ObjectData {
                    data_payload_bytes.fetch_add(frame.payload.len(), Ordering::SeqCst);
                }
                let target = Some(frame.frame_type()) == attack.target();
                let authenticated = if target {
                    match &attack {
                        Attack::StripOffer | Attack::TamperOffer => {
                            frame.header.extensions.contains_key(&CHUNKS_OFFER_EXTENSION)
                        }
                        Attack::MutateFile { .. } => {
                            // The first request is signed inside its JSON envelope,
                            // before sequenced control begins. Mutate before forwarding
                            // it, so the source check and later baseline copy are causal.
                            serde_json::from_slice::<serde_json::Value>(frame.payload())
                                .ok()
                                .is_some_and(|body| {
                                    body["control_seq"].as_u64() == Some(1)
                                        && body["request"]["mode"].as_str() == Some("delta_chunks")
                                        && body["server_auth_tag"].as_array()
                                            .is_some_and(|tag| tag.len() == 32)
                                })
                        }
                        _ => frame.header.extensions.contains_key(&CONTROL_AUTH_EXTENSION),
                    }
                } else {
                    false
                };
                if target && authenticated && !observed.swap(true, Ordering::SeqCst) {
                    match &attack {
                        Attack::Pass => unreachable!("pass-through relay has no attack target"),
                        Attack::TamperData | Attack::TamperCompletion => {
                            let byte = frame.payload.last_mut().expect("nonempty signed frame");
                            *byte ^= 1;
                        }
                        Attack::InterruptData => {
                            let wire = frame.to_wire_bytes().map_err(std::io::Error::other)?;
                            to.write_all(&wire[..wire.len() / 2])?;
                            return Ok(());
                        }
                        Attack::StripOffer => {
                            frame.header.extensions.remove(&CHUNKS_OFFER_EXTENSION);
                        }
                        Attack::TamperOffer => {
                            frame.header.extensions.get_mut(&CHUNKS_OFFER_EXTENSION)
                                .expect("offered capability")[0] ^= 1;
                        }
                        Attack::MutateFile { path, offset, byte } => {
                            let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
                            file.seek(std::io::SeekFrom::Start(*offset))?;
                            file.write_all(&[*byte])?;
                            file.flush()?;
                        }
                    }
                }
                to.write_all(&frame.to_wire_bytes().map_err(std::io::Error::other)?)?;
            }
            let read = from.read(&mut input)?;
            if read == 0 {
                return Ok(());
            }
            buffered.extend_from_slice(&input[..read]);
        }
    })();
    let _ = result;
    let _ = from.shutdown(std::net::Shutdown::Both);
    let _ = to.shutdown(std::net::Shutdown::Both);
}

fn proxy(
    receiver: SocketAddr,
    attack: Attack,
) -> (
    SocketAddr,
    thread::JoinHandle<()>,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let observed = Arc::new(AtomicBool::new(false));
    let relay_observed = Arc::clone(&observed);
    let data_payload_bytes = Arc::new(AtomicUsize::new(0));
    let relay_data_bytes = Arc::clone(&data_payload_bytes);
    let handle = thread::spawn(move || {
        let (client, _) = listener.accept().unwrap();
        let server = std::net::TcpStream::connect(receiver).unwrap();
        for stream in [&client, &server] {
            stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
            stream.set_nodelay(true).unwrap();
        }
        let client_read = client.try_clone().unwrap();
        let server_write = server.try_clone().unwrap();
        let outgoing_observed = Arc::clone(&relay_observed);
        let outgoing_data_bytes = Arc::clone(&relay_data_bytes);
        let outgoing_attack = attack.clone();
        let outgoing = thread::spawn(move || {
            relay_direction(
                client_read,
                server_write,
                outgoing_attack,
                &outgoing_observed,
                &outgoing_data_bytes,
            );
        });
        relay_direction(server, client, attack, &relay_observed, &relay_data_bytes);
        outgoing.join().unwrap();
    });
    (addr, handle, observed, data_payload_bytes)
}

#[test]
fn changed_chunk_offer_data_and_completion_tampering_preserve_the_original_destination() {
    for attack in [Attack::TamperOffer, Attack::TamperData, Attack::TamperCompletion] {
        let baseline = payload(2, 0);
        let mut updated = baseline.clone();
        updated[CHUNK_BYTES + 11] ^= 0x5A;
        let (source, destination) = fixture("delta_tamper", &updated, &baseline);
        let (receiver_addr, receive) = receiver(destination.clone());
        let (addr, relay, observed, _) = proxy(receiver_addr, attack);
        let sent = sender(addr, source, config());
        let received = receive.join().unwrap();
        relay.join().unwrap();
        assert!(observed.load(Ordering::SeqCst), "signed target frame was reached");
        assert!(sent.is_err());
        assert!(matches!(received, Err(RqError::Authentication(_))));
        assert_clean_destination(&destination, &baseline);
    }
}

#[test]
fn interrupted_changed_chunk_does_not_publish_partial_reconstruction() {
    let baseline = payload(2, 0);
    let mut updated = baseline.clone();
    updated[CHUNK_BYTES + 11] ^= 0x5A;
    let (source, destination) = fixture("delta_interrupted", &updated, &baseline);
    let (receiver_addr, receive) = receiver(destination.clone());
    let (addr, relay, observed, _) = proxy(receiver_addr, Attack::InterruptData);
    let sent = sender(addr, source, config());
    let received = receive.join().unwrap();
    relay.join().unwrap();
    assert!(observed.load(Ordering::SeqCst));
    assert!(sent.is_err() && received.is_err());
    assert_clean_destination(&destination, &baseline);
}

#[test]
fn opting_in_preserves_full_transfer_fallback_for_prior_authenticated_peers() {
    let baseline = payload(2, 0);
    let mut updated = baseline.clone();
    updated[CHUNK_BYTES + 11] ^= 0x5A;
    for new_sender in [true, false] {
        let (source, destination) = fixture("delta_legacy", &updated, &baseline);
        let (addr, receive) = if new_sender {
            spawn_receiver_with_options(
                destination.clone(),
                config(),
                RqReceiveOptions::new().with_authenticated_control(true),
            )
        } else {
            receiver(destination.clone())
        };
        let sent = if new_sender {
            sender(addr, source, config())
        } else {
            sender_with_offer(addr, source, config(), false)
        }
        .unwrap();
        let received = receive.join().unwrap().unwrap();
        assert!(sent.receipt.committed && received.committed);
        assert_eq!(sent.bytes_sent, updated.len() as u64);
        assert_eq!(received.bytes_received, updated.len() as u64);
        assert_clean_destination(&destination, &updated);
    }
}

#[test]
fn changed_chunk_sender_refuses_completely_legacy_full_object_control() {
    let baseline = payload(2, 0);
    let mut updated = baseline.clone();
    updated[CHUNK_BYTES + 11] ^= 0x5A;
    let (source, destination) = fixture("delta_legacy_refusal", &updated, &baseline);
    let (addr, receive) = spawn_receiver(destination.clone(), config());
    let sent = sender(addr, source, config());
    let received = receive.join().unwrap();
    assert!(matches!(sent, Err(RqError::Authentication(_))));
    assert!(received.is_err());
    assert_clean_destination(&destination, &baseline);
}

#[test]
fn stripping_the_optional_offer_preserves_authenticated_full_object_fallback() {
    let baseline = payload(2, 0);
    let mut updated = baseline.clone();
    updated[CHUNK_BYTES + 11] ^= 0x5A;
    let (source, destination) = fixture("delta_stripped_offer", &updated, &baseline);
    let (receiver_addr, receive) = receiver(destination.clone());
    let (addr, relay, observed, data_payload_bytes) = proxy(receiver_addr, Attack::StripOffer);
    let sent = sender(addr, source, config()).unwrap();
    let received = receive.join().unwrap().unwrap();
    relay.join().unwrap();
    assert!(observed.load(Ordering::SeqCst));
    assert!(sent.receipt.committed && received.committed);
    assert_eq!(sent.bytes_sent, updated.len() as u64);
    assert_eq!(received.bytes_received, updated.len() as u64);
    assert!(sent.symbols_sent > 0 && received.symbols_accepted > 0);
    assert_eq!(data_payload_bytes.load(Ordering::SeqCst), 0);
    assert_clean_destination(&destination, &updated);
}

#[test]
fn source_and_reused_baseline_changes_after_the_signed_request_prevent_commit() {
    for mutate_source in [true, false] {
        let baseline = payload(2, 0);
        let mut updated = baseline.clone();
        updated[CHUNK_BYTES + 11] ^= 0x5A;
        let (source, destination) = fixture("delta_mutated_file", &updated, &baseline);
        // This range belongs to an unrequested/reused chunk. Checking only the
        // remote missing subset would overlook either of these mutations.
        let offset = 17;
        let byte = baseline[offset] ^ 0x33;
        let path = if mutate_source {
            source.clone()
        } else {
            destination.join("payload.bin")
        };
        let mut expected_destination = baseline.clone();
        if !mutate_source {
            expected_destination[offset] = byte;
        }
        let (receiver_addr, receive) = receiver(destination.clone());
        let (addr, relay, observed, _) = proxy(
            receiver_addr,
            Attack::MutateFile { path, offset: offset as u64, byte },
        );
        let sent = sender(addr, source, config());
        let received = receive.join().unwrap();
        relay.join().unwrap();
        assert!(observed.load(Ordering::SeqCst), "signed missing-chunk request was reached");
        if mutate_source {
            assert!(matches!(sent, Err(RqError::Source(_) | RqError::Integrity(_))));
            assert!(received.is_err());
        } else {
            assert!(sent.is_err());
            assert!(matches!(received, Err(RqError::Integrity(_))));
        }
        assert_clean_destination(&destination, &expected_destination);
    }
}
