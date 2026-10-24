//! Real TCP/UDP regressions for the additive authenticated RQ control surface.

use super::*;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType};
use asupersync::net::atp::protocol::varint::VarInt;
use asupersync::net::atp::transport_rq::send_path_with_authenticated_control;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONTROL_AUTH_EXTENSION: u16 = 0x5251;

fn strict_config(drop_one_in: u32) -> RqConfig {
    RqConfig {
        enable_delta: true,
        symbol_size: 256,
        max_block_size: 4 * 1024,
        udp_fanout: 1,
        repair_overhead: 1.0,
        round0_loss_target: 0.0,
        source_retransmit_rounds: 8,
        debug_drop_one_in: drop_one_in,
        delta_control_timeout: Duration::from_secs(5),
        accept_timeout: Duration::from_secs(5),
        ..auth_test_config()
    }
}

fn strict_sender(addr: SocketAddr, source: PathBuf, config: RqConfig) -> Result<SendReport, RqError> {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .enable_platform_reactor(true)
        .build()
        .expect("strict sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("strict sender context");
        asupersync::time::timeout(
            cx.now(),
            Duration::from_secs(20),
            send_path_with_authenticated_control(&cx, addr, &source, config, "sender"),
        )
        .await
        .expect("strict sender finishes within its test deadline")
    }))
}

fn fixture(label: &str) -> (PathBuf, PathBuf, Vec<u8>, Vec<u8>) {
    let root = unique_tmp(label);
    let source_dir = root.join("source");
    let destination = root.join("destination");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::create_dir_all(&destination).unwrap();
    let payload: Vec<u8> = (0..16_519u32)
        .map(|i| i.wrapping_mul(1_664_525).rotate_left(3) as u8)
        .collect();
    let original = vec![0xA5; payload.len()];
    let source = source_dir.join("payload.bin");
    std::fs::write(&source, &payload).unwrap();
    std::fs::write(destination.join("payload.bin"), &original).unwrap();
    (source, destination, payload, original)
}

#[derive(Clone)]
enum RelayAction {
    Pass,
    Tamper(FrameType),
    Capture(FrameType, Arc<Mutex<Option<Frame>>>),
    Replay(FrameType, Frame),
}

impl RelayAction {
    fn target(&self) -> Option<FrameType> {
        match self {
            Self::Pass => None,
            Self::Tamper(kind) | Self::Capture(kind, _) | Self::Replay(kind, _) => Some(*kind),
        }
    }
}

/// A real on-path relay changes a frame after its peer signed it. It retains
/// canonical codec framing so failures must come from authentication.
fn relay_direction(
    mut from: std::net::TcpStream,
    mut to: std::net::TcpStream,
    action: RelayAction,
    handled: &AtomicBool,
) {
    let mut codec = AtpFrameCodec::new();
    let mut buffered = BytesMut::new();
    let mut input = [0u8; 4096];
    let result = (|| -> std::io::Result<()> {
        loop {
            while let Some(mut frame) = codec
                .decode(&mut buffered)
                .map_err(std::io::Error::other)?
            {
                if action.target() == Some(frame.frame_type())
                    && frame.header.extensions.contains_key(&CONTROL_AUTH_EXTENSION)
                    && !handled.swap(true, Ordering::SeqCst)
                {
                    match &action {
                        RelayAction::Pass => {}
                        RelayAction::Capture(_, slot) => {
                            *slot.lock().unwrap() = Some(frame.clone());
                        }
                        RelayAction::Replay(_, captured) => frame = captured.clone(),
                        RelayAction::Tamper(kind) => {
                            let mut body: serde_json::Value =
                                serde_json::from_slice(frame.payload()).unwrap();
                            match kind {
                                FrameType::ObjectRequest => {
                                    body["round_loss_fraction"] = serde_json::json!(0.99);
                                }
                                FrameType::Proof => {
                                    body["committed"] = serde_json::json!(false);
                                }
                                FrameType::ObjectComplete => {
                                    body["round_symbols_sent"] = serde_json::json!(
                                        body["round_symbols_sent"].as_u64().unwrap_or(0) + 1
                                    );
                                }
                                _ => unreachable!(),
                            }
                            frame.payload = serde_json::to_vec(&body).unwrap();
                            frame.header.payload_length =
                                VarInt::new(frame.payload.len() as u64).unwrap();
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
    // A terminal peer/error closes both relay halves so the other endpoint
    // cannot stay parked after the attack or test deadline.
    let _ = result;
    let _ = from.shutdown(std::net::Shutdown::Both);
    let _ = to.shutdown(std::net::Shutdown::Both);
}

fn proxy(
    receiver: SocketAddr,
    action: RelayAction,
) -> (SocketAddr, thread::JoinHandle<()>, Arc<AtomicBool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handled = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&handled);
    let handle = thread::spawn(move || {
        let (client, _) = listener.accept().unwrap();
        let server = std::net::TcpStream::connect(receiver).unwrap();
        for stream in [&client, &server] {
            stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
            stream.set_nodelay(true).unwrap();
        }
        let client_read = client.try_clone().unwrap();
        let server_write = server.try_clone().unwrap();
        let action_out = action.clone();
        let observed_out = Arc::clone(&observed);
        let outbound = thread::spawn(move || {
            relay_direction(client_read, server_write, action_out, &observed_out);
        });
        relay_direction(server, client, action, &observed);
        outbound.join().unwrap();
    });
    (addr, handle, handled)
}

fn strict_receiver(
    destination: PathBuf,
    config: RqConfig,
) -> (SocketAddr, thread::JoinHandle<Result<ReceiveReport, RqError>>) {
    spawn_receiver_with_options(
        destination,
        config,
        RqReceiveOptions::new().with_authenticated_control(true),
    )
}

#[test]
fn strict_full_object_roundtrips_with_loss_and_existing_legacy_mode_still_works() {
    for drop_one_in in [0, 3] {
        let (source, destination, payload, _) = fixture("strict_roundtrip");
        let (receiver_addr, receiver) = strict_receiver(destination.clone(), strict_config(0));
        let (addr, relay, _) = proxy(receiver_addr, RelayAction::Pass);
        let send = strict_sender(addr, source, strict_config(drop_one_in)).unwrap();
        let received = receiver.join().unwrap().unwrap();
        relay.join().unwrap();
        assert!(send.receipt.committed && send.receipt.sha_ok && send.receipt.merkle_ok);
        assert!(received.committed);
        assert!(send.symbols_sent > 0 && received.symbols_accepted > 0);
        if drop_one_in > 0 {
            assert!(send.feedback_rounds > 0, "a repair round really occurred");
        }
        assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), payload);
    }

    let (source, destination, payload, _) = fixture("legacy_roundtrip");
    let (addr, receiver) = spawn_receiver(destination.clone(), strict_config(0));
    let send = run_sender(addr, source, strict_config(0)).unwrap();
    assert!(receiver.join().unwrap().unwrap().committed);
    assert!(send.receipt.committed);
    assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), payload);
}

#[test]
fn strict_control_refuses_legacy_selection_and_preserves_signed_noop() {
    let (source, destination, payload, original) = fixture("strict_legacy_refusal");
    let (addr, receiver) = spawn_receiver(destination.clone(), strict_config(0));
    assert!(matches!(
        strict_sender(addr, source.clone(), strict_config(0)),
        Err(RqError::Authentication(_))
    ));
    assert!(receiver.join().unwrap().is_err());
    assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), original);

    std::fs::write(destination.join("payload.bin"), &payload).unwrap();
    let (addr, receiver) = strict_receiver(destination.clone(), strict_config(0));
    let send = strict_sender(addr, source, strict_config(0)).unwrap();
    assert!(receiver.join().unwrap().unwrap().committed);
    assert_eq!(send.bytes_sent, 0);
    assert_eq!(send.symbols_sent, 0);
    assert!(send.receipt.committed_paths.is_empty());
    assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), payload);
}

#[test]
fn strict_control_rejects_real_mitm_round_feedback_and_proof_tampering() {
    for target in [
        FrameType::ObjectComplete,
        FrameType::ObjectRequest,
        FrameType::Proof,
    ] {
        let (source, destination, payload, original) = fixture("strict_mitm");
        let (receiver_addr, receiver) = strict_receiver(destination.clone(), strict_config(0));
        let (addr, relay, attacked) = proxy(receiver_addr, RelayAction::Tamper(target));
        let send = strict_sender(addr, source, strict_config(3));
        let received = receiver.join().unwrap();
        relay.join().unwrap();
        assert!(attacked.load(Ordering::SeqCst), "target frame was reached");
        match target {
            FrameType::ObjectComplete => {
                assert!(matches!(received, Err(RqError::Authentication(_))));
                assert!(send.is_err());
                assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), original);
            }
            FrameType::ObjectRequest => {
                assert!(matches!(send, Err(RqError::Authentication(_))));
                assert!(received.is_err());
                assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), original);
            }
            FrameType::Proof => {
                assert!(matches!(send, Err(RqError::Authentication(_))));
                // The peer committed before its genuine proof was tampered.
                assert!(received.unwrap().committed);
                assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), payload);
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn strict_control_rejects_a_genuine_completion_replayed_into_a_fresh_session() {
    let (source, destination, payload, original) = fixture("strict_session_replay");
    let captured = Arc::new(Mutex::new(None));
    let (receiver_addr, receiver) = strict_receiver(destination.clone(), strict_config(0));
    let (addr, relay, observed) = proxy(
        receiver_addr,
        RelayAction::Capture(FrameType::ObjectComplete, Arc::clone(&captured)),
    );
    strict_sender(addr, source.clone(), strict_config(0)).unwrap();
    assert!(receiver.join().unwrap().unwrap().committed);
    relay.join().unwrap();
    assert!(observed.load(Ordering::SeqCst));
    assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), payload);
    let old_completion = captured.lock().unwrap().clone().expect("genuine signed frame");

    // Force FullObject again with identical source/path/key. Fresh session
    // challenges must still make the first transfer's valid tag unusable.
    std::fs::write(destination.join("payload.bin"), &original).unwrap();
    let (receiver_addr, receiver) = strict_receiver(destination.clone(), strict_config(0));
    let (addr, relay, replayed) = proxy(
        receiver_addr,
        RelayAction::Replay(FrameType::ObjectComplete, old_completion),
    );
    assert!(strict_sender(addr, source, strict_config(0)).is_err());
    let received = receiver.join().unwrap();
    relay.join().unwrap();
    assert!(replayed.load(Ordering::SeqCst));
    assert!(matches!(received, Err(RqError::Authentication(_))));
    assert_eq!(std::fs::read(destination.join("payload.bin")).unwrap(), original);
}
