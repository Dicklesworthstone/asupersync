//! E2E: Transport TCP+UDP — connect, send, receive, close, large transfer.
//!
//! QUIC requires feature flag and external dependencies, tested separately.
//! See net_tcp.rs and net_udp.rs for comprehensive individual protocol tests.
//! This E2E validates the combined transport layer.

#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::redundant_clone)]

#[macro_use]
mod common;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunScenarioIdentity, LoserDrainRecord,
    NormalizedSemantics, ObligationBalanceRecord, Phase, ResourceSurfaceRecord, SeedPlan,
    TerminalOutcome, assert_dual_run_passes, capture_region_close, run_live_adapter,
};
use asupersync::net::tcp::traits::{TcpListenerApi, TcpStreamApi};
use asupersync::net::tcp::virtual_tcp::{VirtualTcpListener, VirtualTcpStream};
use asupersync::net::{TcpListener, TcpStream, UdpSocket};
use common::*;
use futures_lite::future::block_on;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::thread;
use std::time::Duration;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

const LOOPBACK_TRANSPORT_CONTRACT_VERSION: &str = "transport.loopback.close_ordering.v1";
const LOOPBACK_TRANSPORT_VIRTUALIZATION_BOUNDARY: &str = "lab=VirtualTcpListener/VirtualTcpStream pair; live=127.0.0.1 loopback TcpListener/TcpStream; no ambient internet or remote peers";
const LOOPBACK_TRANSPORT_NORMALIZATION_WINDOW: &str = "exact_frame_sequence_and_half_close";
const LOOPBACK_TRANSPORT_FRAMES_SENT: usize = 2;
const LOOPBACK_TRANSPORT_FRAME_ONE: &[u8] = b"frame-alpha";
const LOOPBACK_TRANSPORT_FRAME_TWO: &[u8] = b"frame-omega";
const LOOPBACK_TRANSPORT_ACK: &[u8] = b"ack-close";

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoopbackTransportObservation {
    frames_sent: usize,
    frames_observed: usize,
    payload_bytes_observed: usize,
    ordering_preserved: bool,
    eof_after_client_half_close: bool,
    ack_after_half_close: bool,
    peer_addr_loopback: bool,
}

impl LoopbackTransportObservation {
    fn to_semantics(self) -> NormalizedSemantics {
        let mut outcome = TerminalOutcome::ok();
        outcome.surface_result = Some("expected_loopback_transport_parity".to_string());

        NormalizedSemantics {
            terminal_outcome: outcome,
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: capture_region_close(true, true),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("transport.loopback.close_ordering")
                .with_counter("frames_sent", i64::try_from(self.frames_sent).unwrap_or(0))
                .with_counter(
                    "frames_observed",
                    i64::try_from(self.frames_observed).unwrap_or(0),
                )
                .with_counter(
                    "payload_bytes_observed",
                    i64::try_from(self.payload_bytes_observed).unwrap_or(0),
                )
                .with_counter("ordering_preserved", i64::from(self.ordering_preserved))
                .with_counter(
                    "eof_after_client_half_close",
                    i64::from(self.eof_after_client_half_close),
                )
                .with_counter("ack_after_half_close", i64::from(self.ack_after_half_close))
                .with_counter("peer_addr_loopback", i64::from(self.peer_addr_loopback)),
        }
    }
}

fn transport_loopback_identity() -> DualRunScenarioIdentity {
    let scenario_id = "phase2.transport.loopback_close_ordering";
    let seed_plan = SeedPlan::inherit(0x51A0_C041, format!("seed.{scenario_id}.v1"));
    let mut identity = DualRunScenarioIdentity::phase1(
        scenario_id,
        "transport.loopback.close_ordering",
        LOOPBACK_TRANSPORT_CONTRACT_VERSION,
        "Transport differential pilot preserves ordering and half-close semantics on a controlled virtualized or loopback boundary",
        seed_plan.canonical_seed,
    )
    .with_seed_plan(seed_plan)
    .with_metadata("eligibility_verdict", "eligible_for_pilot")
    .with_metadata("surface_family", "virtual_transport_surface")
    .with_metadata(
        "virtualization_boundary",
        LOOPBACK_TRANSPORT_VIRTUALIZATION_BOUNDARY,
    )
    .with_metadata(
        "compared_observables",
        "frame_order,payload_bytes,eof_after_half_close,ack_after_half_close,peer_addr_loopback",
    )
    .with_metadata(
        "excluded_external_effects",
        "ambient_internet,remote_peer_timing,dns,tls,packet_loss",
    )
    .with_metadata("observability_status", "captured_boundary_exact_frame_observables")
    .with_metadata("normalization_window", LOOPBACK_TRANSPORT_NORMALIZATION_WINDOW)
    .with_metadata("capture_manifest_path", "live.metadata.capture_manifest")
    .with_metadata(
        "normalized_record_path",
        "dual_run.transport.loopback.close_ordering.normalized",
    )
    .with_metadata(
        "artifact_bundle",
        "dual_run.transport.loopback.close_ordering.bundle",
    )
    .with_metadata(
        "repro_command",
        "rch exec -- cargo test --test e2e_transport transport_dual_run_pilot_preserves_virtualized_loopback_close_and_ordering_semantics -- --nocapture",
    );
    identity.phase = Phase::Phase2;
    identity
}

fn observe_virtualized_loopback_transport() -> io::Result<LoopbackTransportObservation> {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 41_001));
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let listener = VirtualTcpListener::new(server_addr);
    let (mut client, server) = VirtualTcpStream::pair(client_addr, server_addr);
    listener.inject_connection(server, client_addr);

    block_on(async move {
        let (mut accepted, peer) = listener.accept().await?;

        client.write_all(LOOPBACK_TRANSPORT_FRAME_ONE).await?;
        client.write_all(LOOPBACK_TRANSPORT_FRAME_TWO).await?;
        client.shutdown(Shutdown::Write)?;

        let mut first = vec![0u8; LOOPBACK_TRANSPORT_FRAME_ONE.len()];
        accepted.read_exact(&mut first).await?;
        let mut second = vec![0u8; LOOPBACK_TRANSPORT_FRAME_TWO.len()];
        accepted.read_exact(&mut second).await?;

        let mut eof_tail = Vec::new();
        accepted.read_to_end(&mut eof_tail).await?;
        accepted.write_all(LOOPBACK_TRANSPORT_ACK).await?;

        let mut ack = vec![0u8; LOOPBACK_TRANSPORT_ACK.len()];
        client.read_exact(&mut ack).await?;

        Ok(LoopbackTransportObservation {
            frames_sent: LOOPBACK_TRANSPORT_FRAMES_SENT,
            frames_observed: usize::from(!first.is_empty()) + usize::from(!second.is_empty()),
            payload_bytes_observed: first.len() + second.len(),
            ordering_preserved: first.as_slice() == LOOPBACK_TRANSPORT_FRAME_ONE
                && second.as_slice() == LOOPBACK_TRANSPORT_FRAME_TWO,
            eof_after_client_half_close: eof_tail.is_empty(),
            ack_after_half_close: ack.as_slice() == LOOPBACK_TRANSPORT_ACK,
            peer_addr_loopback: peer.ip().is_loopback(),
        })
    })
}

fn observe_live_loopback_transport() -> io::Result<LoopbackTransportObservation> {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server_addr = listener.local_addr()?;

        let server = thread::spawn(move || {
            block_on(async move {
                let (mut accepted, peer) = listener.accept().await?;

                let mut first = vec![0u8; LOOPBACK_TRANSPORT_FRAME_ONE.len()];
                accepted.read_exact(&mut first).await?;
                let mut second = vec![0u8; LOOPBACK_TRANSPORT_FRAME_TWO.len()];
                accepted.read_exact(&mut second).await?;

                let mut eof_tail = Vec::new();
                accepted.read_to_end(&mut eof_tail).await?;
                accepted.write_all(LOOPBACK_TRANSPORT_ACK).await?;

                Ok::<_, io::Error>((first, second, eof_tail, peer.ip().is_loopback()))
            })
        });

        thread::sleep(Duration::from_millis(10));

        let client_result = async {
            let mut client = TcpStream::connect(server_addr).await?;
            client.write_all(LOOPBACK_TRANSPORT_FRAME_ONE).await?;
            client.write_all(LOOPBACK_TRANSPORT_FRAME_TWO).await?;
            client.shutdown(Shutdown::Write)?;

            let mut ack = vec![0u8; LOOPBACK_TRANSPORT_ACK.len()];
            client.read_exact(&mut ack).await?;
            Ok::<_, io::Error>(ack)
        }
        .await;

        if client_result.is_err() {
            recover_loopback_transport_server(server_addr).await;
        }

        let (first, second, eof_tail, peer_addr_loopback) = server
            .join()
            .map_err(|_| io::Error::other("loopback server panicked"))??;
        let ack = client_result?;

        Ok(LoopbackTransportObservation {
            frames_sent: LOOPBACK_TRANSPORT_FRAMES_SENT,
            frames_observed: usize::from(!first.is_empty()) + usize::from(!second.is_empty()),
            payload_bytes_observed: first.len() + second.len(),
            ordering_preserved: first.as_slice() == LOOPBACK_TRANSPORT_FRAME_ONE
                && second.as_slice() == LOOPBACK_TRANSPORT_FRAME_TWO,
            eof_after_client_half_close: eof_tail.is_empty(),
            ack_after_half_close: ack.as_slice() == LOOPBACK_TRANSPORT_ACK,
            peer_addr_loopback,
        })
    })
}

fn make_transport_live_result(
    identity: &DualRunScenarioIdentity,
) -> asupersync::lab::LiveRunResult {
    run_live_adapter(
        identity,
        |_config, witness| match observe_live_loopback_transport() {
            Ok(observation) => {
                let mut outcome = TerminalOutcome::ok();
                outcome.surface_result = Some("expected_loopback_transport_parity".to_string());

                witness.set_outcome(outcome);
                witness.set_cancellation(CancellationRecord::none());
                witness.set_loser_drain(LoserDrainRecord::not_applicable());
                witness.set_region_close(capture_region_close(true, true));
                witness.set_obligation_balance(ObligationBalanceRecord::zero());
                witness.record_counter(
                    "frames_sent",
                    i64::try_from(observation.frames_sent).unwrap_or(0),
                );
                witness.record_counter(
                    "frames_observed",
                    i64::try_from(observation.frames_observed).unwrap_or(0),
                );
                witness.record_counter(
                    "payload_bytes_observed",
                    i64::try_from(observation.payload_bytes_observed).unwrap_or(0),
                );
                witness.record_counter(
                    "ordering_preserved",
                    i64::from(observation.ordering_preserved),
                );
                witness.record_counter(
                    "eof_after_client_half_close",
                    i64::from(observation.eof_after_client_half_close),
                );
                witness.record_counter(
                    "ack_after_half_close",
                    i64::from(observation.ack_after_half_close),
                );
                witness.record_counter(
                    "peer_addr_loopback",
                    i64::from(observation.peer_addr_loopback),
                );
                witness.note_nondeterminism(
                    "loopback accept scheduling may vary, but exact frame-order and half-close observables remain stable",
                );
            }
            Err(error) => {
                let mut outcome = TerminalOutcome::err("transport_io_error");
                outcome.surface_result = Some(format!(
                    "live_loopback_transport_io_error:{:?}",
                    error.kind()
                ));
                witness.set_outcome(outcome);
                witness.set_region_close(capture_region_close(true, true));
                witness.set_obligation_balance(ObligationBalanceRecord::zero());
                witness.record_counter("frames_sent", 0);
                witness.record_counter("frames_observed", 0);
                witness.record_counter("payload_bytes_observed", 0);
                witness.record_counter("ordering_preserved", 0);
                witness.record_counter("eof_after_client_half_close", 0);
                witness.record_counter("ack_after_half_close", 0);
                witness.record_counter("peer_addr_loopback", 0);
                witness.note_nondeterminism(format!(
                    "loopback transport observation failed before normalization: {error}"
                ));
            }
        },
    )
}

async fn recover_echo_server(addr: SocketAddr, payload: &[u8]) {
    if let Ok(mut client) = TcpStream::connect(addr).await {
        let _ = client.write_all(payload).await;
    }
}

async fn recover_large_transfer_server(addr: SocketAddr) {
    if let Ok(client) = TcpStream::connect(addr).await {
        drop(client);
    }
}

async fn recover_loopback_transport_server(addr: SocketAddr) {
    if let Ok(mut client) = TcpStream::connect(addr).await {
        let _ = client.write_all(LOOPBACK_TRANSPORT_FRAME_ONE).await;
        let _ = client.write_all(LOOPBACK_TRANSPORT_FRAME_TWO).await;
        let _ = client.shutdown(Shutdown::Write);
    }
}

// =========================================================================
// TCP: connect -> send known-size -> read exact -> close
// =========================================================================

#[test]
fn e2e_tcp_connect_echo_close() {
    init_test("e2e_tcp_connect_echo_close");

    let msg = b"hello transport layer";
    let msg_len = msg.len();

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        test_section!("Start echo server");
        let server = thread::spawn(move || {
            block_on(async {
                let (mut stream, peer) = listener.accept().await?;
                tracing::info!(?peer, "accepted");

                let mut buf = vec![0u8; msg_len];
                stream.read_exact(&mut buf).await?;
                stream.write_all(&buf).await?;
                Ok::<_, io::Error>(())
            })
        });

        thread::sleep(Duration::from_millis(10));

        let client_result = async {
            test_section!("Client connect and echo");
            let mut client = TcpStream::connect(addr).await?;
            client.write_all(msg).await?;

            let mut buf = vec![0u8; msg_len];
            client.read_exact(&mut buf).await?;
            assert_eq!(&buf, msg);

            test_section!("Close");
            drop(client);
            Ok::<_, io::Error>(())
        }
        .await;

        if client_result.is_err() {
            recover_echo_server(addr, msg).await;
        }

        let server_result = server
            .join()
            .map_err(|_| io::Error::other("server panicked"))?;
        client_result?;
        server_result?;

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TCP echo: {result:?}");
    test_complete!("e2e_tcp_echo");
}

// =========================================================================
// UDP: bidirectional datagram exchange
// =========================================================================

#[test]
fn e2e_udp_bidirectional() {
    init_test("e2e_udp_bidirectional");

    let result = block_on(async {
        let mut sock_a = UdpSocket::bind("127.0.0.1:0").await?;
        let mut sock_b = UdpSocket::bind("127.0.0.1:0").await?;
        let addr_a = sock_a.local_addr()?;
        let addr_b = sock_b.local_addr()?;

        test_section!("A -> B");
        sock_a.send_to(b"ping", addr_b).await?;
        let mut buf = [0u8; 64];
        let (n, from) = sock_b.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, addr_a);

        test_section!("B -> A");
        sock_b.send_to(b"pong", addr_a).await?;
        let (n, from) = sock_a.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(from, addr_b);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "UDP bidirectional: {result:?}");
    test_complete!("e2e_udp_bidirectional");
}

// =========================================================================
// TCP: multiple sequential clients with known-size messages
// =========================================================================

#[test]
fn e2e_tcp_multiple_clients() {
    init_test("e2e_tcp_multiple_clients");
    let client_count = 3usize;
    // Each message is "client-N" which is 8 bytes for single-digit N
    let msg_len = 8;

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server = thread::spawn(move || {
            block_on(async {
                for _ in 0..client_count {
                    let (mut stream, _) = listener.accept().await?;
                    let mut buf = vec![0u8; msg_len];
                    stream.read_exact(&mut buf).await?;
                    stream.write_all(&buf).await?;
                }
                Ok::<_, io::Error>(())
            })
        });

        thread::sleep(Duration::from_millis(10));

        let client_result = async {
            test_section!("Connect clients sequentially");
            for i in 0..client_count {
                let mut client = TcpStream::connect(addr).await?;
                let msg = format!("client-{i}");
                client.write_all(msg.as_bytes()).await?;
                let mut buf = vec![0u8; msg.len()];
                client.read_exact(&mut buf).await?;
                assert_eq!(&buf, msg.as_bytes());
            }
            Ok::<_, io::Error>(())
        }
        .await;

        if client_result.is_err() {
            for _ in 0..client_count {
                recover_echo_server(addr, b"recovery").await;
            }
        }

        let server_result = server
            .join()
            .map_err(|_| io::Error::other("server panicked"))?;
        client_result?;
        server_result?;
        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TCP multi-client: {result:?}");
    test_complete!("e2e_tcp_multi_client", clients = client_count);
}

// =========================================================================
// TCP: large data transfer (client -> server via read_to_end)
// =========================================================================

#[test]
fn e2e_tcp_large_transfer() {
    init_test("e2e_tcp_large_transfer");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let data_size = 64 * 1024; // 64KB

        let server = thread::spawn(move || {
            block_on(async {
                let (mut stream, _) = listener.accept().await?;
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            })
        });

        thread::sleep(Duration::from_millis(10));

        let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
        let client_result = async {
            test_section!("Send large data");
            let mut client = TcpStream::connect(addr).await?;
            client.write_all(&data).await?;
            drop(client); // close to signal EOF
            Ok::<_, io::Error>(())
        }
        .await;

        if client_result.is_err() {
            recover_large_transfer_server(addr).await;
        }

        let received = server
            .join()
            .map_err(|_| io::Error::other("server panicked"))??;
        client_result?;
        assert_eq!(received.len(), data_size);
        assert_eq!(received, data);
        tracing::info!(bytes = data_size, "large transfer verified");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TCP large transfer: {result:?}");
    test_complete!("e2e_tcp_large_transfer");
}

// =========================================================================
// Phase 2 differential transport pilot: virtualized transport vs loopback TCP
// =========================================================================

#[test]
fn transport_virtualized_loopback_observation_encodes_normalized_contract() {
    init_test("transport_virtualized_loopback_observation_encodes_normalized_contract");

    let semantics = observe_virtualized_loopback_transport()
        .expect("virtualized transport observation should succeed")
        .to_semantics();

    assert_eq!(
        semantics.resource_surface.contract_scope,
        "transport.loopback.close_ordering"
    );
    assert_eq!(
        semantics.terminal_outcome.surface_result.as_deref(),
        Some("expected_loopback_transport_parity")
    );
    assert_eq!(semantics.resource_surface.counters["frames_sent"], 2);
    assert_eq!(semantics.resource_surface.counters["frames_observed"], 2);
    assert_eq!(
        semantics.resource_surface.counters["payload_bytes_observed"],
        i64::try_from(LOOPBACK_TRANSPORT_FRAME_ONE.len() + LOOPBACK_TRANSPORT_FRAME_TWO.len())
            .unwrap_or(0)
    );
    assert_eq!(semantics.resource_surface.counters["ordering_preserved"], 1);
    assert_eq!(
        semantics.resource_surface.counters["eof_after_client_half_close"],
        1
    );
    assert_eq!(
        semantics.resource_surface.counters["ack_after_half_close"],
        1
    );
    assert_eq!(semantics.resource_surface.counters["peer_addr_loopback"], 1);

    test_complete!("transport_virtualized_loopback_observation_encodes_normalized_contract");
}

#[test]
fn transport_dual_run_pilot_preserves_virtualized_loopback_close_and_ordering_semantics() {
    init_test(
        "transport_dual_run_pilot_preserves_virtualized_loopback_close_and_ordering_semantics",
    );

    let identity = transport_loopback_identity();
    assert_eq!(identity.phase, Phase::Phase2);
    assert_eq!(
        identity.metadata.get("surface_family").map(String::as_str),
        Some("virtual_transport_surface")
    );
    assert_eq!(
        identity
            .metadata
            .get("virtualization_boundary")
            .map(String::as_str),
        Some(LOOPBACK_TRANSPORT_VIRTUALIZATION_BOUNDARY)
    );
    assert_eq!(
        identity
            .metadata
            .get("excluded_external_effects")
            .map(String::as_str),
        Some("ambient_internet,remote_peer_timing,dns,tls,packet_loss")
    );
    let live_result = make_transport_live_result(&identity);

    assert!(
        live_result
            .metadata
            .capture_manifest
            .annotations
            .iter()
            .any(|annotation| annotation.field == "resource_surface.counters.ordering_preserved"),
        "live capture manifest should record ordering evidence",
    );
    assert!(
        live_result
            .metadata
            .nondeterminism_notes
            .iter()
            .any(|note| note.contains("loopback accept scheduling")),
        "live result should preserve the loopback scheduling note",
    );

    let result = DualRunHarness::from_identity(identity)
        .lab(move |_config| {
            observe_virtualized_loopback_transport()
                .expect("virtualized transport observation should succeed")
                .to_semantics()
        })
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(
        result.live.semantics.resource_surface.counters["frames_sent"],
        2
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["frames_observed"],
        2
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["ordering_preserved"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["eof_after_client_half_close"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["ack_after_half_close"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["peer_addr_loopback"],
        1
    );
    assert_eq!(
        result.live.provenance.family.id,
        "phase2.transport.loopback_close_ordering"
    );

    test_complete!(
        "transport_dual_run_pilot_preserves_virtualized_loopback_close_and_ordering_semantics"
    );
}
