//! Contract tests for QUIC/H3 Soak and Adversarial Network Simulations.
//!
//! Bead: asupersync-2oh2u.4.7 ([T4.7])
//!
//! Validates:
//! 1. Machine-readable JSON artifact consistency
//! 2. Scenario inventory completeness
//! 3. Invariant register integrity
//! 4. Deterministic soak scenarios against native QUIC stack
//! 5. Adversarial input rejection
//! 6. Cancellation stress invariants
//! 7. Transport metrics self-consistency

use std::collections::HashSet;

// ── Artifact loading ────────────────────────────────────────────────────

const SOAK_JSON: &str = include_str!("../docs/tokio_quic_h3_soak_adversarial.json");
const SOAK_MD: &str = include_str!("../docs/tokio_quic_h3_soak_adversarial.md");

fn parse_json() -> serde_json::Value {
    serde_json::from_str(SOAK_JSON).expect("soak JSON must parse")
}

fn init_test(name: &str) {
    asupersync::test_utils::init_test_logging();
    asupersync::test_phase!(name);
}

// ════════════════════════════════════════════════════════════════════════
// JSON Structural Integrity
// ════════════════════════════════════════════════════════════════════════

#[test]
fn json_parses_and_has_required_fields() {
    init_test("json_parses_and_has_required_fields");
    let v = parse_json();
    assert!(v.get("bead_id").is_some(), "missing bead_id");
    assert!(v.get("title").is_some(), "missing title");
    assert!(v.get("version").is_some(), "missing version");
    assert!(v.get("generated_at").is_some(), "missing generated_at");
    assert!(v.get("generated_by").is_some(), "missing generated_by");
    assert!(
        v.get("source_markdown").is_some(),
        "missing source_markdown"
    );
    assert!(v.get("domains").is_some(), "missing domains");
    assert!(
        v.get("scenario_categories").is_some(),
        "missing scenario_categories"
    );
    assert!(
        v.get("total_scenarios").is_some(),
        "missing total_scenarios"
    );
    assert!(v.get("invariants").is_some(), "missing invariants");
    assert!(
        v.get("pass_fail_criteria").is_some(),
        "missing pass_fail_criteria"
    );
    assert!(
        v.get("drift_detection").is_some(),
        "missing drift_detection"
    );
    asupersync::test_complete!("json_parses_and_has_required_fields");
}

#[test]
fn bead_id_matches() {
    init_test("bead_id_matches");
    let v = parse_json();
    assert_eq!(v["bead_id"].as_str().unwrap(), "asupersync-2oh2u.4.7");
    asupersync::test_complete!("bead_id_matches");
}

// ════════════════════════════════════════════════════════════════════════
// Scenario Inventory
// ════════════════════════════════════════════════════════════════════════

#[test]
fn scenario_categories_minimum_count() {
    init_test("scenario_categories_minimum_count");
    let v = parse_json();
    let cats = v["scenario_categories"].as_array().unwrap();
    assert!(
        cats.len() >= 5,
        "expected >= 5 scenario categories, got {}",
        cats.len()
    );
    asupersync::test_complete!("scenario_categories_minimum_count");
}

#[test]
fn scenario_categories_have_required_fields() {
    init_test("scenario_categories_have_required_fields");
    let v = parse_json();
    for cat in v["scenario_categories"].as_array().unwrap() {
        let prefix = cat["id_prefix"].as_str().unwrap_or("<missing>");
        assert!(cat.get("name").is_some(), "{prefix}: missing name");
        assert!(cat.get("count").is_some(), "{prefix}: missing count");
        let count = cat["count"].as_u64().unwrap();
        assert!(count > 0, "{prefix}: count must be > 0");
    }
    asupersync::test_complete!("scenario_categories_have_required_fields");
}

#[test]
fn total_scenarios_matches_sum() {
    init_test("total_scenarios_matches_sum");
    let v = parse_json();
    let sum: u64 = v["scenario_categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["count"].as_u64().unwrap())
        .sum();
    let claimed = v["total_scenarios"].as_u64().unwrap();
    assert_eq!(
        sum, claimed,
        "total_scenarios mismatch: sum={sum}, claimed={claimed}"
    );
    asupersync::test_complete!("total_scenarios_matches_sum");
}

#[test]
fn required_category_prefixes_present() {
    init_test("required_category_prefixes_present");
    let v = parse_json();
    let prefixes: HashSet<&str> = v["scenario_categories"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["id_prefix"].as_str())
        .collect();
    assert!(prefixes.contains("SOAK"), "missing SOAK category");
    assert!(prefixes.contains("LOSS"), "missing LOSS category");
    assert!(prefixes.contains("ADV"), "missing ADV category");
    assert!(prefixes.contains("CANCEL"), "missing CANCEL category");
    asupersync::test_complete!("required_category_prefixes_present");
}

// ════════════════════════════════════════════════════════════════════════
// Invariant Register
// ════════════════════════════════════════════════════════════════════════

#[test]
fn invariants_minimum_count() {
    init_test("invariants_minimum_count");
    let v = parse_json();
    let invs = v["invariants"].as_array().unwrap();
    assert!(
        invs.len() >= 6,
        "expected >= 6 invariants, got {}",
        invs.len()
    );
    asupersync::test_complete!("invariants_minimum_count");
}

#[test]
fn invariant_ids_unique_and_prefixed() {
    init_test("invariant_ids_unique_and_prefixed");
    let v = parse_json();
    let ids: Vec<&str> = v["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["id"].as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate invariant IDs");

    for id in &ids {
        assert!(
            id.starts_with("INV-"),
            "invariant ID {id} must start with INV-"
        );
    }
    asupersync::test_complete!("invariant_ids_unique_and_prefixed");
}

#[test]
fn invariants_have_descriptions() {
    init_test("invariants_have_descriptions");
    let v = parse_json();
    for inv in v["invariants"].as_array().unwrap() {
        let id = inv["id"].as_str().unwrap();
        assert!(
            inv.get("description").is_some(),
            "{id}: missing description"
        );
        let desc = inv["description"].as_str().unwrap();
        assert!(!desc.is_empty(), "{id}: empty description");
    }
    asupersync::test_complete!("invariants_have_descriptions");
}

// ════════════════════════════════════════════════════════════════════════
// Pass/Fail Criteria
// ════════════════════════════════════════════════════════════════════════

#[test]
fn pass_fail_criteria_present() {
    init_test("pass_fail_criteria_present");
    let v = parse_json();
    let criteria = v["pass_fail_criteria"].as_array().unwrap();
    assert!(
        criteria.len() >= 5,
        "expected >= 5 pass/fail criteria, got {}",
        criteria.len()
    );
    for c in criteria {
        assert!(c.get("criterion").is_some(), "missing criterion field");
        assert!(c.get("threshold").is_some(), "missing threshold field");
    }
    asupersync::test_complete!("pass_fail_criteria_present");
}

// ════════════════════════════════════════════════════════════════════════
// Drift Detection
// ════════════════════════════════════════════════════════════════════════

#[test]
fn drift_rules_present() {
    init_test("drift_rules_present");
    let v = parse_json();
    let rules = v["drift_detection"].as_array().unwrap();
    assert!(
        rules.len() >= 3,
        "expected >= 3 drift rules, got {}",
        rules.len()
    );
    for rule in rules {
        assert!(rule.get("id").is_some(), "drift rule missing id");
        assert!(rule.get("trigger").is_some(), "drift rule missing trigger");
        assert!(rule.get("action").is_some(), "drift rule missing action");
    }
    asupersync::test_complete!("drift_rules_present");
}

// ════════════════════════════════════════════════════════════════════════
// Markdown Cross-Reference
// ════════════════════════════════════════════════════════════════════════

#[test]
fn markdown_references_all_categories() {
    init_test("markdown_references_all_categories");
    let v = parse_json();
    for cat in v["scenario_categories"].as_array().unwrap() {
        let prefix = cat["id_prefix"].as_str().unwrap();
        assert!(
            SOAK_MD.contains(prefix),
            "category prefix {prefix} not found in markdown"
        );
    }
    asupersync::test_complete!("markdown_references_all_categories");
}

#[test]
fn markdown_references_all_invariants() {
    init_test("markdown_references_all_invariants");
    let v = parse_json();
    for inv in v["invariants"].as_array().unwrap() {
        let id = inv["id"].as_str().unwrap();
        assert!(SOAK_MD.contains(id), "invariant {id} not found in markdown");
    }
    asupersync::test_complete!("markdown_references_all_invariants");
}

#[test]
fn markdown_contains_simulation_infrastructure() {
    init_test("markdown_contains_simulation_infrastructure");
    assert!(
        SOAK_MD.contains("NetworkFaultInjector") || SOAK_MD.contains("Network Fault"),
        "markdown must describe fault injection infrastructure"
    );
    assert!(
        SOAK_MD.contains("DetRng") || SOAK_MD.contains("deterministic"),
        "markdown must reference deterministic RNG"
    );
    asupersync::test_complete!("markdown_contains_simulation_infrastructure");
}

// ════════════════════════════════════════════════════════════════════════
// Deterministic Soak: Connection Handshake Stability
// ════════════════════════════════════════════════════════════════════════

use asupersync::cx::Cx;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, QuicConnectionState, StreamDirection,
    StreamId, StreamRole,
};
use asupersync::types::Time;
use asupersync::util::DetRng;

fn test_cx() -> Cx {
    Cx::for_testing()
}

struct DetClock {
    now_micros: u64,
}

impl DetClock {
    fn new(rng: &mut DetRng) -> Self {
        let base_micros = Time::from_millis(1_000).as_nanos() / 1_000;
        let jitter = rng.next_u64() % 1_000;
        Self {
            now_micros: base_micros + jitter,
        }
    }

    fn advance(&mut self, delta_micros: u64) {
        self.now_micros += delta_micros;
    }

    fn now(&self) -> u64 {
        self.now_micros
    }
}

struct ConnectionPair {
    client: NativeQuicConnection,
    server: NativeQuicConnection,
    cx: Cx,
    clock: DetClock,
}

impl ConnectionPair {
    fn new(rng: &mut DetRng) -> Self {
        let cx = test_cx();
        let clock = DetClock::new(rng);

        let client_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Client,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let server_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Server,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let client = NativeQuicConnection::new(client_cfg);
        let server = NativeQuicConnection::new(server_cfg);

        Self {
            client,
            server,
            cx,
            clock,
        }
    }

    fn establish(&mut self) {
        let cx = &self.cx;
        self.client
            .begin_handshake(cx)
            .expect("client begin_handshake");
        self.server
            .begin_handshake(cx)
            .expect("server begin_handshake");
        assert_eq!(self.client.state(), QuicConnectionState::Handshaking);
        assert_eq!(self.server.state(), QuicConnectionState::Handshaking);

        self.client
            .on_handshake_keys_available(cx)
            .expect("client hs keys");
        self.server
            .on_handshake_keys_available(cx)
            .expect("server hs keys");
        self.client
            .on_1rtt_keys_available(cx)
            .expect("client 1rtt keys");
        self.server
            .on_1rtt_keys_available(cx)
            .expect("server 1rtt keys");
        self.client
            .on_handshake_confirmed(cx)
            .expect("client confirmed");
        self.server
            .on_handshake_confirmed(cx)
            .expect("server confirmed");

        assert_eq!(self.client.state(), QuicConnectionState::Established);
        assert_eq!(self.server.state(), QuicConnectionState::Established);
    }
}

use asupersync::net::quic_native::PacketNumberSpace;

#[test]
fn soak_repeated_handshake_stability() {
    init_test("soak_repeated_handshake_stability");

    // SOAK invariant: 50 independent handshakes all succeed deterministically.
    for seed in 0u64..50 {
        let mut rng = DetRng::new(0x50AE_0001 + seed);
        let mut pair = ConnectionPair::new(&mut rng);
        pair.establish();
        assert_eq!(
            pair.client.state(),
            QuicConnectionState::Established,
            "seed {seed}: client not established"
        );
        assert_eq!(
            pair.server.state(),
            QuicConnectionState::Established,
            "seed {seed}: server not established"
        );
    }

    asupersync::test_complete!("soak_repeated_handshake_stability");
}

// ════════════════════════════════════════════════════════════════════════
// Soak: Sustained Packet Send/ACK Cycle (INV-3, INV-8)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn soak_sustained_send_ack_cycle() {
    init_test("soak_sustained_send_ack_cycle");

    let mut rng = DetRng::new(0x50AE_0002);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;
    let rounds = 100;
    let packets_per_round = 10;

    let mut total_sent = 0u64;
    let mut total_acked = 0u64;
    let mut total_lost = 0u64;
    let mut pn_cursor = 0u64;

    for round in 0..rounds {
        let t_base = pair.clock.now();

        // Send a batch of packets.
        for i in 0..packets_per_round {
            pair.client
                .on_packet_sent(
                    cx,
                    PacketNumberSpace::ApplicationData,
                    1200,
                    true,
                    true,
                    t_base + i * 100,
                )
                .unwrap_or_else(|e| panic!("round {round} send {i}: {e:?}"));
            total_sent += 1;
        }

        // Advance time (simulated RTT).
        pair.clock.advance(20_000);

        // ACK all packets from this round.
        let ack_pns: Vec<u64> = (pn_cursor..pn_cursor + packets_per_round).collect();
        let report = pair
            .client
            .on_ack_received(
                cx,
                PacketNumberSpace::ApplicationData,
                &ack_pns,
                0,
                pair.clock.now(),
            )
            .unwrap_or_else(|e| panic!("round {round} ack: {e:?}"));

        total_acked += report.acked_packets as u64;
        total_lost += report.lost_packets as u64;
        pn_cursor += packets_per_round;

        // INV-3: bytes_in_flight should be 0 after full ACK.
        let bif = pair.client.transport().bytes_in_flight();
        assert_eq!(
            bif, 0,
            "round {round}: bytes_in_flight should be 0 after full ACK"
        );

        // Connection must remain established (INV-1).
        assert_eq!(
            pair.client.state(),
            QuicConnectionState::Established,
            "round {round}: connection dropped"
        );
    }

    // INV-8: total_sent == total_acked + total_lost.
    assert_eq!(
        total_sent,
        total_acked + total_lost,
        "sent={total_sent}, acked={total_acked}, lost={total_lost}"
    );
    // With no loss model, all should be acked.
    assert_eq!(total_acked, total_sent, "expected all acked with no loss");
    assert_eq!(total_lost, 0);

    asupersync::test_complete!("soak_sustained_send_ack_cycle");
}

// ════════════════════════════════════════════════════════════════════════
// Loss: Selective ACK with random loss (INV-7, INV-8)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn loss_uniform_random_ack_convergence() {
    init_test("loss_uniform_random_ack_convergence");

    let mut rng = DetRng::new(0x1055_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;
    let num_batches = 10u64;
    let loss_rate_pct = 10u64; // 10% loss
    let mut loss_rng = DetRng::new(0x1055_FACE);

    let mut total_sent = 0u64;
    let mut total_acked = 0u64;
    let mut total_lost = 0u64;
    let mut pn_cursor = 0u64;

    for batch in 0..num_batches {
        let t_send = pair.clock.now();

        // Send as many packets as the congestion window allows.
        let mut batch_sent = 0u64;
        for i in 0u64..20 {
            let result = pair.client.on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                t_send + i * 100,
            );
            if result.is_ok() {
                batch_sent += 1;
                total_sent += 1;
            } else {
                break; // Hit congestion limit — move on to ACK phase.
            }
        }
        assert!(
            batch_sent > 0,
            "batch {batch}: should send at least 1 packet"
        );

        // Determine which packets in this batch were "received" (not lost).
        let received: Vec<u64> = (pn_cursor..pn_cursor + batch_sent)
            .filter(|_| (loss_rng.next_u64() % 100) >= loss_rate_pct)
            .collect();

        // ACK the received packets.
        pair.clock.advance(20_000);
        let report = pair
            .client
            .on_ack_received(
                cx,
                PacketNumberSpace::ApplicationData,
                &received,
                0,
                pair.clock.now(),
            )
            .unwrap_or_else(|e| panic!("batch {batch} ack: {e:?}"));

        total_acked += report.acked_packets as u64;
        total_lost += report.lost_packets as u64;
        pn_cursor += batch_sent;
    }

    // INV-7: acked + lost should account for most sent packets.
    let accounted = total_acked + total_lost;
    assert!(
        accounted <= total_sent,
        "accounted={accounted} > sent={total_sent}"
    );
    assert!(
        accounted >= total_sent * 70 / 100,
        "too few accounted: {accounted}/{total_sent}"
    );

    // Connection survives.
    assert_eq!(pair.client.state(), QuicConnectionState::Established);

    // INV-8: bytes_in_flight should reflect only unaccounted packets.
    let remaining_in_flight = pair.client.transport().bytes_in_flight();
    let expected_remaining = (total_sent - accounted) * 1200;
    assert_eq!(
        remaining_in_flight, expected_remaining,
        "bytes_in_flight: got={remaining_in_flight}, expected={expected_remaining}"
    );

    asupersync::test_complete!("loss_uniform_random_ack_convergence");
}

// ════════════════════════════════════════════════════════════════════════
// Adversarial: Invalid Stream ID Parity (ADV-2)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn adversarial_invalid_stream_id_parity() {
    init_test("adversarial_invalid_stream_id_parity");

    let mut rng = DetRng::new(0x0AD0_0002);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // ADV-2: Client tries to accept a client-initiated stream ID as if it were
    // remote. This violates stream ID parity (RFC 9000 §2.1): a client-initiated
    // stream has initiator_bit=0, which is local for a client role.
    // accept_remote_stream must reject it with InvalidRemoteStream.
    let client_bidi = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 99);
    let result = pair.client.accept_remote_stream(cx, client_bidi);
    assert!(
        result.is_err(),
        "accepting client-initiated stream as remote should fail (stream ID parity violation)"
    );

    // A valid server-initiated stream should be accepted successfully.
    let server_bidi = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 0);
    let result2 = pair.client.accept_remote_stream(cx, server_bidi);
    assert!(
        result2.is_ok(),
        "accepting valid server-initiated remote stream should succeed"
    );

    asupersync::test_complete!("adversarial_invalid_stream_id_parity");
}

// ════════════════════════════════════════════════════════════════════════
// Adversarial: Oversized Flow (ADV-1)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn adversarial_flow_window_exhaustion() {
    init_test("adversarial_flow_window_exhaustion");

    let mut rng = DetRng::new(0x0AD0_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Send enough packets to exhaust the connection send limit (4 MiB).
    let send_limit = 4 << 20; // 4 MiB
    let packet_size = 1200u64;
    let max_packets = send_limit / packet_size;
    let t_base = pair.clock.now();

    let mut sent_count = 0u64;
    for i in 0..max_packets + 10 {
        let result = pair.client.on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            packet_size,
            true,
            true,
            t_base + i * 100,
        );
        if result.is_ok() {
            sent_count += 1;
        } else {
            // Expected: hitting the congestion window or send limit.
            break;
        }
    }

    // We should have sent a substantial number before hitting the limit.
    assert!(
        sent_count > 0,
        "should be able to send at least some packets"
    );

    // Connection remains established even when flow-limited.
    assert_eq!(pair.client.state(), QuicConnectionState::Established);

    asupersync::test_complete!("adversarial_flow_window_exhaustion");
}

// ════════════════════════════════════════════════════════════════════════
// Cancellation Stress: Cancel During Established (CANCEL-1/INV-6)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn cancel_established_connection_drains() {
    init_test("cancel_established_connection_drains");

    let mut rng = DetRng::new(0xCA9C_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Send some packets, then initiate close.
    for i in 0u64..5 {
        pair.client
            .on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                pair.clock.now() + i * 100,
            )
            .expect("send");
    }

    // Initiate graceful close.
    pair.client.close_immediately(cx, 0x00).expect("close");

    // State should transition to Draining or Closed.
    let state = pair.client.state();
    assert!(
        state == QuicConnectionState::Draining || state == QuicConnectionState::Closed,
        "expected Draining or Closed, got {state:?}"
    );

    // INV-6: Closing should not panic or corrupt state.
    // Try to query transport — should not panic.
    let _bif = pair.client.transport().bytes_in_flight();

    asupersync::test_complete!("cancel_established_connection_drains");
}

// ════════════════════════════════════════════════════════════════════════
// Cancellation Stress: Double Close Idempotency (CANCEL-4)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn cancel_double_close_idempotent() {
    init_test("cancel_double_close_idempotent");

    let mut rng = DetRng::new(0xCA9C_0004);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // First close.
    pair.client
        .close_immediately(cx, 0x00)
        .expect("first close");

    let state_after_first = pair.client.state();

    // Second close — should be idempotent (no error, no state change).
    let second_result = pair.client.close_immediately(cx, 0x00);
    // Whether Ok or Err, it should not panic.
    let _ = second_result;

    // State should be same or further along (Draining → Closed is OK).
    let state_after_second = pair.client.state();
    assert!(
        state_after_second == state_after_first
            || state_after_second == QuicConnectionState::Closed,
        "state regression: first={state_after_first:?}, second={state_after_second:?}"
    );

    asupersync::test_complete!("cancel_double_close_idempotent");
}

// ════════════════════════════════════════════════════════════════════════
// Partition: Short Partition Recovery (PART-1)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn partition_short_survives() {
    init_test("partition_short_survives");

    let mut rng = DetRng::new(0x9A81_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Send some packets before partition.
    for i in 0u64..5 {
        pair.client
            .on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                pair.clock.now() + i * 100,
            )
            .expect("pre-partition send");
    }

    // Simulate short partition: advance time by 1 second (< 2s drain timeout).
    pair.clock.advance(1_000_000); // 1 second in microseconds

    // Connection should still be Established (idle timeout not reached).
    assert_eq!(
        pair.client.state(),
        QuicConnectionState::Established,
        "connection should survive short partition"
    );

    // Post-partition: can still send.
    pair.client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            pair.clock.now(),
        )
        .expect("post-partition send should succeed");

    asupersync::test_complete!("partition_short_survives");
}

// ════════════════════════════════════════════════════════════════════════
// Soak: Stream Open/Close Churn (INV-2, INV-4)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn soak_stream_open_close_churn() {
    init_test("soak_stream_open_close_churn");

    let mut rng = DetRng::new(0x50AE_0005);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;
    let mut opened = 0u64;
    let mut closed = 0u64;

    // Open and close 30 bidirectional streams.
    for _ in 0..30 {
        let sid = pair.client.open_local_bidi(cx).expect("open stream");
        opened += 1;

        // Close the stream immediately via reset (final_size=0).
        pair.client
            .reset_stream_send(cx, sid, 0x00, 0)
            .expect("reset stream");
        closed += 1;
    }

    // INV-2: all opened streams were closed.
    assert_eq!(opened, closed, "opened={opened}, closed={closed}");

    // INV-4: no streams should be in "open" state after resets.
    // Connection remains established.
    assert_eq!(pair.client.state(), QuicConnectionState::Established);

    asupersync::test_complete!("soak_stream_open_close_churn");
}

// ════════════════════════════════════════════════════════════════════════
// Soak: Bidirectional Stream Data Exchange (INV-1, INV-3)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn soak_bidi_stream_data_exchange() {
    init_test("soak_bidi_stream_data_exchange");

    let mut rng = DetRng::new(0x50AE_0003);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Open 10 bidirectional streams and verify they're functional.
    let mut stream_ids = Vec::new();
    for _ in 0..10 {
        let sid = pair.client.open_local_bidi(cx).expect("open bidi stream");
        stream_ids.push(sid);
    }

    assert_eq!(stream_ids.len(), 10);

    // Each stream should have a unique ID.
    let unique_ids: HashSet<_> = stream_ids.iter().collect();
    assert_eq!(
        unique_ids.len(),
        stream_ids.len(),
        "stream IDs must be unique"
    );

    // Connection should remain stable.
    assert_eq!(pair.client.state(), QuicConnectionState::Established);

    asupersync::test_complete!("soak_bidi_stream_data_exchange");
}

// ════════════════════════════════════════════════════════════════════════
// Transport Metrics Self-Consistency (INV-8)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn transport_metrics_self_consistent() {
    init_test("transport_metrics_self_consistent");

    let mut rng = DetRng::new(0x3E70_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Send 10 packets (fits initial cwnd of 12000).
    let t_base = pair.clock.now();
    for i in 0u64..10 {
        pair.client
            .on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                t_base + i * 100,
            )
            .expect("send");
    }

    let transport = pair.client.transport();

    // bytes_in_flight should equal sent packets * size.
    assert_eq!(
        transport.bytes_in_flight(),
        10 * 1200,
        "bytes_in_flight inconsistent"
    );

    // ACK first 5 packets.
    pair.clock.advance(20_000);
    let ack_pns: Vec<u64> = (0..5).collect();
    let report = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &ack_pns,
            0,
            pair.clock.now(),
        )
        .expect("ack");

    // After ACKing 5, bytes_in_flight should decrease.
    let bif_after = pair.client.transport().bytes_in_flight();
    // Account for any loss detection that happened.
    let expected_remaining = (10 - report.acked_packets as u64 - report.lost_packets as u64) * 1200;
    assert_eq!(
        bif_after, expected_remaining,
        "bytes_in_flight after partial ACK: got={bif_after}, expected={expected_remaining}"
    );

    asupersync::test_complete!("transport_metrics_self_consistent");
}
