//! Fuzz target for QUIC ACK frame processing in transport layer.
//!
//! This fuzzer targets the ACK frame processing in `QuicTransportMachine`, focusing on:
//! - `on_ack_received` - processes individual packet numbers from ACK frames
//! - `on_ack_ranges` - processes ACK ranges from ACK frames
//!
//! ACK frames are a critical attack surface in QUIC as they:
//! - Control congestion window updates
//! - Trigger loss recovery algorithms
//! - Can cause integer overflows in packet accounting
//! - May lead to infinite loops in range processing

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use asupersync::net::quic_native::transport::{
    QuicTransportMachine, AckRange, PacketNumberSpace, SentPacketMeta
};

#[derive(Debug, Arbitrary)]
struct FuzzAckData {
    /// Packet number space for the ACK
    space_variant: u8,
    /// Choice of ACK processing method
    method: AckMethod,
    /// ACK delay in microseconds (can be malicious)
    ack_delay_micros: u64,
    /// Current time in microseconds
    now_micros: u64,
    /// Pre-populate some sent packets for more realistic fuzzing
    sent_packets: Vec<FuzzSentPacket>,
}

#[derive(Debug, Arbitrary)]
enum AckMethod {
    /// Fuzz on_ack_received with packet numbers
    PacketNumbers(Vec<u64>),
    /// Fuzz on_ack_ranges with ACK ranges
    Ranges(Vec<FuzzAckRange>),
}

#[derive(Debug, Arbitrary)]
struct FuzzAckRange {
    largest: u64,
    smallest: u64,
}

#[derive(Debug, Arbitrary)]
struct FuzzSentPacket {
    space_variant: u8,
    packet_number: u64,
    bytes: u64,
    ack_eliciting: bool,
    in_flight: bool,
    time_sent_micros: u64,
}

impl FuzzAckRange {
    fn to_ack_range(self) -> Option<AckRange> {
        AckRange::new(self.largest, self.smallest)
    }
}

impl FuzzSentPacket {
    fn to_sent_packet_meta(self) -> SentPacketMeta {
        let space = match self.space_variant % 3 {
            0 => PacketNumberSpace::Initial,
            1 => PacketNumberSpace::Handshake,
            _ => PacketNumberSpace::ApplicationData,
        };

        SentPacketMeta {
            space,
            packet_number: self.packet_number,
            bytes: self.bytes,
            ack_eliciting: self.ack_eliciting,
            in_flight: self.in_flight,
            time_sent_micros: self.time_sent_micros,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let fuzz_data: FuzzAckData = match u.arbitrary() {
        Ok(data) => data,
        Err(_) => return, // Invalid input, skip
    };

    // Create a QUIC transport instance
    let mut transport = QuicTransportMachine::new();

    // Establish the connection to enable packet processing
    if transport.on_established().is_err() {
        return;
    }

    // Convert space variant to actual packet number space
    let space = match fuzz_data.space_variant % 3 {
        0 => PacketNumberSpace::Initial,
        1 => PacketNumberSpace::Handshake,
        _ => PacketNumberSpace::ApplicationData,
    };

    // Pre-populate some sent packets to make ACK processing more meaningful
    for sent_packet in fuzz_data.sent_packets {
        let packet_meta = sent_packet.to_sent_packet_meta();
        transport.on_packet_sent(packet_meta);
    }

    // Fuzz the ACK processing based on the chosen method
    match fuzz_data.method {
        AckMethod::PacketNumbers(packet_numbers) => {
            // Limit the number of packet numbers to prevent excessive memory usage
            let limited_packet_numbers: Vec<u64> = packet_numbers
                .into_iter()
                .take(10000) // Reasonable limit for fuzzing
                .collect();

            // Fuzz on_ack_received
            let _ack_event = transport.on_ack_received(
                space,
                &limited_packet_numbers,
                fuzz_data.ack_delay_micros,
                fuzz_data.now_micros,
            );
        }
        AckMethod::Ranges(ranges) => {
            // Convert fuzz ranges to actual AckRange objects, filtering out invalid ones
            let ack_ranges: Vec<AckRange> = ranges
                .into_iter()
                .take(1000) // Limit ranges to prevent excessive processing
                .filter_map(|r| r.to_ack_range())
                .collect();

            // Fuzz on_ack_ranges
            let _ack_event = transport.on_ack_ranges(
                space,
                &ack_ranges,
                fuzz_data.ack_delay_micros,
                fuzz_data.now_micros,
            );
        }
    }

    // Test additional transport state queries that might be affected by ACK processing
    let _bytes_in_flight = transport.bytes_in_flight();
    let _congestion_window = transport.congestion_window_bytes();
    let _ssthresh = transport.ssthresh_bytes();
    let _can_send = transport.can_send(1024);
});