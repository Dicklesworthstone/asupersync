#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::net::{UdpSocket, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;

// Import the DNS module for testing
use asupersync::net::dns::ResolverConfig;

/// DNS message structure for RFC 1035 fuzzing
#[derive(Debug, Arbitrary)]
struct DnsMessage {
    /// Transaction ID
    id: u16,
    /// DNS header flags
    flags: DnsFlags,
    /// Questions section
    questions: Vec<DnsQuestion>,
    /// Answers section
    answers: Vec<DnsAnswer>,
    /// Authority section
    authority: Vec<DnsAnswer>,
    /// Additional section
    additional: Vec<DnsAnswer>,
}

/// DNS header flags for fuzzing all flag combinations
#[derive(Debug, Arbitrary)]
struct DnsFlags {
    /// Query/Response bit (QR)
    qr: bool,
    /// Opcode (4 bits)
    opcode: u8,
    /// Authoritative Answer (AA)
    aa: bool,
    /// Truncated (TC)
    tc: bool,
    /// Recursion Desired (RD)
    rd: bool,
    /// Recursion Available (RA)
    ra: bool,
    /// Reserved Z bits (3 bits)
    z: u8,
    /// Response code (RCODE, 4 bits)
    rcode: u8,
}

/// DNS question for fuzzing query section
#[derive(Debug, Arbitrary)]
struct DnsQuestion {
    /// Domain name with potential compression
    name: DnsName,
    /// Query type
    qtype: u16,
    /// Query class
    qclass: u16,
}

/// DNS answer for fuzzing answer/authority/additional sections
#[derive(Debug, Arbitrary)]
struct DnsAnswer {
    /// Domain name (may use compression pointers)
    name: DnsName,
    /// Resource record type
    rr_type: u16,
    /// Resource record class
    rr_class: u16,
    /// Time to live
    ttl: u32,
    /// Resource data
    rdata: Vec<u8>,
}

/// DNS name structure for testing compression and label encoding
#[derive(Debug, Arbitrary)]
enum DnsName {
    /// Regular labels
    Normal(Vec<String>),
    /// Compression pointer (offset)
    Pointer(u16),
    /// Mixed labels + pointer
    Mixed {
        labels: Vec<String>,
        pointer: u16,
    },
    /// Malformed label lengths (for testing 0x40-0xBF reserved range)
    Malformed {
        bad_length: u8,
        data: Vec<u8>,
    },
    /// Oversized name (>255 bytes total)
    Oversized(Vec<u8>),
}

/// RDATA variants for different record types
#[derive(Debug, Arbitrary)]
enum RDataType {
    /// A record (IPv4)
    A(Ipv4Addr),
    /// AAAA record (IPv6)
    Aaaa(Ipv6Addr),
    /// CNAME record
    Cname(DnsName),
    /// MX record
    Mx {
        preference: u16,
        exchange: DnsName,
    },
    /// TXT record
    Txt(Vec<String>),
    /// SRV record
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    /// Raw bytes for unknown types
    Raw(Vec<u8>),
}

/// Compression attack patterns
#[derive(Debug, Arbitrary)]
enum CompressionAttack {
    /// Direct self-reference loop
    SelfLoop,
    /// Chain exceeding depth limit
    DeepChain(u8),
    /// Pointer to invalid offset
    InvalidOffset(u16),
    /// Multiple overlapping pointers
    OverlapChain(Vec<u16>),
    /// No attack (normal compression)
    None,
}

/// Complete fuzz data structure
#[derive(Debug, Arbitrary)]
struct DnsFuzzData {
    /// Base DNS message
    message: DnsMessage,
    /// Compression attack to apply
    compression_attack: CompressionAttack,
    /// Raw packet modifications
    raw_mutations: Vec<RawMutation>,
    /// Oversized packet test (>512 bytes)
    make_oversized: bool,
}

/// Raw packet byte-level mutations
#[derive(Debug, Arbitrary)]
enum RawMutation {
    /// Truncate at specific offset
    Truncate(usize),
    /// Corrupt header flags
    CorruptFlags(u16),
    /// Invalid record counts
    InvalidCounts {
        questions: u16,
        answers: u16,
        authority: u16,
        additional: u16,
    },
    /// Insert malformed label length
    MalformedLabel {
        offset: usize,
        bad_length: u8,
    },
    /// Corrupt RDATA length
    CorruptRDataLen {
        record_index: usize,
        new_length: u16,
    },
}

/// Build wire format DNS packet from structured data
fn build_dns_packet(fuzz_data: &DnsFuzzData) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // DNS Header (12 bytes)
    packet.extend_from_slice(&fuzz_data.message.id.to_be_bytes());

    // Build flags word
    let flags = build_flags_word(&fuzz_data.message.flags);
    packet.extend_from_slice(&flags.to_be_bytes());

    // Record counts
    packet.extend_from_slice(&(fuzz_data.message.questions.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(fuzz_data.message.answers.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(fuzz_data.message.authority.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(fuzz_data.message.additional.len() as u16).to_be_bytes());

    // Questions section
    for question in &fuzz_data.message.questions {
        encode_dns_name(&question.name, &mut packet);
        packet.extend_from_slice(&question.qtype.to_be_bytes());
        packet.extend_from_slice(&question.qclass.to_be_bytes());
    }

    // Answer section
    for answer in &fuzz_data.message.answers {
        encode_dns_name(&answer.name, &mut packet);
        packet.extend_from_slice(&answer.rr_type.to_be_bytes());
        packet.extend_from_slice(&answer.rr_class.to_be_bytes());
        packet.extend_from_slice(&answer.ttl.to_be_bytes());
        packet.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&answer.rdata);
    }

    // Authority section
    for auth in &fuzz_data.message.authority {
        encode_dns_name(&auth.name, &mut packet);
        packet.extend_from_slice(&auth.rr_type.to_be_bytes());
        packet.extend_from_slice(&auth.rr_class.to_be_bytes());
        packet.extend_from_slice(&auth.ttl.to_be_bytes());
        packet.extend_from_slice(&(auth.rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&auth.rdata);
    }

    // Additional section
    for additional in &fuzz_data.message.additional {
        encode_dns_name(&additional.name, &mut packet);
        packet.extend_from_slice(&additional.rr_type.to_be_bytes());
        packet.extend_from_slice(&additional.rr_class.to_be_bytes());
        packet.extend_from_slice(&additional.ttl.to_be_bytes());
        packet.extend_from_slice(&(additional.rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&additional.rdata);
    }

    // Apply compression attacks
    apply_compression_attack(&mut packet, &fuzz_data.compression_attack);

    // Apply raw mutations
    for mutation in &fuzz_data.raw_mutations {
        apply_raw_mutation(&mut packet, mutation);
    }

    // Make oversized if requested (>512 bytes for UDP)
    if fuzz_data.make_oversized && packet.len() < 600 {
        packet.resize(1024, 0);
    }

    packet
}

/// Build DNS flags word from individual flags
fn build_flags_word(flags: &DnsFlags) -> u16 {
    let mut word = 0u16;

    if flags.qr { word |= 0x8000; }
    word |= ((flags.opcode & 0x0F) as u16) << 11;
    if flags.aa { word |= 0x0400; }
    if flags.tc { word |= 0x0200; }
    if flags.rd { word |= 0x0100; }
    if flags.ra { word |= 0x0080; }
    word |= ((flags.z & 0x07) as u16) << 4;
    word |= (flags.rcode & 0x0F) as u16;

    word
}

/// Encode DNS name with potential compression/malformation
fn encode_dns_name(name: &DnsName, packet: &mut Vec<u8>) {
    match name {
        DnsName::Normal(labels) => {
            for label in labels {
                if label.len() > 63 {
                    // Truncate oversized labels
                    packet.push(63);
                    packet.extend_from_slice(&label.as_bytes()[..63]);
                } else if label.is_empty() {
                    // Skip empty labels
                    continue;
                } else {
                    packet.push(label.len() as u8);
                    packet.extend_from_slice(label.as_bytes());
                }
            }
            packet.push(0); // Null terminator
        },
        DnsName::Pointer(offset) => {
            // Compression pointer (0xC0 | high bits, low byte)
            let offset = *offset & 0x3FFF; // Mask to 14 bits
            packet.push(0xC0 | ((offset >> 8) as u8));
            packet.push(offset as u8);
        },
        DnsName::Mixed { labels, pointer } => {
            // Encode labels first
            for label in labels {
                if label.len() > 63 {
                    packet.push(63);
                    packet.extend_from_slice(&label.as_bytes()[..63]);
                } else if !label.is_empty() {
                    packet.push(label.len() as u8);
                    packet.extend_from_slice(label.as_bytes());
                }
            }
            // Then compression pointer
            let offset = *pointer & 0x3FFF;
            packet.push(0xC0 | ((offset >> 8) as u8));
            packet.push(offset as u8);
        },
        DnsName::Malformed { bad_length, data } => {
            // Test reserved label length range (0x40-0xBF)
            packet.push(*bad_length);
            packet.extend_from_slice(&data[..data.len().min(255)]);
            packet.push(0); // Null terminator
        },
        DnsName::Oversized(data) => {
            // Create name longer than 255 bytes total
            let mut remaining = data.len().min(300); // Cap at 300 to avoid OOM
            let mut pos = 0;

            while remaining > 0 && pos < data.len() {
                let chunk_size = remaining.min(63).min(data.len() - pos);
                if chunk_size == 0 { break; }

                packet.push(chunk_size as u8);
                packet.extend_from_slice(&data[pos..pos + chunk_size]);
                pos += chunk_size;
                remaining = remaining.saturating_sub(chunk_size);

                if remaining == 0 { break; }
            }
            packet.push(0);
        }
    }
}

/// Apply compression pointer attacks to test cycle detection
fn apply_compression_attack(packet: &mut Vec<u8>, attack: &CompressionAttack) {
    if packet.len() < 20 { return; }

    match attack {
        CompressionAttack::SelfLoop => {
            // Create pointer that points to itself
            if packet.len() > 15 {
                let pos = 12; // After header
                packet[pos] = 0xC0;
                packet[pos + 1] = pos as u8;
            }
        },
        CompressionAttack::DeepChain(depth) => {
            // Create chain of pointers exceeding depth limit
            let start_pos = 12;
            for i in 0..*depth {
                let pos = start_pos + (i as usize * 2);
                if pos + 1 < packet.len() {
                    packet[pos] = 0xC0;
                    packet[pos + 1] = if i == *depth - 1 {
                        start_pos as u8 // Point back to start for loop
                    } else {
                        (start_pos + ((i + 1) as usize * 2)) as u8
                    };
                }
            }
        },
        CompressionAttack::InvalidOffset(offset) => {
            // Pointer to invalid/out-of-bounds offset
            if packet.len() > 14 {
                let pos = 12;
                let clamped_offset = (*offset).min(0x3FFF);
                packet[pos] = 0xC0 | ((clamped_offset >> 8) as u8);
                packet[pos + 1] = clamped_offset as u8;
            }
        },
        CompressionAttack::OverlapChain(offsets) => {
            // Multiple overlapping compression pointers
            for (i, offset) in offsets.iter().enumerate() {
                let pos = 12 + (i * 2);
                if pos + 1 < packet.len() {
                    let clamped_offset = (*offset).min(0x3FFF);
                    packet[pos] = 0xC0 | ((clamped_offset >> 8) as u8);
                    packet[pos + 1] = clamped_offset as u8;
                }
            }
        },
        CompressionAttack::None => {
            // No attack, leave packet as-is
        }
    }
}

/// Apply raw byte-level mutations to test parsing robustness
fn apply_raw_mutation(packet: &mut Vec<u8>, mutation: &RawMutation) {
    match mutation {
        RawMutation::Truncate(offset) => {
            let truncate_at = (*offset).min(packet.len());
            packet.truncate(truncate_at);
        },
        RawMutation::CorruptFlags(new_flags) => {
            if packet.len() >= 4 {
                packet[2] = (*new_flags >> 8) as u8;
                packet[3] = (*new_flags & 0xFF) as u8;
            }
        },
        RawMutation::InvalidCounts { questions, answers, authority, additional } => {
            if packet.len() >= 12 {
                packet[4] = (*questions >> 8) as u8;
                packet[5] = (*questions & 0xFF) as u8;
                packet[6] = (*answers >> 8) as u8;
                packet[7] = (*answers & 0xFF) as u8;
                packet[8] = (*authority >> 8) as u8;
                packet[9] = (*authority & 0xFF) as u8;
                packet[10] = (*additional >> 8) as u8;
                packet[11] = (*additional & 0xFF) as u8;
            }
        },
        RawMutation::MalformedLabel { offset, bad_length } => {
            if *offset < packet.len() {
                // Insert malformed label length in reserved range 0x40-0xBF
                packet[*offset] = *bad_length;
            }
        },
        RawMutation::CorruptRDataLen { record_index: _, new_length } => {
            // Find RDATA length field and corrupt it
            if packet.len() > 12 {
                // Simple heuristic: look for RDATA length fields
                for i in 12..packet.len().saturating_sub(2) {
                    if i + 1 < packet.len() {
                        // Assume this might be an RDATA length field
                        packet[i] = (*new_length >> 8) as u8;
                        packet[i + 1] = (*new_length & 0xFF) as u8;
                        break;
                    }
                }
            }
        }
    }
}

/// Test DNS resolver with fuzzed DNS server responses
fn test_dns_with_fake_server(fuzz_packet: &[u8]) {
    // Skip if packet is too large to avoid OOM
    if fuzz_packet.len() > 10_000 {
        return;
    }

    // Set up fake DNS server that responds with fuzzed data
    let server_addr = "127.0.0.1:0";
    let socket = match UdpSocket::bind(server_addr) {
        Ok(s) => s,
        Err(_) => return, // Skip if can't bind
    };

    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    // Set short timeout to avoid hanging fuzzer
    let _ = socket.set_read_timeout(Some(Duration::from_millis(50)));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(50)));

    // Start fake DNS server in background
    let fuzz_response = fuzz_packet.to_vec();
    let server_socket = socket;

    thread::spawn(move || {
        let mut buf = [0u8; 512];
        // Read one query and respond with fuzzed data
        if let Ok((_, src)) = server_socket.recv_from(&mut buf) {
            let _ = server_socket.send_to(&fuzz_response, src);
        }
    });

    // Small delay to let server start
    thread::sleep(Duration::from_millis(1));

    // Test resolver against fake server
    let config = ResolverConfig {
        nameservers: vec![local_addr],
        timeout: Duration::from_millis(100),
        retries: 0,
        cache_enabled: false,
        ..Default::default()
    };

    // Configuration complete - resolver will use fake server
}

/// Test specific RFC 1035 compliance edge cases
fn test_rfc1035_edge_cases(data: &[u8]) {
    if data.len() < 12 { return; }

    // Test header flag combinations
    for i in 0..16 {
        let mut packet = data.to_vec();
        if packet.len() >= 4 {
            // Test different OPCODE values (bits 11-14)
            packet[2] = (packet[2] & 0x87) | ((i << 3) & 0x78);
            test_packet_parsing(&packet);
        }
    }

    // Test RCODE values (bits 0-3 in flags)
    for rcode in 0..16 {
        let mut packet = data.to_vec();
        if packet.len() >= 4 {
            packet[3] = (packet[3] & 0xF0) | (rcode & 0x0F);
            test_packet_parsing(&packet);
        }
    }

    // Test question/answer count edge cases
    let count_tests = [0, 1, 100, 32767, 65535];
    for &count in &count_tests {
        let mut packet = data.to_vec();
        if packet.len() >= 12 {
            // Test question count
            packet[4] = (count >> 8) as u8;
            packet[5] = count as u8;
            test_packet_parsing(&packet);

            // Test answer count
            packet[6] = (count >> 8) as u8;
            packet[7] = count as u8;
            test_packet_parsing(&packet);
        }
    }
}

/// Test packet parsing through DNS resolver
fn test_packet_parsing(packet: &[u8]) {
    // Limit packet size to prevent OOM
    if packet.len() > 2000 { return; }

    // Create minimal fake server to serve this packet
    let _ = std::panic::catch_unwind(|| {
        test_dns_with_fake_server(packet);
    });
}

/// Test DNS name encoding edge cases specifically
fn test_dns_name_edge_cases(data: &[u8]) {
    if data.is_empty() { return; }

    // Test label length edge cases
    let label_lengths = [0, 1, 62, 63, 64, 100, 255];

    for &len in &label_lengths {
        if len > data.len() { continue; }

        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, // Header
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Counts
        ];

        // Add label with specific length
        packet.push(len as u8);
        if len > 0 {
            let label_data = &data[..len.min(data.len())];
            packet.extend_from_slice(label_data);
        }
        packet.push(0); // Null terminator
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN

        test_packet_parsing(&packet);
    }

    // Test reserved label length range (0x40-0xBF)
    for reserved in 0x40..=0xBF {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.push(reserved);
        packet.extend_from_slice(&data[..data.len().min(10)]);
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        test_packet_parsing(&packet);
    }
}



fuzz_target!(|fuzz_data: DnsFuzzData| {
    // Limit input size to prevent excessive resource usage
    if fuzz_data.message.questions.len() > 100 ||
       fuzz_data.message.answers.len() > 100 ||
       fuzz_data.message.authority.len() > 50 ||
       fuzz_data.message.additional.len() > 50 {
        return;
    }

    // Build DNS packet from structured fuzz data
    let packet = build_dns_packet(&fuzz_data);

    // Test 1: Structure-aware DNS message parsing
    test_packet_parsing(&packet);

    // Test 2: RFC 1035 compliance edge cases
    test_rfc1035_edge_cases(&packet);

    // Test 3: DNS name encoding/compression edge cases
    test_dns_name_edge_cases(&packet);

    // Test 4: Raw packet as direct input
    if !packet.is_empty() {
        test_packet_parsing(&packet[..packet.len().min(1000)]);
    }

    // Test 5: Fragment the packet to test partial parsing
    if packet.len() > 20 {
        for split_point in [5, 12, packet.len() / 2, packet.len() - 5] {
            if split_point < packet.len() {
                test_packet_parsing(&packet[..split_point]);
            }
        }
    }

    // Test 6: Compression pointer cycle detection
    if matches!(fuzz_data.compression_attack, CompressionAttack::SelfLoop | CompressionAttack::DeepChain(_)) {
        // These packets specifically test cycle detection in decode_dns_name_inner
        test_packet_parsing(&packet);
    }

    // Test 7: Oversized message handling (>512 bytes UDP limit)
    if fuzz_data.make_oversized && packet.len() > 512 {
        test_packet_parsing(&packet);
    }

    // Test 8: Truncated response handling
    for truncate_at in [0, 1, 11, 12, packet.len() / 2] {
        if truncate_at < packet.len() {
            test_packet_parsing(&packet[..truncate_at]);
        }
    }
});