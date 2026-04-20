//! RFC 1035 name-compression fuzz target for `src/net/dns/resolver.rs`.
//!
//! This harness drives the real `Resolver` parser path through a fake UDP
//! nameserver. It focuses on compressed owner names and compressed names inside
//! CNAME/MX/SRV RDATA, including malformed forward pointers and rdlen-overrun
//! cases.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::net::dns::{Resolver, ResolverConfig};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    scenario: Scenario,
    label_seed: Vec<u8>,
    addr: [u8; 4],
    ttl: u16,
    preference: u16,
    priority: u16,
    weight: u16,
    port: u16,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum Scenario {
    ValidA,
    ValidMxCompressed,
    ValidSrvCompressed,
    ForwardPointerOwner,
    InvalidLabelEncodingOwner,
    CnameRdlenOverrun,
    SrvRdlenOverrun,
}

#[derive(Debug)]
enum LookupResult {
    Ip(Vec<std::net::IpAddr>),
    Mx(Vec<(u16, String)>),
    Srv(Vec<(u16, u16, u16, String)>),
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    run_case(input);
});

fn run_case(input: FuzzInput) {
    let socket = match UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))) {
        Ok(socket) => socket,
        Err(_) => return,
    };
    if socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .is_err()
    {
        return;
    }
    if socket
        .set_write_timeout(Some(Duration::from_millis(100)))
        .is_err()
    {
        return;
    }

    let server_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    let server_input = input.clone();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 512];
        if let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let response = build_response(&buf[..n], &server_input);
            let _ = socket.send_to(&response, peer);
        }
    });

    let resolver = Resolver::with_config(ResolverConfig {
        nameservers: vec![server_addr],
        cache_enabled: false,
        timeout: Duration::from_millis(150),
        retries: 0,
        ..ResolverConfig::default()
    });

    let result = match input.scenario {
        Scenario::ValidA => block_on(async { resolver.lookup_ip("example.test").await })
            .map(|lookup| LookupResult::Ip(lookup.addresses().to_vec())),
        Scenario::ValidMxCompressed
        | Scenario::ForwardPointerOwner
        | Scenario::InvalidLabelEncodingOwner
        | Scenario::CnameRdlenOverrun => {
            block_on(async { resolver.lookup_mx("example.test").await }).map(|lookup| {
                LookupResult::Mx(
                    lookup
                        .records()
                        .map(|record| (record.preference, record.exchange.clone()))
                        .collect(),
                )
            })
        }
        Scenario::ValidSrvCompressed | Scenario::SrvRdlenOverrun => {
            block_on(async { resolver.lookup_srv("example.test").await }).map(|lookup| {
                LookupResult::Srv(
                    lookup
                        .records()
                        .map(|record| {
                            (
                                record.priority,
                                record.weight,
                                record.port,
                                record.target.clone(),
                            )
                        })
                        .collect(),
                )
            })
        }
    };

    let _ = handle.join();

    match input.scenario {
        Scenario::ValidA => match result {
            Ok(LookupResult::Ip(addrs)) => {
                assert_eq!(
                    addrs,
                    vec![std::net::IpAddr::V4(Ipv4Addr::from(input.addr))]
                );
            }
            other => panic!("valid A response did not parse successfully: {other:?}"),
        },
        Scenario::ValidMxCompressed => {
            let expected = format!("{}.example.test", sanitize_label(&input.label_seed, "mx"));
            match result {
                Ok(LookupResult::Mx(records)) => {
                    assert_eq!(records, vec![(input.preference, expected)]);
                }
                other => panic!("valid MX response did not parse successfully: {other:?}"),
            }
        }
        Scenario::ValidSrvCompressed => {
            let expected = format!("{}.example.test", sanitize_label(&input.label_seed, "svc"));
            match result {
                Ok(LookupResult::Srv(records)) => {
                    assert_eq!(
                        records,
                        vec![(input.priority, input.weight, input.port, expected)]
                    );
                }
                other => panic!("valid SRV response did not parse successfully: {other:?}"),
            }
        }
        Scenario::ForwardPointerOwner
        | Scenario::InvalidLabelEncodingOwner
        | Scenario::CnameRdlenOverrun
        | Scenario::SrvRdlenOverrun => {
            assert!(result.is_err(), "malformed DNS packet should not resolve");
        }
    }
}

fn build_response(request: &[u8], input: &FuzzInput) -> Vec<u8> {
    let question_end = parse_question_end(request).unwrap_or(request.len().min(12));
    let question = request.get(12..question_end).unwrap_or(&[]);

    let mut response = Vec::with_capacity(128);
    response.extend_from_slice(request.get(0..2).unwrap_or(&[0, 0]));
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(question);

    let owner_offset = response.len();
    match input.scenario {
        Scenario::ForwardPointerOwner => {
            response.extend_from_slice(&compression_ptr(owner_offset + 2));
        }
        Scenario::InvalidLabelEncodingOwner => {
            response.push(0x40);
        }
        _ => response.extend_from_slice(&compression_ptr(12)),
    }

    let (rr_type, rdata) = match input.scenario {
        Scenario::ValidA => (1u16, Ipv4Addr::from(input.addr).octets().to_vec()),
        Scenario::ValidMxCompressed
        | Scenario::ForwardPointerOwner
        | Scenario::InvalidLabelEncodingOwner => {
            let mut data = input.preference.to_be_bytes().to_vec();
            data.extend_from_slice(&encode_prefix_with_question_pointer(&sanitize_label(
                &input.label_seed,
                "mx",
            )));
            (15u16, data)
        }
        Scenario::ValidSrvCompressed | Scenario::SrvRdlenOverrun => {
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&input.priority.to_be_bytes());
            data.extend_from_slice(&input.weight.to_be_bytes());
            data.extend_from_slice(&input.port.to_be_bytes());
            data.extend_from_slice(&encode_prefix_with_question_pointer(&sanitize_label(
                &input.label_seed,
                "svc",
            )));
            if matches!(input.scenario, Scenario::SrvRdlenOverrun) && !data.is_empty() {
                data.truncate(data.len().saturating_sub(1));
            }
            (33u16, data)
        }
        Scenario::CnameRdlenOverrun => {
            let data =
                encode_prefix_with_question_pointer(&sanitize_label(&input.label_seed, "alias"));
            let truncated = data[..data.len().saturating_sub(1)].to_vec();
            (5u16, truncated)
        }
    };

    response.extend_from_slice(&rr_type.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&u32::from(input.ttl.max(1)).to_be_bytes());

    let advertised_len = match input.scenario {
        Scenario::CnameRdlenOverrun => u16::try_from(rdata.len() + 1).unwrap_or(u16::MAX),
        Scenario::SrvRdlenOverrun => u16::try_from(rdata.len() + 1).unwrap_or(u16::MAX),
        _ => u16::try_from(rdata.len()).unwrap_or(u16::MAX),
    };
    response.extend_from_slice(&advertised_len.to_be_bytes());
    response.extend_from_slice(&rdata);
    response
}

fn parse_question_end(request: &[u8]) -> Option<usize> {
    let mut offset = 12usize;
    loop {
        let len = *request.get(offset)?;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            offset += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        offset += usize::from(len);
    }
    Some(offset + 4)
}

fn compression_ptr(offset: usize) -> [u8; 2] {
    let offset = u16::try_from(offset.min(0x3FFF)).unwrap_or(0x3FFF);
    (0xC000 | offset).to_be_bytes()
}

fn encode_prefix_with_question_pointer(prefix: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 3);
    out.push(u8::try_from(prefix.len()).unwrap_or(0));
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(&compression_ptr(12));
    out
}

fn sanitize_label(seed: &[u8], fallback: &str) -> String {
    let mut label = String::new();
    for byte in seed.iter().copied().take(16) {
        let ch = match byte {
            b'a'..=b'z' | b'0'..=b'9' => byte as char,
            b'A'..=b'Z' => (byte as char).to_ascii_lowercase(),
            b'-' => '-',
            _ => continue,
        };
        label.push(ch);
    }

    let trimmed = label.trim_matches('-');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed[..trimmed.len().min(16)].to_string()
    }
}
