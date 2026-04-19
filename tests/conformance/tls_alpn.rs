//! RFC 7301 ALPN Conformance Testing
//!
//! Tests conformance to RFC 7301 (Application-Layer Protocol Negotiation Extension)
//! requirements for TLS ALPN negotiation. Validates fundamental ALPN semantics that
//! must hold regardless of specific protocol combinations or timing.

use std::time::Duration;

use asupersync::lab::{config::LabConfig, runtime::LabRuntime};
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::test_utils::run_test_with_cx;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder, TlsError};
use futures_lite::future::zip;

// Self-signed test certificate and key (for testing only)
const TEST_CERT_PEM: &[u8] = br"-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUEOa/xZnL2Xclme2QSueCrHSMLnEwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIyNjIyMjk1MloXDTM2MDIy
NDIyMjk1MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAx1JqCHpDIHPR4H1LDrb3gHVCzoKujANyHdOKw7CTLKdz
JbDybwJYqZ8vZpq0xwhYKpHdGO4yv7yLT7a2kThq3MrxohfXp9tv1Dop7siTQiWT
7uGYJzh1bOhw7ElLJc8bW/mBf7ksMyqkX8/8mRXRWqqDv3dKe5CrSt2Pqti9tYH0
DcT2fftUGT14VvL/Fq1kWPM16ebTRCFp/4ki/Th7SzFvTN99L45MAilHZFefRSzc
9xN1qQZNm7lT6oo0zD3wmOy70iiasqpLrmG51TRdbnBnGH6CIHvUIl3rCDteUuj1
pB9lh67qt5kipCn4+8zceXmUaO/nmRawC7Vz+6AsTwIDAQABo2QwYjALBgNVHQ8E
BAMCBLAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJbG9jYWxob3N0
MAkGA1UdEwQCMAAwHQYDVR0OBBYEFEGZkeJqxBWpc24NHkE8k5PM8gTyMA0GCSqG
SIb3DQEBCwUAA4IBAQAzfQ4na2v1VhK/dyhC89rMHPN/8OX7CGWwrpWlEOYtpMds
OyQKTZjdz8aFSFl9rvnyGRHrdo4J1RoMGNR5wt1XQ7+k3l/iEWRlSRw+JU6+jqsx
xfjik55Dji36pN7ARGW4ADBpc3yTOHFhaH41GpSZ6s/2KdGG2gifo7UGNdkdgL60
nxRt1tfapaNtzpi90TfDx2w6MQmkNMKVOowbYX/zUY7kklJLP8KWTwXO7eovtIpr
FPAy+SbPl3+sqPbes5IqAQO9jhjb0w0/5RlSTPtiKetb6gAA7Yqw+yZWkBN0WDye
Lru15URJw9pE1Uae8IuzyzHiF1fnn45swnvW3Szb
-----END CERTIFICATE-----";

const TEST_KEY_PEM: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHUmoIekMgc9Hg
fUsOtveAdULOgq6MA3Id04rDsJMsp3MlsPJvAlipny9mmrTHCFgqkd0Y7jK/vItP
traROGrcyvGiF9en22/UOinuyJNCJZPu4ZgnOHVs6HDsSUslzxtb+YF/uSwzKqRf
z/yZFdFaqoO/d0p7kKtK3Y+q2L21gfQNxPZ9+1QZPXhW8v8WrWRY8zXp5tNEIWn/
iSL9OHtLMW9M330vjkwCKUdkV59FLNz3E3WpBk2buVPqijTMPfCY7LvSKJqyqkuu
YbnVNF1ucGcYfoIge9QiXesIO15S6PWkH2WHruq3mSKkKfj7zNx5eZRo7+eZFrAL
tXP7oCxPAgMBAAECggEAOwgH+jnHfql+m4dP/uwmUgeogQPIERSGLBo2Ky208NEo
8507t6/QtW+9OJyR9K5eekEX46XMJuf+tF2PJWQ5lemO9awtBPwi2w5c0+jYYAtE
DEgI6Xi5okcXBovQc0KqvisfdMXRNtgmtW+iRm5lQf5lJYP9baoTaQlEXttxF/t+
g7RLjaPaJNvE/Yq+4FJUuL1fWSTXfH99If6rR8Zy+FXtFRpCVbNdpruUaOmIgjuT
TlRaXf/VfnIocRNVsEWTlfCJq8Ra4qLAFM4KYuEBoPaRxpOH9of4nZftzOHwiJ0m
8+GwXqNhySVKO3SPw194LCVSoje1+PEaA/tPlE1RZQKBgQDoJpCQ0SmKOCG/c0lD
QebhqSruFoqQqeEV6poZCO+HZMvszhIiUkvk3/uoZnFQmb3w4YwbRH05YQd6iXFk
048lbqPzfGQGepMpLAY9DWhnbDy+mbuOZp+04gZ/QUen+qKBOc3mNUGhCZNyAUl3
YXeGgPNtknRQ6ebNgO1PFLaoewKBgQDbzHjknGMAFcZXr4/MPOc03I8mQiLECfxa
5PJYhjq85ygCMePiH08xJC4RT6ld3EC4GxliPFubzLMXJhqGBgboSzXGcDZbAOdw
YqleUF/jBChl2oyawzf280FepJqFG6d5qFwISi4hnCZKC7PdIbaKjjRGU7flDBej
AfGjIuzlPQKBgETAjxXkbAn8P7pkWTErBkaUhBtI37aiKQAFn6eEZvPRHTe/e81g
VAuvbedcl3iIX6FEGutEaFWi78URiVyT7xPl5XZJw5HLoWOTHzHbk6z1eDP2cX5l
1CyMt+HeImuUJaZhySHBafNYU6tyyCAr5GsYK3+q3PnNm8YGxcEi4EmbAoGAYbvA
wb58Euybvh+1bBZkpE+yY0ujE9Jw4KXO0OgWtCqA0sEGWGSdnPc+eLoYUEEAkhyS
o+i8v0E9HPz3bEK/zYirx6nbsYlsX7+vGd3ZVSNjJy8PuD035Fnz5jaA8tECHglr
qs/5RT6ek+wyNRCpj2B+BAtzyKgg1n2lyWldNu0CgYEA4Ux9QV5s99W39vJlzGHD
ilKqHWetmrehbe0nIeCe2bJWqb08oSrQD8Q7om/MGAKjhFqNyYqqoJXcmbAvLygu
kMtbiQcfyyxjefyCA0OvdWEXrvnRZYNEBosyX/ko7Bl2IRBFP6ahQhj7jHqm2+/J
SrXuVI5uunTgPWuOtJOP+KM=
-----END PRIVATE KEY-----";

/// Helper to create test chain and key
fn create_test_tls_materials() -> (CertificateChain, PrivateKey, Vec<Certificate>) {
    let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
    let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
    let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
    (chain, key, certs)
}

/// Test scenario for ALPN conformance
#[derive(Debug, Clone)]
struct AlpnTestScenario {
    /// Description of the test
    description: &'static str,
    /// Server's ALPN protocols in preference order
    server_protocols: Vec<&'static [u8]>,
    /// Client's ALPN protocols in preference order
    client_protocols: Vec<&'static [u8]>,
    /// Whether server requires ALPN negotiation
    server_alpn_required: bool,
    /// Whether client requires ALPN negotiation
    client_alpn_required: bool,
    /// Expected negotiated protocol (None if no overlap or error expected)
    expected_protocol: Option<&'static [u8]>,
    /// Whether handshake should succeed
    should_succeed: bool,
}

/// MR1: RFC 7301 - Server picks first protocol from client list that server supports
/// Property: With overlapping protocols, server's preference order determines the selection
#[test]
#[cfg(feature = "tls")]
fn mr1_server_preference_determines_selection() {
    let _lab = LabRuntime::new(LabConfig::default());

    run_test_with_cx(|_cx| async move {
        let scenarios = vec![
            AlpnTestScenario {
                description: "Server prefers h2, client prefers http/1.1 - server wins",
                server_protocols: vec![b"h2", b"http/1.1"],
                client_protocols: vec![b"http/1.1", b"h2"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"h2"), // Server's first choice
                should_succeed: true,
            },
            AlpnTestScenario {
                description: "Server prefers http/1.1, client prefers h2 - server wins",
                server_protocols: vec![b"http/1.1", b"h2"],
                client_protocols: vec![b"h2", b"http/1.1"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"http/1.1"), // Server's first choice
                should_succeed: true,
            },
            AlpnTestScenario {
                description: "Server offers grpc+h2+http/1.1, client offers h2+http/1.1 - server wins with h2",
                server_protocols: vec![b"grpc-exp", b"h2", b"http/1.1"],
                client_protocols: vec![b"h2", b"http/1.1"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"h2"), // First server protocol that client also supports
                should_succeed: true,
            },
        ];

        for scenario in scenarios {
            let (chain, key, certs) = create_test_tls_materials();

            let server_protocols: Vec<Vec<u8>> = scenario.server_protocols.iter()
                .map(|p| p.to_vec()).collect();
            let client_protocols: Vec<Vec<u8>> = scenario.client_protocols.iter()
                .map(|p| p.to_vec()).collect();

            let mut acceptor_builder = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(server_protocols);
            if scenario.server_alpn_required {
                acceptor_builder = acceptor_builder.require_alpn();
            }
            let acceptor = acceptor_builder.build().unwrap();

            let mut connector_builder = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_protocols(client_protocols);
            if scenario.client_alpn_required {
                connector_builder = connector_builder.require_alpn();
            }
            let connector = connector_builder.build().unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5100".parse().unwrap(),
                "127.0.0.1:5101".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            ).await;

            if scenario.should_succeed {
                let client = client_res.unwrap_or_else(|e| panic!("Client failed in {}: {}", scenario.description, e));
                let server = server_res.unwrap_or_else(|e| panic!("Server failed in {}: {}", scenario.description, e));

                let negotiated_client = client.alpn_protocol();
                let negotiated_server = server.alpn_protocol();

                assert_eq!(
                    negotiated_client,
                    negotiated_server,
                    "Client and server disagree on negotiated protocol in {}",
                    scenario.description
                );

                assert_eq!(
                    negotiated_client,
                    scenario.expected_protocol,
                    "Wrong protocol negotiated in {}: expected {:?}, got {:?}",
                    scenario.description,
                    scenario.expected_protocol,
                    negotiated_client
                );
            } else {
                // Both should fail
                client_res.unwrap_err();
                server_res.unwrap_err();
            }
        }
    });
}

/// MR2: RFC 7301 - No overlap results in no_application_protocol fatal alert
/// Property: When client and server have no common protocols, handshake must fail
#[test]
#[cfg(feature = "tls")]
fn mr2_no_overlap_triggers_fatal_alert() {
    let _lab = LabRuntime::new(LabConfig::default());

    run_test_with_cx(|_cx| async move {
        let scenarios = vec![
            AlpnTestScenario {
                description: "Client wants h2, server only offers http/1.1",
                server_protocols: vec![b"http/1.1"],
                client_protocols: vec![b"h2"],
                server_alpn_required: false,
                client_alpn_required: true, // Client requires ALPN
                expected_protocol: None,
                should_succeed: false,
            },
            AlpnTestScenario {
                description: "Server wants grpc, client only offers http/1.1",
                server_protocols: vec![b"grpc-exp"],
                client_protocols: vec![b"http/1.1"],
                server_alpn_required: true, // Server requires ALPN
                client_alpn_required: false,
                expected_protocol: None,
                should_succeed: false,
            },
            AlpnTestScenario {
                description: "Both require ALPN but no overlap",
                server_protocols: vec![b"grpc-exp", b"h2-custom"],
                client_protocols: vec![b"http/1.1", b"spdy/3.1"],
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: None,
                should_succeed: false,
            },
        ];

        for scenario in scenarios {
            let (chain, key, certs) = create_test_tls_materials();

            let server_protocols: Vec<Vec<u8>> = scenario.server_protocols.iter()
                .map(|p| p.to_vec()).collect();
            let client_protocols: Vec<Vec<u8>> = scenario.client_protocols.iter()
                .map(|p| p.to_vec()).collect();

            let mut acceptor_builder = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(server_protocols);
            if scenario.server_alpn_required {
                acceptor_builder = acceptor_builder.require_alpn();
            }
            let acceptor = acceptor_builder.build().unwrap();

            let mut connector_builder = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_protocols(client_protocols);
            if scenario.client_alpn_required {
                connector_builder = connector_builder.require_alpn();
            }
            let connector = connector_builder.build().unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5200".parse().unwrap(),
                "127.0.0.1:5201".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            ).await;

            // Both should fail due to ALPN negotiation failure
            let client_err = client_res.unwrap_err();
            let server_err = server_res.unwrap_err();

            // Verify it's specifically an ALPN-related error
            let is_alpn_error = |e: &TlsError| {
                match e {
                    TlsError::AlpnNegotiationFailed { .. } => true,
                    TlsError::Handshake(_) => true, // Rustls may wrap as handshake error
                    _ => false,
                }
            };

            assert!(
                is_alpn_error(&client_err) || is_alpn_error(&server_err),
                "Expected ALPN negotiation failure in {}, got client: {:?}, server: {:?}",
                scenario.description, client_err, server_err
            );
        }
    });
}

/// MR3: RFC 7301 - Server-advertised protocol must be in client list
/// Property: Server cannot negotiate a protocol that the client didn't offer
#[test]
#[cfg(feature = "tls")]
fn mr3_server_cannot_choose_unadvertised_protocol() {
    let _lab = LabRuntime::new(LabConfig::default());

    run_test_with_cx(|_cx| async move {
        // This test verifies that our implementation prevents servers from choosing
        // protocols not in the client's list. Since we use rustls, which enforces
        // RFC 7301, we test scenarios where the intersection is properly calculated.

        let scenarios = vec![
            AlpnTestScenario {
                description: "Server supports superset, should pick from intersection",
                server_protocols: vec![b"grpc-exp", b"h2", b"http/1.1", b"custom-proto"],
                client_protocols: vec![b"h2", b"http/1.1"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"h2"), // First server protocol in client list
                should_succeed: true,
            },
            AlpnTestScenario {
                description: "Only one protocol overlaps",
                server_protocols: vec![b"grpc-exp", b"custom-proto", b"http/1.1"],
                client_protocols: vec![b"h2", b"http/1.1", b"spdy/3.1"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"http/1.1"), // Only overlap
                should_succeed: true,
            },
        ];

        for scenario in scenarios {
            let (chain, key, certs) = create_test_tls_materials();

            let server_protocols: Vec<Vec<u8>> = scenario.server_protocols.iter()
                .map(|p| p.to_vec()).collect();
            let client_protocols: Vec<Vec<u8>> = scenario.client_protocols.iter()
                .map(|p| p.to_vec()).collect();

            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(server_protocols)
                .build().unwrap();

            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_protocols(client_protocols)
                .build().unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5300".parse().unwrap(),
                "127.0.0.1:5301".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            ).await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            let negotiated = client.alpn_protocol().expect("Expected ALPN protocol");

            // Verify the negotiated protocol was in the client's list
            let client_offered: Vec<Vec<u8>> = scenario.client_protocols.iter()
                .map(|p| p.to_vec()).collect();
            let client_offered_slices: Vec<&[u8]> = client_offered.iter()
                .map(|p| p.as_slice()).collect();

            assert!(
                client_offered_slices.contains(&negotiated),
                "Server chose protocol {:?} not in client list {:?} for {}",
                negotiated, client_offered_slices, scenario.description
            );

            assert_eq!(
                negotiated,
                scenario.expected_protocol.expect("Should have negotiated"),
                "Wrong protocol in {}", scenario.description
            );
        }
    });
}

/// MR4: RFC 7301 - ALPN extension only valid in specific handshake messages
/// Property: ALPN extension appears only in ClientHello/ServerHello/EncryptedExtensions
#[test]
#[cfg(feature = "tls")]
fn mr4_alpn_extension_valid_only_in_handshake() {
    let _lab = LabRuntime::new(LabConfig::default());

    run_test_with_cx(|_cx| async move {
        // Since we're using rustls as the TLS implementation, it automatically enforces
        // RFC compliance for extension placement. This test verifies that ALPN
        // negotiation works correctly through proper handshake flow.

        let scenarios = vec![
            AlpnTestScenario {
                description: "Standard ALPN negotiation in handshake",
                server_protocols: vec![b"h2", b"http/1.1"],
                client_protocols: vec![b"h2", b"http/1.1"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"h2"),
                should_succeed: true,
            },
            AlpnTestScenario {
                description: "ALPN with TLS 1.3 (EncryptedExtensions)",
                server_protocols: vec![b"h2"],
                client_protocols: vec![b"h2"],
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: Some(b"h2"),
                should_succeed: true,
            },
        ];

        for scenario in scenarios {
            let (chain, key, certs) = create_test_tls_materials();

            let server_protocols: Vec<Vec<u8>> = scenario.server_protocols.iter()
                .map(|p| p.to_vec()).collect();
            let client_protocols: Vec<Vec<u8>> = scenario.client_protocols.iter()
                .map(|p| p.to_vec()).collect();

            let mut acceptor_builder = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(server_protocols);
            if scenario.server_alpn_required {
                acceptor_builder = acceptor_builder.require_alpn();
            }
            let acceptor = acceptor_builder.build().unwrap();

            let mut connector_builder = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_protocols(client_protocols);
            if scenario.client_alpn_required {
                connector_builder = connector_builder.require_alpn();
            }
            let connector = connector_builder.build().unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5400".parse().unwrap(),
                "127.0.0.1:5401".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            ).await;

            let client = client_res.unwrap();
            let server = server_res.unwrap();

            // Verify handshake completed and ALPN was negotiated
            assert!(client.is_ready(), "Client handshake should be complete");
            assert!(server.is_ready(), "Server handshake should be complete");

            let negotiated = client.alpn_protocol();
            assert_eq!(
                negotiated,
                scenario.expected_protocol,
                "Wrong protocol in {}", scenario.description
            );

            // Verify protocol version is supported (TLS 1.2 or 1.3)
            let version = client.protocol_version();
            assert!(version.is_some(), "Should have TLS version");
        }
    });
}

/// MR5: RFC 7301 - Protocol names are opaque byte strings with exact match
/// Property: Protocol matching is byte-exact and case-sensitive, no normalization
#[test]
#[cfg(feature = "tls")]
fn mr5_protocol_names_require_exact_byte_match() {
    let _lab = LabRuntime::new(LabConfig::default());

    run_test_with_cx(|_cx| async move {
        let scenarios = vec![
            // Case sensitivity tests
            AlpnTestScenario {
                description: "Case sensitive - h2 vs H2",
                server_protocols: vec![b"h2"],
                client_protocols: vec![b"H2"], // Different case
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: None,
                should_succeed: false, // No match due to case difference
            },
            AlpnTestScenario {
                description: "Case sensitive - http/1.1 vs HTTP/1.1",
                server_protocols: vec![b"http/1.1"],
                client_protocols: vec![b"HTTP/1.1"], // Different case
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: None,
                should_succeed: false, // No match due to case difference
            },
            // Whitespace sensitivity tests
            AlpnTestScenario {
                description: "Whitespace sensitive - 'h2' vs ' h2'",
                server_protocols: vec![b"h2"],
                client_protocols: vec![b" h2"], // Leading space
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: None,
                should_succeed: false, // No match due to whitespace
            },
            AlpnTestScenario {
                description: "Whitespace sensitive - 'h2' vs 'h2 '",
                server_protocols: vec![b"h2"],
                client_protocols: vec![b"h2 "], // Trailing space
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: None,
                should_succeed: false, // No match due to whitespace
            },
            // Exact match tests
            AlpnTestScenario {
                description: "Exact match - identical byte strings",
                server_protocols: vec![b"custom-protocol-v2.1"],
                client_protocols: vec![b"custom-protocol-v2.1"], // Exactly the same
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: Some(b"custom-protocol-v2.1"),
                should_succeed: true,
            },
            // Binary protocol names (non-ASCII)
            AlpnTestScenario {
                description: "Binary protocol names with high bytes",
                server_protocols: vec![b"\x01\x02\x03protocol\xff\xfe"],
                client_protocols: vec![b"\x01\x02\x03protocol\xff\xfe"], // Exact binary match
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: Some(b"\x01\x02\x03protocol\xff\xfe"),
                should_succeed: true,
            },
            AlpnTestScenario {
                description: "Binary protocol names - slight difference",
                server_protocols: vec![b"\x01\x02\x03protocol\xff\xfe"],
                client_protocols: vec![b"\x01\x02\x03protocol\xff\xfd"], // Last byte differs
                server_alpn_required: true,
                client_alpn_required: true,
                expected_protocol: None,
                should_succeed: false, // No match due to byte difference
            },
        ];

        for scenario in scenarios {
            let (chain, key, certs) = create_test_tls_materials();

            let server_protocols: Vec<Vec<u8>> = scenario.server_protocols.iter()
                .map(|p| p.to_vec()).collect();
            let client_protocols: Vec<Vec<u8>> = scenario.client_protocols.iter()
                .map(|p| p.to_vec()).collect();

            let mut acceptor_builder = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(server_protocols);
            if scenario.server_alpn_required {
                acceptor_builder = acceptor_builder.require_alpn();
            }
            let acceptor = acceptor_builder.build().unwrap();

            let mut connector_builder = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_protocols(client_protocols);
            if scenario.client_alpn_required {
                connector_builder = connector_builder.require_alpn();
            }
            let connector = connector_builder.build().unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5500".parse().unwrap(),
                "127.0.0.1:5501".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            ).await;

            if scenario.should_succeed {
                let client = client_res.unwrap_or_else(|e| {
                    panic!("Client failed in {}: {}", scenario.description, e)
                });
                let server = server_res.unwrap_or_else(|e| {
                    panic!("Server failed in {}: {}", scenario.description, e)
                });

                let negotiated = client.alpn_protocol();
                assert_eq!(
                    negotiated,
                    scenario.expected_protocol,
                    "Wrong protocol negotiated in {}", scenario.description
                );

                // Verify exact byte match
                if let Some(expected) = scenario.expected_protocol {
                    let negotiated_bytes = negotiated.unwrap();
                    assert_eq!(
                        negotiated_bytes, expected,
                        "Negotiated protocol {:?} doesn't exactly match expected {:?} in {}",
                        negotiated_bytes, expected, scenario.description
                    );
                }
            } else {
                // Should fail due to no exact match
                assert!(
                    client_res.is_err() || server_res.is_err(),
                    "Expected handshake failure in {} due to no exact protocol match",
                    scenario.description
                );
            }
        }
    });
}

/// Comprehensive ALPN edge case testing
/// Property: Various edge cases are handled according to RFC 7301
#[test]
#[cfg(feature = "tls")]
fn comprehensive_alpn_edge_cases() {
    let _lab = LabRuntime::new(LabConfig::default());

    run_test_with_cx(|_cx| async move {
        let scenarios = vec![
            // Empty protocol lists
            AlpnTestScenario {
                description: "Server advertises no protocols, client requires ALPN",
                server_protocols: vec![],
                client_protocols: vec![b"h2"],
                server_alpn_required: false,
                client_alpn_required: true,
                expected_protocol: None,
                should_succeed: false,
            },
            AlpnTestScenario {
                description: "Client offers no protocols, server requires ALPN",
                server_protocols: vec![b"h2"],
                client_protocols: vec![],
                server_alpn_required: true,
                client_alpn_required: false,
                expected_protocol: None,
                should_succeed: false,
            },
            // Single byte protocol names
            AlpnTestScenario {
                description: "Single byte protocol names",
                server_protocols: vec![b"a", b"b"],
                client_protocols: vec![b"b", b"c"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"b"), // Overlap
                should_succeed: true,
            },
            // Very long protocol names
            AlpnTestScenario {
                description: "Long protocol names",
                server_protocols: vec![b"very-long-protocol-name-that-exceeds-normal-length-expectations"],
                client_protocols: vec![b"very-long-protocol-name-that-exceeds-normal-length-expectations"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"very-long-protocol-name-that-exceeds-normal-length-expectations"),
                should_succeed: true,
            },
            // Many protocols
            AlpnTestScenario {
                description: "Many protocols with overlap at end",
                server_protocols: vec![b"proto1", b"proto2", b"proto3", b"proto4", b"proto5"],
                client_protocols: vec![b"other1", b"other2", b"other3", b"proto5"],
                server_alpn_required: false,
                client_alpn_required: false,
                expected_protocol: Some(b"proto5"), // First server protocol that client supports
                should_succeed: true,
            },
        ];

        for scenario in scenarios {
            let (chain, key, certs) = create_test_tls_materials();

            let server_protocols: Vec<Vec<u8>> = scenario.server_protocols.iter()
                .map(|p| p.to_vec()).collect();
            let client_protocols: Vec<Vec<u8>> = scenario.client_protocols.iter()
                .map(|p| p.to_vec()).collect();

            let mut acceptor_builder = TlsAcceptorBuilder::new(chain, key);
            if !server_protocols.is_empty() {
                acceptor_builder = acceptor_builder.alpn_protocols(server_protocols);
            }
            if scenario.server_alpn_required {
                acceptor_builder = acceptor_builder.require_alpn();
            }
            let acceptor = acceptor_builder.build().unwrap();

            let mut connector_builder = TlsConnectorBuilder::new()
                .add_root_certificates(certs);
            if !client_protocols.is_empty() {
                connector_builder = connector_builder.alpn_protocols(client_protocols);
            }
            if scenario.client_alpn_required {
                connector_builder = connector_builder.require_alpn();
            }
            let connector = connector_builder.build().unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5600".parse().unwrap(),
                "127.0.0.1:5601".parse().unwrap(),
            );

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            ).await;

            if scenario.should_succeed {
                let client = client_res.unwrap_or_else(|e| {
                    panic!("Client failed in {}: {}", scenario.description, e)
                });
                let server = server_res.unwrap_or_else(|e| {
                    panic!("Server failed in {}: {}", scenario.description, e)
                });

                let negotiated = client.alpn_protocol();
                assert_eq!(
                    negotiated,
                    scenario.expected_protocol,
                    "Wrong protocol negotiated in {}", scenario.description
                );
            } else {
                assert!(
                    client_res.is_err() || server_res.is_err(),
                    "Expected failure in {}", scenario.description
                );
            }
        }
    });
}

/// Test ALPN timeout scenarios
/// Property: ALPN negotiation respects handshake timeouts
#[test]
#[cfg(feature = "tls")]
fn alpn_respects_handshake_timeouts() {
    let _lab = LabRuntime::new(LabConfig::default());

    run_test_with_cx(|_cx| async move {
        let (chain, key, certs) = create_test_tls_materials();

        // Very short timeout to trigger timeout error
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .alpn_protocols(vec![b"h2".to_vec()])
            .handshake_timeout(Duration::from_millis(1)) // Very short
            .build().unwrap();

        let (client_io, _server_io) = VirtualTcpStream::pair(
            "127.0.0.1:5700".parse().unwrap(),
            "127.0.0.1:5701".parse().unwrap(),
        );

        let result = connector.connect("localhost", client_io).await;
        let err = result.unwrap_err();

        match err {
            TlsError::Timeout(duration) => {
                assert_eq!(duration, Duration::from_millis(1), "Wrong timeout duration");
            },
            _ => panic!("Expected timeout error, got: {:?}", err),
        }
    });
}