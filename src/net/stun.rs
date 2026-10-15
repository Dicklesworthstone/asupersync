//! STUN (Session Traversal Utilities for NAT) protocol implementation.
//!
//! Implements STUN client for ICE candidate gathering and NAT traversal.
//! This is the foundation for ATP-F Path Graph Engine NAT traversal.

use crate::cx::Cx;
use crate::runtime::spawn_blocking;
use crate::types::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const STUN_BINDING_ERROR_RESPONSE: u16 = 0x0111;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;
const STUN_TRANSACTION_ID_LEN: usize = 12;
const STUN_MAX_MESSAGE_LEN: usize = 1200;
const STUN_DEFAULT_TIMEOUT: Duration = Duration::from_millis(750);

/// STUN message types (RFC 5389).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StunMessageType {
    /// Binding request to discover reflexive address.
    BindingRequest,
    /// Binding response with reflexive address.
    BindingResponse,
    /// Binding error response.
    BindingError,
}

/// STUN client for NAT traversal and ICE candidate discovery.
#[derive(Debug)]
pub struct StunClient {
    /// Local UDP socket address.
    local_addr: SocketAddr,
    /// Known STUN servers for reflexive address discovery.
    stun_servers: Vec<SocketAddr>,
    /// Discovered ICE candidates.
    candidates: HashMap<String, IceCandidate>,
}

/// ICE candidate types for NAT traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IceCandidateType {
    /// Host candidate (local interface address).
    Host,
    /// Server reflexive candidate (discovered via STUN).
    ServerReflexive,
    /// Peer reflexive candidate (discovered during connectivity checks).
    PeerReflexive,
    /// Relay candidate (allocated via TURN server).
    Relay,
}

/// ICE candidate for NAT traversal path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Candidate foundation (for grouping related candidates).
    pub foundation: String,
    /// Component ID (1 for RTP, 2 for RTCP, 1 for ATP).
    pub component: u16,
    /// Transport protocol (UDP).
    pub protocol: String,
    /// Candidate priority.
    pub priority: u32,
    /// IP address and port.
    pub address: SocketAddr,
    /// Candidate type.
    pub candidate_type: IceCandidateType,
    /// Related address (for reflexive/relay candidates).
    pub related_address: Option<SocketAddr>,
}

impl StunClient {
    /// Create a new STUN client for the given local address.
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            stun_servers: Vec::new(),
            candidates: HashMap::new(),
        }
    }

    /// Add a STUN server for reflexive address discovery.
    pub fn add_stun_server(&mut self, server_addr: SocketAddr) {
        self.stun_servers.push(server_addr);
    }

    /// Gather ICE candidates for NAT traversal.
    pub async fn gather_candidates(&mut self, cx: &Cx) -> Outcome<Vec<IceCandidate>, StunError> {
        // Step 1: Add host candidate (local interface)
        let host_candidate = IceCandidate {
            foundation: "1".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 126, // Host candidate priority
            address: self.local_addr,
            candidate_type: IceCandidateType::Host,
            related_address: None,
        };
        self.candidates
            .insert("host".to_string(), host_candidate.clone());

        let mut candidates = vec![host_candidate];
        for (index, server) in self.stun_servers.iter().copied().enumerate() {
            match self.send_binding_request(cx, server).await {
                Outcome::Ok(reflexive_addr) => {
                    let candidate = IceCandidate {
                        foundation: format!("srflx-{}", index + 1),
                        component: 1,
                        protocol: "udp".to_string(),
                        priority: 100,
                        address: reflexive_addr,
                        candidate_type: IceCandidateType::ServerReflexive,
                        related_address: Some(self.local_addr),
                    };
                    self.candidates
                        .insert(format!("srflx:{server}"), candidate.clone());
                    candidates.push(candidate);
                }
                Outcome::Err(err) => {
                    cx.trace(&format!("STUN binding request to {server} failed: {err}"));
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        Outcome::ok(candidates)
    }

    /// Send STUN binding request to discover reflexive address.
    async fn send_binding_request(
        &self,
        _cx: &Cx,
        server: SocketAddr,
    ) -> Outcome<SocketAddr, StunError> {
        let local_addr = self.local_addr;
        let transaction_id = Self::transaction_id(local_addr, server);

        match spawn_blocking(move || {
            let request = encode_binding_request(transaction_id);
            let socket = std::net::UdpSocket::bind(local_addr)
                .map_err(|err| StunError::Network(err.to_string()))?;
            socket
                .set_read_timeout(Some(STUN_DEFAULT_TIMEOUT))
                .map_err(|err| StunError::Network(err.to_string()))?;
            socket
                .set_write_timeout(Some(STUN_DEFAULT_TIMEOUT))
                .map_err(|err| StunError::Network(err.to_string()))?;
            socket
                .send_to(&request, server)
                .map_err(|err| StunError::Network(err.to_string()))?;

            let mut response = [0u8; STUN_MAX_MESSAGE_LEN];
            let (len, peer) = socket.recv_from(&mut response).map_err(|err| {
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) {
                    StunError::Timeout
                } else {
                    StunError::Network(err.to_string())
                }
            })?;

            if peer != server {
                return Err(StunError::InvalidResponse);
            }

            parse_binding_response(&response[..len], transaction_id)
        })
        .await
        {
            Ok(addr) => Outcome::ok(addr),
            Err(err) => Outcome::err(err),
        }
    }

    /// Get discovered candidates.
    pub fn candidates(&self) -> Vec<&IceCandidate> {
        self.candidates.values().collect()
    }

    fn transaction_id(
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> [u8; STUN_TRANSACTION_ID_LEN] {
        use sha2::{Digest, Sha256};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut hasher = Sha256::new();
        hasher.update(local_addr.to_string().as_bytes());
        hasher.update(server_addr.to_string().as_bytes());
        hasher.update(now.to_be_bytes());
        let digest = hasher.finalize();
        let mut transaction_id = [0u8; STUN_TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&digest[..STUN_TRANSACTION_ID_LEN]);
        transaction_id
    }
}

fn encode_binding_request(transaction_id: [u8; STUN_TRANSACTION_ID_LEN]) -> [u8; STUN_HEADER_LEN] {
    let mut request = [0u8; STUN_HEADER_LEN];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    request
}

fn parse_binding_response(
    message: &[u8],
    transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
) -> Result<SocketAddr, StunError> {
    if message.len() < STUN_HEADER_LEN {
        return Err(StunError::InvalidResponse);
    }

    let message_type = u16::from_be_bytes([message[0], message[1]]);
    if message_type == STUN_BINDING_ERROR_RESPONSE {
        return Err(StunError::Protocol(
            "STUN server returned binding error response".to_string(),
        ));
    }
    if message_type != STUN_BINDING_SUCCESS_RESPONSE {
        return Err(StunError::InvalidResponse);
    }

    let message_len = usize::from(u16::from_be_bytes([message[2], message[3]]));
    let end = STUN_HEADER_LEN
        .checked_add(message_len)
        .ok_or(StunError::InvalidResponse)?;
    if end > message.len() || message_len % 4 != 0 {
        return Err(StunError::InvalidResponse);
    }

    let cookie = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(StunError::InvalidResponse);
    }

    if message[8..20] != transaction_id {
        return Err(StunError::InvalidResponse);
    }

    let mut mapped_address = None;
    let mut offset = STUN_HEADER_LEN;
    while offset < end {
        if offset + 4 > end {
            return Err(StunError::InvalidResponse);
        }

        let attr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let attr_len = usize::from(u16::from_be_bytes([
            message[offset + 2],
            message[offset + 3],
        ]));
        let value_start = offset + 4;
        let value_end = value_start
            .checked_add(attr_len)
            .ok_or(StunError::InvalidResponse)?;
        let padded_end = value_start
            .checked_add((attr_len + 3) & !3)
            .ok_or(StunError::InvalidResponse)?;
        if value_end > end || padded_end > end {
            return Err(StunError::InvalidResponse);
        }

        let value = &message[value_start..value_end];
        match attr_type {
            STUN_ATTR_XOR_MAPPED_ADDRESS => {
                return parse_stun_address(value, true, transaction_id);
            }
            STUN_ATTR_MAPPED_ADDRESS => {
                mapped_address = Some(parse_stun_address(value, false, transaction_id)?);
            }
            _ => {}
        }

        offset = padded_end;
    }

    mapped_address.ok_or(StunError::InvalidResponse)
}

fn parse_stun_address(
    value: &[u8],
    xor_mapped: bool,
    transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidResponse);
    }

    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor_mapped {
        port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
    }

    match family {
        0x01 => {
            if value.len() != 8 {
                return Err(StunError::InvalidResponse);
            }
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor_mapped {
                for (octet, cookie) in octets
                    .iter_mut()
                    .zip(STUN_MAGIC_COOKIE.to_be_bytes().iter().copied())
                {
                    *octet ^= cookie;
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 => {
            if value.len() != 20 {
                return Err(StunError::InvalidResponse);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor_mapped {
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for index in 0..4 {
                    octets[index] ^= cookie[index];
                }
                for index in 0..STUN_TRANSACTION_ID_LEN {
                    octets[index + 4] ^= transaction_id[index];
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(StunError::InvalidResponse),
    }
}

/// STUN protocol errors.
#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum StunError {
    #[error("STUN server timeout")]
    Timeout,

    #[error("Invalid STUN response")]
    InvalidResponse,

    #[error("STUN protocol error: {0}")]
    Protocol(String),

    #[error("Network error: {0}")]
    Network(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn stun_client_creation() {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let client = StunClient::new(local_addr);
        assert_eq!(client.local_addr, local_addr);
        assert!(client.stun_servers.is_empty());
        assert!(client.candidates.is_empty());
    }

    #[test]
    fn add_stun_server() {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let mut client = StunClient::new(local_addr);

        let stun_server = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478));
        client.add_stun_server(stun_server);

        assert_eq!(client.stun_servers.len(), 1);
        assert_eq!(client.stun_servers[0], stun_server);
    }

    fn binding_success_response(
        transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
        mapped_addr: SocketAddr,
    ) -> Vec<u8> {
        let mut attr_value = Vec::new();
        attr_value.push(0);
        match mapped_addr {
            SocketAddr::V4(addr) => {
                attr_value.push(0x01);
                attr_value.extend_from_slice(
                    &(addr.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                );
                for (octet, cookie) in addr
                    .ip()
                    .octets()
                    .iter()
                    .zip(STUN_MAGIC_COOKIE.to_be_bytes().iter())
                {
                    attr_value.push(*octet ^ *cookie);
                }
            }
            SocketAddr::V6(addr) => {
                attr_value.push(0x02);
                attr_value.extend_from_slice(
                    &(addr.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                );
                let mut octets = addr.ip().octets();
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for index in 0..4 {
                    octets[index] ^= cookie[index];
                }
                for index in 0..STUN_TRANSACTION_ID_LEN {
                    octets[index + 4] ^= transaction_id[index];
                }
                attr_value.extend_from_slice(&octets);
            }
        }

        let message_len = 4 + attr_value.len();
        let mut response = Vec::with_capacity(STUN_HEADER_LEN + message_len);
        response.extend_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response.extend_from_slice(&(message_len as u16).to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        response.extend_from_slice(&attr_value);
        response
    }

    #[test]
    fn binding_request_header_is_rfc5389_canonical() {
        let transaction_id = [0xAB; STUN_TRANSACTION_ID_LEN];
        let request = encode_binding_request(transaction_id);

        assert_eq!(
            u16::from_be_bytes([request[0], request[1]]),
            STUN_BINDING_REQUEST
        );
        assert_eq!(u16::from_be_bytes([request[2], request[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&request[8..20], &transaction_id);
    }

    #[test]
    fn parses_xor_mapped_address_from_success_response() {
        let transaction_id = [0x42; STUN_TRANSACTION_ID_LEN];
        let mapped = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 54321));
        let response = binding_success_response(transaction_id, mapped);

        let parsed = parse_binding_response(&response, transaction_id).unwrap();

        assert_eq!(parsed, mapped);
    }

    #[test]
    fn gather_candidates_uses_real_udp_stun_exchange() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let mapped = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 20), 50000));

        let server_thread = std::thread::spawn(move || {
            let mut request = [0u8; STUN_MAX_MESSAGE_LEN];
            let (len, peer) = server.recv_from(&mut request).unwrap();
            assert!(len >= STUN_HEADER_LEN);
            assert_eq!(
                u16::from_be_bytes([request[0], request[1]]),
                STUN_BINDING_REQUEST
            );
            let mut transaction_id = [0u8; STUN_TRANSACTION_ID_LEN];
            transaction_id.copy_from_slice(&request[8..20]);
            let response = binding_success_response(transaction_id, mapped);
            server.send_to(&response, peer).unwrap();
        });

        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let mut client = StunClient::new(local_addr);
        client.add_stun_server(server_addr);
        let cx = Cx::for_testing();

        let outcome = futures_lite::future::block_on(client.gather_candidates(&cx));
        server_thread.join().unwrap();

        let candidates = match outcome {
            Outcome::Ok(candidates) => candidates,
            other => panic!("expected gathered candidates, got {other:?}"),
        };
        assert!(candidates.iter().any(|candidate| {
            matches!(candidate.candidate_type, IceCandidateType::ServerReflexive)
                && candidate.address == mapped
        }));
    }

    // Golden Artifact Tests for STUN/ICE Serialization Stability

    #[test]
    fn golden_stun_message_types_serialization() {
        use insta::assert_json_snapshot;

        let message_types = vec![
            StunMessageType::BindingRequest,
            StunMessageType::BindingResponse,
            StunMessageType::BindingError,
        ];
        assert_json_snapshot!("stun_message_types", message_types);
    }

    #[test]
    fn golden_ice_candidate_types_serialization() {
        use insta::assert_json_snapshot;

        let candidate_types = vec![
            IceCandidateType::Host,
            IceCandidateType::ServerReflexive,
            IceCandidateType::PeerReflexive,
            IceCandidateType::Relay,
        ];
        assert_json_snapshot!("ice_candidate_types", candidate_types);
    }

    #[test]
    fn golden_ice_candidate_host_serialization() {
        use insta::assert_json_snapshot;

        let host_candidate = IceCandidate {
            foundation: "1".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 126,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 5000)),
            candidate_type: IceCandidateType::Host,
            related_address: None,
        };
        assert_json_snapshot!("ice_candidate_host", host_candidate);
    }

    #[test]
    fn golden_ice_candidate_server_reflexive_serialization() {
        use insta::assert_json_snapshot;

        let reflexive_candidate = IceCandidate {
            foundation: "2".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 100,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 54400)),
            candidate_type: IceCandidateType::ServerReflexive,
            related_address: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 1, 100),
                5000,
            ))),
        };
        assert_json_snapshot!("ice_candidate_server_reflexive", reflexive_candidate);
    }

    #[test]
    fn golden_ice_candidate_relay_serialization() {
        use insta::assert_json_snapshot;

        let relay_candidate = IceCandidate {
            foundation: "3".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 50,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 49152)),
            candidate_type: IceCandidateType::Relay,
            related_address: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(203, 0, 113, 10),
                54400,
            ))),
        };
        assert_json_snapshot!("ice_candidate_relay", relay_candidate);
    }

    #[test]
    fn golden_stun_error_types_serialization() {
        use insta::assert_json_snapshot;

        let error_types = vec![
            StunError::Timeout,
            StunError::InvalidResponse,
            StunError::Protocol("Binding error".to_string()),
            StunError::Network("Connection refused".to_string()),
        ];
        assert_json_snapshot!("stun_error_types", error_types);
    }
}
