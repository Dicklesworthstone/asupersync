//! STUN (Session Traversal Utilities for NAT) protocol implementation.
//!
//! Implements STUN client for ICE candidate gathering and NAT traversal.
//! This is the foundation for ATP-F Path Graph Engine NAT traversal.

use crate::types::Outcome;
use crate::cx::Cx;
use std::net::SocketAddr;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// STUN message types (RFC 5389).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub async fn gather_candidates(&mut self, _cx: &Cx) -> Outcome<Vec<IceCandidate>, StunError> {
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
        self.candidates.insert("host".to_string(), host_candidate.clone());

        // Step 2: Discover server reflexive candidates via STUN
        // TODO: Implement STUN binding request/response
        // For now, return host candidate as foundation

        Ok(vec![host_candidate])
    }

    /// Send STUN binding request to discover reflexive address.
    async fn send_binding_request(&self, _cx: &Cx, _server: SocketAddr) -> Outcome<SocketAddr, StunError> {
        // TODO: Implement STUN message encoding/decoding
        // TODO: Send UDP packet with STUN binding request
        // TODO: Parse response to extract XOR-MAPPED-ADDRESS
        Err(StunError::NotImplemented)
    }

    /// Get discovered candidates.
    pub fn candidates(&self) -> Vec<&IceCandidate> {
        self.candidates.values().collect()
    }
}

/// STUN protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("STUN not implemented yet")]
    NotImplemented,

    #[error("STUN server timeout")]
    Timeout,

    #[error("Invalid STUN response")]
    InvalidResponse,

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
}