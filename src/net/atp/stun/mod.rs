//! STUN-like endpoint observation records for ATP path discovery.
//!
//! This module deliberately models the observation layer without opening
//! sockets. Runtime transport code can feed these deterministic records into
//! NAT classification and rendezvous exchange code.

/// IP address family for an ATP endpoint observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointFamily {
    /// IPv4 endpoint.
    Ipv4,
    /// IPv6 endpoint.
    Ipv6,
}

/// Host and port observed by either the local peer or a rendezvous server.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservedEndpoint {
    family: EndpointFamily,
    address: String,
    port: u16,
}

impl ObservedEndpoint {
    /// Construct an endpoint from already-normalized host text and a UDP port.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::EmptyAddress`] when `address` is empty or
    /// whitespace and [`ObservationError::ZeroPort`] when `port` is zero.
    pub fn new(
        family: EndpointFamily,
        address: impl Into<String>,
        port: u16,
    ) -> Result<Self, ObservationError> {
        let address = address.into();
        if address.trim().is_empty() {
            return Err(ObservationError::EmptyAddress);
        }
        if port == 0 {
            return Err(ObservationError::ZeroPort);
        }

        Ok(Self {
            family,
            address,
            port,
        })
    }

    /// IP family for this endpoint.
    #[must_use]
    pub const fn family(&self) -> EndpointFamily {
        self.family
    }

    /// Host text exactly as recorded by the observer.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// UDP port for this endpoint.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Whether this endpoint uses IPv6.
    #[must_use]
    pub const fn is_ipv6(&self) -> bool {
        matches!(self.family, EndpointFamily::Ipv6)
    }
}

/// Request used to build one endpoint observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRequest {
    /// Endpoint the local peer believes it used for the probe.
    pub local_endpoint: ObservedEndpoint,
    /// Endpoint reported by the remote observer.
    pub observed_endpoint: ObservedEndpoint,
    /// Stable rendezvous or observation server identifier.
    pub observer_id: String,
    /// Probe nonce used to bind request and response.
    pub probe_nonce: u64,
    /// Deterministic timestamp supplied by the caller.
    pub observed_at_micros: u64,
}

/// One STUN-like observation of a peer's apparent public endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointObservation {
    local_endpoint: ObservedEndpoint,
    observed_endpoint: ObservedEndpoint,
    observer_id: String,
    probe_nonce: u64,
    observed_at_micros: u64,
}

impl EndpointObservation {
    /// Build and validate an endpoint observation.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::EmptyObserverId`] when the observer id is
    /// blank and [`ObservationError::ZeroProbeNonce`] when the nonce is zero.
    pub fn from_request(request: ObservationRequest) -> Result<Self, ObservationError> {
        if request.observer_id.trim().is_empty() {
            return Err(ObservationError::EmptyObserverId);
        }
        if request.probe_nonce == 0 {
            return Err(ObservationError::ZeroProbeNonce);
        }

        Ok(Self {
            local_endpoint: request.local_endpoint,
            observed_endpoint: request.observed_endpoint,
            observer_id: request.observer_id,
            probe_nonce: request.probe_nonce,
            observed_at_micros: request.observed_at_micros,
        })
    }

    /// Endpoint the local peer believes it used.
    #[must_use]
    pub const fn local_endpoint(&self) -> &ObservedEndpoint {
        &self.local_endpoint
    }

    /// Endpoint reported by the observer.
    #[must_use]
    pub const fn observed_endpoint(&self) -> &ObservedEndpoint {
        &self.observed_endpoint
    }

    /// Stable observer identifier.
    #[must_use]
    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }

    /// Probe nonce.
    #[must_use]
    pub const fn probe_nonce(&self) -> u64 {
        self.probe_nonce
    }

    /// Deterministic observation timestamp.
    #[must_use]
    pub const fn observed_at_micros(&self) -> u64 {
        self.observed_at_micros
    }
}

/// Endpoint observation validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObservationError {
    /// Endpoint address text was empty.
    #[error("endpoint address is empty")]
    EmptyAddress,
    /// Endpoint port was zero.
    #[error("endpoint port is zero")]
    ZeroPort,
    /// Observer id was empty.
    #[error("observer id is empty")]
    EmptyObserverId,
    /// Probe nonce was zero.
    #[error("probe nonce is zero")]
    ZeroProbeNonce,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    #[test]
    fn observation_records_observed_endpoint_and_nonce() {
        let observation = EndpointObservation::from_request(ObservationRequest {
            local_endpoint: endpoint("10.0.0.2", 40_000),
            observed_endpoint: endpoint("198.51.100.10", 50_000),
            observer_id: "rendezvous-a".to_owned(),
            probe_nonce: 7,
            observed_at_micros: 99,
        })
        .expect("valid observation");

        assert_eq!(observation.observer_id(), "rendezvous-a");
        assert_eq!(observation.probe_nonce(), 7);
        assert_eq!(observation.local_endpoint().address(), "10.0.0.2");
        assert_eq!(observation.observed_endpoint().port(), 50_000);
    }

    #[test]
    fn observation_rejects_blank_observer_and_zero_nonce() {
        let err = EndpointObservation::from_request(ObservationRequest {
            local_endpoint: endpoint("10.0.0.2", 40_000),
            observed_endpoint: endpoint("198.51.100.10", 50_000),
            observer_id: " ".to_owned(),
            probe_nonce: 7,
            observed_at_micros: 99,
        })
        .expect_err("blank observer");
        assert_eq!(err, ObservationError::EmptyObserverId);

        let err = EndpointObservation::from_request(ObservationRequest {
            local_endpoint: endpoint("10.0.0.2", 40_000),
            observed_endpoint: endpoint("198.51.100.10", 50_000),
            observer_id: "rendezvous-a".to_owned(),
            probe_nonce: 0,
            observed_at_micros: 99,
        })
        .expect_err("zero nonce");
        assert_eq!(err, ObservationError::ZeroProbeNonce);
    }

    #[test]
    fn endpoint_rejects_empty_address_and_zero_port() {
        assert_eq!(
            ObservedEndpoint::new(EndpointFamily::Ipv4, " ", 1).expect_err("empty address"),
            ObservationError::EmptyAddress
        );
        assert_eq!(
            ObservedEndpoint::new(EndpointFamily::Ipv6, "2001:db8::1", 0).expect_err("zero port"),
            ObservationError::ZeroPort
        );
    }
}
