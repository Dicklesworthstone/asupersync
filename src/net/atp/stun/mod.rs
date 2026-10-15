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
        validate_observation_metadata(&request.observer_id, request.probe_nonce)?;

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

/// One endpoint probe result used for ATP NAT classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProbeObservation {
    local_endpoint: ObservedEndpoint,
    observed_endpoint: Option<ObservedEndpoint>,
    observer_id: String,
    probe_nonce: u64,
    observed_at_micros: u64,
    hairpin_succeeded: Option<bool>,
}

impl EndpointProbeObservation {
    /// Convert a successful endpoint observation into classifier evidence.
    #[must_use]
    pub fn observed(observation: EndpointObservation) -> Self {
        Self {
            local_endpoint: observation.local_endpoint,
            observed_endpoint: Some(observation.observed_endpoint),
            observer_id: observation.observer_id,
            probe_nonce: observation.probe_nonce,
            observed_at_micros: observation.observed_at_micros,
            hairpin_succeeded: None,
        }
    }

    /// Build a failed UDP probe observation.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::EmptyObserverId`] when the observer id is
    /// blank and [`ObservationError::ZeroProbeNonce`] when the nonce is zero.
    pub fn blocked(
        local_endpoint: ObservedEndpoint,
        observer_id: impl Into<String>,
        probe_nonce: u64,
        observed_at_micros: u64,
    ) -> Result<Self, ObservationError> {
        let observer_id = observer_id.into();
        validate_observation_metadata(&observer_id, probe_nonce)?;

        Ok(Self {
            local_endpoint,
            observed_endpoint: None,
            observer_id,
            probe_nonce,
            observed_at_micros,
            hairpin_succeeded: None,
        })
    }

    /// Attach a measured hairpin probe result to this observation.
    #[must_use]
    pub const fn with_hairpin_result(mut self, succeeded: bool) -> Self {
        self.hairpin_succeeded = Some(succeeded);
        self
    }

    /// Endpoint the local peer believes it used.
    #[must_use]
    pub const fn local_endpoint(&self) -> &ObservedEndpoint {
        &self.local_endpoint
    }

    /// Endpoint reported by the observer, if the probe succeeded.
    #[must_use]
    pub const fn observed_endpoint(&self) -> Option<&ObservedEndpoint> {
        self.observed_endpoint.as_ref()
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

    /// Whether the UDP endpoint probe reached the observer.
    #[must_use]
    pub const fn probe_succeeded(&self) -> bool {
        self.observed_endpoint.is_some()
    }
}

impl From<EndpointObservation> for EndpointProbeObservation {
    fn from(observation: EndpointObservation) -> Self {
        Self::observed(observation)
    }
}

/// ATP endpoint NAT/path shape inferred from endpoint probe observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointNatKind {
    /// No successful UDP endpoint observation was recorded.
    UdpBlocked,
    /// Observed public IPv6 endpoint matches the local IPv6 endpoint.
    Ipv6Direct,
    /// Observed public IPv4 endpoint matches the local IPv4 endpoint.
    PublicIpv4Direct,
    /// A stable public mapping was observed, but it differs from the local endpoint.
    LikelyEasyNat,
    /// Multiple public mappings were observed for the same local UDP endpoint.
    HardOrSymmetricNat,
    /// Observations were insufficient or contradictory.
    Unknown,
}

/// Hairpin capability inferred from explicitly measured endpoint probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointHairpinSupport {
    /// Hairpin probes succeeded at least once.
    Supported,
    /// Hairpin probes were measured and failed.
    Unsupported,
    /// Hairpin behavior was not measured.
    Unknown,
}

/// Confidence attached to an ATP endpoint NAT/path assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointNatConfidence {
    /// One or more observations are missing, so callers should treat the result as a hint.
    Low,
    /// A single successful observation supports the assessment.
    Medium,
    /// Multiple observations or a conclusive blocked/direct result support the assessment.
    High,
}

/// NAT/path assessment derived from ATP endpoint probe observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointNatAssessment {
    /// Inferred NAT/path kind.
    pub kind: EndpointNatKind,
    /// Inferred hairpin behavior.
    pub hairpin: EndpointHairpinSupport,
    /// Confidence in the inferred kind.
    pub confidence: EndpointNatConfidence,
    /// Stable observed public endpoint, if there is exactly one.
    pub observed_public_endpoint: Option<ObservedEndpoint>,
    /// Stable machine-readable caveat for path logs and diagnostics.
    pub caveat: &'static str,
}

/// Classify ATP endpoint NAT/path behavior from STUN-like probe observations.
#[must_use]
pub fn classify_endpoint_nat(observations: &[EndpointProbeObservation]) -> EndpointNatAssessment {
    if observations.is_empty() {
        return EndpointNatAssessment {
            kind: EndpointNatKind::Unknown,
            hairpin: EndpointHairpinSupport::Unknown,
            confidence: EndpointNatConfidence::Low,
            observed_public_endpoint: None,
            caveat: "missing_endpoint_observation",
        };
    }

    let hairpin = classify_endpoint_hairpin(observations);
    let successful = observations
        .iter()
        .filter_map(|observation| {
            observation
                .observed_endpoint()
                .map(|public_endpoint| (observation, public_endpoint))
        })
        .collect::<Vec<_>>();

    if successful.is_empty() {
        return EndpointNatAssessment {
            kind: EndpointNatKind::UdpBlocked,
            hairpin,
            confidence: EndpointNatConfidence::High,
            observed_public_endpoint: None,
            caveat: "no_udp_probe_reached_rendezvous",
        };
    }

    if successful.iter().all(|(observation, public_endpoint)| {
        observation.local_endpoint().is_ipv6() && observation.local_endpoint() == *public_endpoint
    }) {
        return EndpointNatAssessment {
            kind: EndpointNatKind::Ipv6Direct,
            hairpin,
            confidence: confidence_for_success_count(successful.len()),
            observed_public_endpoint: successful
                .first()
                .map(|(_, public_endpoint)| (*public_endpoint).clone()),
            caveat: "ipv6_endpoint_observed_directly",
        };
    }

    let mut unique_observed: Vec<ObservedEndpoint> = Vec::new();
    for (_, public_endpoint) in &successful {
        if !unique_observed
            .iter()
            .any(|endpoint| endpoint == *public_endpoint)
        {
            unique_observed.push((*public_endpoint).clone());
        }
    }

    let same_local_endpoint = successful.first().is_some_and(|(first, _)| {
        successful
            .iter()
            .all(|(observation, _)| observation.local_endpoint() == first.local_endpoint())
    });

    if unique_observed.len() > 1 && same_local_endpoint {
        return EndpointNatAssessment {
            kind: EndpointNatKind::HardOrSymmetricNat,
            hairpin,
            confidence: EndpointNatConfidence::High,
            observed_public_endpoint: None,
            caveat: "multiple_public_mappings_observed",
        };
    }

    if unique_observed.len() > 1 {
        return EndpointNatAssessment {
            kind: EndpointNatKind::Unknown,
            hairpin,
            confidence: EndpointNatConfidence::Low,
            observed_public_endpoint: None,
            caveat: "multiple_local_endpoints_observed",
        };
    }

    let Some(observed) = unique_observed.into_iter().next() else {
        return EndpointNatAssessment {
            kind: EndpointNatKind::Unknown,
            hairpin,
            confidence: EndpointNatConfidence::Low,
            observed_public_endpoint: None,
            caveat: "missing_public_mapping_after_success",
        };
    };
    let direct = successful
        .iter()
        .any(|(observation, _)| observation.local_endpoint() == &observed);
    let kind = if direct {
        EndpointNatKind::PublicIpv4Direct
    } else {
        EndpointNatKind::LikelyEasyNat
    };
    let caveat = if direct {
        "ipv4_endpoint_observed_directly"
    } else {
        "stable_public_mapping_observed"
    };

    EndpointNatAssessment {
        kind,
        hairpin,
        confidence: confidence_for_success_count(successful.len()),
        observed_public_endpoint: Some(observed),
        caveat,
    }
}

fn classify_endpoint_hairpin(observations: &[EndpointProbeObservation]) -> EndpointHairpinSupport {
    let mut measured_failure = false;
    for observation in observations {
        match observation.hairpin_succeeded {
            Some(true) => return EndpointHairpinSupport::Supported,
            Some(false) => measured_failure = true,
            None => {}
        }
    }

    if measured_failure {
        EndpointHairpinSupport::Unsupported
    } else {
        EndpointHairpinSupport::Unknown
    }
}

const fn confidence_for_success_count(count: usize) -> EndpointNatConfidence {
    if count > 1 {
        EndpointNatConfidence::High
    } else {
        EndpointNatConfidence::Medium
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

fn validate_observation_metadata(
    observer_id: &str,
    probe_nonce: u64,
) -> Result<(), ObservationError> {
    if observer_id.trim().is_empty() {
        return Err(ObservationError::EmptyObserverId);
    }
    if probe_nonce == 0 {
        return Err(ObservationError::ZeroProbeNonce);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    fn ipv6_endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv6, address, port).expect("endpoint")
    }

    fn probe(
        local_endpoint: ObservedEndpoint,
        observed_endpoint: ObservedEndpoint,
        probe_nonce: u64,
    ) -> EndpointProbeObservation {
        EndpointObservation::from_request(ObservationRequest {
            local_endpoint,
            observed_endpoint,
            observer_id: format!("rendezvous-{probe_nonce}"),
            probe_nonce,
            observed_at_micros: probe_nonce * 10,
        })
        .expect("valid observation")
        .into()
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

    #[test]
    fn endpoint_probe_observation_records_blocked_probe_metadata() {
        let probe = EndpointProbeObservation::blocked(endpoint("10.0.0.2", 40_000), "rv-a", 9, 99)
            .expect("blocked probe");

        assert!(!probe.probe_succeeded());
        assert_eq!(probe.observer_id(), "rv-a");
        assert_eq!(probe.probe_nonce(), 9);
        assert_eq!(probe.observed_at_micros(), 99);
        assert_eq!(probe.observed_endpoint(), None);
        assert_eq!(probe.local_endpoint().address(), "10.0.0.2");
    }

    #[test]
    fn endpoint_nat_classifier_reports_missing_observations_as_unknown() {
        let assessment = classify_endpoint_nat(&[]);

        assert_eq!(assessment.kind, EndpointNatKind::Unknown);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Low);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "missing_endpoint_observation");
    }

    #[test]
    fn endpoint_nat_classifier_reports_blocked_when_probes_fail() {
        let assessment = classify_endpoint_nat(&[EndpointProbeObservation::blocked(
            endpoint("10.0.0.2", 40_000),
            "rv-a",
            3,
            30,
        )
        .expect("blocked")]);

        assert_eq!(assessment.kind, EndpointNatKind::UdpBlocked);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, EndpointNatConfidence::High);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "no_udp_probe_reached_rendezvous");
    }

    #[test]
    fn endpoint_nat_classifier_distinguishes_ipv6_direct_path() {
        let local = ipv6_endpoint("2001:db8::10", 49_152);
        let assessment = classify_endpoint_nat(&[probe(local.clone(), local.clone(), 4)]);

        assert_eq!(assessment.kind, EndpointNatKind::Ipv6Direct);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Medium);
        assert_eq!(assessment.observed_public_endpoint, Some(local));
        assert_eq!(assessment.caveat, "ipv6_endpoint_observed_directly");
    }

    #[test]
    fn endpoint_nat_classifier_reports_public_ipv4_direct_path() {
        let local = endpoint("198.51.100.10", 49_152);
        let assessment = classify_endpoint_nat(&[probe(local.clone(), local.clone(), 5)]);

        assert_eq!(assessment.kind, EndpointNatKind::PublicIpv4Direct);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Medium);
        assert_eq!(assessment.observed_public_endpoint, Some(local));
        assert_eq!(assessment.caveat, "ipv4_endpoint_observed_directly");
    }

    #[test]
    fn endpoint_nat_classifier_reports_stable_mapping_as_likely_easy_nat() {
        let public = endpoint("198.51.100.20", 62_000);
        let observations = [
            probe(endpoint("10.0.0.2", 49_152), public.clone(), 6).with_hairpin_result(true),
            probe(endpoint("10.0.0.2", 49_152), public.clone(), 7),
        ];

        let assessment = classify_endpoint_nat(&observations);

        assert_eq!(assessment.kind, EndpointNatKind::LikelyEasyNat);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Supported);
        assert_eq!(assessment.confidence, EndpointNatConfidence::High);
        assert_eq!(assessment.observed_public_endpoint, Some(public));
        assert_eq!(assessment.caveat, "stable_public_mapping_observed");
    }

    #[test]
    fn endpoint_nat_classifier_reports_multiple_mappings_as_hard_or_symmetric_nat() {
        let observations = [
            probe(
                endpoint("10.0.0.2", 49_152),
                endpoint("198.51.100.20", 62_000),
                8,
            )
            .with_hairpin_result(false),
            probe(
                endpoint("10.0.0.2", 49_152),
                endpoint("198.51.100.21", 62_001),
                9,
            ),
        ];

        let assessment = classify_endpoint_nat(&observations);

        assert_eq!(assessment.kind, EndpointNatKind::HardOrSymmetricNat);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unsupported);
        assert_eq!(assessment.confidence, EndpointNatConfidence::High);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "multiple_public_mappings_observed");
    }

    #[test]
    fn endpoint_nat_classifier_reports_contradictory_multi_local_observations_as_unknown() {
        let observations = [
            probe(
                endpoint("10.0.0.2", 49_152),
                endpoint("198.51.100.20", 62_000),
                10,
            ),
            probe(
                endpoint("10.0.0.3", 49_153),
                endpoint("198.51.100.21", 62_001),
                11,
            ),
        ];

        let assessment = classify_endpoint_nat(&observations);

        assert_eq!(assessment.kind, EndpointNatKind::Unknown);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Low);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "multiple_local_endpoints_observed");
    }
}
