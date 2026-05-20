//! NAT classification for ATP path discovery.

use crate::net::atp::stun::{EndpointFamily, EndpointObservation, ObservedEndpoint};

/// Coarse NAT profile inferred from endpoint observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NatProfile {
    /// Public IPv6 is directly usable.
    Ipv6Direct,
    /// UDP appears usable with stable endpoint mapping.
    LikelyEasyNat,
    /// Multiple observers saw incompatible mappings, suggesting symmetric NAT.
    HardSymmetricNat,
    /// UDP probing failed before any useful observation was made.
    UdpBlocked,
    /// Evidence is insufficient or contradictory.
    Unknown,
}

/// Hairpin behavior evidence for a NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HairpinBehavior {
    /// Hairpinning was measured successfully.
    Supported,
    /// Hairpinning was measured and failed.
    NotSupported,
    /// Hairpinning was not measured.
    Unknown,
}

/// Confidence attached to a NAT classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NatConfidence {
    /// Evidence is weak or absent.
    Low,
    /// Evidence is plausible but not conclusive.
    Medium,
    /// Evidence is strong enough for path-selection decisions.
    High,
}

/// UDP probe outcome before endpoint classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UdpProbe {
    /// UDP probe completed.
    Succeeded,
    /// UDP probe failed or timed out.
    Blocked,
    /// UDP probe has not run.
    NotMeasured,
}

/// Evidence used by the deterministic NAT classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatEvidence {
    local_endpoint: ObservedEndpoint,
    observations: Vec<EndpointObservation>,
    udp_probe: UdpProbe,
    hairpin: HairpinBehavior,
}

impl NatEvidence {
    /// Construct NAT evidence from local and observed endpoints.
    #[must_use]
    pub fn new(
        local_endpoint: ObservedEndpoint,
        observations: Vec<EndpointObservation>,
        udp_probe: UdpProbe,
        hairpin: HairpinBehavior,
    ) -> Self {
        Self {
            local_endpoint,
            observations,
            udp_probe,
            hairpin,
        }
    }

    /// Local endpoint supplied by the peer.
    #[must_use]
    pub const fn local_endpoint(&self) -> &ObservedEndpoint {
        &self.local_endpoint
    }

    /// Endpoint observations from rendezvous servers.
    #[must_use]
    pub fn observations(&self) -> &[EndpointObservation] {
        &self.observations
    }

    /// UDP probe result.
    #[must_use]
    pub const fn udp_probe(&self) -> UdpProbe {
        self.udp_probe
    }

    /// Hairpin measurement result.
    #[must_use]
    pub const fn hairpin(&self) -> HairpinBehavior {
        self.hairpin
    }
}

/// Result of NAT classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatClassification {
    /// Coarse NAT profile.
    pub profile: NatProfile,
    /// Confidence in the profile.
    pub confidence: NatConfidence,
    /// Hairpin behavior evidence.
    pub hairpin: HairpinBehavior,
    /// Stable caveat code for path logs.
    pub caveat: &'static str,
}

/// Classify NAT behavior from STUN-like observations.
#[must_use]
pub fn classify_nat(evidence: &NatEvidence) -> NatClassification {
    if matches!(evidence.udp_probe, UdpProbe::Blocked) {
        return NatClassification {
            profile: NatProfile::UdpBlocked,
            confidence: NatConfidence::High,
            hairpin: evidence.hairpin,
            caveat: "udp_probe_blocked",
        };
    }

    if evidence.local_endpoint.family() == EndpointFamily::Ipv6
        && evidence
            .observations
            .iter()
            .any(|observation| observation.observed_endpoint().is_ipv6())
    {
        return NatClassification {
            profile: NatProfile::Ipv6Direct,
            confidence: NatConfidence::High,
            hairpin: evidence.hairpin,
            caveat: "ipv6_observed",
        };
    }

    if evidence.observations.is_empty() {
        return NatClassification {
            profile: NatProfile::Unknown,
            confidence: NatConfidence::Low,
            hairpin: evidence.hairpin,
            caveat: "no_observations",
        };
    }

    if has_incompatible_mappings(&evidence.observations) {
        return NatClassification {
            profile: NatProfile::HardSymmetricNat,
            confidence: NatConfidence::High,
            hairpin: evidence.hairpin,
            caveat: "incompatible_observed_mappings",
        };
    }

    NatClassification {
        profile: NatProfile::LikelyEasyNat,
        confidence: match evidence.hairpin {
            HairpinBehavior::Unknown => NatConfidence::Medium,
            HairpinBehavior::Supported | HairpinBehavior::NotSupported => NatConfidence::High,
        },
        hairpin: evidence.hairpin,
        caveat: "stable_observed_mapping",
    }
}

fn has_incompatible_mappings(observations: &[EndpointObservation]) -> bool {
    let Some(first) = observations.first() else {
        return false;
    };
    let first_endpoint = first.observed_endpoint();
    observations
        .iter()
        .skip(1)
        .any(|observation| observation.observed_endpoint() != first_endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::stun::{ObservationRequest, ObservedEndpoint};

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    fn ipv6_endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv6, address, port).expect("endpoint")
    }

    fn observation(
        local: ObservedEndpoint,
        observed: ObservedEndpoint,
        nonce: u64,
    ) -> EndpointObservation {
        EndpointObservation::from_request(ObservationRequest {
            local_endpoint: local,
            observed_endpoint: observed,
            observer_id: format!("observer-{nonce}"),
            probe_nonce: nonce,
            observed_at_micros: nonce,
        })
        .expect("observation")
    }

    #[test]
    fn classifies_udp_blocked_without_observations() {
        let evidence = NatEvidence::new(
            endpoint("10.0.0.2", 40_000),
            Vec::new(),
            UdpProbe::Blocked,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::UdpBlocked);
        assert_eq!(classification.confidence, NatConfidence::High);
        assert_eq!(classification.caveat, "udp_probe_blocked");
    }

    #[test]
    fn classifies_ipv6_direct_when_ipv6_is_observed() {
        let local = ipv6_endpoint("2001:db8::1", 40_000);
        let observed = ipv6_endpoint("2001:db8::1", 40_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![observation(local, observed, 1)],
            UdpProbe::Succeeded,
            HairpinBehavior::Supported,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::Ipv6Direct);
        assert_eq!(classification.confidence, NatConfidence::High);
    }

    #[test]
    fn classifies_hard_nat_when_observers_disagree() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed_a = endpoint("198.51.100.10", 50_000);
        let observed_b = endpoint("198.51.100.10", 51_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed_a, 1),
                observation(local, observed_b, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::NotSupported,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::HardSymmetricNat);
        assert_eq!(classification.hairpin, HairpinBehavior::NotSupported);
    }

    #[test]
    fn classifies_stable_mapping_as_easy_nat() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed = endpoint("198.51.100.10", 50_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed.clone(), 1),
                observation(local, observed, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::LikelyEasyNat);
        assert_eq!(classification.confidence, NatConfidence::Medium);
    }
}
