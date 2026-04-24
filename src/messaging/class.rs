//! Delivery-class taxonomy for the native FABRIC lane.

#![allow(clippy::struct_field_names)]

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

/// Named delivery classes reserved by the FABRIC design.
///
/// The enum order is intentional: moving upward makes stronger guarantees
/// explicit and never silently downgrades the common-case packet plane.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryClass {
    /// Hot ephemeral pub/sub. No durability or obligation tracking.
    #[default]
    EphemeralInteractive,
    /// Durable ordered stream semantics with authority-plane commit.
    DurableOrdered,
    /// Request/reply and service flows backed by explicit obligations.
    ObligationBacked,
    /// Safe for stewardship change and cut-certified mobility operations.
    MobilitySafe,
    /// Replay-heavy reasoning tier with explicit evidence retention.
    ForensicReplayable,
}

impl DeliveryClass {
    /// All delivery classes in ascending cost/strength order.
    pub const ALL: [Self; 5] = [
        Self::EphemeralInteractive,
        Self::DurableOrdered,
        Self::ObligationBacked,
        Self::MobilitySafe,
        Self::ForensicReplayable,
    ];

    /// Return the operator-facing cost vector for this class.
    #[inline]
    #[must_use]
    pub const fn cost_vector(self) -> DeliveryCostVector {
        match self {
            Self::EphemeralInteractive => DeliveryCostVector::new(0, 0, 0, 0),
            Self::DurableOrdered => DeliveryCostVector::new(1, 1, 1, 1),
            Self::ObligationBacked => DeliveryCostVector::new(2, 2, 2, 2),
            Self::MobilitySafe => DeliveryCostVector::new(3, 2, 3, 3),
            Self::ForensicReplayable => DeliveryCostVector::new(4, 3, 4, 4),
        }
    }

    /// Minimum acknowledgement boundary this class can honestly claim.
    #[inline]
    #[must_use]
    pub const fn minimum_ack(self) -> AckKind {
        match self {
            Self::EphemeralInteractive => AckKind::Accepted,
            Self::DurableOrdered => AckKind::Recoverable,
            Self::ObligationBacked => AckKind::Served,
            Self::MobilitySafe | Self::ForensicReplayable => AckKind::Received,
        }
    }
}

impl fmt::Display for DeliveryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::EphemeralInteractive => "ephemeral-interactive",
            Self::DurableOrdered => "durable-ordered",
            Self::ObligationBacked => "obligation-backed",
            Self::MobilitySafe => "mobility-safe",
            Self::ForensicReplayable => "forensic-replayable",
        };
        write!(f, "{name}")
    }
}

/// Distinct acknowledgement boundaries for delivery classes and policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckKind {
    /// Packet plane accepted custody for forwarding.
    Accepted,
    /// Authority plane committed the control entry or obligation.
    Committed,
    /// Declared durability class has been met.
    Recoverable,
    /// Service obligation completed by the callee.
    Served,
    /// Configured delivery or receipt boundary was crossed.
    Received,
}

impl fmt::Display for AckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Accepted => "accepted",
            Self::Committed => "committed",
            Self::Recoverable => "recoverable",
            Self::Served => "served",
            Self::Received => "received",
        };
        write!(f, "{name}")
    }
}

/// Relative cost envelope for a delivery class.
///
/// These are tier numbers, not calibrated performance claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeliveryCostVector {
    /// Relative latency cost of the class.
    pub latency_tier: u8,
    /// Relative storage cost of the class.
    pub storage_tier: u8,
    /// Relative CPU cost of the class.
    pub cpu_tier: u8,
    /// Relative evidence or replay overhead of the class.
    pub evidence_tier: u8,
}

impl DeliveryCostVector {
    /// Construct a new cost vector.
    #[must_use]
    pub const fn new(latency_tier: u8, storage_tier: u8, cpu_tier: u8, evidence_tier: u8) -> Self {
        Self {
            latency_tier,
            storage_tier,
            cpu_tier,
            evidence_tier,
        }
    }
}

/// Provider-declared admissible classes plus the common-case default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryClassPolicy {
    /// Default class applied when the caller does not explicitly request one.
    pub default_class: DeliveryClass,
    admissible_classes: Vec<DeliveryClass>,
}

impl DeliveryClassPolicy {
    /// Build a canonical provider policy.
    pub fn new<I>(
        default_class: DeliveryClass,
        admissible_classes: I,
    ) -> Result<Self, DeliveryClassPolicyError>
    where
        I: IntoIterator<Item = DeliveryClass>,
    {
        let mut admissible_classes = admissible_classes.into_iter().collect::<Vec<_>>();
        admissible_classes.sort_unstable();
        admissible_classes.dedup();

        if admissible_classes.is_empty() {
            return Err(DeliveryClassPolicyError::EmptyProviderPolicy);
        }
        if admissible_classes.binary_search(&default_class).is_err() {
            return Err(DeliveryClassPolicyError::DefaultClassNotAdmissible { default_class });
        }

        Ok(Self {
            default_class,
            admissible_classes,
        })
    }

    /// Return the canonical admissible class set in ascending order.
    #[must_use]
    pub fn admissible_classes(&self) -> &[DeliveryClass] {
        &self.admissible_classes
    }

    /// Return true when the provider admits the requested class.
    #[must_use]
    pub fn allows(&self, requested: DeliveryClass) -> bool {
        self.admissible_classes.binary_search(&requested).is_ok()
    }

    /// Select the effective class for a caller request.
    ///
    /// `None` means "use the provider default".
    pub fn select_for_caller(
        &self,
        requested: Option<DeliveryClass>,
    ) -> Result<DeliveryClass, DeliveryClassPolicyError> {
        let requested = requested.unwrap_or(self.default_class);
        if self.allows(requested) {
            Ok(requested)
        } else {
            Err(DeliveryClassPolicyError::RequestedClassNotAdmissible {
                requested,
                default_class: self.default_class,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeliveryClassPolicyRepr {
    default_class: DeliveryClass,
    admissible_classes: Vec<DeliveryClass>,
}

impl Serialize for DeliveryClassPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DeliveryClassPolicyRepr {
            default_class: self.default_class,
            admissible_classes: self.admissible_classes.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeliveryClassPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = DeliveryClassPolicyRepr::deserialize(deserializer)?;
        Self::new(repr.default_class, repr.admissible_classes).map_err(serde::de::Error::custom)
    }
}

/// Validation failures for provider/caller class selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeliveryClassPolicyError {
    /// Provider policy must declare at least one admissible class.
    #[error("provider policy must declare at least one admissible delivery class")]
    EmptyProviderPolicy,
    /// Provider default must be a member of the admissible set.
    #[error("provider default class {default_class} is not in the admissible set")]
    DefaultClassNotAdmissible {
        /// Default class that was not admitted by the provider.
        default_class: DeliveryClass,
    },
    /// Caller requested a class outside the provider envelope.
    #[error(
        "caller requested class {requested}, but the provider only admits classes rooted at default {default_class}"
    )]
    RequestedClassNotAdmissible {
        /// Class requested by the caller.
        requested: DeliveryClass,
        /// Provider default used for the service surface.
        default_class: DeliveryClass,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn delivery_class_default_is_ephemeral_interactive() {
        assert_eq!(
            DeliveryClass::default(),
            DeliveryClass::EphemeralInteractive
        );
    }

    #[test]
    fn delivery_class_order_tracks_non_decreasing_cost() {
        for pair in DeliveryClass::ALL.windows(2) {
            let left = pair[0].cost_vector();
            let right = pair[1].cost_vector();
            assert!(
                left <= right,
                "expected {:?} cost {:?} <= {:?} cost {:?}",
                pair[0],
                left,
                pair[1],
                right
            );
        }
    }

    #[test]
    fn delivery_class_minimum_ack_is_monotonic() {
        for pair in DeliveryClass::ALL.windows(2) {
            assert!(
                pair[0].minimum_ack() <= pair[1].minimum_ack(),
                "expected {:?} minimum ack {} <= {:?} minimum ack {}",
                pair[0],
                pair[0].minimum_ack(),
                pair[1],
                pair[1].minimum_ack()
            );
        }
    }

    #[test]
    fn ack_kind_order_is_progressive() {
        assert!(AckKind::Accepted < AckKind::Committed);
        assert!(AckKind::Committed < AckKind::Recoverable);
        assert!(AckKind::Recoverable < AckKind::Served);
        assert!(AckKind::Served < AckKind::Received);
    }

    #[test]
    fn serde_round_trip_preserves_taxonomy_values() {
        let class = DeliveryClass::MobilitySafe;
        let ack = AckKind::Recoverable;

        let class_json = serde_json::to_string(&class).expect("serialize delivery class");
        let ack_json = serde_json::to_string(&ack).expect("serialize ack kind");

        assert_eq!(
            serde_json::from_str::<DeliveryClass>(&class_json).expect("deserialize delivery class"),
            class
        );
        assert_eq!(
            serde_json::from_str::<AckKind>(&ack_json).expect("deserialize ack kind"),
            ack
        );
    }

    #[test]
    fn provider_policy_requires_non_empty_admissible_set() {
        let err = DeliveryClassPolicy::new(DeliveryClass::EphemeralInteractive, [])
            .expect_err("empty provider policy must fail");
        assert_eq!(err, DeliveryClassPolicyError::EmptyProviderPolicy);
    }

    #[test]
    fn provider_policy_requires_default_to_be_admissible() {
        let err = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [DeliveryClass::EphemeralInteractive],
        )
        .expect_err("default outside admissible set must fail");
        assert_eq!(
            err,
            DeliveryClassPolicyError::DefaultClassNotAdmissible {
                default_class: DeliveryClass::DurableOrdered,
            }
        );
    }

    #[test]
    fn provider_policy_deduplicates_and_sorts_classes() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [
                DeliveryClass::DurableOrdered,
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
            ],
        )
        .expect("provider policy should canonicalize duplicates");

        assert_eq!(
            policy.admissible_classes(),
            &[
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
            ]
        );
    }

    #[test]
    fn provider_policy_uses_default_when_caller_omits_request() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
            ],
        )
        .expect("valid provider policy");

        assert_eq!(
            policy
                .select_for_caller(None)
                .expect("use provider default"),
            DeliveryClass::DurableOrdered
        );
    }

    #[test]
    fn provider_policy_rejects_unavailable_requested_class() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::EphemeralInteractive,
            [DeliveryClass::EphemeralInteractive],
        )
        .expect("valid provider policy");

        let err = policy
            .select_for_caller(Some(DeliveryClass::ForensicReplayable))
            .expect_err("caller request outside provider envelope must fail");
        assert_eq!(
            err,
            DeliveryClassPolicyError::RequestedClassNotAdmissible {
                requested: DeliveryClass::ForensicReplayable,
                default_class: DeliveryClass::EphemeralInteractive,
            }
        );
    }

    #[test]
    fn provider_policy_deserialization_revalidates_invariants() {
        let invalid =
            r#"{"default_class":"durable_ordered","admissible_classes":["ephemeral_interactive"]}"#;
        let err = serde_json::from_str::<DeliveryClassPolicy>(invalid)
            .expect_err("invalid serialized policy must be rejected");
        let err = err.to_string();
        assert!(
            err.contains("default class durable-ordered"),
            "expected validation error to mention the invalid default, got {err}"
        );
    }

    #[test]
    fn delivery_class_display_and_minimum_ack_cover_every_variant() {
        let cases = [
            (
                DeliveryClass::EphemeralInteractive,
                "ephemeral-interactive",
                AckKind::Accepted,
            ),
            (
                DeliveryClass::DurableOrdered,
                "durable-ordered",
                AckKind::Recoverable,
            ),
            (
                DeliveryClass::ObligationBacked,
                "obligation-backed",
                AckKind::Served,
            ),
            (
                DeliveryClass::MobilitySafe,
                "mobility-safe",
                AckKind::Received,
            ),
            (
                DeliveryClass::ForensicReplayable,
                "forensic-replayable",
                AckKind::Received,
            ),
        ];

        for (class, expected_display, expected_ack) in cases {
            assert_eq!(class.to_string(), expected_display);
            assert_eq!(class.minimum_ack(), expected_ack);
        }
    }

    #[test]
    fn provider_policy_allows_valid_requested_classes_and_round_trips() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [
                DeliveryClass::MobilitySafe,
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
            ],
        )
        .expect("valid provider policy");

        assert!(policy.allows(DeliveryClass::DurableOrdered));
        assert!(policy.allows(DeliveryClass::ObligationBacked));
        assert!(policy.allows(DeliveryClass::MobilitySafe));
        assert!(!policy.allows(DeliveryClass::ForensicReplayable));

        assert_eq!(
            policy
                .select_for_caller(Some(DeliveryClass::ObligationBacked))
                .expect("caller request within provider envelope"),
            DeliveryClass::ObligationBacked
        );
        assert_eq!(
            policy
                .select_for_caller(Some(DeliveryClass::MobilitySafe))
                .expect("caller request within provider envelope"),
            DeliveryClass::MobilitySafe
        );

        let json = serde_json::to_string(&policy).expect("serialize provider policy");
        let decoded: DeliveryClassPolicy =
            serde_json::from_str(&json).expect("deserialize provider policy");
        assert_eq!(decoded, policy);
        assert_eq!(
            decoded.admissible_classes(),
            &[
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
                DeliveryClass::MobilitySafe,
            ]
        );
    }
}
