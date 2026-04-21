#![allow(clippy::all)]
//! Metamorphic tests for evidence ledger serialization roundtrips.
//!
//! These tests validate the serialization/deserialization properties of evidence
//! structures using metamorphic relations without requiring oracle outputs.

use std::time::Duration;

use proptest::prelude::*;
use serde_json;

use asupersync::evidence::{
    EvidenceDetail, EvidenceRecord, GeneralizedLedger, LinkDetail, MonitorDetail, RegistryDetail,
    Subsystem, SupervisionDetail, Verdict,
};
use asupersync::types::{CancelReason, Outcome, RegionId, TaskId};

/// Arbitrary instance for Subsystem enum.
fn arb_subsystem() -> impl Strategy<Value = Subsystem> {
    prop_oneof![
        Just(Subsystem::Supervision),
        Just(Subsystem::Registry),
        Just(Subsystem::Link),
        Just(Subsystem::Monitor),
    ]
}

/// Arbitrary instance for Verdict enum.
fn arb_verdict() -> impl Strategy<Value = Verdict> {
    prop_oneof![
        Just(Verdict::Restart),
        Just(Verdict::Stop),
        Just(Verdict::Escalate),
        Just(Verdict::Accept),
        Just(Verdict::Reject),
        Just(Verdict::Release),
        Just(Verdict::Abort),
        Just(Verdict::Propagate),
        Just(Verdict::Suppress),
        Just(Verdict::Deliver),
        Just(Verdict::Drop),
    ]
}

/// Arbitrary instance for SupervisionDetail.
fn arb_supervision_detail() -> impl Strategy<Value = SupervisionDetail> {
    prop_oneof![
        ".*".prop_map(|s| SupervisionDetail::MonotoneSeverity { outcome_kind: s }),
        Just(SupervisionDetail::ExplicitStop),
        Just(SupervisionDetail::ExplicitEscalate),
        (1u32..100, prop::option::of(0u64..1000000)).prop_map(|(attempt, delay_ns)| {
            SupervisionDetail::RestartAllowed {
                attempt,
                delay: delay_ns.map(Duration::from_nanos),
            }
        }),
        (1u32..50, 0u64..1000000).prop_map(|(max_restarts, window_ns)| {
            SupervisionDetail::WindowExhausted {
                max_restarts,
                window: Duration::from_nanos(window_ns),
            }
        }),
        ".*".prop_map(|constraint| SupervisionDetail::BudgetRefused { constraint }),
    ]
}

/// Arbitrary instance for RegistryDetail.
fn arb_registry_detail() -> impl Strategy<Value = RegistryDetail> {
    prop_oneof![
        Just(RegistryDetail::NameAvailable),
        ".*".prop_map(|name| RegistryDetail::NameCollision { name }),
        Just(RegistryDetail::RegionClosed),
        Just(RegistryDetail::TaskShuttingDown),
        ".*".prop_map(|reason| RegistryDetail::CleanupScheduled { reason }),
        ".*".prop_map(|reason| RegistryDetail::CleanupCompleted { reason }),
    ]
}

/// Arbitrary instance for LinkDetail.
fn arb_link_detail() -> impl Strategy<Value = LinkDetail> {
    prop_oneof![
        Just(LinkDetail::TrapExitActive {
            linked_task: TaskId::new_for_test(1, 0),
        }),
        Just(LinkDetail::TrapExitActive {
            linked_task: TaskId::new_for_test(2, 0),
        }),
        Just(LinkDetail::LinkBroken {
            target_task: TaskId::new_for_test(3, 0),
            reason: "test".to_string(),
        }),
    ]
}

/// Arbitrary instance for MonitorDetail.
fn arb_monitor_detail() -> impl Strategy<Value = MonitorDetail> {
    prop_oneof![
        Just(MonitorDetail::WatcherTerminated {
            watcher_task: TaskId::new_for_test(4, 0),
        }),
        Just(MonitorDetail::MonitorBroken {
            monitored_task: TaskId::new_for_test(5, 0),
            reason: "test".to_string(),
        }),
    ]
}

/// Arbitrary instance for EvidenceDetail.
fn arb_evidence_detail() -> impl Strategy<Value = EvidenceDetail> {
    prop_oneof![
        arb_supervision_detail().prop_map(EvidenceDetail::Supervision),
        arb_registry_detail().prop_map(EvidenceDetail::Registry),
        arb_link_detail().prop_map(EvidenceDetail::Link),
        arb_monitor_detail().prop_map(EvidenceDetail::Monitor),
    ]
}

/// Arbitrary instance for EvidenceRecord.
fn arb_evidence_record() -> impl Strategy<Value = EvidenceRecord> {
    (
        any::<u64>(), // timestamp
        any::<u32>(), // task_id inner
        any::<u32>(), // task_id region
        any::<u32>(), // region_id inner
        any::<u32>(), // region_id arena
        arb_subsystem(),
        arb_verdict(),
        arb_evidence_detail(),
    )
        .prop_map(
            |(timestamp, task_inner, task_region, region_inner, region_arena, subsystem, verdict, detail)| {
                EvidenceRecord {
                    timestamp,
                    task_id: TaskId::new_for_test(task_inner, task_region),
                    region_id: RegionId::new_for_test(region_inner, region_arena),
                    subsystem,
                    verdict,
                    detail,
                }
            },
        )
}

/// Arbitrary instance for GeneralizedLedger.
fn arb_generalized_ledger() -> impl Strategy<Value = GeneralizedLedger> {
    prop::collection::vec(arb_evidence_record(), 0..20).prop_map(|records| {
        let mut ledger = GeneralizedLedger::new();
        for record in records {
            ledger.push(record);
        }
        ledger
    })
}

// Metamorphic Relations

/// MR1: Round-trip property - serialize then deserialize recovers original.
/// This is the fundamental property for serialization correctness.
#[test]
fn mr_evidence_record_roundtrip() {
    proptest!(|(record in arb_evidence_record())| {
        // Serialize to JSON
        let serialized = serde_json::to_string(&record)
            .expect("EvidenceRecord should serialize to JSON");

        // Deserialize back
        let deserialized: EvidenceRecord = serde_json::from_str(&serialized)
            .expect("Serialized EvidenceRecord should deserialize back");

        // Original and round-trip result must be equal
        prop_assert_eq!(record, deserialized);
    });
}

/// MR2: Round-trip property for GeneralizedLedger.
#[test]
fn mr_generalized_ledger_roundtrip() {
    proptest!(|(ledger in arb_generalized_ledger())| {
        // Serialize to JSON
        let serialized = serde_json::to_string(&ledger)
            .expect("GeneralizedLedger should serialize to JSON");

        // Deserialize back
        let deserialized: GeneralizedLedger = serde_json::from_str(&serialized)
            .expect("Serialized GeneralizedLedger should deserialize back");

        // Original and round-trip result must be equal
        prop_assert_eq!(ledger.entries(), deserialized.entries());
    });
}

/// MR3: Serialization determinism - same record always produces same bytes.
#[test]
fn mr_evidence_record_deterministic() {
    proptest!(|(record in arb_evidence_record())| {
        let serialized1 = serde_json::to_string(&record)
            .expect("EvidenceRecord should serialize");
        let serialized2 = serde_json::to_string(&record)
            .expect("EvidenceRecord should serialize again");

        // Same record must produce identical serialized bytes
        prop_assert_eq!(serialized1, serialized2);
    });
}

/// MR4: Individual record properties preserved in ledger serialization.
/// Each record in a ledger should serialize identically whether alone or in ledger.
#[test]
fn mr_ledger_individual_record_preservation() {
    proptest!(|(records in prop::collection::vec(arb_evidence_record(), 1..10))| {
        // Create ledger with records
        let mut ledger = GeneralizedLedger::new();
        for record in &records {
            ledger.push(record.clone());
        }

        // Serialize the ledger
        let ledger_serialized = serde_json::to_string(&ledger)
            .expect("Ledger should serialize");

        // Deserialize back
        let ledger_deserialized: GeneralizedLedger = serde_json::from_str(&ledger_serialized)
            .expect("Ledger should deserialize");

        // Each individual record should serialize identically whether alone or in ledger
        for (original_record, ledger_record) in records.iter().zip(ledger_deserialized.entries()) {
            let original_serialized = serde_json::to_string(original_record)
                .expect("Original record should serialize");
            let ledger_record_serialized = serde_json::to_string(ledger_record)
                .expect("Ledger record should serialize");

            prop_assert_eq!(original_serialized, ledger_record_serialized);
        }
    });
}

/// MR5: Binary format stability - serialize to bytes and back.
#[test]
fn mr_evidence_record_binary_roundtrip() {
    proptest!(|(record in arb_evidence_record())| {
        // Serialize to binary format (bincode)
        let serialized = bincode::serialize(&record)
            .expect("EvidenceRecord should serialize to binary");

        // Deserialize back
        let deserialized: EvidenceRecord = bincode::deserialize(&serialized)
            .expect("Binary EvidenceRecord should deserialize back");

        // Original and round-trip result must be equal
        prop_assert_eq!(record, deserialized);
    });
}

/// MR6: Cross-format consistency - JSON and binary should preserve structure.
#[test]
fn mr_evidence_record_cross_format_consistency() {
    proptest!(|(record in arb_evidence_record())| {
        // Serialize to JSON then deserialize
        let json_serialized = serde_json::to_string(&record)
            .expect("Should serialize to JSON");
        let from_json: EvidenceRecord = serde_json::from_str(&json_serialized)
            .expect("Should deserialize from JSON");

        // Serialize to binary then deserialize
        let binary_serialized = bincode::serialize(&record)
            .expect("Should serialize to binary");
        let from_binary: EvidenceRecord = bincode::deserialize(&binary_serialized)
            .expect("Should deserialize from binary");

        // Both formats should produce identical records
        prop_assert_eq!(from_json, from_binary);
        prop_assert_eq!(record, from_json);
        prop_assert_eq!(record, from_binary);
    });
}

/// MR7: Ledger size preservation - number of entries preserved through serialization.
#[test]
fn mr_ledger_size_preservation() {
    proptest!(|(ledger in arb_generalized_ledger())| {
        let original_size = ledger.entries().len();

        // Round-trip through JSON
        let serialized = serde_json::to_string(&ledger)
            .expect("Ledger should serialize");
        let deserialized: GeneralizedLedger = serde_json::from_str(&serialized)
            .expect("Ledger should deserialize");

        // Size must be preserved
        prop_assert_eq!(original_size, deserialized.entries().len());
    });
}

/// MR8: Empty ledger stability - empty ledger serializes and deserializes correctly.
#[test]
fn mr_empty_ledger_stability() {
    let empty_ledger = GeneralizedLedger::new();

    // Serialize empty ledger
    let serialized = serde_json::to_string(&empty_ledger)
        .expect("Empty ledger should serialize");

    // Deserialize back
    let deserialized: GeneralizedLedger = serde_json::from_str(&serialized)
        .expect("Empty ledger should deserialize");

    // Should still be empty
    assert_eq!(empty_ledger.entries().len(), 0);
    assert_eq!(deserialized.entries().len(), 0);
}

/// Unit tests for specific edge cases
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_evidence_record_with_duration_zero() {
        let record = EvidenceRecord {
            timestamp: 12345,
            task_id: TaskId::from_inner(1, 0),
            region_id: RegionId::from_inner(1, 0),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 1,
                delay: Some(Duration::from_nanos(0)),
            }),
        };

        let serialized = serde_json::to_string(&record).unwrap();
        let deserialized: EvidenceRecord = serde_json::from_str(&serialized).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_evidence_record_with_duration_none() {
        let record = EvidenceRecord {
            timestamp: 12345,
            task_id: TaskId::from_inner(1, 0),
            region_id: RegionId::from_inner(1, 0),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 1,
                delay: None,
            }),
        };

        let serialized = serde_json::to_string(&record).unwrap();
        let deserialized: EvidenceRecord = serde_json::from_str(&serialized).unwrap();
        assert_eq!(record, deserialized);
    }
}