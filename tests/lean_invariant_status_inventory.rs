//! Invariant inventory consistency checks (bd-1v4tc).

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const INVARIANT_INVENTORY_JSON: &str =
    include_str!("../formal/lean/coverage/invariant_status_inventory.json");
const THEOREM_INVENTORY_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_surface_inventory.json");

#[test]
fn invariant_inventory_is_consistent() {
    let invariant_inventory: Value =
        serde_json::from_str(INVARIANT_INVENTORY_JSON).expect("invariant inventory must parse");
    let theorem_inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");

    let theorem_names = theorem_inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array")
        .iter()
        .filter_map(|entry| entry.get("theorem").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();

    let invariants = invariant_inventory
        .get("invariants")
        .and_then(Value::as_array)
        .expect("invariants must be an array");
    assert!(
        !invariants.is_empty(),
        "invariant inventory must include at least one invariant"
    );

    let mut ids = BTreeSet::new();
    let mut fully_proven = 0usize;
    let mut partially_proven = 0usize;
    let mut unproven = 0usize;

    for invariant in invariants {
        let id = invariant
            .get("id")
            .and_then(Value::as_str)
            .expect("invariant id must be a string");
        assert!(ids.insert(id), "duplicate invariant id: {id}");

        let status = invariant
            .get("lean_status")
            .and_then(Value::as_str)
            .expect("lean_status must be a string");
        match status {
            "fully_proven" => fully_proven += 1,
            "partially_proven" => partially_proven += 1,
            "unproven" => unproven += 1,
            _ => panic!("unknown lean_status '{status}' for invariant {id}"),
        }

        let theorem_refs = invariant
            .get("lean_theorems")
            .and_then(Value::as_array)
            .expect("lean_theorems must be an array");
        for theorem in theorem_refs {
            let theorem_name = theorem
                .as_str()
                .expect("theorem refs must be strings in lean_theorems");
            assert!(
                theorem_names.contains(theorem_name),
                "invariant {id} references missing theorem {theorem_name}"
            );
        }

        let test_refs = invariant
            .get("test_refs")
            .and_then(Value::as_array)
            .expect("test_refs must be an array");
        for test_ref in test_refs {
            let path = test_ref
                .as_str()
                .expect("test refs must be strings in test_refs");
            assert!(
                Path::new(path).exists(),
                "invariant {id} references missing test path {path}"
            );
        }
    }

    let summary = invariant_inventory
        .get("summary")
        .expect("summary object must exist");
    assert_eq!(
        summary
            .get("fully_proven")
            .and_then(Value::as_u64)
            .expect("summary.fully_proven must be numeric") as usize,
        fully_proven
    );
    assert_eq!(
        summary
            .get("partially_proven")
            .and_then(Value::as_u64)
            .expect("summary.partially_proven must be numeric") as usize,
        partially_proven
    );
    assert_eq!(
        summary
            .get("unproven")
            .and_then(Value::as_u64)
            .expect("summary.unproven must be numeric") as usize,
        unproven
    );
}

#[test]
fn invariant_inventory_uses_canonical_names() {
    let invariant_inventory: Value =
        serde_json::from_str(INVARIANT_INVENTORY_JSON).expect("invariant inventory must parse");

    let canonical = invariant_inventory
        .get("canonical_invariant_definitions")
        .and_then(Value::as_array)
        .expect("canonical_invariant_definitions must be an array");
    let canonical_names = canonical
        .iter()
        .map(|entry| {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .expect("canonical id must be a string");
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .expect("canonical name must be a string");
            assert!(
                entry
                    .get("statement")
                    .and_then(Value::as_str)
                    .is_some_and(|statement| !statement.trim().is_empty()),
                "canonical statement must be non-empty for {id}"
            );
            (id, name)
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let expected = std::collections::BTreeMap::from([
        (
            "inv.structured_concurrency.single_owner",
            "Structured concurrency: every task is owned by exactly one region",
        ),
        ("inv.region_close.quiescence", "Region close = quiescence"),
        (
            "inv.cancel.protocol",
            "Cancellation is a protocol: request -> drain -> finalize (idempotent)",
        ),
        ("inv.race.losers_drained", "Losers are drained after races"),
        ("inv.obligation.no_leaks", "No obligation leaks"),
        ("inv.authority.no_ambient", "No ambient authority"),
    ]);
    assert_eq!(
        canonical_names, expected,
        "canonical invariant lexicon must match project non-negotiable invariants"
    );

    let invariants = invariant_inventory
        .get("invariants")
        .and_then(Value::as_array)
        .expect("invariants must be an array");
    for invariant in invariants {
        let id = invariant
            .get("id")
            .and_then(Value::as_str)
            .expect("invariant id must be a string");
        let name = invariant
            .get("name")
            .and_then(Value::as_str)
            .expect("invariant name must be a string");
        let Some(expected_name) = expected.get(id) else {
            panic!("unexpected invariant id in inventory: {id}");
        };
        assert_eq!(
            name, *expected_name,
            "invariant {id} must use canonical name"
        );
    }
}
