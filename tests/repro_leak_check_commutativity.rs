//! Regression tests for leak-check join commutativity in obligation analysis.

use asupersync::obligation::VarState;
use asupersync::record::ObligationKind;

#[test]
fn test_var_state_join_commutativity() {
    let state_a = VarState::Held(ObligationKind::SendPermit);
    let state_b = VarState::Held(ObligationKind::Lease);

    let join_ab = state_a.join(state_b);
    let join_ba = state_b.join(state_a);

    assert_eq!(join_ab, join_ba, "Join should be commutative");
    assert_eq!(join_ab, VarState::MayHoldAmbiguous);
}

#[test]
fn test_var_state_ambiguous_propagation() {
    let state_a = VarState::MayHoldAmbiguous;
    let state_b = VarState::Held(ObligationKind::SendPermit);

    let join = state_a.join(state_b);
    assert!(
        matches!(join, VarState::MayHoldAmbiguous),
        "Ambiguity should propagate"
    );
}
