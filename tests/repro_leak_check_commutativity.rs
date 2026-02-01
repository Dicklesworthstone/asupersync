#![doc = "Repro for leak-check commutativity in obligation analysis."]
#![allow(missing_docs)]

use asupersync::obligation::VarState;
use asupersync::record::ObligationKind;

#[test]
fn test_var_state_join_commutativity() {
    let state_a = VarState::Held(ObligationKind::SendPermit);
    let state_b = VarState::Held(ObligationKind::Lease);

    let join_ab = state_a.join(state_b);
    let join_ba = state_b.join(state_a);

    println!("A: {:?}", state_a);
    println!("B: {:?}", state_b);
    println!("A join B: {:?}", join_ab);
    println!("B join A: {:?}", join_ba);

    assert_eq!(join_ab, join_ba, "Join should be commutative");
    
    // Check that we got the ambiguous state
    assert!(matches!(join_ab, VarState::MayHoldAmbiguous), "Should be ambiguous");
}

#[test]
fn test_var_state_ambiguous_propagation() {
    let state_a = VarState::MayHoldAmbiguous;
    let state_b = VarState::Held(ObligationKind::SendPermit);
    
    let join = state_a.join(state_b);
    assert!(matches!(join, VarState::MayHoldAmbiguous), "Ambiguity should propagate");
}
