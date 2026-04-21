#![allow(warnings)]
#![allow(clippy::all)]
//! Tests for ORSet CRDT regressions.

use asupersync::remote::NodeId;
use asupersync::trace::distributed::crdt::{Merge, ORSet};

#[test]
fn orset_remove_is_not_undone_by_old_replica() {
    let mut a = ORSet::new();
    a.add("x", &NodeId::new("n1"));
    let b = a.clone(); // B has the tag

    a.remove(&"x"); // A completely removes "x" from its entries
    assert!(!a.contains(&"x"));

    // Now B (who hasn't seen the remove) merges back into A
    a.merge(&b);

    // The tag from B is merged back in, undoing the remove!
    assert!(!a.contains(&"x"), "Remove was undone by merging old state!");
}
