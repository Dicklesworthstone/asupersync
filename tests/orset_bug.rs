//! Tests for ORSet CRDT regressions.

use asupersync::remote::NodeId;
use asupersync::trace::distributed::crdt::{Merge, ORSet};

#[test]
fn orset_remove_is_not_undone_by_old_replica() {
    let mut a = ORSet::new();
    a.add("x", &NodeId::new("n1"));
    let b = a.clone(); // B has observed the original add tag.

    a.remove(&"x");
    assert!(!a.contains(&"x"));

    // Merging a stale replica must not resurrect a tag that A tombstoned.
    a.merge(&b);

    assert!(!a.contains(&"x"), "Remove was undone by merging old state!");
}
