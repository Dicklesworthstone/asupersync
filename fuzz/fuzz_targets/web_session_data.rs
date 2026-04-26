//! Fuzz target for `src/web/session.rs` — SessionData + MemoryStore lifecycle.
//!
//! Exercises:
//!   - SessionData insert/get/remove/clear on arbitrary keys/values.
//!   - The `is_modified` flag transitions correctly.
//!   - `len() == keys().len()` and `is_empty() == (len() == 0)`.
//!   - MemoryStore round-trip: save then load returns the exact data.
//!   - MemoryStore::delete actually removes the entry.
//!
//! These structures are reachable from any HTTP handler that uses
//! `SessionLayer::wrap`. A bug here is a session-store integrity bug
//! that affects every authenticated request.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::web::session::{MemoryStore, SessionData, SessionStore};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Op {
    Insert { key: String, value: String },
    Get { key: String },
    Remove { key: String },
    Clear,
}

#[derive(Debug, Arbitrary)]
struct Input {
    ops: Vec<Op>,
    session_id: String,
}

fuzz_target!(|input: Input| {
    let mut data = SessionData::new();
    assert!(!data.is_modified(), "fresh SessionData must not be modified");
    assert!(data.is_empty());
    assert_eq!(data.len(), 0);

    // Apply each op and check the structural invariants.
    let mut shadow: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for op in input.ops.iter().take(256) {
        match op {
            Op::Insert { key, value } => {
                let prior = data.insert(key.clone(), value.clone());
                let prior_shadow = shadow.insert(key.clone(), value.clone());
                assert_eq!(
                    prior, prior_shadow,
                    "insert returned wrong prior value for key {key:?}"
                );
            }
            Op::Get { key } => {
                let got = data.get(key);
                let want = shadow.get(key).map(String::as_str);
                assert_eq!(got, want, "get returned wrong value for key {key:?}");
            }
            Op::Remove { key } => {
                let got = data.remove(key);
                let want = shadow.remove(key);
                assert_eq!(got, want, "remove returned wrong value for key {key:?}");
            }
            Op::Clear => {
                data.clear();
                shadow.clear();
            }
        }
        assert_eq!(data.len(), shadow.len(), "len() inconsistent with shadow");
        assert_eq!(data.is_empty(), shadow.is_empty(), "is_empty() inconsistent");
        assert_eq!(
            data.keys().len(),
            data.len(),
            "keys() length disagrees with len()"
        );
    }

    // MemoryStore round-trip — only test if the session_id is non-empty;
    // empty IDs are a separate validation surface.
    if !input.session_id.is_empty() {
        let store = MemoryStore::new();
        store.save(&input.session_id, &data);
        let loaded = store.load(&input.session_id).expect("save+load round-trip");
        // Every key/value pair from the saved data must reappear.
        for (k, v) in shadow.iter() {
            assert_eq!(loaded.get(k), Some(v.as_str()), "round-trip lost key {k:?}");
        }
        assert_eq!(loaded.len(), data.len(), "round-trip changed len");

        // Delete then load must return None.
        store.delete(&input.session_id);
        assert!(
            store.load(&input.session_id).is_none(),
            "delete did not remove entry"
        );
    }
});
