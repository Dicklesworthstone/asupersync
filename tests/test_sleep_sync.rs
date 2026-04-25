//! Verifies `Sleep` remains `Send + Sync` for cross-thread scheduler usage.

use asupersync::time::Sleep;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn sleep_is_send_and_sync() {
    assert_send_sync::<Sleep>();
}
