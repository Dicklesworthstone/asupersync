//! Structural-depth sentinel for the exact stable 1.99.x qualification lane.
//!
//! The fix commit's 1.99.1 measurements put SpawnRequest at 53-54 after
//! erasure, versus 63-64 with the concrete TLS client. A ceiling of 60
//! distinguishes that regression without raising an application's limit.
//! This is a separate, opt-in crate target: lib.rs retains Rust's default.
//! Do not carry this numeric ceiling to a new compiler without remeasuring.
#![recursion_limit = "60"]
#![forbid(unsafe_code)]

use asupersync::runtime::spawn_mailbox::SpawnRequest;

fn assert_send<T: Send>() {}

fn main() {
    assert_send::<SpawnRequest>();
}
