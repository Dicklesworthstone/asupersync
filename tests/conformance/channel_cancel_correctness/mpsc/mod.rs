//! MPSC cancellation conformance scenarios.

pub mod send_cancel_tests;

pub use send_cancel_tests::{MpscSendCancelTest, MpscSendCleanupTest, MpscSendContentionTest};
