Rewrite of src/sync/barrier.rs to be async-aware.

- Replaced blocking `std::sync::Condvar` with `Vec<Waker>`.
- Changed `Barrier::wait` to return `BarrierWaitFuture`.
- Implemented `BarrierWaitFuture` to handle async waiting and cancellation.
- Implemented `Drop` for `BarrierWaitFuture` to ensure correct cleanup on future drop.
- Updated `tests/sync_conformance.rs` and `tests/sync_e2e.rs` to use `block_on` for async barrier calls.
- Verified that existing usages of `std::sync::Barrier` in other tests remain untouched.
