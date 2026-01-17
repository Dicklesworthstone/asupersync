//! Platform-specific networking primitives.
//!
//! This module will contain io_uring/epoll/kqueue/iocp implementations in Phase 1.
//! For Phase 0, we rely on std::net wrappers.

#[cfg(target_os = "linux")]
pub mod linux {}

#[cfg(target_os = "macos")]
pub mod macos {}

#[cfg(target_os = "windows")]
pub mod windows {}
