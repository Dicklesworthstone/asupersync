//! Linux reactor aliases.
//!
//! This module keeps a stable path for Linux-specific reactor names while the
//! concrete implementations live in dedicated modules.

pub use super::epoll::EpollReactor;
pub use super::io_uring::IoUringReactor;
