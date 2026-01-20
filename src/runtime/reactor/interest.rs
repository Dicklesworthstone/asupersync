//! Interest flags for I/O readiness.
//!
//! This module defines the [`Interest`] bitflags for specifying which I/O events
//! to monitor on registered sources.
//!
//! # Platform Mapping
//!
//! | Interest Flag | epoll | kqueue | IOCP |
//! |--------------|-------|--------|------|
//! | READABLE | EPOLLIN | EVFILT_READ | Completion |
//! | WRITABLE | EPOLLOUT | EVFILT_WRITE | Completion |
//! | ERROR | EPOLLERR | EV_ERROR | Completion |
//! | HUP | EPOLLHUP/RDHUP | EV_EOF | Completion |
//! | PRIORITY | EPOLLPRI | N/A | N/A |
//! | ONESHOT | EPOLLONESHOT | EV_ONESHOT | N/A |
//! | EDGE_TRIGGERED | EPOLLET | EV_CLEAR | N/A |
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::Interest;
//!
//! let interest = Interest::READABLE | Interest::WRITABLE;
//! assert!(interest.contains(Interest::READABLE));
//! assert!(interest.is_readable());
//! assert!(interest.is_writable());
//! ```

use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

/// Interest in I/O readiness events.
///
/// Combines multiple interests with the `|` operator.
///
/// # Example
///
/// ```ignore
/// let interest = Interest::READABLE | Interest::WRITABLE;
/// assert!(interest.contains(Interest::READABLE));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Interest(u8);

impl Interest {
    /// No interest (empty set).
    pub const NONE: Self = Self(0);

    /// Interested in read readiness.
    pub const READABLE: Self = Self(1 << 0);

    /// Interested in write readiness.
    pub const WRITABLE: Self = Self(1 << 1);

    /// Interested in error conditions.
    pub const ERROR: Self = Self(1 << 2);

    /// Interested in hang-up (peer closed).
    pub const HUP: Self = Self(1 << 3);

    /// Interested in priority/OOB data (EPOLLPRI).
    pub const PRIORITY: Self = Self(1 << 4);

    /// Request one-shot notification (EPOLLONESHOT).
    /// After firing, must re-arm with modify().
    pub const ONESHOT: Self = Self(1 << 5);

    /// Request edge-triggered mode (EPOLLET).
    /// Event fires on state CHANGE, not while condition persists.
    pub const EDGE_TRIGGERED: Self = Self(1 << 6);

    /// Common combination for sockets.
    pub const SOCKET: Self =
        Self(Self::READABLE.0 | Self::WRITABLE.0 | Self::ERROR.0 | Self::HUP.0);

    /// Returns interest in readable events.
    #[must_use]
    pub const fn readable() -> Self {
        Self::READABLE
    }

    /// Returns interest in writable events.
    #[must_use]
    pub const fn writable() -> Self {
        Self::WRITABLE
    }

    /// Returns interest in both readable and writable events.
    #[must_use]
    pub const fn both() -> Self {
        Self(Self::READABLE.0 | Self::WRITABLE.0)
    }

    /// Create empty interest set.
    #[must_use]
    pub const fn empty() -> Self {
        Self::NONE
    }

    /// Create interest from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    #[must_use]
    pub const fn bits(&self) -> u8 {
        self.0
    }

    /// Check if interest contains all flags in other.
    #[must_use]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Check if interest is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Check if readable interest is set.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        (self.0 & Self::READABLE.0) != 0
    }

    /// Check if writable interest is set.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        (self.0 & Self::WRITABLE.0) != 0
    }

    /// Check if error interest is set.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        (self.0 & Self::ERROR.0) != 0
    }

    /// Check if HUP interest is set.
    #[must_use]
    pub const fn is_hup(&self) -> bool {
        (self.0 & Self::HUP.0) != 0
    }

    /// Check if priority interest is set.
    #[must_use]
    pub const fn is_priority(&self) -> bool {
        (self.0 & Self::PRIORITY.0) != 0
    }

    /// Check if oneshot mode is set.
    #[must_use]
    pub const fn is_oneshot(&self) -> bool {
        (self.0 & Self::ONESHOT.0) != 0
    }

    /// Check if edge-triggered mode is set.
    #[must_use]
    pub const fn is_edge_triggered(&self) -> bool {
        (self.0 & Self::EDGE_TRIGGERED.0) != 0
    }

    /// Combines interests by adding flags.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub const fn add(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Removes interest flags.
    #[must_use]
    pub const fn remove(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Returns a new interest with oneshot mode set.
    #[must_use]
    pub const fn with_oneshot(self) -> Self {
        Self(self.0 | Self::ONESHOT.0)
    }

    /// Returns a new interest with edge-triggered mode set.
    #[must_use]
    pub const fn with_edge_triggered(self) -> Self {
        Self(self.0 | Self::EDGE_TRIGGERED.0)
    }
}

impl BitOr for Interest {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Interest {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for Interest {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Interest {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for Interest {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl std::fmt::Display for Interest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        if self.is_readable() {
            flags.push("READABLE");
        }
        if self.is_writable() {
            flags.push("WRITABLE");
        }
        if self.is_error() {
            flags.push("ERROR");
        }
        if self.is_hup() {
            flags.push("HUP");
        }
        if self.is_priority() {
            flags.push("PRIORITY");
        }
        if self.is_oneshot() {
            flags.push("ONESHOT");
        }
        if self.is_edge_triggered() {
            flags.push("EDGE_TRIGGERED");
        }
        if flags.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", flags.join(" | "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn interest_constants() {
        init_test("interest_constants");
        crate::test_section!("bits");
        crate::assert_with_log!(
            Interest::NONE.bits() == 0,
            "NONE bits",
            0,
            Interest::NONE.bits()
        );
        crate::assert_with_log!(
            Interest::READABLE.bits() == 1,
            "READABLE bits",
            1,
            Interest::READABLE.bits()
        );
        crate::assert_with_log!(
            Interest::WRITABLE.bits() == 2,
            "WRITABLE bits",
            2,
            Interest::WRITABLE.bits()
        );
        crate::assert_with_log!(
            Interest::ERROR.bits() == 4,
            "ERROR bits",
            4,
            Interest::ERROR.bits()
        );
        crate::assert_with_log!(
            Interest::HUP.bits() == 8,
            "HUP bits",
            8,
            Interest::HUP.bits()
        );
        crate::assert_with_log!(
            Interest::PRIORITY.bits() == 16,
            "PRIORITY bits",
            16,
            Interest::PRIORITY.bits()
        );
        crate::assert_with_log!(
            Interest::ONESHOT.bits() == 32,
            "ONESHOT bits",
            32,
            Interest::ONESHOT.bits()
        );
        crate::assert_with_log!(
            Interest::EDGE_TRIGGERED.bits() == 64,
            "EDGE_TRIGGERED bits",
            64,
            Interest::EDGE_TRIGGERED.bits()
        );
        crate::test_complete!("interest_constants");
    }

    #[test]
    fn interest_combining() {
        init_test("interest_combining");
        let interest = Interest::READABLE | Interest::WRITABLE;
        crate::assert_with_log!(
            interest.is_readable(),
            "combined interest is readable",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "combined interest is writable",
            true,
            interest.is_writable()
        );
        crate::assert_with_log!(
            !interest.is_error(),
            "combined interest excludes error",
            false,
            interest.is_error()
        );
        crate::assert_with_log!(
            interest == Interest::both(),
            "combined interest equals both()",
            Interest::both(),
            interest
        );
        crate::test_complete!("interest_combining");
    }

    #[test]
    fn interest_contains() {
        init_test("interest_contains");
        let interest = Interest::READABLE | Interest::WRITABLE | Interest::ERROR;
        crate::assert_with_log!(
            interest.contains(Interest::READABLE),
            "contains READABLE",
            true,
            interest.contains(Interest::READABLE)
        );
        crate::assert_with_log!(
            interest.contains(Interest::WRITABLE),
            "contains WRITABLE",
            true,
            interest.contains(Interest::WRITABLE)
        );
        crate::assert_with_log!(
            interest.contains(Interest::ERROR),
            "contains ERROR",
            true,
            interest.contains(Interest::ERROR)
        );
        crate::assert_with_log!(
            interest.contains(Interest::both()),
            "contains both()",
            true,
            interest.contains(Interest::both())
        );
        crate::assert_with_log!(
            !interest.contains(Interest::HUP),
            "does not contain HUP",
            false,
            interest.contains(Interest::HUP)
        );
        crate::test_complete!("interest_contains");
    }

    #[test]
    fn interest_add_remove() {
        init_test("interest_add_remove");
        let mut interest = Interest::READABLE;
        interest = interest.add(Interest::WRITABLE);
        crate::assert_with_log!(
            interest.is_readable(),
            "readable retained after add",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "writable set after add",
            true,
            interest.is_writable()
        );

        interest = interest.remove(Interest::READABLE);
        crate::assert_with_log!(
            !interest.is_readable(),
            "readable removed",
            false,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "writable remains",
            true,
            interest.is_writable()
        );
        crate::test_complete!("interest_add_remove");
    }

    #[test]
    fn interest_bit_operators() {
        init_test("interest_bit_operators");
        // BitOr
        let interest = Interest::READABLE | Interest::WRITABLE;
        crate::assert_with_log!(interest.bits() == 3, "bitor bits", 3, interest.bits());

        // BitAnd
        let masked = interest & Interest::READABLE;
        crate::assert_with_log!(
            masked.is_readable(),
            "bitand keeps readable",
            true,
            masked.is_readable()
        );
        crate::assert_with_log!(
            !masked.is_writable(),
            "bitand clears writable",
            false,
            masked.is_writable()
        );

        // BitOrAssign
        let mut interest = Interest::READABLE;
        interest |= Interest::WRITABLE;
        crate::assert_with_log!(
            interest.is_writable(),
            "bitorassign sets writable",
            true,
            interest.is_writable()
        );

        // BitAndAssign
        interest &= Interest::READABLE;
        crate::assert_with_log!(
            !interest.is_writable(),
            "bitandassign clears writable",
            false,
            interest.is_writable()
        );

        // Not
        let not_readable = !Interest::READABLE;
        crate::assert_with_log!(
            !not_readable.is_readable(),
            "not clears readable",
            false,
            not_readable.is_readable()
        );
        crate::test_complete!("interest_bit_operators");
    }

    #[test]
    fn interest_socket() {
        init_test("interest_socket");
        let socket = Interest::SOCKET;
        crate::assert_with_log!(
            socket.is_readable(),
            "socket readable",
            true,
            socket.is_readable()
        );
        crate::assert_with_log!(
            socket.is_writable(),
            "socket writable",
            true,
            socket.is_writable()
        );
        crate::assert_with_log!(socket.is_error(), "socket error", true, socket.is_error());
        crate::assert_with_log!(socket.is_hup(), "socket hup", true, socket.is_hup());
        crate::assert_with_log!(
            !socket.is_priority(),
            "socket priority unset",
            false,
            socket.is_priority()
        );
        crate::test_complete!("interest_socket");
    }

    #[test]
    fn interest_modes() {
        init_test("interest_modes");
        let interest = Interest::READABLE.with_oneshot().with_edge_triggered();
        crate::assert_with_log!(
            interest.is_readable(),
            "modes keep readable",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_oneshot(),
            "oneshot set",
            true,
            interest.is_oneshot()
        );
        crate::assert_with_log!(
            interest.is_edge_triggered(),
            "edge-triggered set",
            true,
            interest.is_edge_triggered()
        );
        crate::test_complete!("interest_modes");
    }

    #[test]
    fn interest_from_bits() {
        init_test("interest_from_bits");
        let interest = Interest::from_bits(0b011);
        crate::assert_with_log!(
            interest.is_readable(),
            "from_bits readable",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "from_bits writable",
            true,
            interest.is_writable()
        );
        crate::assert_with_log!(
            !interest.is_error(),
            "from_bits excludes error",
            false,
            interest.is_error()
        );
        crate::test_complete!("interest_from_bits");
    }

    #[test]
    fn interest_empty() {
        init_test("interest_empty");
        crate::assert_with_log!(
            Interest::NONE.is_empty(),
            "NONE is empty",
            true,
            Interest::NONE.is_empty()
        );
        crate::assert_with_log!(
            Interest::empty().is_empty(),
            "empty is empty",
            true,
            Interest::empty().is_empty()
        );
        crate::assert_with_log!(
            !Interest::READABLE.is_empty(),
            "READABLE not empty",
            false,
            Interest::READABLE.is_empty()
        );
        crate::test_complete!("interest_empty");
    }

    #[test]
    fn interest_default() {
        init_test("interest_default");
        crate::assert_with_log!(
            Interest::default() == Interest::NONE,
            "default is NONE",
            Interest::NONE,
            Interest::default()
        );
        crate::test_complete!("interest_default");
    }

    #[test]
    fn interest_display() {
        init_test("interest_display");
        let none_display = format!("{}", Interest::NONE);
        crate::assert_with_log!(none_display == "NONE", "NONE display", "NONE", none_display);
        let readable_display = format!("{}", Interest::READABLE);
        crate::assert_with_log!(
            readable_display == "READABLE",
            "READABLE display",
            "READABLE",
            readable_display
        );
        let both_display = format!("{}", Interest::READABLE | Interest::WRITABLE);
        crate::assert_with_log!(
            both_display == "READABLE | WRITABLE",
            "combined display",
            "READABLE | WRITABLE",
            both_display
        );
        crate::test_complete!("interest_display");
    }

    #[test]
    fn interest_helpers() {
        init_test("interest_helpers");
        crate::assert_with_log!(
            Interest::readable() == Interest::READABLE,
            "readable helper",
            Interest::READABLE,
            Interest::readable()
        );
        crate::assert_with_log!(
            Interest::writable() == Interest::WRITABLE,
            "writable helper",
            Interest::WRITABLE,
            Interest::writable()
        );
        crate::assert_with_log!(
            Interest::both() == (Interest::READABLE | Interest::WRITABLE),
            "both helper",
            Interest::READABLE | Interest::WRITABLE,
            Interest::both()
        );
        crate::test_complete!("interest_helpers");
    }
}
