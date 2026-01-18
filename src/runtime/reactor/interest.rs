//! Interest flags for I/O readiness.

/// Interest flags indicating what I/O events to monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest(u8);

impl Interest {
    /// Interest in readable events.
    pub const READABLE: Self = Self(0b01);
    /// Interest in writable events.
    pub const WRITABLE: Self = Self(0b10);

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
        Self(0b11)
    }

    /// Returns true if readable interest is set.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.0 & Self::READABLE.0 != 0
    }

    /// Returns true if writable interest is set.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.0 & Self::WRITABLE.0 != 0
    }

    /// Combines interests.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Removes interest.
    #[must_use]
    pub fn remove(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}
