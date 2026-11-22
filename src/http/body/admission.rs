//! Shared admission for buffered request-body payload reservations.
//!
//! Protocols choose when a validated framing length becomes a reservation.
//! The token can then move into the actual request owner without coupling
//! this accounting to a particular listener or public request representation.

use crate::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

#[derive(Debug, Default)]
pub(crate) struct BodyBudget {
    /// Zero means no configured aggregate limit.
    limit: AtomicUsize,
    reserved: AtomicUsize,
    refusals: AtomicU64,
}

impl BodyBudget {
    pub(crate) fn set_limit(&self, limit: NonZeroUsize) {
        self.limit.store(limit.get(), Ordering::Relaxed);
    }

    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }

    pub(crate) fn refusals(&self) -> u64 {
        self.refusals.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub(crate) struct BodyReservation {
    budget: Arc<BodyBudget>,
    bytes: usize,
}

impl BodyReservation {
    pub(crate) fn new(budget: Arc<BodyBudget>) -> Self {
        Self { budget, bytes: 0 }
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn try_grow(&mut self, additional: usize) -> Result<(), BodyBudgetExceeded> {
        if additional == 0 {
            return Ok(());
        }
        let limit = self.budget.limit.load(Ordering::Relaxed);
        self.budget
            .reserved
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(additional)
                    .filter(|&next| limit == 0 || next <= limit)
            })
            .map_err(|_| {
                self.budget.refusals.fetch_add(1, Ordering::Relaxed);
                BodyBudgetExceeded
            })?;
        // This reservation is part of the checked shared total, so its own
        // sum cannot overflow after the successful atomic update.
        self.bytes += additional;
        Ok(())
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        if self.bytes != 0 {
            let previous = self.budget.reserved.fetch_sub(self.bytes, Ordering::AcqRel);
            debug_assert!(previous >= self.bytes, "request-body reservation underflow");
        }
    }
}

/// A private error source keeps public protocol error enums compatible.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BodyBudgetExceeded;

impl fmt::Display for BodyBudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("listener request-body admission capacity exhausted")
    }
}

impl std::error::Error for BodyBudgetExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_reservation_refusal_preserves_credit_and_release_reuses_it() {
        let budget = Arc::new(BodyBudget::default());
        budget.set_limit(NonZeroUsize::new(8).unwrap());
        let mut first = BodyReservation::new(Arc::clone(&budget));
        let mut second = BodyReservation::new(Arc::clone(&budget));
        first.try_grow(6).unwrap();
        second.try_grow(2).unwrap();
        assert!(second.try_grow(1).is_err());
        assert_eq!(second.bytes(), 2);
        assert_eq!(budget.reserved_bytes(), 8);
        assert_eq!(budget.refusals(), 1);
        second.try_grow(0).unwrap();
        assert_eq!(budget.refusals(), 1);
        drop(second);
        first.try_grow(2).unwrap();
        assert_eq!(budget.reserved_bytes(), 8);
        drop(first);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn unlimited_reservations_still_refuse_arithmetic_overflow() {
        let budget = Arc::new(BodyBudget::default());
        let mut reservation = BodyReservation::new(Arc::clone(&budget));
        reservation.try_grow(usize::MAX).unwrap();
        assert!(reservation.try_grow(1).is_err());
        assert_eq!(reservation.bytes(), usize::MAX);
        assert_eq!(budget.reserved_bytes(), usize::MAX);
        assert_eq!(budget.refusals(), 1);
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
