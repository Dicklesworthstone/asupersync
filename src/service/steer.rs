//! Steer combinator: routes requests to one of several services.
//!
//! [`Steer`] dispatches each request to one of N inner services based on
//! a user-supplied routing function. This enables content-based routing,
//! A/B testing, and service selection patterns.

use super::Service;
use std::fmt;
use std::task::{Context, Poll};

// ─── Steer ────────────────────────────────────────────────────────────────

/// A service that routes requests to one of several inner services.
///
/// The `picker` function is called with the request to select which
/// backend receives it (by index into the `services` vec).
pub struct Steer<S, F> {
    services: Vec<S>,
    picker: F,
}

impl<S, F> Steer<S, F> {
    /// Create a new steer combinator.
    ///
    /// `picker` is called with a reference to the request and must return
    /// an index into `services`.
    ///
    /// # Panics
    ///
    /// Panics if `services` is empty.
    #[must_use]
    pub fn new(services: Vec<S>, picker: F) -> Self {
        assert!(!services.is_empty(), "steer requires at least one service");
        Self { services, picker }
    }

    /// Get the number of inner services.
    #[must_use]
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Returns false (at least one service is always present).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Get a reference to the inner services.
    #[must_use]
    pub fn services(&self) -> &[S] {
        &self.services
    }

    /// Get a mutable reference to the inner services.
    pub fn services_mut(&mut self) -> &mut [S] {
        &mut self.services
    }
}

impl<S: fmt::Debug, F> fmt::Debug for Steer<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Steer")
            .field("services", &self.services)
            .finish_non_exhaustive()
    }
}

impl<S, F, Request> Service<Request> for Steer<S, F>
where
    S: Service<Request>,
    F: Fn(&Request) -> usize,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // All services must be ready.
        for svc in &mut self.services {
            match svc.poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let idx = (self.picker)(&req) % self.services.len();
        self.services[idx].call(req)
    }
}

// ─── SteerError ───────────────────────────────────────────────────────────

/// Error wrapping for steer operations.
#[derive(Debug)]
pub enum SteerError<E> {
    /// Inner service error.
    Inner(E),
    /// No services available.
    NoServices,
}

impl<E: fmt::Display> fmt::Display for SteerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "steer service error: {e}"),
            Self::NoServices => write!(f, "no services available"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SteerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::NoServices => None,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // Mock services.
    #[derive(Debug, Clone)]
    struct IdService {
        id: usize,
    }

    #[test]
    fn steer_new() {
        init_test("steer_new");
        let svcs = vec![IdService { id: 0 }, IdService { id: 1 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        assert_eq!(steer.len(), 2);
        assert!(!steer.is_empty());
        crate::test_complete!("steer_new");
    }

    #[test]
    #[should_panic(expected = "steer requires at least one service")]
    fn steer_empty_panics() {
        let svcs: Vec<IdService> = vec![];
        let _ = Steer::new(svcs, |_req: &()| 0);
    }

    #[test]
    fn steer_services_ref() {
        let svcs = vec![IdService { id: 10 }, IdService { id: 20 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        assert_eq!(steer.services().len(), 2);
        assert_eq!(steer.services()[0].id, 10);
    }

    #[test]
    fn steer_services_mut() {
        let svcs = vec![IdService { id: 10 }];
        let mut steer = Steer::new(svcs, |_req: &()| 0);
        steer.services_mut()[0].id = 99;
        assert_eq!(steer.services()[0].id, 99);
    }

    #[test]
    fn steer_debug() {
        let svcs = vec![IdService { id: 1 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        let dbg = format!("{steer:?}");
        assert!(dbg.contains("Steer"));
    }

    #[test]
    fn steer_picker_routes() {
        init_test("steer_picker_routes");
        // Route even numbers to service 0, odd to service 1.
        let svcs = vec![IdService { id: 0 }, IdService { id: 1 }];
        let steer = Steer::new(svcs, |req: &usize| req % 2);
        // Verify the picker logic.
        let picker = &steer.picker;
        assert_eq!(picker(&0), 0);
        assert_eq!(picker(&1), 1);
        assert_eq!(picker(&2), 0);
        assert_eq!(picker(&3), 1);
        crate::test_complete!("steer_picker_routes");
    }

    #[test]
    fn steer_picker_wraps() {
        // Index beyond services.len() should wrap.
        let svcs = vec![IdService { id: 0 }, IdService { id: 1 }];
        let steer = Steer::new(svcs, |(): &()| 5);
        // 5 % 2 == 1, so service 1 would be selected.
        let idx = (steer.picker)(&()) % steer.len();
        assert_eq!(idx, 1);
    }

    // ================================================================
    // SteerError
    // ================================================================

    #[test]
    fn steer_error_inner_display() {
        let err: SteerError<std::io::Error> = SteerError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("steer service error"));
    }

    #[test]
    fn steer_error_no_services_display() {
        let err: SteerError<std::io::Error> = SteerError::NoServices;
        assert!(format!("{err}").contains("no services available"));
    }

    #[test]
    fn steer_error_source() {
        use std::error::Error;
        let err: SteerError<std::io::Error> = SteerError::Inner(std::io::Error::other("fail"));
        assert!(err.source().is_some());

        let err2: SteerError<std::io::Error> = SteerError::NoServices;
        assert!(err2.source().is_none());
    }

    #[test]
    fn steer_error_debug() {
        let err: SteerError<std::io::Error> = SteerError::NoServices;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NoServices"));
    }
}
