//! Two-phase effect patterns for network operations.
//!
//! This module provides adapters and patterns for making network operations
//! follow the two-phase reserve/commit pattern required by the asupersync runtime.
//!
//! # Pattern Implementation
//!
//! Network streams should implement the `TwoPhaseNetworkSend` trait to ensure
//! cancel-safe operation:
//!
//! ```ignore
//! use asupersync::runtime::effects::SendPermit;
//!
//! trait TwoPhaseNetworkSend {
//!     type Error;
//!
//!     async fn reserve_send(&mut self) -> Result<SendPermit<Self::Error>, Self::Error>;
//! }
//! ```
//!
//! # Migration Guide
//!
//! Network operations that currently use direct send patterns should be migrated:
//!
//! ```ignore
//! // BEFORE: Direct send (violates runtime invariant)
//! impl AtpH3Stream {
//!     pub fn send(&mut self, data: &[u8]) -> Result<(), AtpH3Error> {
//!         // Direct queue operation - NOT cancel-safe
//!         self.send_queue.push_back(data.to_vec());
//!         Ok(())
//!     }
//! }
//!
//! // AFTER: Two-phase send (follows runtime invariant)
//! impl AtpH3Stream {
//!     pub async fn reserve_send(&mut self) -> Result<SendPermit<AtpH3Error>, AtpH3Error> {
//!         // Check if we can send and reserve space
//!         if !self.can_send() {
//!             return Err(AtpH3Error::Stream(format!(
//!                 "Cannot send on stream {} in state {:?}",
//!                 self.stream_id, self.state
//!             )));
//!         }
//!
//!         if self.send_queue.len() >= self.send_queue_high_water {
//!             return Err(AtpH3Error::Stream(
//!                 "Send queue full - apply backpressure".to_string(),
//!             ));
//!         }
//!
//!         // Reserve space by incrementing a reserved count
//!         self.reserved_sends += 1;
//!
//!         let stream_id = self.stream_id;
//!         let send_queue = &mut self.send_queue;
//!         let reserved_sends = &mut self.reserved_sends;
//!         let max_buffer_size = self.max_buffer_size;
//!
//!         Ok(SendPermit::new(
//!             move |data: &[u8]| {
//!                 // Commit: add to send queue
//!                 if data.len() > max_buffer_size {
//!                     return Err(AtpH3Error::Stream(format!(
//!                         "Data size {} exceeds maximum buffer size {}",
//!                         data.len(),
//!                         max_buffer_size
//!                     )));
//!                 }
//!                 send_queue.push_back(data.to_vec());
//!                 *reserved_sends -= 1;
//!                 Ok(())
//!             },
//!             move || {
//!                 // Abort: release reservation
//!                 *reserved_sends -= 1;
//!             }
//!         ))
//!     }
//! }
//! ```

use super::SendPermit;

/// Trait for network streams that support two-phase send operations.
#[allow(async_fn_in_trait)]
pub trait TwoPhaseNetworkSend {
    /// The error type for send operations.
    type Error;

    /// Reserve space for a send operation.
    ///
    /// This returns a permit that can be used to commit data or abort the operation.
    /// The reservation ensures that:
    /// - Space is available in the send queue
    /// - The stream is in a valid state for sending
    /// - Resources are tracked for proper cleanup on cancellation
    async fn reserve_send(&mut self) -> Result<SendPermit<Self::Error>, Self::Error>;
}

/// Trait for streams that use the legacy direct-send pattern.
///
/// This trait identifies streams that need to be migrated to the two-phase pattern.
/// Implementing this trait is a temporary step during migration.
pub trait DirectSend {
    /// The error type for send operations.
    type Error;

    /// Send data directly (legacy pattern - should be migrated).
    ///
    /// **Warning**: This method violates the asupersync runtime invariant and
    /// should be replaced with the two-phase `reserve_send()` pattern.
    fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Return an error indicating capacity is exceeded.
    fn capacity_error(&self) -> Self::Error;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStream {
        sent_data: Vec<Vec<u8>>,
        can_send: bool,
    }

    impl DirectSend for TestStream {
        type Error = String;

        fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            if !self.can_send {
                return Err("Cannot send".to_string());
            }
            self.sent_data.push(data.to_vec());
            Ok(())
        }

        fn capacity_error(&self) -> Self::Error {
            "Capacity exceeded".to_string()
        }
    }

    #[test]
    fn test_direct_send_trait() {
        let mut stream = TestStream {
            sent_data: Vec::new(),
            can_send: true,
        };

        assert!(stream.send(b"test").is_ok());
        assert_eq!(stream.sent_data.len(), 1);
        assert_eq!(stream.sent_data[0], b"test");
    }
}
