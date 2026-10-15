//! Targeted authority removal without abandoning the service's owned work.
//!
//! Revocation and retirement are separate: retain every join and local outcome,
//! then retire idle sinks explicitly. A started commit may still complete while
//! cancellation drains. No new connection may route to a revoked certificate,
//! including a handshake that already passed TLS verification.

use super::{JobKind, NativeClientCertificateId, ResumableService};
use crate::types::CancelReason;
use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

/// Maximum distinct client revocations retained for one service lifetime.
/// Revocations are never evicted to admit another identity.
pub const MAX_REVOKED_RESUME_CLIENTS: usize = 1024;

/// Synchronous authority change, not evidence of task or application completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "collect affected child results and retire their idle sinks"]
pub struct ResumeClientRevocation {
    /// False when this certificate was already revoked; the operation is idempotent.
    pub newly_revoked: bool,
    /// Routed workers signalled, including uncollected terminal results. Their
    /// actual cancellation, commit, or success results still come from next/drain.
    pub signalled_connections: usize,
    /// Active and idle session owners retained for this client. No sink is
    /// destroyed and no storage or resident allowance is refunded by revocation.
    pub retained_sessions: usize,
}

/// The requested revocation was not added. Existing revocations remain intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResumeRevokeError {
    /// The fixed lifetime revocation budget is full; stop admission instead of
    /// treating this refusal as successful revocation.
    #[error("shared resume client revocation capacity exhausted")]
    Capacity,
    /// The service has already released all children and admission ownership.
    #[error("shared resume service is fully drained")]
    Drained,
}

#[derive(Default)]
pub(super) struct Revocations(BTreeSet<NativeClientCertificateId>);

impl Revocations {
    fn insert(&mut self, client: NativeClientCertificateId) -> Result<bool, ResumeRevokeError> {
        if self.0.contains(&client) {
            return Ok(false);
        }
        if self.0.len() == MAX_REVOKED_RESUME_CLIENTS {
            return Err(ResumeRevokeError::Capacity);
        }
        Ok(self.0.insert(client))
    }
}

impl<W> ResumableService<W> {
    /// Permanently revoke this full client certificate in this service instance.
    ///
    /// The deny decision is installed before signalling any owned worker. Every
    /// subsequent route is refused before key admission, sink creation, or
    /// receipt restoration, even if TLS verification finished earlier. Other
    /// certificates, the listening socket, and their workers are unaffected.
    ///
    /// Cancellation is cooperative, not rollback or forced preemption. A started
    /// sink operation/commit may finish; collect its canonical result through
    /// `next`, `next_restoring`, or `drain_next`. No result is consumed here and
    /// no sink, publication receipt, file, or refusal tombstone is discarded.
    /// Call `retire` on each affected idle session after observing its snapshot.
    ///
    /// This does not change shared TLS trust or another receiver's policy. Also
    /// remove the certificate with `NativeClientAuthorization::replace_allowed`
    /// to refuse future TLS handshakes. Persist and reapply operator revocation
    /// policy when restarting: this bounded deny set is memory-only.
    ///
    /// Duplicate calls do not change the first cancellation attribution. A new
    /// identity beyond the lifetime bound fails without evicting an earlier one.
    /// Ordinary unwinding cancellation callbacks are fanned out before rethrowing
    /// the first panic; the admission denial is already in effect at that point.
    pub fn revoke_client(
        &mut self,
        client: NativeClientCertificateId,
        reason: CancelReason,
    ) -> Result<ResumeClientRevocation, ResumeRevokeError> {
        if self.is_drained() && !self.is_client_revoked(&client) {
            return Err(ResumeRevokeError::Drained);
        }
        let newly_revoked = self.revocations.insert(client)?;
        let retained_sessions = self.clients.get(&client).copied().unwrap_or(0);
        let mut signalled_connections = 0;
        let mut first_panic = None;
        if newly_revoked {
            for job in &self.jobs {
                if let JobKind::Transfer { key, task } = &job.kind {
                    if key.client == client {
                        signalled_connections += 1;
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            task.abort_with_reason(reason.clone());
                        }));
                        if first_panic.is_none() {
                            first_panic = result.err();
                        }
                    }
                }
            }
        }
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
        Ok(ResumeClientRevocation {
            newly_revoked,
            signalled_connections,
            retained_sessions,
        })
    }

    /// Whether this service will refuse every nonce for the exact certificate.
    /// This remains true after retirement and final drain; it is not TLS state.
    #[must_use]
    pub fn is_client_revoked(&self, client: &NativeClientCertificateId) -> bool {
        self.revocations.0.contains(client)
    }

    /// Lifetime retained client denials, independent of session/key capacity.
    #[must_use]
    pub fn revoked_clients(&self) -> usize {
        self.revocations.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(number: u32) -> NativeClientCertificateId {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&number.to_be_bytes());
        NativeClientCertificateId::from_sha256(bytes)
    }

    #[test]
    fn revocations_are_monotonic_bounded_and_duplicates_cost_no_capacity() {
        let mut denied = Revocations::default();
        for number in 0..MAX_REVOKED_RESUME_CLIENTS as u32 {
            assert_eq!(denied.insert(id(number)), Ok(true));
            assert_eq!(denied.insert(id(number)), Ok(false));
        }
        assert_eq!(denied.insert(id(1024)), Err(ResumeRevokeError::Capacity));
        assert_eq!(denied.0.len(), MAX_REVOKED_RESUME_CLIENTS);
        for number in 0..MAX_REVOKED_RESUME_CLIENTS as u32 {
            assert!(denied.0.contains(&id(number)));
            assert_eq!(denied.insert(id(number)), Ok(false));
        }
        assert!(!denied.0.contains(&id(1024)));
    }
}
