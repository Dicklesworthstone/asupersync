//! Targeted authority removal without abandoning the service's owned work.
//!
//! Certificate denials cover every nonce; session denials bind one exact nonce
//! to its authenticated certificate. Both are retained separately from session
//! retirement. A started commit may still complete while cancellation drains.
//! Persist and reapply operator policy across process restarts.

use super::{
    JobKind, NativeClientCertificateId, ResumableService, ResumeSessionKey, ResumeSessionStatus,
};
use crate::types::CancelReason;
use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

/// Maximum distinct certificate denials retained for one service lifetime.
/// Denials are never evicted to admit another identity.
pub const MAX_REVOKED_RESUME_CLIENTS: usize = 1024;
/// Maximum distinct authenticated session denials retained for one service
/// lifetime, independent of resident sessions and certificate denials.
pub const MAX_REVOKED_RESUME_SESSIONS: usize = 1024;

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

/// Authority change for one exact certificate/nonce pair, without consuming its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "collect the affected child result and retire its idle sink"]
pub struct ResumeSessionRevocation {
    /// False when this exact key was already denied.
    pub newly_revoked: bool,
    /// Routed workers signalled. At most one worker can own this exact key.
    pub signalled_connections: usize,
    /// Active or idle owners retained for this key, either zero or one.
    pub retained_sessions: usize,
}

/// One atomically admitted set of certificate and session denials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "denial admission is not a drain or rollback receipt"]
pub struct ResumeRevocationReport {
    /// Previously unseen certificate denials added by this call.
    pub newly_revoked_clients: usize,
    /// Previously unseen exact session denials added by this call.
    pub newly_revoked_sessions: usize,
    /// Routed workers covered by newly installed denials, counted once.
    pub signalled_connections: usize,
    /// Active/idle owners covered by the requested policy, counted once.
    pub retained_sessions: usize,
}

/// The requested revocation was not added. Existing revocations remain intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResumeRevokeError {
    /// A fixed lifetime denial budget or bounded policy input is full.
    #[error("shared resume client revocation capacity exhausted")]
    Capacity,
    /// The service has already released all children and admission ownership.
    #[error("shared resume service is fully drained")]
    Drained,
}

#[derive(Default)]
pub(super) struct Revocations(
    BTreeSet<NativeClientCertificateId>,
    BTreeSet<ResumeSessionKey>,
);

struct Prepared {
    clients: BTreeSet<NativeClientCertificateId>,
    sessions: BTreeSet<ResumeSessionKey>,
}

impl Revocations {
    #[cfg(test)]
    fn insert(&mut self, client: NativeClientCertificateId) -> Result<bool, ResumeRevokeError> {
        let prepared = self.prepare(&[client], &[])?;
        Ok(self.0.insert(client) && !prepared.clients.is_empty())
    }

    fn prepare(
        &self,
        clients: &[NativeClientCertificateId],
        sessions: &[ResumeSessionKey],
    ) -> Result<Prepared, ResumeRevokeError> {
        // Bound even a caller-supplied batch full of duplicate entries. The
        // caller retains its input storage; no unbounded temporary set is built.
        if clients.len() > MAX_REVOKED_RESUME_CLIENTS || sessions.len() > MAX_REVOKED_RESUME_SESSIONS
        {
            return Err(ResumeRevokeError::Capacity);
        }
        let clients: BTreeSet<_> = clients
            .iter()
            .copied()
            .filter(|client| !self.0.contains(client))
            .collect();
        let sessions: BTreeSet<_> = sessions
            .iter()
            .copied()
            .filter(|key| !self.1.contains(key))
            .collect();
        if clients.len() > MAX_REVOKED_RESUME_CLIENTS - self.0.len()
            || sessions.len() > MAX_REVOKED_RESUME_SESSIONS - self.1.len()
        {
            return Err(ResumeRevokeError::Capacity);
        }
        Ok(Prepared { clients, sessions })
    }
}

impl<W> ResumableService<W> {
    fn prepare_revocations(
        &self,
        clients: &[NativeClientCertificateId],
        sessions: &[ResumeSessionKey],
    ) -> Result<Prepared, ResumeRevokeError> {
        let prepared = self.revocations.prepare(clients, sessions)?;
        if self.is_drained() && (!prepared.clients.is_empty() || !prepared.sessions.is_empty()) {
            return Err(ResumeRevokeError::Drained);
        }
        Ok(prepared)
    }

    /// Check a whole prospective policy without changing admission or waking
    /// any worker. Each input slice is bounded by its corresponding MAX constant.
    /// Duplicates within a bounded batch consume no additional denial capacity.
    ///
    /// This is useful before tightening an external TLS allowlist. The caller
    /// must retain exclusive service access until `apply_revocations`; that
    /// operation repeats the check before making any change.
    pub fn check_revocations(
        &self,
        clients: &[NativeClientCertificateId],
        sessions: &[ResumeSessionKey],
    ) -> Result<(), ResumeRevokeError> {
        self.prepare_revocations(clients, sessions).map(|_| ())
    }

    /// Atomically admit a bounded policy, then signal its newly affected workers.
    ///
    /// Capacity/drained refusal changes nothing. Every requested denial is
    /// installed before the first cancellation callback runs, with no await or
    /// routing opportunity between those operations. A session key includes the
    /// authenticated client certificate; its nonce alone grants no authority.
    ///
    /// Cancellation is cooperative, not rollback. A started commit or an
    /// uncollected success remains an actual commit/success. Collect canonical
    /// results through next/drain_next; no result, sink, storage charge or
    /// refusal tombstone is consumed here. Unwinding cancellation callbacks are
    /// fanned out before the first panic is rethrown.
    pub fn apply_revocations(
        &mut self,
        clients: &[NativeClientCertificateId],
        sessions: &[ResumeSessionKey],
        reason: CancelReason,
    ) -> Result<ResumeRevocationReport, ResumeRevokeError> {
        let prepared = self.prepare_revocations(clients, sessions)?;
        let requested_clients: BTreeSet<_> = clients.iter().copied().collect();
        let requested_sessions: BTreeSet<_> = sessions.iter().copied().collect();
        let retained_sessions = self
            .entries
            .iter()
            .filter(|(key, entry)| {
                entry.status != ResumeSessionStatus::Retired
                    && (requested_clients.contains(&key.client) || requested_sessions.contains(*key))
            })
            .count();
        let newly_revoked_clients = prepared.clients.len();
        let newly_revoked_sessions = prepared.sessions.len();
        self.revocations.0.extend(prepared.clients.iter().copied());
        self.revocations.1.extend(prepared.sessions.iter().copied());

        let mut signalled_connections = 0;
        let mut first_panic = None;
        for job in &self.jobs {
            if let JobKind::Transfer { key, task } = &job.kind {
                if prepared.clients.contains(&key.client) || prepared.sessions.contains(key) {
                    signalled_connections += 1;
                    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
                        task.abort_with_reason(reason.clone());
                    })) {
                        if first_panic.is_none() {
                            first_panic = Some(payload);
                        } else {
                            // A secondary panic payload can have a panicking
                            // destructor; do not let it interrupt the fan-out.
                            std::mem::forget(payload);
                        }
                    }
                }
            }
        }
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
        Ok(ResumeRevocationReport {
            newly_revoked_clients,
            newly_revoked_sessions,
            signalled_connections,
            retained_sessions,
        })
    }

    /// Permanently revoke every nonce for this certificate in this service.
    ///
    /// Other certificates are unaffected. Remove the certificate from shared
    /// TLS authority separately to reject future handshakes too. This service
    /// still checks every already-authenticated connection before routing it.
    /// Duplicate calls preserve the first cancellation attribution and signal
    /// no additional workers. Persist and reapply policy after process restart.
    pub fn revoke_client(
        &mut self,
        client: NativeClientCertificateId,
        reason: CancelReason,
    ) -> Result<ResumeClientRevocation, ResumeRevokeError> {
        // Preserve the original single-client refusal precedence.
        if self.is_drained() && !self.is_client_revoked(&client) {
            return Err(ResumeRevokeError::Drained);
        }
        let changed = self.apply_revocations(&[client], &[], reason)?;
        Ok(ResumeClientRevocation {
            newly_revoked: changed.newly_revoked_clients != 0,
            signalled_connections: changed.signalled_connections,
            retained_sessions: changed.retained_sessions,
        })
    }

    /// Permanently deny one exact authenticated certificate/nonce pair.
    ///
    /// Other sessions using the same certificate continue. The denial also
    /// fences an unknown key before its first hello or restored receipt, and
    /// remains after retirement. Duplicate calls do not signal again. This
    /// changes neither shared TLS trust nor another service's policy.
    pub fn revoke_session(
        &mut self,
        key: ResumeSessionKey,
        reason: CancelReason,
    ) -> Result<ResumeSessionRevocation, ResumeRevokeError> {
        let changed = self.apply_revocations(&[], &[key], reason)?;
        Ok(ResumeSessionRevocation {
            newly_revoked: changed.newly_revoked_sessions != 0,
            signalled_connections: changed.signalled_connections,
            retained_sessions: changed.retained_sessions,
        })
    }

    /// Whether this service will refuse every nonce for the exact certificate.
    /// This remains true after retirement and final drain; it is not TLS state.
    #[must_use]
    pub fn is_client_revoked(&self, client: &NativeClientCertificateId) -> bool {
        self.revocations.0.contains(client)
    }

    /// Whether this exact session was denied, independent of a broader client
    /// denial. Admission checks both sets. This remains true after final drain.
    #[must_use]
    pub fn is_session_revoked(&self, key: &ResumeSessionKey) -> bool {
        self.revocations.1.contains(key)
    }

    /// Lifetime retained certificate denials, independent of session/key capacity.
    #[must_use]
    pub fn revoked_clients(&self) -> usize {
        self.revocations.0.len()
    }

    /// Lifetime retained exact session denials, independent of resident capacity.
    #[must_use]
    pub fn revoked_sessions(&self) -> usize {
        self.revocations.1.len()
    }
}

#[cfg(test)]
#[path = "revocation_inline_tests.rs"]
mod tests;
