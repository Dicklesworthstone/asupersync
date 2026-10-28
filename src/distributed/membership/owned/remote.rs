//! Compose authenticated local membership ownership with checked remote work.
//!
//! Membership's logical-node incarnation controls local admission and settlement.
//! It is not a claim about the peer process's incarnation: transport identity,
//! destination selection and computation grants remain the caller's existing
//! `RemoteCap`/`RemoteRuntime` policy. No route, TLS credential, discovery source,
//! authority decision, or replacement remote capability is created here.

use super::{MembershipWorkError, MembershipWorkReport, OwnedMembershipController};
use crate::cx::Cx;
use crate::distributed::remote_owned::{RemoteRunConfig, RemoteRunError, RemoteRunReport, run_remote};
use crate::remote::{ComputationName, NodeId, RemoteInput};
#[cfg(not(target_arch = "wasm32"))]
use crate::distributed::membership::driver::SwimContact;
#[cfg(not(target_arch = "wasm32"))]
use super::work::MembershipWorkGuard;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

/// Refusal before membership-owned remote work reached its reporting phase.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipRemoteError {
    /// The caller has no usable remote capability; simulated fallback is refused.
    #[error(transparent)]
    Remote(#[from] RemoteRunError),
    /// Authenticated membership, checked lease or child admission refused.
    #[error(transparent)]
    Membership(#[from] MembershipWorkError),
    /// The supplied contact belongs to another logical destination.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("SWIM contact does not match the remote destination")]
    ContactMismatch,
    /// This captured contact epoch ended; recovery requires a fresh token.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("SWIM contact ended before remote admission")]
    ContactEnded,
}

/// Preserve both independent ownership and terminal-result reports.
///
/// A remote Success can race an authority revocation. It remains visible in the
/// nested report but is not authorized success unless [`Self::is_success`] is
/// true. Likewise, closing the membership subtree alone is not proof of remote
/// success or remote quiescence after an ambiguous transport failure.
#[derive(Debug)]
pub struct MembershipRemoteReport {
    /// Membership stop cause, checked lease settlement, outer child close, and
    /// the exact remote runner result, including its own child close receipt.
    pub work: MembershipWorkReport<Result<RemoteRunReport, RemoteRunError>>,
}

impl MembershipRemoteReport {
    /// Accept only committed membership ownership AND successful, drained remote
    /// work. The caller still interprets opaque application success bytes.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.work.is_success()
            && matches!(&self.work.task, Ok(Ok(remote)) if remote.is_success())
    }
}

impl OwnedMembershipController {
    /// Run a named computation while holding an authenticated membership lease.
    ///
    /// The caller's existing remote capability, destination policy, credentials,
    /// computation grants and remote budget are preserved. Missing capability or
    /// runtime refuses before membership admission; no simulated fallback runs.
    /// The exact `node`/`incarnation` must have an accepted Alive statement.
    /// Suspect refuses new work without revoking already admitted work.
    ///
    /// Dead, Left, supersession, expiry and controller closure stop the outer
    /// membership child. Its remote runner then cancels and drains its own proxy
    /// child through the existing `RemoteHandle::close` protocol. A native V3
    /// runtime attempts same-connection cancellation and collects the drained
    /// terminal response. Transport failures remain failures, not drain proof.
    /// Unrelated work and the calling context are not cancelled.
    ///
    /// `config.timeout` starts at membership admission, before opening either
    /// child. The same timeout also bounds the inner runner; its later admission
    /// cannot extend the outer lease. `config.child` constrains both children.
    /// These deadlines initiate cancellation, not a universal wall-clock bound
    /// on cleanup. Continue polling through both closes to receive their reports.
    /// Dropping the future requests child close; the runtime retains its subtree.
    ///
    /// This composes local authority with actual remote ownership. It does not
    /// authenticate a peer's process incarnation, create SWIM-driven authority,
    /// update routes, renew the membership lease, or retry an invocation.
    pub async fn run_remote(
        &self,
        cx: &Cx,
        node: NodeId,
        incarnation: u64,
        computation: ComputationName,
        input: RemoteInput,
        config: RemoteRunConfig,
    ) -> Result<MembershipRemoteReport, MembershipRemoteError> {
        if cx.is_cancel_requested() {
            return Err(RemoteRunError::Cancelled.into());
        }
        let cap = cx.remote().ok_or(RemoteRunError::NoCapability)?;
        if cap.runtime().is_none() {
            return Err(RemoteRunError::NoRemoteRuntime.into());
        }
        let destination = node.clone();
        let work = self
            .run_scoped(
                cx,
                &node,
                incarnation,
                config.timeout,
                config.child.clone(),
                move |body_cx| async move {
                    let report = run_remote(&body_cx, destination, computation, input, config).await;
                    // The body must acknowledge its own cancellation after drain.
                    // Otherwise ordinary Cx::spawn may replace this useful nested
                    // terminal/cleanup report with task-level cancellation.
                    let _ = body_cx.checkpoint();
                    report
                },
            )
            .await?;
        Ok(MembershipRemoteReport { work })
    }

    /// Run remote work with an additional one-way SWIM contact veto.
    ///
    /// The contact must name `node` and still be live before admission. Accepted
    /// authenticated Alive authority for the exact `node`/`incarnation` and the
    /// caller's existing transport credentials and computation grants remain
    /// independently required. The detector's incarnation is not proof of the
    /// remote process's authenticated identity.
    ///
    /// Any observed suspicion, departure, incarnation change, or detector stop
    /// permanently ends this operation's contact token, even if the observer
    /// misses an intervening loss/recovery or its event log is compacted. The
    /// runner aborts its checked membership lease with `OwnedLeaseStatus::Dropped`,
    /// cancels its child, and waits for the existing remote cancel/drain path.
    /// The contact remains monitored while child cleanup drains. This local
    /// retirement never signs a membership update or revokes unrelated leases.
    ///
    /// A fresh direct contact permits a new token and a separately authorized
    /// invocation; it cannot revive or retry this invocation. Existing
    /// `run_remote` behavior is unchanged and does not opt in to this veto.
    /// Continue polling through cleanup to obtain the independent close and
    /// transport reports; an aborted local lease alone proves no remote drain.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_arguments)]
    pub async fn run_remote_with_swim(
        &self,
        cx: &Cx,
        node: NodeId,
        incarnation: u64,
        contact: SwimContact,
        computation: ComputationName,
        input: RemoteInput,
        config: RemoteRunConfig,
    ) -> Result<MembershipRemoteReport, MembershipRemoteError> {
        if cx.is_cancel_requested() {
            return Err(RemoteRunError::Cancelled.into());
        }
        if contact.node() != &node {
            return Err(MembershipRemoteError::ContactMismatch);
        }
        if !contact.is_live() {
            return Err(MembershipRemoteError::ContactEnded);
        }
        let cap = cx.remote().ok_or(RemoteRunError::NoCapability)?;
        if cap.runtime().is_none() {
            return Err(RemoteRunError::NoRemoteRuntime.into());
        }
        let live = contact.clone();
        let guard = MembershipWorkGuard {
            active: Arc::new(move || live.is_live()),
            ended: Box::pin(async move { contact.ended().await }),
        };
        let destination = node.clone();
        let work = self.run_scoped_guarded(
            cx, &node, incarnation, config.timeout, config.child.clone(), Some(guard),
            move |body_cx| async move {
                let report = run_remote(&body_cx, destination, computation, input, config).await;
                let _ = body_cx.checkpoint();
                report
            },
        ).await?;
        Ok(MembershipRemoteReport { work })
    }
}

#[cfg(test)]
#[path = "remote_inline_tests.rs"]
mod tests;
