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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor};
    use crate::remote::RemoteCap;
    use crate::security::AuthKey;
    use crate::time::{TimerDriver, TimerDriverHandle};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn no_remote_capability_or_runtime_never_creates_a_membership_lease() {
        let timer = TimerDriverHandle::new(Arc::new(TimerDriver::new()));
        let owner = OwnedMembershipController::new(
            NodeId::new("authority"),
            1,
            AuthKey::from_seed(7),
            vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 1, sequence: 0 }],
            MembershipControllerLimits { max_members: 1, max_lease_ids: 1 },
            timer,
        ).unwrap();
        for (cx, has_cap) in [
            (Cx::for_testing(), false),
            (Cx::for_testing_with_remote(RemoteCap::new()), true),
        ] {
            let result = futures_lite::future::block_on(owner.run_remote(
                &cx, NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(),
                RemoteRunConfig { timeout: Duration::from_secs(1), child: crate::cx::ChildRegionSpec::inherit() },
            ));
            assert!(match result {
                Err(MembershipRemoteError::Remote(RemoteRunError::NoRemoteRuntime)) => has_cap,
                Err(MembershipRemoteError::Remote(RemoteRunError::NoCapability)) => !has_cap,
                _ => false,
            });
            assert_eq!(owner.live_leases(), 0);
        }
    }
}
