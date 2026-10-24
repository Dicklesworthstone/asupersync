//! Membership revocation joined to the isolated admitted native transport.
//!
//! The immutable route is the single source of controller, logical destination,
//! incarnation and TLS policy. No caller-supplied membership identity can be
//! paired with a reservation for a different destination.

use super::{NativeRemoteAdmissionError, NativeRemoteReservation};
use crate::cx::Cx;
use crate::distributed::membership::owned::remote::MembershipRemoteReport;
use crate::distributed::membership::owned::{MembershipWorkError, MembershipWorkReport};
use crate::distributed::remote_owned::{
    OwnedRemoteRequest, RemoteRunConfig, RemoteRunError, RemoteRunReport,
    RemoteRunRetention, prepare_owned_timing, run_owned_request,
};
use crate::remote::ComputationName;
use std::time::Duration;

/// Refusal before membership-owned admitted work reaches its reporting phase.
///
/// Later protocol, cancellation, lease and child-close outcomes remain separate
/// in the existing MembershipRemoteReport. An Ok report alone is not success.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeRemoteMembershipError {
    /// The reserved route has no explicitly provisioned membership binding.
    #[error("native membership-owned work requires a membership-bound route")]
    MembershipRequired,
    /// Payload, capability mask or fixed native admission policy refused.
    #[error(transparent)]
    Admission(#[from] NativeRemoteAdmissionError),
    /// Caller liveness or the native ownership deadline could not be prepared.
    #[error(transparent)]
    Ownership(#[from] RemoteRunError),
    /// Exact-generation membership, checked lease or outer child admission failed.
    #[error(transparent)]
    Membership(#[from] MembershipWorkError),
}

// The membership body may finish while its owner is still closing the outer
// child, or after that owner's future was dropped. Keep the native charge in
// the runtime-owned result channel until that exact payload is consumed or
// destroyed. Field order destroys report bytes before the last credit share.
struct RetainedMembershipRemoteReport {
    result: Result<RemoteRunReport, RemoteRunError>,
    _retention: Option<RemoteRunRetention>,
}

impl NativeRemoteReservation {
    /// Run admitted native work under its route's authenticated membership lease.
    ///
    /// The route must have an explicit
    /// [membership binding](crate::remote::NativeRemoteRoute::with_membership).
    /// Its controller, destination, incarnation and enforcing TLS identity are
    /// preserved together. No legacy RemoteCap, discovery authority, replacement
    /// route or simulated transport is acquired. The context's effective remote
    /// capability mask and child attenuation still apply.
    ///
    /// A checked membership Lease is granted for the exact Alive incarnation
    /// before either body or remote dispatch can begin. Dead, Left, supersession,
    /// expiry and controller closure cancel only this invocation's membership
    /// subtree. Its native proxy retains the existing route and protected control
    /// capacity while requesting cancellation and collecting a terminal response.
    /// Suspect pauses new grants; it does not revoke already running work.
    /// The native route is checked again at actual dispatch, including after
    /// child admission waits. No old-generation reservation can adopt a rejoin.
    ///
    /// The existing native owned runner registers its own checked Lease before
    /// wire publication and closes its child before reporting. The outer runner
    /// also awaits actual child close and lease settlement. A transport failure,
    /// lost acknowledgement or bounded drain timeout preserves its uncertainty;
    /// local membership revocation does not certify remote quiescence.
    /// Use MembershipRemoteReport::is_success before accepting the returned work.
    ///
    /// This method makes one bounded input copy under the reservation's existing
    /// charge. The caller retains ownership of the borrowed input. Pending child
    /// admission, native retries and runtime-owned terminal reports retain that
    /// charge. Consuming the outer result transfers report bytes to the caller.
    /// Dropping an unpolled future releases the reservation without dispatch.
    /// Dropping a started future requests subtree close; runtime-owned work and
    /// unread result bytes keep their credit until their actual retirement.
    ///
    /// The native deadline starts before membership admission; the same timeout
    /// supplies the fixed membership lease. There is no automatic membership
    /// renewal or invocation retry. Deadlines initiate cooperative cleanup rather
    /// than imposing a universal wall-clock drain bound. Continue polling to
    /// receive both close receipts. Existing run_owned behavior is unchanged.
    pub async fn run_membership_owned(
        self,
        cx: &Cx,
        computation: &ComputationName,
        input: &[u8],
        lease: Duration,
        config: RemoteRunConfig,
    ) -> Result<MembershipRemoteReport, NativeRemoteMembershipError> {
        let (controller, incarnation) = self
            .domain
            .runtime
            .route(&self.node)
            .ok_or(NativeRemoteAdmissionError::UnknownRoute)?
            .membership
            .clone()
            .ok_or(NativeRemoteMembershipError::MembershipRequired)?;
        let node = self.node.clone();
        let timing = prepare_owned_timing(cx, &config)?;
        let request = self.prepare_owned(cx, computation, input, lease)?;
        let work = controller
            .run_scoped(
                cx,
                &node,
                incarnation,
                config.timeout,
                config.child.clone(),
                move |body_cx| async move {
                    // This share outlives the inner runner's transfer to its
                    // caller: that caller is still a runtime-owned body task.
                    let retention = request.retention();
                    let result =
                        run_owned_request(&body_cx, request, config.child, timing).await;
                    // Preserve the nested cancellation/drain report through
                    // ordinary spawn's acknowledged-cancellation semantics.
                    let _ = body_cx.checkpoint();
                    RetainedMembershipRemoteReport {
                        result,
                        _retention: retention,
                    }
                },
            )
            .await?;
        let MembershipWorkReport {
            trigger,
            task,
            close,
            lease,
        } = work;
        // run_scoped has closed the outer child and consumed its terminal
        // channel. Only this final transfer sheds the result's credit share.
        let task = task.map(|retained| retained.result);
        Ok(MembershipRemoteReport {
            work: MembershipWorkReport {
                trigger,
                task,
                close,
                lease,
            },
        })
    }
}
