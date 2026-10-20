//! Checked ownership of one protocol-side incoming HTTP/1 body.
//!
//! The consumer never owns this token. Its early drop transfers the remaining
//! framing work to the same protocol writer, which must synchronize or close.

use super::IncomingBodyError;
use crate::cx::Cx;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken};
use crate::types::CancelKind;

/// Refusal before a checked request body becomes visible to application code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IncomingBodyAdmissionError {
    Policy(IncomingBodyError),
    Cancelled { kind: CancelKind },
    Runtime(ObligationAdmissionError),
    RuntimeRequired,
}

impl std::fmt::Display for IncomingBodyAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => std::fmt::Display::fmt(error, formatter),
            Self::Cancelled { kind } => {
                write!(formatter, "incoming body admission cancelled ({kind:?})")
            }
            Self::Runtime(error) => std::fmt::Display::fmt(error, formatter),
            Self::RuntimeRequired => {
                formatter.write_str("checked incoming body requires a runtime-owned task")
            }
        }
    }
}

impl std::error::Error for IncomingBodyAdmissionError {}

/// Holds the credit even while the consumer is gone and no sender remains.
/// All settlement is synchronous and independent of a cancelled channel send.
#[derive(Debug)]
pub(super) struct IncomingBodyObligation {
    token: Option<ObligationToken>,
    owner: Cx,
}

impl IncomingBodyObligation {
    pub(super) fn admit(cx: &Cx) -> Result<Self, IncomingBodyAdmissionError> {
        checkpoint(cx)?;
        let token = cx
            .try_register_obligation_checked(ObligationKind::IoOp, cx.task_id())
            .map_err(IncomingBodyAdmissionError::Runtime)?
            .ok_or(IncomingBodyAdmissionError::RuntimeRequired)?;
        // Install the abort backstop before a second checkpoint or liveness
        // check: admission notifications may themselves cancel the owner.
        let admitted = Self {
            token: Some(token),
            owner: cx.clone(),
        };
        checkpoint(cx)?;
        let (gateway, holder) = cx
            .obligation_transfer_destination()
            .map_err(IncomingBodyAdmissionError::Runtime)?;
        let token = admitted.token.as_ref().expect("admitted body credit");
        let refusal = if !gateway.is_runtime_available() {
            Some(ObligationAdmissionError::RuntimeUnavailable)
        } else if !holder.is_live() {
            Some(ObligationAdmissionError::HolderNotLive)
        } else if token.holder() != holder.holder()
            || token.region() != holder.region()
            || token.holder() != cx.task_id()
            || token.region() != cx.region_id()
        {
            Some(ObligationAdmissionError::HolderMismatch)
        } else {
            None
        };
        if let Some(error) = refusal {
            return Err(IncomingBodyAdmissionError::Runtime(error));
        }
        Ok(admitted)
    }

    pub(super) fn commit(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = token.commit();
        }
    }

    pub(super) fn abort(&mut self, error: &IncomingBodyError) {
        if let Some(token) = self.token.take() {
            let reason = if matches!(error, IncomingBodyError::Cancelled { .. }) {
                ObligationAbortReason::Cancel
            } else {
                ObligationAbortReason::Error
            };
            let _ = token.abort(reason);
        }
    }

    pub(super) fn abandoned_error(&self) -> IncomingBodyError {
        if self.owner.is_cancel_requested() {
            IncomingBodyError::cancelled(&self.owner)
        } else {
            IncomingBodyError::SourceDisconnected
        }
    }
}

impl Drop for IncomingBodyObligation {
    fn drop(&mut self) {
        let error = self.abandoned_error();
        self.abort(&error);
    }
}

fn checkpoint(cx: &Cx) -> Result<(), IncomingBodyAdmissionError> {
    cx.checkpoint()
        .map_err(|_| IncomingBodyAdmissionError::Cancelled {
            kind: cx
                .cancel_reason()
                .map_or(CancelKind::User, |reason| reason.kind()),
        })
}
