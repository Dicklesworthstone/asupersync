//! Shared authentication, decode admission, and accounting for both SDK paths.

use super::{
    AuthMode, AuthenticatedSymbol, AuthenticatedSymbolState, Error, ErrorKind, Metrics, ObjectId,
    ObjectParams, RaptorQConfig, ReceiveAuthenticationSummary, ReceiveOutcome, SecurityContext,
    required_security, usize_to_u32_saturating,
};
use crate::decoding::{
    BlockDecodeJob, BlockDecodeOutcome, DecodingConfig, DecodingPipeline, DeferredSymbolAcceptResult,
    RejectReason, SymbolAcceptResult,
};

pub(super) struct ReceiveState {
    decoder: DecodingPipeline,
    object_id: ObjectId,
    security: Option<SecurityContext>,
    reject_unauthenticated: bool,
    authenticate_other_objects: bool,
    symbols_received: usize,
    authenticated: bool,
    authentication: ReceiveAuthenticationSummary,
}

impl ReceiveState {
    #[allow(clippy::result_large_err)]
    pub(super) fn new(
        config: &RaptorQConfig,
        explicit: Option<&SecurityContext>,
        params: &ObjectParams,
        require_authentication: bool,
    ) -> Result<Self, Error> {
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.encoding.symbol_size,
            max_block_size: config.encoding.max_block_size,
            repair_overhead: config.encoding.repair_overhead,
            // Verify at this boundary before feeding the decode matrix.
            verify_auth: false,
            // Let the object parameters size the cap to K. A fixed cap can
            // reject valid large-K objects before enough symbols arrive.
            max_buffered_symbols: 0,
            ..Default::default()
        });
        decoder.set_object_params(*params).map_err(Error::from)?;

        // Preserve the synchronous path's explicit-context precedence and
        // configured authentication policy. The new asynchronous path always
        // verifies, including when the supplied context was permissive.
        let security = if require_authentication {
            Some(required_security(config, explicit)?)
        } else {
            explicit
                .cloned()
                .or_else(|| config.security.build_context())
        };
        let reject_unauthenticated = require_authentication
            || (config.security.reject_unauthenticated
                && security.as_ref().is_some_and(|ctx| ctx.mode() == AuthMode::Strict));
        Ok(Self {
            decoder,
            object_id: params.object_id,
            authenticated: security.is_some(),
            security,
            reject_unauthenticated,
            authenticate_other_objects: require_authentication,
            symbols_received: 0,
            authentication: ReceiveAuthenticationSummary::default(),
        })
    }

    pub(super) fn is_complete(&self) -> bool {
        self.decoder.is_complete()
    }

    pub(super) const fn symbols_received(&self) -> usize {
        self.symbols_received
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn accept(
        &mut self,
        mut symbol: AuthenticatedSymbol,
        metrics: &mut Option<Metrics>,
    ) -> Result<(), Error> {
        let Some((verified, authentication)) = self.authenticate(&mut symbol, metrics)? else {
            return Ok(());
        };
        let accepted = self.decoder.feed(symbol).map_err(Error::from)?;
        self.record_acceptance(&accepted, verified, authentication, metrics)
    }

    /// Admit one verified symbol without running a block solve on this thread.
    #[allow(clippy::result_large_err)]
    pub(super) fn accept_deferred(
        &mut self,
        mut symbol: AuthenticatedSymbol,
        metrics: &mut Option<Metrics>,
    ) -> Result<Option<BlockDecodeJob>, Error> {
        let Some((verified, authentication)) = self.authenticate(&mut symbol, metrics)? else {
            return Ok(None);
        };
        match self.decoder.feed_deferred(symbol).map_err(Error::from)? {
            DeferredSymbolAcceptResult::Immediate(accepted) => {
                self.record_acceptance(&accepted, verified, authentication, metrics)?;
                Ok(None)
            }
            DeferredSymbolAcceptResult::Decode(job) => {
                // The triggering symbol was accepted before the job was made.
                // Joining the solve must not count that admission a second time.
                self.record_accepted(verified, authentication, metrics);
                Ok(Some(job))
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn finish_deferred(
        &mut self,
        outcome: BlockDecodeOutcome,
        metrics: &mut Option<Metrics>,
    ) -> Result<Option<BlockDecodeJob>, Error> {
        match self.decoder.finish_decode_job_deferred(outcome) {
            DeferredSymbolAcceptResult::Decode(retry) => Ok(Some(retry)),
            DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(
                RejectReason::AuthenticationFailed,
            )) => {
                Self::record_rejection(metrics);
                Err(Error::new(ErrorKind::CorruptedSymbol)
                    .with_message("symbol authentication failed during receive"))
            }
            // Completion records no new symbol admission. Rank-deficient jobs
            // restore their rows so a later authentic symbol can retry.
            DeferredSymbolAcceptResult::Immediate(_) => Ok(None),
        }
    }

    #[allow(clippy::result_large_err)]
    fn authenticate(
        &self,
        symbol: &mut AuthenticatedSymbol,
        metrics: &mut Option<Metrics>,
    ) -> Result<Option<(bool, AuthenticatedSymbolState)>, Error> {
        let target_object = symbol.symbol().object_id() == self.object_id;
        if !target_object && !self.authenticate_other_objects {
            return Ok(None);
        }
        let verified = if let Some(security) = &self.security {
            if let Err(error) = security.verify_authenticated_symbol(symbol) {
                Self::record_rejection(metrics);
                return Err(Error::new(ErrorKind::CorruptedSymbol).with_message(error.to_string()));
            }
            symbol.is_verified()
        } else {
            false
        };
        let authentication = symbol.authentication_state();
        if self.reject_unauthenticated && self.security.is_some() && !verified {
            Self::record_rejection(metrics);
            return Err(Error::new(ErrorKind::CorruptedSymbol).with_message(
                "symbol rejected: reject_unauthenticated=true and symbol did not authenticate",
            ));
        }
        if !target_object {
            return Ok(None);
        }
        Ok(Some((verified, authentication)))
    }

    #[allow(clippy::result_large_err)]
    fn record_acceptance(
        &mut self,
        accepted: &SymbolAcceptResult,
        verified: bool,
        authentication: AuthenticatedSymbolState,
        metrics: &mut Option<Metrics>,
    ) -> Result<(), Error> {
        match accepted {
            SymbolAcceptResult::Accepted { .. }
            | SymbolAcceptResult::DecodingStarted { .. }
            | SymbolAcceptResult::BlockComplete { .. } => {
                self.record_accepted(verified, authentication, metrics);
            }
            SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => {
                Self::record_rejection(metrics);
                return Err(Error::new(ErrorKind::CorruptedSymbol)
                    .with_message("symbol authentication failed during receive"));
            }
            SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_) => {}
        }
        Ok(())
    }

    fn record_accepted(
        &mut self,
        verified: bool,
        authentication: AuthenticatedSymbolState,
        metrics: &mut Option<Metrics>,
    ) {
        self.authenticated &= verified;
        self.authentication.record(authentication);
        self.symbols_received += 1;
        if let Some(metrics) = metrics {
            metrics.counter("raptorq.symbols_received").increment();
        }
    }

    pub(super) fn insufficient_symbols(&self) -> Error {
        let progress = self.decoder.progress();
        Error::insufficient_symbols(
            usize_to_u32_saturating(progress.symbols_received),
            usize_to_u32_saturating(progress.symbols_needed_estimate),
        )
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn finish(self, metrics: &mut Option<Metrics>) -> Result<ReceiveOutcome, Error> {
        let data = self.decoder.into_data().map_err(Error::from)?;
        if let Some(metrics) = metrics {
            metrics.counter("raptorq.objects_received").increment();
        }
        Ok(ReceiveOutcome {
            data,
            symbols_received: self.symbols_received,
            authenticated: self.authenticated,
            authentication: self.authentication,
        })
    }

    fn record_rejection(metrics: &mut Option<Metrics>) {
        if let Some(metrics) = metrics {
            metrics.counter("raptorq.auth_rejected").increment();
        }
    }
}
