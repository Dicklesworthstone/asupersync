//! Distribution of symbols to replicas with consistency guarantees.
//!
//! Provides [`SymbolDistributor`] for distributing encoded symbols to
//! replicas and tracking acknowledgements with quorum semantics.

use crate::combinator::quorum::{QuorumResult, quorum_outcomes};
use crate::cx::Cx;
use crate::error::ErrorKind;
use crate::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use crate::security::SecurityContext;
use crate::security::authenticated::AuthenticatedSymbol;
use crate::types::symbol::ObjectId;
use crate::types::{Outcome, Time};
use std::future::Future;
use std::time::Duration;

use super::assignment::{AssignmentStrategy, SymbolAssigner};
use super::encoding::{EncodedState, EncodingConfig, PathQualitySnapshot};

mod driver;
#[cfg(test)]
mod fanout_tests;

// ---------------------------------------------------------------------------
// DistributorTransport
// ---------------------------------------------------------------------------

/// Transport interface for distributing symbols.
///
/// The returned future owns one send attempt. Implementations must release its
/// local resources when dropped (including on timeout or caller cancellation),
/// must not detach work, and must keep each poll nonblocking. Already transmitted
/// bytes cannot be rolled back: failures do not prove that the replica received
/// nothing. Authentication of the peer and acknowledgement is the transport's
/// responsibility; the distributor additionally validates replica ID and count.
pub trait DistributorTransport: Sync {
    /// Sends a batch of symbols to a replica.
    fn send_symbols(
        &self,
        replica_id: &str,
        symbols: Vec<AuthenticatedSymbol>,
    ) -> impl Future<Output = Result<ReplicaAck, ReplicaFailure>> + Send;
}

// ---------------------------------------------------------------------------
// DistributionConfig
// ---------------------------------------------------------------------------

/// Configuration for symbol distribution.
#[derive(Debug, Clone)]
pub struct DistributionConfig {
    /// Consistency level for distribution.
    pub consistency: ConsistencyLevel,
    /// Per-admitted-replica acknowledgement timeout. Zero refuses without sending.
    pub ack_timeout: Duration,
    /// Maximum in-flight send attempts per call. Zero denies all replica admission.
    pub max_concurrent: usize,
    /// Whether to use hedged requests.
    pub hedge_enabled: bool,
    /// Hedge delay (send to backup after this delay).
    pub hedge_delay: Duration,
    /// Optional path-quality snapshot to apply when creating an encoder config.
    pub encoding_path_quality: Option<PathQualitySnapshot>,
}

impl Default for DistributionConfig {
    /// Creates the default distribution configuration.
    fn default() -> Self {
        Self {
            consistency: ConsistencyLevel::Quorum,
            ack_timeout: Duration::from_secs(5),
            max_concurrent: 10,
            hedge_enabled: false,
            hedge_delay: Duration::from_millis(50),
            encoding_path_quality: None,
        }
    }
}

impl DistributionConfig {
    /// Returns a copy with path-quality input for adaptive RaptorQ block layout.
    #[must_use]
    pub const fn with_encoding_path_quality(mut self, quality: PathQualitySnapshot) -> Self {
        self.encoding_path_quality = Some(quality);
        self
    }

    /// Applies this distribution config's path-quality input to an encoding config.
    #[must_use]
    pub const fn apply_to_encoding_config(&self, mut config: EncodingConfig) -> EncodingConfig {
        config.path_quality = self.encoding_path_quality;
        config
    }
}

// ---------------------------------------------------------------------------
// DistributionResult
// ---------------------------------------------------------------------------

/// Result of a distribution operation.
#[derive(Debug)]
pub struct DistributionResult {
    /// Object ID that was distributed.
    pub object_id: ObjectId,
    /// Number of symbol sends attempted across the computed replica plan.
    pub symbols_distributed: u32,
    /// Successful replica acknowledgements.
    pub acks: Vec<ReplicaAck>,
    /// Failed replicas.
    pub failures: Vec<ReplicaFailure>,
    /// Whether quorum was achieved.
    pub quorum_achieved: bool,
    /// Total distribution duration.
    pub duration: Duration,
}

/// Acknowledgement from a replica.
#[derive(Debug, Clone)]
pub struct ReplicaAck {
    /// Identifier of the acknowledging replica.
    pub replica_id: String,
    /// Number of symbols received.
    pub symbols_received: u32,
    /// Timestamp of acknowledgement.
    pub ack_time: Time,
}

/// Failure information for a replica.
#[derive(Debug, Clone)]
pub struct ReplicaFailure {
    /// Identifier of the failed replica.
    pub replica_id: String,
    /// Error description.
    pub error: String,
    /// Error kind for categorization.
    pub error_kind: ErrorKind,
}

// ---------------------------------------------------------------------------
// DistributionMetrics
// ---------------------------------------------------------------------------

/// Metrics for distribution operations.
#[derive(Debug, Default)]
pub struct DistributionMetrics {
    /// Total distribution attempts.
    pub distributions_total: u64,
    /// Successful distributions (quorum achieved).
    pub distributions_successful: u64,
    /// Failed distributions (quorum not achieved).
    pub distributions_failed: u64,
    /// Total symbols sent across all distributions.
    pub symbols_sent_total: u64,
    /// Total acknowledgements received.
    pub acks_received_total: u64,
    /// Count of distributions where quorum was achieved.
    pub quorum_achieved_count: u64,
    /// Count of distributions where quorum was missed.
    pub quorum_missed_count: u64,
}

// ---------------------------------------------------------------------------
// SymbolDistributor
// ---------------------------------------------------------------------------

/// Distributes encoded symbols to replicas.
///
/// Handles symbol assignment, distribution, and quorum-based acknowledgement
/// tracking. The async `distribute` method is intended for runtime use;
/// [`evaluate_outcomes`](Self::evaluate_outcomes) provides a synchronous
/// test path.
pub struct SymbolDistributor {
    config: DistributionConfig,
    /// Metrics for distribution operations.
    pub metrics: DistributionMetrics,
}

impl SymbolDistributor {
    /// Creates a new distributor with the given configuration.
    #[must_use]
    pub fn new(config: DistributionConfig) -> Self {
        Self {
            config,
            metrics: DistributionMetrics::default(),
        }
    }

    /// Returns a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &DistributionConfig {
        &self.config
    }

    /// Distributes symbols to replicas using the provided transport.
    ///
    /// Signs only admitted batches, polls at most `max_concurrent` sends per
    /// turn, and waits for all eligible replicas to finish or time out. Results
    /// retain assignment order, not completion order. Cancellation stops new
    /// admission and drops every owned attempt before returning unresolved peers
    /// as `Cancelled` failures. This observes requests without acknowledging the
    /// runtime cancellation protocol or claiming remote rollback/quiescence.
    /// A transport must obey the ownership contract of [`DistributorTransport`].
    /// Pending sends require an explicit `cx.timer_driver()`; otherwise they
    /// fail with `ConfigError` instead of acquiring ambient timer authority.
    ///
    /// br-asupersync-307rnt: the start/end timestamps used to compute
    /// `DistributionResult.duration` are read through `cx.timer_driver()`
    /// (falling back to `crate::time::wall_now` when no driver is
    /// installed). In the lab runtime the timer driver returns
    /// virtual time, which makes the resulting `duration` field
    /// replay-stable. Previously this captured `std::time::Instant::now()`
    /// directly and leaked wall-clock into the public result.
    pub async fn distribute<T: DistributorTransport>(
        &mut self,
        cx: &Cx,
        encoded: &EncodedState,
        replicas: &[ReplicaInfo],
        transport: &T,
        auth_context: &SecurityContext,
    ) -> DistributionResult {
        self.distribute_with_strategy(
            cx, encoded, replicas, transport, auth_context, AssignmentStrategy::Full,
        ).await
    }

    /// Distribute an explicit symbol layout through the same bounded fanout.
    ///
    /// `Full` preserves [`Self::distribute`]. Other strategies send only each
    /// replica's assigned symbols. Acknowledgement quorum counts distinct
    /// replicas; it does not prove that their combined symbols can reconstruct
    /// the object. Checkpoint publication performs that additional check before
    /// returning authenticated recovery metadata. Hedging may stop before an
    /// erasure-coded layout has enough independent symbols for recovery.
    #[allow(clippy::too_many_arguments)]
    pub async fn distribute_with_strategy<T: DistributorTransport>(
        &mut self,
        cx: &Cx,
        encoded: &EncodedState,
        replicas: &[ReplicaInfo],
        transport: &T,
        auth_context: &SecurityContext,
        strategy: AssignmentStrategy,
    ) -> DistributionResult {
        let assignments = Self::compute_assignments_with_strategy(
            encoded, replicas, auth_context, None, strategy,
        );
        self.distribute_assignments(cx, encoded, assignments, transport, auth_context, usize::MAX).await
    }

    // Checkpoint preparation retains the exact plan it authenticated. Do not
    // recompute placement after validating per-replica batch digests.
    pub(crate) async fn distribute_assignments<T: DistributorTransport>(
        &mut self,
        cx: &Cx,
        encoded: &EncodedState,
        assignments: Vec<super::assignment::ReplicaAssignment>,
        transport: &T,
        auth_context: &SecurityContext,
        in_flight_ceiling: usize,
    ) -> DistributionResult {
        self.distribute_assignments_with_completion(
            cx, encoded, assignments, transport, auth_context, in_flight_ceiling, None,
        ).await
    }

    // A checkpoint can require both receipt quorum and authenticated coverage.
    // Only verified, distinct assignment acknowledgements reach this callback.
    // Keeping it private preserves the established public fanout semantics.
    //
    // A bounded transport refuses a send beyond its in-flight limit instead of
    // queueing it, so a wider fanout would count healthy replicas as failed.
    // `in_flight_ceiling` lowers `max_concurrent` for this call only; later
    // replicas start as earlier sends finish.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn distribute_assignments_with_completion<T: DistributorTransport>(
        &mut self,
        cx: &Cx,
        encoded: &EncodedState,
        assignments: Vec<super::assignment::ReplicaAssignment>,
        transport: &T,
        auth_context: &SecurityContext,
        in_flight_ceiling: usize,
        completion: Option<&mut (dyn FnMut(&ReplicaAck) -> bool + Send)>,
    ) -> DistributionResult {
        let capped;
        let config = if self.config.max_concurrent > in_flight_ceiling {
            capped = DistributionConfig { max_concurrent: in_flight_ceiling, ..self.config.clone() };
            &capped
        } else {
            &self.config
        };
        let timer = cx.timer_driver();
        let start = driver::now(timer.as_ref());
        let fanout = if completion.is_some() {
            driver::run_with_completion(
                config, cx, encoded, assignments, transport, auth_context, timer.clone(), completion,
            ).await
        } else {
            driver::run(config, cx, encoded, assignments, transport, auth_context, timer.clone()).await
        };
        let duration = Duration::from_nanos(driver::now(timer.as_ref()).duration_since(start));

        // Fix the denominator before admission. Cancellation, limits, timeouts,
        // and invalid acknowledgements must not make the requested quorum easier.
        // Unauthorized/empty assignments are excluded and repeated identities
        // contribute at most one vote. Empty non-Local delivery stays fail-closed.
        let required = if fanout.eligible_replicas == 0
            && self.config.consistency != ConsistencyLevel::Local
        {
            1
        } else {
            Self::required_acks(self.config.consistency, fanout.eligible_replicas)
        };
        self.evaluate_outcomes_with_sent(
            encoded, required, fanout.outcomes, fanout.symbols_attempted, duration,
        )
    }

    /// Computes the required acknowledgement count for the given consistency
    /// level and replica count.
    #[inline]
    #[must_use]
    pub fn required_acks(consistency: ConsistencyLevel, replica_count: usize) -> usize {
        match consistency {
            ConsistencyLevel::One => 1,
            ConsistencyLevel::Quorum => (replica_count / 2) + 1,
            ConsistencyLevel::All => replica_count,
            ConsistencyLevel::Local => 0,
        }
    }

    /// Computes symbol assignments for the given encoded state and replicas.
    ///
    /// asupersync-j18rga: This is the legacy version that uses a default
    /// security context. Use `compute_assignments_with_auth` for explicit control.
    #[inline]
    #[must_use]
    pub fn compute_assignments(
        encoded: &EncodedState,
        replicas: &[ReplicaInfo],
    ) -> Vec<super::assignment::ReplicaAssignment> {
        // asupersync-j18rga: Use a default security context for backward compatibility
        // In production, callers should migrate to compute_assignments_with_auth
        let default_security_context = SecurityContext::for_testing(0);
        Self::compute_assignments_with_auth(encoded, replicas, &default_security_context, None)
    }

    /// Computes symbol assignments with explicit replica authorization.
    ///
    /// asupersync-j18rga: Validates replica authorization before assignment
    /// to prevent unauthorized nodes from participating in symbol distribution.
    #[inline]
    #[must_use]
    pub fn compute_assignments_with_auth(
        encoded: &EncodedState,
        replicas: &[ReplicaInfo],
        security_context: &SecurityContext,
        region_id: Option<&str>,
    ) -> Vec<super::assignment::ReplicaAssignment> {
        Self::compute_assignments_with_strategy(
            encoded, replicas, security_context, region_id, AssignmentStrategy::Full,
        )
    }

    /// Computes an explicit placement without changing the full-copy defaults.
    /// Unauthorized replicas are filtered using the supplied security context.
    #[inline]
    #[must_use]
    pub fn compute_assignments_with_strategy(
        encoded: &EncodedState,
        replicas: &[ReplicaInfo],
        security_context: &SecurityContext,
        region_id: Option<&str>,
        strategy: AssignmentStrategy,
    ) -> Vec<super::assignment::ReplicaAssignment> {
        let assigner = SymbolAssigner::new(strategy);
        assigner.assign(
            &encoded.symbols,
            replicas,
            security_context,
            region_id,
            encoded.source_count,
        )
    }

    /// Evaluates pre-computed outcomes with quorum semantics.
    ///
    /// This is the synchronous core of the distribution logic. The async
    /// `distribute` method wraps actual I/O around this function.
    ///
    /// # Arguments
    ///
    /// * `encoded` - The encoded state being distributed
    /// * `replicas` - Target replicas (for computing required acks)
    /// * `outcomes` - Pre-computed outcomes from each replica
    /// * `duration` - Time spent distributing
    pub fn evaluate_outcomes(
        &mut self,
        encoded: &EncodedState,
        replicas: &[ReplicaInfo],
        outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>>,
        duration: Duration,
    ) -> DistributionResult {
        let symbols_sent_total = Self::compute_assignments(encoded, replicas)
            .into_iter()
            .map(|assignment| assignment.symbol_indices.len() as u64)
            .sum();
        let required = Self::required_acks(self.config.consistency, replicas.len());
        self.evaluate_outcomes_with_sent(encoded, required, outcomes, symbols_sent_total, duration)
    }

    fn evaluate_outcomes_with_sent(
        &mut self,
        encoded: &EncodedState,
        required: usize,
        outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>>,
        symbols_sent_total: u64,
        duration: Duration,
    ) -> DistributionResult {
        let quorum_result: QuorumResult<ReplicaAck, ReplicaFailure> =
            quorum_outcomes(required, outcomes);

        self.metrics.distributions_total = self.metrics.distributions_total.saturating_add(1);
        self.metrics.symbols_sent_total = self
            .metrics
            .symbols_sent_total
            .saturating_add(symbols_sent_total);

        let acks: Vec<ReplicaAck> = quorum_result
            .successes
            .into_iter()
            .map(|(_, ack)| ack)
            .collect();

        let failures: Vec<ReplicaFailure> = quorum_result
            .failures
            .into_iter()
            .filter_map(|(_, f)| match f {
                crate::combinator::quorum::QuorumFailure::Error(e) => Some(e),
                _ => None,
            })
            .collect();

        self.metrics.acks_received_total = self
            .metrics
            .acks_received_total
            .saturating_add(acks.len() as u64);

        if quorum_result.quorum_met {
            self.metrics.distributions_successful =
                self.metrics.distributions_successful.saturating_add(1);
            self.metrics.quorum_achieved_count =
                self.metrics.quorum_achieved_count.saturating_add(1);
        } else {
            self.metrics.distributions_failed = self.metrics.distributions_failed.saturating_add(1);
            self.metrics.quorum_missed_count = self.metrics.quorum_missed_count.saturating_add(1);
        }

        DistributionResult {
            object_id: encoded.params.object_id,
            symbols_distributed: u32::try_from(symbols_sent_total).unwrap_or(u32::MAX),
            acks,
            failures,
            quorum_achieved: quorum_result.quorum_met,
            duration,
        }
    }
}

impl std::fmt::Debug for SymbolDistributor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolDistributor")
            .field("config", &self.config)
            .field("metrics", &self.metrics)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "distribution_inline_tests.rs"]
mod tests;
