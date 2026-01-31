//! Pipeline combinator for staged processing.
//!
//! The pipeline combinator chains a sequence of transformations where each
//! stage's output feeds the next stage's input. This module implements
//! sequential pipeline execution for Phase 0 (single-threaded).
//!
//! # Design Philosophy
//!
//! Two modes of pipeline operation:
//! 1. **Sequential pipeline** (Phase 0): Stage N+1 starts only after stage N completes
//! 2. **Streaming pipeline** (Phase 1+): Stages run concurrently via channels
//!
//! This module implements sequential pipeline for the deterministic lab runtime.
//!
//! # Behavior
//!
//! ```text
//! pipeline(input, [stage1, stage2, stage3]):
//!   r1 <- stage1(input)
//!   if r1 is Err/Cancelled/Panicked: return r1
//!   r2 <- stage2(r1.value)
//!   if r2 is Err/Cancelled/Panicked: return r2
//!   r3 <- stage3(r2.value)
//!   return r3
//! ```
//!
//! # Cancellation Handling
//!
//! - Check cancellation between stages
//! - If cancelled before stage N: return Cancelled, stages N..end never execute
//! - Stage cleanup runs if stage was started
//!
//! # Invariants
//!
//! - **Sequential ordering**: Output of stage N is input to stage N+1
//! - **Error short-circuit**: First error stops pipeline
//! - **No partial results**: Either all stages complete or none
//! - **Cancel-correctness**: Respects cancellation at stage boundaries

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::Outcome;
use core::fmt;
use std::marker::PhantomData;

/// Configuration for a pipeline operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Whether to check cancellation between stages.
    pub check_cancellation: bool,
    /// Whether to continue after recoverable errors (vs short-circuit).
    /// Default is false (short-circuit on first error).
    pub continue_on_error: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineConfig {
    /// Creates a new pipeline configuration with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            check_cancellation: true,
            continue_on_error: false,
        }
    }

    /// Creates a configuration that checks cancellation between stages.
    #[must_use]
    pub const fn with_cancellation_check() -> Self {
        Self {
            check_cancellation: true,
            continue_on_error: false,
        }
    }

    /// Creates a configuration that skips cancellation checks (for tight loops).
    #[must_use]
    pub const fn without_cancellation_check() -> Self {
        Self {
            check_cancellation: false,
            continue_on_error: false,
        }
    }
}

/// A pipeline combinator marker type.
///
/// This is a builder/marker type; actual execution happens via the runtime.
#[derive(Debug)]
pub struct Pipeline<T> {
    /// Pipeline configuration.
    pub config: PipelineConfig,
    _t: PhantomData<T>,
}

impl<T> Pipeline<T> {
    /// Creates a new pipeline with default configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: PipelineConfig::new(),
            _t: PhantomData,
        }
    }

    /// Creates a pipeline with the given configuration.
    #[must_use]
    pub const fn with_config(config: PipelineConfig) -> Self {
        Self {
            config,
            _t: PhantomData,
        }
    }
}

impl<T> Clone for Pipeline<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Pipeline<T> {}

impl<T> Default for Pipeline<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Which stage failed in a pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedStage {
    /// Zero-based index of the failed stage.
    pub index: usize,
    /// Total number of stages in the pipeline.
    pub total_stages: usize,
}

impl FailedStage {
    /// Creates a new failed stage indicator.
    #[must_use]
    pub const fn new(index: usize, total_stages: usize) -> Self {
        Self {
            index,
            total_stages,
        }
    }

    /// Returns true if this is the first stage (index 0).
    #[must_use]
    pub const fn is_first(&self) -> bool {
        self.index == 0
    }

    /// Returns true if this is the last stage.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        self.index + 1 == self.total_stages
    }

    /// Returns the stage number (1-based for display).
    #[must_use]
    pub const fn stage_number(&self) -> usize {
        self.index + 1
    }
}

impl fmt::Display for FailedStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stage {}/{}", self.stage_number(), self.total_stages)
    }
}

/// The result of a pipeline operation.
#[derive(Debug, Clone)]
pub enum PipelineResult<T, E> {
    /// Pipeline completed successfully.
    Completed {
        /// The final output value.
        value: T,
        /// Number of stages executed.
        stages_completed: usize,
    },
    /// Pipeline failed at a specific stage with an error.
    Failed {
        /// The error from the failed stage.
        error: E,
        /// Which stage failed.
        failed_at: FailedStage,
    },
    /// Pipeline was cancelled at a stage boundary.
    Cancelled {
        /// The cancellation reason.
        reason: CancelReason,
        /// Which stage was about to run (or was running).
        cancelled_at: FailedStage,
    },
    /// A stage panicked.
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Which stage panicked.
        panicked_at: FailedStage,
    },
}

impl<T, E> PipelineResult<T, E> {
    /// Creates a completed result.
    #[must_use]
    pub const fn completed(value: T, stages_completed: usize) -> Self {
        Self::Completed {
            value,
            stages_completed,
        }
    }

    /// Creates a failed result.
    #[must_use]
    pub const fn failed(error: E, failed_at: FailedStage) -> Self {
        Self::Failed { error, failed_at }
    }

    /// Creates a cancelled result.
    #[must_use]
    pub const fn cancelled(reason: CancelReason, cancelled_at: FailedStage) -> Self {
        Self::Cancelled {
            reason,
            cancelled_at,
        }
    }

    /// Creates a panicked result.
    #[must_use]
    pub const fn panicked(payload: PanicPayload, panicked_at: FailedStage) -> Self {
        Self::Panicked {
            payload,
            panicked_at,
        }
    }

    /// Returns true if the pipeline completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Returns true if the pipeline failed with an error.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns true if the pipeline was cancelled.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    /// Returns true if a stage panicked.
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked { .. })
    }

    /// Converts to an Outcome.
    pub fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Self::Completed { value, .. } => Outcome::Ok(value),
            Self::Failed { error, .. } => Outcome::Err(error),
            Self::Cancelled { reason, .. } => Outcome::Cancelled(reason),
            Self::Panicked { payload, .. } => Outcome::Panicked(payload),
        }
    }

    /// Returns the number of stages that were executed (successfully or not).
    #[must_use]
    pub const fn stages_executed(&self) -> usize {
        match self {
            Self::Completed {
                stages_completed, ..
            } => *stages_completed,
            Self::Failed { failed_at, .. } => failed_at.index + 1,
            Self::Cancelled { cancelled_at, .. } => cancelled_at.index,
            Self::Panicked { panicked_at, .. } => panicked_at.index + 1,
        }
    }
}

/// Error type for pipeline operations.
#[derive(Debug, Clone)]
pub enum PipelineError<E> {
    /// A stage failed with an error.
    StageError {
        /// The error from the stage.
        error: E,
        /// Which stage failed.
        stage: FailedStage,
    },
    /// The pipeline was cancelled.
    Cancelled {
        /// The cancellation reason.
        reason: CancelReason,
        /// Which stage was cancelled at.
        stage: FailedStage,
    },
    /// A stage panicked.
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Which stage panicked.
        stage: FailedStage,
    },
}

impl<E: fmt::Display> fmt::Display for PipelineError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StageError { error, stage } => {
                write!(f, "pipeline failed at {stage}: {error}")
            }
            Self::Cancelled { reason, stage } => {
                write!(f, "pipeline cancelled at {stage}: {reason}")
            }
            Self::Panicked { payload, stage } => {
                write!(f, "pipeline panicked at {stage}: {payload}")
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for PipelineError<E> {}

/// Constructs a pipeline result from the outcome of a specific stage.
///
/// # Arguments
/// * `outcome` - The outcome from the stage
/// * `stage_index` - Zero-based index of the current stage
/// * `total_stages` - Total number of stages in the pipeline
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::stage_outcome_to_result;
/// use asupersync::types::Outcome;
///
/// // Stage 0 succeeded in a 3-stage pipeline
/// let result = stage_outcome_to_result::<i32, &str>(
///     Outcome::Ok(42),
///     0,
///     3,
/// );
/// // This returns None because the stage succeeded - continue to next stage
/// assert!(result.is_none());
///
/// // Stage 1 failed in a 3-stage pipeline
/// let result = stage_outcome_to_result::<i32, &str>(
///     Outcome::Err("failed"),
///     1,
///     3,
/// );
/// // This returns Some because the stage failed - pipeline should stop
/// assert!(result.is_some());
/// assert!(result.unwrap().is_failed());
/// ```
#[must_use]
pub fn stage_outcome_to_result<T, E>(
    outcome: Outcome<T, E>,
    stage_index: usize,
    total_stages: usize,
) -> Option<PipelineResult<T, E>> {
    let stage = FailedStage::new(stage_index, total_stages);

    match outcome {
        Outcome::Ok(_) => None, // Success - continue to next stage
        Outcome::Err(e) => Some(PipelineResult::failed(e, stage)),
        Outcome::Cancelled(r) => Some(PipelineResult::cancelled(r, stage)),
        Outcome::Panicked(p) => Some(PipelineResult::panicked(p, stage)),
    }
}

/// Creates a pipeline result for a 2-stage pipeline.
///
/// # Arguments
/// * `o1` - Outcome from stage 1
/// * `o2` - Outcome from stage 2 (only evaluated if o1 succeeded)
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline2_outcomes;
/// use asupersync::types::Outcome;
///
/// // Both stages succeed
/// let result = pipeline2_outcomes::<i32, &str>(
///     Outcome::Ok(1),
///     Some(Outcome::Ok(2)),
/// );
/// assert!(result.is_completed());
///
/// // First stage fails (second not evaluated)
/// let result = pipeline2_outcomes::<i32, &str>(
///     Outcome::Err("stage1 failed"),
///     None,
/// );
/// assert!(result.is_failed());
/// ```
#[must_use]
pub fn pipeline2_outcomes<T, E>(
    o1: Outcome<T, E>,
    o2: Option<Outcome<T, E>>,
) -> PipelineResult<T, E> {
    const TOTAL_STAGES: usize = 2;

    // Check first stage
    if let Some(result) = stage_outcome_to_result(o1, 0, TOTAL_STAGES) {
        return result;
    }

    // First stage succeeded, check second
    match o2 {
        Some(Outcome::Ok(v)) => PipelineResult::completed(v, TOTAL_STAGES),
        Some(outcome) => {
            // Second stage failed - convert to result
            stage_outcome_to_result(outcome, 1, TOTAL_STAGES)
                .expect("non-Ok should return Some result")
        }
        None => PipelineResult::panicked(
            PanicPayload::new("o2 must be provided when o1 succeeds"),
            FailedStage::new(1, TOTAL_STAGES),
        ),
    }
}

/// Creates a pipeline result for a 3-stage pipeline.
///
/// # Arguments
/// * `o1` - Outcome from stage 1
/// * `o2` - Outcome from stage 2 (only evaluated if o1 succeeded)
/// * `o3` - Outcome from stage 3 (only evaluated if o1 and o2 succeeded)
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline3_outcomes;
/// use asupersync::types::Outcome;
///
/// // All stages succeed
/// let result = pipeline3_outcomes::<i32, &str>(
///     Outcome::Ok(1),
///     Some(Outcome::Ok(2)),
///     Some(Outcome::Ok(3)),
/// );
/// assert!(result.is_completed());
///
/// // Second stage fails
/// let result = pipeline3_outcomes::<i32, &str>(
///     Outcome::Ok(1),
///     Some(Outcome::Err("stage2 failed")),
///     None,
/// );
/// assert!(result.is_failed());
/// ```
#[must_use]
pub fn pipeline3_outcomes<T, E>(
    o1: Outcome<T, E>,
    o2: Option<Outcome<T, E>>,
    o3: Option<Outcome<T, E>>,
) -> PipelineResult<T, E> {
    const TOTAL_STAGES: usize = 3;

    // Check first stage
    if let Some(result) = stage_outcome_to_result(o1, 0, TOTAL_STAGES) {
        return result;
    }

    // Check second stage
    match o2 {
        Some(outcome) => {
            if let Some(result) = stage_outcome_to_result(outcome, 1, TOTAL_STAGES) {
                return result;
            }
        }
        None => {
            return PipelineResult::panicked(
                PanicPayload::new("o2 must be provided when o1 succeeds"),
                FailedStage::new(1, TOTAL_STAGES),
            );
        }
    }

    // Check third stage
    match o3 {
        Some(Outcome::Ok(v)) => PipelineResult::completed(v, TOTAL_STAGES),
        Some(outcome) => {
            // Third stage failed - convert to result
            stage_outcome_to_result(outcome, 2, TOTAL_STAGES)
                .expect("non-Ok should return Some result")
        }
        None => PipelineResult::panicked(
            PanicPayload::new("o3 must be provided when o1 and o2 succeed"),
            FailedStage::new(2, TOTAL_STAGES),
        ),
    }
}

/// Creates a pipeline result from a vector of outcomes.
///
/// # Arguments
/// * `outcomes` - Vector of outcomes from each stage (only includes stages that were executed)
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline_n_outcomes;
/// use asupersync::types::Outcome;
///
/// // All 4 stages succeed
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Ok(3),
///     Outcome::Ok(4),
/// ];
/// let result = pipeline_n_outcomes(outcomes, 4);
/// assert!(result.is_completed());
///
/// // Third stage fails
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
///     Outcome::Err("stage3 failed"),
/// ];
/// let result = pipeline_n_outcomes(outcomes, 5);
/// assert!(result.is_failed());
/// ```
#[must_use]
pub fn pipeline_n_outcomes<T, E>(
    outcomes: Vec<Outcome<T, E>>,
    total_stages: usize,
) -> PipelineResult<T, E> {
    assert!(!outcomes.is_empty(), "outcomes must not be empty");
    assert!(outcomes.len() <= total_stages, "more outcomes than stages");

    let num_provided = outcomes.len();
    let mut last_ok_value: Option<T> = None;

    for (index, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::Ok(v) => {
                // Track the last Ok value
                last_ok_value = Some(v);
            }
            Outcome::Err(e) => {
                return PipelineResult::failed(e, FailedStage::new(index, total_stages));
            }
            Outcome::Cancelled(r) => {
                return PipelineResult::cancelled(r, FailedStage::new(index, total_stages));
            }
            Outcome::Panicked(p) => {
                return PipelineResult::panicked(p, FailedStage::new(index, total_stages));
            }
        }
    }

    // All provided outcomes were Ok
    // Check if we've covered all stages
    if num_provided == total_stages {
        // All stages complete - return with final value
        PipelineResult::completed(
            last_ok_value.expect("at least one outcome was provided"),
            total_stages,
        )
    } else {
        // Partial pipeline - all provided stages succeeded but more remain
        // This is a valid state: caller may be building incrementally
        // Return completed with stages_executed showing partial completion
        PipelineResult::completed(
            last_ok_value.expect("at least one outcome was provided"),
            num_provided,
        )
    }
}

/// Creates a pipeline result from a vector of outcomes, with the final value provided separately.
///
/// This is the preferred function when the final value needs to be preserved.
///
/// # Arguments
/// * `intermediate_outcomes` - Outcomes from stages 0..N-1 (should all be Ok, or first failure)
/// * `final_outcome` - Outcome from the final stage (only checked if all intermediates succeeded)
/// * `total_stages` - Total number of stages
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::pipeline_with_final;
/// use asupersync::types::Outcome;
///
/// // All stages succeed
/// let intermediates: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(1),
///     Outcome::Ok(2),
/// ];
/// let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);
/// assert!(result.is_completed());
/// ```
#[must_use]
pub fn pipeline_with_final<T, E>(
    intermediate_outcomes: Vec<Outcome<T, E>>,
    final_outcome: Outcome<T, E>,
    total_stages: usize,
) -> PipelineResult<T, E> {
    // Check intermediate stages
    for (index, outcome) in intermediate_outcomes.into_iter().enumerate() {
        if let Some(result) = stage_outcome_to_result(outcome, index, total_stages) {
            return result;
        }
    }

    // Check final stage
    let final_index = total_stages - 1;
    match final_outcome {
        Outcome::Ok(v) => PipelineResult::completed(v, total_stages),
        Outcome::Err(e) => PipelineResult::failed(e, FailedStage::new(final_index, total_stages)),
        Outcome::Cancelled(r) => {
            PipelineResult::cancelled(r, FailedStage::new(final_index, total_stages))
        }
        Outcome::Panicked(p) => {
            PipelineResult::panicked(p, FailedStage::new(final_index, total_stages))
        }
    }
}

/// Converts a pipeline result to a standard Result for fail-fast handling.
///
/// If the pipeline completed, returns `Ok` with the final value.
/// If the pipeline failed, returns `Err` with the appropriate error.
///
/// # Example
/// ```
/// use asupersync::combinator::pipeline::{pipeline_to_result, PipelineResult, FailedStage};
/// use asupersync::types::Outcome;
///
/// // Completed pipeline
/// let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
/// assert_eq!(pipeline_to_result(result).unwrap(), 42);
///
/// // Failed pipeline
/// let result: PipelineResult<i32, &str> = PipelineResult::failed(
///     "error",
///     FailedStage::new(1, 3),
/// );
/// assert!(pipeline_to_result(result).is_err());
/// ```
pub fn pipeline_to_result<T, E>(result: PipelineResult<T, E>) -> Result<T, PipelineError<E>> {
    match result {
        PipelineResult::Completed { value, .. } => Ok(value),
        PipelineResult::Failed { error, failed_at } => Err(PipelineError::StageError {
            error,
            stage: failed_at,
        }),
        PipelineResult::Cancelled {
            reason,
            cancelled_at,
        } => Err(PipelineError::Cancelled {
            reason,
            stage: cancelled_at,
        }),
        PipelineResult::Panicked {
            payload,
            panicked_at,
        } => Err(PipelineError::Panicked {
            payload,
            stage: panicked_at,
        }),
    }
}

/// Macro for creating a sequential pipeline (placeholder).
///
/// In the full implementation, this chains stages with cancellation checks.
///
/// # Example (API shape)
/// ```ignore
/// let result = pipeline!(cx, input,
///     |cx, x| stage1(cx, x),
///     |cx, x| stage2(cx, x),
///     |cx, x| stage3(cx, x),
/// );
/// ```
#[macro_export]
macro_rules! pipeline {
    ($cx:expr, $input:expr, $($stage:expr),+ $(,)?) => {{
        // Placeholder: in real implementation, this chains stages
        let _ = $cx;
        let _ = $input;
        $(let _ = $stage;)+
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // PipelineConfig Tests
    // =========================================================================

    #[test]
    fn pipeline_config_default() {
        let config = PipelineConfig::default();
        assert!(config.check_cancellation);
        assert!(!config.continue_on_error);
    }

    #[test]
    fn pipeline_config_with_cancellation_check() {
        let config = PipelineConfig::with_cancellation_check();
        assert!(config.check_cancellation);
    }

    #[test]
    fn pipeline_config_without_cancellation_check() {
        let config = PipelineConfig::without_cancellation_check();
        assert!(!config.check_cancellation);
    }

    // =========================================================================
    // Pipeline Type Tests
    // =========================================================================

    #[test]
    fn pipeline_creation() {
        let pipeline = Pipeline::<()>::new();
        assert!(pipeline.config.check_cancellation);
    }

    #[test]
    fn pipeline_with_config() {
        let config = PipelineConfig::without_cancellation_check();
        let pipeline = Pipeline::<()>::with_config(config);
        assert!(!pipeline.config.check_cancellation);
    }

    #[test]
    fn pipeline_clone_and_copy() {
        let p1 = Pipeline::<()>::new();
        let p2 = p1; // Copy
        let p3 = p1; // Also copy

        assert_eq!(p1.config.check_cancellation, p2.config.check_cancellation);
        assert_eq!(p1.config.check_cancellation, p3.config.check_cancellation);
    }

    // =========================================================================
    // FailedStage Tests
    // =========================================================================

    #[test]
    fn failed_stage_first() {
        let stage = FailedStage::new(0, 3);
        assert!(stage.is_first());
        assert!(!stage.is_last());
        assert_eq!(stage.stage_number(), 1);
    }

    #[test]
    fn failed_stage_middle() {
        let stage = FailedStage::new(1, 3);
        assert!(!stage.is_first());
        assert!(!stage.is_last());
        assert_eq!(stage.stage_number(), 2);
    }

    #[test]
    fn failed_stage_last() {
        let stage = FailedStage::new(2, 3);
        assert!(!stage.is_first());
        assert!(stage.is_last());
        assert_eq!(stage.stage_number(), 3);
    }

    #[test]
    fn failed_stage_display() {
        let stage = FailedStage::new(1, 5);
        assert_eq!(stage.to_string(), "stage 2/5");
    }

    // =========================================================================
    // PipelineResult Tests
    // =========================================================================

    #[test]
    fn pipeline_result_completed() {
        let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);

        assert!(result.is_completed());
        assert!(!result.is_failed());
        assert!(!result.is_cancelled());
        assert!(!result.is_panicked());
        assert_eq!(result.stages_executed(), 3);
    }

    #[test]
    fn pipeline_result_failed() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(1, 3));

        assert!(!result.is_completed());
        assert!(result.is_failed());
        assert_eq!(result.stages_executed(), 2); // Stages 0 and 1 were executed
    }

    #[test]
    fn pipeline_result_cancelled() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(1, 3));

        assert!(!result.is_completed());
        assert!(result.is_cancelled());
        assert_eq!(result.stages_executed(), 1); // Only stage 0 completed before cancel
    }

    #[test]
    fn pipeline_result_panicked() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("boom"), FailedStage::new(2, 3));

        assert!(!result.is_completed());
        assert!(result.is_panicked());
        assert_eq!(result.stages_executed(), 3); // All stages were attempted
    }

    #[test]
    fn pipeline_result_into_outcome() {
        let completed: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
        assert!(matches!(completed.into_outcome(), Outcome::Ok(42)));

        let failed: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(0, 1));
        assert!(matches!(failed.into_outcome(), Outcome::Err("error")));

        let cancelled: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(0, 1));
        assert!(cancelled.into_outcome().is_cancelled());

        let panicked: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("oops"), FailedStage::new(0, 1));
        assert!(panicked.into_outcome().is_panicked());
    }

    // =========================================================================
    // stage_outcome_to_result Tests
    // =========================================================================

    #[test]
    fn stage_outcome_ok_returns_none() {
        let result = stage_outcome_to_result::<i32, &str>(Outcome::Ok(42), 0, 3);
        assert!(result.is_none());
    }

    #[test]
    fn stage_outcome_err_returns_failed() {
        let result = stage_outcome_to_result::<i32, &str>(Outcome::Err("error"), 1, 3);
        assert!(result.is_some());
        assert!(result.unwrap().is_failed());
    }

    #[test]
    fn stage_outcome_cancelled_returns_cancelled() {
        let result = stage_outcome_to_result::<i32, &str>(
            Outcome::Cancelled(CancelReason::shutdown()),
            2,
            3,
        );
        assert!(result.is_some());
        assert!(result.unwrap().is_cancelled());
    }

    #[test]
    fn stage_outcome_panicked_returns_panicked() {
        let result = stage_outcome_to_result::<i32, &str>(
            Outcome::Panicked(PanicPayload::new("boom")),
            0,
            3,
        );
        assert!(result.is_some());
        assert!(result.unwrap().is_panicked());
    }

    // =========================================================================
    // pipeline2_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline2_both_ok() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Ok(2)));

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 2);
            assert_eq!(stages_completed, 2);
        } else {
            panic!("Expected Completed");
        }
    }

    #[test]
    fn pipeline2_first_fails() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Err("stage1 error"), None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "stage1 error");
            assert!(failed_at.is_first());
        } else {
            panic!("Expected Failed");
        }
    }

    #[test]
    fn pipeline2_second_fails() {
        let result = pipeline2_outcomes(Outcome::Ok(1), Some(Outcome::Err("stage2 error")));

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "stage2 error");
            assert!(failed_at.is_last());
            assert_eq!(failed_at.index, 1);
        } else {
            panic!("Expected Failed");
        }
    }

    #[test]
    fn pipeline2_first_cancelled() {
        let result =
            pipeline2_outcomes::<i32, &str>(Outcome::Cancelled(CancelReason::shutdown()), None);

        assert!(result.is_cancelled());
    }

    #[test]
    fn pipeline2_panicked_when_o2_missing() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Ok(1), None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(payload.message(), "o2 must be provided when o1 succeeds");
            assert_eq!(panicked_at.index, 1);
        } else {
            panic!("Expected Panicked");
        }
    }

    // =========================================================================
    // pipeline3_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline3_all_ok() {
        let result = pipeline3_outcomes::<i32, &str>(
            Outcome::<i32, &str>::Ok(1),
            Some(Outcome::Ok(2)),
            Some(Outcome::Ok(3)),
        );

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 3);
            assert_eq!(stages_completed, 3);
        } else {
            panic!("Expected Completed");
        }
    }

    #[test]
    fn pipeline3_first_fails() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Err("s1"), None, None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 0);
        }
    }

    #[test]
    fn pipeline3_second_fails() {
        let result =
            pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Err("s2")), None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 1);
        }
    }

    #[test]
    fn pipeline3_third_fails() {
        let result = pipeline3_outcomes(
            Outcome::Ok(1),
            Some(Outcome::Ok(2)),
            Some(Outcome::Err("s3")),
        );

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert!(failed_at.is_last());
        }
    }

    #[test]
    fn pipeline3_panicked_when_o2_missing() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), None, None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(payload.message(), "o2 must be provided when o1 succeeds");
            assert_eq!(panicked_at.index, 1);
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    fn pipeline3_panicked_when_o3_missing() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Ok(2)), None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(
                payload.message(),
                "o3 must be provided when o1 and o2 succeed"
            );
            assert_eq!(panicked_at.index, 2);
        } else {
            panic!("Expected Panicked");
        }
    }

    // =========================================================================
    // pipeline_with_final Tests
    // =========================================================================

    #[test]
    fn pipeline_with_final_all_ok() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_completed());
        if let PipelineResult::Completed { value, .. } = result {
            assert_eq!(value, 42);
        }
    }

    #[test]
    fn pipeline_with_final_intermediate_fails() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Err("mid fail")];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 1);
        }
    }

    #[test]
    fn pipeline_with_final_final_fails() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(intermediates, Outcome::Err("final fail"), 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert!(failed_at.is_last());
        }
    }

    // =========================================================================
    // pipeline_to_result Tests
    // =========================================================================

    #[test]
    fn pipeline_to_result_completed() {
        let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
        assert_eq!(pipeline_to_result(result).unwrap(), 42);
    }

    #[test]
    fn pipeline_to_result_failed() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(1, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::StageError { .. }));
    }

    #[test]
    fn pipeline_to_result_cancelled() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(0, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::Cancelled { .. }));
    }

    #[test]
    fn pipeline_to_result_panicked() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("boom"), FailedStage::new(2, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::Panicked { .. }));
    }

    // =========================================================================
    // PipelineError Tests
    // =========================================================================

    #[test]
    fn pipeline_error_display_stage_error() {
        let err: PipelineError<&str> = PipelineError::StageError {
            error: "test error",
            stage: FailedStage::new(1, 3),
        };
        let display = err.to_string();
        assert!(display.contains("stage 2/3"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn pipeline_error_display_cancelled() {
        let err: PipelineError<&str> = PipelineError::Cancelled {
            reason: CancelReason::shutdown(),
            stage: FailedStage::new(0, 2),
        };
        let display = err.to_string();
        assert!(display.contains("cancelled"));
        assert!(display.contains("stage 1/2"));
    }

    #[test]
    fn pipeline_error_display_panicked() {
        let err: PipelineError<&str> = PipelineError::Panicked {
            payload: PanicPayload::new("boom"),
            stage: FailedStage::new(2, 3),
        };
        let display = err.to_string();
        assert!(display.contains("panicked"));
        assert!(display.contains("boom"));
    }

    // =========================================================================
    // Invariant Tests
    // =========================================================================

    #[test]
    fn error_short_circuits_at_first_failure() {
        // Simulate a 5-stage pipeline where stage 2 fails
        let intermediates: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Ok(2),
            Outcome::Err("stage 3 failed"),
            // Stages 4 and 5 should never be reached
        ];
        // Using pipeline_with_final with a dummy final outcome
        // since we expect to short-circuit at stage 2
        let result = pipeline_with_final(intermediates, Outcome::Ok(999), 5);

        assert!(result.is_failed());
        assert_eq!(result.stages_executed(), 3); // Executed stages 0, 1, 2
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert_eq!(failed_at.total_stages, 5);
        }
    }

    #[test]
    fn cancelled_stops_at_boundary() {
        let intermediates: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::shutdown())];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_cancelled());
        // Stage 0 succeeded, stage 1 cancelled
        if let PipelineResult::Cancelled { cancelled_at, .. } = result {
            assert_eq!(cancelled_at.index, 1);
        }
    }

    #[test]
    fn stages_executed_reflects_actual_execution() {
        // All stages complete
        let completed: PipelineResult<i32, &str> = PipelineResult::completed(42, 5);
        assert_eq!(completed.stages_executed(), 5);

        // Failed at stage 2 (index 1)
        let failed: PipelineResult<i32, &str> =
            PipelineResult::failed("err", FailedStage::new(1, 5));
        assert_eq!(failed.stages_executed(), 2); // Stages 0 and 1 were executed

        // Cancelled before stage 3 (index 2)
        let cancelled: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(2, 5));
        assert_eq!(cancelled.stages_executed(), 2); // Stages 0 and 1 completed
    }
}
