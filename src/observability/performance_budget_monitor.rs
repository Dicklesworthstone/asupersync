//! Real-time performance budget evaluation and alerting.
//!
//! This module provides a deterministic budget monitor that converts explicit
//! metric samples into warning/critical alerts and an aggregate headroom signal
//! suitable for propagating through [`crate::types::SystemPressure`].
//!
//! The monitor is intentionally simple:
//! - Callers register named budgets once.
//! - Callers feed explicit sampled values tagged by budget id.
//! - The monitor returns a stable snapshot of evaluations and alerts.
//! - If configured with a [`crate::types::SystemPressure`] handle, the monitor
//!   also updates the shared headroom signal to the worst sampled budget.

use crate::types::SystemPressure;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Direction of a budget constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDirection {
    /// Sampled values must stay at or below the threshold.
    UpperBound,
    /// Sampled values must stay at or above the threshold.
    LowerBound,
}

/// Severity classification for a sampled budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BudgetSeverity {
    /// The sample remains comfortably inside the budget.
    Healthy,
    /// The sample is approaching the budget boundary.
    Warning,
    /// The sample has crossed the budget boundary.
    Critical,
}

/// A registered performance budget definition.
#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceBudget {
    /// Stable budget identifier.
    pub id: String,
    /// Component or subsystem name surfaced in alerts.
    pub component: String,
    /// Metric name, such as `p99_latency_ms` or `throughput_ops_per_sec`.
    pub metric: String,
    /// Constraint direction.
    pub direction: BudgetDirection,
    /// Hard budget threshold.
    pub threshold: f64,
    /// Warning margin expressed as a fraction of the threshold.
    ///
    /// For an upper-bound budget this warns once the sample crosses
    /// `threshold * (1 - warning_margin)`.
    ///
    /// For a lower-bound budget this warns once the sample drops below
    /// `threshold * (1 + warning_margin)`.
    pub warning_margin: f64,
    /// Optional operator guidance emitted with alerts.
    pub recommendation: String,
}

impl PerformanceBudget {
    /// Create a new budget definition.
    #[must_use]
    pub fn new(
        id: &str,
        component: &str,
        metric: &str,
        direction: BudgetDirection,
        threshold: f64,
    ) -> Self {
        assert!(!id.trim().is_empty(), "budget id must not be empty");
        assert!(
            !component.trim().is_empty(),
            "budget component must not be empty"
        );
        assert!(!metric.trim().is_empty(), "budget metric must not be empty");
        assert!(
            threshold.is_finite() && threshold > 0.0,
            "budget threshold must be positive and finite"
        );
        Self {
            id: id.trim().to_string(),
            component: component.trim().to_string(),
            metric: metric.trim().to_string(),
            direction,
            threshold,
            warning_margin: 0.10,
            recommendation: String::new(),
        }
    }

    /// Override the warning margin.
    #[must_use]
    pub fn with_warning_margin(mut self, warning_margin: f64) -> Self {
        assert!(
            warning_margin.is_finite() && (0.0..1.0).contains(&warning_margin),
            "warning_margin must be finite and in [0.0, 1.0)"
        );
        self.warning_margin = warning_margin;
        self
    }

    /// Attach human-readable operator guidance.
    #[must_use]
    pub fn with_recommendation(mut self, recommendation: &str) -> Self {
        self.recommendation = recommendation.trim().to_string();
        self
    }
}

/// A sampled value for a registered budget.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetSample {
    /// Budget id that this sample applies to.
    pub budget_id: String,
    /// Sampled value.
    pub observed: f64,
}

impl BudgetSample {
    /// Create a new budget sample.
    #[must_use]
    pub fn new(budget_id: &str, observed: f64) -> Self {
        assert!(
            !budget_id.trim().is_empty(),
            "sample budget id must not be empty"
        );
        assert!(
            observed.is_finite() && observed >= 0.0,
            "sample value must be finite and non-negative"
        );
        Self {
            budget_id: budget_id.trim().to_string(),
            observed,
        }
    }
}

/// Per-budget evaluation result.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetEvaluation {
    /// Registered budget id.
    pub budget_id: String,
    /// Component name.
    pub component: String,
    /// Metric name.
    pub metric: String,
    /// Observed sample value.
    pub observed: f64,
    /// Hard threshold.
    pub threshold: f64,
    /// Severity classification.
    pub severity: BudgetSeverity,
    /// Remaining normalized headroom in `[0.0, 1.0]`.
    pub headroom: f32,
}

/// Alert emitted for warning or critical budgets.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetAlert {
    /// Sequence identifier supplied by the caller.
    pub sequence: u64,
    /// Registered budget id.
    pub budget_id: String,
    /// Component name.
    pub component: String,
    /// Metric name.
    pub metric: String,
    /// Severity classification.
    pub severity: BudgetSeverity,
    /// Observed sample value.
    pub observed: f64,
    /// Hard threshold.
    pub threshold: f64,
    /// Optional operator guidance.
    pub recommendation: String,
}

/// Snapshot of the monitor after a single evaluation pass.
#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceBudgetSnapshot {
    /// Sequence identifier supplied by the caller.
    pub sequence: u64,
    /// Per-budget evaluations sorted by budget id.
    pub evaluations: Vec<BudgetEvaluation>,
    /// Active alerts sorted by severity then budget id.
    pub alerts: Vec<BudgetAlert>,
    /// Worst severity observed in this evaluation pass.
    pub worst_severity: BudgetSeverity,
    /// Worst normalized headroom observed in this evaluation pass.
    pub worst_headroom: f32,
}

/// Deterministic real-time budget evaluator.
#[derive(Debug, Default)]
pub struct PerformanceBudgetMonitor {
    budgets: BTreeMap<String, PerformanceBudget>,
    pressure: Option<Arc<SystemPressure>>,
}

impl PerformanceBudgetMonitor {
    /// Create an empty budget monitor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a shared [`SystemPressure`] handle that receives the worst
    /// headroom from each evaluation pass.
    #[must_use]
    pub fn with_pressure(mut self, pressure: Arc<SystemPressure>) -> Self {
        self.pressure = Some(pressure);
        self
    }

    /// Register a budget definition.
    ///
    /// A later registration with the same id replaces the previous definition.
    pub fn register_budget(&mut self, budget: PerformanceBudget) {
        self.budgets.insert(budget.id.clone(), budget);
    }

    /// Evaluate a batch of samples and return a deterministic snapshot.
    #[must_use]
    pub fn evaluate(&self, sequence: u64, samples: &[BudgetSample]) -> PerformanceBudgetSnapshot {
        let mut sample_map = BTreeMap::new();
        for sample in samples {
            sample_map.insert(sample.budget_id.as_str(), sample);
        }

        let mut evaluations = Vec::new();
        let mut alerts = Vec::new();
        let mut worst_severity = BudgetSeverity::Healthy;
        let mut worst_headroom = 1.0_f32;

        for (budget_id, budget) in &self.budgets {
            let Some(sample) = sample_map.get(budget_id.as_str()) else {
                continue;
            };

            let (severity, headroom) = classify_budget(budget, sample.observed);
            let evaluation = BudgetEvaluation {
                budget_id: budget.id.clone(),
                component: budget.component.clone(),
                metric: budget.metric.clone(),
                observed: sample.observed,
                threshold: budget.threshold,
                severity,
                headroom,
            };
            worst_severity = worst_severity.max(severity);
            worst_headroom = worst_headroom.min(headroom);
            if severity != BudgetSeverity::Healthy {
                alerts.push(BudgetAlert {
                    sequence,
                    budget_id: budget.id.clone(),
                    component: budget.component.clone(),
                    metric: budget.metric.clone(),
                    severity,
                    observed: sample.observed,
                    threshold: budget.threshold,
                    recommendation: budget.recommendation.clone(),
                });
            }
            evaluations.push(evaluation);
        }

        alerts.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.budget_id.cmp(&right.budget_id))
        });

        if let Some(pressure) = &self.pressure {
            pressure.set_headroom(worst_headroom);
        }

        PerformanceBudgetSnapshot {
            sequence,
            evaluations,
            alerts,
            worst_severity,
            worst_headroom,
        }
    }
}

fn classify_budget(budget: &PerformanceBudget, observed: f64) -> (BudgetSeverity, f32) {
    match budget.direction {
        BudgetDirection::UpperBound => classify_upper_bound(budget, observed),
        BudgetDirection::LowerBound => classify_lower_bound(budget, observed),
    }
}

fn classify_upper_bound(budget: &PerformanceBudget, observed: f64) -> (BudgetSeverity, f32) {
    let warning_level = budget.threshold * (1.0 - budget.warning_margin);
    if observed > budget.threshold {
        return (BudgetSeverity::Critical, 0.0);
    }
    if observed <= warning_level {
        return (BudgetSeverity::Healthy, 1.0);
    }
    let span = budget.threshold - warning_level;
    let headroom = ((budget.threshold - observed) / span).clamp(0.0, 1.0) as f32;
    (BudgetSeverity::Warning, headroom)
}

fn classify_lower_bound(budget: &PerformanceBudget, observed: f64) -> (BudgetSeverity, f32) {
    let warning_level = budget.threshold * (1.0 + budget.warning_margin);
    if observed < budget.threshold {
        return (BudgetSeverity::Critical, 0.0);
    }
    if observed >= warning_level {
        return (BudgetSeverity::Healthy, 1.0);
    }
    let span = warning_level - budget.threshold;
    let headroom = ((observed - budget.threshold) / span).clamp(0.0, 1.0) as f32;
    (BudgetSeverity::Warning, headroom)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn upper_bound_budget_transitions_from_healthy_to_critical() {
        let pressure = Arc::new(SystemPressure::new());
        let mut monitor = PerformanceBudgetMonitor::new().with_pressure(pressure.clone());
        monitor.register_budget(
            PerformanceBudget::new(
                "sched.p99_latency_ms",
                "scheduler",
                "p99_latency_ms",
                BudgetDirection::UpperBound,
                10.0,
            )
            .with_warning_margin(0.20)
            .with_recommendation("inspect queue contention"),
        );

        let healthy = monitor.evaluate(1, &[BudgetSample::new("sched.p99_latency_ms", 7.0)]);
        assert_eq!(healthy.worst_severity, BudgetSeverity::Healthy);
        assert!(healthy.alerts.is_empty());
        assert!((pressure.headroom() - 1.0).abs() < f32::EPSILON);

        let warning = monitor.evaluate(2, &[BudgetSample::new("sched.p99_latency_ms", 8.5)]);
        assert_eq!(warning.worst_severity, BudgetSeverity::Warning);
        assert_eq!(warning.alerts.len(), 1);
        assert_eq!(warning.alerts[0].severity, BudgetSeverity::Warning);
        assert!(pressure.headroom() < 1.0);
        assert!(pressure.headroom() > 0.0);

        let critical = monitor.evaluate(3, &[BudgetSample::new("sched.p99_latency_ms", 12.0)]);
        assert_eq!(critical.worst_severity, BudgetSeverity::Critical);
        assert_eq!(critical.alerts.len(), 1);
        assert_eq!(critical.alerts[0].severity, BudgetSeverity::Critical);
        assert!(pressure.headroom().abs() < f32::EPSILON);
    }

    #[test]
    fn lower_bound_budget_warns_before_falling_below_threshold() {
        let mut monitor = PerformanceBudgetMonitor::new();
        monitor.register_budget(
            PerformanceBudget::new(
                "codec.throughput_ops_per_sec",
                "codec",
                "throughput_ops_per_sec",
                BudgetDirection::LowerBound,
                1_000.0,
            )
            .with_warning_margin(0.10),
        );

        let warning = monitor.evaluate(
            7,
            &[BudgetSample::new("codec.throughput_ops_per_sec", 1_050.0)],
        );
        assert_eq!(warning.worst_severity, BudgetSeverity::Warning);
        assert_eq!(warning.alerts.len(), 1);
        assert_eq!(warning.alerts[0].severity, BudgetSeverity::Warning);

        let critical = monitor.evaluate(
            8,
            &[BudgetSample::new("codec.throughput_ops_per_sec", 980.0)],
        );
        assert_eq!(critical.worst_severity, BudgetSeverity::Critical);
        assert_eq!(critical.alerts.len(), 1);
        assert_eq!(critical.alerts[0].severity, BudgetSeverity::Critical);
        assert!(critical.worst_headroom.abs() < f32::EPSILON);
    }

    #[test]
    fn alerts_are_sorted_by_severity_then_budget_id() {
        let mut monitor = PerformanceBudgetMonitor::new();
        monitor.register_budget(PerformanceBudget::new(
            "b.latency",
            "network",
            "latency_ms",
            BudgetDirection::UpperBound,
            5.0,
        ));
        monitor.register_budget(
            PerformanceBudget::new(
                "a.throughput",
                "network",
                "throughput_ops_per_sec",
                BudgetDirection::LowerBound,
                100.0,
            )
            .with_warning_margin(0.25),
        );

        let snapshot = monitor.evaluate(
            11,
            &[
                BudgetSample::new("b.latency", 7.0),
                BudgetSample::new("a.throughput", 110.0),
            ],
        );

        assert_eq!(snapshot.alerts.len(), 2);
        assert_eq!(snapshot.alerts[0].budget_id, "b.latency");
        assert_eq!(snapshot.alerts[0].severity, BudgetSeverity::Critical);
        assert_eq!(snapshot.alerts[1].budget_id, "a.throughput");
        assert_eq!(snapshot.alerts[1].severity, BudgetSeverity::Warning);
    }

    #[test]
    fn unknown_budget_samples_are_ignored() {
        let mut monitor = PerformanceBudgetMonitor::new();
        monitor.register_budget(PerformanceBudget::new(
            "runtime.queue_depth",
            "runtime",
            "queue_depth",
            BudgetDirection::UpperBound,
            1_000.0,
        ));

        let snapshot = monitor.evaluate(13, &[BudgetSample::new("other.metric", 123.0)]);
        assert!(snapshot.evaluations.is_empty());
        assert!(snapshot.alerts.is_empty());
        assert_eq!(snapshot.worst_severity, BudgetSeverity::Healthy);
        assert!((snapshot.worst_headroom - 1.0).abs() < f32::EPSILON);
    }
}
