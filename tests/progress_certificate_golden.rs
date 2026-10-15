#![allow(warnings)]
#![allow(clippy::all)]
//! Golden snapshots for progress-certificate verdict serialization.

use asupersync::cancel::progress_certificate::{
    CertificateVerdict, ProgressCertificate, ProgressConfig,
};
use insta::assert_json_snapshot;
use serde_json::json;

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

fn snapshot_verdict(sequence: &[f64], config: ProgressConfig) -> serde_json::Value {
    let mut certificate = ProgressCertificate::new(config.clone());
    for &potential in sequence {
        certificate.observe(potential);
    }

    let verdict = certificate.verdict();
    verdict_to_json(sequence, &config, &verdict)
}

fn verdict_to_json(
    sequence: &[f64],
    config: &ProgressConfig,
    verdict: &CertificateVerdict,
) -> serde_json::Value {
    json!({
        "sequence": sequence.iter().map(|value| round6(*value)).collect::<Vec<_>>(),
        "config": {
            "confidence": round6(config.confidence),
            "max_step_bound": round6(config.max_step_bound),
            "stall_threshold": config.stall_threshold,
            "min_observations": config.min_observations,
            "epsilon": round6(config.epsilon),
        },
        "verdict": {
            "converging": verdict.converging,
            "stall_detected": verdict.stall_detected,
            "total_steps": verdict.total_steps,
            "current_potential": round6(verdict.current_potential),
            "initial_potential": round6(verdict.initial_potential),
            "mean_credit": round6(verdict.mean_credit),
            "max_observed_step": round6(verdict.max_observed_step),
            "confidence_bound": round6(verdict.confidence_bound),
            "azuma_bound": round6(verdict.azuma_bound),
            "freedman_bound": round6(verdict.freedman_bound),
            "estimated_remaining_steps": verdict.estimated_remaining_steps.map(round6),
            "empirical_variance": verdict.empirical_variance.map(round6),
            "drain_phase": verdict.drain_phase.to_string(),
            "evidence": verdict.evidence.iter().map(|entry| {
                json!({
                    "step": entry.step,
                    "potential": round6(entry.potential),
                    "bound": round6(entry.bound),
                    "description": entry.description,
                })
            }).collect::<Vec<_>>(),
            "rendered": verdict.to_string(),
        }
    })
}

#[test]
fn progress_certificate_happy_path_snapshot() {
    let config = ProgressConfig {
        confidence: 0.95,
        max_step_bound: 40.0,
        stall_threshold: 4,
        min_observations: 4,
        epsilon: 1e-9,
    };

    assert_json_snapshot!(
        "progress_certificate_happy_path",
        snapshot_verdict(&[120.0, 86.0, 52.0, 25.0, 9.0, 0.0], config)
    );
}

#[test]
fn progress_certificate_cancel_during_drain_snapshot() {
    let config = ProgressConfig {
        confidence: 0.9,
        max_step_bound: 35.0,
        stall_threshold: 3,
        min_observations: 4,
        epsilon: 1e-9,
    };

    assert_json_snapshot!(
        "progress_certificate_cancel_during_drain",
        snapshot_verdict(&[100.0, 68.0, 42.0, 42.0, 41.5, 18.0, 4.0, 0.0], config)
    );
}

#[test]
fn progress_certificate_budget_exceeded_snapshot() {
    let config = ProgressConfig {
        confidence: 0.9,
        max_step_bound: 5.0,
        stall_threshold: 3,
        min_observations: 4,
        epsilon: 1e-9,
    };

    assert_json_snapshot!(
        "progress_certificate_budget_exceeded",
        snapshot_verdict(&[40.0, 52.0, 57.0, 61.0, 61.0, 61.0], config)
    );
}
