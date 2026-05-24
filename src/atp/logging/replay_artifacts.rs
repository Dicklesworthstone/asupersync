//! ATP replay artifact contract.
//!
//! Replay artifacts are intentionally plain data: callers gather traces,
//! qlog/path/repair/journal files, and proof bundle references, then serialize
//! this contract into failure bundles or release-proof outputs.

use serde::{Deserialize, Serialize};

use super::AtpLoggerConfig;

/// Stable ATP replay-artifact schema id.
pub const ATP_REPLAY_ARTIFACT_SCHEMA_ID: &str = "asupersync.atp.replay_artifacts.v1";

/// Replay artifact bundle for deterministic ATP failure reproduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayArtifacts {
    /// Stable schema id for machine validation.
    pub schema_id: String,
    /// Contract schema version.
    pub schema_version: u32,
    /// ATP session that produced the artifacts.
    pub session_id: String,
    /// Deterministic seed used by the lab/runtime lane.
    pub seed: u64,
    /// Command that should reproduce the failure.
    pub replay_command: String,
    /// Structured trace artifact path or identifier.
    pub trace_artifact: String,
    /// QUIC qlog-ish artifact path or identifier.
    pub qlog_artifact: String,
    /// Path-racing diagnostic artifact path or identifier.
    pub pathlog_artifact: String,
    /// RaptorQ repair diagnostic artifact path or identifier.
    pub repairlog_artifact: String,
    /// Journal digest artifact path or identifier.
    pub journal_digest_artifact: String,
    /// Proof bundle artifact path or identifier.
    pub proof_bundle_artifact: String,
    /// Environment summary needed for replay.
    pub environment_summary: ReplayEnvironment,
}

/// Environment fields that are safe to share in replay artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEnvironment {
    /// Target operating system family.
    pub os: String,
    /// Target architecture.
    pub arch: String,
    /// Whether redaction was enabled when the artifact was created.
    pub redaction_enabled: bool,
}

/// Generate a deterministic replay artifact contract for a session.
#[must_use]
pub fn generate(session_id: &str, seed: u64, config: &AtpLoggerConfig) -> ReplayArtifacts {
    let safe_session = sanitize_identifier(session_id);
    ReplayArtifacts {
        schema_id: ATP_REPLAY_ARTIFACT_SCHEMA_ID.to_string(),
        schema_version: 1,
        session_id: safe_session.clone(),
        seed,
        replay_command: format!("atp replay --session {safe_session} --seed {seed}"),
        trace_artifact: format!("{safe_session}/trace.jsonl"),
        qlog_artifact: format!("{safe_session}/quic.qlog.json"),
        pathlog_artifact: format!("{safe_session}/pathlog.json"),
        repairlog_artifact: format!("{safe_session}/repairlog.json"),
        journal_digest_artifact: format!("{safe_session}/journal.digest.json"),
        proof_bundle_artifact: format!("{safe_session}/proof.bundle.json"),
        environment_summary: ReplayEnvironment {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            redaction_enabled: config.redaction_enabled,
        },
    }
}

fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_artifacts_include_reproduction_context() {
        let artifacts = generate("session:ATP-N6", 42, &AtpLoggerConfig::default());

        assert_eq!(artifacts.schema_id, ATP_REPLAY_ARTIFACT_SCHEMA_ID);
        assert_eq!(artifacts.schema_version, 1);
        assert_eq!(artifacts.session_id, "session_ATP-N6");
        assert_eq!(
            artifacts.replay_command,
            "atp replay --session session_ATP-N6 --seed 42"
        );
        assert_eq!(artifacts.trace_artifact, "session_ATP-N6/trace.jsonl");
        assert_eq!(artifacts.qlog_artifact, "session_ATP-N6/quic.qlog.json");
        assert_eq!(artifacts.pathlog_artifact, "session_ATP-N6/pathlog.json");
        assert_eq!(
            artifacts.repairlog_artifact,
            "session_ATP-N6/repairlog.json"
        );
        assert_eq!(
            artifacts.journal_digest_artifact,
            "session_ATP-N6/journal.digest.json"
        );
        assert_eq!(
            artifacts.proof_bundle_artifact,
            "session_ATP-N6/proof.bundle.json"
        );
    }
}
