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
