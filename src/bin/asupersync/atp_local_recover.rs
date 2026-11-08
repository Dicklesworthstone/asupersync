//! Freshly reviewed restoration from saved local ATP application receipts.

use super::atp_local_mirror::{DirectoryLimitsArgs, parse_review_id};
use asupersync::cli::{CliError, ExitCode, Output};
use clap::{ArgAction, Args};
use std::path::PathBuf;

#[derive(Args, Debug)]
#[command(
    long_about = "Preview restoration of originals retained by an earlier local-sync or \
        local-mirror application. RECEIPT is its saved JSON application report. LOCAL and \
        REMOTE are the original roots in their original order (SOURCE and DESTINATION \
        for a mirror). Linux/glibc only. The default scans current retained originals \
        and destinations and displays a new recovery review without changing files.",
    after_long_help = "Inspect every freshly captured content identity, then apply with \
        --apply REVIEW_ID from that recovery preview. A receipt supplies associations, \
        not authenticity or permission to overwrite. RECEIPT must be a regular file; \
        its final path component must not be a symlink. Existing destination files require \
        BOTH --allow-overwrite and --allow-permission-change and are atomically exchanged \
        into the retained quarantine. Missing destinations are restored without copying \
        bytes. Both roots and the recovery job must be exclusively owned during the \
        command. Only quarantined originals are restored: newly copied files remain and \
        persistent local-sync history is not rewound. This is not whole-tree rollback or \
        unattended crash replay. Retain both the original receipt and the recovery receipt."
)]
pub(super) struct RecoverArgs {
    /// Saved JSON application receipt, recovery source, or output_error with context.receipt
    #[arg(value_name = "RECEIPT")]
    receipt: PathBuf,
    /// Original local root (the authoritative source for local-mirror)
    #[arg(value_name = "LOCAL")]
    local: PathBuf,
    /// Original remote root (the destination for local-mirror)
    #[arg(value_name = "REMOTE")]
    remote: PathBuf,
    /// Restore only if current originals and destinations match this recovery review
    #[arg(long, value_name = "REVIEW_ID", value_parser = parse_review_id)]
    apply: Option<String>,
    /// Authorize exchanging an existing file into retained quarantine
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_overwrite: bool,
    /// Accept the restored original's metadata instead of the current file's metadata
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_permission_change: bool,
    /// Bound actual receipt bytes before JSON decoding (1..=67108864)
    #[arg(long, default_value_t = 16_777_216, value_parser = parse_receipt_bound)]
    max_receipt_bytes: usize,
    #[command(flatten)]
    limits: DirectoryLimitsArgs,
}

fn parse_receipt_bound(value: &str) -> Result<usize, String> {
    value.parse::<usize>()
        .ok()
        .filter(|bound| (1..=64 * 1024 * 1024).contains(bound))
        .ok_or_else(|| "receipt byte bound must be in 1..=67108864".to_owned())
}

pub(super) fn run(args: &RecoverArgs, output: &mut Output) -> Result<(), CliError> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        native::run(args, output)
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (args, output);
        Err(CliError::new(
            "atp_local_recover_unsupported",
            "Local directory recovery requires Linux/glibc",
        )
        .exit_code(ExitCode::USER_ERROR))
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod native {
    use super::{CliError, ExitCode, Output, RecoverArgs};
    use super::super::atp_local_mirror::native::{
        CONTENT_PROFILE, current_cx, native_error, require_shutdown, run_owned,
        validate_path, write_receipt,
    };
    use asupersync::atp::sync::native::{
        NativeDirectoryRecoveryReceipt, NativeDirectoryRecoveryReport,
        NativeDirectoryRecoverySource, NativeDirectoryRecoverySourceAction,
        NativeDirectoryRecoveryState, prepare_native_directory_recovery_from_source,
    };
    use asupersync::atp::sync::{DestructiveAuthorization, DirectoryManifestEntry};
    use asupersync::cli::Outputtable;
    use serde::Deserialize;
    use std::fmt::Write as _;
    use std::io;
    use std::path::PathBuf;

    #[derive(Debug, serde::Serialize)]
    struct RecoveryOutput {
        schema_version: u32,
        command: &'static str,
        mode: &'static str,
        content_profile: &'static str,
        receipt: PathBuf,
        source_plan_id: String,
        review_id: String,
        local_root: PathBuf,
        remote_root: PathBuf,
        recovery_directory: PathBuf,
        has_overwrites: bool,
        entries: Vec<EntryOutput>,
        result: Option<ApplicationOutput>,
        application_error: Option<String>,
        runtime_quiescent: bool,
        runtime_stopped: bool,
    }

    #[derive(Debug, serde::Serialize)]
    struct EntryOutput {
        path: String,
        destination_root: PathBuf,
        quarantine_path: PathBuf,
        quarantined: DirectoryManifestEntry,
        current: Option<DirectoryManifestEntry>,
    }

    #[derive(Debug, serde::Serialize)]
    struct ApplicationOutput {
        source_plan_id: String,
        complete: bool,
        dry_run: bool,
        failure: Option<String>,
        actions: Vec<ActionOutput>,
    }

    #[derive(Debug, serde::Serialize)]
    struct ActionOutput {
        path: String,
        destination_root: PathBuf,
        quarantine_path: PathBuf,
        state: &'static str,
        durable: bool,
    }

    impl From<NativeDirectoryRecoveryReceipt> for ActionOutput {
        fn from(receipt: NativeDirectoryRecoveryReceipt) -> Self {
            Self {
                path: receipt.path.as_str().to_owned(),
                destination_root: receipt.destination_root,
                quarantine_path: receipt.quarantine_path,
                state: match receipt.state {
                    NativeDirectoryRecoveryState::NotStarted => "not_started",
                    NativeDirectoryRecoveryState::Restored => "restored",
                    NativeDirectoryRecoveryState::Exchanged => "exchanged",
                    _ => "unknown",
                },
                durable: receipt.durable,
            }
        }
    }

    impl From<NativeDirectoryRecoveryReport> for ApplicationOutput {
        fn from(report: NativeDirectoryRecoveryReport) -> Self {
            Self {
                source_plan_id: report.source_plan_id,
                complete: report.complete,
                dry_run: report.dry_run,
                failure: report.failure.map(|error| error.to_string()),
                actions: report.actions.into_iter().map(ActionOutput::from).collect(),
            }
        }
    }

    impl Outputtable for RecoveryOutput {
        fn human_format(&self) -> String {
            let mut text = format!(
                "Local recovery {}\n  Original operation: {}\n  Review ID: {}\n  Local: {}\n  Remote: {}\n  Recovery directory: {}\n",
                self.mode, self.source_plan_id, self.review_id,
                self.local_root.display(), self.remote_root.display(),
                self.recovery_directory.display(),
            );
            for entry in &self.entries {
                let effect = if entry.current.is_some() {
                    "exchange; overwrite and permission-change grants required"
                } else {
                    "restore absent destination"
                };
                let _ = writeln!(text, "  {}: {} ({effect})",
                    entry.destination_root.display(), entry.path);
                let _ = writeln!(text, "    Retained: {}", entry.quarantine_path.display());
                let _ = writeln!(text, "    Captured original: {:?}", entry.quarantined);
                let _ = writeln!(text, "    Captured destination: {:?}", entry.current);
            }
            if let Some(result) = &self.result {
                let _ = writeln!(text, "  Complete and verified: {}", result.complete);
                for action in &result.actions {
                    let _ = writeln!(text, "  {}: {} (durable: {})",
                        action.path, action.state, action.durable);
                    if action.state == "exchanged" {
                        let _ = writeln!(text, "    Displaced current file retained at: {}",
                            action.quarantine_path.display());
                    }
                }
                if let Some(error) = &result.failure {
                    let _ = writeln!(text, "  Failure: {error}");
                }
            } else if self.mode == "plan" {
                text.push_str("  Preview only. Review captured contents before --apply REVIEW_ID.\n");
            }
            if let Some(error) = &self.application_error {
                let _ = writeln!(text, "  Application was not confirmed: {error}");
            }
            text.push_str("  New files from the earlier operation remain; synchronization history is not rewound.\n");
            if !self.runtime_quiescent || !self.runtime_stopped {
                text.push_str("  Runtime cleanup was not confirmed.\n");
            }
            text
        }
    }

    pub(super) fn run(args: &RecoverArgs, output: &mut Output) -> Result<(), CliError> {
        validate_path("receipt", &args.receipt)?;
        validate_path("local", &args.local)?;
        validate_path("remote", &args.remote)?;
        let (mut report, quiescent, stopped) = run_owned(prepare_and_apply(args))?;
        report.runtime_quiescent = quiescent;
        report.runtime_stopped = stopped;
        write_receipt(output, &report)?;
        if args.apply.is_some()
            && !report.result.as_ref().is_some_and(|result| {
                result.complete && !result.dry_run && result.failure.is_none()
            })
        {
            let detail = report.application_error.as_deref()
                .or_else(|| report.result.as_ref().and_then(|result| result.failure.as_deref()))
                .unwrap_or("The recovery did not return a complete verified restoration receipt");
            return Err(CliError::new("atp_local_recover_incomplete", "Local recovery did not complete")
                .detail(detail)
                .context("source_plan_id", &report.source_plan_id)
                .context("review_id", &report.review_id)
                .exit_code(ExitCode::USER_ERROR));
        }
        require_shutdown(quiescent, stopped)
    }

    async fn prepare_and_apply(args: &RecoverArgs) -> Result<RecoveryOutput, CliError> {
        let cx = current_cx()?;
        let bytes = cx.scoped_fs().read_regular_bounded(args.receipt.clone(), args.max_receipt_bytes)
            .await.map_err(|error| CliError::new(
                "atp_local_recover_receipt", "Cannot read the complete bounded recovery receipt",
            ).detail(error.to_string()).exit_code(ExitCode::USER_ERROR))?;
        // Parsing runs in the same owned blocking facility as filesystem work;
        // cancellation drains its buffer and worker before the CLI returns.
        let source = cx.scoped_fs().run_io(move |child| {
            let source = decode_receipt(&bytes)?;
            child.checkpoint()
                .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error))?;
            Ok(source)
        }).await.map_err(|error| CliError::new(
            "atp_local_recover_receipt", "Invalid saved recovery receipt",
        ).detail(error.to_string()).exit_code(ExitCode::USER_ERROR))?;
        let prepared = prepare_native_directory_recovery_from_source(
            &cx, &source, &args.local, &args.remote, args.limits.native(),
        ).await.map_err(|error| native_error("recovery_prepare", error))?;
        let recovery_directory = prepared.recovery_directory().to_path_buf();
        let entries: Vec<_> = prepared.preview().iter().map(|entry| EntryOutput {
            path: entry.path.as_str().to_owned(),
            destination_root: entry.destination_root.clone(),
            quarantine_path: recovery_directory.join(entry.quarantined.path.as_str()),
            quarantined: entry.quarantined.clone(),
            current: entry.current.clone(),
        }).collect();
        let mut report = RecoveryOutput {
            schema_version: 1,
            command: "atp.local-recover",
            mode: if args.apply.is_some() { "apply" } else { "plan" },
            content_profile: CONTENT_PROFILE,
            receipt: args.receipt.clone(),
            source_plan_id: prepared.source_plan_id().to_owned(),
            review_id: prepared.review_id().to_owned(),
            local_root: args.local.clone(),
            remote_root: args.remote.clone(),
            recovery_directory,
            has_overwrites: entries.iter().any(|entry| entry.current.is_some()),
            entries,
            result: None,
            application_error: None,
            runtime_quiescent: false,
            runtime_stopped: false,
        };
        if let Some(reviewed) = &args.apply {
            if reviewed != &report.review_id {
                report.application_error = Some(format!(
                    "Reviewed ID {reviewed} does not match current recovery review {}; inspect the new captured contents before applying",
                    report.review_id,
                ));
                return Ok(report);
            }
            let authorization = DestructiveAuthorization {
                dry_run: false,
                allow_overwrite: args.allow_overwrite,
                allow_permission_change: args.allow_permission_change,
                ..DestructiveAuthorization::default()
            };
            match prepared.apply(&cx, authorization).await {
                Ok(result) => report.result = Some(result.into()),
                Err(error) => report.application_error = Some(error.to_string()),
            }
        }
        Ok(report)
    }

    // Output fields unrelated to association are deliberately ignored, but the
    // wrapper version, command, mode and profile must be explicitly understood.
    #[derive(Deserialize)]
    struct RecordedOperation {
        schema_version: u32,
        command: String,
        mode: String,
        content_profile: String,
        plan_id: String,
        result: Option<JsonObject<RecordedApplication>>,
        // A nested error or a second top-level source must not masquerade as
        // a full report by adding otherwise valid operation fields.
        #[serde(default, rename = "type", deserialize_with = "reject_mixed_shape")]
        _error_envelope: (),
        #[serde(default, rename = "dry_run", deserialize_with = "reject_mixed_shape")]
        _source_dry_run: (),
        #[serde(default, rename = "staging_directory", deserialize_with = "reject_mixed_shape")]
        _source_staging: (),
        #[serde(default, rename = "actions", deserialize_with = "reject_mixed_shape")]
        _source_actions: (),
    }

    #[derive(Deserialize)]
    struct RecordedApplication {
        dry_run: bool,
        staging_directory: Option<PathBuf>,
        actions: Vec<NativeDirectoryRecoverySourceAction>,
        recovery_source: Option<JsonObject<NativeDirectoryRecoverySource>>,
    }

    #[derive(Deserialize)]
    struct RecordedOutputError {
        #[serde(rename = "type")]
        error_type: String,
        context: JsonObject<RecordedErrorContext>,
    }

    #[derive(Deserialize)]
    struct RecordedErrorContext {
        // Typed all the way down: a Value intermediary would discard duplicate
        // fields in the receipt, nested source, and action associations.
        receipt: JsonObject<RecordedOperation>,
    }

    // Serde structs also support positional sequences. These external JSON
    // wrappers are specifically objects; keep map entries intact for typed
    // duplicate-field checks instead of converting them through Value.
    struct JsonObject<T>(T);

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct ObjectVisitor<T>(std::marker::PhantomData<T>);

            impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
                type Value = JsonObject<T>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a JSON object")
                }

                fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                    T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(JsonObject)
                }
            }

            deserializer.deserialize_map(ObjectVisitor::<T>(std::marker::PhantomData))
        }
    }

    // Inspect presence, including explicit null, without retaining arbitrary
    // JSON values. The selected shape is then decoded from the ORIGINAL bytes.
    #[derive(Deserialize)]
    struct ReceiptKind {
        #[serde(default, rename = "type", deserialize_with = "field_present")]
        error: bool,
        #[serde(default, deserialize_with = "field_present")]
        command: bool,
        #[serde(default, deserialize_with = "field_present")]
        schema_version: bool,
        #[serde(default, deserialize_with = "field_present")]
        mode: bool,
        #[serde(default, deserialize_with = "field_present")]
        content_profile: bool,
        #[serde(default, deserialize_with = "field_present")]
        result: bool,
        #[serde(default, deserialize_with = "field_present")]
        dry_run: bool,
        #[serde(default, deserialize_with = "field_present")]
        staging_directory: bool,
        #[serde(default, deserialize_with = "field_present")]
        actions: bool,
    }

    impl ReceiptKind {
        fn operation(&self) -> bool {
            self.command || self.schema_version || self.mode || self.content_profile || self.result
        }

        fn source(&self) -> bool {
            self.dry_run || self.staging_directory || self.actions
        }
    }

    fn field_present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(true)
    }

    fn reject_mixed_shape<'de, D: serde::Deserializer<'de>>(_: D) -> Result<(), D::Error> {
        Err(serde::de::Error::custom("mixed receipt shapes or nested error envelopes are not supported"))
    }

    fn invalid_receipt(detail: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, detail.into())
    }

    fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
        serde_json::from_slice::<JsonObject<T>>(bytes)
            .map(|object| object.0)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn decode_receipt(bytes: &[u8]) -> io::Result<NativeDirectoryRecoverySource> {
        let kind: ReceiptKind = decode_json(bytes)?;
        if kind.error {
            if kind.operation() || kind.source() {
                return Err(invalid_receipt("an error envelope cannot also be an application receipt or recovery source"));
            }
            let envelope: RecordedOutputError = decode_json(bytes)?;
            if envelope.error_type != "output_error" {
                return Err(invalid_receipt("only output_error can contain an application receipt"));
            }
            return source_from_operation(envelope.context.0.receipt.0);
        }
        if kind.operation() {
            if kind.source() {
                return Err(invalid_receipt("an application receipt cannot also be a standalone recovery source"));
            }
            return source_from_operation(decode_json(bytes)?);
        }
        decode_json(bytes)
    }

    fn source_from_operation(operation: RecordedOperation) -> io::Result<NativeDirectoryRecoverySource> {
        if operation.schema_version != 1
            || !matches!(operation.command.as_str(), "atp.local-mirror" | "atp.local-sync")
            || operation.mode != "apply"
            || operation.content_profile != CONTENT_PROFILE
        {
            return Err(invalid_receipt("unsupported receipt version, command, mode or content profile"));
        }
        let result = operation.result
            .ok_or_else(|| invalid_receipt("receipt has no observed application result"))?.0;
        let source = NativeDirectoryRecoverySource::new(
            operation.plan_id, result.dry_run, result.staging_directory, result.actions,
        );
        if let Some(recorded) = result.recovery_source
            && recorded.0 != source
        {
            return Err(invalid_receipt("nested recovery source disagrees with the application receipt"));
        }
        // Native preparation is the shared validator for every shape. No saved
        // root path, digest, completion claim or permission flag is authority.
        Ok(source)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use asupersync::atp::sync::BidirectionalSyncAction;
        use asupersync::atp::sync::native::{NativeDirectoryActionState, NativeDirectoryLimits};
        use serde_json::{Value, json};

        fn source_document() -> Value {
            let plan = "a".repeat(64);
            let job = format!("/retained/asupersync-sync-{plan}");
            json!({
                "plan_id": plan,
                "dry_run": false,
                "staging_directory": job,
                "actions": [
                    { "path": "untouched", "action": "Keep", "state": "unchanged", "quarantine_path": null },
                    { "path": "nested/file.txt", "action": "CopyLocalToRemote", "state": "published",
                      "quarantine_path": format!("{job}/previous-00000001") }
                ]
            })
        }

        fn operation_document(command: &str) -> Value {
            let source = source_document();
            let mut result = json!({
                "complete": false, "dry_run": false, "failure": "directory sync failed",
                "persistence_failure": "history not published",
                "publication": { "state": "staging", "generation": 3 },
                "staging_directory": source["staging_directory"].clone(),
                "actions": source["actions"].clone()
            });
            for action in result["actions"].as_array_mut().unwrap() {
                action["bytes_written"] = json!(17);
                action["durable"] = json!(false);
                action["staged_path"] = Value::Null;
            }
            if command == "atp.local-mirror" {
                result["recovery_source"] = source.clone();
            }
            json!({
                "schema_version": 1, "command": command, "mode": "apply",
                "content_profile": CONTENT_PROFILE,
                "plan_id": source["plan_id"].clone(), "review_id": "b".repeat(64),
                "source_root": "/old/source", "destination_root": "/old/destination",
                "local_root": "/old/local", "remote_root": "/old/remote",
                "runtime_quiescent": false, "runtime_stopped": false,
                "result": result
            })
        }

        fn text(value: &Value) -> String {
            serde_json::to_string(value).unwrap()
        }

        fn wrap_error(report: &str) -> String {
            ["{\"type\":\"output_error\",\"context\":{\"receipt\":", report, "}}"].concat()
        }

        fn prepend_field(document: &str, key: &str, value: &str) -> String {
            ["{\"", key, "\":", value, ",", document.strip_prefix('{').unwrap()].concat()
        }

        fn assert_source(source: &NativeDirectoryRecoverySource) {
            let plan = "a".repeat(64);
            let job = PathBuf::from(format!("/retained/asupersync-sync-{plan}"));
            assert_eq!(source.plan_id, plan, "use the execution plan, never the saved review ID");
            assert!(!source.dry_run);
            assert_eq!(source.staging_directory.as_ref(), Some(&job));
            assert_eq!(source.actions.len(), 2, "keep nonquarantined actions in position");
            assert_eq!(source.actions[0].path.as_str(), "untouched");
            assert_eq!(source.actions[0].action, BidirectionalSyncAction::Keep);
            assert_eq!(source.actions[0].state, NativeDirectoryActionState::Unchanged);
            assert!(source.actions[0].quarantine_path.is_none());
            assert_eq!(source.actions[1].path.as_str(), "nested/file.txt");
            assert_eq!(source.actions[1].action, BidirectionalSyncAction::CopyLocalToRemote);
            assert_eq!(source.actions[1].state, NativeDirectoryActionState::Published);
            assert_eq!(source.actions[1].quarantine_path.as_ref(), Some(&job.join("previous-00000001")));
        }

        fn assert_invalid(bytes: &[u8], case: &str) {
            let error = decode_receipt(bytes).expect_err(case);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{case}: {error}");
        }

        #[test]
        fn recovery_source_and_partial_cli_receipts_preserve_original_associations() {
            assert_source(&decode_receipt(text(&source_document()).as_bytes()).unwrap());
            for command in ["atp.local-sync", "atp.local-mirror"] {
                let report = text(&operation_document(command));
                assert_source(&decode_receipt(report.as_bytes()).unwrap());
                assert_source(&decode_receipt(wrap_error(&report).as_bytes()).unwrap());
            }
        }

        #[test]
        fn receipt_completion_claims_and_saved_roots_do_not_supply_recovery_authority() {
            let mut report = operation_document("atp.local-mirror");
            let original = decode_receipt(text(&report).as_bytes()).unwrap();
            for field in ["source_root", "destination_root", "local_root", "remote_root"] {
                report[field] = json!("/untrusted/serialized/path");
            }
            report["review_id"] = json!("c".repeat(64));
            report["allow_overwrite"] = json!(true);
            report["result"]["complete"] = json!(true);
            report["result"]["failure"] = Value::Null;
            report["result"]["actions"][1]["durable"] = json!(true);
            assert_eq!(decode_receipt(text(&report).as_bytes()).unwrap(), original);
        }

        #[test]
        fn unsupported_or_missing_operation_headers_cannot_fall_back_to_a_source() {
            for (field, value) in [
                ("schema_version", json!(2)),
                ("command", json!("atp.local-recover")),
                ("command", json!("atp.send")),
                ("mode", json!("plan")),
                ("content_profile", json!("future-profile")),
                ("result", Value::Null),
            ] {
                let mut report = operation_document("atp.local-sync");
                report[field] = value;
                assert_invalid(text(&report).as_bytes(), field);
            }
            for field in ["schema_version", "command", "mode", "content_profile", "result"] {
                let mut report = operation_document("atp.local-sync");
                report.as_object_mut().unwrap().remove(field);
                assert_invalid(text(&report).as_bytes(), field);
                let mut source = source_document();
                source[field] = Value::Null;
                assert_invalid(text(&source).as_bytes(), "recognized null header cannot be ignored");
            }
        }

        #[test]
        fn contradictory_embedded_recovery_sources_are_rejected() {
            for (field, value) in [
                ("plan_id", json!("c".repeat(64))),
                ("dry_run", json!(true)),
                ("staging_directory", json!("/other/recovery-job")),
                ("actions", json!([])),
            ] {
                let mut report = operation_document("atp.local-mirror");
                report["result"]["recovery_source"][field] = value;
                assert_invalid(text(&report).as_bytes(), field);
            }
            let mut report = operation_document("atp.local-mirror");
            report["result"]["recovery_source"]["actions"].as_array_mut().unwrap().reverse();
            assert_invalid(text(&report).as_bytes(), "action order is part of the association");
        }

        #[test]
        fn ambiguous_source_operation_and_error_shapes_are_rejected() {
            let source = source_document();
            let mut operation = operation_document("atp.local-sync");
            for field in ["dry_run", "staging_directory", "actions"] {
                operation[field] = source[field].clone();
            }
            assert_invalid(text(&operation).as_bytes(), "mixed operation and source");
            assert_invalid(wrap_error(&text(&operation)).as_bytes(), "mixed payload inside error");
            let report = operation_document("atp.local-mirror");
            for mut mixed in [source, report.clone()] {
                mixed["type"] = json!("output_error");
                mixed["context"] = json!({ "receipt": report.clone() });
                assert_invalid(text(&mixed).as_bytes(), "mixed error and receipt");
            }
        }

        #[test]
        fn error_envelopes_require_one_typed_application_receipt() {
            let report = text(&operation_document("atp.local-sync"));
            let envelope = wrap_error(&report);
            assert_invalid(wrap_error(&envelope).as_bytes(), "nested error");
            assert_invalid(wrap_error(&text(&source_document())).as_bytes(), "source is not a full application report");
            assert_invalid(prepend_field(&report, "type", "\"output_error\"").as_bytes(), "error marker in report");
            assert_invalid(wrap_error(&prepend_field(&report, "type", "null")).as_bytes(), "null nested error marker");
            for malformed in [
                "{\"type\":\"output_error\"}",
                "{\"type\":\"output_error\",\"context\":{}}",
                "{\"type\":\"output_error\",\"context\":{\"receipt\":null}}",
                "{\"type\":null,\"context\":{}}",
            ] {
                assert_invalid(malformed.as_bytes(), "incomplete error envelope");
            }
            assert_invalid(envelope.replacen("output_error", "unrelated_error", 1).as_bytes(), "unrelated error type");
        }

        #[test]
        fn positional_sequences_cannot_replace_json_wrapper_objects() {
            let report = operation_document("atp.local-sync");
            let positional = json!([
                1, "atp.local-sync", "apply", CONTENT_PROFILE,
                report["plan_id"].clone(), report["result"].clone()
            ]);
            assert_invalid(text(&positional).as_bytes(), "positional top-level report");
            assert_invalid(wrap_error(&text(&positional)).as_bytes(), "positional context receipt");
            assert_invalid(text(&json!({
                "type": "output_error", "context": [report.clone()]
            })).as_bytes(), "positional error context");
            let mut positional_result = report;
            let source = source_document();
            positional_result["result"] = json!([
                false, source["staging_directory"].clone(), source["actions"].clone(), null
            ]);
            assert_invalid(text(&positional_result).as_bytes(), "positional application result");
            let mut mirror = operation_document("atp.local-mirror");
            mirror["result"]["recovery_source"] = json!([
                source["plan_id"].clone(), false,
                source["staging_directory"].clone(), source["actions"].clone()
            ]);
            assert_invalid(text(&mirror).as_bytes(), "positional embedded source");
        }

        #[test]
        fn duplicate_root_and_error_context_fields_are_rejected() {
            let source = text(&source_document());
            let report = text(&operation_document("atp.local-sync"));
            for duplicate in [
                prepend_field(&source, "plan_id", &text(&json!("c".repeat(64)))),
                prepend_field(&source, "dry_run", "true"),
                prepend_field(&report, "command", "\"atp.local-mirror\""),
                prepend_field(&report, "plan_id", &text(&json!("c".repeat(64)))),
                prepend_field(&report, "mode", "\"plan\""),
                prepend_field(&wrap_error(&report), "type", "\"output_error\""),
                prepend_field(&wrap_error(&report), "context", "{}"),
            ] {
                assert_invalid(duplicate.as_bytes(), "duplicate known field");
            }
            let duplicate_receipt = [
                "{\"type\":\"output_error\",\"context\":{\"receipt\":", &report,
                ",\"receipt\":", &report, "}}",
            ].concat();
            assert_invalid(duplicate_receipt.as_bytes(), "duplicate context.receipt");
        }

        #[test]
        fn duplicate_nested_source_and_action_fields_survive_wrapper_decoding() {
            let source = text(&source_document());
            let report = text(&operation_document("atp.local-mirror"));
            let duplicate_source = prepend_field(&source, "plan_id", &text(&json!("c".repeat(64))));
            let nested = report.replacen(&source, &duplicate_source, 1);
            assert_ne!(nested, report, "plant the duplicate inside recovery_source");
            let action = report.replacen(
                "\"state\":\"published\"", "\"state\":\"published\",\"state\":\"staged\"", 1,
            );
            assert_ne!(action, report, "plant the duplicate in an action");
            for malformed in [nested, action] {
                assert_invalid(malformed.as_bytes(), "duplicate inside application receipt");
                assert_invalid(wrap_error(&malformed).as_bytes(), "duplicate inside error receipt");
            }
        }

        #[test]
        fn invalid_action_types_and_states_are_not_coerced() {
            for (field, value) in [
                ("action", json!("copy_local_to_remote")),
                ("action", json!("FutureAction")),
                ("state", json!("Published")),
                ("state", json!("unknown")),
                ("quarantine_path", json!(17)),
            ] {
                let mut source = source_document();
                source["actions"][1][field] = value;
                assert_invalid(text(&source).as_bytes(), field);
            }
        }

        #[test]
        fn malformed_trailing_and_non_object_json_is_refused() {
            let source = text(&source_document());
            assert_source(&decode_receipt(format!(" \n{source}\n ").as_bytes()).unwrap());
            for malformed in ["null", "[]", "\"not an object\"", "{}", "{"] {
                assert_invalid(malformed.as_bytes(), "invalid document");
            }
            assert_invalid(format!("{source}{source}").as_bytes(), "concatenated documents");
            let mut invalid_utf8 = source.into_bytes();
            invalid_utf8.push(0xff);
            assert_invalid(&invalid_utf8, "invalid UTF-8");
        }

        #[test]
        fn decoding_does_not_replace_native_association_validation() {
            let mut source = source_document();
            source["actions"][1]["path"] = json!("../escape");
            let decoded = decode_receipt(text(&source).as_bytes()).unwrap();
            assert_eq!(decoded.actions[1].path.as_str(), "../escape");
            let bytes = serde_json::to_vec(&decoded).unwrap();
            assert!(NativeDirectoryRecoverySource::from_json_slice(
                &bytes, 16_777_216, NativeDirectoryLimits::default(),
            ).is_err(), "native preparation's shared association validator must refuse traversal");
        }
    }
}
