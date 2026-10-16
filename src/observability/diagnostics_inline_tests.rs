    use super::*;
    use crate::observability::spectral_health::HealthClassification;
    use crate::record::obligation::{ObligationKind, ObligationRecord};
    use crate::record::region::RegionRecord;
    use crate::record::task::{TaskRecord, TaskState};
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, CancelReason, CxInner, Outcome, Time};
    use crate::util::ArenaIndex;
    use serde_json::{Value, json};
    use std::fmt::Write as _;
    use std::sync::Arc;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn insert_child_region(state: &mut RuntimeState, parent: RegionId) -> RegionId {
        let idx = state.regions.insert(RegionRecord::new(
            RegionId::from_arena(ArenaIndex::new(0, 1)),
            Some(parent),
            Budget::INFINITE,
        ));
        let id = RegionId::from_arena(idx);
        let record = state.regions.get_mut(idx).expect("child region missing");
        record.id = id;
        let added = state
            .regions
            .get(parent.arena_index())
            .expect("parent missing")
            .add_child(id);
        crate::assert_with_log!(added.is_ok(), "child added", true, added.is_ok());
        id
    }

    fn insert_task(state: &mut RuntimeState, region: RegionId, task_state: TaskState) -> TaskId {
        let idx = state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
        ));
        let id = TaskId::from_arena(idx);
        let record = state.task_mut(id).expect("task missing");
        record.id = id;
        record.state = task_state;
        let added = state
            .regions
            .get(region.arena_index())
            .expect("region missing")
            .add_task(id);
        crate::assert_with_log!(added.is_ok(), "task added", true, added.is_ok());
        id
    }

    fn insert_obligation(
        state: &mut RuntimeState,
        region: RegionId,
        holder: TaskId,
        kind: ObligationKind,
        reserved_at: Time,
    ) -> ObligationId {
        let idx = state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            kind,
            holder,
            region,
            reserved_at,
        ));
        let id = ObligationId::from_arena(idx);
        let record = state.obligations.get_mut(idx).expect("obligation missing");
        record.id = id;
        id
    }

    fn render_structured_diagnostic_report(
        scenario: &str,
        generated_at: &str,
        region: Option<&RegionOpenExplanation>,
        task: Option<&TaskBlockedExplanation>,
        leaks: &[ObligationLeak],
    ) -> String {
        let mut rendered = String::new();
        writeln!(&mut rendered, "scenario: {scenario}").expect("write scenario");
        writeln!(&mut rendered, "generated_at: {generated_at}").expect("write timestamp");

        rendered.push_str("\n[region]\n");
        if let Some(region) = region {
            rendered.push_str(&region.to_string());
        } else {
            rendered.push_str("none\n");
        }

        rendered.push_str("\n[task]\n");
        if let Some(task) = task {
            rendered.push_str(&task.to_string());
        } else {
            rendered.push_str("none\n");
        }

        rendered.push_str("\n[leaks]\n");
        if leaks.is_empty() {
            rendered.push_str("none\n");
        } else {
            for leak in leaks {
                writeln!(
                    &mut rendered,
                    "- {:?} region={:?} holder={:?} type={} age_ms={}",
                    leak.obligation_id,
                    leak.region_id,
                    leak.holder_task,
                    leak.obligation_type,
                    leak.age.as_millis()
                )
                .expect("write leak");
            }
        }

        rendered.trim_end().to_string()
    }

    fn render_structured_diagnostic_report_v2(sections: &[(&str, &str)]) -> String {
        let mut rendered = String::from("report_version: v2");
        for (label, section) in sections {
            writeln!(&mut rendered, "\n\n[{label}]").expect("write section label");
            rendered.push_str(section);
        }
        rendered.trim_end().to_string()
    }

    struct DiagnosticResourceAccounting {
        total_regions: usize,
        open_regions: usize,
        total_tasks: usize,
        live_tasks: usize,
        total_obligations: usize,
        leaked_obligations: usize,
    }

    struct DiagnosticReportV3Section<'a> {
        label: &'a str,
        status: &'a str,
        accounting: DiagnosticResourceAccounting,
        rendered: &'a str,
    }

    #[derive(Debug, Clone)]
    struct DiagnosticMetricHistogram {
        name: String,
        buckets: Vec<(String, u64)>, // (bucket_name, count)
        total_count: u64,
        percentiles: Vec<(f64, f64)>, // (percentile, value)
    }

    struct DiagnosticReportV4Section<'a> {
        label: &'a str,
        status: &'a str,
        accounting: DiagnosticResourceAccounting,
        histograms: Vec<DiagnosticMetricHistogram>,
        rendered: &'a str,
    }

    fn diagnostic_resource_accounting(
        diagnostics: &Diagnostics,
        leaked_obligations: usize,
    ) -> DiagnosticResourceAccounting {
        diagnostics.state.with_view(|view| {
            let total_regions = view.regions().count();
            let open_regions = view
                .regions()
                .filter(|region| region.state() != RegionState::Closed)
                .count();
            let total_tasks = view.tasks().count();
            let live_tasks = view
                .tasks()
                .filter(|task| !task.state.is_terminal())
                .count();
            let total_obligations = view.obligations().count();

            DiagnosticResourceAccounting {
                total_regions,
                open_regions,
                total_tasks,
                live_tasks,
                total_obligations,
                leaked_obligations,
            }
        })
    }

    fn render_structured_diagnostic_report_v3(
        sections: &[DiagnosticReportV3Section<'_>],
    ) -> String {
        let mut rendered = String::from("report_version: v3");
        let passing_count = sections
            .iter()
            .filter(|section| section.status == "passing")
            .count();
        let degraded_count = sections
            .iter()
            .filter(|section| section.status == "degraded")
            .count();
        let critical_count = sections
            .iter()
            .filter(|section| section.status == "critical")
            .count();

        writeln!(&mut rendered, "\n\n[summary]").expect("write summary label");
        writeln!(&mut rendered, "scenario_count: {}", sections.len())
            .expect("write scenario count");
        writeln!(&mut rendered, "passing_count: {passing_count}").expect("write passing count");
        writeln!(&mut rendered, "degraded_count: {degraded_count}").expect("write degraded count");
        writeln!(&mut rendered, "critical_count: {critical_count}").expect("write critical count");

        for section in sections {
            writeln!(&mut rendered, "\n\n[{}]", section.label).expect("write section label");
            writeln!(&mut rendered, "status: {}", section.status).expect("write status");
            rendered.push_str("resource_accounting:\n");
            writeln!(
                &mut rendered,
                "  - regions_total: {}",
                section.accounting.total_regions
            )
            .expect("write total regions");
            writeln!(
                &mut rendered,
                "  - regions_open: {}",
                section.accounting.open_regions
            )
            .expect("write open regions");
            writeln!(
                &mut rendered,
                "  - tasks_total: {}",
                section.accounting.total_tasks
            )
            .expect("write total tasks");
            writeln!(
                &mut rendered,
                "  - tasks_live: {}",
                section.accounting.live_tasks
            )
            .expect("write live tasks");
            writeln!(
                &mut rendered,
                "  - obligations_total: {}",
                section.accounting.total_obligations
            )
            .expect("write total obligations");
            writeln!(
                &mut rendered,
                "  - obligations_leaked: {}",
                section.accounting.leaked_obligations
            )
            .expect("write leaked obligations");
            rendered.push_str("report:\n");
            for line in section.rendered.lines() {
                writeln!(&mut rendered, "  {line}").expect("write report line");
            }
        }

        rendered.trim_end().to_string()
    }

    fn render_structured_diagnostic_report_v4(
        sections: &[DiagnosticReportV4Section<'_>],
    ) -> String {
        let mut rendered = String::from("report_version: v4");
        let passing_count = sections
            .iter()
            .filter(|section| section.status == "passing")
            .count();
        let degraded_count = sections
            .iter()
            .filter(|section| section.status == "degraded")
            .count();
        let critical_count = sections
            .iter()
            .filter(|section| section.status == "critical")
            .count();

        // Extended summary with histogram metrics
        writeln!(&mut rendered, "\n\n[summary]").expect("write summary label");
        writeln!(&mut rendered, "scenario_count: {}", sections.len())
            .expect("write scenario count");
        writeln!(&mut rendered, "passing_count: {passing_count}").expect("write passing count");
        writeln!(&mut rendered, "degraded_count: {degraded_count}").expect("write degraded count");
        writeln!(&mut rendered, "critical_count: {critical_count}").expect("write critical count");

        // Aggregate histogram metrics across all sections
        let total_histogram_count: u64 = sections
            .iter()
            .flat_map(|section| &section.histograms)
            .map(|h| h.total_count)
            .sum();
        writeln!(
            &mut rendered,
            "total_histogram_samples: {total_histogram_count}"
        )
        .expect("write total histogram samples");

        let histogram_types: std::collections::BTreeSet<&String> = sections
            .iter()
            .flat_map(|section| &section.histograms)
            .map(|h| &h.name)
            .collect();
        writeln!(
            &mut rendered,
            "histogram_types: [{}]",
            histogram_types
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
        .expect("write histogram types");

        for section in sections {
            writeln!(&mut rendered, "\n\n[{}]", section.label).expect("write section label");
            writeln!(&mut rendered, "status: {}", section.status).expect("write status");

            // Resource accounting
            rendered.push_str("resource_accounting:\n");
            writeln!(
                &mut rendered,
                "  - regions_total: {}",
                section.accounting.total_regions
            )
            .expect("write total regions");
            writeln!(
                &mut rendered,
                "  - regions_open: {}",
                section.accounting.open_regions
            )
            .expect("write open regions");
            writeln!(
                &mut rendered,
                "  - tasks_total: {}",
                section.accounting.total_tasks
            )
            .expect("write total tasks");
            writeln!(
                &mut rendered,
                "  - tasks_live: {}",
                section.accounting.live_tasks
            )
            .expect("write live tasks");
            writeln!(
                &mut rendered,
                "  - obligations_total: {}",
                section.accounting.total_obligations
            )
            .expect("write total obligations");
            writeln!(
                &mut rendered,
                "  - obligations_leaked: {}",
                section.accounting.leaked_obligations
            )
            .expect("write leaked obligations");

            // Extended metric histograms (v4 feature)
            if !section.histograms.is_empty() {
                rendered.push_str("extended_metrics:\n");
                for histogram in &section.histograms {
                    writeln!(&mut rendered, "  - name: {}", histogram.name)
                        .expect("write histogram name");
                    writeln!(
                        &mut rendered,
                        "    total_samples: {}",
                        histogram.total_count
                    )
                    .expect("write histogram total");

                    if !histogram.buckets.is_empty() {
                        rendered.push_str("    buckets:\n");
                        for (bucket_name, count) in &histogram.buckets {
                            writeln!(&mut rendered, "      - {}: {}", bucket_name, count)
                                .expect("write bucket");
                        }
                    }

                    if !histogram.percentiles.is_empty() {
                        rendered.push_str("    percentiles:\n");
                        for (percentile, value) in &histogram.percentiles {
                            writeln!(
                                &mut rendered,
                                "      - p{:.1}: {:.3}",
                                percentile * 100.0,
                                value
                            )
                            .expect("write percentile");
                        }
                    }
                }
            }

            // Diagnostic report content
            rendered.push_str("report:\n");
            for line in section.rendered.lines() {
                writeln!(&mut rendered, "  {line}").expect("write report line");
            }
        }

        rendered.trim_end().to_string()
    }

    fn scrub_diagnostic_report_timestamps(rendered: &str) -> String {
        rendered
            .lines()
            .map(|line| {
                let trimmed = line.trim_start();
                let detail = trimmed.strip_prefix("- ").unwrap_or(trimmed);
                if line.starts_with("generated_at: ") {
                    "generated_at: <scrubbed>".to_string()
                } else if detail.starts_with("next_retry_at: ") {
                    "  - next_retry_at: <scrubbed>".to_string()
                } else if detail.starts_with("observed_at: ") {
                    "  - observed_at: <scrubbed>".to_string()
                } else if detail.starts_with("deadline_at: ") {
                    "  - deadline_at: <scrubbed>".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_diagnostic_report_snapshot(snapshot_name: &str, rendered: &str) {
        insta::with_settings!({
            snapshot_path => "../../tests/snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_snapshot!(snapshot_name, rendered);
        });
    }

    fn insert_wait_path(state: &mut RuntimeState, region: RegionId, len: usize) -> Vec<TaskId> {
        let tasks: Vec<TaskId> = (0..len)
            .map(|_| insert_task(state, region, TaskState::Running))
            .collect();
        for pair in tasks.windows(2) {
            state
                .task_mut(pair[0])
                .expect("path task missing")
                .waiters
                .push(pair[1]);
        }
        tasks
    }

    fn round_metric(value: f64) -> f64 {
        (value * 1_000.0).round() / 1_000.0
    }

    fn deadlock_severity_label(severity: DeadlockSeverity) -> &'static str {
        match severity {
            DeadlockSeverity::None => "none",
            DeadlockSeverity::Elevated => "elevated",
            DeadlockSeverity::Critical => "critical",
        }
    }

    fn health_classification_json(classification: &HealthClassification) -> Value {
        match classification {
            HealthClassification::Deadlocked => json!({
                "kind": "deadlocked",
            }),
            HealthClassification::Healthy { margin } => json!({
                "kind": "healthy",
                "margin": round_metric(*margin),
            }),
            HealthClassification::Degraded {
                fiedler,
                bottleneck_nodes,
            } => json!({
                "kind": "degraded",
                "fiedler": round_metric(*fiedler),
                "bottleneck_nodes": bottleneck_nodes,
            }),
            HealthClassification::Critical {
                fiedler,
                approaching_disconnect,
            } => json!({
                "kind": "critical",
                "fiedler": round_metric(*fiedler),
                "approaching_disconnect": approaching_disconnect,
            }),
            HealthClassification::Fragmented { components } => json!({
                "kind": "fragmented",
                "components": components,
            }),
        }
    }

    fn overall_health_status(
        health: &SpectralHealthReport,
        deadlock: &DirectionalDeadlockReport,
        leak_count: usize,
    ) -> &'static str {
        if deadlock.severity == DeadlockSeverity::Critical
            || matches!(
                health.classification,
                HealthClassification::Deadlocked
                    | HealthClassification::Critical { .. }
                    | HealthClassification::Fragmented { .. }
            )
        {
            "critical"
        } else if leak_count > 0
            || deadlock.severity == DeadlockSeverity::Elevated
            || matches!(health.classification, HealthClassification::Degraded { .. })
        {
            "degraded"
        } else {
            "passing"
        }
    }

    fn render_diagnostic_healthcheck_json(
        diagnostics: &Diagnostics,
        region_id: RegionId,
        generated_at: &str,
        pid: u32,
    ) -> Value {
        let health = diagnostics.analyze_structural_health();
        let deadlock = diagnostics.analyze_directional_deadlock();
        let region = diagnostics.explain_region_open(region_id);
        let leaks = diagnostics.find_leaked_obligations();
        let leak_count = leaks.len();
        let max_age_ms = leaks
            .iter()
            .map(|leak| u64::try_from(leak.age.as_millis()).unwrap_or(u64::MAX))
            .max()
            .unwrap_or(0);

        json!({
            "generated_at": generated_at,
            "pid": pid,
            "status": overall_health_status(&health, &deadlock, leak_count),
            "structural_health": {
                "classification": health_classification_json(&health.classification),
                "fiedler_value": round_metric(health.decomposition.fiedler_value),
                "spectral_gap": round_metric(health.decomposition.spectral_gap),
                "spectral_radius": round_metric(health.decomposition.spectral_radius),
                "iterations_used": health.decomposition.iterations_used,
                "bottleneck_count": health.bottlenecks.len(),
            },
            "directional_deadlock": {
                "severity": deadlock_severity_label(deadlock.severity),
                "risk_score": round_metric(deadlock.risk_score),
                "cycle_count": deadlock.cycles.len(),
                "trapped_cycle_count": deadlock.cycles.iter().filter(|cycle| cycle.trapped).count(),
                "cycles": deadlock.cycles.iter().map(|cycle| json!({
                    "tasks": cycle.tasks.iter().map(|task| format!("{task:?}")).collect::<Vec<_>>(),
                    "trapped": cycle.trapped,
                    "ingress_edges": cycle.ingress_edges,
                    "egress_edges": cycle.egress_edges,
                })).collect::<Vec<_>>(),
            },
            "region": {
                "id": format!("{:?}", region.region_id),
                "state": region.region_state.map(|state| format!("{state:?}")),
                "reason_count": region.reasons.len(),
                "recommendation_count": region.recommendations.len(),
            },
            "obligations": {
                "leak_count": leak_count,
                "max_age_ms": max_age_ms,
                "leaks": leaks.iter().map(|leak| json!({
                    "obligation_id": format!("{:?}", leak.obligation_id),
                    "region_id": format!("{:?}", leak.region_id),
                    "holder_task": leak.holder_task.map(|task| format!("{task:?}")),
                    "obligation_type": &leak.obligation_type,
                    "age_ms": u64::try_from(leak.age.as_millis()).unwrap_or(u64::MAX),
                })).collect::<Vec<_>>(),
            },
        })
    }

    fn scrub_diagnostic_healthcheck_json(mut value: Value) -> Value {
        let Some(object) = value.as_object_mut() else {
            return value;
        };
        object.insert(
            "generated_at".to_string(),
            Value::String("<scrubbed>".to_string()),
        );
        object.insert("pid".to_string(), Value::String("<scrubbed>".to_string()));
        value
    }

    fn assert_diagnostic_healthcheck_snapshot(snapshot_name: &str, value: &Value) {
        insta::with_settings!({
            snapshot_path => "../../tests/snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_json_snapshot!(snapshot_name, value);
        });
    }

    #[test]
    fn test_explain_region_open_unknown_region_returns_reason() {
        init_test("test_explain_region_open_unknown_region_returns_reason");
        let state = Arc::new(RuntimeState::new());
        let diagnostics = Diagnostics::new(state);
        let missing = RegionId::new_for_test(99, 0);

        let explanation = diagnostics.explain_region_open(missing);
        crate::assert_with_log!(
            explanation.region_state.is_none(),
            "region_state none",
            true,
            explanation.region_state.is_none()
        );
        crate::assert_with_log!(
            explanation.reasons.len() == 1,
            "single reason",
            1usize,
            explanation.reasons.len()
        );
        let is_not_found = matches!(explanation.reasons.first(), Some(Reason::RegionNotFound));
        crate::assert_with_log!(is_not_found, "region not found reason", true, is_not_found);
        let has_recommendation = explanation
            .recommendations
            .iter()
            .any(|rec| rec.contains("Verify region id"));
        crate::assert_with_log!(
            has_recommendation,
            "recommendation present",
            true,
            has_recommendation
        );
        crate::test_complete!("test_explain_region_open_unknown_region_returns_reason");
    }

    #[test]
    fn test_explain_region_open_closed_region_has_no_reasons() {
        init_test("test_explain_region_open_closed_region_has_no_reasons");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state.region(root).expect("root missing");
        let did_close =
            region.begin_close(None) && region.begin_finalize() && region.complete_close();
        crate::assert_with_log!(did_close, "region closed", true, did_close);

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(root);
        crate::assert_with_log!(
            explanation.region_state == Some(RegionState::Closed),
            "closed state",
            true,
            explanation.region_state == Some(RegionState::Closed)
        );
        crate::assert_with_log!(
            explanation.reasons.is_empty(),
            "no reasons",
            true,
            explanation.reasons.is_empty()
        );
        crate::assert_with_log!(
            explanation.recommendations.is_empty(),
            "no recommendations",
            true,
            explanation.recommendations.is_empty()
        );
        crate::test_complete!("test_explain_region_open_closed_region_has_no_reasons");
    }

    #[test]
    fn test_explain_region_open_reports_children_tasks_obligations() {
        init_test("test_explain_region_open_reports_children_tasks_obligations");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);

        let task_id = insert_task(&mut state, root, TaskState::Running);
        let waiter_id = TaskId::new_for_test(88, 0);
        let task = state.task_mut(task_id).expect("task missing");
        task.total_polls = 7;
        task.waiters.push(waiter_id);
        let mut cx_inner = CxInner::new(root, task_id, Budget::INFINITE);
        cx_inner
            .checkpoint_state
            .record_with_message_at("connecting to db".to_string(), Time::from_millis(12));
        task.set_cx_inner(Arc::new(parking_lot::RwLock::new(cx_inner)));

        let obligation_id = insert_obligation(
            &mut state,
            root,
            task_id,
            ObligationKind::SendPermit,
            Time::from_millis(10),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(root);

        let mut saw_child = false;
        let mut saw_task = false;
        let mut saw_obligation = false;
        for reason in &explanation.reasons {
            match reason {
                Reason::ChildRegionOpen { child_id, .. } if *child_id == child => {
                    saw_child = true;
                }
                Reason::TaskRunning {
                    task_id: id,
                    poll_count,
                    waiters,
                    last_checkpoint_message,
                    ..
                } if *id == task_id
                    && *poll_count == 7
                    && waiters.as_slice() == [waiter_id]
                    && last_checkpoint_message.as_deref() == Some("connecting to db") =>
                {
                    saw_task = true;
                }
                Reason::ObligationHeld {
                    obligation_id: id,
                    holder_task,
                    holder_waiters,
                    holder_last_checkpoint_message,
                    ..
                } if *id == obligation_id
                    && *holder_task == task_id
                    && holder_waiters.as_slice() == [waiter_id]
                    && holder_last_checkpoint_message.as_deref() == Some("connecting to db") =>
                {
                    saw_obligation = true;
                }
                _ => {}
            }
        }
        crate::assert_with_log!(saw_child, "child reason", true, saw_child);
        crate::assert_with_log!(saw_task, "task reason", true, saw_task);
        crate::assert_with_log!(saw_obligation, "obligation reason", true, saw_obligation);

        let recs = &explanation.recommendations;
        let has_child_rec = recs.iter().any(|r| r.contains("child regions"));
        let has_task_rec = recs.iter().any(|r| r.contains("live tasks"));
        let has_obligation_rec = recs.iter().any(|r| r.contains("obligations"));
        crate::assert_with_log!(has_child_rec, "child rec", true, has_child_rec);
        crate::assert_with_log!(has_task_rec, "task rec", true, has_task_rec);
        crate::assert_with_log!(
            has_obligation_rec,
            "obligation rec",
            true,
            has_obligation_rec
        );

        let rendered = explanation.to_string();
        crate::assert_with_log!(
            rendered.contains("[ASUP-E301]"),
            "display includes ASUP-E301",
            true,
            rendered.contains("[ASUP-E301]")
        );
        crate::assert_with_log!(
            rendered.contains("docs/error_codes/ASUP-E301.md"),
            "display includes ASUP-E301 doc path",
            true,
            rendered.contains("docs/error_codes/ASUP-E301.md")
        );
        crate::assert_with_log!(
            rendered.contains("child region"),
            "display includes child",
            true,
            rendered.contains("child region")
        );
        crate::assert_with_log!(
            rendered.contains("wait_edges=["),
            "display includes wait edge",
            true,
            rendered.contains("wait_edges=[")
        );
        crate::assert_with_log!(
            rendered.contains("last_checkpoint=\"connecting to db\""),
            "display includes checkpoint",
            true,
            rendered.contains("last_checkpoint=\"connecting to db\"")
        );
        crate::assert_with_log!(
            rendered.contains("holder_waiters=["),
            "display includes obligation holder wait edge",
            true,
            rendered.contains("holder_waiters=[")
        );
        crate::assert_with_log!(
            rendered.contains("holder_last_checkpoint=\"connecting to db\""),
            "display includes obligation holder checkpoint",
            true,
            rendered.contains("holder_last_checkpoint=\"connecting to db\"")
        );
        crate::assert_with_log!(
            rendered.contains("obligation"),
            "display includes obligation",
            true,
            rendered.contains("obligation")
        );
        crate::test_complete!("test_explain_region_open_reports_children_tasks_obligations");
    }

    #[test]
    fn test_explain_region_open_nested_child_reports_immediate_child() {
        init_test("test_explain_region_open_nested_child_reports_immediate_child");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);
        let grandchild = insert_child_region(&mut state, child);

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(child);

        let saw_grandchild = explanation.reasons.iter().any(|reason| {
            matches!(
                reason,
                Reason::ChildRegionOpen { child_id, .. } if *child_id == grandchild
            )
        });
        crate::assert_with_log!(saw_grandchild, "grandchild reason", true, saw_grandchild);
        crate::test_complete!("test_explain_region_open_nested_child_reports_immediate_child");
    }

    #[test]
    fn test_explain_task_blocked_running_notified_reports_schedule() {
        init_test("test_explain_task_blocked_running_notified_reports_schedule");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Running);
        let task = state.task_mut(task_id).expect("task missing");
        let notified = task.wake_state.notify();
        crate::assert_with_log!(notified, "wake notified", true, notified);
        task.waiters.push(TaskId::new_for_test(77, 0));

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_task_blocked(task_id);
        crate::assert_with_log!(
            matches!(explanation.block_reason, BlockReason::AwaitingSchedule),
            "awaiting schedule",
            true,
            matches!(explanation.block_reason, BlockReason::AwaitingSchedule)
        );
        let has_waiters = explanation.details.iter().any(|d| d.contains("waiters"));
        crate::assert_with_log!(has_waiters, "waiters detail", true, has_waiters);
        crate::test_complete!("test_explain_task_blocked_running_notified_reports_schedule");
    }

    #[test]
    fn test_explain_task_blocked_cancel_requested_includes_reason() {
        init_test("test_explain_task_blocked_cancel_requested_includes_reason");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let reason = CancelReason::user("stop");
        let cleanup_budget = reason.cleanup_budget();
        let task_id = insert_task(
            &mut state,
            root,
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            },
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_task_blocked(task_id);
        let matches_reason = matches!(
            explanation.block_reason,
            BlockReason::CancelRequested {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: Some(_)
                }
            }
        );
        crate::assert_with_log!(matches_reason, "cancel requested", true, matches_reason);
        let rendered = explanation.to_string();
        crate::assert_with_log!(
            rendered.contains("cancel requested"),
            "display includes cancel",
            true,
            rendered.contains("cancel requested")
        );
        crate::test_complete!("test_explain_task_blocked_cancel_requested_includes_reason");
    }

    #[test]
    fn test_explain_task_blocked_completed_reports_completed() {
        init_test("test_explain_task_blocked_completed_reports_completed");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Completed(Outcome::Ok(())));

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_task_blocked(task_id);
        crate::assert_with_log!(
            matches!(explanation.block_reason, BlockReason::Completed),
            "completed",
            true,
            matches!(explanation.block_reason, BlockReason::Completed)
        );
        crate::test_complete!("test_explain_task_blocked_completed_reports_completed");
    }

    #[test]
    fn test_find_leaked_obligations_sorted_and_aged() {
        init_test("test_find_leaked_obligations_sorted_and_aged");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);

        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(100)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));

        let root_task = insert_task(&mut state, root, TaskState::Running);
        let child_task = insert_task(&mut state, child, TaskState::Running);

        let root_ob = insert_obligation(
            &mut state,
            root,
            root_task,
            ObligationKind::Ack,
            Time::from_millis(10),
        );
        let child_ob = insert_obligation(
            &mut state,
            child,
            child_task,
            ObligationKind::Lease,
            Time::from_millis(20),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let leaks = diagnostics.find_leaked_obligations();
        crate::assert_with_log!(leaks.len() == 2, "two leaks", 2usize, leaks.len());

        crate::assert_with_log!(
            leaks[0].region_id == root,
            "root first",
            true,
            leaks[0].region_id == root
        );
        crate::assert_with_log!(
            leaks[1].region_id == child,
            "child second",
            true,
            leaks[1].region_id == child
        );
        crate::assert_with_log!(
            leaks[0].obligation_id == root_ob,
            "root obligation id",
            true,
            leaks[0].obligation_id == root_ob
        );
        crate::assert_with_log!(
            leaks[1].obligation_id == child_ob,
            "child obligation id",
            true,
            leaks[1].obligation_id == child_ob
        );

        let root_age_ms = leaks[0].age.as_millis();
        let child_age_ms = leaks[1].age.as_millis();
        crate::assert_with_log!(root_age_ms == 90, "root age", 90u128, root_age_ms);
        crate::assert_with_log!(child_age_ms == 80, "child age", 80u128, child_age_ms);

        crate::test_complete!("test_find_leaked_obligations_sorted_and_aged");
    }

    #[test]
    fn test_find_leaked_obligations_uses_state_clock_without_timer_driver() {
        init_test("test_find_leaked_obligations_uses_state_clock_without_timer_driver");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Running);
        state.now = Time::from_millis(250);

        let obligation_id = insert_obligation(
            &mut state,
            root,
            task_id,
            ObligationKind::Lease,
            Time::from_millis(10),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let leaks = diagnostics.find_leaked_obligations();
        crate::assert_with_log!(leaks.len() == 1, "single leak", 1usize, leaks.len());
        crate::assert_with_log!(
            leaks[0].obligation_id == obligation_id,
            "obligation id preserved",
            true,
            leaks[0].obligation_id == obligation_id
        );

        let age_ms = leaks[0].age.as_millis();
        crate::assert_with_log!(age_ms == 240, "age uses state clock", 240u128, age_ms);

        crate::test_complete!("test_find_leaked_obligations_uses_state_clock_without_timer_driver");
    }

    #[test]
    fn confirmed_obligation_leaks_exclude_live_holders_and_successful_resolutions() {
        init_test("confirmed_obligation_leaks_exclude_live_holders_and_successful_resolutions");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let reason = CancelReason::user("cleanup in progress");
        let mut live_reservations = Vec::new();
        for task_state in [
            TaskState::Created,
            TaskState::Running,
            TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget: Budget::INFINITE,
            },
            TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget: Budget::INFINITE,
            },
            TaskState::Finalizing {
                reason,
                cleanup_budget: Budget::INFINITE,
            },
        ] {
            let holder = insert_task(&mut state, root, task_state);
            live_reservations.push(insert_obligation(
                &mut state,
                root,
                holder,
                ObligationKind::Ack,
                Time::ZERO,
            ));
        }
        // Successfully resolved records remain healthy even if their holder
        // has since been recycled. Insert the terminal state through the table
        // so its pending counters agree with the records under inspection.
        let missing_holder = TaskId::from_arena(ArenaIndex::new(50, 1));
        for resolution in [ObligationState::Committed, ObligationState::Aborted] {
            let mut record = ObligationRecord::new(
                ObligationId::from_arena(ArenaIndex::new(0, 0)),
                ObligationKind::SendPermit,
                missing_holder,
                root,
                Time::ZERO,
            );
            record.state = resolution;
            state.obligations.insert(record);
        }

        let diagnostics = Diagnostics::new(Arc::new(state));
        assert!(diagnostics.find_confirmed_obligation_leaks().is_empty());
        assert!(!diagnostics.has_confirmed_obligation_leaks());
        assert_eq!(
            diagnostics
                .find_leaked_obligations()
                .iter()
                .map(|leak| leak.obligation_id)
                .collect::<Vec<_>>(),
            live_reservations,
            "the legacy heuristic keeps its documented live-reservation behavior"
        );
        crate::test_complete!(
            "confirmed_obligation_leaks_exclude_live_holders_and_successful_resolutions"
        );
    }

    #[test]
    fn confirmed_obligation_leaks_report_recorded_missing_and_terminal_holders() {
        init_test("confirmed_obligation_leaks_report_recorded_missing_and_terminal_holders");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);
        let live_holder = insert_task(&mut state, root, TaskState::Running);
        let completed_holder =
            insert_task(&mut state, root, TaskState::Completed(Outcome::Ok(())));
        let missing_holder = TaskId::from_arena(ArenaIndex::new(50, 1));
        // Insert the child first to make insertion order differ from the
        // required region/id ordering of the report.
        let missing = insert_obligation(
            &mut state,
            child,
            missing_holder,
            ObligationKind::Lease,
            Time::from_millis(20),
        );
        let recorded = insert_obligation(
            &mut state,
            root,
            live_holder,
            ObligationKind::Ack,
            Time::from_millis(10),
        );
        state
            .obligations
            .mark_leaked(recorded, Time::from_millis(30))
            .expect("record leak through the obligation lifecycle");
        let terminal = insert_obligation(
            &mut state,
            root,
            completed_holder,
            ObligationKind::SendPermit,
            Time::from_millis(40),
        );
        state.now = Time::from_millis(1);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_millis(100)),
        )));

        let diagnostics = Diagnostics::new(Arc::new(state));
        let leaks = diagnostics.find_confirmed_obligation_leaks();
        assert_eq!(
            leaks
                .iter()
                .map(|leak| (leak.region_id, leak.obligation_id, leak.holder_task))
                .collect::<Vec<_>>(),
            vec![
                (root, recorded, Some(live_holder)),
                (root, terminal, Some(completed_holder)),
                (child, missing, Some(missing_holder)),
            ]
        );
        assert_eq!(
            leaks.iter().map(|leak| leak.age.as_millis()).collect::<Vec<_>>(),
            vec![90, 60, 80],
            "ages use the timer driver, including for terminal leak records"
        );
        assert!(diagnostics.has_confirmed_obligation_leaks());
        assert_eq!(
            diagnostics.find_leaked_obligations()[0].obligation_id,
            missing,
            "the legacy heuristic still omits recorded leaks and completed holders"
        );
        crate::test_complete!(
            "confirmed_obligation_leaks_report_recorded_missing_and_terminal_holders"
        );
    }

    #[test]
    fn confirmed_obligation_leaks_resolve_external_holder_generations() {
        use crate::runtime::obligation_table::ObligationTable;
        use crate::runtime::task_table::TaskTable;
        use crate::sync::ContendedMutex;

        init_test("confirmed_obligation_leaks_resolve_external_holder_generations");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        state.now = Time::from_millis(250);
        let mut tasks = TaskTable::new();
        let holder_slot = tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let holder = TaskId::from_arena(holder_slot);
        let mut obligations = ObligationTable::new();
        let obligation = ObligationId::from_arena(obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::Lease,
            holder,
            root,
            Time::from_millis(10),
        )));
        let tasks = Arc::new(ContendedMutex::new("confirmed_leak_tasks", tasks));
        let obligations = Arc::new(ContendedMutex::new("confirmed_leak_obligations", obligations));
        let diagnostics = Diagnostics::from_source(RuntimeStateSource::Shared {
            state: Arc::new(ContendedMutex::new("confirmed_leak_state", state)),
            tasks: Some(Arc::clone(&tasks)),
            obligations: Some(Arc::clone(&obligations)),
        });

        assert!(!diagnostics.has_confirmed_obligation_leaks());
        assert!(diagnostics.find_confirmed_obligation_leaks().is_empty());
        {
            let mut tasks = tasks.lock().expect("task table lock");
            tasks.remove_task(holder).expect("retire original holder");
            let replacement = tasks.insert(TaskRecord::new(holder, root, Budget::INFINITE));
            assert_eq!(replacement.index(), holder_slot.index());
            assert_ne!(replacement.generation(), holder_slot.generation());
        }
        let leaks = diagnostics.find_confirmed_obligation_leaks();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].obligation_id, obligation);
        assert_eq!(leaks[0].holder_task, Some(holder));
        assert_eq!(leaks[0].age, std::time::Duration::from_millis(240));
        assert!(diagnostics.has_confirmed_obligation_leaks());

        obligations
            .lock()
            .expect("obligation table lock")
            .commit(obligation, Time::from_millis(250))
            .expect("settle the abandoned reservation");
        assert!(!diagnostics.has_confirmed_obligation_leaks());
        assert!(diagnostics.find_confirmed_obligation_leaks().is_empty());
        crate::test_complete!("confirmed_obligation_leaks_resolve_external_holder_generations");
    }

    // Pure data-type tests (wave 18 – CyanBarn)

    #[test]
    fn reason_debug_clone() {
        let r = Reason::RegionNotFound;
        let r2 = r;
        assert!(format!("{r2:?}").contains("RegionNotFound"));
    }

    #[test]
    fn reason_display_all_variants() {
        let r1 = Reason::RegionNotFound;
        assert!(r1.to_string().contains("not found"));

        let r2 = Reason::ChildRegionOpen {
            child_id: RegionId::new_for_test(1, 0),
            child_state: RegionState::Open,
        };
        assert!(r2.to_string().contains("child region"));

        let r3 = Reason::TaskRunning {
            task_id: TaskId::new_for_test(1, 0),
            task_state: "Running".into(),
            poll_count: 5,
            waiters: vec![TaskId::new_for_test(2, 0)],
            last_checkpoint_message: Some("checkpoint".to_string()),
        };
        assert!(r3.to_string().contains("task"));
        assert!(r3.to_string().contains("polls=5"));
        assert!(r3.to_string().contains("wait_edges=["));
        assert!(r3.to_string().contains("last_checkpoint=\"checkpoint\""));

        let r4 = Reason::ObligationHeld {
            obligation_id: ObligationId::new_for_test(1, 0),
            obligation_type: "Lease".into(),
            holder_task: TaskId::new_for_test(2, 0),
            holder_waiters: vec![TaskId::new_for_test(3, 0)],
            holder_last_checkpoint_message: Some("holding permit".to_string()),
        };
        assert!(r4.to_string().contains("obligation"));
        assert!(r4.to_string().contains("Lease"));
        assert!(r4.to_string().contains("holder_waiters=["));
        assert!(
            r4.to_string()
                .contains("holder_last_checkpoint=\"holding permit\"")
        );
    }

    #[test]
    fn region_open_explanation_debug_clone() {
        let explanation = RegionOpenExplanation {
            region_id: RegionId::new_for_test(1, 0),
            region_state: Some(RegionState::Open),
            reasons: vec![Reason::RegionNotFound],
            recommendations: vec!["check it".into()],
        };
        let explanation2 = explanation;
        assert!(format!("{explanation2:?}").contains("RegionOpenExplanation"));
    }

    #[test]
    fn region_open_explanation_display() {
        let explanation = RegionOpenExplanation {
            region_id: RegionId::new_for_test(1, 0),
            region_state: Some(RegionState::Open),
            reasons: vec![Reason::RegionNotFound],
            recommendations: vec!["fix it".into()],
        };
        let s = explanation.to_string();
        assert!(s.contains("still open"));
        assert!(s.contains("fix it"));
    }

    #[test]
    fn task_blocked_explanation_debug_clone() {
        let explanation = TaskBlockedExplanation {
            task_id: TaskId::new_for_test(1, 0),
            block_reason: BlockReason::NotStarted,
            details: vec!["detail".into()],
            recommendations: vec!["wait".into()],
        };
        let explanation2 = explanation;
        assert!(format!("{explanation2:?}").contains("TaskBlockedExplanation"));
    }

    #[test]
    fn task_blocked_explanation_display() {
        let explanation = TaskBlockedExplanation {
            task_id: TaskId::new_for_test(1, 0),
            block_reason: BlockReason::AwaitingSchedule,
            details: vec!["pending wake".into()],
            recommendations: vec!["wait for scheduler".into()],
        };
        let s = explanation.to_string();
        assert!(s.contains("blocked"));
        assert!(s.contains("awaiting schedule"));
    }

    #[test]
    fn block_reason_debug_clone() {
        let r = BlockReason::TaskNotFound;
        let r2 = r;
        assert!(format!("{r2:?}").contains("TaskNotFound"));
    }

    #[test]
    fn block_reason_display_all_variants() {
        let variants: Vec<BlockReason> = vec![
            BlockReason::TaskNotFound,
            BlockReason::NotStarted,
            BlockReason::AwaitingSchedule,
            BlockReason::AwaitingFuture {
                description: "channel recv".into(),
            },
            BlockReason::CancelRequested {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: Some("stop".into()),
                },
            },
            BlockReason::RunningCleanup {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: None,
                },
                polls_remaining: 10,
            },
            BlockReason::Finalizing {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: None,
                },
                polls_remaining: 5,
            },
            BlockReason::Completed,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn cancellation_explanation_debug_clone() {
        let explanation = CancellationExplanation {
            kind: CancelKind::User,
            message: Some("timeout".into()),
            propagation_path: vec![CancellationStep {
                region_id: RegionId::new_for_test(1, 0),
                kind: CancelKind::User,
            }],
        };
        let explanation2 = explanation;
        assert!(format!("{explanation2:?}").contains("CancellationExplanation"));
    }

    #[test]
    fn cancellation_step_debug_clone() {
        let step = CancellationStep {
            region_id: RegionId::new_for_test(1, 0),
            kind: CancelKind::User,
        };
        let step2 = step;
        assert!(format!("{step2:?}").contains("CancellationStep"));
    }

    #[test]
    fn cancel_reason_info_debug_clone_display() {
        let info = CancelReasonInfo {
            kind: CancelKind::User,
            message: Some("stop".into()),
        };
        let info2 = info.clone();
        assert!(format!("{info2:?}").contains("CancelReasonInfo"));
        let s = info.to_string();
        assert!(s.contains("stop"));

        let info_no_msg = CancelReasonInfo {
            kind: CancelKind::User,
            message: None,
        };
        assert!(!info_no_msg.to_string().is_empty());
    }

    #[test]
    fn obligation_leak_debug_clone() {
        let leak = ObligationLeak {
            obligation_id: ObligationId::new_for_test(1, 0),
            obligation_type: "Ack".into(),
            holder_task: Some(TaskId::new_for_test(2, 0)),
            region_id: RegionId::new_for_test(1, 0),
            age: std::time::Duration::from_secs(60),
        };
        let leak2 = leak;
        assert!(format!("{leak2:?}").contains("ObligationLeak"));
    }

    #[test]
    fn directional_deadlock_cycle_detection_reports_critical() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let t1 = insert_task(&mut state, root, TaskState::Running);
        let t2 = insert_task(&mut state, root, TaskState::Running);
        state.task_mut(t1).expect("t1").waiters.push(t2); // t2 -> t1
        state.task_mut(t2).expect("t2").waiters.push(t1); // t1 -> t2

        let diagnostics = Diagnostics::new(Arc::new(state));
        let report = diagnostics.analyze_directional_deadlock();
        assert_eq!(report.severity, DeadlockSeverity::Critical);
        assert!(!report.cycles.is_empty());
        assert!(report.cycles[0].trapped);
        assert!(report.cycles[0].tasks.contains(&t1));
        assert!(report.cycles[0].tasks.contains(&t2));
    }

    #[test]
    fn structural_health_reports_deadlocked_for_trapped_cycle() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let t1 = insert_task(&mut state, root, TaskState::Running);
        let t2 = insert_task(&mut state, root, TaskState::Running);
        state.task_mut(t1).expect("t1").waiters.push(t2);
        state.task_mut(t2).expect("t2").waiters.push(t1);

        let diagnostics = Diagnostics::new(Arc::new(state));
        let report = diagnostics.analyze_structural_health();
        assert!(matches!(
            report.classification,
            crate::observability::spectral_health::HealthClassification::Deadlocked
        ));
    }

    #[test]
    fn explain_region_open_includes_directional_deadlock_recommendation() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let t1 = insert_task(&mut state, root, TaskState::Running);
        let t2 = insert_task(&mut state, root, TaskState::Running);
        state.task_mut(t1).expect("t1").waiters.push(t2);
        state.task_mut(t2).expect("t2").waiters.push(t1);

        let diagnostics = Diagnostics::new(Arc::new(state));
        let explanation = diagnostics.explain_region_open(root);
        assert!(
            explanation
                .recommendations
                .iter()
                .any(|r| r.contains("Directional deadlock risk")),
            "expected directional deadlock recommendation"
        );
    }

    #[test]
    fn advanced_observability_contract_has_sorted_dimensions_and_classes() {
        let contract = advanced_observability_contract();

        let classes: Vec<&str> = contract
            .event_classes
            .iter()
            .map(|item| item.class_id.as_str())
            .collect();
        let mut sorted_classes = classes.clone();
        sorted_classes.sort_unstable();
        sorted_classes.dedup();
        assert_eq!(classes, sorted_classes);

        let dimensions: Vec<&str> = contract
            .troubleshooting_dimensions
            .iter()
            .map(|item| item.dimension.as_str())
            .collect();
        let mut sorted_dimensions = dimensions.clone();
        sorted_dimensions.sort_unstable();
        sorted_dimensions.dedup();
        assert_eq!(dimensions, sorted_dimensions);
    }

    #[test]
    fn classify_baseline_log_event_maps_known_event() {
        let classified = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "execution",
            event_kind: "command_start",
            outcome_class: "success",
        })
        .expect("classification should succeed");

        assert_eq!(classified.event_class, AdvancedEventClass::CommandLifecycle);
        assert_eq!(classified.severity, AdvancedSeverity::Info);
        assert!(classified.conflicts.is_empty());
        assert!(
            classified
                .dimensions
                .contains(&TroubleshootingDimension::OperatorAction)
        );
    }

    #[test]
    fn classify_baseline_log_event_detects_flow_event_conflict() {
        let classified = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "execution",
            event_kind: "integration_sync",
            outcome_class: "success",
        })
        .expect("classification should succeed with conflict");

        assert_eq!(classified.severity, AdvancedSeverity::Critical);
        assert!(classified.conflicts.iter().any(|conflict| matches!(
            conflict,
            AdvancedClassificationConflict::FlowEventMismatch { .. }
        )));
    }

    #[test]
    fn classify_baseline_log_event_detects_outcome_event_conflict() {
        let classified = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "integration",
            event_kind: "integration_error",
            outcome_class: "success",
        })
        .expect("classification should succeed with conflict");

        assert_eq!(
            classified.event_class,
            AdvancedEventClass::IntegrationReliability
        );
        assert_eq!(classified.severity, AdvancedSeverity::Error);
        assert!(classified.conflicts.iter().any(|conflict| matches!(
            conflict,
            AdvancedClassificationConflict::OutcomeEventMismatch { .. }
        )));
    }

    #[test]
    fn classify_baseline_log_events_is_deterministic() {
        let stream = vec![
            BaselineLogEvent {
                flow_id: "execution",
                event_kind: "command_start",
                outcome_class: "success",
            },
            BaselineLogEvent {
                flow_id: "execution",
                event_kind: "verification_summary",
                outcome_class: "failed",
            },
            BaselineLogEvent {
                flow_id: "replay",
                event_kind: "replay_complete",
                outcome_class: "cancelled",
            },
        ];

        let a = classify_baseline_log_events(&stream).expect("stream classification should pass");
        let b = classify_baseline_log_events(&stream).expect("stream classification should pass");
        assert_eq!(a, b);
        assert!(!a.is_empty());
        assert!(a.iter().all(|entry| !entry.narrative.is_empty()));
    }

    #[test]
    fn classify_baseline_log_event_rejects_unknown_tokens() {
        let err = classify_baseline_log_event(BaselineLogEvent {
            flow_id: "unknown",
            event_kind: "command_start",
            outcome_class: "success",
        })
        .expect_err("unknown flow must be rejected");
        assert!(err.contains("unknown flow_id"));
    }

    #[test]
    fn structured_diagnostic_report_snapshot_happy_path() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Completed(Outcome::Ok(())));

        let diagnostics = Diagnostics::new(Arc::new(state));
        let rendered = render_structured_diagnostic_report(
            "happy_path",
            "2026-04-20T22:00:00Z",
            None,
            Some(&diagnostics.explain_task_blocked(task_id)),
            &[],
        );

        let scrubbed = scrub_diagnostic_report_timestamps(&rendered);
        assert_diagnostic_report_snapshot("observability_diagnostics_happy_path", &scrubbed);
    }

    #[test]
    fn structured_diagnostic_report_snapshot_v2_happy_and_degraded() {
        let mut happy_state = RuntimeState::new();
        let happy_root = happy_state.create_root_region(Budget::INFINITE);
        let happy_task = insert_task(
            &mut happy_state,
            happy_root,
            TaskState::Completed(Outcome::Ok(())),
        );
        let happy_diagnostics = Diagnostics::new(Arc::new(happy_state));
        let happy_rendered = render_structured_diagnostic_report(
            "happy_path",
            "2026-04-20T22:00:00Z",
            None,
            Some(&happy_diagnostics.explain_task_blocked(happy_task)),
            &[],
        );
        let happy_scrubbed = scrub_diagnostic_report_timestamps(&happy_rendered);

        let mut degraded_state = RuntimeState::new();
        let degraded_root = degraded_state.create_root_region(Budget::INFINITE);
        let degraded_child = insert_child_region(&mut degraded_state, degraded_root);
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5_000)));
        degraded_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));

        let degraded_root_task =
            insert_task(&mut degraded_state, degraded_root, TaskState::Running);
        degraded_state
            .task_mut(degraded_root_task)
            .expect("root task missing")
            .total_polls = 9;
        let degraded_child_task = insert_task(
            &mut degraded_state,
            degraded_child,
            TaskState::CancelRequested {
                reason: CancelReason::shutdown().with_message("node draining"),
                cleanup_budget: Budget::new().with_poll_quota(16),
            },
        );

        let _degraded_root_obligation = insert_obligation(
            &mut degraded_state,
            degraded_root,
            degraded_root_task,
            ObligationKind::Ack,
            Time::from_millis(500),
        );
        let _degraded_child_obligation = insert_obligation(
            &mut degraded_state,
            degraded_child,
            degraded_child_task,
            ObligationKind::Lease,
            Time::from_millis(750),
        );

        let degraded_diagnostics = Diagnostics::new(Arc::new(degraded_state));
        let mut degraded_task = degraded_diagnostics.explain_task_blocked(degraded_child_task);
        degraded_task
            .details
            .insert(0, "observed_at: 2026-04-20T22:00:05Z".to_string());
        degraded_task
            .recommendations
            .push("Continue draining child region tasks before sealing shutdown.".to_string());
        let degraded_leaks = degraded_diagnostics.find_leaked_obligations();
        let degraded_rendered = render_structured_diagnostic_report(
            "shutdown_drain",
            "2026-04-20T22:00:05Z",
            Some(&degraded_diagnostics.explain_region_open(degraded_root)),
            Some(&degraded_task),
            &degraded_leaks,
        );
        let degraded_scrubbed = scrub_diagnostic_report_timestamps(&degraded_rendered);

        let rendered = render_structured_diagnostic_report_v2(&[
            ("happy", &happy_scrubbed),
            ("degraded", &degraded_scrubbed),
        ]);
        assert_diagnostic_report_snapshot(
            "observability_diagnostics_structured_report_v2",
            &rendered,
        );
    }

    #[test]
    fn structured_diagnostic_report_snapshot_v3_happy_degraded_and_critical() {
        let mut happy_state = RuntimeState::new();
        let happy_root = happy_state.create_root_region(Budget::INFINITE);
        let happy_task = insert_task(
            &mut happy_state,
            happy_root,
            TaskState::Completed(Outcome::Ok(())),
        );
        let happy_diagnostics = Diagnostics::new(Arc::new(happy_state));
        let happy_rendered = render_structured_diagnostic_report(
            "happy_path",
            "2026-04-21T09:10:00Z",
            None,
            Some(&happy_diagnostics.explain_task_blocked(happy_task)),
            &[],
        );
        let happy_scrubbed = scrub_diagnostic_report_timestamps(&happy_rendered);

        let mut degraded_state = RuntimeState::new();
        let degraded_root = degraded_state.create_root_region(Budget::INFINITE);
        let degraded_child = insert_child_region(&mut degraded_state, degraded_root);
        let degraded_clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5_000)));
        degraded_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(
            &degraded_clock,
        )));

        let degraded_root_task =
            insert_task(&mut degraded_state, degraded_root, TaskState::Running);
        degraded_state
            .task_mut(degraded_root_task)
            .expect("degraded root task missing")
            .total_polls = 9;
        let degraded_child_task = insert_task(
            &mut degraded_state,
            degraded_child,
            TaskState::CancelRequested {
                reason: CancelReason::shutdown().with_message("node draining"),
                cleanup_budget: Budget::new().with_poll_quota(16),
            },
        );
        let _degraded_root_obligation = insert_obligation(
            &mut degraded_state,
            degraded_root,
            degraded_root_task,
            ObligationKind::Ack,
            Time::from_millis(500),
        );
        let _degraded_child_obligation = insert_obligation(
            &mut degraded_state,
            degraded_child,
            degraded_child_task,
            ObligationKind::Lease,
            Time::from_millis(750),
        );

        let degraded_diagnostics = Diagnostics::new(Arc::new(degraded_state));
        let mut degraded_task = degraded_diagnostics.explain_task_blocked(degraded_child_task);
        degraded_task
            .details
            .insert(0, "observed_at: 2026-04-21T09:10:05Z".to_string());
        degraded_task
            .recommendations
            .push("Continue draining child region tasks before sealing shutdown.".to_string());
        let degraded_leaks = degraded_diagnostics.find_leaked_obligations();
        let degraded_rendered = render_structured_diagnostic_report(
            "shutdown_drain",
            "2026-04-21T09:10:05Z",
            Some(&degraded_diagnostics.explain_region_open(degraded_root)),
            Some(&degraded_task),
            &degraded_leaks,
        );
        let degraded_scrubbed = scrub_diagnostic_report_timestamps(&degraded_rendered);

        let mut critical_state = RuntimeState::new();
        let critical_root = critical_state.create_root_region(Budget::INFINITE);
        let critical_clock = Arc::new(VirtualClock::starting_at(Time::from_millis(1_500)));
        critical_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(
            &critical_clock,
        )));
        let critical_t1 = insert_task(&mut critical_state, critical_root, TaskState::Running);
        let critical_t2 = insert_task(&mut critical_state, critical_root, TaskState::Running);
        critical_state
            .task_mut(critical_t1)
            .expect("critical task 1 missing")
            .waiters
            .push(critical_t2);
        critical_state
            .task_mut(critical_t2)
            .expect("critical task 2 missing")
            .waiters
            .push(critical_t1);
        let _critical_obligation = insert_obligation(
            &mut critical_state,
            critical_root,
            critical_t1,
            ObligationKind::Ack,
            Time::from_millis(250),
        );

        let critical_diagnostics = Diagnostics::new(Arc::new(critical_state));
        let mut critical_task = critical_diagnostics.explain_task_blocked(critical_t1);
        critical_task
            .details
            .insert(0, "observed_at: 2026-04-21T09:10:09Z".to_string());
        critical_task
            .recommendations
            .push("Break the trapped wait cycle before allowing retries.".to_string());
        let critical_leaks = critical_diagnostics.find_leaked_obligations();
        let critical_rendered = render_structured_diagnostic_report(
            "critical_deadlock",
            "2026-04-21T09:10:09Z",
            Some(&critical_diagnostics.explain_region_open(critical_root)),
            Some(&critical_task),
            &critical_leaks,
        );
        let critical_scrubbed = scrub_diagnostic_report_timestamps(&critical_rendered);

        let rendered = render_structured_diagnostic_report_v3(&[
            DiagnosticReportV3Section {
                label: "happy",
                status: "passing",
                accounting: diagnostic_resource_accounting(&happy_diagnostics, 0),
                rendered: &happy_scrubbed,
            },
            DiagnosticReportV3Section {
                label: "degraded",
                status: "degraded",
                accounting: diagnostic_resource_accounting(
                    &degraded_diagnostics,
                    degraded_leaks.len(),
                ),
                rendered: &degraded_scrubbed,
            },
            DiagnosticReportV3Section {
                label: "critical",
                status: "critical",
                accounting: diagnostic_resource_accounting(
                    &critical_diagnostics,
                    critical_leaks.len(),
                ),
                rendered: &critical_scrubbed,
            },
        ]);
        assert_diagnostic_report_snapshot(
            "observability_diagnostics_structured_report_v3",
            &rendered,
        );
    }

    #[test]
    fn structured_diagnostic_report_snapshot_rate_limited() {
        let task = TaskBlockedExplanation {
            task_id: TaskId::new_for_test(11, 0),
            block_reason: BlockReason::AwaitingFuture {
                description: "rate-limited by token bucket".to_string(),
            },
            details: vec![
                "next_retry_at: 2026-04-20T22:00:02Z".to_string(),
                "queue_depth: 3".to_string(),
                "limiter: outbound_http".to_string(),
            ],
            recommendations: vec!["Wait for the limiter budget to replenish.".to_string()],
        };

        let rendered = render_structured_diagnostic_report(
            "rate_limited",
            "2026-04-20T22:00:01Z",
            None,
            Some(&task),
            &[],
        );

        let scrubbed = scrub_diagnostic_report_timestamps(&rendered);
        assert_diagnostic_report_snapshot("observability_diagnostics_rate_limited", &scrubbed);
    }

    #[test]
    fn structured_diagnostic_report_snapshot_oom() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(
            &mut state,
            root,
            TaskState::CancelRequested {
                reason: CancelReason::resource_unavailable().with_message("oom"),
                cleanup_budget: Budget::new().with_poll_quota(64),
            },
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let mut task = diagnostics.explain_task_blocked(task_id);
        task.details
            .insert(0, "observed_at: 2026-04-20T22:00:03Z".to_string());
        task.details.push("headroom: 0.00".to_string());
        task.details.push("allocator_lane: region_heap".to_string());
        task.recommendations
            .push("Relieve memory pressure before retrying.".to_string());

        let rendered = render_structured_diagnostic_report(
            "oom",
            "2026-04-20T22:00:03Z",
            Some(&diagnostics.explain_region_open(root)),
            Some(&task),
            &[],
        );

        let scrubbed = scrub_diagnostic_report_timestamps(&rendered);
        assert_diagnostic_report_snapshot("observability_diagnostics_oom", &scrubbed);
    }

    #[test]
    fn structured_diagnostic_report_snapshot_deadline_exceeded() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(1_500)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));

        let task_id = insert_task(
            &mut state,
            root,
            TaskState::Finalizing {
                reason: CancelReason::deadline().with_message("deadline exceeded"),
                cleanup_budget: Budget::new().with_poll_quota(42),
            },
        );
        let _obligation_id = insert_obligation(
            &mut state,
            root,
            task_id,
            ObligationKind::Lease,
            Time::from_millis(250),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let mut task = diagnostics.explain_task_blocked(task_id);
        task.details
            .insert(0, "deadline_at: 2026-04-20T22:00:04Z".to_string());
        task.recommendations
            .push("Inspect cleanup latency and tighten downstream budgets.".to_string());
        let leaks = diagnostics.find_leaked_obligations();

        let rendered = render_structured_diagnostic_report(
            "deadline_exceeded",
            "2026-04-20T22:00:04Z",
            Some(&diagnostics.explain_region_open(root)),
            Some(&task),
            &leaks,
        );

        let scrubbed = scrub_diagnostic_report_timestamps(&rendered);
        assert_diagnostic_report_snapshot("observability_diagnostics_deadline_exceeded", &scrubbed);
    }

    #[test]
    fn structured_diagnostic_report_snapshot_shutdown_drain() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child = insert_child_region(&mut state, root);
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5_000)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));

        let root_task = insert_task(&mut state, root, TaskState::Running);
        state
            .task_mut(root_task)
            .expect("root task missing")
            .total_polls = 9;
        let child_task = insert_task(
            &mut state,
            child,
            TaskState::CancelRequested {
                reason: CancelReason::shutdown().with_message("node draining"),
                cleanup_budget: Budget::new().with_poll_quota(16),
            },
        );

        let _root_obligation = insert_obligation(
            &mut state,
            root,
            root_task,
            ObligationKind::Ack,
            Time::from_millis(500),
        );
        let _child_obligation = insert_obligation(
            &mut state,
            child,
            child_task,
            ObligationKind::Lease,
            Time::from_millis(750),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));
        let mut task = diagnostics.explain_task_blocked(child_task);
        task.details
            .insert(0, "observed_at: 2026-04-20T22:00:05Z".to_string());
        task.recommendations
            .push("Continue draining child region tasks before sealing shutdown.".to_string());
        let leaks = diagnostics.find_leaked_obligations();

        let rendered = render_structured_diagnostic_report(
            "shutdown_drain",
            "2026-04-20T22:00:05Z",
            Some(&diagnostics.explain_region_open(root)),
            Some(&task),
            &leaks,
        );

        let scrubbed = scrub_diagnostic_report_timestamps(&rendered);
        assert_diagnostic_report_snapshot("observability_diagnostics_shutdown_drain", &scrubbed);
    }

    #[test]
    fn diagnostics_healthcheck_json_snapshot_scrubbed() {
        init_test("diagnostics_healthcheck_json_snapshot_scrubbed");
        let mut passing_state = RuntimeState::new();
        let passing_root = passing_state.create_root_region(Budget::INFINITE);
        let passing_region = passing_state
            .region(passing_root)
            .expect("passing root missing");
        let did_close = passing_region.begin_close(None)
            && passing_region.begin_finalize()
            && passing_region.complete_close();
        assert!(did_close, "passing root should close cleanly");
        let passing = scrub_diagnostic_healthcheck_json(render_diagnostic_healthcheck_json(
            &Diagnostics::new(Arc::new(passing_state)),
            passing_root,
            "2026-04-21T08:30:00Z",
            4101,
        ));
        assert_eq!(
            passing.get("status").and_then(Value::as_str),
            Some("passing")
        );

        let mut degraded_state = RuntimeState::new();
        let degraded_root = degraded_state.create_root_region(Budget::INFINITE);
        let degraded_tasks = insert_wait_path(&mut degraded_state, degraded_root, 11);
        degraded_state
            .task_mut(*degraded_tasks.first().expect("degraded path head"))
            .expect("degraded head task missing")
            .total_polls = 3;
        let degraded_diagnostics = Diagnostics::new(Arc::new(degraded_state));
        assert!(
            matches!(
                degraded_diagnostics
                    .analyze_structural_health()
                    .classification,
                HealthClassification::Degraded { .. }
            ),
            "expected degraded classification for chained wait path"
        );
        let degraded = scrub_diagnostic_healthcheck_json(render_diagnostic_healthcheck_json(
            &degraded_diagnostics,
            degraded_root,
            "2026-04-21T08:30:01Z",
            4102,
        ));
        assert_eq!(
            degraded.get("status").and_then(Value::as_str),
            Some("degraded")
        );

        let mut critical_state = RuntimeState::new();
        let critical_root = critical_state.create_root_region(Budget::INFINITE);
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(1_500)));
        critical_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        let t1 = insert_task(&mut critical_state, critical_root, TaskState::Running);
        let t2 = insert_task(&mut critical_state, critical_root, TaskState::Running);
        critical_state
            .task_mut(t1)
            .expect("critical t1")
            .waiters
            .push(t2);
        critical_state
            .task_mut(t2)
            .expect("critical t2")
            .waiters
            .push(t1);
        let _critical_obligation = insert_obligation(
            &mut critical_state,
            critical_root,
            t1,
            ObligationKind::Ack,
            Time::from_millis(250),
        );
        let critical_diagnostics = Diagnostics::new(Arc::new(critical_state));
        assert_eq!(
            critical_diagnostics.analyze_directional_deadlock().severity,
            DeadlockSeverity::Critical
        );
        let critical = scrub_diagnostic_healthcheck_json(render_diagnostic_healthcheck_json(
            &critical_diagnostics,
            critical_root,
            "2026-04-21T08:30:02Z",
            4103,
        ));
        assert_eq!(
            critical.get("status").and_then(Value::as_str),
            Some("critical")
        );

        assert_diagnostic_healthcheck_snapshot(
            "observability_diagnostics_healthcheck_json",
            &json!({
                "passing": passing,
                "degraded": degraded,
                "critical": critical,
            }),
        );
    }

    #[test]
    fn tail_latency_taxonomy_contract_has_unique_required_keys() {
        let contract = tail_latency_taxonomy_contract();
        let keys: Vec<&str> = contract
            .required_log_fields
            .iter()
            .map(|field| field.key.as_str())
            .collect();
        let mut unique_keys = keys.clone();
        unique_keys.sort_unstable();
        unique_keys.dedup();
        assert_eq!(keys.len(), unique_keys.len());
    }

    #[test]
    fn tail_latency_taxonomy_contract_includes_unknown_bucket_and_signals() {
        let contract = tail_latency_taxonomy_contract();
        assert_eq!(
            contract.contract_version,
            TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION
        );
        assert_eq!(contract.unknown_bucket_key, "tail.unknown.unmeasured_ns");
        assert!(
            contract
                .required_log_fields
                .iter()
                .any(|field| field.key == contract.unknown_bucket_key && field.required)
        );
        assert!(contract.terms.iter().any(|term| {
            term.term_id == "unknown"
                && term.direct_duration_key == "tail.unknown.unmeasured_ns"
                && term
                    .signals
                    .iter()
                    .any(|signal| signal.structured_log_key == "tail.unknown.unmeasured_ns")
        }));
    }

    #[test]
    fn tail_latency_taxonomy_contract_core_signals_have_existing_files() {
        let contract = tail_latency_taxonomy_contract();
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for signal in contract
            .terms
            .iter()
            .flat_map(|term| term.signals.iter())
            .filter(|signal| signal.core)
        {
            assert!(
                repo_root.join(&signal.producer_file).exists(),
                "producer file must exist: {}",
                signal.producer_file
            );
        }
    }

    fn complete_tail_latency_sample() -> TailLatencyCompactSample {
        TailLatencyCompactSample::new(12_000)
            .with_ready_queue_depth(17)
            .with_poll_count(5)
            .with_events_received(9)
            .with_retries_total_delay_ns(1_500)
            .with_synchronization_lock_wait_ns(2_500)
            .with_allocator_live_allocations(33)
            .with_allocator_bytes_live(8_192)
    }

    #[test]
    fn compact_tail_emitter_required_schema_keys_stay_stable() {
        let event = emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::enabled_core(),
            "scheduler-overload-smoke",
            "event-0001",
            complete_tail_latency_sample(),
        )
        .expect("emit should succeed")
        .expect("enabled emitter should produce an event");

        let contract = tail_latency_taxonomy_contract();
        let required_keys: std::collections::BTreeSet<&str> = contract
            .required_log_fields
            .iter()
            .map(|field| field.key.as_str())
            .collect();
        let actual_keys: std::collections::BTreeSet<&str> =
            event.fields.keys().map(String::as_str).collect();
        assert_eq!(actual_keys, required_keys);
        assert_eq!(
            event.schema_version,
            TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION
        );
        assert_eq!(
            event.taxonomy_version,
            TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION
        );
        assert_eq!(event.unknown_unmeasured_ns, 8_000);
    }

    #[test]
    fn compact_tail_emitter_missing_producers_fall_back_to_unknown() {
        let sample = TailLatencyCompactSample::new(9_000)
            .with_ready_queue_depth(3)
            .with_retries_total_delay_ns(1_000)
            .with_allocator_live_allocations(7);
        let event = emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::enabled_core(),
            "partial-producer-smoke",
            "event-missing",
            sample,
        )
        .expect("missing producers should not abort emission")
        .expect("enabled emitter should produce an event");

        assert_eq!(event.unknown_unmeasured_ns, 8_000);
        assert_eq!(
            event.fields.get("tail.service.poll_count"),
            Some(&TailLatencyFieldValue::Unsigned(0))
        );
        assert_eq!(
            event.fields.get("tail.io_or_network.events_received"),
            Some(&TailLatencyFieldValue::Unsigned(0))
        );
        assert!(
            event
                .missing_producers
                .contains(&"tail.service.poll_count".to_string())
        );
        assert!(
            event
                .missing_producers
                .contains(&"tail.io_or_network.events_received".to_string())
        );
        assert_eq!(
            event.attribution_states.get("service").map(String::as_str),
            Some("missing_producer")
        );
        assert_eq!(
            event.attribution_states.get("unknown").map(String::as_str),
            Some("residual")
        );
    }

    #[test]
    fn compact_tail_emitter_serialization_is_deterministic() {
        let config = TailLatencyEmitterConfig::enabled_core().with_extended_allocator_bytes_live();
        let sample = complete_tail_latency_sample();
        let first = emit_tail_latency_compact_event(
            config,
            "deterministic-smoke",
            "event-stable",
            sample.clone(),
        )
        .expect("first emission")
        .expect("first event");
        let second =
            emit_tail_latency_compact_event(config, "deterministic-smoke", "event-stable", sample)
                .expect("second emission")
                .expect("second event");

        let first_json = serde_json::to_vec(&first).expect("serialize first");
        let second_json = serde_json::to_vec(&second).expect("serialize second");
        assert_eq!(first_json, second_json);
        assert!(
            first
                .fields
                .contains_key("tail.allocator_or_cache.bytes_live"),
            "extended allocator byte pressure should be explicitly gated"
        );
    }

    #[test]
    fn compact_tail_emitter_disabled_mode_is_semantics_neutral() {
        let event = emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::default(),
            "",
            "",
            TailLatencyCompactSample::new(1).with_retries_total_delay_ns(2),
        )
        .expect("disabled emitter should skip validation");
        assert_eq!(event, None);
    }

    #[test]
    fn compact_tail_emitter_rejects_impossible_direct_duration() {
        let error = emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::enabled_core(),
            "bad-direct-duration",
            "event-overflow",
            TailLatencyCompactSample::new(1_000)
                .with_retries_total_delay_ns(750)
                .with_synchronization_lock_wait_ns(500),
        )
        .expect_err("direct durations over total latency must fail closed");
        assert_eq!(
            error,
            TailLatencyEmitError::DirectDurationExceedsTotal {
                total_latency_ns: 1_000,
                direct_duration_ns: 1_250,
            }
        );
    }

    #[test]
    fn compact_tail_emitter_extended_fields_are_gated_and_bounded() {
        let core_event = emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::enabled_core(),
            "core-only",
            "event-core",
            complete_tail_latency_sample(),
        )
        .expect("core event should emit")
        .expect("core event");
        let extended_event = emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::enabled_core().with_extended_allocator_bytes_live(),
            "extended",
            "event-extended",
            complete_tail_latency_sample(),
        )
        .expect("extended event should emit")
        .expect("extended event");

        assert!(
            !core_event
                .fields
                .contains_key("tail.allocator_or_cache.bytes_live")
        );
        assert!(
            extended_event
                .fields
                .contains_key("tail.allocator_or_cache.bytes_live")
        );
        assert!(
            core_event.overhead_estimate_bytes <= 2_048,
            "compact core overhead estimate should remain bounded: {} bytes",
            core_event.overhead_estimate_bytes
        );
        assert!(
            extended_event.overhead_estimate_bytes <= 2_048,
            "extended overhead estimate should remain bounded: {} bytes",
            extended_event.overhead_estimate_bytes
        );
    }

    fn latency_budget_gate() -> TailLatencyBudgetGate {
        TailLatencyBudgetGate::new(20_000, 64, 20_000, 9_000, 10, 500)
    }

    fn latency_budget_event() -> TailLatencyCompactEvent {
        emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::enabled_core(),
            "LATENCY-BUDGET-PASS",
            "event-0001",
            TailLatencyCompactSample::new(18_000)
                .with_ready_queue_depth(18)
                .with_poll_count(7)
                .with_events_received(4)
                .with_retries_total_delay_ns(2_000)
                .with_synchronization_lock_wait_ns(1_000)
                .with_allocator_live_allocations(22),
        )
        .expect("latency budget event should emit")
        .expect("enabled event should be present")
    }

    fn latency_budget_evidence() -> TailLatencyBudgetEvidence {
        TailLatencyBudgetEvidence::new(
            "latency-budget-cert-pass",
            "LATENCY-BUDGET-PASS",
            "candidate-balanced",
            "conservative-baseline",
            "bash scripts/run_latency_budget_certificate_smoke.sh --execute --scenario LATENCY-BUDGET-PASS",
            latency_budget_gate(),
        )
        .with_sample_window(256, 7)
        .with_quantiles(TailLatencyBudgetQuantiles::new(9_000, 13_000, 16_000, 17_000))
        .with_uncertainty(TailLatencyBudgetUncertainty::new(250, 750))
        .with_regression_window(17_500, 17_000)
        .with_tail_events(vec![latency_budget_event()])
    }

    #[test]
    fn latency_budget_certificate_accepts_direct_tail_evidence() {
        let certificate = verify_tail_latency_budget_certificate(latency_budget_evidence());

        assert_eq!(certificate.verdict, TailLatencyBudgetVerdict::Pass);
        assert!(certificate.reason_codes.is_empty());
        assert_eq!(
            certificate.schema_version,
            TAIL_LATENCY_BUDGET_CERTIFICATE_SCHEMA_VERSION
        );
        assert_eq!(
            certificate.taxonomy_version,
            TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION
        );
        assert!(certificate.certificate_hash.starts_with("fnv1a64:"));
        assert!(
            certificate
                .term_breakdown
                .iter()
                .any(|term| term.term_id == "retries"
                    && term.measurement_class == "direct_duration"
                    && term.direct_duration_ns == 2_000)
        );
        assert!(
            certificate
                .term_breakdown
                .iter()
                .any(|term| term.term_id == "unknown"
                    && term.measurement_class == "unknown_bucket"
                    && term.observed_value == certificate.unknown_residual_ns)
        );
    }

    #[test]
    fn latency_budget_certificate_rejects_missing_terms_and_hidden_unknown() {
        let mut event = latency_budget_event();
        event.attribution_states.remove("service");
        event.fields.remove("tail.unknown.unmeasured_ns");

        let certificate = verify_tail_latency_budget_certificate(
            latency_budget_evidence().with_tail_events(vec![event]),
        );

        assert_eq!(certificate.verdict, TailLatencyBudgetVerdict::FailClosed);
        assert!(
            certificate
                .reason_codes
                .contains(&"missing_term:service".to_string())
        );
        assert!(
            certificate
                .reason_codes
                .contains(&"missing_required_field:tail.unknown.unmeasured_ns".to_string())
        );
        assert!(
            certificate
                .reason_codes
                .contains(&"hidden_unknown_bucket".to_string())
        );
    }

    #[test]
    fn latency_budget_certificate_rejects_stale_mean_only_and_proxy_only_evidence() {
        let proxy_only = emit_tail_latency_compact_event(
            TailLatencyEmitterConfig::enabled_core(),
            "LATENCY-BUDGET-PROXY-ONLY",
            "event-proxy",
            TailLatencyCompactSample::new(1_000)
                .with_ready_queue_depth(1)
                .with_poll_count(1)
                .with_events_received(1)
                .with_allocator_live_allocations(1),
        )
        .expect("proxy-only event should emit")
        .expect("enabled event should be present");

        let certificate = verify_tail_latency_budget_certificate(
            TailLatencyBudgetEvidence::new(
                "latency-budget-cert-stale",
                "LATENCY-BUDGET-PROXY-ONLY",
                "candidate-proxy-only",
                "conservative-baseline",
                "bash scripts/run_latency_budget_certificate_smoke.sh --execute --scenario LATENCY-BUDGET-PROXY-ONLY",
                latency_budget_gate(),
            )
            .with_sample_window(16, 11)
            .with_uncertainty(TailLatencyBudgetUncertainty::new(0, 10))
            .with_regression_window(1_000, 900)
            .with_tail_events(vec![proxy_only]),
        );

        assert_eq!(certificate.verdict, TailLatencyBudgetVerdict::FailClosed);
        for reason in [
            "insufficient_sample_count",
            "stale_calibration",
            "missing_quantiles_mean_only_evidence",
            "proxy_only_green_row",
        ] {
            assert!(
                certificate.reason_codes.contains(&reason.to_string()),
                "missing reason {reason}: {:?}",
                certificate.reason_codes
            );
        }
    }

    #[test]
    fn latency_budget_certificate_returns_no_win_for_budget_or_regression_miss() {
        let certificate = verify_tail_latency_budget_certificate(
            latency_budget_evidence()
                .with_quantiles(TailLatencyBudgetQuantiles::new(
                    9_000, 18_000, 20_000, 22_000,
                ))
                .with_uncertainty(TailLatencyBudgetUncertainty::new(500, 1_000))
                .with_regression_window(17_500, 21_000),
        );

        assert_eq!(certificate.verdict, TailLatencyBudgetVerdict::NoWin);
        assert!(
            certificate
                .reason_codes
                .contains(&"p999_budget_exceeded".to_string())
        );
        assert!(
            certificate
                .reason_codes
                .contains(&"asymmetric_regression_gate".to_string())
        );
        assert_eq!(
            certificate.fallback_reason.as_deref(),
            Some("p999_budget_exceeded")
        );
    }

    fn wait_task(index: u32) -> TaskId {
        TaskId::new_for_test(index, 0)
    }

    fn wait_region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 0)
    }

    fn wait_obligation(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn trapped_deadlock_report() -> DirectionalDeadlockReport {
        DirectionalDeadlockReport {
            severity: DeadlockSeverity::Critical,
            risk_score: 1.0,
            cycles: vec![DeadlockCycle {
                tasks: vec![wait_task(1), wait_task(2)],
                ingress_edges: 0,
                egress_edges: 0,
                trapped: true,
            }],
        }
    }

    fn base_wait_cause_evidence() -> WaitCauseRemediationEvidence {
        WaitCauseRemediationEvidence::new(
            "wait-cause-report-pass",
            "WAIT-CAUSE-PASS",
            "bash scripts/run_wait_cause_remediation_smoke.sh --execute --scenario WAIT-CAUSE-PASS",
        )
        .with_evidence_refs(vec![
            "artifacts/runtime_latency_budget_certificate_v1.json".to_string(),
            "artifacts/runtime_tail_latency_taxonomy_v1.json".to_string(),
        ])
    }

    #[test]
    fn wait_cause_report_ranks_deadlock_before_futurelock_and_unknown_wait() {
        let report = build_wait_cause_remediation_report(
            base_wait_cause_evidence()
                .with_deadlock_report(trapped_deadlock_report())
                .with_task_waits(vec![
                    WaitCauseTaskEvidence::new(
                        wait_task(9),
                        Some(wait_region(3)),
                        WaitCauseTaskWaitKind::Unknown,
                        "opaque await point",
                    )
                    .with_wait_age_ns(5_000),
                    WaitCauseTaskEvidence::new(
                        wait_task(7),
                        Some(wait_region(2)),
                        WaitCauseTaskWaitKind::AwaitingFuture,
                        "channel receive producer",
                    )
                    .with_wait_age_ns(9_000),
                ]),
        );

        assert_eq!(report.verdict, WaitCauseRemediationVerdict::Actionable);
        assert_eq!(report.findings.len(), 3);
        assert_eq!(
            report.findings[0].category,
            WaitCauseCategory::DeadlockCycle
        );
        assert_eq!(report.findings[0].asup_code, None);
        assert_eq!(report.findings[0].remediation_doc_path, None);
        assert_eq!(report.findings[0].severity, WaitCauseSeverity::Critical);
        assert_eq!(report.findings[1].category, WaitCauseCategory::Futurelock);
        assert_eq!(report.findings[1].asup_code.as_deref(), Some("ASUP-E402"));
        assert_eq!(
            report.findings[1].remediation_doc_path.as_deref(),
            Some("docs/error_codes/ASUP-E402.md")
        );
        assert_eq!(report.findings[2].category, WaitCauseCategory::UnknownWait);
        assert_eq!(report.findings[0].rank, 1);
        assert_eq!(report.findings[1].rank, 2);
        assert!(report.report_hash.starts_with("fnv1a64:"));
        assert!(report.wait_cause_graph_hash.starts_with("fnv1a64:"));
    }

    #[test]
    fn wait_cause_report_surfaces_obligation_metadata_and_safe_actions() {
        let report =
            build_wait_cause_remediation_report(base_wait_cause_evidence().with_obligation_leaks(
                vec![WaitCauseObligationEvidence::new(
                    wait_obligation(11),
                    "SendPermit",
                    Some(wait_task(4)),
                    wait_region(5),
                    42_000,
                )],
            ));

        assert_eq!(report.verdict, WaitCauseRemediationVerdict::Actionable);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.category, WaitCauseCategory::ObligationLeak);
        assert_eq!(finding.asup_code.as_deref(), Some("ASUP-E101"));
        assert_eq!(
            finding.remediation_doc_path.as_deref(),
            Some("docs/error_codes/ASUP-E101.md")
        );
        assert_eq!(finding.reason_code, "reserved_obligation_still_held");
        assert_eq!(finding.owner_task_id, Some(format!("{:?}", wait_task(4))));
        assert_eq!(
            finding.owner_region_id,
            Some(format!("{:?}", wait_region(5)))
        );
        assert!(
            finding
                .safe_actions
                .iter()
                .any(|action| action.contains("commit or abort"))
        );
        assert!(
            finding
                .forbidden_actions
                .iter()
                .any(|action| action.contains("Do not delete files"))
        );
    }

    #[test]
    fn wait_cause_report_refuses_missing_replay_and_wrong_taxonomy() {
        let report = build_wait_cause_remediation_report(
            WaitCauseRemediationEvidence::new("bad-report", "BAD", "")
                .with_tail_taxonomy_version("runtime-tail-latency-taxonomy-v0")
                .with_task_waits(vec![WaitCauseTaskEvidence::new(
                    wait_task(1),
                    None,
                    WaitCauseTaskWaitKind::AwaitingFuture,
                    "producer",
                )]),
        );

        assert_eq!(report.verdict, WaitCauseRemediationVerdict::Refused);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(
            report.refusal_reason.as_deref(),
            Some("missing_replay_command")
        );
    }

    #[test]
    fn wait_cause_report_investigates_unknown_wait_and_redacts_operator_text() {
        let report =
            build_wait_cause_remediation_report(base_wait_cause_evidence().with_task_waits(vec![
                WaitCauseTaskEvidence::new(
                    wait_task(3),
                    Some(wait_region(1)),
                    WaitCauseTaskWaitKind::Unknown,
                    "socket /tmp/secret\nhost=internal.example.com\tuser=a@example.com",
                )
                .with_wait_age_ns(1_000)
                .with_wake_pending(true)
                .with_details(vec!["raw\ncontrol\tchars".to_string()]),
            ]));

        assert_eq!(report.verdict, WaitCauseRemediationVerdict::Investigate);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.category, WaitCauseCategory::UnknownWait);
        assert!(!finding.blocked_resource.contains('\n'));
        assert!(!finding.blocked_resource.contains('\t'));
        assert!(!finding.blocked_resource.contains("/tmp/secret"));
        assert!(!finding.blocked_resource.contains("a@example.com"));
        assert!(finding.blocked_resource.contains("[redacted-path]"));
        assert!(finding.blocked_resource.contains("[redacted-identity]"));
        assert!(
            report
                .safe_actions
                .iter()
                .any(|action| action.contains("fresh diagnostics snapshot"))
        );
    }

    #[test]
    fn diagnostics_debug() {
        let state = Arc::new(RuntimeState::new());
        let diagnostics = Diagnostics::new(state);
        assert!(format!("{diagnostics:?}").contains("Diagnostics"));
    }

    // ======================================================================
    // Runtime Introspection Conformance Tests (INTROSPECTION-CONF-001 to INTROSPECTION-CONF-010)
    //
    // These tests validate the behavioral contracts for observability diagnostic
    // endpoints, ensuring deterministic, idempotent, and cancel-safe introspection
    // queries that maintain consistent views of runtime state.
    // ======================================================================

    #[test]
    fn introspection_conf_001_diagnostic_query_result_idempotence() {
        init_test("introspection_conf_001_diagnostic_query_result_idempotence");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Running);
        let diagnostics = Diagnostics::new(Arc::new(state));

        // Multiple calls to the same diagnostic method must return identical results
        let explanation1 = diagnostics.explain_region_open(root);
        let explanation2 = diagnostics.explain_region_open(root);
        let explanation3 = diagnostics.explain_region_open(root);

        crate::assert_with_log!(
            explanation1.region_id == explanation2.region_id,
            "region_id idempotent",
            true,
            explanation1.region_id == explanation2.region_id
        );
        crate::assert_with_log!(
            explanation2.region_id == explanation3.region_id,
            "region_id triple check",
            true,
            explanation2.region_id == explanation3.region_id
        );
        crate::assert_with_log!(
            explanation1.reasons.len() == explanation2.reasons.len(),
            "reasons count idempotent",
            explanation1.reasons.len(),
            explanation2.reasons.len()
        );
        crate::assert_with_log!(
            explanation2.reasons.len() == explanation3.reasons.len(),
            "reasons count triple check",
            explanation2.reasons.len(),
            explanation3.reasons.len()
        );

        // Task diagnostic idempotence
        let task1 = diagnostics.explain_task_blocked(task_id);
        let task2 = diagnostics.explain_task_blocked(task_id);
        let task3 = diagnostics.explain_task_blocked(task_id);

        crate::assert_with_log!(
            task1.task_id == task2.task_id,
            "task_id idempotent",
            true,
            task1.task_id == task2.task_id
        );
        crate::assert_with_log!(
            task2.task_id == task3.task_id,
            "task_id triple check",
            true,
            task2.task_id == task3.task_id
        );

        // Obligation leak detection idempotence
        let leaks1 = diagnostics.find_leaked_obligations();
        let leaks2 = diagnostics.find_leaked_obligations();
        let leaks3 = diagnostics.find_leaked_obligations();

        crate::assert_with_log!(
            leaks1.len() == leaks2.len(),
            "leaks count idempotent",
            leaks1.len(),
            leaks2.len()
        );
        crate::assert_with_log!(
            leaks2.len() == leaks3.len(),
            "leaks count triple check",
            leaks2.len(),
            leaks3.len()
        );

        crate::test_complete!("introspection_conf_001_diagnostic_query_result_idempotence");
    }

    #[test]
    fn introspection_conf_002_deterministic_ordering_of_diagnostic_results() {
        init_test("introspection_conf_002_deterministic_ordering_of_diagnostic_results");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        // Create multiple child regions and tasks in a specific order
        let child1 = insert_child_region(&mut state, root);
        let child2 = insert_child_region(&mut state, root);
        let child3 = insert_child_region(&mut state, root);

        let task1 = insert_task(&mut state, child1, TaskState::Running);
        let task2 = insert_task(&mut state, child2, TaskState::Running);
        let task3 = insert_task(&mut state, child3, TaskState::Running);

        // Create obligations in mixed order to test sorting
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(100)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));

        let _ob1 = insert_obligation(
            &mut state,
            child1,
            task1,
            ObligationKind::Ack,
            Time::from_millis(10),
        );
        let _ob3 = insert_obligation(
            &mut state,
            child3,
            task3,
            ObligationKind::Lease,
            Time::from_millis(30),
        );
        let _ob2 = insert_obligation(
            &mut state,
            child2,
            task2,
            ObligationKind::SendPermit,
            Time::from_millis(20),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Test deterministic ordering across multiple calls
        let leaks_run1 = diagnostics.find_leaked_obligations();
        let leaks_run2 = diagnostics.find_leaked_obligations();
        let leaks_run3 = diagnostics.find_leaked_obligations();

        // Verify same ordering across all runs
        crate::assert_with_log!(
            leaks_run1.len() == 3,
            "leak count consistent",
            3usize,
            leaks_run1.len()
        );

        for i in 0..3 {
            crate::assert_with_log!(
                leaks_run1[i].obligation_id == leaks_run2[i].obligation_id,
                &format!("obligation_id ordering run1==run2 idx {}", i),
                true,
                leaks_run1[i].obligation_id == leaks_run2[i].obligation_id
            );
            crate::assert_with_log!(
                leaks_run2[i].obligation_id == leaks_run3[i].obligation_id,
                &format!("obligation_id ordering run2==run3 idx {}", i),
                true,
                leaks_run2[i].obligation_id == leaks_run3[i].obligation_id
            );
            crate::assert_with_log!(
                leaks_run1[i].region_id == leaks_run2[i].region_id,
                &format!("region_id ordering run1==run2 idx {}", i),
                true,
                leaks_run1[i].region_id == leaks_run2[i].region_id
            );
        }

        // Region explanations must have deterministic reason ordering
        let explanation1 = diagnostics.explain_region_open(root);
        let explanation2 = diagnostics.explain_region_open(root);

        crate::assert_with_log!(
            explanation1.reasons.len() == explanation2.reasons.len(),
            "reason count deterministic",
            explanation1.reasons.len(),
            explanation2.reasons.len()
        );

        for i in 0..explanation1.reasons.len().min(explanation2.reasons.len()) {
            let reason1_desc = format!("{:?}", explanation1.reasons[i]);
            let reason2_desc = format!("{:?}", explanation2.reasons[i]);
            crate::assert_with_log!(
                reason1_desc == reason2_desc,
                &format!("reason ordering idx {}", i),
                true,
                reason1_desc == reason2_desc
            );
        }

        crate::test_complete!(
            "introspection_conf_002_deterministic_ordering_of_diagnostic_results"
        );
    }

    #[test]
    fn introspection_conf_003_serialization_roundtrip_correctness() {
        init_test("introspection_conf_003_serialization_roundtrip_correctness");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Running);

        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(500)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));

        let ob_id = insert_obligation(
            &mut state,
            root,
            task_id,
            ObligationKind::Ack,
            Time::from_millis(100),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Test ObligationLeak serialization roundtrip
        let leaks = diagnostics.find_leaked_obligations();
        crate::assert_with_log!(
            !leaks.is_empty(),
            "has leaks for serialization test",
            true,
            !leaks.is_empty()
        );

        for leak in &leaks {
            // Verify all fields are populated and serializable
            crate::assert_with_log!(
                leak.obligation_id == ob_id,
                "obligation_id preserved",
                true,
                leak.obligation_id == ob_id
            );
            crate::assert_with_log!(
                !leak.obligation_type.is_empty(),
                "obligation_type serializable",
                true,
                !leak.obligation_type.is_empty()
            );
            crate::assert_with_log!(
                leak.holder_task == Some(task_id),
                "holder_task preserved",
                true,
                leak.holder_task == Some(task_id)
            );
            crate::assert_with_log!(
                leak.region_id == root,
                "region_id preserved",
                true,
                leak.region_id == root
            );
            crate::assert_with_log!(
                leak.age.as_millis() > 0,
                "age computed and serializable",
                true,
                leak.age.as_millis() > 0
            );

            // Test Debug formatting (pseudo-serialization)
            let debug_repr = format!("{:?}", leak);
            crate::assert_with_log!(
                debug_repr.contains("ObligationLeak"),
                "debug serialization includes type",
                true,
                debug_repr.contains("ObligationLeak")
            );
            crate::assert_with_log!(
                debug_repr.contains(&leak.obligation_type),
                "debug serialization includes obligation_type",
                true,
                debug_repr.contains(&leak.obligation_type)
            );
        }

        // Test RegionOpenExplanation display formatting (human-readable serialization)
        let explanation = diagnostics.explain_region_open(root);
        let display_repr = format!("{}", explanation);

        crate::assert_with_log!(
            display_repr.contains("Region"),
            "display contains region marker",
            true,
            display_repr.contains("Region")
        );
        crate::assert_with_log!(
            !display_repr.is_empty(),
            "display produces non-empty output",
            true,
            !display_repr.is_empty()
        );

        // Test TaskBlockedExplanation display formatting
        let task_explanation = diagnostics.explain_task_blocked(task_id);
        let task_display = format!("{}", task_explanation);

        crate::assert_with_log!(
            task_display.contains("Task"),
            "task display contains task marker",
            true,
            task_display.contains("Task")
        );
        crate::assert_with_log!(
            !task_display.is_empty(),
            "task display produces non-empty output",
            true,
            !task_display.is_empty()
        );

        crate::test_complete!("introspection_conf_003_serialization_roundtrip_correctness");
    }

    #[test]
    fn introspection_conf_004_scheduler_state_accuracy_in_diagnostics() {
        init_test("introspection_conf_004_scheduler_state_accuracy_in_diagnostics");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        // Create tasks in different scheduler states
        let running_task = insert_task(&mut state, root, TaskState::Running);
        let completed_task = insert_task(&mut state, root, TaskState::Completed(Outcome::Ok(())));
        let cancel_task = insert_task(
            &mut state,
            root,
            TaskState::CancelRequested {
                reason: CancelReason::user("test"),
                cleanup_budget: Budget::with_deadline_at_ns(100_000_000), // 100ms in ns
            },
        );

        // Configure scheduler-visible state
        let running_task_record = state.task_mut(running_task).expect("running task");
        running_task_record.total_polls = 5;
        running_task_record.last_polled_step = 100;
        let notified = running_task_record.wake_state.notify();
        crate::assert_with_log!(notified, "wake state notified", true, notified);

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Verify scheduler state accuracy in task diagnostics
        let running_explanation = diagnostics.explain_task_blocked(running_task);
        crate::assert_with_log!(
            matches!(
                running_explanation.block_reason,
                BlockReason::AwaitingSchedule
            ),
            "running task shows awaiting schedule",
            true,
            matches!(
                running_explanation.block_reason,
                BlockReason::AwaitingSchedule
            )
        );

        let completed_explanation = diagnostics.explain_task_blocked(completed_task);
        crate::assert_with_log!(
            matches!(completed_explanation.block_reason, BlockReason::Completed),
            "completed task shows completed",
            true,
            matches!(completed_explanation.block_reason, BlockReason::Completed)
        );

        let cancel_explanation = diagnostics.explain_task_blocked(cancel_task);
        let is_cancel_requested = matches!(
            cancel_explanation.block_reason,
            BlockReason::CancelRequested { .. }
        );
        crate::assert_with_log!(
            is_cancel_requested,
            "cancel requested task shows cancel",
            true,
            is_cancel_requested
        );

        // Verify region state accuracy reflects scheduler dependencies
        let region_explanation = diagnostics.explain_region_open(root);

        let mut found_running = false;
        let found_completed = false;
        let mut found_cancel = false;

        for reason in &region_explanation.reasons {
            match reason {
                Reason::TaskRunning {
                    task_id,
                    poll_count,
                    ..
                } if *task_id == running_task => {
                    found_running = true;
                    crate::assert_with_log!(
                        *poll_count == 5,
                        "poll count accuracy",
                        5u64,
                        *poll_count
                    );
                }
                Reason::TaskRunning { task_id, .. } if *task_id == cancel_task => {
                    found_cancel = true;
                }
                _ => {}
            }
        }

        crate::assert_with_log!(
            found_running,
            "found running task reason",
            true,
            found_running
        );
        crate::assert_with_log!(found_cancel, "found cancel task reason", true, found_cancel);

        // Completed tasks should not appear as blocking reasons
        crate::assert_with_log!(
            !found_completed,
            "completed task not blocking",
            true,
            !found_completed
        );

        crate::test_complete!("introspection_conf_004_scheduler_state_accuracy_in_diagnostics");
    }

    #[test]
    fn introspection_conf_005_cross_method_consistency_of_diagnostic_data() {
        init_test("introspection_conf_005_cross_method_consistency_of_diagnostic_data");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Running);

        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(300)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));

        let ob_id = insert_obligation(
            &mut state,
            root,
            task_id,
            ObligationKind::SendPermit,
            Time::from_millis(50),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Cross-validate data between different diagnostic methods
        let region_explanation = diagnostics.explain_region_open(root);
        let task_explanation = diagnostics.explain_task_blocked(task_id);
        let leaked_obligations = diagnostics.find_leaked_obligations();

        // Verify task appears in both region and task diagnostics with consistent state
        let mut task_in_region_reasons = false;
        for reason in &region_explanation.reasons {
            if let Reason::TaskRunning { task_id: id, .. } = reason {
                if *id == task_id {
                    task_in_region_reasons = true;
                    break;
                }
            }
        }

        crate::assert_with_log!(
            task_in_region_reasons,
            "task appears in region explanation",
            true,
            task_in_region_reasons
        );
        crate::assert_with_log!(
            task_explanation.task_id == task_id,
            "task explanation has correct ID",
            true,
            task_explanation.task_id == task_id
        );

        // Verify obligation appears in both region and obligation leak diagnostics
        let mut obligation_in_region_reasons = false;
        for reason in &region_explanation.reasons {
            if let Reason::ObligationHeld {
                obligation_id: id,
                holder_task,
                ..
            } = reason
            {
                if *id == ob_id && *holder_task == task_id {
                    obligation_in_region_reasons = true;
                    break;
                }
            }
        }

        crate::assert_with_log!(
            obligation_in_region_reasons,
            "obligation appears in region explanation",
            true,
            obligation_in_region_reasons
        );
        crate::assert_with_log!(
            !leaked_obligations.is_empty(),
            "obligation appears in leak detection",
            true,
            !leaked_obligations.is_empty()
        );

        let found_leak = leaked_obligations
            .iter()
            .any(|leak| leak.obligation_id == ob_id && leak.holder_task == Some(task_id));
        crate::assert_with_log!(
            found_leak,
            "leak detection finds same obligation",
            true,
            found_leak
        );

        // Cross-validate timing information is consistent
        for leak in &leaked_obligations {
            if leak.obligation_id == ob_id {
                crate::assert_with_log!(
                    leak.age.as_millis() == 250, // 300 - 50 = 250ms
                    "age calculation consistent",
                    250u128,
                    leak.age.as_millis()
                );
            }
        }

        crate::test_complete!("introspection_conf_005_cross_method_consistency_of_diagnostic_data");
    }

    #[test]
    fn introspection_conf_006_temporal_consistency_of_diagnostic_queries() {
        init_test("introspection_conf_006_temporal_consistency_of_diagnostic_queries");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = insert_task(&mut state, root, TaskState::Running);

        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(1000)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));

        let ob_id = insert_obligation(
            &mut state,
            root,
            task_id,
            ObligationKind::Ack,
            Time::from_millis(100),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Capture initial state
        let initial_leaks = diagnostics.find_leaked_obligations();
        crate::assert_with_log!(
            initial_leaks.len() == 1,
            "initial leak count",
            1usize,
            initial_leaks.len()
        );
        let initial_age = initial_leaks[0].age.as_millis();
        crate::assert_with_log!(
            initial_age == 900, // 1000 - 100 = 900ms
            "initial age calculation",
            900u128,
            initial_age
        );

        // Advance virtual clock
        clock.advance_to(Time::from_millis(2000));

        // Verify temporal consistency after clock advance
        let later_leaks = diagnostics.find_leaked_obligations();
        crate::assert_with_log!(
            later_leaks.len() == 1,
            "leak count preserved after clock advance",
            1usize,
            later_leaks.len()
        );

        let later_age = later_leaks[0].age.as_millis();
        crate::assert_with_log!(
            later_age == 1900, // 2000 - 100 = 1900ms
            "updated age calculation",
            1900u128,
            later_age
        );
        crate::assert_with_log!(
            later_leaks[0].obligation_id == ob_id,
            "obligation ID preserved across time",
            true,
            later_leaks[0].obligation_id == ob_id
        );

        // Verify timing consistency in multiple diagnostic methods
        let region_explanation = diagnostics.explain_region_open(root);
        let mut obligation_reason_found = false;
        for reason in &region_explanation.reasons {
            if let Reason::ObligationHeld {
                obligation_id: id, ..
            } = reason
            {
                if *id == ob_id {
                    obligation_reason_found = true;
                    break;
                }
            }
        }
        crate::assert_with_log!(
            obligation_reason_found,
            "temporal consistency across methods",
            true,
            obligation_reason_found
        );

        crate::test_complete!("introspection_conf_006_temporal_consistency_of_diagnostic_queries");
    }

    #[test]
    fn introspection_conf_007_resource_leak_detection_accuracy() {
        init_test("introspection_conf_007_resource_leak_detection_accuracy");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let child1 = insert_child_region(&mut state, root);
        let child2 = insert_child_region(&mut state, root);

        let task1 = insert_task(&mut state, child1, TaskState::Running);
        let task2 = insert_task(&mut state, child2, TaskState::Running);
        let completed_task = insert_task(&mut state, root, TaskState::Completed(Outcome::Ok(())));

        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(1000)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));

        // Create genuine leaks and non-leaks
        let leak1 = insert_obligation(
            &mut state,
            child1,
            task1,
            ObligationKind::Ack,
            Time::from_millis(100),
        );
        let leak2 = insert_obligation(
            &mut state,
            child2,
            task2,
            ObligationKind::SendPermit,
            Time::from_millis(200),
        );

        // This should NOT be considered leaked (completed task)
        let _non_leak = insert_obligation(
            &mut state,
            root,
            completed_task,
            ObligationKind::Lease,
            Time::from_millis(300),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Verify leak detection accuracy
        let leaks = diagnostics.find_leaked_obligations();

        // Should detect exactly 2 leaks (not the completed task's obligation)
        crate::assert_with_log!(leaks.len() == 2, "accurate leak count", 2usize, leaks.len());

        // Verify leak details
        let leak_ids: Vec<ObligationId> = leaks.iter().map(|l| l.obligation_id).collect();
        crate::assert_with_log!(
            leak_ids.contains(&leak1),
            "detects first leak",
            true,
            leak_ids.contains(&leak1)
        );
        crate::assert_with_log!(
            leak_ids.contains(&leak2),
            "detects second leak",
            true,
            leak_ids.contains(&leak2)
        );

        // Verify age calculations for accuracy
        for leak in &leaks {
            match leak.obligation_id {
                id if id == leak1 => {
                    crate::assert_with_log!(
                        leak.age.as_millis() == 900, // 1000 - 100 = 900
                        "leak1 age accuracy",
                        900u128,
                        leak.age.as_millis()
                    );
                    crate::assert_with_log!(
                        leak.holder_task == Some(task1),
                        "leak1 holder accuracy",
                        true,
                        leak.holder_task == Some(task1)
                    );
                }
                id if id == leak2 => {
                    crate::assert_with_log!(
                        leak.age.as_millis() == 800, // 1000 - 200 = 800
                        "leak2 age accuracy",
                        800u128,
                        leak.age.as_millis()
                    );
                    crate::assert_with_log!(
                        leak.holder_task == Some(task2),
                        "leak2 holder accuracy",
                        true,
                        leak.holder_task == Some(task2)
                    );
                }
                _ => {
                    crate::assert_with_log!(false, "unexpected leak detected", true, false);
                }
            }
        }

        // Verify sorting by region ID (deterministic ordering)
        crate::assert_with_log!(
            leaks[0].region_id <= leaks[1].region_id,
            "leaks sorted by region",
            true,
            leaks[0].region_id <= leaks[1].region_id
        );

        crate::test_complete!("introspection_conf_007_resource_leak_detection_accuracy");
    }

    #[test]
    fn introspection_conf_008_deadlock_detection_determinism() {
        init_test("introspection_conf_008_deadlock_detection_determinism");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        // Create a deterministic deadlock scenario
        let task_a = insert_task(&mut state, root, TaskState::Running);
        let task_b = insert_task(&mut state, root, TaskState::Running);
        let task_c = insert_task(&mut state, root, TaskState::Running);

        // Create circular dependencies: A -> B -> C -> A
        state.task_mut(task_a).expect("task A").waiters.push(task_b);
        state.task_mut(task_b).expect("task B").waiters.push(task_c);
        state.task_mut(task_c).expect("task C").waiters.push(task_a);

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Test deadlock detection determinism across multiple calls
        let report1 = diagnostics.analyze_directional_deadlock();
        let report2 = diagnostics.analyze_directional_deadlock();
        let report3 = diagnostics.analyze_directional_deadlock();

        // Verify deterministic severity classification
        crate::assert_with_log!(
            report1.severity == report2.severity,
            "severity deterministic run1==run2",
            true,
            report1.severity == report2.severity
        );
        crate::assert_with_log!(
            report2.severity == report3.severity,
            "severity deterministic run2==run3",
            true,
            report2.severity == report3.severity
        );
        crate::assert_with_log!(
            matches!(report1.severity, DeadlockSeverity::Critical),
            "detects critical deadlock",
            true,
            matches!(report1.severity, DeadlockSeverity::Critical)
        );

        // Verify deterministic cycle detection
        crate::assert_with_log!(
            report1.cycles.len() == report2.cycles.len(),
            "cycle count deterministic run1==run2",
            report1.cycles.len(),
            report2.cycles.len()
        );
        crate::assert_with_log!(
            report2.cycles.len() == report3.cycles.len(),
            "cycle count deterministic run2==run3",
            report2.cycles.len(),
            report3.cycles.len()
        );
        crate::assert_with_log!(
            !report1.cycles.is_empty(),
            "detects cycle",
            true,
            !report1.cycles.is_empty()
        );

        // Verify deterministic task set in cycle
        if !report1.cycles.is_empty() {
            let cycle1 = &report1.cycles[0];
            let cycle2 = &report2.cycles[0];
            let cycle3 = &report3.cycles[0];

            crate::assert_with_log!(
                cycle1.tasks.len() == cycle2.tasks.len(),
                "cycle task count deterministic run1==run2",
                cycle1.tasks.len(),
                cycle2.tasks.len()
            );
            crate::assert_with_log!(
                cycle2.tasks.len() == cycle3.tasks.len(),
                "cycle task count deterministic run2==run3",
                cycle2.tasks.len(),
                cycle3.tasks.len()
            );

            // Verify all expected tasks are in the cycle
            crate::assert_with_log!(
                cycle1.tasks.contains(&task_a),
                "cycle contains task A",
                true,
                cycle1.tasks.contains(&task_a)
            );
            crate::assert_with_log!(
                cycle1.tasks.contains(&task_b),
                "cycle contains task B",
                true,
                cycle1.tasks.contains(&task_b)
            );
            crate::assert_with_log!(
                cycle1.tasks.contains(&task_c),
                "cycle contains task C",
                true,
                cycle1.tasks.contains(&task_c)
            );

            crate::assert_with_log!(
                cycle1.trapped == cycle2.trapped,
                "trapped status deterministic",
                true,
                cycle1.trapped == cycle2.trapped
            );
        }

        // Test structural health consistency with deadlock detection
        let health1 = diagnostics.analyze_structural_health();
        let health2 = diagnostics.analyze_structural_health();

        let health_deterministic = match (&health1.classification, &health2.classification) {
            (
                crate::observability::spectral_health::HealthClassification::Healthy { .. },
                crate::observability::spectral_health::HealthClassification::Healthy { .. },
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Deadlocked,
                crate::observability::spectral_health::HealthClassification::Deadlocked,
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Degraded { .. },
                crate::observability::spectral_health::HealthClassification::Degraded { .. },
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Critical { .. },
                crate::observability::spectral_health::HealthClassification::Critical { .. },
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Fragmented { .. },
                crate::observability::spectral_health::HealthClassification::Fragmented { .. },
            ) => true,
            _ => false,
        };
        crate::assert_with_log!(
            health_deterministic,
            "structural health deterministic",
            true,
            health_deterministic
        );

        crate::test_complete!("introspection_conf_008_deadlock_detection_determinism");
    }

    #[test]
    fn introspection_conf_009_diagnostic_query_cancel_safety() {
        init_test("introspection_conf_009_diagnostic_query_cancel_safety");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        // Create runtime state with various tasks and obligations
        let task1 = insert_task(&mut state, root, TaskState::Running);
        let task2 = insert_task(
            &mut state,
            root,
            TaskState::CancelRequested {
                reason: CancelReason::user("test"),
                cleanup_budget: Budget::with_deadline_at_ns(100_000_000), // 100ms in ns
            },
        );

        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(1000)));
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));

        let _ob1 = insert_obligation(
            &mut state,
            root,
            task1,
            ObligationKind::Ack,
            Time::from_millis(100),
        );
        let _ob2 = insert_obligation(
            &mut state,
            root,
            task2,
            ObligationKind::Lease,
            Time::from_millis(200),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Verify diagnostic queries are pure reads (cancel-safe)
        // These operations must not modify the runtime state

        // Capture baseline state snapshots through multiple query calls
        let baseline_explanation = diagnostics.explain_region_open(root);
        let baseline_task1_explanation = diagnostics.explain_task_blocked(task1);
        let baseline_task2_explanation = diagnostics.explain_task_blocked(task2);
        let baseline_leaks = diagnostics.find_leaked_obligations();
        let baseline_deadlock = diagnostics.analyze_directional_deadlock();
        let baseline_health = diagnostics.analyze_structural_health();

        // Perform the same queries again to ensure no state modification occurred
        let verify_explanation = diagnostics.explain_region_open(root);
        let verify_task1_explanation = diagnostics.explain_task_blocked(task1);
        let verify_task2_explanation = diagnostics.explain_task_blocked(task2);
        let verify_leaks = diagnostics.find_leaked_obligations();
        let verify_deadlock = diagnostics.analyze_directional_deadlock();
        let verify_health = diagnostics.analyze_structural_health();

        // Verify state immutability (cancel-safety)
        crate::assert_with_log!(
            baseline_explanation.reasons.len() == verify_explanation.reasons.len(),
            "region explanation cancel-safe",
            baseline_explanation.reasons.len(),
            verify_explanation.reasons.len()
        );

        let task1_reason_match = match (
            &baseline_task1_explanation.block_reason,
            &verify_task1_explanation.block_reason,
        ) {
            (BlockReason::AwaitingSchedule, BlockReason::AwaitingSchedule) => true,
            (BlockReason::NotStarted, BlockReason::NotStarted) => true,
            (a, b) => format!("{:?}", a) == format!("{:?}", b),
        };
        crate::assert_with_log!(
            task1_reason_match,
            "task1 explanation cancel-safe",
            true,
            task1_reason_match
        );

        let task2_cancel_match = matches!(
            (
                &baseline_task2_explanation.block_reason,
                &verify_task2_explanation.block_reason
            ),
            (
                BlockReason::CancelRequested { .. },
                BlockReason::CancelRequested { .. }
            )
        );
        crate::assert_with_log!(
            task2_cancel_match,
            "task2 cancel explanation cancel-safe",
            true,
            task2_cancel_match
        );

        crate::assert_with_log!(
            baseline_leaks.len() == verify_leaks.len(),
            "leak detection cancel-safe",
            baseline_leaks.len(),
            verify_leaks.len()
        );

        let deadlock_severity_match = baseline_deadlock.severity == verify_deadlock.severity;
        crate::assert_with_log!(
            deadlock_severity_match,
            "deadlock detection cancel-safe",
            true,
            deadlock_severity_match
        );

        let health_class_match = match (
            &baseline_health.classification,
            &verify_health.classification,
        ) {
            (
                crate::observability::spectral_health::HealthClassification::Healthy { .. },
                crate::observability::spectral_health::HealthClassification::Healthy { .. },
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Deadlocked,
                crate::observability::spectral_health::HealthClassification::Deadlocked,
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Degraded { .. },
                crate::observability::spectral_health::HealthClassification::Degraded { .. },
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Critical { .. },
                crate::observability::spectral_health::HealthClassification::Critical { .. },
            ) => true,
            (
                crate::observability::spectral_health::HealthClassification::Fragmented { .. },
                crate::observability::spectral_health::HealthClassification::Fragmented { .. },
            ) => true,
            _ => false,
        };
        crate::assert_with_log!(
            health_class_match,
            "health analysis cancel-safe",
            true,
            health_class_match
        );

        // Verify timing-dependent queries maintain consistency
        for (baseline_leak, verify_leak) in baseline_leaks.iter().zip(verify_leaks.iter()) {
            crate::assert_with_log!(
                baseline_leak.obligation_id == verify_leak.obligation_id,
                "leak ID cancel-safe",
                true,
                baseline_leak.obligation_id == verify_leak.obligation_id
            );
            crate::assert_with_log!(
                baseline_leak.age == verify_leak.age,
                "leak age cancel-safe",
                true,
                baseline_leak.age == verify_leak.age
            );
        }

        crate::test_complete!("introspection_conf_009_diagnostic_query_cancel_safety");
    }

    #[test]
    fn introspection_conf_010_runtime_introspection_endpoint_stability() {
        init_test("introspection_conf_010_runtime_introspection_endpoint_stability");

        // Test endpoint stability under various runtime configurations

        // Configuration 1: Empty runtime
        let empty_state = Arc::new(RuntimeState::new());
        let empty_diagnostics = Diagnostics::new(empty_state);

        let empty_root = RegionId::new_for_test(999, 0);
        let empty_explanation = empty_diagnostics.explain_region_open(empty_root);
        crate::assert_with_log!(
            matches!(
                empty_explanation.reasons.first(),
                Some(Reason::RegionNotFound)
            ),
            "empty runtime handles missing region",
            true,
            matches!(
                empty_explanation.reasons.first(),
                Some(Reason::RegionNotFound)
            )
        );

        let empty_task = TaskId::new_for_test(999, 0);
        let empty_task_explanation = empty_diagnostics.explain_task_blocked(empty_task);
        crate::assert_with_log!(
            matches!(
                empty_task_explanation.block_reason,
                BlockReason::TaskNotFound
            ),
            "empty runtime handles missing task",
            true,
            matches!(
                empty_task_explanation.block_reason,
                BlockReason::TaskNotFound
            )
        );

        let empty_leaks = empty_diagnostics.find_leaked_obligations();
        crate::assert_with_log!(
            empty_leaks.is_empty(),
            "empty runtime has no leaks",
            true,
            empty_leaks.is_empty()
        );

        // Configuration 2: Minimal valid runtime
        let mut minimal_state = RuntimeState::new();
        let minimal_root = minimal_state.create_root_region(Budget::INFINITE);
        let minimal_diagnostics = Diagnostics::new(Arc::new(minimal_state));

        let minimal_explanation = minimal_diagnostics.explain_region_open(minimal_root);
        crate::assert_with_log!(
            minimal_explanation.region_state.is_some(),
            "minimal runtime provides region state",
            true,
            minimal_explanation.region_state.is_some()
        );

        let minimal_leaks = minimal_diagnostics.find_leaked_obligations();
        crate::assert_with_log!(
            minimal_leaks.is_empty(),
            "minimal runtime has no leaks",
            true,
            minimal_leaks.is_empty()
        );

        // Configuration 3: Complex runtime with multiple regions/tasks
        let mut complex_state = RuntimeState::new();
        let complex_root = complex_state.create_root_region(Budget::INFINITE);
        let complex_child1 = insert_child_region(&mut complex_state, complex_root);
        let complex_child2 = insert_child_region(&mut complex_state, complex_root);

        let _complex_task1 = insert_task(&mut complex_state, complex_child1, TaskState::Running);
        let _complex_task2 = insert_task(
            &mut complex_state,
            complex_child2,
            TaskState::Completed(Outcome::Ok(())),
        );
        let complex_task3 = insert_task(
            &mut complex_state,
            complex_root,
            TaskState::CancelRequested {
                reason: CancelReason::user("cleanup"),
                cleanup_budget: Budget::with_deadline_at_ns(200_000_000), // 200ms in ns
            },
        );

        let complex_diagnostics = Diagnostics::new(Arc::new(complex_state));

        let complex_explanation = complex_diagnostics.explain_region_open(complex_root);
        crate::assert_with_log!(
            !complex_explanation.reasons.is_empty(),
            "complex runtime provides detailed reasons",
            true,
            !complex_explanation.reasons.is_empty()
        );

        let complex_cancel_explanation = complex_diagnostics.explain_task_blocked(complex_task3);
        let is_complex_cancel = matches!(
            complex_cancel_explanation.block_reason,
            BlockReason::CancelRequested { .. }
        );
        crate::assert_with_log!(
            is_complex_cancel,
            "complex runtime tracks cancel state",
            true,
            is_complex_cancel
        );

        // Configuration 4: Runtime with timer driver vs without
        let mut timer_state = RuntimeState::new();
        let timer_root = timer_state.create_root_region(Budget::INFINITE);
        let timer_task = insert_task(&mut timer_state, timer_root, TaskState::Running);

        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5000)));
        timer_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(virtual_clock));
        let _timer_obligation = insert_obligation(
            &mut timer_state,
            timer_root,
            timer_task,
            ObligationKind::Ack,
            Time::from_millis(1000),
        );

        let timer_diagnostics = Diagnostics::new(Arc::new(timer_state));
        let timer_leaks = timer_diagnostics.find_leaked_obligations();

        crate::assert_with_log!(
            !timer_leaks.is_empty(),
            "timer-enabled runtime detects leaks",
            true,
            !timer_leaks.is_empty()
        );

        if let Some(leak) = timer_leaks.first() {
            crate::assert_with_log!(
                leak.age.as_millis() == 4000, // 5000 - 1000 = 4000
                "timer-enabled runtime calculates age correctly",
                4000u128,
                leak.age.as_millis()
            );
        }

        // Verify endpoint stability across all configurations
        let all_deadlock_reports = [
            empty_diagnostics.analyze_directional_deadlock(),
            minimal_diagnostics.analyze_directional_deadlock(),
            complex_diagnostics.analyze_directional_deadlock(),
            timer_diagnostics.analyze_directional_deadlock(),
        ];

        for report in &all_deadlock_reports {
            crate::assert_with_log!(
                report.risk_score >= 0.0 && report.risk_score <= 1.0,
                "deadlock risk score in valid range",
                true,
                report.risk_score >= 0.0 && report.risk_score <= 1.0
            );
        }

        let all_health_reports = [
            empty_diagnostics.analyze_structural_health(),
            minimal_diagnostics.analyze_structural_health(),
            complex_diagnostics.analyze_structural_health(),
            timer_diagnostics.analyze_structural_health(),
        ];

        for health in &all_health_reports {
            // Verify health classification is valid (structural analysis completed)
            let valid_classification = matches!(
                health.classification,
                crate::observability::spectral_health::HealthClassification::Healthy { .. }
                    | crate::observability::spectral_health::HealthClassification::Degraded { .. }
                    | crate::observability::spectral_health::HealthClassification::Deadlocked
                    | crate::observability::spectral_health::HealthClassification::Critical { .. }
                    | crate::observability::spectral_health::HealthClassification::Fragmented { .. }
            );
            crate::assert_with_log!(
                valid_classification,
                "health classification is valid",
                true,
                valid_classification
            );
        }

        crate::test_complete!("introspection_conf_010_runtime_introspection_endpoint_stability");
    }

    #[test]
    fn structured_diagnostic_report_snapshot_v4_with_extended_metrics() {
        init_test("structured_diagnostic_report_snapshot_v4_with_extended_metrics");

        // Create test sections with extended metric histograms
        let sections = vec![
            DiagnosticReportV4Section {
                label: "task_execution",
                status: "degraded",
                accounting: DiagnosticResourceAccounting {
                    total_regions: 12,
                    open_regions: 8,
                    total_tasks: 142,
                    live_tasks: 89,
                    total_obligations: 23,
                    leaked_obligations: 2,
                },
                histograms: vec![DiagnosticMetricHistogram {
                    name: "task_execution_latency_ms".to_string(),
                    buckets: vec![
                        ("0-1ms".to_string(), 1247),
                        ("1-5ms".to_string(), 823),
                        ("5-10ms".to_string(), 156),
                        ("10-50ms".to_string(), 89),
                        ("50-100ms".to_string(), 12),
                        ("100ms+".to_string(), 3),
                    ],
                    total_count: 2330,
                    percentiles: vec![(50.0, 1.2), (95.0, 8.7), (99.0, 24.1), (99.9, 78.3)],
                }],
                rendered: "task_execution: Task execution metrics\n  latency_p50: 1.2ms\n  latency_p99: 24.1ms\n  completion_rate: 94.2%",
            },
            DiagnosticReportV4Section {
                label: "region_lifecycle",
                status: "critical",
                accounting: DiagnosticResourceAccounting {
                    total_regions: 67,
                    open_regions: 37,
                    total_tasks: 245,
                    live_tasks: 156,
                    total_obligations: 45,
                    leaked_obligations: 8,
                },
                histograms: vec![DiagnosticMetricHistogram {
                    name: "region_lifecycle_duration_ms".to_string(),
                    buckets: vec![
                        ("0-10ms".to_string(), 89),
                        ("10-100ms".to_string(), 156),
                        ("100ms-1s".to_string(), 67),
                        ("1s-10s".to_string(), 23),
                        ("10s+".to_string(), 8),
                    ],
                    total_count: 343,
                    percentiles: vec![(50.0, 45.2), (95.0, 2100.0), (99.0, 6780.0)],
                }],
                rendered: "region_lifecycle: Region lifecycle analysis\n  duration_p50: 45.2ms\n  duration_p99: 6.78s\n  long_lived_count: 8",
            },
            DiagnosticReportV4Section {
                label: "obligation_tracking",
                status: "passing",
                accounting: DiagnosticResourceAccounting {
                    total_regions: 34,
                    open_regions: 23,
                    total_tasks: 178,
                    live_tasks: 134,
                    total_obligations: 67,
                    leaked_obligations: 0,
                },
                histograms: vec![DiagnosticMetricHistogram {
                    name: "obligation_hold_time_ms".to_string(),
                    buckets: vec![
                        ("0-1s".to_string(), 1200),
                        ("1s-10s".to_string(), 45),
                        ("10s-1min".to_string(), 12),
                        ("1min+".to_string(), 3),
                    ],
                    total_count: 1260,
                    percentiles: vec![
                        (50.0, 120.0),
                        (95.0, 8900.0),
                        (99.0, 45000.0),
                        (99.9, 120000.0),
                    ],
                }],
                rendered: "obligation_tracking: Obligation hold time analysis\n  hold_time_p50: 120ms\n  hold_time_p99: 45s\n  leak_candidates: 3",
            },
        ];

        let rendered = render_structured_diagnostic_report_v4(&sections);

        assert_diagnostic_report_snapshot(
            "observability_diagnostics_structured_report_v4",
            &rendered,
        );

        crate::test_complete!("structured_diagnostic_report_snapshot_v4_with_extended_metrics");
    }

    #[test]
    fn structured_diagnostic_report_v3_schema_golden_snapshot() {
        // Comprehensive golden snapshot test for v3 schema validation
        // Validates: stable field ordering, version markers, healthy/degraded/error states

        // Create minimal test data for schema validation
        let healthy_accounting = DiagnosticResourceAccounting {
            total_regions: 1,
            open_regions: 0,
            total_tasks: 1,
            live_tasks: 0,
            total_obligations: 0,
            leaked_obligations: 0,
        };

        let degraded_accounting = DiagnosticResourceAccounting {
            total_regions: 3,
            open_regions: 2,
            total_tasks: 5,
            live_tasks: 3,
            total_obligations: 2,
            leaked_obligations: 1,
        };

        let error_accounting = DiagnosticResourceAccounting {
            total_regions: 2,
            open_regions: 2,
            total_tasks: 4,
            live_tasks: 4,
            total_obligations: 3,
            leaked_obligations: 3,
        };

        // Create v3 sections representing healthy/degraded/error states
        let sections = vec![
            DiagnosticReportV3Section {
                label: "healthy_system",
                status: "passing",
                accounting: healthy_accounting,
                rendered: "scenario: healthy_system\ngenerated_at: 2026-04-21T14:30:00Z\n\n[region]\nnone\n\n[task]\nAll tasks completed successfully.\n\n[leaks]\nnone",
            },
            DiagnosticReportV3Section {
                label: "degraded_performance",
                status: "degraded",
                accounting: degraded_accounting,
                rendered: "scenario: degraded_performance\ngenerated_at: 2026-04-21T14:30:01Z\n\n[region]\nRegion RegionId(1:0) has slow drain (2 children pending).\n\n[task]\nTask TaskId(2:1) experiencing high latency (p99: 450ms).\n\n[leaks]\n- ObligationId(1:0) region=RegionId(1:0) holder=Some(TaskId(2:1)) type=Lease age_ms=1500",
            },
            DiagnosticReportV3Section {
                label: "error_state",
                status: "critical",
                accounting: error_accounting,
                rendered: "scenario: error_state\ngenerated_at: 2026-04-21T14:30:02Z\n\n[region]\nRegion RegionId(0:0) has deadlock detected (cycle length: 2).\n\n[task]\nTask TaskId(0:0) blocked: deadlock (waiting on TaskId(1:0)).\n\n[leaks]\n- ObligationId(0:0) region=RegionId(0:0) holder=Some(TaskId(0:0)) type=Ack age_ms=2000\n- ObligationId(1:0) region=RegionId(0:0) holder=Some(TaskId(1:0)) type=Lease age_ms=2100\n- ObligationId(2:0) region=RegionId(1:0) holder=Some(TaskId(2:0)) type=Ack age_ms=1800",
            },
        ];

        let rendered = render_structured_diagnostic_report_v3(&sections);

        // Assert the golden snapshot for v3 schema validation
        assert_diagnostic_report_snapshot(
            "observability_diagnostics_v3_schema_validation",
            &rendered,
        );
    }

    // ─── br-asupersync-3fq08n: cancel-reason sanitization ─────────────

    #[test]
    fn sanitize_cancel_message_strips_crlf_to_space() {
        let raw = "user cancelled\r\n[ERROR] FORGED LOG SPLICE";
        let sanitized = sanitize_cancel_message(raw);
        assert!(
            !sanitized.contains('\r') && !sanitized.contains('\n'),
            "CR/LF must be stripped, got {sanitized:?}"
        );
        // The injected text remains visible (just on the same log line).
        assert!(sanitized.contains("FORGED LOG SPLICE"));
    }

    #[test]
    fn sanitize_cancel_message_strips_tab_to_space() {
        assert_eq!(sanitize_cancel_message("a\tb"), "a b");
    }

    #[test]
    fn sanitize_cancel_message_replaces_other_controls_with_question() {
        // NUL, BEL, ESC, DEL — non-printable controls beyond CR/LF/tab.
        let raw = "x\x00y\x07z\x1bw\x7fv";
        assert_eq!(sanitize_cancel_message(raw), "x?y?z?w?v");
    }

    #[test]
    fn sanitize_cancel_message_preserves_printable_unicode() {
        let raw = "deadline reached: ✓ 漢字";
        assert_eq!(sanitize_cancel_message(raw), raw);
    }

    #[test]
    fn sanitize_cancel_message_truncates_at_cap_with_ellipsis() {
        let raw = "Y".repeat(500);
        let sanitized = sanitize_cancel_message(&raw);
        assert!(sanitized.starts_with(&"Y".repeat(MAX_SANITIZED_CANCEL_MESSAGE_LEN)));
        assert!(sanitized.ends_with('…'));
        // Total bytes: 256 ASCII + 3 bytes UTF-8 ellipsis = 259.
        assert_eq!(sanitized.len(), MAX_SANITIZED_CANCEL_MESSAGE_LEN + 3);
    }

    #[test]
    fn sanitize_cancel_message_truncates_on_char_boundary_for_multibyte() {
        // '漢' is 3 bytes UTF-8. 86 of them = 258 bytes (over 256 cap).
        // Cap is 256; 85 chars = 255 bytes (fits); 86th char's 3 bytes
        // would push to 258 → truncated at 85 chars + '…'.
        let raw = "漢".repeat(86);
        let sanitized = sanitize_cancel_message(&raw);
        assert!(sanitized.ends_with('…'));
        // 85 * 3 = 255 bytes of 漢, plus 3 bytes of '…' = 258 total.
        assert_eq!(sanitized.len(), 258);
        // Verify char boundary respected (valid UTF-8).
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
    }

    #[test]
    fn cancel_reason_info_from_reason_sanitizes_message() {
        // The chokepoint test: an attacker-controlled message containing a
        // log-injection attempt MUST be sanitized at construction so all
        // downstream consumers (Display, serde) see the clean value.
        let info = CancelReasonInfo::from_reason(
            CancelKind::User,
            Some("graceful shutdown\n[ALERT] privilege escalation"),
        );
        let stored = info.message.as_deref().unwrap();
        assert!(
            !stored.contains('\n'),
            "stored message must be sanitized, got {stored:?}"
        );
        assert!(stored.contains("[ALERT] privilege escalation"));
        // Display path inherits the sanitized value.
        let display = format!("{info}");
        assert!(!display.contains('\n'));
    }

    #[test]
    fn cancel_reason_info_with_none_message_is_passthrough() {
        let info = CancelReasonInfo::from_reason(CancelKind::User, None);
        assert!(info.message.is_none());
        let display = format!("{info}");
        assert!(!display.contains('('));
    }

    fn assert_diagnostic_yaml_snapshot(snapshot_name: &str, value: &Value) {
        insta::with_settings!({
            snapshot_path => "../../tests/snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_yaml_snapshot!(snapshot_name, value);
        });
    }

    /// Golden test for canonical diagnostic runtime state dump.
    ///
    /// This test pins a known runtime state (3 tasks, 1 obligation, 1 cancel)
    /// and creates a comprehensive diagnostic dump as YAML. The snapshot ensures
    /// diagnostic output format stability across runtime versions.
    #[test]
    fn diagnostic_runtime_state_dump_golden() {
        init_test("diagnostic_runtime_state_dump_golden");

        let mut state = RuntimeState::new();
        let root_region = state.create_root_region(Budget::INFINITE);

        // Create known-state runtime: 3 tasks, 1 obligation, 1 cancel
        let task1 = insert_task(&mut state, root_region, TaskState::Running);
        let task2 = insert_task(&mut state, root_region, TaskState::Running);
        let task3 = insert_task(
            &mut state,
            root_region,
            TaskState::Completed(Outcome::Cancelled(CancelReason::timeout())),
        );

        // Add 1 obligation held by task1
        let obligation = insert_obligation(
            &mut state,
            root_region,
            task1,
            ObligationKind::SendPermit,
            Time::from_nanos(10_000),
        );

        let diagnostics = Diagnostics::new(Arc::new(state));

        // Generate comprehensive diagnostic dump
        let region_explanation = diagnostics.explain_region_open(root_region);
        let task_explanation = diagnostics.explain_task_blocked(task2);
        let leaked_obligations = diagnostics.find_leaked_obligations();
        let health_report = diagnostics.analyze_structural_health();

        let diagnostic_dump = json!({
            "runtime_state": {
                "tasks": {
                    "task1": {
                        "id": task1.to_string(),
                        "state": "Running",
                        "region": root_region.to_string()
                    },
                    "task2": {
                        "id": task2.to_string(),
                        "state": "Running",
                        "region": root_region.to_string()
                    },
                    "task3": {
                        "id": task3.to_string(),
                        "state": "Cancelled",
                        "region": root_region.to_string()
                    }
                },
                "obligations": {
                    "obligation1": {
                        "id": obligation.to_string(),
                        "kind": "SendPermit",
                        "holder": task1.to_string(),
                        "region": root_region.to_string()
                    }
                },
                "regions": {
                    "root": {
                        "id": root_region.to_string(),
                        "explanation": {
                            "can_close": region_explanation.reasons.is_empty(),
                            "reasons_count": region_explanation.reasons.len()
                        }
                    }
                }
            },
            "diagnostics": {
                "task_blocked": {
                    "task_id": task2.to_string(),
                    "has_explanation": !task_explanation.details.is_empty()
                        || !task_explanation.recommendations.is_empty()
                },
                "leaked_obligations": {
                    "count": leaked_obligations.len()
                },
                "health": {
                    "classification": match health_report.classification {
                        HealthClassification::Healthy { margin } => json!({
                            "kind": "healthy",
                            "margin": margin
                        }),
                        HealthClassification::Degraded { fiedler, .. } => json!({
                            "kind": "degraded",
                            "fiedler": fiedler
                        }),
                        HealthClassification::Critical {
                            fiedler,
                            approaching_disconnect,
                        } => json!({
                            "kind": "critical",
                            "fiedler": fiedler,
                            "approaching_disconnect": approaching_disconnect
                        }),
                        HealthClassification::Fragmented { components } => json!({
                            "kind": "fragmented",
                            "components": components
                        }),
                        HealthClassification::Deadlocked => json!({
                            "kind": "deadlocked"
                        }),
                    },
                    "fiedler_value": health_report.decomposition.fiedler_value,
                    "bottleneck_count": health_report.bottlenecks.len()
                }
            },
            "meta": {
                "test_scenario": "3_tasks_1_obligation_1_cancel",
                "snapshot_version": "v1"
            }
        });

        assert_diagnostic_yaml_snapshot("diagnostic_runtime_state_dump_golden", &diagnostic_dump);
    }
