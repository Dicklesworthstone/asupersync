    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::remote::{NodeId, RemoteCap};
    use crate::runtime::SpawnError;
    use crate::runtime::state::RuntimeState;
    use crate::supervision::{ChildSpec, NameRegistrationPolicy, SupervisionStrategy};
    use crate::types::{Budget, TaskId};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn lab_spawn_cx(runtime: &crate::lab::LabRuntime, region: RegionId, budget: Budget) -> Cx {
        Cx::new(region, TaskId::testing_default(), budget)
            .with_spawn_gateway(runtime.state.spawn_gateway())
            .with_pending_spawn_counter(
                runtime
                    .state
                    .region(region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            )
    }

    fn make_child(name: &str) -> ChildSpec {
        ChildSpec {
            name: name.into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    let region = scope.region_id();
                    let budget = scope.budget();
                    state
                        .create_task(region, budget, async { 42_u8 })
                        .map(|(_, stored)| stored.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        }
    }

    fn close_app_region_and_remove_records(state: &mut RuntimeState, app_region: RegionId) {
        let effects = state.cancel_request(app_region, &CancelReason::shutdown(), None);
        let (_, cancel_wakes) = effects.into_parts();
        cancel_wakes.dispatch();

        let mut previous_region_count = usize::MAX;
        while state.region(app_region).is_some() && state.regions_len() != previous_region_count {
            previous_region_count = state.regions_len();
            let region_ids: Vec<_> = state.regions_iter().map(|(_, region)| region.id).collect();
            for region_id in region_ids {
                state.advance_region_state(region_id);
            }
        }
    }

    // --- Unit tests ---

    fn appspec_v1_sample_json() -> Value {
        json!({
            "schema_version": APPSPEC_V1_SCHEMA_VERSION,
            "name": "payments",
            "services": [
                {
                    "name": "api",
                    "routes": [
                        {
                            "name": "readiness",
                            "method": "GET",
                            "path": "/ready",
                            "handler": "crate::payments::ready",
                            "required_capabilities": {
                                "cx_capabilities": ["net", "trace"],
                                "feature_flags": ["native-runtime", "tracing-integration"],
                                "resources": ["public_socket"]
                            },
                            "budget": "request",
                            "slo_hook": "latency_50ms"
                        }
                    ],
                    "actors": [
                        {
                            "name": "cache_warmer",
                            "entrypoint": "crate::payments::cache_warmer",
                            "mailbox_capacity": 64,
                            "required_capabilities": {
                                "cx_capabilities": ["spawn", "time"],
                                "feature_flags": ["native-runtime"],
                                "resources": []
                            },
                            "budget": "background"
                        }
                    ],
                    "background_jobs": [
                        {
                            "name": "sweeper",
                            "entrypoint": "crate::payments::sweep",
                            "trigger": { "interval": { "every_ms": 1000 } },
                            "required_capabilities": {
                                "cx_capabilities": ["time", "trace"],
                                "feature_flags": [],
                                "resources": ["timer"]
                            },
                            "budget": "background",
                            "slo_hook": "latency_50ms"
                        }
                    ],
                    "resources": ["public_socket", "timer"],
                    "budget": "service",
                    "supervision_group": "root"
                }
            ],
            "resources": [
                {
                    "name": "public_socket",
                    "kind": "socket",
                    "capability": "net",
                    "feature_flag": "native-runtime"
                },
                {
                    "name": "timer",
                    "kind": "timer",
                    "capability": "time",
                    "feature_flag": null
                }
            ],
            "budgets": [
                {
                    "name": "service",
                    "poll_quota": 100000,
                    "deadline_ms": null,
                    "io_bytes": null,
                    "memory_bytes": null
                },
                {
                    "name": "request",
                    "poll_quota": 10000,
                    "deadline_ms": 50,
                    "io_bytes": 65536,
                    "memory_bytes": null
                },
                {
                    "name": "background",
                    "poll_quota": 25000,
                    "deadline_ms": 1000,
                    "io_bytes": null,
                    "memory_bytes": null
                }
            ],
            "slo_hooks": [
                {
                    "name": "latency_50ms",
                    "kind": "latency",
                    "target": "api.readiness",
                    "budget": "request"
                }
            ],
            "supervision": {
                "root_group": "root",
                "groups": [
                    {
                        "name": "root",
                        "services": ["api"],
                        "restart_policy": "one_for_one"
                    }
                ]
            },
            "observability": [
                {
                    "name": "trace",
                    "kind": "trace",
                    "required_capabilities": {
                        "cx_capabilities": ["trace"],
                        "feature_flags": ["tracing-integration"],
                        "resources": []
                    }
                }
            ],
            "compatibility": {
                "fail_closed_unknown_fields": true,
                "fail_closed_unknown_capabilities": true,
                "future_schema_requires_new_version": true
            }
        })
    }

    fn appspec_v1_sample() -> AppSpecV1 {
        serde_json::from_value(appspec_v1_sample_json()).expect("sample AppSpec v1 parses")
    }

    #[test]
    fn appspec_v1_roundtrip_preserves_capability_contract() {
        init_test("appspec_v1_roundtrip_preserves_capability_contract");
        let spec = appspec_v1_sample();
        spec.validate().expect("sample AppSpec v1 validates");

        assert_eq!(spec.schema_version, APPSPEC_V1_SCHEMA_VERSION);
        let route = &spec.services[0].routes[0];
        assert_eq!(route.method, AppRouteMethodV1::Get);
        assert_eq!(
            route.required_capabilities.cx_capabilities,
            vec![AppCxCapabilityV1::Net, AppCxCapabilityV1::Trace]
        );
        assert_eq!(
            route.required_capabilities.feature_flags,
            vec![
                AppFeatureFlagV1::NativeRuntime,
                AppFeatureFlagV1::TracingIntegration
            ]
        );

        let roundtrip =
            serde_json::to_value(&spec).expect("serialize sample AppSpec v1 back to JSON");
        assert_eq!(
            roundtrip["schema_version"],
            json!(APPSPEC_V1_SCHEMA_VERSION)
        );
        assert_eq!(
            roundtrip["services"][0]["routes"][0]["required_capabilities"]["cx_capabilities"],
            json!(["net", "trace"])
        );
        crate::test_complete!("appspec_v1_roundtrip_preserves_capability_contract");
    }

    #[test]
    fn appspec_v1_rejects_missing_route_capabilities_field() {
        init_test("appspec_v1_rejects_missing_route_capabilities_field");
        let mut value = appspec_v1_sample_json();
        value["services"][0]["routes"][0]
            .as_object_mut()
            .expect("route object")
            .remove("required_capabilities");

        let err = serde_json::from_value::<AppSpecV1>(value).expect_err("missing field rejects");
        assert!(
            err.to_string().contains("required_capabilities"),
            "unexpected serde error: {err}"
        );
        crate::test_complete!("appspec_v1_rejects_missing_route_capabilities_field");
    }

    #[test]
    fn appspec_v1_rejects_unknown_capability_string() {
        init_test("appspec_v1_rejects_unknown_capability_string");
        let mut value = appspec_v1_sample_json();
        value["services"][0]["routes"][0]["required_capabilities"]["cx_capabilities"][0] =
            json!("ambient_global");

        let err =
            serde_json::from_value::<AppSpecV1>(value).expect_err("unknown capability rejects");
        assert!(
            err.to_string().contains("unknown variant"),
            "unexpected serde error: {err}"
        );
        crate::test_complete!("appspec_v1_rejects_unknown_capability_string");
    }

    #[test]
    fn appspec_v1_validate_rejects_ambient_route_authority() {
        init_test("appspec_v1_validate_rejects_ambient_route_authority");
        let mut spec = appspec_v1_sample();
        spec.services[0].routes[0].required_capabilities = AppRequiredCapabilitiesV1 {
            cx_capabilities: Vec::new(),
            feature_flags: Vec::new(),
            resources: Vec::new(),
        };

        let err = spec.validate().expect_err("ambient route rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::AmbientAuthority { ref owner }
                    if owner == "service.api.route.readiness"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_ambient_route_authority");
    }

    #[test]
    fn appspec_v1_validate_rejects_duplicate_services() {
        init_test("appspec_v1_validate_rejects_duplicate_services");
        let mut spec = appspec_v1_sample();
        spec.services.push(spec.services[0].clone());

        let err = spec.validate().expect_err("duplicate service rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::DuplicateName {
                    collection: "services",
                    ref name
                } if name == "api"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_duplicate_services");
    }

    #[test]
    fn appspec_v1_validate_rejects_unassigned_service() {
        init_test("appspec_v1_validate_rejects_unassigned_service");
        let mut spec = appspec_v1_sample();
        let mut worker = spec.services[0].clone();
        worker.name = "worker".to_string();
        worker.supervision_group = None;
        spec.services.push(worker);

        let err = spec.validate().expect_err("unassigned service rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::MissingSupervisionAssignment {
                    ref service
                } if service == "worker"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_unassigned_service");
    }

    #[test]
    fn appspec_v1_validate_rejects_duplicate_service_assignment() {
        init_test("appspec_v1_validate_rejects_duplicate_service_assignment");
        let mut spec = appspec_v1_sample();
        spec.supervision.groups.push(AppSupervisionGroupSpecV1 {
            name: "secondary".to_string(),
            services: vec!["api".to_string()],
            restart_policy: AppRestartPolicyV1::OneForOne,
        });

        let err = spec
            .validate()
            .expect_err("duplicate supervision assignment rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::DuplicateSupervisionAssignment {
                    ref service,
                    ref first_group,
                    ref second_group,
                } if service == "api" && first_group == "root" && second_group == "secondary"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_duplicate_service_assignment");
    }

    #[test]
    fn appspec_v1_validate_rejects_service_group_mismatch() {
        init_test("appspec_v1_validate_rejects_service_group_mismatch");
        let mut spec = appspec_v1_sample();
        spec.supervision.groups.push(AppSupervisionGroupSpecV1 {
            name: "declared".to_string(),
            services: vec!["shadow".to_string()],
            restart_policy: AppRestartPolicyV1::OneForOne,
        });
        spec.services[0].supervision_group = Some("declared".to_string());

        let err = spec
            .validate()
            .expect_err("mismatched supervision group rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::UnknownReference {
                    field: "supervision.group.services",
                    ref name,
                } if name == "shadow"
            ),
            "unknown services should still fail before mismatch analysis: {err:?}"
        );

        let mut spec = appspec_v1_sample();
        spec.supervision.groups.push(AppSupervisionGroupSpecV1 {
            name: "declared".to_string(),
            services: vec!["aux".to_string()],
            restart_policy: AppRestartPolicyV1::OneForOne,
        });
        let mut aux = spec.services[0].clone();
        aux.name = "aux".to_string();
        aux.supervision_group = Some("root".to_string());
        spec.services.push(aux);

        let err = spec
            .validate()
            .expect_err("declared group mismatch rejects");
        assert!(
            matches!(
                err,
                AppSpecV1ValidationError::SupervisionGroupMismatch {
                    ref service,
                    ref declared_group,
                    ref actual_group,
                } if service == "aux" && declared_group == "root" && actual_group == "declared"
            ),
            "unexpected validation error: {err:?}"
        );
        crate::test_complete!("appspec_v1_validate_rejects_service_group_mismatch");
    }

    #[test]
    fn appspec_v1_schema_artifact_matches_runtime_contract() {
        init_test("appspec_v1_schema_artifact_matches_runtime_contract");
        let schema: Value =
            serde_json::from_str(include_str!("../artifacts/appspec_v1_schema.json"))
                .expect("schema artifact parses");
        assert_eq!(schema["schema_version"], json!(APPSPEC_V1_SCHEMA_VERSION));
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            json!(APPSPEC_V1_SCHEMA_VERSION)
        );

        let required = schema["required"]
            .as_array()
            .expect("schema required is array")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for field in [
            "schema_version",
            "services",
            "resources",
            "budgets",
            "slo_hooks",
            "supervision",
            "observability",
            "compatibility",
        ] {
            assert!(required.contains(field), "schema should require {field}");
        }

        let capability_enum = schema["$defs"]["cx_capability"]["enum"]
            .as_array()
            .expect("capability enum exists")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for capability in ["pure", "spawn", "time", "net", "trace", "database"] {
            assert!(
                capability_enum.contains(capability),
                "schema should include capability {capability}"
            );
        }
        crate::test_complete!("appspec_v1_schema_artifact_matches_runtime_contract");
    }

    #[test]
    fn appspec_v1_compiler_plan_is_deterministic_and_explicit() {
        init_test("appspec_v1_compiler_plan_is_deterministic_and_explicit");
        let spec = appspec_v1_sample();
        let plan = spec.compiler_plan().expect("compiler plan builds");
        let second = appspec_v1_sample()
            .compiler_plan()
            .expect("second compiler plan builds");

        assert_eq!(plan, second, "compiler plan must be deterministic");
        assert_eq!(plan.app_name, "payments");
        assert_eq!(plan.root_group, "root");
        assert_eq!(plan.root_restart_policy, AppRestartPolicyV1::OneForOne);
        assert_eq!(
            plan.children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "api.route.readiness",
                "api.actor.cache_warmer",
                "api.job.sweeper"
            ]
        );
        assert_eq!(plan.children[0].kind, AppSpecV1WorkUnitKind::Route);
        assert_eq!(
            plan.children[0].route,
            Some(AppSpecV1RouteBinding {
                method: AppRouteMethodV1::Get,
                path: "/ready".to_string(),
            })
        );
        assert_eq!(plan.children[2].kind, AppSpecV1WorkUnitKind::BackgroundJob);
        assert!(
            matches!(
                plan.children[2].trigger,
                Some(AppJobTriggerV1::Interval { every_ms: 1000 })
            ),
            "background job trigger should be preserved"
        );
        assert_eq!(plan.observability_sinks.len(), 1);
        assert!(
            plan.no_claim_boundaries
                .iter()
                .any(|claim| claim.contains("Does not resolve handler symbols")),
            "compiler plan must carry no-claim boundaries"
        );
        crate::test_complete!("appspec_v1_compiler_plan_is_deterministic_and_explicit");
    }

    #[test]
    fn appspec_v1_compile_requires_explicit_child_factories() {
        init_test("appspec_v1_compile_requires_explicit_child_factories");
        let err = appspec_v1_sample()
            .compile_with_child_specs(Vec::new())
            .expect_err("missing child factories reject");
        assert!(
            matches!(
                err,
                AppSpecV1CompileError::MissingChildSpec { ref name }
                    if name == "api.route.readiness"
            ),
            "unexpected compile error: {err:?}"
        );

        let unexpected = appspec_v1_sample()
            .compile_with_child_specs(vec![make_child("api.route.readiness"), make_child("extra")])
            .expect_err("unexpected child factory rejects");
        assert!(
            matches!(
                unexpected,
                AppSpecV1CompileError::UnexpectedChildSpec { ref name } if name == "extra"
            ),
            "unexpected compile error: {unexpected:?}"
        );
        crate::test_complete!("appspec_v1_compile_requires_explicit_child_factories");
    }

    #[test]
    fn appspec_v1_compile_lowers_to_existing_builder() {
        init_test("appspec_v1_compile_lowers_to_existing_builder");
        let app = appspec_v1_sample()
            .compile_with_child_specs(vec![
                make_child("api.route.readiness"),
                make_child("api.actor.cache_warmer"),
                make_child("api.job.sweeper"),
            ])
            .expect("explicit factories lower to AppSpec");

        let compiled = app.compile().expect("lowered AppSpec compiles");
        assert_eq!(compiled.name(), "payments");
        assert_eq!(
            compiled
                .compiled_supervisor()
                .children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "api.route.readiness",
                "api.actor.cache_warmer",
                "api.job.sweeper"
            ]
        );
        assert_eq!(compiled.compiled_supervisor().start_order.len(), 3);
        crate::test_complete!("appspec_v1_compile_lowers_to_existing_builder");
    }

    #[test]
    fn app_spec_new_creates_named_spec() {
        init_test("app_spec_new_creates_named_spec");
        let spec = AppSpec::new("test_app");
        assert_eq!(spec.name, "test_app");
        assert!(spec.budget.is_none());
        crate::test_complete!("app_spec_new_creates_named_spec");
    }

    #[test]
    fn app_spec_with_budget_sets_budget() {
        init_test("app_spec_with_budget_sets_budget");
        let budget = Budget::new().with_poll_quota(100);
        let spec = AppSpec::new("budgeted").with_budget(budget);
        assert_eq!(spec.budget, Some(budget));
        crate::test_complete!("app_spec_with_budget_sets_budget");
    }

    #[test]
    fn app_start_creates_region_and_spawns() {
        init_test("app_start_creates_region_and_spawns");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("my_app").child(make_child("worker"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert_eq!(handle.name(), "my_app");
        assert_ne!(handle.root_region(), root); // Separate child region.
        assert_eq!(handle.supervisor().started.len(), 1);
        assert_eq!(handle.supervisor().started[0].name, "worker");

        // Resolve to avoid drop bomb.
        let _raw = handle.into_raw();
        crate::test_complete!("app_start_creates_region_and_spawns");
    }

    #[test]
    fn app_start_with_multiple_children() {
        init_test("app_start_with_multiple_children");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("multi")
            .child(make_child("alpha"))
            .child(make_child("bravo"))
            .child(make_child("charlie"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert_eq!(handle.supervisor().started.len(), 3);
        let _raw = handle.into_raw();
        crate::test_complete!("app_start_with_multiple_children");
    }

    #[test]
    fn app_stop_initiates_cancel() {
        init_test("app_stop_initiates_cancel");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("stoppable").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let stopped = handle.stop(&mut state).expect("stop ok");
        assert_eq!(stopped.name, "stoppable");
        assert_eq!(stopped.root_region, app_region);

        // Region should have a cancel request and be closing.
        let region = state.region(app_region).expect("region exists");
        assert!(
            region.state() == RegionState::Closing || region.state() == RegionState::Closed,
            "region should be closing or closed, got {:?}",
            region.state()
        );

        crate::test_complete!("app_stop_initiates_cancel");
    }

    #[test]
    fn app_join_on_closed_region_succeeds() {
        init_test("app_join_on_closed_region_succeeds");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Start app with no children (empty supervisor).
        let spec = AppSpec::new("empty_app");
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Force-close the region for testing purposes.
        if let Some(r) = state.region(app_region) {
            // Remove tasks to satisfy strict quiescence
            for task in r.task_ids() {
                r.remove_task(task);
            }
            for child in r.child_ids() {
                r.remove_child(child);
            }
            r.begin_close(None);
            r.begin_drain();
            r.begin_finalize();
            assert!(r.complete_close(), "should be able to close empty region");
        }

        assert!(
            state
                .region(app_region)
                .is_some_and(|r| r.state() == RegionState::Closed)
        );

        let stopped = handle.join(&state).expect("join ok");
        assert_eq!(stopped.name, "empty_app");
        crate::test_complete!("app_join_on_closed_region_succeeds");
    }

    #[test]
    fn app_join_on_open_region_preserves_handle() {
        init_test("app_join_on_open_region_preserves_handle");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("still_running").child(make_child("worker"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let result = handle.join(&state);
        assert!(
            matches!(
                result,
                Err(AppStopError::RegionNotStopped { region, state })
                    if region == app_region && state == RegionState::Open
            ),
            "expected RegionNotStopped(Open) for the running app region"
        );

        let stopped = handle
            .stop(&mut state)
            .expect("handle should remain usable after join miss");
        assert_eq!(stopped.root_region, app_region);

        crate::test_complete!("app_join_on_open_region_preserves_handle");
    }

    #[test]
    fn app_into_raw_disarms_drop_bomb() {
        init_test("app_into_raw_disarms_drop_bomb");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("raw_app");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        let raw = handle.into_raw();
        assert_eq!(raw.name, "raw_app");
        // raw can be dropped without panic.
        drop(raw);
        crate::test_complete!("app_into_raw_disarms_drop_bomb");
    }

    #[test]
    fn app_handle_drop_without_resolve_reports_without_panicking() {
        init_test("app_handle_drop_without_resolve_reports_without_panicking");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("leaky");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        drop(handle);
        crate::test_complete!("app_handle_drop_without_resolve_reports_without_panicking");
    }

    #[test]
    fn app_start_compile_error_on_duplicate_children() {
        init_test("app_start_compile_error_on_duplicate_children");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("dup")
            .child(make_child("same"))
            .child(make_child("same"));

        let err = spec.start(&mut state, &cx, root).unwrap_err();
        assert!(
            matches!(
                err,
                AppStartError::CompileFailed(AppCompileError::SupervisorCompile(
                    SupervisorCompileError::DuplicateChildName(_)
                ))
            ),
            "expected DuplicateChildName, got {err:?}"
        );
        crate::test_complete!("app_start_compile_error_on_duplicate_children");
    }

    #[test]
    fn app_start_spawn_failure_cleans_up_allocated_region() {
        init_test("app_start_spawn_failure_cleans_up_allocated_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let failing_child = ChildSpec {
            name: "broken".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 _state: &mut RuntimeState,
                 _cx: &Cx| Err(SpawnError::RegionClosed(scope.region_id())),
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("broken_app").child(failing_child);
        let result = spec.start(&mut state, &cx, root);
        assert!(matches!(result, Err(AppStartError::SpawnFailed(_))));
        assert_eq!(
            state.regions_len(),
            1,
            "failed app start should not leak an extra region"
        );
        assert_eq!(
            state
                .region(root)
                .map(crate::record::RegionRecord::child_count),
            Some(0),
            "parent root should not retain a leaked child region"
        );

        crate::test_complete!("app_start_spawn_failure_cleans_up_allocated_region");
    }

    #[test]
    fn app_start_spawn_failure_cleans_up_started_tasks() {
        init_test("app_start_spawn_failure_cleans_up_started_tasks");
        use crate::runtime::state::completion_observer_test_support::PanickingCompletionMetrics;

        let metrics = PanickingCompletionMetrics::panic_persistently();
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let failing_child = ChildSpec {
            name: "broken".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 _state: &mut RuntimeState,
                 _cx: &Cx| Err(SpawnError::RegionClosed(scope.region_id())),
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["started".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("partially_started_app")
            .child(make_child("started"))
            .child(failing_child);
        let result = spec.start(&mut state, &cx, root);

        assert!(matches!(result, Err(AppStartError::SpawnFailed(_))));
        assert_eq!(
            state.live_task_count(),
            0,
            "failed app start should not leave unscheduled tasks behind"
        );
        assert_eq!(
            state.regions_len(),
            1,
            "failed app start should remove the temporary app region tree"
        );
        assert_eq!(
            state
                .region(root)
                .map(crate::record::RegionRecord::child_count),
            Some(0),
            "parent root should not retain leaked app descendants"
        );
        assert_eq!(
            metrics.completion_attempts(),
            0,
            "failed-start cleanup must suppress direct completion observers"
        );

        crate::test_complete!("app_start_spawn_failure_cleans_up_started_tasks");
    }

    #[test]
    fn app_start_spawn_failure_drains_async_finalizers() {
        init_test("app_start_spawn_failure_drains_async_finalizers");
        let metrics =
            crate::runtime::state::spawn_observer_test_support::PanickingSpawnMetrics::new();
        let mut state = RuntimeState::new_with_metrics(metrics.clone());
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let finalizer_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finalizer_ran_clone = Arc::clone(&finalizer_ran);
        let rollback_spawn_denied = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rollback_spawn_denied_clone = Arc::clone(&rollback_spawn_denied);
        let failing_child = ChildSpec {
            name: "broken".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      _cx: &Cx| {
                    let registered = state.register_async_finalizer(scope.region_id(), {
                        let finalizer_ran = Arc::clone(&finalizer_ran_clone);
                        let rollback_spawn_denied = Arc::clone(&rollback_spawn_denied_clone);
                        async move {
                            let rollback_cx = Cx::current()
                                .expect("failed-start finalizer should receive an ambient Cx");
                            rollback_spawn_denied.store(
                                matches!(
                                    rollback_cx.spawn(|_| async {}),
                                    Err(SpawnError::RuntimeUnavailable)
                                ),
                                std::sync::atomic::Ordering::SeqCst,
                            );
                            finalizer_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    });
                    assert!(registered, "startup region should accept async finalizer");
                    Err(SpawnError::RegionClosed(scope.region_id()))
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("broken_finalizer_app").child(failing_child);
        let result = spec.start(&mut state, &cx, root);

        assert!(matches!(result, Err(AppStartError::SpawnFailed(_))));
        assert!(
            finalizer_ran.load(std::sync::atomic::Ordering::SeqCst),
            "failed app start should still drain registered async finalizers"
        );
        assert!(
            rollback_spawn_denied.load(std::sync::atomic::Ordering::SeqCst),
            "failed-start rollback must deny work that could keep its closing subtree live"
        );
        assert_eq!(
            metrics.spawn_attempts(),
            0,
            "failed-start inline finalizers are rollback callbacks, not unpublished tasks"
        );
        assert_eq!(
            state.live_task_count(),
            0,
            "failed app start should not leave async finalizer tasks behind"
        );
        assert_eq!(
            state.regions_len(),
            1,
            "failed app start should remove the temporary app region tree"
        );
        assert_eq!(
            state
                .region(root)
                .map(crate::record::RegionRecord::child_count),
            Some(0),
            "parent root should not retain leaked app descendants"
        );
        assert_eq!(
            state.cancel_protocol_validator().lock().violation_count(),
            0,
            "failed-start finalization should stay validator-aligned"
        );

        crate::test_complete!("app_start_spawn_failure_drains_async_finalizers");
    }

    #[test]
    fn app_is_quiescent_after_close() {
        init_test("app_is_quiescent_after_close");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("quiescent_test");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Disarm drop bomb early so assertions can't cause double-panic.
        let raw = handle.into_raw();

        // Force region through lifecycle.
        if let Some(r) = state.region(app_region) {
            // Remove tasks and children to satisfy strict quiescence
            for task in r.task_ids() {
                r.remove_task(task);
            }
            for child in r.child_ids() {
                r.remove_child(child);
            }
            r.begin_close(None);
            r.begin_drain();
            r.begin_finalize();
            assert!(r.complete_close(), "should close empty region");
        }

        let region = state.region(app_region).expect("region exists");
        assert_eq!(region.state(), RegionState::Closed);
        // Note: is_quiescent requires all children removed, which force-close
        // doesn't do. In production, the drain phase handles child cleanup.

        drop(raw);
        crate::test_complete!("app_is_quiescent_after_close");
    }

    #[test]
    fn app_with_budget_propagates_to_region() {
        init_test("app_with_budget_propagates_to_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let budget = Budget::new().with_poll_quota(100_000);
        let spec = AppSpec::new("budgeted_app").with_budget(budget);
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        let region = state.region(handle.root_region()).expect("region exists");
        assert_eq!(region.budget().poll_quota, budget.poll_quota);

        let _raw = handle.into_raw();
        crate::test_complete!("app_with_budget_propagates_to_region");
    }

    // --- Compile + Spawn tests (bd-32w45) ---

    #[test]
    fn app_compile_produces_compiled_app() {
        init_test("app_compile_produces_compiled_app");
        let compiled = AppSpec::new("compiled_test")
            .child(make_child("a"))
            .child(make_child("b"))
            .compile()
            .expect("compile ok");
        assert_eq!(compiled.name(), "compiled_test");
        crate::test_complete!("app_compile_produces_compiled_app");
    }

    #[test]
    fn app_compile_detects_duplicate_names() {
        init_test("app_compile_detects_duplicate_names");
        let err = AppSpec::new("dup_compile")
            .child(make_child("same"))
            .child(make_child("same"))
            .compile()
            .unwrap_err();
        assert!(
            matches!(
                err,
                AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(_))
            ),
            "expected DuplicateChildName, got {err:?}"
        );
        crate::test_complete!("app_compile_detects_duplicate_names");
    }

    #[test]
    fn app_compiled_start_creates_region_and_spawns() {
        init_test("app_compiled_start_creates_region_and_spawns");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let compiled = AppSpec::new("two_phase")
            .child(make_child("w1"))
            .child(make_child("w2"))
            .compile()
            .expect("compile ok");
        let handle = compiled.start(&mut state, &cx, root).expect("start ok");
        assert_eq!(handle.name(), "two_phase");
        assert_eq!(handle.supervisor().started.len(), 2);
        let _raw = handle.into_raw();
        crate::test_complete!("app_compiled_start_creates_region_and_spawns");
    }

    #[test]
    fn app_compile_is_deterministic() {
        init_test("app_compile_is_deterministic");
        let build = || {
            AppSpec::new("det")
                .child(make_child("c"))
                .child(make_child("a"))
                .child(make_child("b"))
        };
        let c1 = build().compile().unwrap();
        let c2 = build().compile().unwrap();
        assert_eq!(
            c1.compiled_supervisor().start_order,
            c2.compiled_supervisor().start_order,
            "compile must produce identical start orders"
        );
        crate::test_complete!("app_compile_is_deterministic");
    }

    #[test]
    fn app_compile_with_dependencies_is_deterministic() {
        init_test("app_compile_with_dependencies_is_deterministic");
        let build = || {
            let mut b = make_child("b");
            b.depends_on = vec!["a".into()];
            let mut c = make_child("c");
            c.depends_on = vec!["b".into()];
            AppSpec::new("dep_det")
                .child(c)
                .child(make_child("a"))
                .child(b)
        };
        let c1 = build().compile().unwrap();
        let c2 = build().compile().unwrap();
        assert_eq!(
            c1.compiled_supervisor().start_order,
            c2.compiled_supervisor().start_order
        );
        crate::test_complete!("app_compile_with_dependencies_is_deterministic");
    }

    #[test]
    fn app_compile_budget_propagates() {
        init_test("app_compile_budget_propagates");
        let budget = Budget::new().with_poll_quota(100_000);
        let compiled = AppSpec::new("budgeted_compile")
            .with_budget(budget)
            .compile()
            .unwrap();
        assert_eq!(compiled.budget, Some(budget));
        crate::test_complete!("app_compile_budget_propagates");
    }

    // --- Conformance tests ---

    #[test]
    fn conformance_start_stop_lifecycle() {
        init_test("conformance_start_stop_lifecycle");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Start → stop → region transitions correctly.
        let spec = AppSpec::new("lifecycle").child(make_child("w1"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Region starts open.
        assert_eq!(state.region(app_region).unwrap().state(), RegionState::Open);

        let _stopped = handle.stop(&mut state).expect("stop ok");

        // Region should transition past Open.
        let region_state = state.region(app_region).unwrap().state();
        assert_ne!(
            region_state,
            RegionState::Open,
            "region should no longer be open after stop"
        );

        crate::test_complete!("conformance_start_stop_lifecycle");
    }

    #[test]
    fn conformance_no_ambient_authority() {
        init_test("conformance_no_ambient_authority");

        // Verify AppSpec is pure data: cannot access globals or state
        // without being explicitly given &mut RuntimeState and &Cx.
        let spec = AppSpec::new("isolated");
        // spec holds no references to runtime state, only description data.
        assert_eq!(spec.name, "isolated");
        assert!(spec.budget.is_none());
        // The only way to start is by providing explicit state + cx.

        crate::test_complete!("conformance_no_ambient_authority");
    }

    #[test]
    fn conformance_root_region_is_child_of_parent() {
        init_test("conformance_root_region_is_child_of_parent");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("nested");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The app's root region should be a child of the parent region.
        let app_region = handle.root_region();
        let region_record = state.region(app_region).expect("region exists");
        assert_eq!(
            region_record.parent,
            Some(root),
            "app root region must be a child of the given parent"
        );

        let _raw = handle.into_raw();
        crate::test_complete!("conformance_root_region_is_child_of_parent");
    }

    #[test]
    fn conformance_stop_is_cancel_correct() {
        init_test("conformance_stop_is_cancel_correct");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("cancel_correct").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let _stopped = handle.stop(&mut state).expect("stop ok");

        // After stop, the region should have a cancel reason set.
        let region = state.region(app_region).expect("region exists");
        assert!(
            region.cancel_reason().is_some(),
            "stop must set a cancel reason on the root region"
        );

        crate::test_complete!("conformance_stop_is_cancel_correct");
    }

    #[test]
    fn conformance_deterministic_child_start_order() {
        init_test("conformance_deterministic_child_start_order");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Children with dependencies: charlie depends on bravo, bravo depends on alpha.
        let alpha = ChildSpec {
            name: "alpha".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 1_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let bravo = ChildSpec {
            name: "bravo".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 2_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["alpha".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let charlie = ChildSpec {
            name: "charlie".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 3_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["bravo".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("ordered")
            .child(charlie) // Intentionally out of order.
            .child(alpha)
            .child(bravo);
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Start order should be alpha → bravo → charlie regardless of insertion order.
        let names: Vec<&str> = handle
            .supervisor()
            .started
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);

        let _raw = handle.into_raw();
        crate::test_complete!("conformance_deterministic_child_start_order");
    }

    #[test]
    fn conformance_compiled_app_starts_and_closes() {
        init_test("conformance_compiled_app_starts_and_closes");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let compiled = AppSpec::new("quiesce")
            .child(make_child("w1"))
            .compile()
            .expect("compile ok");
        let mut handle = compiled.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();
        let _stopped = handle.stop(&mut state).expect("stop ok");

        if let Some(r) = state.region(app_region) {
            // Remove tasks and children to satisfy strict quiescence
            for task in r.task_ids() {
                r.remove_task(task);
            }
            for child in r.child_ids() {
                r.remove_child(child);
            }
            if r.state() == RegionState::Closing {
                r.begin_drain();
            }
            if r.state() == RegionState::Draining {
                r.begin_finalize();
            }
            if r.state() == RegionState::Finalizing {
                assert!(r.complete_close(), "should complete close");
            }
        }

        assert_eq!(
            state.region(app_region).unwrap().state(),
            RegionState::Closed,
        );
        crate::test_complete!("conformance_compiled_app_starts_and_closes");
    }

    #[test]
    fn conformance_compile_errors_are_explicit() {
        init_test("conformance_compile_errors_are_explicit");
        let err = AppSpec::new("errs")
            .child(make_child("dup"))
            .child(make_child("dup"))
            .compile()
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("compile failed"),
            "error should mention compile: {msg}"
        );
        assert!(
            std::error::Error::source(&err).is_some(),
            "AppCompileError must have a source"
        );
        crate::test_complete!("conformance_compile_errors_are_explicit");
    }

    #[test]
    fn conformance_compile_then_start_matches_direct() {
        init_test("conformance_compile_then_start_matches_direct");

        let mut s1 = RuntimeState::new();
        let r1 = s1.create_root_region(Budget::INFINITE);
        let cx1 = Cx::new(
            r1,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let mut s2 = RuntimeState::new();
        let r2 = s2.create_root_region(Budget::INFINITE);
        let cx2 = Cx::new(
            r2,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let h1 = AppSpec::new("direct")
            .child(make_child("w"))
            .start(&mut s1, &cx1, r1)
            .unwrap();
        let compiled = AppSpec::new("compiled")
            .child(make_child("w"))
            .compile()
            .unwrap();
        let h2 = compiled.start(&mut s2, &cx2, r2).unwrap();

        assert_eq!(h1.supervisor().started.len(), h2.supervisor().started.len());
        assert_ne!(h1.root_region(), r1);
        assert_ne!(h2.root_region(), r2);

        let _raw1 = h1.into_raw();
        let _raw2 = h2.into_raw();
        crate::test_complete!("conformance_compile_then_start_matches_direct");
    }

    // --- Registry wiring tests (bd-2ukjr) ---

    #[test]
    fn app_with_registry_propagates_to_children() {
        init_test("app_with_registry_propagates_to_children");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Parent Cx has no registry.
        assert!(!cx.has_registry());

        // Build a child that checks for registry capability.
        let registry_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&registry_seen);
        let child = ChildSpec {
            name: "checker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    // Child should see the registry propagated through the app.
                    seen_clone.store(cx.has_registry(), std::sync::atomic::Ordering::SeqCst);
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("registry_app")
            .with_registry(handle)
            .child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The child factory should have seen the registry.
        assert!(
            registry_seen.load(std::sync::atomic::Ordering::SeqCst),
            "child Cx must carry registry when app is started with one"
        );

        // The app handle should expose the registry.
        assert!(app_handle.registry().is_some());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_with_registry_propagates_to_children");
    }

    #[test]
    fn app_bootstrap_cx_targets_app_root_and_preserves_capabilities() {
        init_test("app_bootstrap_cx_targets_app_root_and_preserves_capabilities");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let parent_task = crate::types::TaskId::new_for_test(77, 9);
        let cx = Cx::new(root, parent_task, Budget::INFINITE)
            .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin-test")));

        let seen = Arc::new(parking_lot::Mutex::new(
            None::<(RegionId, crate::types::TaskId, bool, Option<String>)>,
        ));
        let seen_clone = Arc::clone(&seen);
        let child = ChildSpec {
            name: "checker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    *seen_clone.lock() = Some((
                        cx.region_id(),
                        cx.task_id(),
                        cx.has_registry(),
                        cx.remote_cap_handle()
                            .map(|cap| cap.local_node().as_str().to_string()),
                    ));
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, stored)| stored.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let app_handle = AppSpec::new("bootstrap_cx_app")
            .with_registry(handle)
            .child(child)
            .start(&mut state, &cx, root)
            .expect("start ok");

        let (seen_region, seen_task, saw_registry, remote_origin) = seen
            .lock()
            .clone()
            .expect("child should observe bootstrap cx");
        assert_eq!(
            seen_region,
            app_handle.root_region(),
            "startup closures must observe the app root region, not the caller's region"
        );
        assert_ne!(
            seen_task, parent_task,
            "startup closures must not inherit the caller's task identity"
        );
        assert!(
            saw_registry,
            "app registry override must be visible during startup"
        );
        assert_eq!(remote_origin.as_deref(), Some("origin-test"));

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_bootstrap_cx_targets_app_root_and_preserves_capabilities");
    }

    #[test]
    fn app_without_registry_children_see_none() {
        init_test("app_without_registry_children_see_none");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let registry_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&registry_seen);
        let child = ChildSpec {
            name: "no_reg".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    seen_clone.store(cx.has_registry(), std::sync::atomic::Ordering::SeqCst);
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("no_registry_app").child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert!(
            !registry_seen.load(std::sync::atomic::Ordering::SeqCst),
            "child Cx must NOT have registry when app has none"
        );
        assert!(app_handle.registry().is_none());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_without_registry_children_see_none");
    }

    #[test]
    fn app_registry_named_service_whereis() {
        init_test("app_registry_named_service_whereis");

        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));
        let reg_handle =
            RegistryHandle::new(Arc::clone(&registry) as Arc<dyn crate::cx::RegistryCap>);

        // Shared slot for the NameLease (must be resolved before drop).
        let lease_slot: Arc<parking_lot::Mutex<Option<crate::cx::NameLease>>> =
            Arc::new(parking_lot::Mutex::new(None));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Child registers itself in the shared registry.
        let reg_clone = Arc::clone(&registry);
        let lease_clone = Arc::clone(&lease_slot);
        let child = ChildSpec {
            name: "named_worker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      _cx: &Cx| {
                    let region = scope.region_id();
                    let budget = scope.budget();
                    let (_, stored) = state.create_task(region, budget, async { 1_u8 })?;
                    let task_id = stored.task_id();

                    // Register the task name in the shared registry.
                    let now = crate::types::Time::from_nanos(1_000_000_000);
                    let lease = reg_clone
                        .lock()
                        .register("my_worker", task_id, region, now)
                        .expect("register ok");

                    // Store the lease so it can be resolved after assertions.
                    *lease_clone.lock() = Some(lease);

                    Ok(task_id)
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("named_app")
            .with_registry(reg_handle)
            .child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The named worker should be findable via whereis.
        let found = registry.lock().whereis("my_worker");
        assert!(found.is_some(), "named worker must be visible via whereis");

        // Clean up: release the lease to avoid obligation drop bomb.
        lease_slot
            .lock()
            .as_mut()
            .expect("lease should have been set")
            .release()
            .expect("release ok");

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_registry_named_service_whereis");
    }

    #[test]
    fn app_registry_compile_preserves_handle() {
        init_test("app_registry_compile_preserves_handle");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let compiled = AppSpec::new("compiled_reg")
            .with_registry(handle)
            .child(make_child("w"))
            .compile()
            .expect("compile ok");

        // Registry should survive compilation.
        assert!(compiled.registry.is_some());

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let app_handle = compiled.start(&mut state, &cx, root).expect("start ok");
        assert!(app_handle.registry().is_some());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_registry_compile_preserves_handle");
    }

    #[test]
    fn app_registry_stop_does_not_panic() {
        init_test("app_registry_stop_does_not_panic");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("stoppable_reg")
            .with_registry(handle)
            .child(make_child("w"));
        let mut app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Stop should work without panic.
        let _stopped = app_handle.stop(&mut state).expect("stop ok");
        crate::test_complete!("app_registry_stop_does_not_panic");
    }

    // =====================================================================
    // Mini Chat App Example (bd-2cruj)
    //
    // Demonstrates GenServer + Registry + Supervisor integration patterns.
    // =====================================================================

    use crate::gen_server::{GenServer, Reply, SystemMsg};
    use std::future::Future;
    use std::pin::Pin;

    /// Chat room state: holds a bounded message history.
    struct ChatRoom {
        history: Vec<String>,
        max_history: usize,
    }

    /// Synchronous requests (call): operations that return a response.
    enum ChatCall {
        /// Get the current message history.
        GetHistory,
        /// Get the number of messages.
        #[allow(dead_code)]
        Count,
    }

    /// Asynchronous messages (cast): fire-and-forget operations.
    enum ChatCast {
        /// Post a message to the room.
        Post(String),
        /// Clear all messages.
        Clear,
    }

    impl GenServer for ChatRoom {
        type Call = ChatCall;
        type Reply = Vec<String>;
        type Cast = ChatCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: ChatCall,
            reply: Reply<Vec<String>>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                ChatCall::GetHistory => {
                    let _ = reply.send(self.history.clone());
                }
                ChatCall::Count => {
                    // Encode count as a single-element vec to satisfy the Reply type.
                    let _ = reply.send(vec![self.history.len().to_string()]);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: ChatCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                ChatCast::Post(text) => {
                    self.history.push(text);
                    if self.history.len() > self.max_history {
                        self.history.remove(0);
                    }
                }
                ChatCast::Clear => {
                    self.history.clear();
                }
            }
            Box::pin(async {})
        }
    }

    impl ChatRoom {
        fn new(max_history: usize) -> Self {
            Self {
                history: Vec::new(),
                max_history,
            }
        }
    }

    #[test]
    fn example_chat_room_call_and_cast() {
        // Demonstrates: GenServer with typed call (GetHistory) and cast (Post).
        init_test("example_chat_room_call_and_cast");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(100), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Cast: post messages (fire-and-forget).
        handle
            .try_cast(ChatCast::Post("alice: hello".into()))
            .unwrap();
        handle
            .try_cast(ChatCast::Post("bob: hi alice".into()))
            .unwrap();
        handle
            .try_cast(ChatCast::Post("alice: how are you?".into()))
            .unwrap();

        // Spawn a client task that calls GetHistory.
        let server_ref = handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        // Schedule the server, run until idle; the client is admitted via the
        // spawn gateway while the long-lived server remains parked on receive.
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        // Verify the client received the full history.
        let history =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], "alice: hello");
        assert_eq!(history[1], "bob: hi alice");
        assert_eq!(history[2], "alice: how are you?");

        crate::test_complete!("example_chat_room_call_and_cast");
    }

    #[test]
    fn example_chat_room_bounded_history() {
        // Demonstrates: cast overflow handling (bounded history, not bounded channel).
        init_test("example_chat_room_bounded_history");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        // Chat room with max 2 messages.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(2), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Post 3 messages; oldest should be evicted.
        handle.try_cast(ChatCast::Post("msg1".into())).unwrap();
        handle.try_cast(ChatCast::Post("msg2".into())).unwrap();
        handle.try_cast(ChatCast::Post("msg3".into())).unwrap();

        let server_ref = handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let history =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(history, vec!["msg2", "msg3"], "oldest message evicted");

        crate::test_complete!("example_chat_room_bounded_history");
    }

    #[test]
    fn example_chat_room_named_via_registry() {
        // Demonstrates: named server registration + whereis lookup.
        init_test("example_chat_room_named_via_registry");

        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        // Spawn a named chat room via the atomic spawn_named_gen_server API.
        let (mut named_handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry.lock(),
                "lobby",
                ChatRoom::new(100),
                32,
                crate::types::Time::from_nanos(1_000_000_000),
            )
            .unwrap();
        let task_id = named_handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // The room should be discoverable via whereis.
        let found = registry.lock().whereis("lobby");
        assert!(
            found.is_some(),
            "named chat room must be visible via whereis"
        );
        assert_eq!(found.unwrap(), task_id);

        // Post and read via the named handle's server_ref.
        named_handle
            .inner()
            .try_cast(ChatCast::Post("welcome to lobby".into()))
            .unwrap();

        let server_ref = named_handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let history = futures_lite::future::block_on(client_handle.join(&cx)).expect("join ok");
        assert_eq!(history, vec!["welcome to lobby"]);

        // Clean up the example explicitly. Dedicated `release_name` semantics
        // are covered in `gen_server` tests; this example just needs to resolve
        // the name lease deterministically before teardown.
        let mut lease = named_handle.take_lease().expect("lease present");
        named_handle.inner().abort();
        let release_now = runtime.state.now;
        let mut registry_guard = registry.lock();
        registry_guard
            .unregister_owned_and_grant(&lease, release_now)
            .expect("manual unregister ok");
        lease.abort().expect("lease abort ok");
        drop(registry_guard);

        // After stop-and-release, whereis should return None.
        let found_after = registry.lock().whereis("lobby");
        assert!(
            found_after.is_none(),
            "name must be gone after stop-and-release"
        );

        crate::test_complete!("example_chat_room_named_via_registry");
    }

    #[test]
    fn example_chat_room_supervised_app() {
        // Demonstrates: ChatRoom as a supervised child in an AppSpec.
        init_test("example_chat_room_supervised_app");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let chat_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_clone = Arc::clone(&chat_started);

        // ChildSpec that spawns a ChatRoom GenServer.
        let chat_child = ChildSpec {
            name: "lobby".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    let (handle, stored) =
                        scope.spawn_gen_server::<ChatRoom>(state, cx, ChatRoom::new(100), 32)?;
                    started_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                    let task_id = handle.task_id();
                    state.store_spawned_task(task_id, stored);
                    Ok(task_id)
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("chat_app").child(chat_child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert!(
            chat_started.load(std::sync::atomic::Ordering::SeqCst),
            "ChatRoom GenServer child must be started by supervisor"
        );
        assert_eq!(app_handle.name(), "chat_app");
        assert_eq!(app_handle.supervisor().started.len(), 1);
        assert_eq!(app_handle.supervisor().started[0].name, "lobby");

        let _raw = app_handle.into_raw();
        crate::test_complete!("example_chat_room_supervised_app");
    }

    #[test]
    fn example_chat_app_with_dependencies() {
        // Demonstrates: supervisor compilation with child dependencies.
        // The "announcements" child depends on "lobby" — topological sort
        // ensures lobby starts first regardless of insertion order.
        init_test("example_chat_app_with_dependencies");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let lobby_child = ChildSpec {
            name: "lobby".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 1_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(3, std::time::Duration::from_secs(60)),
            ),
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let announcements_child = ChildSpec {
            name: "announcements".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 2_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(3, std::time::Duration::from_secs(60)),
            ),
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["lobby".into()], // depends on lobby
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        // Insert in reverse order: announcements first, then lobby.
        let spec = AppSpec::new("chat_app")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(announcements_child)
            .child(lobby_child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Despite insertion order, start order must be lobby -> announcements.
        let names: Vec<&str> = app_handle
            .supervisor()
            .started
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["lobby", "announcements"]);

        let _raw = app_handle.into_raw();
        crate::test_complete!("example_chat_app_with_dependencies");
    }

    #[test]
    fn example_chat_clear_resets_history() {
        // Demonstrates: cast (Clear) resets server state.
        init_test("example_chat_clear_resets_history");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("example region should allocate");
        let cx = lab_spawn_cx(&runtime, region, Budget::INFINITE);
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(100), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Post, then clear, then post again.
        handle.try_cast(ChatCast::Post("old msg".into())).unwrap();
        handle.try_cast(ChatCast::Clear).unwrap();
        handle
            .try_cast(ChatCast::Post("fresh start".into()))
            .unwrap();

        let server_ref = handle.server_ref();
        let mut client_handle = cx
            .spawn(
                move |cx| async move { server_ref.call(&cx, ChatCall::GetHistory).await.unwrap() },
            )
            .unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let history = futures_lite::future::block_on(client_handle.join(&cx)).expect("join ok");
        assert_eq!(history, vec!["fresh start"], "clear must reset history");

        crate::test_complete!("example_chat_clear_resets_history");
    }

    // --- Regression tests for audit-found bugs ---

    #[test]
    fn stop_region_not_found_does_not_panic() {
        // REGRESSION TEST: stop() must defuse the drop bomb even when returning Err,
        // preventing panic ("APP HANDLE LEAKED") when the handle is later dropped.
        init_test("stop_region_not_found_does_not_panic");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("phantom").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Simulate corruption/removal inside the originating runtime.
        let _ = state.regions.remove(app_region.arena_index());

        // This must NOT panic — the drop bomb should be defused on the error path.
        let result = handle.stop(&mut state);
        assert!(
            matches!(result, Err(AppStopError::RegionNotFound(region)) if region == app_region),
            "expected RegionNotFound for a missing root region in the originating runtime"
        );
        crate::test_complete!("stop_region_not_found_does_not_panic");
    }

    #[test]
    fn join_region_not_found_does_not_panic() {
        // REGRESSION TEST: join() must defuse the drop bomb even when returning Err,
        // same as stop() path above.
        init_test("join_region_not_found_does_not_panic");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("phantom_join").child(make_child("w"));
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");

        let app_region = handle.root_region();

        // Simulate corruption/removal inside the originating runtime.
        let _ = state.regions.remove(app_region.arena_index());

        let result = handle.join(&state);
        assert!(
            matches!(result, Err(AppStopError::RegionNotFound(region)) if region == app_region),
            "expected RegionNotFound for a missing root region in the originating runtime"
        );
        crate::test_complete!("join_region_not_found_does_not_panic");
    }

    #[test]
    fn app_join_succeeds_after_runtime_removes_closed_region() {
        init_test("app_join_succeeds_after_runtime_removes_closed_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("removed_root");
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        close_app_region_and_remove_records(&mut state, app_region);

        assert!(
            state.region(app_region).is_none(),
            "normal shutdown should remove the closed app region record"
        );
        assert!(handle.is_stopped(&state));
        assert!(handle.is_quiescent(&state));

        let stopped = handle
            .join(&state)
            .expect("join should succeed after removal");
        assert_eq!(stopped.name, "removed_root");
        assert_eq!(stopped.root_region, app_region);

        crate::test_complete!("app_join_succeeds_after_runtime_removes_closed_region");
    }

    #[test]
    fn app_stop_is_idempotent_after_runtime_removes_closed_region() {
        init_test("app_stop_is_idempotent_after_runtime_removes_closed_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("removed_then_stop");
        let mut handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        close_app_region_and_remove_records(&mut state, app_region);

        let stopped = handle
            .stop(&mut state)
            .expect("stop should treat an already removed closed region as stopped");
        assert_eq!(stopped.name, "removed_then_stop");
        assert_eq!(stopped.root_region, app_region);

        crate::test_complete!("app_stop_is_idempotent_after_runtime_removes_closed_region");
    }

    #[test]
    fn app_join_wrong_runtime_preserves_handle_even_with_tombstone_collision() {
        init_test("app_join_wrong_runtime_preserves_handle_even_with_tombstone_collision");

        let mut state_a = RuntimeState::new();
        let root_a = state_a.create_root_region(Budget::INFINITE);
        let cx_a = Cx::new(
            root_a,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let mut state_b = RuntimeState::new();
        let root_b = state_b.create_root_region(Budget::INFINITE);
        let cx_b = Cx::new(
            root_b,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let mut handle_a = AppSpec::new("state_a_app")
            .start(&mut state_a, &cx_a, root_a)
            .expect("start ok");
        let mut handle_b = AppSpec::new("state_b_app")
            .start(&mut state_b, &cx_b, root_b)
            .expect("start ok");

        assert_eq!(
            handle_a.root_region(),
            handle_b.root_region(),
            "fresh runtimes currently allocate the same test root/app region ids"
        );

        close_app_region_and_remove_records(&mut state_b, handle_b.root_region());
        let _ = handle_b.join(&state_b).expect("join state_b app");

        let result = handle_a.join(&state_b);
        assert!(
            matches!(
                result,
                Err(AppStopError::WrongRuntime { region }) if region == handle_a.root_region()
            ),
            "wrong-runtime joins must fail even if a colliding tombstone exists"
        );

        let stopped = handle_a
            .stop(&mut state_a)
            .expect("wrong-runtime join must preserve the original handle");
        assert_eq!(stopped.name, "state_a_app");

        crate::test_complete!(
            "app_join_wrong_runtime_preserves_handle_even_with_tombstone_collision"
        );
    }
