//! Integration tests for Agent Swarm Control Plane.
//!
//! Tests the core agent admission, resource allocation, validation coordination,
//! and proof aggregation workflows under realistic multi-agent scenarios.

use anyhow::Result;
use asupersync::agent_swarm::{
    AdmissionController, AdmissionPriority, AgentAdmissionRequest, AgentAdmissionResult,
    AgentSwarmControlPlane, ControlPlaneConfig, PressureMonitor, ResourceRequirements,
    SystemPressure, ValidationCoordinator,
};
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, Outcome};
use std::time::{Duration, SystemTime};

/// Test basic agent admission and resource allocation.
#[test]
fn test_agent_admission_basic() -> Result<()> {
    asupersync::test_utils::init_test_logging();

    // Create deterministic lab runtime for consistent E2E testing
    let mut runtime = LabRuntime::new(LabConfig::new(0x5157_9001).max_steps(50_000));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    runtime.run(&root, |cx| async {
        // Create control plane configuration
        let config = create_test_config();
        let control_plane = AgentSwarmControlPlane::new(config)?;

        // Create an agent admission request
        let admission_request = AgentAdmissionRequest {
            agent_id: "test-agent-1".to_string(),
            resource_requirements: ResourceRequirements {
                cpu_cores: 2.0,
                memory_bytes: 1 * 1024 * 1024 * 1024, // 1GB
                disk_bytes: 5 * 1024 * 1024 * 1024,   // 5GB
                network_bandwidth: 100_000,           // 100KB/s
                estimated_duration: Some(Duration::from_secs(3600)),
            },
            required_capabilities: vec![],
            priority: AdmissionPriority::Normal,
            requested_at: SystemTime::now(),
            admission_timeout: Some(Duration::from_secs(300)),
            auth_token: Some("agent_token_test-agent-1".to_string()),
            agent_credentials: None,
        };

        // Admit the agent
        let result = control_plane.admit_agent(cx, admission_request).await?;

        // Verify admission was successful
        match result {
            AgentAdmissionResult::Admitted {
                session_id,
                allocated_resources,
                agent_region,
            } => {
                assert!(session_id.starts_with("session-test-agent-1"));
                assert_eq!(allocated_resources.cpu_cores, 2.0);
                assert_eq!(allocated_resources.memory_bytes, 1 * 1024 * 1024 * 1024);
            }
            AgentAdmissionResult::Rejected { reason, .. } => {
                panic!("Agent admission unexpectedly rejected: {:?}", reason);
            }
        }

        // Check control plane metrics
        let metrics = control_plane.metrics().await;
        assert_eq!(metrics.total_agents_admitted, 1);
        assert_eq!(metrics.active_agent_count, 1);
        assert_eq!(metrics.total_agents_rejected, 0);

        Ok(())
    });

    Ok(())
}

/// Test agent admission under system pressure.
#[test]
fn test_agent_admission_under_pressure() -> Result<()> {
    asupersync::test_utils::init_test_logging();

    // Create deterministic lab runtime for consistent E2E testing
    let mut runtime = LabRuntime::new(LabConfig::new(0x5157_9002).max_steps(50_000));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    runtime.run(&root, |cx| async {
        let config = create_test_config();
        let control_plane = AgentSwarmControlPlane::new(config)?;

        // Simulate high system pressure
        let high_pressure = SystemPressure {
            cpu_pressure: 0.9,
            memory_pressure: 0.85,
            disk_pressure: 0.8,
            network_pressure: 0.75,
            validation_pressure: 0.7,
            overall_pressure: 0.85,
            measured_at: SystemTime::now(),
        };

        control_plane.update_pressure(high_pressure).await?;

        // Create an agent admission request
        let admission_request = AgentAdmissionRequest {
            agent_id: "test-agent-pressure".to_string(),
            resource_requirements: ResourceRequirements {
                cpu_cores: 4.0,
                memory_bytes: 2 * 1024 * 1024 * 1024, // 2GB
                disk_bytes: 10 * 1024 * 1024 * 1024,  // 10GB
                network_bandwidth: 1_000_000,         // 1MB/s
                estimated_duration: Some(Duration::from_secs(7200)),
            },
            required_capabilities: vec![],
            priority: AdmissionPriority::Low,
            requested_at: SystemTime::now(),
            admission_timeout: Some(Duration::from_secs(300)),
            auth_token: Some("agent_token_test-agent-pressure".to_string()),
            agent_credentials: None,
        };

        // Attempt to admit the agent
        let result = control_plane.admit_agent(cx, admission_request).await?;

        // Verify admission was rejected due to system pressure
        match result {
            AgentAdmissionResult::Rejected {
                reason,
                retry_after,
            } => {
                assert_eq!(
                    reason,
                    asupersync::agent_swarm::AdmissionRejectionReason::SystemPressure
                );
                assert!(retry_after.is_some());
            }
            AgentAdmissionResult::Admitted { .. } => {
                panic!("Agent admission should have been rejected under high pressure");
            }
        }

        // Check metrics show rejection
        let metrics = control_plane.metrics().await;
        assert_eq!(metrics.total_agents_rejected, 1);

        Ok(())
    });

    Ok(())
}

/// Test multiple concurrent agent admissions.
#[test]
fn test_concurrent_agent_admissions() -> Result<()> {
    asupersync::test_utils::init_test_logging();

    // Create deterministic lab runtime for consistent E2E testing
    let mut runtime = LabRuntime::new(LabConfig::new(0x5157_9003).max_steps(50_000));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    runtime.run(&root, |cx| async {
        let config = create_test_config();
        let control_plane = AgentSwarmControlPlane::new(config)?;

        // Create multiple admission requests
        let mut admission_futures = vec![];

        for i in 0..5 {
            let agent_id = format!("concurrent-agent-{}", i);
            let admission_request = AgentAdmissionRequest {
                agent_id: agent_id.clone(),
                resource_requirements: ResourceRequirements {
                    cpu_cores: 1.0,
                    memory_bytes: 512 * 1024 * 1024,    // 512MB
                    disk_bytes: 2 * 1024 * 1024 * 1024, // 2GB
                    network_bandwidth: 50_000,          // 50KB/s
                    estimated_duration: Some(Duration::from_secs(1800)),
                },
                required_capabilities: vec![],
                priority: AdmissionPriority::Normal,
                requested_at: SystemTime::now(),
                admission_timeout: Some(Duration::from_secs(300)),
                auth_token: Some(format!("agent_token_{}", agent_id)),
                agent_credentials: None,
            };

            let control_plane_ref = &control_plane;
            admission_futures
                .push(async move { control_plane_ref.admit_agent(cx, admission_request).await });
        }

        // Wait for all admissions to complete
        let results = futures::future::join_all(admission_futures).await;

        // Count successful and failed admissions
        let mut admitted_count = 0;
        let mut rejected_count = 0;

        for result in results {
            match result? {
                AgentAdmissionResult::Admitted { .. } => admitted_count += 1,
                AgentAdmissionResult::Rejected { .. } => rejected_count += 1,
            }
        }

        // Verify some agents were admitted (exact number depends on resource policies)
        assert!(
            admitted_count > 0,
            "At least some agents should be admitted"
        );
        assert_eq!(
            admitted_count + rejected_count,
            5,
            "All requests should be processed"
        );

        // Check final metrics
        let metrics = control_plane.metrics().await;
        assert_eq!(metrics.total_agents_admitted as usize, admitted_count);
        assert_eq!(metrics.total_agents_rejected as usize, rejected_count);

        Ok(())
    });

    Ok(())
}

/// Test control plane graceful shutdown.
#[test]
fn test_control_plane_shutdown() -> Result<()> {
    asupersync::test_utils::init_test_logging();

    // Create deterministic lab runtime for consistent E2E testing
    let mut runtime = LabRuntime::new(LabConfig::new(0x5157_9004).max_steps(50_000));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    runtime.run(&root, |cx| async {
        let config = create_test_config();
        let control_plane = AgentSwarmControlPlane::new(config)?;

        // Admit a few agents first
        for i in 0..3 {
            let admission_request = AgentAdmissionRequest {
                agent_id: format!("shutdown-test-agent-{}", i),
                resource_requirements: ResourceRequirements {
                    cpu_cores: 0.5,
                    memory_bytes: 256 * 1024 * 1024, // 256MB
                    disk_bytes: 1024 * 1024 * 1024,  // 1GB
                    network_bandwidth: 25_000,       // 25KB/s
                    estimated_duration: Some(Duration::from_secs(600)),
                },
                required_capabilities: vec![],
                priority: AdmissionPriority::Normal,
                requested_at: SystemTime::now(),
                admission_timeout: Some(Duration::from_secs(300)),
                auth_token: Some(format!("agent_token_shutdown-test-agent-{}", i)),
                agent_credentials: None,
            };

            control_plane.admit_agent(cx, admission_request).await?;
        }

        // Verify agents were admitted
        let metrics_before = control_plane.metrics().await;
        assert_eq!(metrics_before.active_agent_count, 3);

        // Graceful shutdown
        control_plane.shutdown(cx).await?;

        // After shutdown, the control plane should still be queryable
        let metrics_after = control_plane.metrics().await;
        // Implementation would update metrics during shutdown
        // but for this test we just verify the call succeeds

        Ok(())
    });

    Ok(())
}

/// Create a test configuration for the control plane.
fn create_test_config() -> ControlPlaneConfig {
    use asupersync::agent_swarm::{
        AdmissionConfig, CpuAllocationPolicy, DiskAllocationPolicy, HandoffVerifierConfig,
        LanePolicies, MemoryAllocationPolicy, NetworkAllocationPolicy, PressureMonitorConfig,
        PressureThresholds, ProofRoutingConfig, ResourcePolicies, ValidationCoordinatorConfig,
    };
    use std::collections::HashMap;

    ControlPlaneConfig {
        admission_config: AdmissionConfig {
            max_concurrent_agents: 10,
            resource_policies: ResourcePolicies {
                cpu_policy: CpuAllocationPolicy {
                    max_cores_per_agent: 8.0,
                    reservation_strategy: "fair-share".to_string(),
                },
                memory_policy: MemoryAllocationPolicy {
                    max_memory_per_agent: 8 * 1024 * 1024 * 1024, // 8GB
                    oom_protection: true,
                },
                disk_policy: DiskAllocationPolicy {
                    max_disk_per_agent: 50 * 1024 * 1024 * 1024, // 50GB
                    cleanup_strategy: "lru".to_string(),
                },
                network_policy: NetworkAllocationPolicy {
                    max_bandwidth_per_agent: 10_000_000, // 10MB/s
                    qos_enabled: true,
                },
            },
        },
        validation_config: ValidationCoordinatorConfig {
            max_validation_lanes: 8,
            lane_policies: LanePolicies {
                lane_assignment_strategy: "priority-queue".to_string(),
                max_lanes_per_agent: 2,
            },
            proof_routing: ProofRoutingConfig {
                routing_strategy: "load-balance".to_string(),
                proof_retention_policy: "30-days".to_string(),
            },
        },
        handoff_config: HandoffVerifierConfig {
            session_timeout: Duration::from_secs(3600),
            verification_policy: "strict".to_string(),
        },
        proof_config: asupersync::agent_swarm::AggregatorConfig {
            max_beads_per_aggregation: 100,
            aggregation_timeout: Duration::from_secs(300),
            enable_validation: true,
        },
        pressure_config: PressureMonitorConfig {
            monitoring_interval: Duration::from_secs(30),
            pressure_thresholds: {
                let mut thresholds = HashMap::new();
                thresholds.insert(
                    "cpu".to_string(),
                    PressureThresholds {
                        warning_threshold: 0.7,
                        critical_threshold: 0.85,
                        emergency_threshold: 0.95,
                    },
                );
                thresholds.insert(
                    "memory".to_string(),
                    PressureThresholds {
                        warning_threshold: 0.75,
                        critical_threshold: 0.90,
                        emergency_threshold: 0.98,
                    },
                );
                thresholds
            },
        },
    }
}

#[cfg(test)]
mod agent_swarm_e2e_tests {
    use super::*;

    /// End-to-end test simulating a realistic agent swarm workflow.
    #[test]
    fn test_e2e_agent_swarm_workflow() -> Result<()> {
        asupersync::test_utils::init_test_logging();

        // Create deterministic lab runtime for consistent E2E testing
        let mut runtime = LabRuntime::new(LabConfig::new(0x5157_9005).max_steps(100_000));
        let root = runtime.state.create_root_region(Budget::INFINITE);

        runtime.run(&root, |cx| async {
            let config = create_test_config();
            let control_plane = AgentSwarmControlPlane::new(config)?;

            // Phase 1: Normal operations - admit several agents
            let mut admitted_agents = vec![];

            for i in 0..4 {
                let admission_request = AgentAdmissionRequest {
                    agent_id: format!("e2e-agent-{}", i),
                    resource_requirements: ResourceRequirements {
                        cpu_cores: 1.5,
                        memory_bytes: 1024 * 1024 * 1024,   // 1GB
                        disk_bytes: 3 * 1024 * 1024 * 1024, // 3GB
                        network_bandwidth: 100_000,         // 100KB/s
                        estimated_duration: Some(Duration::from_secs(2400)),
                    },
                    required_capabilities: vec![],
                    priority: AdmissionPriority::Normal,
                    requested_at: SystemTime::now(),
                    admission_timeout: Some(Duration::from_secs(300)),
                    auth_token: Some(format!("agent_token_e2e-agent-{}", i)),
                    agent_credentials: None,
                };

                match control_plane.admit_agent(cx, admission_request).await? {
                    AgentAdmissionResult::Admitted { session_id, .. } => {
                        admitted_agents.push(session_id);
                    }
                    AgentAdmissionResult::Rejected { .. } => {
                        // Expected for some agents due to resource limits
                    }
                }
            }

            // Phase 2: Pressure increase - simulate system load
            let medium_pressure = SystemPressure {
                cpu_pressure: 0.6,
                memory_pressure: 0.7,
                disk_pressure: 0.5,
                network_pressure: 0.4,
                validation_pressure: 0.3,
                overall_pressure: 0.58,
                measured_at: SystemTime::now(),
            };

            control_plane.update_pressure(medium_pressure).await?;

            // Phase 3: High priority agent admission during pressure
            let high_priority_request = AgentAdmissionRequest {
                agent_id: "critical_agent_e2e-critical".to_string(),
                resource_requirements: ResourceRequirements {
                    cpu_cores: 0.5,
                    memory_bytes: 256 * 1024 * 1024, // 256MB
                    disk_bytes: 1024 * 1024 * 1024,  // 1GB
                    network_bandwidth: 50_000,       // 50KB/s
                    estimated_duration: Some(Duration::from_secs(600)),
                },
                required_capabilities: vec![],
                priority: AdmissionPriority::Critical,
                requested_at: SystemTime::now(),
                admission_timeout: Some(Duration::from_secs(300)),
                auth_token: Some("agent_token_critical_agent_e2e-critical".to_string()),
                agent_credentials: None,
            };

            let critical_result = control_plane.admit_agent(cx, high_priority_request).await?;

            // Critical priority should often succeed even under pressure
            match critical_result {
                AgentAdmissionResult::Admitted { session_id, .. } => {
                    admitted_agents.push(session_id);
                }
                AgentAdmissionResult::Rejected { reason, .. } => {
                    // Acceptable if system is truly overloaded
                    println!("Critical agent rejected: {:?}", reason);
                }
            }

            // Phase 4: Verify final state
            let final_metrics = control_plane.metrics().await;
            assert!(
                final_metrics.total_agents_admitted > 0,
                "Some agents should have been admitted"
            );
            assert!(
                admitted_agents.len() > 0,
                "Should have at least one successful admission"
            );

            // Phase 5: Graceful shutdown
            control_plane.shutdown(cx).await?;

            Ok(())
        });

        Ok(())
    }
}
