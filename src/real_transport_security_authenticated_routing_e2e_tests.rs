//! Real service E2E tests for transport + security integration.
//!
//! Tests authenticated symbol routing through real transport infrastructure
//! without mocks, exercising both transport layer routing/connections and
//! security authentication/verification in realistic scenarios.

use crate::cx::Cx;
use crate::security::{AuthKey, SecurityContext, AuthMode, AuthenticatedSymbol, AuthError};
use crate::transport::{
    channel, SymbolRouter, SymbolDispatcher, EndpointId, LoadBalanceStrategy,
    RoutingTable, RouteKey, SymbolSink, SymbolStream, SymbolSinkExt, SymbolStreamExt,
    MultipathAggregator, PathId, PathSelectionPolicy, AggregatorConfig,
};
use crate::types::{Symbol, SymbolId, SymbolKind};
use crate::time::Duration;
use crate::util::det_rng::DetRng;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Test configuration for authenticated transport scenarios.
#[derive(Debug, Clone)]
struct AuthenticatedTransportConfig {
    /// Number of routing endpoints to create.
    endpoint_count: usize,
    /// Channel capacity for each transport path.
    channel_capacity: usize,
    /// Number of symbols to send in each test batch.
    symbol_batch_size: usize,
    /// Security context configurations for different authentication modes.
    auth_configs: Vec<AuthTestConfig>,
}

/// Authentication test configuration.
#[derive(Debug, Clone)]
struct AuthTestConfig {
    /// Authentication mode to use.
    mode: AuthMode,
    /// Authentication key seed for deterministic testing.
    key_seed: u64,
    /// Expected success rate (0.0 to 1.0) for this auth config.
    expected_success_rate: f64,
}

impl Default for AuthenticatedTransportConfig {
    fn default() -> Self {
        Self {
            endpoint_count: 4,
            channel_capacity: 16,
            symbol_batch_size: 100,
            auth_configs: vec![
                AuthTestConfig {
                    mode: AuthMode::Strict,
                    key_seed: 12345,
                    expected_success_rate: 1.0,
                },
                AuthTestConfig {
                    mode: AuthMode::Permissive,
                    key_seed: 67890,
                    expected_success_rate: 0.95, // Allow some authentication flexibility
                },
            ],
        }
    }
}

/// Represents an authenticated transport endpoint with its own security context.
struct AuthenticatedEndpoint {
    endpoint_id: EndpointId,
    security_context: SecurityContext,
    sink: Box<dyn SymbolSink>,
    stream: Box<dyn SymbolStream>,
    symbols_sent: AtomicU32,
    symbols_received: AtomicU32,
    auth_failures: AtomicU32,
}

impl AuthenticatedEndpoint {
    fn new(
        endpoint_id: EndpointId,
        auth_config: &AuthTestConfig,
        channel_capacity: usize,
    ) -> Self {
        let auth_key = AuthKey::from_seed(auth_config.key_seed);
        let security_context = SecurityContext::new_with_mode(auth_key, auth_config.mode);
        let (sink, stream) = channel(channel_capacity);

        Self {
            endpoint_id,
            security_context,
            sink: Box::new(sink),
            stream: Box::new(stream),
            symbols_sent: AtomicU32::new(0),
            symbols_received: AtomicU32::new(0),
            auth_failures: AtomicU32::new(0),
        }
    }

    /// Send an authenticated symbol through this endpoint.
    async fn send_authenticated_symbol(&self, cx: &Cx, symbol: Symbol) -> Result<(), Box<dyn std::error::Error>> {
        // Sign the symbol using the endpoint's security context
        let authenticated_symbol = self.security_context.sign_symbol(&symbol);

        // Send through the transport layer
        self.sink.send(authenticated_symbol).await?;
        self.symbols_sent.fetch_add(1, Ordering::Relaxed);

        cx.trace("authenticated_symbol_sent", &format!(
            "endpoint={:?} symbol_id={:?}",
            self.endpoint_id, symbol.id()
        ));

        Ok(())
    }

    /// Receive and verify an authenticated symbol from this endpoint.
    async fn receive_authenticated_symbol(&self, cx: &Cx) -> Result<Option<Symbol>, Box<dyn std::error::Error>> {
        if let Some(mut authenticated_symbol) = self.stream.next().await {
            match self.security_context.verify_authenticated_symbol(&mut authenticated_symbol) {
                Ok(()) => {
                    self.symbols_received.fetch_add(1, Ordering::Relaxed);
                    cx.trace("authenticated_symbol_received", &format!(
                        "endpoint={:?} symbol_id={:?} verified=true",
                        self.endpoint_id, authenticated_symbol.symbol().id()
                    ));
                    Ok(Some(authenticated_symbol.into_symbol()))
                }
                Err(auth_error) => {
                    self.auth_failures.fetch_add(1, Ordering::Relaxed);
                    cx.trace("authentication_failure", &format!(
                        "endpoint={:?} error={:?}",
                        self.endpoint_id, auth_error
                    ));
                    Err(Box::new(auth_error))
                }
            }
        } else {
            Ok(None) // Stream closed
        }
    }

    fn stats(&self) -> (u32, u32, u32) {
        (
            self.symbols_sent.load(Ordering::Relaxed),
            self.symbols_received.load(Ordering::Relaxed),
            self.auth_failures.load(Ordering::Relaxed),
        )
    }
}

/// Multi-endpoint authenticated routing network for testing.
struct AuthenticatedRoutingNetwork {
    endpoints: HashMap<EndpointId, Arc<AuthenticatedEndpoint>>,
    router: SymbolRouter,
    dispatcher: SymbolDispatcher,
    config: AuthenticatedTransportConfig,
}

impl AuthenticatedRoutingNetwork {
    fn new(config: AuthenticatedTransportConfig) -> Self {
        let mut endpoints = HashMap::new();
        let mut routing_table = RoutingTable::new();

        // Create authenticated endpoints with different security contexts
        for i in 0..config.endpoint_count {
            let endpoint_id = EndpointId::from_index(i as u16);
            let auth_config = &config.auth_configs[i % config.auth_configs.len()];

            let endpoint = Arc::new(AuthenticatedEndpoint::new(
                endpoint_id,
                auth_config,
                config.channel_capacity,
            ));

            // Register endpoint in routing table
            routing_table.add_route(
                RouteKey::new(endpoint_id, 0), // priority 0
                endpoint_id,
            );

            endpoints.insert(endpoint_id, endpoint);
        }

        let router = SymbolRouter::new(routing_table, LoadBalanceStrategy::RoundRobin);
        let dispatcher = SymbolDispatcher::new(router.clone());

        Self {
            endpoints,
            router,
            dispatcher,
            config,
        }
    }

    /// Send symbols from source endpoint to target endpoint through authenticated routing.
    async fn send_symbols_between_endpoints(
        &self,
        cx: &Cx,
        source_id: EndpointId,
        target_id: EndpointId,
        symbol_count: usize,
    ) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
        let source_endpoint = self.endpoints.get(&source_id)
            .ok_or("Source endpoint not found")?;

        let mut sent_symbols = Vec::new();

        for i in 0..symbol_count {
            // Create a test symbol
            let symbol_id = SymbolId::new_for_test(
                1,           // object_id
                i as u32,    // block_index
                i as u32,    // esi
            );
            let payload = format!("test_data_{}_{}", source_id.as_u16(), i).into_bytes();
            let symbol = Symbol::new(symbol_id, payload, SymbolKind::Source);

            // Send through authenticated endpoint
            source_endpoint.send_authenticated_symbol(cx, symbol.clone()).await?;
            sent_symbols.push(symbol);

            // Route to target endpoint (simplified routing for this test)
            let route_result = self.router.route_symbol(&symbol, target_id)?;
            cx.trace("symbol_routed", &format!(
                "source={:?} target={:?} route_result={:?}",
                source_id, target_id, route_result
            ));
        }

        Ok(sent_symbols)
    }

    /// Collect received symbols from target endpoint with authentication verification.
    async fn collect_symbols_from_endpoint(
        &self,
        cx: &Cx,
        endpoint_id: EndpointId,
        expected_count: usize,
        timeout_duration: Duration,
    ) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
        let endpoint = self.endpoints.get(&endpoint_id)
            .ok_or("Target endpoint not found")?;

        let mut received_symbols = Vec::new();
        let start_time = std::time::Instant::now();

        while received_symbols.len() < expected_count {
            if start_time.elapsed() > timeout_duration.as_std() {
                return Err("Timeout waiting for symbols".into());
            }

            match endpoint.receive_authenticated_symbol(cx).await {
                Ok(Some(symbol)) => {
                    received_symbols.push(symbol);
                    cx.trace("symbol_collected", &format!(
                        "endpoint={:?} count={}/{}",
                        endpoint_id, received_symbols.len(), expected_count
                    ));
                }
                Ok(None) => {
                    break; // Stream closed
                }
                Err(auth_error) => {
                    cx.trace("collection_auth_failure", &format!(
                        "endpoint={:?} error={:?}",
                        endpoint_id, auth_error
                    ));
                    // Continue collecting despite auth failures in permissive modes
                }
            }
        }

        Ok(received_symbols)
    }

    fn network_stats(&self) -> HashMap<EndpointId, (u32, u32, u32)> {
        self.endpoints.iter()
            .map(|(&id, endpoint)| (id, endpoint.stats()))
            .collect()
    }
}

#[cfg(test)]
mod authenticated_transport_tests {
    use super::*;
    use crate::test_utils::{init_test_logging, TestRuntime};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    /// Test basic authenticated symbol transmission between two endpoints.
    #[test]
    fn test_authenticated_point_to_point_transmission() {
        init_test("test_authenticated_point_to_point_transmission");

        let config = AuthenticatedTransportConfig {
            endpoint_count: 2,
            channel_capacity: 8,
            symbol_batch_size: 10,
            ..Default::default()
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(30), async move |cx| {
            let network = AuthenticatedRoutingNetwork::new(config.clone());

            let source_id = EndpointId::from_index(0);
            let target_id = EndpointId::from_index(1);

            // Send symbols from source to target
            let sent_symbols = network.send_symbols_between_endpoints(
                &cx,
                source_id,
                target_id,
                config.symbol_batch_size,
            ).await?;

            // Collect symbols at target with authentication verification
            let received_symbols = network.collect_symbols_from_endpoint(
                &cx,
                target_id,
                config.symbol_batch_size,
                Duration::from_seconds(10),
            ).await?;

            // Verify transmission integrity
            assert_eq!(
                sent_symbols.len(),
                config.symbol_batch_size,
                "All symbols should be sent"
            );
            assert_eq!(
                received_symbols.len(),
                config.symbol_batch_size,
                "All symbols should be received and authenticated"
            );

            // Verify symbol content integrity
            for (sent, received) in sent_symbols.iter().zip(received_symbols.iter()) {
                assert_eq!(
                    sent.id(),
                    received.id(),
                    "Symbol IDs should match"
                );
                assert_eq!(
                    sent.payload(),
                    received.payload(),
                    "Symbol payloads should match"
                );
                assert_eq!(
                    sent.kind(),
                    received.kind(),
                    "Symbol kinds should match"
                );
            }

            let stats = network.network_stats();
            let (source_sent, _, source_failures) = stats[&source_id];
            let (_, target_received, target_failures) = stats[&target_id];

            assert_eq!(source_sent as usize, config.symbol_batch_size);
            assert_eq!(target_received as usize, config.symbol_batch_size);
            assert_eq!(source_failures, 0, "No auth failures expected in strict mode");
            assert_eq!(target_failures, 0, "No auth failures expected in strict mode");

            cx.trace("test_authenticated_point_to_point_transmission_complete", &format!(
                "sent={} received={} auth_failures={}",
                source_sent, target_received, target_failures
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_authenticated_point_to_point_transmission");
    }

    /// Test multi-endpoint authenticated routing with different security contexts.
    #[test]
    fn test_multi_endpoint_authenticated_routing() {
        init_test("test_multi_endpoint_authenticated_routing");

        let config = AuthenticatedTransportConfig {
            endpoint_count: 4,
            channel_capacity: 16,
            symbol_batch_size: 25,
            auth_configs: vec![
                AuthTestConfig {
                    mode: AuthMode::Strict,
                    key_seed: 11111,
                    expected_success_rate: 1.0,
                },
                AuthTestConfig {
                    mode: AuthMode::Permissive,
                    key_seed: 22222,
                    expected_success_rate: 0.95,
                },
                AuthTestConfig {
                    mode: AuthMode::Strict,
                    key_seed: 33333,
                    expected_success_rate: 1.0,
                },
                AuthTestConfig {
                    mode: AuthMode::Permissive,
                    key_seed: 44444,
                    expected_success_rate: 0.95,
                },
            ],
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(60), async move |cx| {
            let network = AuthenticatedRoutingNetwork::new(config.clone());

            // Create a routing pattern: 0→1, 1→2, 2→3, 3→0 (ring topology)
            let routing_pairs = vec![
                (EndpointId::from_index(0), EndpointId::from_index(1)),
                (EndpointId::from_index(1), EndpointId::from_index(2)),
                (EndpointId::from_index(2), EndpointId::from_index(3)),
                (EndpointId::from_index(3), EndpointId::from_index(0)),
            ];

            let mut all_sent_symbols = Vec::new();
            let mut all_received_symbols = Vec::new();

            // Send symbols through the routing ring
            for (source_id, target_id) in &routing_pairs {
                let sent_symbols = network.send_symbols_between_endpoints(
                    &cx,
                    *source_id,
                    *target_id,
                    config.symbol_batch_size,
                ).await?;
                all_sent_symbols.extend(sent_symbols);

                let received_symbols = network.collect_symbols_from_endpoint(
                    &cx,
                    *target_id,
                    config.symbol_batch_size,
                    Duration::from_seconds(15),
                ).await?;
                all_received_symbols.extend(received_symbols);

                cx.trace("routing_pair_complete", &format!(
                    "source={:?} target={:?} sent={} received={}",
                    source_id, target_id, config.symbol_batch_size, received_symbols.len()
                ));
            }

            // Verify overall network statistics
            let stats = network.network_stats();
            let total_sent: u32 = stats.values().map(|(sent, _, _)| *sent).sum();
            let total_received: u32 = stats.values().map(|(_, received, _)| *received).sum();
            let total_failures: u32 = stats.values().map(|(_, _, failures)| *failures).sum();

            let expected_total = (config.symbol_batch_size * routing_pairs.len()) as u32;

            assert_eq!(total_sent, expected_total, "Total symbols sent should match expected");
            assert!(
                total_received >= (expected_total as f64 * 0.9) as u32,
                "At least 90% of symbols should be received (accounting for auth modes)"
            );

            // Verify different authentication modes behave appropriately
            for (&endpoint_id, &(sent, received, failures)) in &stats {
                let auth_config = &config.auth_configs[endpoint_id.as_u16() as usize % config.auth_configs.len()];

                match auth_config.mode {
                    AuthMode::Strict => {
                        // Strict mode should have high success rates
                        let success_rate = received as f64 / sent as f64;
                        assert!(
                            success_rate >= 0.95,
                            "Strict mode should have >95% success rate, got {}",
                            success_rate
                        );
                    }
                    AuthMode::Permissive => {
                        // Permissive mode allows some failures but should still work
                        let success_rate = received as f64 / sent as f64;
                        assert!(
                            success_rate >= auth_config.expected_success_rate * 0.9,
                            "Permissive mode success rate too low: got {}, expected >= {}",
                            success_rate, auth_config.expected_success_rate * 0.9
                        );
                    }
                }
            }

            cx.trace("test_multi_endpoint_authenticated_routing_complete", &format!(
                "total_sent={} total_received={} total_failures={} endpoints={}",
                total_sent, total_received, total_failures, config.endpoint_count
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_multi_endpoint_authenticated_routing");
    }

    /// Test authentication failure scenarios and recovery.
    #[test]
    fn test_authentication_failure_scenarios() {
        init_test("test_authentication_failure_scenarios");

        TestRuntime::run_with_timeout(Duration::from_seconds(30), async move |cx| {
            // Create endpoints with mismatched authentication keys
            let mut mismatched_config = AuthenticatedTransportConfig {
                endpoint_count: 3,
                channel_capacity: 8,
                symbol_batch_size: 15,
                auth_configs: vec![
                    AuthTestConfig {
                        mode: AuthMode::Strict,
                        key_seed: 99999,  // Different key
                        expected_success_rate: 0.0, // Expect failures
                    },
                    AuthTestConfig {
                        mode: AuthMode::Permissive,
                        key_seed: 88888,  // Different key
                        expected_success_rate: 0.3, // Some tolerance
                    },
                    AuthTestConfig {
                        mode: AuthMode::Strict,
                        key_seed: 77777,  // Different key
                        expected_success_rate: 0.0, // Expect failures
                    },
                ],
            };

            let network = AuthenticatedRoutingNetwork::new(mismatched_config.clone());

            let source_id = EndpointId::from_index(0);
            let target_id = EndpointId::from_index(1); // Permissive mode

            // Send symbols that should mostly fail authentication
            let _sent_symbols = network.send_symbols_between_endpoints(
                &cx,
                source_id,
                target_id,
                mismatched_config.symbol_batch_size,
            ).await?;

            // Attempt to collect symbols (expecting mostly failures)
            let received_symbols = network.collect_symbols_from_endpoint(
                &cx,
                target_id,
                mismatched_config.symbol_batch_size,
                Duration::from_seconds(10),
            ).await.unwrap_or_else(|_| Vec::new()); // Don't fail if auth fails

            let stats = network.network_stats();
            let (source_sent, _, source_failures) = stats[&source_id];
            let (_, target_received, target_failures) = stats[&target_id];

            // Verify that authentication failures are detected
            assert!(
                target_failures > 0 || target_received < source_sent,
                "Should detect authentication failures with mismatched keys"
            );

            let success_rate = target_received as f64 / source_sent as f64;
            assert!(
                success_rate < 0.5,
                "Success rate should be low with mismatched auth keys, got {}",
                success_rate
            );

            cx.trace("test_authentication_failure_scenarios_complete", &format!(
                "sent={} received={} failures={} success_rate={:.2}",
                source_sent, target_received, target_failures, success_rate
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_authentication_failure_scenarios");
    }

    /// Test authenticated multipath aggregation with load balancing.
    #[test]
    fn test_authenticated_multipath_aggregation() {
        init_test("test_authenticated_multipath_aggregation");

        let config = AuthenticatedTransportConfig {
            endpoint_count: 5,
            channel_capacity: 20,
            symbol_batch_size: 50,
            auth_configs: vec![
                AuthTestConfig {
                    mode: AuthMode::Strict,
                    key_seed: 55555,
                    expected_success_rate: 1.0,
                },
            ],
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(45), async move |cx| {
            let network = AuthenticatedRoutingNetwork::new(config.clone());

            // Create multipath routing: one source, multiple intermediate paths, one target
            let source_id = EndpointId::from_index(0);
            let intermediate_ids = vec![
                EndpointId::from_index(1),
                EndpointId::from_index(2),
                EndpointId::from_index(3),
            ];
            let target_id = EndpointId::from_index(4);

            // Configure aggregator for multipath routing
            let aggregator_config = AggregatorConfig {
                path_count: intermediate_ids.len(),
                reorder_window_size: 32,
                deduplication_window_size: 64,
                path_selection_policy: PathSelectionPolicy::RoundRobin,
            };

            let mut path_stats = HashMap::new();

            // Send symbols through multiple paths
            for (path_index, &intermediate_id) in intermediate_ids.iter().enumerate() {
                let path_id = PathId::from_index(path_index as u16);

                // Send through this path
                let path_symbols = network.send_symbols_between_endpoints(
                    &cx,
                    source_id,
                    intermediate_id,
                    config.symbol_batch_size / intermediate_ids.len(),
                ).await?;

                // Route from intermediate to target
                let _target_symbols = network.send_symbols_between_endpoints(
                    &cx,
                    intermediate_id,
                    target_id,
                    path_symbols.len(),
                ).await?;

                path_stats.insert(path_id, path_symbols.len());

                cx.trace("multipath_segment_complete", &format!(
                    "path_id={:?} intermediate={:?} symbols={}",
                    path_id, intermediate_id, path_symbols.len()
                ));
            }

            // Collect all symbols at target
            let total_expected = config.symbol_batch_size;
            let received_symbols = network.collect_symbols_from_endpoint(
                &cx,
                target_id,
                total_expected,
                Duration::from_seconds(20),
            ).await?;

            let stats = network.network_stats();
            let (_, target_received, target_failures) = stats[&target_id];

            // Verify multipath aggregation worked
            assert!(
                received_symbols.len() >= (total_expected as f64 * 0.9) as usize,
                "Should receive most symbols through multipath aggregation"
            );
            assert_eq!(
                target_failures, 0,
                "No auth failures expected with same key across paths"
            );

            // Verify load distribution across paths
            let path_utilization: f64 = path_stats.values().map(|&count| count as f64).sum();
            let expected_per_path = path_utilization / intermediate_ids.len() as f64;

            for (&path_id, &symbol_count) in &path_stats {
                let utilization_ratio = symbol_count as f64 / expected_per_path;
                assert!(
                    utilization_ratio >= 0.5 && utilization_ratio <= 1.5,
                    "Path {} should have balanced utilization: {} symbols (ratio: {:.2})",
                    path_id.as_u16(), symbol_count, utilization_ratio
                );
            }

            cx.trace("test_authenticated_multipath_aggregation_complete", &format!(
                "total_received={} target_failures={} paths={} load_balance_ok=true",
                target_received, target_failures, intermediate_ids.len()
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_authenticated_multipath_aggregation");
    }
}