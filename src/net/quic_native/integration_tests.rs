//! Integration tests for ATP native QUIC endpoint with connection routing and timer integration.
//!
//! These tests verify that the complete system works together:
//! - UDP packet I/O
//! - Connection-ID routing
//! - Timer scheduling
//! - Connection lifecycle management

#[cfg(test)]
mod tests {
    use crate::net::quic_native::{
        ConnectionRouter, ManagedEndpointConfig, ManagedQuicEndpoint, NativeQuicConnectionConfig,
        QuicTimerScheduler,
    };
    use crate::test_utils::run_test_with_cx;
    use std::net::SocketAddr;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn test_managed_endpoint_basic_lifecycle() {
        run_test_with_cx(|cx| async move {
            // Create server endpoint
            let server_config = ManagedEndpointConfig {
                is_server: true,
                max_connections: 10,
                ..ManagedEndpointConfig::default()
            };

            let mut server =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), server_config)
                    .await
                    .expect("server bind should succeed");

            let _server_addr = server.local_addr();

            // Create client endpoint
            let client_config = ManagedEndpointConfig {
                is_server: false,
                max_connections: 5,
                ..ManagedEndpointConfig::default()
            };

            let mut client =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), client_config)
                    .await
                    .expect("client bind should succeed");

            // Verify initial state
            let server_stats = server.connection_stats();
            assert_eq!(server_stats.active_connections, 0);
            assert_eq!(server_stats.established_connections, 0);

            let client_stats = client.connection_stats();
            assert_eq!(client_stats.active_connections, 0);

            // Test graceful shutdown
            server
                .shutdown(&cx)
                .await
                .expect("server shutdown should succeed");
            client
                .shutdown(&cx)
                .await
                .expect("client shutdown should succeed");
        });
    }

    #[test]
    fn test_connection_router_with_timer_integration() {
        run_test_with_cx(|cx| async move {
            let connection_config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(connection_config);

            // Initially no connections
            assert_eq!(router.connection_stats().active_connections, 0);
            assert_eq!(router.next_timer_deadline(), None);

            // Create a connection
            let connection_id = router.allocate_connection_id();
            let peer_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();

            router
                .create_connection(&cx, connection_id, peer_addr, true)
                .await
                .expect("connection creation should succeed");

            // Verify connection was created
            let stats = router.connection_stats();
            assert_eq!(stats.active_connections, 1);
            assert_eq!(stats.pending_connections, 1); // Not established yet

            // Process timer events (no timers scheduled yet)
            let now = Instant::now();
            let packets = router
                .process_timer_events(&cx, now)
                .await
                .expect("timer processing should succeed");
            assert!(packets.is_empty());

            // Remove connection
            router
                .remove_connection(&cx, connection_id)
                .expect("connection removal should succeed");

            assert_eq!(router.connection_stats().active_connections, 0);
        });
    }

    #[test]
    fn test_timer_scheduler_deadline_management() {
        run_test_with_cx(|cx| async move {
            let mut scheduler = QuicTimerScheduler::new();

            // No timer initially
            assert!(!scheduler.has_pending_timer());
            assert_eq!(scheduler.current_deadline(), None);

            // Schedule a timer
            let deadline1 = Instant::now() + Duration::from_millis(100);
            scheduler
                .schedule_timer(&cx, deadline1)
                .await
                .expect("timer scheduling should succeed");

            assert!(scheduler.has_pending_timer());
            assert_eq!(scheduler.current_deadline(), Some(deadline1));

            // Schedule an earlier timer (should reschedule)
            let deadline2 = Instant::now() + Duration::from_millis(50);
            scheduler
                .schedule_timer(&cx, deadline2)
                .await
                .expect("timer rescheduling should succeed");

            assert!(scheduler.has_pending_timer());
            assert_eq!(scheduler.current_deadline(), Some(deadline2));

            // Schedule a later timer (should not reschedule)
            let deadline3 = Instant::now() + Duration::from_millis(200);
            scheduler
                .schedule_timer(&cx, deadline3)
                .await
                .expect("timer scheduling should succeed");

            // Should still have the earlier deadline
            assert_eq!(scheduler.current_deadline(), Some(deadline2));
        });
    }

    #[test]
    fn test_endpoint_configuration_validation() {
        run_test_with_cx(|cx| async move {
            // Test various invalid configurations
            let test_cases = vec![
                // max_connections = 0
                ManagedEndpointConfig {
                    max_connections: 0,
                    ..ManagedEndpointConfig::default()
                },
                // packet_batch_size = 0
                ManagedEndpointConfig {
                    packet_batch_size: 0,
                    ..ManagedEndpointConfig::default()
                },
            ];

            for config in test_cases {
                let result =
                    ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
                assert!(result.is_err(), "Expected configuration validation to fail");
            }

            // Valid configuration should succeed
            let valid_config = ManagedEndpointConfig::default();
            let endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), valid_config)
                    .await
                    .expect("valid configuration should succeed");

            assert_ne!(endpoint.local_addr().port(), 0);
        });
    }

    #[test]
    fn test_endpoint_stats_and_metrics() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig {
                max_connections: 100,
                packet_batch_size: 16,
                is_server: true,
                ..ManagedEndpointConfig::default()
            };

            let endpoint = ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("endpoint creation should succeed");

            // Verify initial metrics
            let stats = endpoint.connection_stats();
            assert_eq!(stats.active_connections, 0);
            assert_eq!(stats.established_connections, 0);
            assert_eq!(stats.pending_connections, 0);

            // Verify endpoint properties
            assert!(endpoint.endpoint_id() > 0);
            let addr = endpoint.local_addr();
            assert_eq!(addr.ip().to_string(), "127.0.0.1");
            assert!(addr.port() > 0);
        });
    }

    #[test]
    fn test_connection_id_routing_behavior() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);

            // Test connection ID allocation uniqueness
            let mut allocated_ids = std::collections::HashSet::new();
            for _ in 0..10 {
                let id = router.allocate_connection_id();
                assert!(allocated_ids.insert(id), "Connection IDs should be unique");
            }

            // Test connection creation with specific IDs
            for id in &allocated_ids {
                let peer_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
                router
                    .create_connection(&cx, *id, peer_addr, false)
                    .await
                    .expect("connection creation should succeed");
            }

            // Verify all connections were created
            let stats = router.connection_stats();
            assert_eq!(stats.active_connections, allocated_ids.len());

            // Clean up
            for id in allocated_ids {
                router
                    .remove_connection(&cx, id)
                    .expect("connection removal should succeed");
            }

            assert_eq!(router.connection_stats().active_connections, 0);
        });
    }

    #[test]
    fn test_integration_with_real_socket_addresses() {
        run_test_with_cx(|cx| async move {
            // Test with IPv4
            let ipv4_config = ManagedEndpointConfig::default();
            let ipv4_endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), ipv4_config)
                    .await
                    .expect("IPv4 endpoint should bind successfully");

            assert!(ipv4_endpoint.local_addr().is_ipv4());

            // Test with IPv6 (if available)
            let ipv6_config = ManagedEndpointConfig::default();
            if let Ok(ipv6_endpoint) =
                ManagedQuicEndpoint::bind(&cx, "[::1]:0".parse().unwrap(), ipv6_config).await
            {
                assert!(ipv6_endpoint.local_addr().is_ipv6());
            }
            // If IPv6 fails, that's acceptable on some systems

            // Test different ports
            let specific_port = 19841; // Choose an uncommon port
            let port_config = ManagedEndpointConfig::default();

            // Note: This might fail if port is in use, which is acceptable
            if let Ok(port_endpoint) = ManagedQuicEndpoint::bind(
                &cx,
                format!("127.0.0.1:{specific_port}").parse().unwrap(),
                port_config,
            )
            .await
            {
                assert_eq!(port_endpoint.local_addr().port(), specific_port);
            }
        });
    }
}
