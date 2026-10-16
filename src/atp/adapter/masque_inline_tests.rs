    use super::*;
    use futures_lite::future::block_on;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_masque_adapter_creation() {
        let config = MasqueConfig::default();
        let adapter = MasqueAdapter::new(config);

        assert_eq!(adapter.stats.active_tunnels, 0);
        assert_eq!(adapter.stats.total_tunnels_created, 0);
        assert!(adapter.tunnels.is_empty());
    }

    #[test]
    fn test_tunnel_establishment() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

            assert!(!tunnel_id.is_empty());
            assert_eq!(adapter.stats.active_tunnels, 1);
            assert_eq!(adapter.stats.total_tunnels_created, 1);
            assert!(adapter.tunnels.contains_key(&tunnel_id));
        });
    }

    #[test]
    fn test_datagram_size_limits() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig {
                max_datagram_size: 1000,
                ..Default::default()
            });
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

            // Test payload within limits
            let small_payload = vec![0u8; 500];
            assert!(
                adapter
                    .send_datagram(&cx, &tunnel_id, &small_payload)
                    .await
                    .is_ok()
            );

            // Test payload exceeding limits
            let large_payload = vec![0u8; 1500];
            let result = adapter.send_datagram(&cx, &tunnel_id, &large_payload).await;
            assert!(matches!(result, Err(MasqueError::DatagramTooLarge { .. })));
        });
    }

    #[test]
    fn test_tunnel_lifecycle() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

            // Establish tunnel
            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();
            assert_eq!(adapter.stats.active_tunnels, 1);

            // Send some data
            let payload = vec![0u8; 100];
            adapter
                .send_datagram(&cx, &tunnel_id, &payload)
                .await
                .unwrap();

            // Close tunnel
            adapter.close_tunnel(&cx, &tunnel_id).await.unwrap();
            assert_eq!(adapter.stats.active_tunnels, 0);
            assert_eq!(adapter.stats.total_tunnels_closed, 1);
            assert!(!adapter.tunnels.contains_key(&tunnel_id));
        });
    }

    #[test]
    fn test_tunnel_not_found_error() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();

            let result = adapter.send_datagram(&cx, "nonexistent", &[]).await;
            assert!(matches!(result, Err(MasqueError::TunnelNotFound { .. })));
        });
    }

    #[test]
    fn test_health_check() {
        block_on(async {
            let adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();

            let health = adapter.health_check(&cx).await.unwrap();

            assert!(health.proxy_reachable);
            assert!(!health.auth_valid); // No auth configured in default
            assert!(health.avg_latency > Duration::ZERO);
            assert_eq!(health.active_tunnels, 0);
        });
    }

    #[test]
    fn test_overhead_tracking() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

            // Send data and verify overhead tracking
            let payload = vec![0u8; 1000];
            adapter
                .send_datagram(&cx, &tunnel_id, &payload)
                .await
                .unwrap();

            assert!(adapter.stats.total_payload_bytes > 0);
            assert!(adapter.stats.total_overhead_bytes > 0);
            assert!(adapter.stats.current_overhead_ratio > 0.0);
            assert!(adapter.stats.current_overhead_ratio < 1.0);
        });
    }

    #[test]
    fn test_receive_reads_queued_proxy_datagram() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();
            let inbound = vec![1, 2, 3, 4, 5];

            adapter
                .queue_inbound_datagram(&tunnel_id, inbound.clone())
                .unwrap();
            let received = adapter.receive_datagram(&cx, &tunnel_id).await.unwrap();

            assert_eq!(received, inbound);
            assert!(adapter.stats.total_payload_bytes >= 5);
        });
    }

    #[test]
    fn test_receive_reports_empty_tunnel_queue() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

            let result = adapter.receive_datagram(&cx, &tunnel_id).await;

            assert!(matches!(
                result,
                Err(MasqueError::NoDatagramAvailable { .. })
            ));
        });
    }

    #[test]
    fn test_authentication_config() {
        block_on(async {
            let config = MasqueConfig {
                proxy_auth: Some(MasqueAuth::Bearer {
                    token: "test-token".to_string(),
                }),
                ..Default::default()
            };

            let adapter = MasqueAdapter::new(config);
            let cx = Cx::for_testing();

            let health = adapter.health_check(&cx).await.unwrap();
            assert!(health.auth_valid);
        });
    }
