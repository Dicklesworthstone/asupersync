    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::network::{JitterModel, LatencyModel, NetworkConfig};
    use std::collections::BTreeMap;

    #[test]
    fn deterministic_delivery_same_seed() {
        let config = NetworkConfig {
            seed: 123,
            ..Default::default()
        };
        let mut net1 = DeterministicNetwork::new(config.clone());
        let mut net2 = DeterministicNetwork::new(config);

        let a1 = net1.add_host("a");
        let b1 = net1.add_host("b");
        let a2 = net2.add_host("a");
        let b2 = net2.add_host("b");

        let payload = Bytes::copy_from_slice(b"hello");
        for _ in 0..10 {
            net1.send(a1, b1, payload.clone());
            net2.send(a2, b2, payload.clone());
        }

        net1.run_until_idle();
        net2.run_until_idle();

        let inbox1 = net1.inbox(b1).unwrap();
        let inbox2 = net2.inbox(b2).unwrap();
        assert_eq!(inbox1.len(), inbox2.len());
        for (p1, p2) in inbox1.iter().zip(inbox2.iter()) {
            assert_eq!(p1.received_at, p2.received_at);
            assert_eq!(p1.payload[..], p2.payload[..]);
        }
    }

    #[test]
    fn multiple_hosts_receive() {
        let mut net = DeterministicNetwork::new(NetworkConfig::default());
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");
        let h3 = net.add_host("h3");

        net.send(h1, h2, Bytes::copy_from_slice(b"one"));
        net.send(h1, h3, Bytes::copy_from_slice(b"two"));
        net.run_until_idle();

        assert_eq!(net.inbox(h2).unwrap().len(), 1);
        assert_eq!(net.inbox(h3).unwrap().len(), 1);
    }

    #[test]
    fn fixed_latency_respected() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Fixed(Duration::from_millis(10)),
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"delay"));
        net.run_for(Duration::from_millis(9));
        assert!(net.inbox(h2).unwrap().is_empty());

        net.run_for(Duration::from_millis(1));
        assert_eq!(net.inbox(h2).unwrap().len(), 1);
    }

    #[test]
    fn uniform_latency_within_bounds() {
        let min = Duration::from_millis(5);
        let max = Duration::from_millis(15);
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Uniform { min, max },
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        for _ in 0..50 {
            net.send(h1, h2, Bytes::copy_from_slice(b"x"));
        }
        net.run_until_idle();

        for packet in net.inbox(h2).unwrap() {
            let nanos = packet.received_at.duration_since(packet.sent_at);
            let latency = Duration::from_nanos(nanos);
            assert!(latency >= min && latency <= max);
        }
    }

    #[test]
    fn packet_loss_drops_all() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                packet_loss: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"drop"));
        net.run_until_idle();

        assert!(net.inbox(h2).unwrap().is_empty());
        assert_eq!(net.metrics().packets_dropped, 1);
    }

    #[test]
    fn packet_corruption_marks_payload() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                packet_corrupt: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        let payload = Bytes::copy_from_slice(&[0b0000_0001]);
        net.send(h1, h2, payload.clone());
        net.run_until_idle();

        let packet = &net.inbox(h2).unwrap()[0];
        assert!(packet.corrupted);
        assert_ne!(packet.payload[..], payload[..]);
        assert_eq!(net.metrics().packets_corrupted, 1);
    }

    #[test]
    fn bandwidth_limiting_spaces_packets() {
        let config = NetworkConfig {
            enable_bandwidth: true,
            default_bandwidth: 1_000,
            default_conditions: NetworkConditions::ideal(),
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        let payload = Bytes::copy_from_slice(&vec![0u8; 1000]);
        net.send(h1, h2, payload.clone());
        net.send(h1, h2, payload);
        net.run_until_idle();

        let inbox = net.inbox(h2).unwrap();
        assert_eq!(inbox.len(), 2);
        assert_eq!(inbox[0].received_at.as_nanos(), 1_000_000_000);
        assert_eq!(inbox[1].received_at.as_nanos(), 2_000_000_000);
    }

    #[test]
    fn max_in_flight_limits_enforced() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Fixed(Duration::from_millis(10)),
                max_in_flight: 1,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"first"));
        net.send(h1, h2, Bytes::copy_from_slice(b"second"));
        net.run_until_idle();

        let inbox = net.inbox(h2).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(net.metrics().packets_dropped, 1);
    }

    #[test]
    fn trace_capture_records_events() {
        let config = NetworkConfig {
            capture_trace: true,
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"trace"));
        net.run_until_idle();

        let trace = net.trace();
        assert!(trace.iter().any(|e| e.kind == NetworkTraceKind::Send));
        assert!(trace.iter().any(|e| e.kind == NetworkTraceKind::Deliver));
    }

    #[test]
    fn host_crash_and_restart() {
        let mut net = DeterministicNetwork::new(NetworkConfig::default());
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"first"));
        net.run_until_idle();
        assert_eq!(net.inbox(h2).unwrap().len(), 1);

        net.inject_fault(&Fault::HostCrash { host: h2 });
        net.send(h1, h2, Bytes::copy_from_slice(b"drop"));
        net.run_until_idle();
        assert!(net.inbox(h2).unwrap().is_empty());

        net.inject_fault(&Fault::HostRestart { host: h2 });
        net.send(h1, h2, Bytes::copy_from_slice(b"after"));
        net.run_until_idle();
        assert_eq!(net.inbox(h2).unwrap().len(), 1);
    }

    #[test]
    fn host_crash_drops_in_flight_packets_even_after_restart() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Fixed(Duration::from_millis(10)),
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"in-flight"));
        net.inject_fault(&Fault::HostCrash { host: h2 });
        net.inject_fault(&Fault::HostRestart { host: h2 });
        net.run_until_idle();

        assert!(net.inbox(h2).unwrap().is_empty());
        assert_eq!(net.metrics().packets_dropped, 1);
    }

    #[test]
    fn dropped_in_flight_packets_do_not_consume_future_bandwidth() {
        let config = NetworkConfig {
            enable_bandwidth: true,
            default_bandwidth: 1_000,
            default_conditions: NetworkConditions::ideal(),
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");
        let payload = Bytes::copy_from_slice(&vec![0u8; 1_000]);

        net.send(h1, h2, payload.clone());
        net.inject_fault(&Fault::HostCrash { host: h2 });
        net.inject_fault(&Fault::HostRestart { host: h2 });
        net.send(h1, h2, payload);
        net.run_until_idle();

        let inbox = net.inbox(h2).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].received_at.as_nanos(), 1_000_000_000);
    }

    #[test]
    fn partition_drops_packets() {
        let mut net = DeterministicNetwork::new(NetworkConfig::default());
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.inject_fault(&Fault::Partition {
            hosts_a: vec![h1],
            hosts_b: vec![h2],
        });

        net.send(h1, h2, Bytes::copy_from_slice(b"drop"));
        net.run_for(Duration::from_millis(10));

        assert!(net.inbox(h2).unwrap().is_empty());
        assert_eq!(net.metrics().packets_dropped, 1);
    }

    #[test]
    fn packet_duplication_delivers_twice() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                packet_duplicate: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"dup"));
        net.run_until_idle();

        let inbox = net.inbox(h2).unwrap();
        assert_eq!(inbox.len(), 2);
        assert_eq!(net.metrics().packets_duplicated, 1);
    }

    #[test]
    fn reorder_trace_records_event() {
        let config = NetworkConfig {
            capture_trace: true,
            default_conditions: NetworkConditions {
                packet_reorder: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"reorder"));
        net.run_until_idle();

        let trace = net.trace();
        assert!(trace.iter().any(|e| e.kind == NetworkTraceKind::Reorder));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let max = Duration::from_millis(5);
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Fixed(Duration::ZERO),
                jitter: Some(JitterModel::Uniform { max }),
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = DeterministicNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        for _ in 0..10 {
            net.send(h1, h2, Bytes::copy_from_slice(b"j"));
        }
        net.run_until_idle();

        for packet in net.inbox(h2).unwrap() {
            let nanos = packet.received_at.duration_since(packet.sent_at);
            let jitter = Duration::from_nanos(nanos);
            assert!(jitter <= max);
        }
    }

    // Pure data-type tests (wave 35 – CyanBarn)

    #[test]
    fn host_id_debug_copy_ord_hash() {
        use std::collections::HashSet;
        let h1 = HostId::new(1);
        let h2 = HostId::new(2);
        let h3 = HostId::new(1);

        let dbg = format!("{h1:?}");
        assert!(dbg.contains("HostId"));

        // Copy
        let h1_copy = h1;
        assert_eq!(h1, h1_copy);

        // Ord
        assert!(h1 < h2);
        assert_eq!(h1.cmp(&h3), std::cmp::Ordering::Equal);

        // Hash
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2);
        set.insert(h3); // duplicate of h1
        assert_eq!(set.len(), 2);

        // raw accessor
        assert_eq!(h1.raw(), 1);
        assert_eq!(h2.raw(), 2);
    }

    #[test]
    fn packet_debug_clone() {
        let pkt = Packet {
            src: HostId::new(1),
            dst: HostId::new(2),
            payload: Bytes::copy_from_slice(b"test"),
            sent_at: Time::ZERO,
            received_at: Time::from_nanos(1000),
            corrupted: false,
        };
        let dbg = format!("{pkt:?}");
        assert!(dbg.contains("Packet"));

        let cloned = pkt;
        assert_eq!(cloned.src, HostId::new(1));
        assert_eq!(cloned.dst, HostId::new(2));
        assert!(!cloned.corrupted);
    }

    #[test]
    fn fault_debug_clone() {
        let partition = Fault::Partition {
            hosts_a: vec![HostId::new(1)],
            hosts_b: vec![HostId::new(2)],
        };
        let dbg = format!("{partition:?}");
        assert!(dbg.contains("Partition"));
        let cloned = partition;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);

        let crash = Fault::HostCrash {
            host: HostId::new(5),
        };
        let dbg = format!("{crash:?}");
        assert!(dbg.contains("HostCrash"));
    }

    #[test]
    fn network_metrics_debug_default_clone() {
        let metrics = NetworkMetrics::default();
        assert_eq!(metrics.packets_sent, 0);
        assert_eq!(metrics.packets_delivered, 0);
        assert_eq!(metrics.packets_dropped, 0);
        assert_eq!(metrics.packets_duplicated, 0);
        assert_eq!(metrics.packets_corrupted, 0);

        let dbg = format!("{metrics:?}");
        assert!(dbg.contains("NetworkMetrics"));

        let cloned = metrics;
        assert_eq!(cloned.packets_sent, 0);
    }

    #[test]
    fn network_trace_event_debug_clone() {
        let event = NetworkTraceEvent {
            time: Time::from_nanos(500),
            kind: NetworkTraceKind::Send,
            src: HostId::new(1),
            dst: HostId::new(2),
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("NetworkTraceEvent"));

        let cloned = event;
        assert_eq!(cloned.kind, NetworkTraceKind::Send);
        assert_eq!(cloned.src, HostId::new(1));
    }

    #[test]
    fn network_trace_kind_debug_copy_eq() {
        let kinds = [
            NetworkTraceKind::Send,
            NetworkTraceKind::Deliver,
            NetworkTraceKind::Drop,
            NetworkTraceKind::Duplicate,
            NetworkTraceKind::Reorder,
        ];
        for kind in &kinds {
            let dbg = format!("{kind:?}");
            assert!(!dbg.is_empty());

            // Copy
            let copy = *kind;
            assert_eq!(*kind, copy);
        }

        // Distinct variants
        assert_ne!(NetworkTraceKind::Send, NetworkTraceKind::Deliver);
        assert_ne!(NetworkTraceKind::Drop, NetworkTraceKind::Duplicate);
    }

    #[test]
    fn topology_snapshot_scrubbed() {
        let mut net = DeterministicNetwork::new(NetworkConfig::default());
        let h1 = net.add_host("alpha");
        let h2 = net.add_host("beta");
        let h3 = net.add_host("gamma");

        net.inject_fault(&Fault::Partition {
            hosts_a: vec![h1],
            hosts_b: vec![h2, h3],
        });

        let mut host_labels = BTreeMap::new();
        for (index, host_id) in [h1, h2, h3].into_iter().enumerate() {
            host_labels.insert(host_id, format!("HOST_{}", index + 1));
        }

        let mut hosts = net
            .hosts
            .iter()
            .map(|(host_id, host)| {
                serde_json::json!({
                    "host": host_labels.get(host_id).expect("scrub host label"),
                    "crashed": host.crashed,
                    "inbox_len": host.inbox.len(),
                })
            })
            .collect::<Vec<_>>();
        hosts.sort_by(|left, right| left["host"].as_str().cmp(&right["host"].as_str()));

        let mut partitions = net
            .partitions
            .iter()
            .map(|link| {
                serde_json::json!({
                    "src": host_labels.get(&link.src).expect("scrub src label"),
                    "dst": host_labels.get(&link.dst).expect("scrub dst label"),
                })
            })
            .collect::<Vec<_>>();
        partitions.sort_by(|left, right| {
            left["src"]
                .as_str()
                .cmp(&right["src"].as_str())
                .then_with(|| left["dst"].as_str().cmp(&right["dst"].as_str()))
        });

        let snapshot = serde_json::json!({
            "hosts": hosts,
            "partitions": partitions,
            "metrics": {
                "sent": net.metrics.packets_sent,
                "delivered": net.metrics.packets_delivered,
                "dropped": net.metrics.packets_dropped,
            },
            "queue_depth": net.queue.len(),
        });

        insta::assert_json_snapshot!("topology_scrubbed", snapshot);
    }
