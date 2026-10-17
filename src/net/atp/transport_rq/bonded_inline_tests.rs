    use super::*;
    use crate::lab::{LabRuntime, assert_deterministic_for_seeds};
    use crate::net::atp::bonding::BondedBlockCompletionPath;
    use crate::net::{LabAtpUdpNetwork, LabUdpLinkPolicy, LabUdpLinkStats};
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;
    use std::num::NonZeroU64;
    use std::sync::mpsc;
    use std::thread;

    fn bonded_e2e_tmp(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!(
            "atp_rq_bonded_{label}_{}_{nanos}",
            std::process::id()
        ))
    }

    fn bonded_e2e_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
            .collect()
    }

    /// Small blocks keep per-block K tiny so debug-build RaptorQ decode stays
    /// fast while still exercising real multi-block routing (mirrors the
    /// single-source loopback e2e configs).
    fn bonded_lab_config() -> RqConfig {
        RqConfig {
            max_block_size: 64 * 1024,
            round_tail_drain: Duration::from_millis(5),
            accept_timeout: Duration::from_secs(30),
            ..RqConfig::default()
        }
        .allow_unauthenticated_for_trusted_transport()
    }

    fn bonded_auth_config() -> RqConfig {
        RqConfig {
            max_block_size: 64 * 1024,
            round_tail_drain: Duration::from_millis(5),
            accept_timeout: Duration::from_secs(30),
            ..RqConfig::default()
        }
        .with_symbol_auth(SecurityContext::for_testing(214))
    }

    #[test]
    fn wrong_key_datagram_is_counted_without_poisoning_authenticated_admission() {
        let verifier = SecurityContext::for_testing(214);
        let wrong_signer = SecurityContext::for_testing(215);
        let object_id = ObjectId::new_for_test(91);
        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 5),
            vec![0x5a; 16],
            SymbolKind::Source,
        );
        let tag = 0xfeed_beef_dead_cafe;
        let wrong = wrong_signer.sign_symbol(&symbol);
        let wrong_datagram = encode_symbol_datagram(tag, 0, &symbol, Some(wrong.tag()));
        let blocks = BTreeMap::new();
        let mut symbol_set = BondedReceiverSymbolSet::new();

        let (rejected, admitted) = admit_bonded_datagram(
            &wrong_datagram,
            wrong_datagram.len(),
            tag,
            Some(&verifier),
            3,
            &blocks,
            &mut symbol_set,
            BondedReceiverRetentionPolicy::unbounded(),
            16,
            |_| Some((0, object_id)),
        );

        assert!(
            !rejected.observed,
            "auth rejection is not liveness progress"
        );
        assert!(!rejected.accepted);
        assert!(admitted.is_none());
        assert_eq!(symbol_set.auth_rejected_symbols(2), 1);
        assert!(
            symbol_set.is_empty(),
            "rejection must not poison dedup state"
        );
        assert_eq!(
            symbol_set.aggregate_stats(),
            crate::net::atp::bonding::BondedReceiverIngressStats::default()
        );
        assert!(symbol_set.donor_targets().is_empty());

        let correct = verifier.sign_symbol(&symbol);
        let correct_datagram = encode_symbol_datagram(tag, 0, &symbol, Some(correct.tag()));
        let (accepted, admitted) = admit_bonded_datagram(
            &correct_datagram,
            correct_datagram.len(),
            tag,
            Some(&verifier),
            3,
            &blocks,
            &mut symbol_set,
            BondedReceiverRetentionPolicy::unbounded(),
            16,
            |_| Some((0, object_id)),
        );

        assert!(accepted.observed);
        assert!(accepted.accepted);
        assert!(admitted.is_some());
        assert_eq!(symbol_set.auth_rejected_symbols(2), 1);
        assert_eq!(symbol_set.len(), 1);
        assert_eq!(symbol_set.aggregate_stats().symbols_accepted, 1);
    }

    #[test]
    fn bonded_receiver_advertisement_is_explicit_bounded_and_bind_compatible() {
        let wildcard: std::net::IpAddr = "0.0.0.0".parse().expect("wildcard IP");
        let direct: std::net::IpAddr = "198.18.0.1".parse().expect("direct IP");
        let tailnet: std::net::IpAddr = "100.101.102.103".parse().expect("tailnet IP");
        assert_eq!(
            validate_bonded_advertised_udp_ips(wildcard, &[direct, tailnet, direct])
                .expect("valid explicit advertisement"),
            vec![direct, tailnet],
            "receiver advertisement must retain deterministic first occurrence order"
        );

        let unspecified: std::net::IpAddr = "0.0.0.0".parse().expect("unspecified IP");
        assert!(matches!(
            validate_bonded_advertised_udp_ips(wildcard, &[unspecified]),
            Err(RqError::Source(message))
                if message.contains("must not contain an unspecified IP")
        ));
        assert_eq!(
            validate_bonded_advertised_udp_ips(direct, &[tailnet])
                .expect("operator-authorized routed or NAT advertisement"),
            vec![tailnet]
        );
        let ipv6: std::net::IpAddr = "2001:db8::1".parse().expect("IPv6 address");
        assert!(matches!(
            validate_bonded_advertised_udp_ips(direct, &[ipv6]),
            Err(RqError::Source(message)) if message.contains("does not match bind address family")
        ));
    }

    #[test]
    fn bonded_receiver_endpoint_set_is_validated_before_donor_enrollment() {
        let duplicate: SocketAddr = "198.18.0.1:41001".parse().expect("duplicate endpoint");
        assert!(matches!(
            validate_bonded_receiver_udp_endpoints(&[duplicate, duplicate]),
            Err(RqError::HandshakeRejected(message)) if message.contains("duplicate")
        ));
        assert!(matches!(
            validate_bonded_receiver_udp_endpoints(&[
                "198.18.0.1:0".parse().expect("port-zero endpoint")
            ]),
            Err(RqError::HandshakeRejected(message)) if message.contains("port zero")
        ));
        assert!(matches!(
            validate_bonded_receiver_udp_endpoints(&[
                "239.1.2.3:41001".parse().expect("multicast endpoint")
            ]),
            Err(RqError::HandshakeRejected(message)) if message.contains("non-unicast")
        ));

        let oversized = (0..=MAX_BONDING_RECEIVER_ENDPOINTS)
            .map(|index| {
                let port = u16::try_from(index + 1).expect("bounded test port");
                SocketAddr::new("198.18.0.1".parse().expect("direct IP"), port)
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            validate_bonded_receiver_udp_endpoints(&oversized),
            Err(RqError::HandshakeRejected(message)) if message.contains("max 1024")
        ));
    }

    #[test]
    fn bonded_donor_selects_control_affine_ip_and_keeps_its_fanout_ports() {
        let control: SocketAddr = "198.18.0.1:8473".parse().expect("control address");
        let assignment = DonorAssignment::new_static(
            0,
            1,
            vec![
                "192.0.2.99:41001".parse().expect("decoy endpoint"),
                "198.18.0.1:41001".parse().expect("direct endpoint one"),
                "198.18.0.1:41002".parse().expect("direct endpoint two"),
            ],
            None,
        );
        assert_eq!(
            select_bonded_receiver_udp_path(&assignment, &[49999], control)
                .expect("control-affine direct path"),
            vec![
                "198.18.0.1:41001".parse().expect("selected endpoint one"),
                "198.18.0.1:41002".parse().expect("selected endpoint two"),
            ],
            "one chosen IP path must retain all of that path's UDP fanout ports"
        );

        let no_matching_path = DonorAssignment::new_static(
            0,
            1,
            vec!["192.0.2.99:41001".parse().expect("unreachable endpoint")],
            None,
        );
        assert!(matches!(
            select_bonded_receiver_udp_path(&no_matching_path, &[41001], control),
            Err(RqError::HandshakeRejected(message))
                if message.contains("no receiver UDP path for connected control IP")
        ));

        let legacy = DonorAssignment::new_static(
            0,
            1,
            vec!["0.0.0.0:41001".parse().expect("legacy wildcard")],
            None,
        );
        assert_eq!(
            select_bonded_receiver_udp_path(&legacy, &[41001, 41002], control)
                .expect("legacy control-IP fallback"),
            vec![
                "198.18.0.1:41001".parse().expect("legacy endpoint one"),
                "198.18.0.1:41002".parse().expect("legacy endpoint two"),
            ]
        );
    }

    #[derive(Debug, Clone, Copy)]
    struct LabBondedScenario {
        donor_count: u32,
        stopped_donor: Option<(u32, u64)>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct LabDonorSendObservation {
        emitted: u64,
        planned: u64,
        stopped_early: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct LabBondedDatagramObservation {
        decoded: Vec<u8>,
        donor_ingress: Vec<BondedDonorIngressStats>,
        donor_links: Vec<LabUdpLinkStats>,
        donor_sends: Vec<LabDonorSendObservation>,
        source_symbols_required: u64,
        source_symbols_accepted: u64,
        repair_symbols_accepted: u64,
        completion_path: BondedBlockCompletionPath,
        missing_source_esis: Vec<u32>,
        deficit_symbols: u32,
        decoder_pipeline_released: bool,
        bytes_written_before_late_source: u64,
        bytes_written_after_late_source: u64,
        final_bytes_written: u64,
        late_source_observed: bool,
        late_source_accepted: bool,
        staging_unchanged_after_late_source: bool,
        first_receive_parked: bool,
        virtual_time_nanos: u64,
    }

    fn lab_bonded_descriptor(
        payload: &[u8],
        config: &RqConfig,
        donor_count: u32,
    ) -> BondTransferDescriptor {
        let size = u64::try_from(payload.len()).expect("lab payload length fits u64");
        let content_sha256: [u8; 32] = Sha256::digest(payload).into();
        let digest = EntryDigest {
            rel_path: "payload.bin".to_string(),
            size,
            content_id: crate::atp::object::ObjectId::content(ContentId::from_bytes(payload)),
            content_sha256,
        };
        BondTransferDescriptor {
            transfer_id: format!("lab-bonded-n{donor_count}-loss-v1"),
            root_name: "payload.bin".to_string(),
            is_directory: false,
            total_bytes: size,
            merkle_root_hex: flat_merkle_root_from_digests(std::slice::from_ref(&digest)),
            metadata: None,
            entries: vec![crate::net::atp::bonding::BondEntry {
                index: 0,
                rel_path: digest.rel_path,
                size,
                sha256_hex: hex_encode(&content_sha256),
            }],
            symbol_size: config.symbol_size,
            max_block_size: u64::try_from(config.max_block_size).expect("lab block size fits u64"),
            auth_key_id: None,
        }
    }

    async fn send_lab_bonded_schedule(
        cx: Cx,
        descriptor: BondTransferDescriptor,
        assignment: DonorAssignment,
        payload: Vec<u8>,
        config: RqConfig,
        mut socket: crate::net::LabAtpUdpNetworkSocket,
        receiver: SocketAddr,
        stop_after: Option<u64>,
    ) -> Result<LabDonorSendObservation, String> {
        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 32)
            .map_err(|error| error.to_string())?;
        let planned = u64::try_from(schedule.total_symbol_count())
            .map_err(|_| "lab donor schedule length does not fit u64".to_string())?;
        let tag = transfer_tag(&descriptor.transfer_id);
        let mut sent = 0u64;
        for block in &schedule.blocks {
            let start = usize::try_from(block.geometry.block_start)
                .map_err(|_| "lab block start does not fit usize".to_string())?;
            let len = usize::try_from(block.geometry.block_bytes)
                .map_err(|_| "lab block length does not fit usize".to_string())?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| "lab block range overflow".to_string())?;
            let block_bytes = payload
                .get(start..end)
                .ok_or_else(|| "lab block range escapes payload".to_string())?;
            for emission in block.iter_symbol_emissions(schedule.donor_index) {
                if stop_after.is_some_and(|limit| sent >= limit) {
                    return Ok(LabDonorSendObservation {
                        emitted: sent,
                        planned,
                        stopped_early: true,
                    });
                }
                let symbol = encode_bonded_donor_emission(emission, block_bytes, &config)
                    .map_err(|error| error.to_string())?;
                let datagram =
                    encode_bonded_donor_datagram(tag, block.geometry.entry_index, &symbol, None);
                socket
                    .send_to(&cx, &datagram, receiver)
                    .await
                    .map_err(|error| error.to_string())?;
                sent = sent.saturating_add(1);
                crate::runtime::yield_now().await;
            }
        }
        Ok(LabDonorSendObservation {
            emitted: sent,
            planned,
            stopped_early: false,
        })
    }

    async fn run_lab_bonded_datagram_scenario(
        cx: Cx,
        scenario: LabBondedScenario,
    ) -> Result<LabBondedDatagramObservation, String> {
        if !(1..=3).contains(&scenario.donor_count) {
            return Err(format!(
                "lab bonded scenario supports one to three donors, got {}",
                scenario.donor_count
            ));
        }
        let payload = bonded_e2e_payload(7_169);
        let config = RqConfig {
            symbol_size: 256,
            max_block_size: 4_096,
            source_retransmit_rounds: 1,
            ..RqConfig::default()
        }
        .allow_unauthenticated_for_trusted_transport();
        let descriptor = lab_bonded_descriptor(&payload, &config, scenario.donor_count);
        descriptor.validate().map_err(|error| error.to_string())?;
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .ok_or_else(|| "lab descriptor has no source block".to_string())?;

        let network = LabAtpUdpNetwork::with_queue_capacity(256);
        let receiver_addr = SocketAddr::from(([127, 0, 0, 1], 41_000));
        let receiver_socket = network
            .bind(receiver_addr)
            .map_err(|error| error.to_string())?;
        let drop_periods = [5_u64, 7, 3];
        let mut donor_addrs = Vec::with_capacity(
            usize::try_from(scenario.donor_count).expect("lab donor count fits usize"),
        );
        let mut donor_handles = Vec::with_capacity(donor_addrs.capacity());
        for donor_index in 0..scenario.donor_count {
            let donor_port = 41_001_u16
                .checked_add(u16::try_from(donor_index).expect("lab donor index fits u16"))
                .expect("lab donor port does not overflow");
            let donor_addr = SocketAddr::from(([127, 0, 0, 1], donor_port));
            let donor_socket = network
                .bind(donor_addr)
                .map_err(|error| error.to_string())?;
            let drop_every = drop_periods
                .get(usize::try_from(donor_index).expect("lab donor index fits usize"))
                .copied()
                .and_then(NonZeroU64::new);
            network
                .set_source_policy(
                    donor_addr,
                    LabUdpLinkPolicy {
                        drop_every,
                        latency: Duration::ZERO,
                    },
                )
                .map_err(|error| error.to_string())?;
            donor_addrs.push(donor_addr);

            let assignment = DonorAssignment::new_static(
                donor_index,
                scenario.donor_count,
                vec![receiver_addr],
                None,
            );
            let stop_after = scenario
                .stopped_donor
                .and_then(|(stopped, limit)| (stopped == donor_index).then_some(limit));
            let handle = cx
                .spawn({
                    let descriptor = descriptor.clone();
                    let payload = payload.clone();
                    let config = config.clone();
                    move |donor_cx| {
                        send_lab_bonded_schedule(
                            donor_cx,
                            descriptor,
                            assignment,
                            payload,
                            config,
                            donor_socket,
                            receiver_addr,
                            stop_after,
                        )
                    }
                })
                .map_err(|error| error.to_string())?;
            donor_handles.push(handle);
        }

        let mut udp = RqReceiverUdpFanout::from_lab_sockets(vec![receiver_socket])
            .map_err(|error| error.to_string())?;
        let packet_size = usize::from(config.symbol_size) + AUTH_DGRAM_HEADER + 64;
        let mut first_receive_parked = false;
        let (_, mut first_batch) = std::future::poll_fn(|task_cx| {
            let poll = udp.poll_recv_batch_any(task_cx, RQ_INBOUND_PUMP_BATCH, packet_size);
            if poll.is_pending() {
                first_receive_parked = true;
                assert_eq!(network.has_receive_waiter(receiver_addr), Some(true));
            }
            poll
        })
        .await
        .map_err(|error| error.to_string())?;
        let mut packets = Vec::new();
        packets.append(&mut first_batch.packets);
        udp.recycle_recv_batch(&mut first_batch, RQ_INBOUND_PUMP_BATCH);

        let mut donor_sends = Vec::with_capacity(donor_handles.len());
        for mut donor in donor_handles {
            let sent = donor.join(&cx).await.map_err(|error| error.to_string())??;
            if sent.emitted == 0 {
                return Err("every lab donor must emit at least one symbol".to_string());
            }
            donor_sends.push(sent);
        }
        while network.queued_datagrams(receiver_addr).unwrap_or(0) > 0 {
            let (_, mut batch) = std::future::poll_fn(|task_cx| {
                udp.poll_recv_batch_any(task_cx, RQ_INBOUND_PUMP_BATCH, packet_size)
            })
            .await
            .map_err(|error| error.to_string())?;
            packets.append(&mut batch.packets);
            udp.recycle_recv_batch(&mut batch, RQ_INBOUND_PUMP_BATCH);
        }

        let manifest = manifest_from_bonded_descriptor(&descriptor);
        let source_streaming = config.repair_overhead <= 1.0 && config.source_retransmit_rounds > 0;
        if !source_streaming {
            return Err("lab bonded matrix must exercise source-streaming decode".to_string());
        }
        let staging_dir =
            bonded_e2e_tmp(&format!("lab_n{}_source_streaming", scenario.donor_count));
        let mut decoders = vec![new_bonded_entry_decoder(
            &manifest.entries[0],
            &manifest,
            &staging_dir,
            None,
            config.symbol_size,
            config.max_block_size,
            descriptor.max_block_size,
            &config,
            None,
            source_streaming,
        )];
        let blocks =
            bonded_block_states(&descriptor, &decoders, 32).map_err(|error| error.to_string())?;
        let mut symbol_set = BondedReceiverSymbolSet::new();
        let retention = BondedReceiverRetentionPolicy::bounded(128, 128);
        let tag = transfer_tag(&descriptor.transfer_id);
        let mut source_packets = Vec::new();
        let mut block_zero_repair_packets = Vec::new();
        let mut later_repair_packets = Vec::new();
        let mut late_source_packet = None;
        for packet in packets {
            let (parsed, _) =
                parse_symbol_datagram_payload(&packet.payload, packet.payload.len(), tag, false)
                    .ok_or_else(|| {
                        "lab network delivered an invalid bonded datagram".to_string()
                    })?;
            if parsed.kind.is_source() && parsed.sbn == 0 && parsed.esi == 10 {
                if late_source_packet.replace(packet).is_some() {
                    return Err("lab schedule emitted duplicate source ESI 10".to_string());
                }
            } else if parsed.kind.is_source() {
                source_packets.push(packet);
            } else if parsed.sbn == 0 {
                block_zero_repair_packets.push(packet);
            } else {
                later_repair_packets.push(packet);
            }
        }
        let late_source_packet = late_source_packet
            .ok_or_else(|| "lab loss schedule must deliver held source ESI 10".to_string())?;

        // Exercise the production bonded receiver seam, not a standalone
        // DecodingPipeline: source symbols persist through EntryDecoder, repair
        // symbols seed that same pipeline, and decoded bytes flow through the
        // E-9 accounting path in persist_decoded_block.
        for packet in source_packets {
            let ingest = feed_bonded_datagram_to_decoders(
                &cx,
                &packet.payload,
                packet.payload.len(),
                tag,
                None,
                scenario.donor_count,
                &blocks,
                &mut symbol_set,
                retention,
                &mut decoders,
                config.symbol_size,
            )
            .await
            .map_err(|error| error.to_string())?;
            if !ingest.observed || !ingest.accepted {
                return Err("production bonded intake rejected a source symbol".to_string());
            }
        }
        let _ = flush_and_seed_source_streaming_round_boundary(
            &cx,
            &mut decoders,
            config.symbol_size,
            None,
        )
        .await
        .map_err(|error| error.to_string())?;
        for packet in block_zero_repair_packets {
            let ingest = feed_bonded_datagram_to_decoders(
                &cx,
                &packet.payload,
                packet.payload.len(),
                tag,
                None,
                scenario.donor_count,
                &blocks,
                &mut symbol_set,
                retention,
                &mut decoders,
                config.symbol_size,
            )
            .await
            .map_err(|error| error.to_string())?;
            if !ingest.observed {
                return Err("production bonded intake did not observe a repair symbol".to_string());
            }
            if decoders[0].bytes_written == geometry.block_bytes {
                break;
            }
        }
        let _ = flush_and_seed_source_streaming_round_boundary(
            &cx,
            &mut decoders,
            config.symbol_size,
            None,
        )
        .await
        .map_err(|error| error.to_string())?;
        let decode_width_budget = rq_decode_width_budget_for_cx(&cx, &decoders, config.symbol_size);
        let _ = join_all_pending_decodes(&cx, &mut decoders, decode_width_budget)
            .await
            .map_err(|error| error.to_string())?;
        flush_cached_entry_staging_files(&mut decoders)
            .await
            .map_err(|error| error.to_string())?;
        if decoders[0].bytes_written != geometry.block_bytes {
            return Err(
                "production bonded EntryDecoder did not persist FEC-completed block zero"
                    .to_string(),
            );
        }
        if decoders[0].complete {
            return Err(
                "block zero completed the entry before the late-source E-9 probe".to_string(),
            );
        }

        let progress = symbol_set.block_progress_metrics(
            geometry.object_id,
            geometry.source_block_number,
            u32::from(geometry.source_symbols),
        );
        let block_source_symbols_accepted = u64::from(progress.source_symbols)
            .saturating_sub(u64::try_from(progress.missing_source_esis.len()).unwrap_or(u64::MAX));
        let aggregate = symbol_set.aggregate_stats();
        let donor_ingress = (0..scenario.donor_count)
            .map(|donor_index| {
                symbol_set
                    .donor_stats(donor_index)
                    .ok_or_else(|| format!("missing donor {donor_index} ingress stats"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bytes_written_before_late_source = decoders[0].bytes_written;
        let staging_path = decoders[0].staging_path.clone();
        let staging_before_late_source = std::fs::read(&staging_path)
            .map_err(|error| format!("read staging bytes before late source: {error}"))?;

        // Deliver every missing block-zero systematic symbol only after FEC
        // completed that block while block one keeps the entry open. ESI 10 is
        // the real datagram held above; symbols lost on the lab links are
        // rebuilt through the production encoder/wire format, exactly as a
        // source-first feedback retransmit would be. Before E-9, the final one
        // drove received_count to K and counted block zero a second time.
        let block_start = usize::try_from(geometry.block_start)
            .map_err(|_| "lab block start does not fit usize".to_string())?;
        let block_len = usize::try_from(geometry.block_bytes)
            .map_err(|_| "lab block length does not fit usize".to_string())?;
        let block_end = block_start
            .checked_add(block_len)
            .ok_or_else(|| "lab block range overflow".to_string())?;
        let block_bytes = payload
            .get(block_start..block_end)
            .ok_or_else(|| "lab block range escapes payload".to_string())?;
        let mut late_sources_observed = true;
        let mut late_source_accepted = false;
        for &esi in &progress.missing_source_esis {
            let datagram = if esi == 10 {
                late_source_packet.payload.clone()
            } else {
                let emission = crate::net::atp::bonding::BondedDonorSymbolEmission {
                    donor_index: esi % scenario.donor_count,
                    geometry,
                    esi,
                    kind: BondedDonorSymbolKind::Source,
                    stagger_delay_slots: 0,
                };
                let symbol = encode_bonded_donor_emission(emission, block_bytes, &config)
                    .map_err(|error| error.to_string())?;
                encode_symbol_datagram(tag, geometry.entry_index, &symbol, None)
            };
            let ingest = feed_bonded_datagram_to_decoders(
                &cx,
                &datagram,
                datagram.len(),
                tag,
                None,
                scenario.donor_count,
                &blocks,
                &mut symbol_set,
                retention,
                &mut decoders,
                config.symbol_size,
            )
            .await
            .map_err(|error| error.to_string())?;
            late_sources_observed &= ingest.observed;
            late_source_accepted |= ingest.accepted;
        }
        flush_cached_entry_staging_files(&mut decoders)
            .await
            .map_err(|error| error.to_string())?;
        let bytes_written_after_late_source = decoders[0].bytes_written;
        let staged_after_late_source = std::fs::read(&staging_path)
            .map_err(|error| format!("read staging bytes after late source: {error}"))?;
        let staging_unchanged_after_late_source =
            staged_after_late_source == staging_before_late_source;

        for packet in later_repair_packets {
            let ingest = feed_bonded_datagram_to_decoders(
                &cx,
                &packet.payload,
                packet.payload.len(),
                tag,
                None,
                scenario.donor_count,
                &blocks,
                &mut symbol_set,
                retention,
                &mut decoders,
                config.symbol_size,
            )
            .await
            .map_err(|error| error.to_string())?;
            if !ingest.observed {
                return Err(
                    "production bonded intake did not observe a later-block repair".to_string(),
                );
            }
            if decoders[0].complete {
                break;
            }
        }
        let _ = flush_and_seed_source_streaming_round_boundary(
            &cx,
            &mut decoders,
            config.symbol_size,
            None,
        )
        .await
        .map_err(|error| error.to_string())?;
        let decode_width_budget = rq_decode_width_budget_for_cx(&cx, &decoders, config.symbol_size);
        let _ = join_all_pending_decodes(&cx, &mut decoders, decode_width_budget)
            .await
            .map_err(|error| error.to_string())?;
        flush_cached_entry_staging_files(&mut decoders)
            .await
            .map_err(|error| error.to_string())?;
        if !decoders[0].complete {
            return Err("production bonded EntryDecoder did not complete the entry".to_string());
        }
        let final_bytes_written = decoders[0].bytes_written;
        let decoded = std::fs::read(&staging_path)
            .map_err(|error| format!("read production bonded staging bytes: {error}"))?;

        let decoded_sha256: [u8; 32] = Sha256::digest(&decoded).into();
        let decoded_digest = EntryDigest {
            rel_path: descriptor.entries[0].rel_path.clone(),
            size: u64::try_from(decoded.len()).expect("decoded lab payload length fits u64"),
            content_id: crate::atp::object::ObjectId::content(ContentId::from_bytes(&decoded)),
            content_sha256: decoded_sha256,
        };
        if hex_encode(&decoded_sha256) != descriptor.entries[0].sha256_hex
            || flat_merkle_root_from_digests(std::slice::from_ref(&decoded_digest))
                != descriptor.merkle_root_hex
        {
            return Err("lab bonded decode failed descriptor integrity verification".to_string());
        }
        let donor_links = donor_addrs
            .iter()
            .enumerate()
            .map(|(donor_index, donor_addr)| {
                network
                    .source_stats(*donor_addr)
                    .ok_or_else(|| format!("missing donor {donor_index} link stats"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if network.queued_datagrams(receiver_addr) != Some(0)
            || network.has_receive_waiter(receiver_addr) != Some(false)
        {
            return Err("lab UDP receiver did not drain cleanly".to_string());
        }

        Ok(LabBondedDatagramObservation {
            decoded,
            donor_ingress,
            donor_links,
            donor_sends,
            source_symbols_required: u64::from(geometry.source_symbols),
            source_symbols_accepted: block_source_symbols_accepted,
            repair_symbols_accepted: aggregate.repair_symbols_accepted,
            completion_path: progress.completion_path,
            missing_source_esis: progress.missing_source_esis,
            deficit_symbols: progress.deficit_symbols,
            decoder_pipeline_released: decoders[0].pipeline.is_none(),
            bytes_written_before_late_source,
            bytes_written_after_late_source,
            final_bytes_written,
            late_source_observed: late_sources_observed,
            late_source_accepted,
            staging_unchanged_after_late_source,
            first_receive_parked,
            virtual_time_nanos: cx.now_for_observability().as_nanos(),
        })
    }

    fn install_lab_bonded_datagram_scenario(runtime: &mut LabRuntime, scenario: LabBondedScenario) {
        let expected = bonded_e2e_payload(7_169);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, mut handle, spawn_effects) = runtime
            .state
            .create_task_with_deferred_spawn_effects(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab bonded task has current Cx");
                run_lab_bonded_datagram_scenario(cx, scenario).await
            })
            .expect("create lab bonded root task");
        runtime
            .scheduler
            .lock()
            .schedule(task_id, Budget::INFINITE.priority);
        spawn_effects.dispatch();
        runtime.advance_time(1_000_000);
        let report = runtime.run_until_quiescent_with_report();
        assert!(
            report.quiescent,
            "lab bonded scenario did not quiesce: {report:?}"
        );
        let observation = handle
            .try_join()
            .expect("join lab bonded root task")
            .expect("lab bonded root task completed")
            .expect("lab bonded datagram scenario succeeds");
        assert_eq!(
            observation.decoded, expected,
            "lab decode must be byte-identical"
        );
        assert!(observation.first_receive_parked);
        assert!(observation.virtual_time_nanos > 0);
        assert!(observation.source_symbols_accepted > 0);
        assert!(
            observation.source_symbols_accepted < observation.source_symbols_required,
            "at least one source symbol must be lost so FEC is required: {observation:?}"
        );
        assert!(
            observation.repair_symbols_accepted > 0,
            "repair/FEC symbols must contribute to completion: {observation:?}"
        );
        assert_eq!(
            observation.completion_path,
            BondedBlockCompletionPath::RepairDecode,
            "accepted coverage must complete through repair decode"
        );
        assert_eq!(observation.deficit_symbols, 0);
        let expected_source_holes = match scenario.donor_count {
            1 => vec![4, 9, 10, 14],
            2 => vec![8, 10, 13],
            3 => vec![8, 10, 11, 12, 14],
            _ => unreachable!("scenario donor count validated by runner"),
        };
        assert_eq!(observation.missing_source_esis, expected_source_holes);
        assert!(observation.decoder_pipeline_released);
        assert_eq!(observation.bytes_written_before_late_source, 4_096);
        assert_eq!(observation.bytes_written_after_late_source, 4_096);
        let expected_len = u64::try_from(expected.len()).expect("lab payload length fits u64");
        assert_eq!(observation.final_bytes_written, expected_len);
        assert!(observation.late_source_observed);
        assert!(
            !observation.late_source_accepted,
            "completed source block must refuse every late source retransmit"
        );
        assert!(
            observation.staging_unchanged_after_late_source,
            "late source must not change staged bytes after FEC completion"
        );
        let donor_count =
            usize::try_from(scenario.donor_count).expect("lab donor count fits usize");
        assert_eq!(observation.donor_ingress.len(), donor_count);
        assert_eq!(observation.donor_links.len(), donor_count);
        assert_eq!(observation.donor_sends.len(), donor_count);
        for (donor, ((ingress, link), send)) in observation
            .donor_ingress
            .into_iter()
            .zip(observation.donor_links)
            .zip(observation.donor_sends)
            .enumerate()
        {
            assert!(
                ingress.symbols_accepted > 0,
                "donor {donor} contributed no accepted symbols"
            );
            assert_eq!(
                ingress.duplicate_symbols, 0,
                "residue-disjoint donor {donor} produced duplicate ESIs"
            );
            assert_eq!(ingress.symbols_rejected_by_retention, 0);
            assert!(link.sent > 0, "donor {donor} sent no datagrams");
            assert!(link.dropped > 0, "donor {donor} experienced no loss");
            assert!(link.delivered > 0, "donor {donor} delivered no datagrams");
            assert_eq!(link.sent, link.dropped + link.delivered);
            assert_eq!(send.emitted, link.sent);
            let expected_stop = scenario.stopped_donor.and_then(|(stopped, limit)| {
                (usize::try_from(stopped).ok() == Some(donor)).then_some(limit)
            });
            if let Some(limit) = expected_stop {
                assert!(send.stopped_early, "donor {donor} must die mid-spray");
                assert_eq!(send.emitted, limit);
                assert!(send.emitted < send.planned);
            } else {
                assert!(!send.stopped_early, "donor {donor} stopped unexpectedly");
                assert_eq!(send.emitted, send.planned);
            }
        }
    }

    fn install_lab_bonded_n1_loss(runtime: &mut LabRuntime) {
        install_lab_bonded_datagram_scenario(
            runtime,
            LabBondedScenario {
                donor_count: 1,
                stopped_donor: None,
            },
        );
    }

    fn install_lab_bonded_n2_loss(runtime: &mut LabRuntime) {
        install_lab_bonded_datagram_scenario(
            runtime,
            LabBondedScenario {
                donor_count: 2,
                stopped_donor: None,
            },
        );
    }

    fn install_lab_bonded_n3_loss_and_donor_death(runtime: &mut LabRuntime) {
        install_lab_bonded_datagram_scenario(
            runtime,
            LabBondedScenario {
                donor_count: 3,
                stopped_donor: Some((2, 3)),
            },
        );
    }

    /// H1: the degenerate one-donor partition remains byte-identical while
    /// deterministic loss forces completion to use repair symbols.
    #[test]
    fn bonded_lab_n1_loss_is_byte_identical_and_replayable() {
        assert_deterministic_for_seeds([0xB04D_0101, 0xB04D_0102], install_lab_bonded_n1_loss);
    }

    /// br-asupersync-kp2kg7: two residue-disjoint donors traverse the actual
    /// bonded schedule, symbol encoder, wire framing, shared admission/dedup,
    /// and RaptorQ decoder over a waker-backed virtual UDP plane. Both links
    /// lose packets, the first receive genuinely parks, virtual time advances,
    /// and same-seed LabRuntime traces replay identically.
    #[test]
    fn bonded_n2_loss_is_byte_identical_and_replayable_under_lab_runtime() {
        assert_deterministic_for_seeds([0xB04D_0002, 0xB04D_0003], install_lab_bonded_n2_loss);
    }

    /// H1: three residue partitions survive independent link loss after donor
    /// two dies mid-spray; every donor contributes novel symbols, source loss
    /// makes FEC necessary, a held late source symbol cannot double-count the
    /// completed block, and the fixed-seed schedules replay identically.
    #[test]
    fn bonded_lab_n3_loss_and_donor_death_is_byte_identical_and_replayable() {
        assert_deterministic_for_seeds(
            [0xB04D_0301, 0xB04D_0302],
            install_lab_bonded_n3_loss_and_donor_death,
        );
    }

    /// Build the shared bonded descriptor exactly like a real coordinator:
    /// per-entry streaming SHA-256 digests + the flat-graph merkle root (the
    /// same digest pass `prove_local_holding` runs on every donor).
    fn bonded_e2e_descriptor(
        src_dir: &Path,
        rel_paths: &[&str],
        root_name: &str,
        is_directory: bool,
        config: &RqConfig,
    ) -> BondTransferDescriptor {
        let mut buf = vec![0u8; 64 * 1024];
        let mut entries = Vec::new();
        let mut digests = Vec::new();
        let mut total_bytes = 0u64;
        for (index, rel_path) in rel_paths.iter().enumerate() {
            let (size, content_id, content_sha256) = futures_lite::future::block_on(
                hash_file_streaming(&src_dir.join(rel_path), &mut buf),
            )
            .expect("hash bonded source entry");
            total_bytes += size;
            entries.push(ManifestEntry {
                index: index as u32,
                rel_path: (*rel_path).to_string(),
                size,
                sha256_hex: hex_encode(&content_sha256),
                members: Vec::new(),
                fragment: None,
            });
            digests.push(EntryDigest {
                rel_path: (*rel_path).to_string(),
                size,
                content_id,
                content_sha256,
            });
        }
        let merkle_root_hex = flat_merkle_root_from_digests(&digests);
        let transfer_id = hex_encode(&Sha256::digest(merkle_root_hex.as_bytes()));
        // The metadata capture root is the TRANSFER root: the file itself for
        // a single-file transfer (a directory root would add directory
        // metadata, which single-file manifests reject fail-closed).
        let metadata_root = if is_directory {
            src_dir.to_path_buf()
        } else {
            src_dir.join(root_name)
        };
        let metadata = futures_lite::future::block_on(source_metadata_manifest_with_config(
            &metadata_root,
            config,
        ))
        .expect("capture bonded source metadata");
        let manifest = TransferManifest {
            transfer_id,
            root_name: root_name.to_string(),
            is_directory,
            total_bytes,
            merkle_root_hex,
            metadata: Some(metadata),
            delta_manifest: None,
            entries,
        };
        BondTransferDescriptor::from_manifest(
            &manifest,
            config.symbol_size,
            config.max_block_size as u64,
            None,
        )
    }

    /// Spawn the bonded receiver on its own runtime/thread (mirrors two real
    /// processes); returns the bound control address and the join handle.
    fn spawn_bonded_receiver(
        descriptor: BondTransferDescriptor,
        dest_dir: PathBuf,
        expected_donors: u32,
        config: RqConfig,
    ) -> (
        SocketAddr,
        thread::JoinHandle<Result<BondedReceiveReport, RqError>>,
        crate::observability::LogCollector,
    ) {
        let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
        let logs = crate::observability::LogCollector::new(256)
            .with_min_level(crate::observability::LogLevel::Trace);
        let receiver_logs = logs.clone();
        let handle = thread::spawn(move || {
            let runtime = RuntimeBuilder::multi_thread()
                .worker_threads(2)
                .enable_platform_reactor(true)
                .build()
                .expect("bonded receiver runtime");
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("bonded receiver cx");
                cx.set_log_collector(receiver_logs);
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                addr_tx.send(addr).expect("send bonded control addr");
                receive_bonded(
                    &cx,
                    &descriptor,
                    &dest_dir,
                    &listener,
                    "127.0.0.1",
                    expected_donors,
                    config,
                    "bonded-receiver",
                    None,
                )
                .await
            }))
        });
        let addr = addr_rx.recv().expect("bonded receiver bound address");
        (addr, handle, logs)
    }

    fn run_bonded_donor(
        descriptor: BondTransferDescriptor,
        control_addr: SocketAddr,
        source_root: PathBuf,
        config: RqConfig,
    ) -> Result<BondedDonateReport, RqError> {
        let runtime = RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .enable_platform_reactor(true)
            .build()
            .expect("bonded donor runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("bonded donor cx");
            donate_bonded(&cx, &descriptor, control_addr, &source_root, config).await
        }))
    }

    fn bonded_enrollment_descriptor() -> BondTransferDescriptor {
        BondTransferDescriptor {
            transfer_id: "enrollment-transfer".to_string(),
            root_name: "payload.bin".to_string(),
            is_directory: false,
            total_bytes: 0,
            merkle_root_hex: "enrollment-merkle".to_string(),
            metadata: Some(RqMetadataManifest {
                version: RQ_METADATA_MANIFEST_VERSION,
                commitment_hex: "enrollment-metadata".to_string(),
                entries: Vec::new(),
                directories: None,
            }),
            entries: Vec::new(),
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: 64 * 1024,
            auth_key_id: None,
        }
    }

    fn bonded_enrollment_hello(descriptor: &BondTransferDescriptor) -> BondedDonorHello {
        BondedDonorHello {
            protocol: ATP_RQ_BONDED_PROTOCOL,
            transfer_id: descriptor.transfer_id.clone(),
            merkle_root_hex: descriptor.merkle_root_hex.clone(),
            metadata_commitment_hex: descriptor
                .metadata
                .as_ref()
                .expect("enrollment metadata")
                .commitment_hex
                .clone(),
            symbol_size: descriptor.symbol_size,
            max_block_size: descriptor.max_block_size,
            symbol_auth: false,
            offer: BondingHandshake::v1_static(
                [BondTransport::DirectIp],
                MAX_BONDING_DONORS,
                false,
            ),
        }
    }

    #[test]
    fn bonded_enrollment_rejects_symbol_size_mismatch() {
        let descriptor = bonded_enrollment_descriptor();
        let mut hello = bonded_enrollment_hello(&descriptor);
        hello.symbol_size = descriptor.symbol_size.saturating_sub(1);

        let refusal = bonded_donor_hello_refusal(&hello, &descriptor, false)
            .expect("mismatched symbol size must be refused during enrollment");

        assert!(
            refusal.contains("symbol size"),
            "unexpected refusal: {refusal}"
        );
        assert!(refusal.contains(&hello.symbol_size.to_string()));
        assert!(refusal.contains(&descriptor.symbol_size.to_string()));
    }

    #[test]
    fn bonded_enrollment_rejects_max_block_size_mismatch() {
        let descriptor = bonded_enrollment_descriptor();
        let mut hello = bonded_enrollment_hello(&descriptor);
        hello.max_block_size = descriptor.max_block_size.saturating_add(1);

        let refusal = bonded_donor_hello_refusal(&hello, &descriptor, false)
            .expect("mismatched max block size must be refused during enrollment");

        assert!(
            refusal.contains("max block size"),
            "unexpected refusal: {refusal}"
        );
        assert!(refusal.contains(&hello.max_block_size.to_string()));
        assert!(refusal.contains(&descriptor.max_block_size.to_string()));
    }

    /// br-asupersync-w9yojl census LOW-1: a bonded descriptor's geometry was
    /// checked only for zero. One byte per block over a 1 MiB entry needs
    /// 2^20 source blocks (a source block number names 256), and the donor
    /// and the receiver sized and iterated per-block state from it.
    #[test]
    fn bonded_descriptor_geometry_gets_the_hello_bounds() {
        let mut descriptor = bonded_enrollment_descriptor();
        descriptor.entries = vec![crate::net::atp::bonding::BondEntry {
            index: 0,
            rel_path: "payload.bin".to_string(),
            size: 1 << 20,
            sha256_hex: "0".repeat(64),
        }];
        descriptor.total_bytes = 1 << 20;
        descriptor.max_block_size = 1;
        let mut config = RqConfig::default();
        let before = config.max_block_size;
        let err = apply_bonded_descriptor_config(&descriptor, &mut config)
            .expect_err("one byte per block over 1 MiB is refused");
        assert!(
            matches!(&err, RqError::Coding(reason) if reason.contains("source blocks")),
            "{err:?}"
        );
        assert_eq!(
            config.max_block_size, before,
            "a refused geometry is not adopted"
        );

        descriptor.max_block_size = 64 * 1024;
        apply_bonded_descriptor_config(&descriptor, &mut config).expect("a sound geometry applies");
        assert_eq!(config.max_block_size, 64 * 1024);
    }

    /// The receiver also applies the Hello path's source-symbol budget. With
    /// 16-byte symbols, three 200 MB entries (each within the per-entry
    /// bounds) need 37.5 million source symbols, over the 2^24 floor budget
    /// of a receiver limited to 1 GiB.
    #[test]
    fn bonded_receive_refuses_a_descriptor_over_the_source_symbol_budget() {
        let mut descriptor = bonded_enrollment_descriptor();
        descriptor.symbol_size = 16;
        descriptor.max_block_size = 900_000;
        descriptor.entries = (0..3)
            .map(|index| crate::net::atp::bonding::BondEntry {
                index,
                rel_path: format!("part{index}.bin"),
                size: 200_000_000,
                sha256_hex: "0".repeat(64),
            })
            .collect();
        descriptor.total_bytes = 600_000_000;
        let config = RqConfig {
            max_transfer_bytes: 1 << 30,
            ..RqConfig::default()
        };
        let mut adopted = config.clone();
        apply_bonded_descriptor_config(&descriptor, &mut adopted)
            .expect("each entry is within the per-entry bounds");
        let err = check_bonded_receive_symbol_budget(&descriptor, &adopted)
            .expect_err("the transfer is over the receiver's symbol budget");
        assert!(
            matches!(&err, RqError::Coding(reason) if reason.contains("budget")),
            "{err:?}"
        );

        descriptor.symbol_size = 1024;
        check_bonded_receive_symbol_budget(&descriptor, &adopted)
            .expect("the same bytes in 1024-byte symbols fit");
    }

    #[test]
    fn bonded_manifest_roundtrips_descriptor() {
        let config = bonded_lab_config();
        let root = bonded_e2e_tmp("manifest_roundtrip");
        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::write(src_dir.join("payload.bin"), bonded_e2e_payload(4096))
            .expect("write payload");

        let descriptor =
            bonded_e2e_descriptor(&src_dir, &["payload.bin"], "payload.bin", false, &config);
        let manifest = manifest_from_bonded_descriptor(&descriptor);

        assert_eq!(manifest.metadata, descriptor.metadata);

        assert_eq!(
            BondTransferDescriptor::from_manifest(
                &manifest,
                descriptor.symbol_size,
                descriptor.max_block_size,
                None,
            ),
            descriptor,
            "descriptor -> manifest -> descriptor must be lossless"
        );
        validate_manifest(&manifest, &config).expect("bonded manifest validates");
    }

    #[test]
    fn bonded_manifest_preserves_metadata_and_rejects_strip_or_tamper() {
        let mut config = bonded_lab_config();
        config.metadata_policy.preserve_timestamps = true;
        let root = bonded_e2e_tmp("metadata_roundtrip");
        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::write(src_dir.join("payload.bin"), bonded_e2e_payload(4096))
            .expect("write payload");
        let mut descriptor =
            bonded_e2e_descriptor(&src_dir, &["payload.bin"], "payload.bin", false, &config);

        let manifest = manifest_from_bonded_descriptor(&descriptor);
        let metadata = manifest.metadata.as_ref().expect("mandatory v4 metadata");
        assert_eq!(metadata, descriptor.metadata.as_ref().unwrap());
        assert_eq!(metadata.entries.len(), 1);
        assert!(metadata.entries[0].metadata.mtime_unix_secs.is_some());
        validate_manifest(&manifest, &config).expect("metadata-preserving bonded manifest");

        let tampered_nanos = descriptor.metadata.as_ref().unwrap().entries[0]
            .metadata
            .mtime_nanos
            .unwrap_or(0)
            .wrapping_add(1)
            % 1_000_000_000;
        descriptor
            .metadata
            .as_mut()
            .expect("descriptor metadata")
            .entries[0]
            .metadata
            .mtime_nanos = Some(tampered_nanos);
        let tampered = manifest_from_bonded_descriptor(&descriptor);
        assert!(validate_manifest(&tampered, &config).is_err());

        descriptor.metadata = None;
        let stripped = manifest_from_bonded_descriptor(&descriptor);
        assert!(validate_manifest(&stripped, &config).is_err());
    }

    /// (a) One-donor bonded transfer commits byte-identical with the
    /// single-source report semantics (z01bbr.8.5 isomorphism), under the
    /// authenticated symbol posture (verify_bonded_symbol_tag on every
    /// datagram).
    #[test]
    fn bonded_receive_single_donor_commits_byte_identical() {
        let config = bonded_auth_config();
        let root = bonded_e2e_tmp("single_donor");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::create_dir_all(&dst_dir).expect("create dst dir");
        // ~96 KiB: two 64 KiB-limit source blocks (multi-block, small K).
        let payload = bonded_e2e_payload(96_007);
        std::fs::write(src_dir.join("payload.bin"), &payload).expect("write payload");

        let descriptor =
            bonded_e2e_descriptor(&src_dir, &["payload.bin"], "payload.bin", false, &config);

        let (addr, recv_handle, _) =
            spawn_bonded_receiver(descriptor.clone(), dst_dir.clone(), 1, config.clone());
        let donor =
            run_bonded_donor(descriptor.clone(), addr, src_dir, config).expect("donor succeeds");
        let report = recv_handle
            .join()
            .expect("receiver thread")
            .expect("bonded receive succeeds");

        assert!(report.committed, "bonded receive must commit");
        assert_eq!(report.transfer_id, descriptor.transfer_id);
        assert_eq!(report.files, 1);
        assert_eq!(report.bytes_received, payload.len() as u64);
        assert_eq!(report.enrolled_donors, 1);
        // Single-source ReceiveReport semantics: one committed path at
        // dest/root_name carrying the exact source bytes.
        assert_eq!(report.committed_paths.len(), 1);
        assert!(
            report.committed_paths[0].ends_with("payload.bin"),
            "committed path must be the transfer root: {:?}",
            report.committed_paths
        );
        let received = std::fs::read(dst_dir.join("payload.bin")).expect("read committed file");
        assert_eq!(received, payload, "commit must be byte-identical");
        assert_eq!(report.donor_ingress.len(), 1);
        assert!(report.donor_ingress[0].1.symbols_accepted > 0);

        assert!(donor.receipt.committed, "donor must see a committed proof");
        assert!(donor.receipt.sha_ok && donor.receipt.merkle_ok);
        assert_eq!(donor.donor_index, 0);
        assert_eq!(donor.donor_count, 1);
        assert!(donor.symbols_sent > 0);
    }

    /// (b) Two donors, multi-block payload: commits byte-identical and BOTH
    /// donors contribute accepted symbols to the shared decoder set.
    #[test]
    fn bonded_receive_two_donors_multi_block_commits_with_both_donors_contributing() {
        let config = bonded_lab_config();
        let root = bonded_e2e_tmp("two_donors");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::create_dir_all(&dst_dir).expect("create dst dir");
        // ~200 KiB across four 64 KiB-limit source blocks.
        let payload = bonded_e2e_payload(200_003);
        std::fs::write(src_dir.join("payload.bin"), &payload).expect("write payload");

        let descriptor =
            bonded_e2e_descriptor(&src_dir, &["payload.bin"], "payload.bin", false, &config);

        let (addr, recv_handle, _) =
            spawn_bonded_receiver(descriptor.clone(), dst_dir.clone(), 2, config.clone());
        let donor_a = {
            let descriptor = descriptor.clone();
            let src = src_dir.clone();
            let config = config.clone();
            thread::spawn(move || run_bonded_donor(descriptor, addr, src, config))
        };
        let donor_b = {
            let descriptor = descriptor.clone();
            let src = src_dir.clone();
            let config = config.clone();
            thread::spawn(move || run_bonded_donor(descriptor, addr, src, config))
        };

        let report_a = donor_a
            .join()
            .expect("donor A thread")
            .expect("donor A succeeds");
        let report_b = donor_b
            .join()
            .expect("donor B thread")
            .expect("donor B succeeds");
        let report = recv_handle
            .join()
            .expect("receiver thread")
            .expect("bonded receive succeeds");

        assert!(report.committed);
        assert_eq!(report.enrolled_donors, 2);
        assert_eq!(report.bytes_received, payload.len() as u64);
        let received = std::fs::read(dst_dir.join("payload.bin")).expect("read committed file");
        assert_eq!(received, payload, "commit must be byte-identical");

        // BOTH donors must have contributed accepted (novel, post-dedup)
        // symbols to the unified receiver set.
        assert_eq!(
            report.donor_ingress.len(),
            2,
            "both donors must appear in ingress stats: {:?}",
            report.donor_ingress
        );
        for (donor_index, stats) in &report.donor_ingress {
            assert!(
                stats.symbols_accepted > 0,
                "donor {donor_index} must contribute accepted symbols: {stats:?}"
            );
        }
        assert!(report_a.receipt.committed);
        assert!(report_b.receipt.committed);
        assert_ne!(
            report_a.donor_index, report_b.donor_index,
            "receiver must assign distinct donor indexes"
        );
    }

    /// Two authenticated donors must converge despite a third enrolled donor
    /// spraying correctly framed symbols under the wrong key. The focused
    /// admission test above proves those packets increment the schedule-owned
    /// rejection counter while remaining outside decoder and ingress state;
    /// this socket-level test proves the terminal receiver trace preserves that
    /// evidence while honest repair reallocation completes the transfer.
    #[test]
    fn bonded_receive_tolerates_wrong_key_donor_and_commits_from_honest_donors() {
        let receiver_config = bonded_auth_config();
        let root = bonded_e2e_tmp("wrong_key_donor");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::create_dir_all(&dst_dir).expect("create dst dir");
        let payload = bonded_e2e_payload(200_003);
        std::fs::write(src_dir.join("payload.bin"), &payload).expect("write payload");

        let descriptor = bonded_e2e_descriptor(
            &src_dir,
            &["payload.bin"],
            "payload.bin",
            false,
            &receiver_config,
        );
        let (addr, recv_handle, receiver_logs) = spawn_bonded_receiver(
            descriptor.clone(),
            dst_dir.clone(),
            3,
            receiver_config.clone(),
        );

        let honest_a = {
            let descriptor = descriptor.clone();
            let src = src_dir.clone();
            let config = receiver_config.clone();
            thread::spawn(move || run_bonded_donor(descriptor, addr, src, config))
        };
        let honest_b = {
            let descriptor = descriptor.clone();
            let src = src_dir.clone();
            let config = receiver_config.clone();
            thread::spawn(move || run_bonded_donor(descriptor, addr, src, config))
        };
        let wrong_key = {
            let descriptor = descriptor.clone();
            let src = src_dir.clone();
            let config = RqConfig {
                max_block_size: 64 * 1024,
                round_tail_drain: Duration::from_millis(5),
                accept_timeout: Duration::from_secs(30),
                ..RqConfig::default()
            }
            .with_symbol_auth(SecurityContext::for_testing(215));
            thread::spawn(move || run_bonded_donor(descriptor, addr, src, config))
        };

        let honest_a = honest_a
            .join()
            .expect("honest donor A thread")
            .expect("honest donor A succeeds");
        let honest_b = honest_b
            .join()
            .expect("honest donor B thread")
            .expect("honest donor B succeeds");
        let wrong_key = wrong_key
            .join()
            .expect("wrong-key donor thread")
            .expect("wrong-key donor receives terminal proof");
        let report = recv_handle
            .join()
            .expect("receiver thread")
            .expect("honest donors must complete transfer");

        assert!(report.committed);
        assert_eq!(report.enrolled_donors, 3);
        assert!(
            report.feedback_rounds > 0,
            "wrong-key holes require feedback"
        );
        assert_eq!(report.bytes_received, payload.len() as u64);
        let received = std::fs::read(dst_dir.join("payload.bin")).expect("read committed file");
        assert_eq!(received, payload, "commit must remain byte-identical");

        for honest in [&honest_a, &honest_b] {
            assert!(honest.receipt.committed);
            assert!(
                report.donor_ingress.iter().any(|(donor_index, stats)| {
                    *donor_index == honest.donor_index && stats.symbols_accepted > 0
                }),
                "honest donor {} must contribute authenticated symbols: {:?}",
                honest.donor_index,
                report.donor_ingress
            );
        }
        assert!(
            wrong_key.symbols_sent > 0,
            "malicious donor must exercise UDP auth"
        );
        assert!(
            wrong_key.receipt.committed,
            "all enrolled donors receive proof"
        );
        // `donor_ingress` and auth-rejection counters are attributed by the
        // receiver-owned ESI schedule, not by socket identity. Honest repair
        // reallocation can therefore contribute authenticated symbols to the
        // wrong-key sender's original schedule bucket. The direct admission
        // test above is the causal proof that rejected datagrams themselves do
        // not enter authenticated ingress.
        let wrong_key_donor = wrong_key.donor_index.to_string();
        let rejection = receiver_logs
            .peek()
            .into_iter()
            .find(|entry| {
                entry.message() == BONDING_AUTH_REJECTION_TRACE_EVENT
                    && entry.get_field("donor_index") == Some(wrong_key_donor.as_str())
                    && entry.get_field("attribution") == Some("esi_schedule")
                    && entry.get_field("phase") == Some("completed")
            })
            .expect("receiver must emit the terminal wrong-key schedule rejection summary");
        let rejected_symbols = rejection
            .get_field("rejected_symbols")
            .expect("rejection count field")
            .parse::<u64>()
            .expect("rejection count is numeric");
        assert!(
            rejected_symbols > 0,
            "receiver-side auth rejection count must be positive"
        );
    }

    /// (c) Two donors, one dies mid-transfer (after round 0 and after
    /// receiving a NeedMore it never serves): the receiver reallocates the
    /// dead donor's outstanding repair windows to the survivor
    /// (reallocate_failed_bonded_repair_windows) and the transfer still
    /// commits byte-identical.
    #[test]
    fn bonded_receive_survives_donor_death_via_repair_reallocation() {
        let config = bonded_lab_config();
        let root = bonded_e2e_tmp("donor_death");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::create_dir_all(&dst_dir).expect("create dst dir");
        let payload = bonded_e2e_payload(200_003);
        std::fs::write(src_dir.join("payload.bin"), &payload).expect("write payload");

        let descriptor =
            bonded_e2e_descriptor(&src_dir, &["payload.bin"], "payload.bin", false, &config);

        let (addr, recv_handle, _) =
            spawn_bonded_receiver(descriptor.clone(), dst_dir.clone(), 2, config.clone());

        // Lossy survivor donor: HALF its datagrams are deterministically
        // dropped, so every block carries a deficit into the feedback rounds
        // and the survivor alone cannot finish round 1 (the dying donor holds
        // most of the round-1 repair windows because its clean round-0 spray
        // gives it the higher goodput weight).
        let survivor = {
            let descriptor = descriptor.clone();
            let src = src_dir.clone();
            let lossy = RqConfig {
                debug_drop_one_in: 2,
                ..config.clone()
            };
            thread::spawn(move || run_bonded_donor(descriptor, addr, src, lossy))
        };

        // Dying donor: enrolls, sprays a CLEAN round 0 (earning the dominant
        // repair-window weight), acknowledges round 0, reads the first
        // NeedMore — and then drops the control connection without serving
        // it, leaving its freshly allocated repair windows outstanding for
        // reallocate_failed_bonded_repair_windows.
        let dying = {
            let descriptor = descriptor.clone();
            let src = src_dir.clone();
            let config = config.clone();
            thread::spawn(move || {
                let runtime = RuntimeBuilder::multi_thread()
                    .worker_threads(2)
                    .enable_platform_reactor(true)
                    .build()
                    .expect("dying donor runtime");
                runtime.block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("dying donor cx");
                    let stream = TcpStream::connect(addr).await?;
                    let mut control = FrameTransport::new(stream);
                    control
                        .send(&json_frame(
                            FrameType::Handshake,
                            &BondedDonorHello {
                                protocol: ATP_RQ_BONDED_PROTOCOL,
                                transfer_id: descriptor.transfer_id.clone(),
                                merkle_root_hex: descriptor.merkle_root_hex.clone(),
                                metadata_commitment_hex: descriptor
                                    .metadata
                                    .as_ref()
                                    .expect("bonded test metadata")
                                    .commitment_hex
                                    .clone(),
                                symbol_size: descriptor.symbol_size,
                                max_block_size: descriptor.max_block_size,
                                symbol_auth: false,
                                offer: BondingHandshake::v1_static(
                                    [BondTransport::DirectIp],
                                    MAX_BONDING_DONORS,
                                    false,
                                ),
                            },
                        )?)
                        .await?;
                    let ack = control.recv().await?;
                    let welcome: BondedDonorWelcome = parse_json(&ack)?;
                    assert!(welcome.accepted, "dying donor must enroll first");
                    let mut assignment = welcome.assignment.expect("assignment");
                    assignment.receiver_udp_endpoints = welcome
                        .udp_ports
                        .iter()
                        .map(|&port| SocketAddr::new(addr.ip(), port))
                        .collect();
                    let primary = assignment.receiver_udp_endpoints[0];
                    let spray =
                        donate_path(&cx, &descriptor, &assignment, primary, &src, config.clone())
                            .await?;
                    control
                        .send(&json_frame(
                            FrameType::ObjectComplete,
                            &BondedRoundComplete {
                                round: 0,
                                donor_index: assignment.donor_index,
                                symbols_sent: spray.symbols_sent,
                            },
                        )?)
                        .await?;
                    let feedback = control.recv().await?;
                    assert_eq!(
                        feedback.frame_type(),
                        FrameType::ObjectRequest,
                        "dying donor must receive a NeedMore before it dies"
                    );
                    // Die mid-transfer: drop the control connection without
                    // serving the allocated repair windows.
                    drop(control);
                    Ok::<u32, RqError>(assignment.donor_index)
                }))
            })
        };

        let dead_donor_index = dying
            .join()
            .expect("dying donor thread")
            .expect("dying donor enrolled, sprayed round 0, then died");
        let survivor_report = survivor
            .join()
            .expect("survivor thread")
            .expect("survivor donor succeeds");
        let report = recv_handle
            .join()
            .expect("receiver thread")
            .expect("bonded receive must survive donor death");

        assert!(report.committed, "transfer must commit despite donor death");
        assert_eq!(report.enrolled_donors, 2);
        assert!(
            report.feedback_rounds >= 2,
            "the survivor's shortfall must outlive the dying donor's windows: {report:?}"
        );
        assert!(
            report.reallocated_repair_windows > 0,
            "the dead donor's outstanding repair windows must be reallocated \
             to the survivor: {report:?}"
        );
        let received = std::fs::read(dst_dir.join("payload.bin")).expect("read committed file");
        assert_eq!(received, payload, "commit must be byte-identical");
        assert!(survivor_report.receipt.committed);
        assert_ne!(survivor_report.donor_index, dead_donor_index);
        // The dead donor delivered round-0 symbols before dying, so it still
        // appears in the ingress stats; the survivor carried the rest.
        assert!(
            report
                .donor_ingress
                .iter()
                .any(|(donor_index, stats)| *donor_index == dead_donor_index
                    && stats.symbols_received > 0),
            "dead donor's round-0 contribution must be visible: {:?}",
            report.donor_ingress
        );
        assert!(
            report
                .donor_ingress
                .iter()
                .any(
                    |(donor_index, stats)| *donor_index == survivor_report.donor_index
                        && stats.symbols_accepted > 0
                ),
            "survivor must contribute accepted symbols: {:?}",
            report.donor_ingress
        );
    }

    /// A NeedMore names repair ESI windows of any size (up to 2^32 ESIs) over
    /// the plaintext control channel. The donor serves at most the per-block
    /// headroom a bonded receiver keeps (2K + 64) instead of allocating and
    /// encoding the whole window.
    #[test]
    fn donor_serves_a_need_more_window_only_up_to_the_block_cap() {
        let config = bonded_lab_config();
        let root = bonded_e2e_tmp("need_more_cap");
        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        let payload = bonded_e2e_payload(4096);
        std::fs::write(src_dir.join("payload.bin"), &payload).expect("write payload");
        let descriptor =
            bonded_e2e_descriptor(&src_dir, &["payload.bin"], "payload.bin", false, &config);
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("block 0 geometry");
        let k = u32::from(geometry.source_symbols);
        let cap = bonded_need_more_block_repair_cap(k);
        // Fifty times the cap: before the fix the donor served all of it,
        // which stays cheap at this size.
        let span = u32::try_from(cap * 50).expect("span fits u32");
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver udp");
        let assignment = DonorAssignment::new_static(
            0,
            1,
            vec![receiver.local_addr().expect("receiver udp addr")],
            None,
        );
        let need = BondedNeedMore {
            round: 1,
            blocks: vec![BondedBlockNeed {
                entry_index: 0,
                source_block_number: 0,
                source_esis: Vec::new(),
                repair_windows: vec![EsiWindow {
                    start_inclusive: k,
                    end_exclusive: k + span,
                }],
            }],
        };

        let runtime = RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .enable_platform_reactor(true)
            .build()
            .expect("bonded donor runtime");
        let sent = runtime
            .block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("bonded donor cx");
                bonded_donor_execute_need_more(
                    &cx,
                    &descriptor,
                    &assignment,
                    &src_dir,
                    &config,
                    None,
                    &need,
                )
                .await
            }))
            .expect("donor serves the NeedMore");
        drop(receiver);

        assert_eq!(
            sent,
            u64::try_from(cap).expect("cap fits u64"),
            "a {span}-ESI window for a K={k} block is served up to the block cap"
        );
    }
