use super::*;

#[test]
fn hello_ack_udp_ports_defaults_to_legacy_port() {
    let ack = HelloAck {
        accepted: true,
        peer_id: "receiver".to_string(),
        udp_port: 8472,
        udp_ports: Vec::new(),
        control_source_stream: false,
        reason: None,
        delta_transfer_nonce: None,
        delta_receiver_nonce: None,
        delta_destination_root: None,
        delta_server_auth_tag: None,
    };

    assert_eq!(hello_ack_udp_ports(&ack).as_slice(), &[8472]);
}

#[test]
fn hello_ack_udp_ports_drive_socket_round_robin() {
    let ack = HelloAck {
        accepted: true,
        peer_id: "receiver".to_string(),
        udp_port: 3001,
        udp_ports: vec![3001, 3002, 3003],
        control_source_stream: false,
        reason: None,
        delta_transfer_nonce: None,
        delta_receiver_nonce: None,
        delta_destination_root: None,
        delta_server_auth_tag: None,
    };
    let ports = hello_ack_udp_ports(&ack);
    let peer: SocketAddr = "192.0.2.10:8472".parse().unwrap();
    let mapped_ports = (0..7)
        .map(|socket_index| {
            receiver_udp_addr_for_socket(peer, &ports, socket_index)
                .unwrap()
                .port()
        })
        .collect::<Vec<_>>();

    assert_eq!(mapped_ports, vec![3001, 3002, 3003, 3001, 3002, 3003, 3001]);
}

#[test]
fn parallel_decode_spawn_gate_respects_matrix5_width_cap() {
    assert!(
        RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY <= RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
        "entry decode width must not exceed the transfer hard cap"
    );
    assert!(
        RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD >= 64,
        "large-object repair decode must fan out on 64-core receivers"
    );
    assert!(can_spawn_parallel_decode(
        0,
        RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY
    ));
    assert!(can_spawn_parallel_decode(
        RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY - 1,
        RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY
    ));
    assert!(!can_spawn_parallel_decode(
        RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY,
        RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY
    ));
    assert!(
        !can_spawn_parallel_decode(0, 0),
        "zero decode width must not spawn"
    );
    assert!(
        !can_spawn_parallel_decode(0, 1),
        "one-wide inline decode gate must not spawn"
    );
}

#[test]
fn decode_round_stats_merge_preserves_trace_counters() {
    let mut first = RqDecodeRoundStats::default();
    first.record_attempt(BlockDecodeKind::RaptorQRepair, Duration::from_micros(7));
    first.record_join_wait(Duration::from_micros(11));
    first.record_queued_job(3);
    first.record_inline_job();
    first.record_spawn_denial();
    first.record_entry_cap_saturation();

    let mut second = RqDecodeRoundStats::default();
    second.record_attempt(BlockDecodeKind::SourceComplete, Duration::from_micros(13));
    second.record_join_wait(Duration::from_micros(17));
    second.record_queued_job(9);
    second.record_transfer_cap_saturation();
    second.apply_micros = 19;
    second.persist_micros = 23;

    first.merge(second);

    assert_eq!(first.attempts, 2);
    assert_eq!(first.repair_attempts, 1);
    assert_eq!(first.source_complete_attempts, 1);
    assert_eq!(first.decode_micros, 20);
    assert_eq!(first.join_wait_micros, 28);
    assert_eq!(first.queued_jobs, 2);
    assert_eq!(first.inline_jobs, 1);
    assert_eq!(first.spawn_denials, 1);
    assert_eq!(first.entry_cap_saturations, 1);
    assert_eq!(first.transfer_cap_saturations, 1);
    assert_eq!(first.pending_peak, 9);
    assert_eq!(first.apply_micros, 19);
    assert_eq!(first.persist_micros, 23);
}

#[test]
fn decode_core_limit_keeps_parallelism_on_four_core_hosts() {
    assert_eq!(rq_decode_core_limit_for_available(1), 1);
    assert_eq!(rq_decode_core_limit_for_available(2), 1);
    assert_eq!(rq_decode_core_limit_for_available(4), 3);
    assert_eq!(rq_decode_core_limit_for_available(8), 6);
    assert_eq!(rq_decode_core_limit_for_available(16), 12);
    assert_eq!(rq_decode_core_limit_for_available(64), 60);
    assert_eq!(
        rq_decode_core_limit_for_available(96),
        RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD
    );
}

#[test]
fn decode_width_uses_receiver_blocking_pool_capacity() {
    let config = RqConfig::default();
    let size_500m = 500 * 1024 * 1024;
    let block_500m = effective_max_block_size_for_largest_entry(&config, size_500m)
        .expect("500M fixture must fit default RQ geometry");
    let dec_500m = decode_width_fixture_entry(size_500m as u64, block_500m, config.symbol_size);
    let pool = crate::runtime::blocking_pool::BlockingPool::new(4, 4);
    let cx = Cx::new(
        crate::types::RegionId::new_for_test(31, 1),
        crate::types::TaskId::new_for_test(31, 0),
        crate::types::Budget::INFINITE,
    )
    .with_blocking_pool_handle(Some(pool.handle()));

    let budget = rq_decode_width_budget_snapshot_for_cx(
        &cx,
        std::slice::from_ref(&dec_500m),
        config.symbol_size,
    );

    assert_eq!(
        budget.core_limit, 3,
        "four blocking threads should reserve one core for UDP/control and leave three decode slots"
    );
    assert_eq!(
        budget.effective,
        budget.core_limit.min(budget.memory_limit),
        "500M geometry should use the receiver blocking-pool width instead of collapsing to host available_parallelism"
    );
}

#[test]
fn auth_verify_width_uses_receiver_blocking_pool_without_decode_size_gate() {
    let no_pool_cx = Cx::for_testing();
    assert_eq!(
        rq_auth_verify_width_for_cx(&no_pool_cx, RQ_AUTH_VERIFY_PARALLEL_MIN_SYMBOLS),
        1,
        "lab/no-pool contexts must verify inline instead of trying to spawn"
    );

    let pool = crate::runtime::blocking_pool::BlockingPool::new(4, 4);
    let cx = Cx::new(
        crate::types::RegionId::new_for_test(41, 1),
        crate::types::TaskId::new_for_test(41, 0),
        crate::types::Budget::INFINITE,
    )
    .with_blocking_pool_handle(Some(pool.handle()));

    assert_eq!(
        rq_auth_verify_width_for_cx(&cx, 512),
        3,
        "auth verification must use blocking-pool CPU width even for 50M-class transfers where repair decode is size-gated"
    );
    assert_eq!(
        rq_auth_verify_width_for_cx(&cx, RQ_AUTH_VERIFY_PARALLEL_MIN_SYMBOLS - 1),
        1,
        "tiny batches should stay inline"
    );
}

#[test]
fn decode_width_budget_reports_effective_core_and_memory_caps() {
    let budget = rq_decode_width_budget_snapshot(&[], DEFAULT_SYMBOL_SIZE);
    assert!(budget.effective >= 1);
    assert!(budget.core_limit >= budget.effective);
    assert!(budget.memory_limit >= budget.effective);
    assert_eq!(budget.max_block_size, DEFAULT_MAX_BLOCK_SIZE);
    assert_eq!(
        budget.job_memory_bytes,
        rq_decode_job_memory_estimate_bytes(DEFAULT_MAX_BLOCK_SIZE, DEFAULT_SYMBOL_SIZE)
    );
    assert_eq!(budget.effective, budget.core_limit.min(budget.memory_limit));
}

#[test]
fn decode_entry_width_gate_keeps_50m_geometry_sequential() {
    let config = RqConfig::default();
    let workload_50m = 50 * 1024 * 1024;
    let max_block_size = effective_max_block_size_for_largest_entry(&config, workload_50m)
        .expect("50M must fit default RQ transfer geometry");
    let block_count = entry_source_block_count_for_geometry(workload_50m as u64, max_block_size, 0);

    assert!(
        block_count < RQ_PARALLEL_DECODE_MIN_SOURCE_BLOCKS,
        "fixture should represent the 50M small-object cell: block_count={block_count} threshold={RQ_PARALLEL_DECODE_MIN_SOURCE_BLOCKS}"
    );
    assert!(!should_parallel_decode_entry_geometry(
        workload_50m as u64,
        max_block_size,
        0
    ));
    assert_eq!(
        entry_decode_width_budget_for_geometry(workload_50m as u64, max_block_size, 0, 64),
        0,
        "50M geometry should close the parallel decode budget"
    );
}

#[test]
fn decode_entry_width_gate_rejects_small_high_block_count_geometry() {
    let config = RqConfig::default();
    let workload_50m = 50 * 1024 * 1024;
    let observed_blocks = RQ_PARALLEL_DECODE_MIN_SOURCE_BLOCKS;

    assert!(!should_parallel_decode_entry_geometry(
        workload_50m as u64,
        usize::from(config.symbol_size).saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK),
        observed_blocks
    ));
    assert_eq!(
        entry_decode_width_budget_for_geometry(
            workload_50m as u64,
            usize::from(config.symbol_size).saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK),
            observed_blocks,
            RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
        ),
        0,
        "50M-class entries must stay sequential even when block count reaches the old fanout threshold"
    );
}

#[test]
fn decode_memory_budget_keeps_500m_geometry_wide() {
    let config = RqConfig::default();
    let workload_500m = 500 * 1024 * 1024;
    let max_block_size = effective_max_block_size_for_largest_entry(&config, workload_500m)
        .expect("500M must fit default RQ transfer geometry");
    let block_count =
        entry_source_block_count_for_geometry(workload_500m as u64, max_block_size, 0);
    let job_memory_bytes = rq_decode_job_memory_estimate_bytes(max_block_size, config.symbol_size);
    let memory_limit = RQ_DECODE_JOB_MEMORY_BUDGET_BYTES / job_memory_bytes;
    let effective_memory_width = memory_limit.min(RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD);

    assert!(
        effective_memory_width >= 48,
        "500M decode should not collapse back to narrow fan-out: max_block_size={max_block_size} job_memory_bytes={job_memory_bytes} memory_limit={memory_limit} effective_memory_width={effective_memory_width}"
    );
    assert!(
        effective_memory_width <= RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
        "effective memory gate should stay within the hard transfer cap"
    );
    assert!(
        should_parallel_decode_entry_geometry(workload_500m as u64, max_block_size, 0),
        "500M geometry should remain eligible for parallel decode: block_count={block_count} threshold={RQ_PARALLEL_DECODE_MIN_SOURCE_BLOCKS}"
    );
    assert_eq!(
        entry_decode_width_budget_for_geometry(
            workload_500m as u64,
            max_block_size,
            0,
            effective_memory_width
        ),
        block_count
            .min(RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
            .min(effective_memory_width)
    );
}

fn decode_width_fixture_entry(size: u64, max_block_size: usize, symbol_size: u16) -> EntryDecoder {
    EntryDecoder {
        index: 0,
        object_id: ObjectId::new(0xD3C0_D3C0, 0),
        size,
        pipeline: None,
        complete: false,
        staging_path: PathBuf::new(),
        staging_write_offset: 0,
        staging_file_len: size,
        staging_shared: false,
        staging_created: false,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: 0,
        max_block_size,
        source_streaming: true,
        source_blocks: source_block_progress_for(size, max_block_size, symbol_size)
            .expect("fixture must fit source-block table"),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    }
}

#[test]
fn decode_width_size_gate_keeps_50m_sequential_and_500m_parallel() {
    let config = RqConfig::default();
    let size_50m = 50 * 1024 * 1024;
    let block_50m = effective_max_block_size_for_largest_entry(&config, size_50m)
        .expect("50M fixture must fit default RQ geometry");
    let dec_50m = decode_width_fixture_entry(size_50m as u64, block_50m, config.symbol_size);

    assert!(
        !should_parallel_decode_entry(&dec_50m),
        "50M decode should stay sequential: block_count={} max_block_size={block_50m}",
        entry_source_block_count(&dec_50m)
    );
    assert_eq!(
        entry_decode_width_budget(&dec_50m, RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD),
        0,
        "50M repair decode fanout should be fully disabled"
    );
    assert_eq!(
        rq_decode_width_budget_snapshot(std::slice::from_ref(&dec_50m), config.symbol_size)
            .effective,
        0,
        "all-small transfers should close the transfer-wide parallel decode budget"
    );

    let size_500m = 500 * 1024 * 1024;
    let block_500m = effective_max_block_size_for_largest_entry(&config, size_500m)
        .expect("500M fixture must fit default RQ geometry");
    let dec_500m = decode_width_fixture_entry(size_500m as u64, block_500m, config.symbol_size);

    assert!(
        should_parallel_decode_entry(&dec_500m),
        "500M decode should retain parallel fanout: block_count={} max_block_size={block_500m}",
        entry_source_block_count(&dec_500m)
    );
    assert!(
        entry_decode_width_budget(&dec_500m, RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD) >= 48,
        "500M repair decode should keep wide fanout after size gating"
    );
    let budget_500m =
        rq_decode_width_budget_snapshot(std::slice::from_ref(&dec_500m), config.symbol_size);
    assert_eq!(
        budget_500m.effective,
        budget_500m.core_limit.min(budget_500m.memory_limit).max(1),
        "500M transfer decode budget should not be narrowed by the size gate"
    );
}

#[test]
fn rq_pacing_carries_path_rate_for_congestion_controller() {
    let pacing = RqSprayPacing::from_rate(
        RQ_COLD_START_PACING_BPS,
        1024,
        RQ_COLD_START_BURST_SYMBOLS,
        None,
        false,
    );
    let symbol_bytes =
        1024_u64.saturating_add(u64::try_from(AUTH_DGRAM_HEADER).unwrap_or(u64::MAX));

    assert_eq!(
        pacing.path_rate_bps,
        RQ_COLD_START_PACING_BPS.saturating_mul(8)
    );
    assert_eq!(pacing.datagram_bytes, u32::try_from(symbol_bytes).unwrap());
    assert_eq!(
        pacing.max_burst_size,
        u32::try_from(RQ_COLD_START_BURST_SYMBOLS).unwrap()
    );
}

#[test]
fn rq_round0_clean_ramp_requires_loss_free_target() {
    let clean = RqConfig {
        symbol_size: 1200,
        repair_overhead: 1.0,
        round0_loss_target: 0.0,
        debug_drop_one_in: 0,
        ..RqConfig::default()
    };
    let pacing = RqSprayPacing::cold_start(clean.symbol_size);

    assert!(round0_clean_ramp_enabled(&clean, pacing));
    assert!(round0_clean_ramp_enabled(
        &RqConfig {
            repair_overhead: RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_REPAIR_OVERHEAD,
            ..clean.clone()
        },
        RqSprayPacing::from_rate(
            RQ_COLD_START_PACING_BPS / 4,
            clean.symbol_size,
            RQ_ADAPTIVE_BURST_SYMBOLS,
            None,
            false,
        )
    ));

    for blocked in [
        RqConfig {
            round0_loss_target: RQ_ROUND0_TARGET_LOSS_ENABLE_MIN / 5.0,
            ..clean.clone()
        },
        RqConfig {
            round0_loss_target: RQ_ROUND0_TARGET_LOSS_ENABLE_MIN,
            ..clean.clone()
        },
        RqConfig {
            round0_loss_target: 0.02,
            ..clean.clone()
        },
        RqConfig {
            round0_loss_target: 0.10,
            ..clean.clone()
        },
        RqConfig {
            repair_overhead: 1.01,
            ..clean.clone()
        },
        RqConfig {
            debug_drop_one_in: 7,
            ..clean.clone()
        },
    ] {
        assert!(
            !round0_clean_ramp_enabled(&blocked, pacing),
            "clean ramp must stay off for good/lossy/debug/repair-configured round 0"
        );
    }

    let fanout = RqConfig {
        udp_fanout: 8,
        ..clean.clone()
    };
    assert!(
        round0_clean_ramp_enabled(&fanout, pacing),
        "fanout should share the aggregate clean ramp instead of disabling it"
    );
}

#[test]
fn rq_round0_clean_ramp_additively_probes_inside_source_round() {
    let mut pacing = RqSprayPacing::cold_start(1200);
    let mut ramp = RqRound0CleanPacingRamp::new(RQ_ROUND0_CLEAN_RAMP_MAX_PACING_BPS);
    let step_datagrams = RQ_ROUND0_CLEAN_RAMP_STEP_BYTES.div_ceil(u64::from(pacing.datagram_bytes));

    ramp.sent_datagrams = step_datagrams.saturating_sub(1);
    let first = ramp
        .observe_datagram(&mut pacing)
        .expect("first clean-ramp step");
    assert_eq!(
        first.new_rate_bytes_per_sec,
        RQ_COLD_START_PACING_BPS + RQ_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S
    );
    assert_eq!(
        pacing.rate_bytes_per_sec(),
        RQ_COLD_START_PACING_BPS + RQ_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S
    );

    ramp.sent_datagrams = ramp
        .next_step_bytes
        .div_ceil(u64::from(pacing.datagram_bytes))
        .saturating_sub(1);
    let second = ramp
        .observe_datagram(&mut pacing)
        .expect("second clean-ramp step");
    assert_eq!(
        second.new_rate_bytes_per_sec,
        RQ_COLD_START_PACING_BPS + RQ_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S * 2
    );
    assert_eq!(
        pacing.rate_bytes_per_sec(),
        RQ_COLD_START_PACING_BPS + RQ_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S * 2
    );

    while pacing.rate_bytes_per_sec() < RQ_ROUND0_CLEAN_RAMP_MAX_PACING_BPS {
        ramp.sent_datagrams = ramp
            .next_step_bytes
            .div_ceil(u64::from(pacing.datagram_bytes))
            .saturating_sub(1);
        let _ = ramp
            .observe_datagram(&mut pacing)
            .expect("clean ramp should keep stepping until max");
    }
    assert_eq!(
        pacing.rate_bytes_per_sec(),
        RQ_ROUND0_CLEAN_RAMP_MAX_PACING_BPS
    );
    assert!(
        pacing.rate_bytes_per_sec() > RQ_MAX_PACING_BPS,
        "clean round-0 probe must be able to test beyond the adaptive cap"
    );
}

#[test]
fn rq_round0_clean_ramp_caps_fanout_aggregate_rate() {
    let single = RqConfig {
        udp_fanout: 1,
        ..RqConfig::default()
    };
    let fanout = RqConfig {
        udp_fanout: 8,
        ..RqConfig::default()
    };
    assert_eq!(
        round0_clean_ramp_max_rate(&single),
        RQ_ROUND0_CLEAN_RAMP_MAX_PACING_BPS
    );
    assert_eq!(
        round0_clean_ramp_max_rate(&fanout),
        RQ_ROUND0_CLEAN_RAMP_FANOUT_MAX_PACING_BPS
    );

    let mut pacing = RqSprayPacing::cold_start(1200);
    let mut ramp = RqRound0CleanPacingRamp::new(round0_clean_ramp_max_rate(&fanout));
    while pacing.rate_bytes_per_sec() < RQ_ROUND0_CLEAN_RAMP_FANOUT_MAX_PACING_BPS {
        ramp.sent_datagrams = ramp
            .next_step_bytes
            .div_ceil(u64::from(pacing.datagram_bytes))
            .saturating_sub(1);
        let report = ramp
            .observe_datagram(&mut pacing)
            .expect("fanout ramp should step until aggregate cap");
        assert_eq!(
            report.max_rate_bytes_per_sec,
            RQ_ROUND0_CLEAN_RAMP_FANOUT_MAX_PACING_BPS
        );
    }
    assert_eq!(
        pacing.rate_bytes_per_sec(),
        RQ_ROUND0_CLEAN_RAMP_FANOUT_MAX_PACING_BPS
    );
}

#[test]
fn rq_round0_clean_ramp_resets_on_feedback_pacer_reconfigure() {
    let config = RqConfig {
        symbol_size: 1200,
        repair_overhead: 1.0,
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };
    let mut pacer = RqSprayPacer::new_round0(RqSprayPacing::cold_start(1200), &config, false);
    assert!(pacer.round0_ramp.is_some());

    pacer.configure_with_shared_decision(
        RqSprayPacing::from_rate(
            RQ_COLD_START_PACING_BPS / 2,
            1200,
            RQ_ADAPTIVE_BURST_SYMBOLS,
            Some(Duration::from_millis(200)),
            true,
        ),
        None,
    );

    assert!(pacer.round0_ramp.is_none());
    assert_eq!(
        pacer.pacing().rate_bytes_per_sec(),
        RQ_COLD_START_PACING_BPS / 2
    );
}

#[test]
fn rq_round0_clean_pacer_reports_ramped_rate_to_window_probe() {
    let config = RqConfig {
        symbol_size: 1200,
        repair_overhead: 1.0,
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };
    let mut pacer = RqSprayPacer::new_round0(RqSprayPacing::cold_start(1200), &config, false);
    let datagrams =
        RQ_ROUND0_CLEAN_RAMP_STEP_BYTES.div_ceil(u64::from(pacer.pacing().datagram_bytes.max(1)));
    for _ in 0..datagrams {
        pacer.observe_datagram_sent();
    }

    let probe = RqSenderWindowProbe::new(
        pacer.pacing(),
        1,
        config.symbol_size,
        Duration::from_millis(1),
        Duration::from_millis(200),
    );

    assert_eq!(
        probe.configured_rate_bytes_per_sec,
        RQ_COLD_START_PACING_BPS + RQ_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S,
        "ATP_RQ_TRACE window_probe should expose the within-round clean ramp"
    );
}

fn rq_test_path_estimate(config: &RqConfig, bytes_per_second: f64) -> PathEstimate {
    PathEstimate {
        rtt_s: 0.050,
        loss_p_hat: 0.0,
        loss_p_bar: 0.0,
        bw_median_bps: bytes_per_second,
        bw_trough_bps: bytes_per_second,
        enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
        dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
        coding_ref_k: fixed_block_k(config),
        coding_gamma: RQ_CODING_GAMMA,
        samples: 1,
    }
}

fn rq_test_block_plan(config: &RqConfig) -> BlockPlan {
    BlockPlan {
        k: fixed_block_k(config),
        overhead: 0.0,
        fanout: 1,
    }
}

#[test]
fn rq_pacing_preserves_measured_slow_link_without_loss() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let measured = 2_u64 * 1024 * 1024;
    state.est = rq_test_path_estimate(&config, measured as f64);

    let rate = state.pacing_rate_for(rq_test_block_plan(&config), &config);

    assert_eq!(rate, measured);
}

#[test]
fn rq_pacing_floors_mild_loss_collapse() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let collapsed = 42_u64 * 1024;
    state.est = rq_test_path_estimate(&config, collapsed as f64);
    state.loss_ema = 0.001;
    state.loss_bar = 0.01;
    state.pacing_loss_ema = 0.001;

    let rate = state.pacing_rate_for(rq_test_block_plan(&config), &config);

    assert!(
        rate >= RQ_COLD_START_PACING_BPS / 2,
        "mild loss should not pace a repair round at {rate} B/s"
    );
    assert!(
        rate > collapsed.saturating_mul(100),
        "floor should break the self-reinforcing 42KB/s collapse"
    );
}

#[test]
fn rq_pacing_floor_stays_off_for_regime_shift_loss() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let collapsed = 42_u64 * 1024;
    state.est = rq_test_path_estimate(&config, collapsed as f64);
    state.pacing_loss_ema = RQ_MILD_LOSS_PACING_MAX_LOSS * 2.0;
    state.loss_bar = RQ_REGIME_SHIFT_LOSS_DELTA;

    let rate = state.pacing_rate_for(rq_test_block_plan(&config), &config);

    assert_eq!(rate, RQ_MIN_PACING_BPS);
}

#[test]
fn rq_pacing_mild_loss_floor_overrides_stale_low_cap() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.est = rq_test_path_estimate(&config, 32.0 * 1024.0 * 1024.0);
    state.controller.update_estimate(state.est);
    state.loss_ema = 0.01;
    state.loss_bar = 0.02;
    state.pacing_loss_ema = RQ_MILD_LOSS_PACING_MAX_LOSS / 2.0;
    state.loss_pacing_cap_bps = Some(RQ_COLD_START_PACING_BPS / 4);

    let tuning = state.round_tuning(&config);

    assert_eq!(
        tuning.pacing.path_rate_bps,
        state.mild_loss_pacing_floor_bps(&config).saturating_mul(8),
        "stale mild-loss caps must not reintroduce the pacing crawl"
    );
}

#[test]
fn rq_good_link_source_first_feedback_uses_full_cold_start_floor() {
    let config = RqConfig {
        round0_loss_target: RQ_ROUND0_TARGET_LOSS_ENABLE_MIN / 5.0,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.est = rq_test_path_estimate(&config, 32.0 * 1024.0 * 1024.0);
    state.controller.update_estimate(state.est);
    state.loss_ema = 0.01;
    state.loss_bar = RQ_PENDING_PRESSURE_LOSS_FLOOR;
    state.pacing_loss_ema = config.round0_loss_target;
    state.loss_pacing_cap_bps = Some(RQ_COLD_START_PACING_BPS / 4);

    let tuning = state.round_tuning(&config);

    assert_eq!(
        tuning.pacing.rate_bytes_per_sec(),
        RQ_COLD_START_PACING_BPS,
        "sub-threshold good-link feedback should recover at cold-start instead of the half-rate repair floor"
    );
}

#[test]
fn rq_bad_link_feedback_keeps_conservative_mild_loss_floor() {
    let config = RqConfig {
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.est = rq_test_path_estimate(&config, 32.0 * 1024.0 * 1024.0);
    state.controller.update_estimate(state.est);
    state.loss_ema = 0.01;
    state.loss_bar = RQ_PENDING_PRESSURE_LOSS_FLOOR;
    state.pacing_loss_ema = config.round0_loss_target;
    state.loss_pacing_cap_bps = Some(RQ_COLD_START_PACING_BPS / 4);

    let tuning = state.round_tuning(&config);

    assert_eq!(
        tuning.pacing.rate_bytes_per_sec(),
        RQ_BAD_LINK_ROUND0_PACING_BPS,
        "configured bad-link repair-target cells must pace near the 50 mbit pipe instead of inheriting the good-link floor"
    );
}

#[test]
fn rq_aimd_halves_rate_on_receiver_observed_loss() {
    let config = RqConfig {
        symbol_size: 1200,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "large.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"large.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);
    let sent_symbols = 10_000_u64;

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        sent_symbols,
        9_400,
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(100),
        total_bytes,
    );

    assert!(state.last_round_loss_fraction > aimd_loss_decrease_threshold(&config));
    assert_eq!(state.aimd_rate_bps, RQ_COLD_START_PACING_BPS / 2);
}

#[test]
fn rq_aimd_prefers_explicit_receiver_loss_fraction() {
    let config = RqConfig {
        symbol_size: 1200,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "large.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"large.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        10_000,
        Some(0.06),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(100),
        total_bytes,
    );

    assert_eq!(state.last_round_loss_fraction, 0.06);
    assert_eq!(state.aimd_rate_bps, RQ_COLD_START_PACING_BPS / 2);
}

#[test]
fn rq_aimd_holds_rate_under_configured_loss_target() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "broken.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"broken.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        9_000,
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(100),
        total_bytes,
    );

    assert!((state.last_round_loss_fraction - 0.10).abs() < f64::EPSILON * 8.0);
    assert_eq!(
        state.aimd_rate_bps, RQ_BROKEN_LINK_ROUND0_PACING_BPS,
        "expected link loss should neither decrease nor increase the AIMD rate"
    );
    assert_eq!(
        state.loss_pacing_cap_bps, None,
        "expected-regime loss must not lower the loss-detector pacing cap (MATRIX-207)"
    );
}

#[test]
fn rq_aimd_holds_broken_link_cap_on_zero_loss_feedback() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "broken.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"broken-zero-loss"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        10_000,
        Some(0.0),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(200),
        total_bytes,
    );

    assert_eq!(state.last_round_loss_fraction, 0.0);
    assert_eq!(
        state.aimd_rate_bps, RQ_BROKEN_LINK_ROUND0_PACING_BPS,
        "explicitly lossy/broken cells must not treat zero-loss feedback as a clean-link additive increase"
    );
    assert_eq!(
        state.round_tuning(&config).pacing.rate_bytes_per_sec(),
        RQ_BROKEN_LINK_ROUND0_PACING_BPS,
        "repair rounds must keep the 10 mbit-class broken-link cap until real delivery evidence changes it"
    );
}

#[test]
fn rq_aimd_backs_off_when_broken_rank_progress_stalls_despite_zero_loss() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.aimd_rate_bps = RQ_COLD_START_PACING_BPS;
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "broken.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"broken-progress-stall"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more_with_progress(
        &config,
        &digests,
        &pending,
        total_bytes,
        RqNeedMoreProgress {
            pending_rank: Some(100),
            pending_rank_columns: Some(43_700),
            pending_rank_deficit: Some(43_600),
            pending_decode_jobs: Some(0),
        },
        10_000,
        6_000,
        Some(0.0),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(200),
        total_bytes,
    );

    assert!(
        state.last_round_loss_fraction > aimd_loss_decrease_threshold(&config),
        "arrival-corroborated rank stall must override underreported receiver loss"
    );
    assert_eq!(
        state.aimd_rate_bps, RQ_MIN_PACING_BPS,
        "stalled rank progress with depressed arrivals should back off to the sender-side delivery floor"
    );
    assert!(
        state.pacing_loss_ema > RQ_MILD_LOSS_PACING_MAX_LOSS,
        "progress-derived congestion must feed the pacing/loss detector path"
    );
}

#[test]
fn rq_aimd_holds_rate_when_rank_stalls_but_arrivals_complete() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.aimd_rate_bps = RQ_COLD_START_PACING_BPS;
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "broken.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"broken-stall-healthy-arrivals"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more_with_progress(
        &config,
        &digests,
        &pending,
        total_bytes,
        RqNeedMoreProgress {
            pending_rank: Some(100),
            pending_rank_columns: Some(43_700),
            pending_rank_deficit: Some(43_600),
            pending_decode_jobs: Some(0),
        },
        10_000,
        10_000,
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(200),
        total_bytes,
    );

    assert!(
        state.last_round_loss_fraction <= aimd_loss_decrease_threshold(&config),
        "a decode-side stall with complete arrivals is not congestion"
    );
    assert_eq!(
        state.aimd_rate_bps, RQ_COLD_START_PACING_BPS,
        "healthy arrivals must veto the rank-stall congestion proxy: slowing the \
         sender cannot un-stall a rank-deficient block (500M/broken collapse, MATRIX-207)"
    );
    assert!(
        state.pacing_loss_ema <= RQ_MILD_LOSS_PACING_MAX_LOSS,
        "an uncorroborated stall must not poison the pacing loss detector"
    );
}

#[test]
fn rq_aimd_holds_broken_cap_when_rank_progress_matches_offer() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "broken.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"broken-progress-healthy"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more_with_progress(
        &config,
        &digests,
        &pending,
        total_bytes,
        RqNeedMoreProgress {
            pending_rank: Some(8_500),
            pending_rank_columns: Some(43_700),
            pending_rank_deficit: Some(35_200),
            pending_decode_jobs: Some(0),
        },
        10_000,
        10_000,
        Some(0.0),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(1_000),
        Duration::from_millis(200),
        total_bytes,
    );

    assert_eq!(state.last_round_loss_fraction, 0.0);
    assert_eq!(
        state.aimd_rate_bps, RQ_BROKEN_LINK_ROUND0_PACING_BPS,
        "healthy rank progress should not back off below the configured broken-link cap"
    );
}

#[test]
fn rq_aimd_recovers_broken_link_cap_after_clean_feedback() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.aimd_rate_bps = RQ_MIN_PACING_BPS;
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "broken.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"broken-recovery"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        10_000,
        Some(0.0),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(200),
        total_bytes,
    );

    assert_eq!(
        state.aimd_rate_bps, RQ_BROKEN_LINK_ROUND0_PACING_BPS,
        "a conservative broken-link decrease must recover up to the 10 mbit-class cap on clean feedback"
    );
}

#[test]
fn rq_aimd_holds_rate_for_bad_link_loss_target() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "bad.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"bad.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        9_800,
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(100),
        total_bytes,
    );

    assert!((state.last_round_loss_fraction - 0.02).abs() < f64::EPSILON * 8.0);
    assert_eq!(
        state.aimd_rate_bps, RQ_BAD_LINK_ROUND0_PACING_BPS,
        "bad-cell target loss should hold the 50 mbit pacing cap, not pace up into self-loss"
    );
}

#[test]
fn rq_aimd_loss_target_backoff_uses_receiver_delivery_rate() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 500_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "bad.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"bad.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);
    state.aimd_rate_bps = RQ_COLD_START_PACING_BPS;

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        5_000,
        Some(0.50),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_secs(1),
        Duration::from_millis(80),
        total_bytes,
    );

    assert_eq!(state.last_round_loss_fraction, 0.50);
    assert!(
        state.aimd_rate_bps.abs_diff(6_600_000) <= 1,
        "loss-targeted overrun should back off to receiver delivery plus headroom, not blind half-rate"
    );
    assert!(
        state.aimd_rate_bps < RQ_COLD_START_PACING_BPS / 2,
        "delivery-rate backoff must be able to settle below blind half-rate on sub-100mbit paths"
    );
}

#[test]
fn rq_aimd_keeps_cold_start_floor_for_good_source_first_feedback() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.001,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 500_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "good.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"good.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        9_400,
        Some(0.06),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(800),
        Duration::from_millis(25),
        total_bytes,
    );

    assert_eq!(state.last_round_loss_fraction, 0.06);
    assert_eq!(
        state.aimd_rate_bps, RQ_COLD_START_PACING_BPS,
        "good-link source-first feedback should not halve below cold-start"
    );
    assert!(
        state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
        "repair sizing should still see pending pressure"
    );
    let tuning = state.round_tuning(&config);
    assert_eq!(
        tuning.pacing.path_rate_bps,
        RQ_COLD_START_PACING_BPS.saturating_mul(8),
        "feedback spray should keep the cold-start sender floor"
    );
}

#[test]
fn rq_aimd_additively_increases_on_clean_receiver_round() {
    let config = RqConfig {
        symbol_size: 1200,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 5_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "clean.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"clean.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);
    state.aimd_rate_bps = 4 * 1024 * 1024;

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        4_000,
        4_000,
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(400),
        Duration::from_millis(100),
        total_bytes,
    );

    assert_eq!(state.last_round_loss_fraction, 0.0);
    assert_eq!(
        state.aimd_rate_bps,
        4 * 1024 * 1024 + RQ_AIMD_ADDITIVE_INCREASE_BYTES_PER_S
    );
}

#[test]
fn rq_round_tuning_honors_persistent_aimd_cap() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.est = rq_test_path_estimate(&config, RQ_MAX_PACING_BPS as f64);
    state.controller.update_estimate(state.est);
    state.aimd_rate_bps = 4 * 1024 * 1024;
    state.aimd_feedback_seen = true;

    let tuning = state.round_tuning(&config);

    assert_eq!(
        tuning.pacing.path_rate_bps,
        state.aimd_rate_bps.saturating_mul(8),
        "AIMD decrease must cap the next sender spray instead of acting as a one-shot sample"
    );
}

#[test]
fn rq_shared_rate_decision_caps_next_pacer_burst() {
    let config = RqConfig {
        symbol_size: 1200,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = u64::from(config.symbol_size) * 2;
    let digests = [EntryDigest {
        rel_path: "receiver-credit.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"receiver-credit"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        10_000,
        1_000,
        Some(0.0),
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_secs(1),
        Duration::from_millis(100),
        total_bytes,
    );

    let decision = state
        .shared_rate_decision()
        .expect("NeedMore should feed shared datagram-rate controller");
    let expected_credit = rq_receiver_flow_credit_bytes(&config, total_bytes);
    assert!(
        decision.sender_loss_fraction_ppm >= 900_000,
        "shared controller must see sender-side queue overflow"
    );
    assert_eq!(
        decision.receiver_credit_bytes,
        Some(expected_credit),
        "pending receiver bytes should be translated into the controller receiver credit"
    );
    assert_eq!(
        decision.receiver_window_bytes,
        Some(expected_credit.saturating_add(decision.bytes_in_flight)),
        "receiver window should include still-outstanding sender payload plus remaining credit"
    );
    assert!(
        decision.send_budget_bytes <= expected_credit,
        "receiver credit must clip the immediate shared send budget"
    );

    let tuning = state.round_tuning(&config);
    assert!(
        tuning.pacing.rate_bytes_per_sec() <= decision.pacing_bytes_per_s,
        "RQ round tuning must consume the shared controller's pacing cap"
    );

    let mut pacer = RqSprayPacer::new_round0(tuning.pacing, &config, false);
    pacer.configure_with_shared_decision(tuning.pacing, Some(decision));
    let now = Instant::now();
    let mut immediate_budget = 0u32;
    while pacer.controller.try_consume_send_budget(now) {
        immediate_budget = immediate_budget.saturating_add(1);
        assert!(
            immediate_budget <= 2,
            "receiver-limited shared decision reopened burst {immediate_budget}"
        );
    }
    assert!(
        immediate_budget <= 2,
        "shared receiver credit should bound immediate RQ burst, got {immediate_budget}"
    );
}

#[test]
fn rq_round_tuning_applies_loss_detector_cap_after_aimd_feedback() {
    let config = RqConfig {
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.est = rq_test_path_estimate(&config, 32.0 * 1024.0 * 1024.0);
    state.controller.update_estimate(state.est);
    state.aimd_feedback_seen = true;
    state.aimd_rate_bps = RQ_COLD_START_PACING_BPS;
    state.loss_ema = 0.01;
    state.loss_bar = RQ_PENDING_PRESSURE_LOSS_FLOOR;
    state.pacing_loss_ema = config.round0_loss_target;
    state.loss_pacing_cap_bps = Some(RQ_COLD_START_PACING_BPS / 4);

    let tuning = state.round_tuning(&config);

    assert_eq!(
        tuning.pacing.rate_bytes_per_sec(),
        RQ_BAD_LINK_ROUND0_PACING_BPS,
        "loss-detector caps must remain active after AIMD feedback, bounded by the bad-link floor"
    );
}

#[test]
fn rq_need_more_entry_pressure_does_not_create_congestion_cap() {
    let config = RqConfig {
        symbol_size: 1024,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 5_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "large.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"large.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);
    let sent_symbols = total_bytes / u64::from(config.symbol_size);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        sent_symbols,
        sent_symbols.saturating_sub(1),
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_secs(120),
        Duration::from_millis(50),
        total_bytes,
    );

    assert!(
        state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
        "large residual entry should still raise the FEC sizing floor"
    );
    assert!(
        state.pacing_loss_ema <= RQ_MILD_LOSS_PACING_MAX_LOSS,
        "entry-level residual pressure must not masquerade as pacing loss"
    );
    assert_eq!(
        state.est.loss_p_bar, state.loss_bar,
        "adaptive path estimate must preserve pending-aware FEC pressure"
    );
    assert!(
        state.pacing_loss_bar < state.loss_bar,
        "wire-loss pacing bar must remain below pending-aware FEC pressure"
    );
    assert_eq!(
        state.loss_pacing_cap_bps, None,
        "one residual pending entry must not manufacture a congestion cap"
    );
    let rate = state.pacing_rate_for(rq_test_block_plan(&config), &config);
    assert!(
        rate >= RQ_COLD_START_PACING_BPS / 2,
        "mild residual repair should recover from the slow-sample floor, got {rate} B/s"
    );
}

#[test]
fn rq_need_more_mild_wire_loss_keeps_pending_pressure_out_of_pacing() {
    let config = RqConfig {
        symbol_size: 1200,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "large.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"large.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    for (sent_symbols, send_wall) in [
        (43_700_u64, Duration::from_millis(3_300)),
        (15_992, Duration::from_millis(12_300)),
        (15_992, Duration::from_millis(13_300)),
        (7_800, Duration::from_millis(12_000)),
        (7_800, Duration::from_millis(13_800)),
        (7_800, Duration::from_millis(15_000)),
    ] {
        let lost_symbols = sent_symbols.div_ceil(50);
        state.observe_need_more(
            &config,
            &digests,
            &pending,
            sent_symbols,
            sent_symbols.saturating_sub(lost_symbols),
            None,
            RqDeliverySampleKind::InitialOrRepair,
            send_wall,
            Duration::from_millis(200),
            total_bytes,
        );
    }

    assert!(
        state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
        "pending pressure should remain available for FEC sizing"
    );
    assert!(
        state.pacing_loss_ema <= RQ_MILD_LOSS_PACING_MAX_LOSS,
        "2% receiver-observed wire loss should keep the mild pacing floor active"
    );
    assert!(
        state.mild_loss_pacing_floor_applies(),
        "entry-granular pending pressure must not disable the pacing floor"
    );
    assert_eq!(
        state.est.loss_p_bar, state.loss_bar,
        "PathEstimate loss bar must keep pending-aware FEC pressure for repair sizing"
    );
    assert!(
        state.pacing_loss_bar < state.loss_bar,
        "receiver-observed wire loss may stay mild while FEC pressure remains high"
    );
    assert!(
        state.pacing_rate_for(rq_test_block_plan(&config), &config)
            >= state.mild_loss_pacing_floor_bps(&config),
        "stalled repair rounds must not drag pacing below the mild-loss floor"
    );
}

#[test]
fn rq_source_retransmit_undercredit_does_not_poison_pacing_estimator() {
    let config = RqConfig {
        symbol_size: 1200,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "large.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"large.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        15_992,
        1_884,
        None,
        RqDeliverySampleKind::SourceRetransmit,
        Duration::from_millis(12_300),
        Duration::from_millis(200),
        total_bytes,
    );

    assert_eq!(
        state.last_round_loss_fraction, 0.0,
        "under-credited source retransmit rounds must not become measured wire loss"
    );
    assert_eq!(
        state.pacing_loss_ema, 0.0,
        "source retransmit under-credit must stay out of pacing loss"
    );
    assert_eq!(
        state.pacing_loss_bar, 0.0,
        "source retransmit under-credit must not disable the pacing floor"
    );
    assert_eq!(
        state.loss_pacing_cap_bps, None,
        "source retransmit under-credit must not create a congestion cap"
    );
    assert!(
        state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
        "pending pressure should still size repair FEC"
    );
    assert_eq!(
        state.round_tuning(&config).pacing.rate_bytes_per_sec(),
        RQ_COLD_START_PACING_BPS,
        "source retransmit under-credit must not collapse the next path rate"
    );
}

#[test]
fn rq_mixed_source_and_fec_feedback_feeds_pacing_estimator() {
    assert_eq!(
        delivery_sample_kind_for_need_more_response(16, false),
        RqDeliverySampleKind::SourceRetransmit,
        "pure source retransmit under-credit should stay out of pacing loss"
    );
    assert_eq!(
        delivery_sample_kind_for_need_more_response(16, true),
        RqDeliverySampleKind::InitialOrRepair,
        "source retransmit plus FEC repair must feed receiver-observed wire loss into AIMD"
    );
    assert_eq!(
        delivery_sample_kind_for_need_more_response(0, false),
        RqDeliverySampleKind::InitialOrRepair,
        "repair-only feedback rounds are pacing samples"
    );
}

#[test]
fn rq_need_more_broken_wire_loss_disables_mild_floor() {
    let config = RqConfig {
        symbol_size: 1200,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let total_bytes = 50_u64 * 1024 * 1024;
    let digests = [EntryDigest {
        rel_path: "large.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"large.bin"),
        ),
        content_sha256: [0; 32],
    }];
    let pending = BTreeSet::from([0_u32]);
    let sent_symbols = 43_700_u64;

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        sent_symbols,
        sent_symbols.saturating_sub(sent_symbols.div_ceil(10)),
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(3_300),
        Duration::from_millis(200),
        total_bytes,
    );

    assert!(
        state.pacing_loss_ema > RQ_MILD_LOSS_PACING_MAX_LOSS,
        "10% receiver-observed wire loss should exceed the mild-loss threshold"
    );
    assert!(
        !state.mild_loss_pacing_floor_applies(),
        "broken-link wire loss must still allow conservative pacing"
    );
    assert!(
        state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
        "broken-link pending pressure should still size repair FEC"
    );
}

#[test]
fn rq_pending_send_batch_groups_by_round_robin_socket() {
    let mut batch = RqPendingSendBatch::new(4);
    let global_flush_symbols = batch.global_flush_symbols();
    assert_eq!(global_flush_symbols, RQ_SEND_BATCH_PER_SOCKET);
    for i in 0..global_flush_symbols {
        batch.push(i % 4, vec![u8::try_from(i).unwrap_or(u8::MAX)]);
    }

    assert_eq!(batch.queued_count(), global_flush_symbols);
    assert!(batch.should_flush());
    assert_eq!(batch.socket_batch_len(0), RQ_SEND_BATCH_PER_SOCKET / 4);
    assert_eq!(batch.socket_batch_len(1), RQ_SEND_BATCH_PER_SOCKET / 4);
    assert_eq!(batch.socket_batch_len(2), RQ_SEND_BATCH_PER_SOCKET / 4);
    assert_eq!(batch.socket_batch_len(3), RQ_SEND_BATCH_PER_SOCKET / 4);
}

#[test]
fn rq_pending_send_batch_caps_aggregate_burst_across_fanout() {
    let mut batch = RqPendingSendBatch::new(8);
    let almost_full = batch.global_flush_symbols().saturating_sub(1);

    for i in 0..almost_full {
        batch.push(i % batch.fanout(), vec![u8::try_from(i).unwrap_or(u8::MAX)]);
    }

    assert!(!batch.should_flush());
    assert!(
        batch
            .by_socket
            .iter()
            .all(|payloads| payloads.len() < RQ_SEND_BATCH_PER_SOCKET)
    );

    batch.push(almost_full % batch.fanout(), vec![0]);
    assert!(batch.should_flush());
    assert_eq!(batch.queued_count(), RQ_SEND_BATCH_PER_SOCKET);
    assert!(
        batch
            .by_socket
            .iter()
            .all(|payloads| payloads.len() <= RQ_SEND_BATCH_PER_SOCKET.div_ceil(8))
    );
}

#[test]
fn rq_pending_send_batch_flushes_on_single_socket_bound() {
    let mut batch = RqPendingSendBatch::new(4);
    for i in 0..RQ_SEND_BATCH_PER_SOCKET {
        batch.push(0, vec![u8::try_from(i).unwrap_or(u8::MAX)]);
    }

    assert_eq!(batch.queued_count(), RQ_SEND_BATCH_PER_SOCKET);
    assert!(batch.should_flush());
    assert_eq!(batch.socket_batch_len(0), RQ_SEND_BATCH_PER_SOCKET);
    assert_eq!(batch.socket_batch_len(1), 0);
}

#[test]
fn rq_default_authenticated_datagrams_plan_as_one_gso_super_packet() {
    let dst_addr: SocketAddr = "127.0.0.1:9000".parse().expect("socket address");
    let ctx = SecurityContext::for_testing(77);
    let payloads = (0..RQ_SEND_BATCH_PER_SOCKET)
        .map(|esi| {
            let sym = Symbol::new(
                SymbolId::new(
                    ObjectId::new(1, 2),
                    0,
                    u32::try_from(esi).expect("test ESI fits u32"),
                ),
                vec![u8::try_from(esi).unwrap_or(u8::MAX); usize::from(DEFAULT_SYMBOL_SIZE)],
                SymbolKind::Source,
            );
            let auth = ctx.sign_symbol(&sym);
            encode_symbol_datagram(0xABCD, 0, &sym, Some(auth.tag()))
        })
        .collect::<Vec<_>>();

    assert!(
        payloads.iter().all(|payload| {
            payload.len() == AUTH_DGRAM_HEADER + usize::from(DEFAULT_SYMBOL_SIZE)
        }),
        "default authenticated RQ datagrams must keep fixed GSO segment size",
    );

    let packets = payloads
        .iter()
        .map(|payload| crate::net::UdpOutboundDatagram { dst_addr, payload })
        .collect::<Vec<_>>();
    let plan = crate::net::UdpSendBatchPlan::for_packets(
        &packets,
        crate::net::UdpSendAccelerationCapabilities {
            sendmmsg: crate::net::UdpCapability::Supported,
            gso: crate::net::UdpCapability::Supported,
            max_sendmmsg_batch: crate::net::UDP_MAX_SENDMMSG_BATCH,
            max_gso_segments: crate::net::UDP_MAX_GSO_SEGMENTS,
        },
        crate::net::UdpSendBatchStrategy::default(),
    );

    assert_eq!(plan.path, crate::net::UdpSendBatchPath::Gso);
    assert_eq!(plan.estimated_syscalls, 1);
    assert_eq!(plan.gso_segments_per_packet, Some(RQ_SEND_BATCH_PER_SOCKET));
    assert_eq!(
        plan.gso_segment_bytes,
        Some(AUTH_DGRAM_HEADER + usize::from(DEFAULT_SYMBOL_SIZE))
    );
}

#[test]
fn rq_batched_send_yields_when_progress_crosses_boundary() {
    assert!(!send_progress_crossed_yield_boundary(0, 63));
    assert!(send_progress_crossed_yield_boundary(63, 64));
    assert!(send_progress_crossed_yield_boundary(60, 96));
    assert!(!send_progress_crossed_yield_boundary(64, 96));
}

#[test]
fn rq_sender_window_probe_estimates_bdp_limited_window() {
    let pacing = RqSprayPacing::from_rate(
        16 * 1024 * 1024,
        1000,
        RQ_COLD_START_BURST_SYMBOLS,
        None,
        false,
    );
    let probe = RqSenderWindowProbe::new(
        pacing,
        13_200,
        1000,
        Duration::from_secs(1),
        Duration::from_millis(200),
    );

    assert_eq!(probe.payload_bytes, 13_200_000);
    assert_eq!(probe.observed_payload_bytes_per_sec, 13_200_000);
    assert_eq!(probe.observed_payload_window_bytes, 2_640_000);
    assert_eq!(probe.configured_rate_bytes_per_sec, 16 * 1024 * 1024);
    assert_eq!(probe.configured_bdp_bytes, 0);
    assert_eq!(
        probe.configured_control_window_bytes,
        rate_window_bytes(16 * 1024 * 1024, Duration::from_millis(200))
    );
    assert_eq!(
        probe.peak_window_bytes(),
        probe
            .configured_bdp_bytes
            .max(probe.configured_control_window_bytes)
            .max(probe.observed_payload_window_bytes)
            .max(probe.observed_wire_window_bytes)
    );
}

#[test]
fn rq_loss_recommendations_apply_advisory_caps_and_fec_floor() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.bw_ema_bps = 10_000_000.0;

    state.apply_loss_recommendations(
        &[
            LossRecommendation::ReduceCongestionWindow { factor: 0.5 },
            LossRecommendation::EnableFec { rate: 0.10 },
            LossRecommendation::SwitchCongestionControl {
                algorithm: "bbr".to_string(),
            },
        ],
        false,
    );

    assert_eq!(state.loss_pacing_cap_bps, Some(5_000_000));
    assert!(state.loss_fec_floor >= 0.10);
    assert!(state.regime_shift);
}

#[test]
fn rq_loss_recommendations_keep_wire_rate_under_expected_regime_loss() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    state.bw_ema_bps = 10_000_000.0;

    state.apply_loss_recommendations(
        &[
            LossRecommendation::ReduceCongestionWindow { factor: 0.5 },
            LossRecommendation::EnablePacing { rate: 1_000_000 },
            LossRecommendation::EnableFec { rate: 0.10 },
        ],
        true,
    );

    assert_eq!(
        state.loss_pacing_cap_bps, None,
        "loss at or below the regime's expectation is the ambient erasure \
         condition FEC pays for, not congestion — the pacing cap must not \
         drop (500M/broken repair-round collapse, MATRIX-207)"
    );
    assert!(
        state.loss_fec_floor >= 0.10,
        "FEC sizing must stay available under expected loss"
    );
    assert!(!state.regime_shift);
}

#[test]
fn rq_feedback_bandwidth_uses_send_wall_not_feedback_wait() {
    let config = RqConfig::default();
    let mut state = RqAdaptiveSendState::new(23, &config, 1);
    let total_bytes = 5 * 1024 * 1024_u64;
    let sent_symbols = total_bytes.div_ceil(u64::from(config.symbol_size.max(1)));
    let digests = vec![EntryDigest {
        rel_path: "payload.bin".to_string(),
        size: total_bytes,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(b"rq-feedback-bandwidth"),
        ),
        content_sha256: [0x42; 32],
    }];
    let pending = BTreeSet::from([0]);

    state.observe_need_more(
        &config,
        &digests,
        &pending,
        sent_symbols,
        sent_symbols,
        None,
        RqDeliverySampleKind::InitialOrRepair,
        Duration::from_millis(300),
        Duration::from_secs(120),
        total_bytes,
    );

    assert!(
        state.bw_ema_bps > 8.0 * 1024.0 * 1024.0,
        "feedback timeout must not collapse a fast spray sample to {} B/s",
        state.bw_ema_bps
    );
}

/// In-process encode→feed→decode roundtrip at a chosen `(bytes, max_block)`,
/// mirroring exactly how `spray_round` encodes and `feed_symbol` decodes —
/// but with NO network — so a coding/params mismatch is isolated from the
/// transport. Feeds source + a generous repair tail and asserts the block
/// decodes back to the original bytes.
fn coding_roundtrip(len: usize, max_block: usize, symbol_size: u16) -> bool {
    let bytes: Vec<u8> = (0..len)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let object_id = entry_object_id("test-transfer", 0);

    // Encode: source + repair (generous), like spray_round.
    let block_k = max_block.div_ceil(usize::from(symbol_size.max(1))).max(1);
    let repair = block_k; // 100% repair — far more than needed
    let pool = SymbolPool::new(PoolConfig::default());
    let mut enc = EncodingPipeline::new(
        crate::config::EncodingConfig {
            repair_overhead: 1.5,
            max_block_size: max_block,
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        pool,
    );
    let symbols: Vec<Symbol> = enc
        .encode_with_repair(object_id, &bytes, repair)
        .map(|e| e.unwrap().into_symbol())
        .collect();

    // Decode: feed all symbols, like feed_symbol.
    let dconfig = DecodingConfig {
        symbol_size,
        max_block_size: max_block,
        repair_overhead: 1.5,
        min_overhead: 0,
        max_buffered_symbols: 0,
        block_timeout: std::time::Duration::from_secs(0),
        verify_auth: false,
    };
    let mut dec = DecodingPipeline::new(dconfig);
    let params = object_params_for(object_id, len as u64, symbol_size, max_block as u64);
    dec.set_object_params(params).expect("set_object_params");
    for s in symbols {
        let _ = dec.feed(AuthenticatedSymbol::new_unauthenticated(s));
    }
    if !dec.is_complete() {
        return false;
    }
    let mut out = dec.into_data().expect("into_data");
    out.truncate(len);
    out == bytes
}

#[test]
fn coding_roundtrip_small_k_single_block() {
    // K = 64 (matches the loopback e2e regime).
    assert!(coding_roundtrip(60_000, 64 * 1024, 1024));
}

#[test]
fn coding_roundtrip_k512_single_block() {
    // K = 512 single 8 MiB block — the default-config regime that the
    // cross-machine transfer exercised. Regression guard for the
    // never-converges bug.
    assert!(coding_roundtrip(512 * 1024, 8 * 1024 * 1024, 1024));
}

#[test]
fn coding_roundtrip_multi_block_small_k() {
    // Three 64 KiB blocks at K=64 exercises SBN routing, per-block decode,
    // and final cross-block assembly without making the normal unit lane
    // pay the K=1024 matrix cost of the historical fleet repro.
    assert!(coding_roundtrip(3 * 64 * 1024, 64 * 1024, 1024));
}

#[test]
fn default_k_multiblock_metadata_is_accepted_by_decoder() {
    // Regression guard for br-asupersync-c8m8ha: the default-ish multi-block
    // shape used to fail at set_object_params before any network I/O. Keep
    // this as metadata-only coverage so the guard stays cheap and stable.
    let len = 3 * 1024 * 1024;
    let max_block = 1024 * 1024;
    let symbol_size = 1024;
    let object_id = entry_object_id("test-transfer", 0);
    let dconfig = DecodingConfig {
        symbol_size,
        max_block_size: max_block,
        repair_overhead: 1.5,
        min_overhead: 0,
        max_buffered_symbols: 0,
        block_timeout: std::time::Duration::from_secs(0),
        verify_auth: false,
    };
    let mut dec = DecodingPipeline::new(dconfig);
    let params = object_params_for(object_id, len as u64, symbol_size, max_block as u64);
    assert_eq!(params.source_blocks, 3);
    assert_eq!(params.symbols_per_block, 1024);
    dec.set_object_params(params)
        .expect("default-ish multi-block params must match decoder plan");
}

#[test]
fn safe_base_for_root_name_contains_hostile_inputs() {
    // Regression guard: a malicious sender controls `root_name` off the
    // wire. It must never escape `dest_dir`, even when absolute or
    // separator-bearing (Path::join replaces the base for absolute args).
    let dest = Path::new("/dst");
    assert_eq!(
        safe_base_for_root_name(dest, "payload").unwrap(),
        dest.join("payload")
    );
    // Hostile names fail closed instead of being silently rewritten.
    assert!(safe_base_for_root_name(dest, "/etc/cron.d/evil").is_err());
    assert!(safe_base_for_root_name(dest, "../../etc/passwd").is_err());
    assert!(safe_base_for_root_name(dest, "").is_err());
    assert!(safe_base_for_root_name(dest, "/").is_err());
    assert!(safe_base_for_root_name(dest, "..").is_err());
    assert!(safe_base_for_root_name(dest, "NUL.txt").is_err());
}

fn bare_metadata_manifest<'a>(
    logical_paths: impl IntoIterator<Item = &'a str>,
) -> RqMetadataManifest {
    let canonical = logical_paths
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|path| (path.to_string(), EntryMetadata::default()))
        .collect::<Vec<_>>();
    let canonical_refs = canonical
        .iter()
        .map(|(path, metadata)| (path.as_str(), metadata))
        .collect::<Vec<_>>();
    RqMetadataManifest {
        version: RQ_METADATA_MANIFEST_VERSION,
        commitment_hex: rq_metadata_commitment(&canonical_refs),
        entries: Vec::new(),
        directories: None,
    }
}

fn manifest_with(entries: Vec<ManifestEntry>, total_bytes: u64) -> TransferManifest {
    let metadata = bare_metadata_manifest(entries.iter().flat_map(|entry| {
        if let Some(fragment) = &entry.fragment {
            vec![fragment.rel_path.as_str()]
        } else if entry.members.is_empty() {
            vec![entry.rel_path.as_str()]
        } else {
            entry
                .members
                .iter()
                .map(|member| member.rel_path.as_str())
                .collect()
        }
    }));
    TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "payload".to_string(),
        is_directory: true,
        total_bytes,
        merkle_root_hex: "0".repeat(64),
        metadata: Some(metadata),
        delta_manifest: None,
        entries,
    }
}

fn rq_delta_manifest_for_bytes(bytes: &[u8]) -> TransferManifest {
    assert!(!bytes.is_empty());
    let rel_path = "payload.bin";
    let digest = digest_for_bytes(rel_path, bytes);
    let tree_id = flat_merkle_root_from_digests(std::slice::from_ref(&digest));
    let content_id = ContentId::from_bytes(bytes);
    let size_bytes = u64::try_from(bytes.len()).unwrap();
    let planner = PersistentChunkManifest::new(
        tree_id.clone(),
        vec![CasChunkRef {
            index: 0,
            byte_offset: 0,
            size_bytes,
            content_id: content_id.clone(),
        }],
    )
    .unwrap();
    TransferManifest {
        transfer_id: "rqdelta1".to_string(),
        root_name: rel_path.to_string(),
        is_directory: false,
        total_bytes: size_bytes,
        merkle_root_hex: tree_id.clone(),
        metadata: Some(bare_metadata_manifest([rel_path])),
        delta_manifest: Some(DeltaManifestWire {
            schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
            tree_id,
            chunk_size: bytes.len(),
            total_size_bytes: size_bytes,
            merkle_root_hex: planner.merkle_root.to_hex(),
            chunks: vec![DeltaChunkWire {
                index: 0,
                entry_index: 0,
                rel_path: rel_path.to_string(),
                entry_offset: 0,
                stream_offset: 0,
                size_bytes,
                content_id_hex: content_id.to_hex(),
            }],
        }),
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: rel_path.to_string(),
            size: size_bytes,
            sha256_hex: hex_encode(&digest.content_sha256),
            members: Vec::new(),
            fragment: None,
        }],
    }
}

fn rq_delta_test_hello(sender_nonce: TransferNonce) -> Hello {
    Hello {
        protocol: ATP_RQ_PROTOCOL,
        role: "sender".to_string(),
        peer_id: "sender-peer".to_string(),
        symbol_size: DEFAULT_SYMBOL_SIZE,
        max_block_size: DEFAULT_MAX_BLOCK_SIZE as u64,
        symbol_auth: true,
        total_bytes: 7,
        prefer_control_source_stream: true,
        delta_transfer_nonce: Some(sender_nonce),
        delta_client_auth_tag: None,
    }
}

fn rq_delta_test_ack(
    context: &SecurityContext,
    hello: &Hello,
) -> (HelloAck, RqDeltaHandshakeContext) {
    let sender_nonce = hello.delta_transfer_nonce.unwrap();
    let mut ack = HelloAck {
        accepted: true,
        peer_id: "receiver-peer".to_string(),
        udp_port: 0,
        udp_ports: Vec::new(),
        control_source_stream: true,
        reason: None,
        delta_transfer_nonce: Some(sender_nonce),
        delta_receiver_nonce: Some(TransferNonce::new([0x22; 32])),
        delta_destination_root: Some([0x33; 32]),
        delta_server_auth_tag: None,
    };
    ack.delta_server_auth_tag = Some(sign_rq_delta_ack(context, hello, &ack).unwrap());
    let handshake = validate_rq_delta_ack(context, hello, &ack)
        .unwrap()
        .unwrap();
    (ack, handshake)
}

#[test]
fn rq_delta_initial_offer_requires_live_strict_key_possession() {
    let context = SecurityContext::for_testing(0xD3_17_A0);
    let wrong_context = SecurityContext::for_testing(0xBAD0_0BAD);
    let mut hello = rq_delta_test_hello(TransferNonce::new([0x11; 32]));
    hello.delta_client_auth_tag = Some(sign_rq_delta_hello(&context, &hello).unwrap());

    assert_eq!(
        validate_rq_delta_hello(Some(&context), &hello).unwrap(),
        hello.delta_transfer_nonce
    );
    assert!(validate_rq_delta_hello(Some(&wrong_context), &hello).is_err());

    let mut tampered = hello.clone();
    tampered.peer_id.push_str("-tampered");
    assert!(validate_rq_delta_hello(Some(&context), &tampered).is_err());

    let mut partial = hello.clone();
    partial.delta_client_auth_tag = None;
    assert!(validate_rq_delta_hello(Some(&context), &partial).is_err());

    let mut legacy = hello;
    legacy.delta_transfer_nonce = None;
    legacy.delta_client_auth_tag = None;
    assert_eq!(validate_rq_delta_hello(None, &legacy).unwrap(), None);
}

#[test]
fn rq_delta_ack_is_fail_closed_and_decline_is_authenticated() {
    let context = SecurityContext::for_testing(0xD3_17_A0);
    let wrong_context = SecurityContext::for_testing(0xBAD0_0BAD);
    let mut hello = rq_delta_test_hello(TransferNonce::new([0x11; 32]));
    hello.delta_client_auth_tag = Some(sign_rq_delta_hello(&context, &hello).unwrap());
    let (ack, _handshake) = rq_delta_test_ack(&context, &hello);

    assert!(
        validate_rq_delta_ack(&context, &hello, &ack)
            .unwrap()
            .is_some()
    );
    assert!(validate_rq_delta_ack(&wrong_context, &hello, &ack).is_err());

    let mut tampered = ack.clone();
    tampered.peer_id.push_str("-tampered");
    assert!(validate_rq_delta_ack(&context, &hello, &tampered).is_err());

    let mut wrong_echo = ack.clone();
    wrong_echo.delta_transfer_nonce = Some(TransferNonce::new([0x44; 32]));
    wrong_echo.delta_server_auth_tag =
        Some(sign_rq_delta_ack(&context, &hello, &wrong_echo).unwrap());
    assert!(matches!(
        validate_rq_delta_ack(&context, &hello, &wrong_echo),
        Err(RqError::Authentication(_))
    ));

    let mut partial = ack.clone();
    partial.delta_receiver_nonce = None;
    partial.delta_server_auth_tag = Some(sign_rq_delta_ack(&context, &hello, &partial).unwrap());
    assert!(matches!(
        validate_rq_delta_ack(&context, &hello, &partial),
        Err(RqError::Authentication(_))
    ));

    let mut decline = ack;
    decline.delta_receiver_nonce = None;
    decline.delta_destination_root = None;
    decline.delta_server_auth_tag = None;
    decline.delta_server_auth_tag = Some(sign_rq_delta_ack(&context, &hello, &decline).unwrap());
    assert_eq!(
        validate_rq_delta_ack(&context, &hello, &decline).unwrap(),
        None
    );
    decline.delta_server_auth_tag = None;
    assert!(matches!(
        validate_rq_delta_ack(&context, &hello, &decline),
        Err(RqError::Authentication(_))
    ));
}

#[test]
fn rq_delta_requires_strict_mode_and_uses_private_destination_salt() {
    let strict = SecurityContext::for_testing(0xD3_17_A0);
    let permissive =
        SecurityContext::for_testing_with_mode(0xD3_17_A0, crate::security::AuthMode::Permissive);
    let disabled =
        SecurityContext::for_testing_with_mode(0xD3_17_A0, crate::security::AuthMode::Disabled);
    let strict_config = RqConfig::default().with_symbol_auth(strict.clone());
    let permissive_config = RqConfig::default().with_symbol_auth(permissive);
    let disabled_config = RqConfig::default().with_symbol_auth(disabled);
    assert!(rq_delta_control_auth_context(&strict_config).is_some());
    assert!(rq_delta_control_auth_context(&permissive_config).is_none());
    assert!(rq_delta_control_auth_context(&disabled_config).is_none());

    let nonce = TransferNonce::new([0x22; 32]);
    let path = Path::new("/receiver/private-destination");
    let first = rq_delta_destination_root_commitment(&strict, nonce, path, &[0x41; 32]).unwrap();
    let second = rq_delta_destination_root_commitment(&strict, nonce, path, &[0x42; 32]).unwrap();
    assert_ne!(first, second, "private salt must blind path equality");
    let binding = RqDeltaDestinationBinding {
        receiver_secret_salt: [0x41; 32],
        commitment: first,
    };
    validate_rq_delta_destination_binding(&binding, &strict, nonce, path).unwrap();
    assert!(
        validate_rq_delta_destination_binding(
            &binding,
            &strict,
            nonce,
            Path::new("/receiver/other-destination"),
        )
        .is_err()
    );
}

#[test]
fn rq_delta_control_rejects_spoof_tamper_and_cross_session_replay() {
    let context = SecurityContext::for_testing(0xD3_17_A0);
    let wrong_context = SecurityContext::for_testing(0xBAD0_0BAD);
    let hello = rq_delta_test_hello(TransferNonce::new([0x11; 32]));
    let (_ack, handshake) = rq_delta_test_ack(&context, &hello);
    let manifest = rq_delta_manifest_for_bytes(b"payload");
    validate_manifest(&manifest, &RqConfig::default()).unwrap();
    let session =
        derive_rq_delta_session(handshake, &hello.peer_id, "receiver-peer", &manifest).unwrap();
    let envelope = make_rq_delta_manifest_envelope(&context, session, &manifest).unwrap();
    validate_rq_delta_manifest_envelope(&context, session, &envelope).unwrap();
    assert!(validate_rq_delta_manifest_envelope(&wrong_context, session, &envelope).is_err());

    let mut exact_tamper = envelope.clone();
    exact_tamper.manifest.transfer_id.push('x');
    assert!(validate_rq_delta_manifest_envelope(&context, session, &exact_tamper).is_err());
    let mut replay_handshake = handshake;
    replay_handshake.receiver_nonce = TransferNonce::new([0x55; 32]);
    let replay_session =
        derive_rq_delta_session(replay_handshake, &hello.peer_id, "receiver-peer", &manifest)
            .unwrap();
    assert!(validate_rq_delta_manifest_envelope(&context, replay_session, &envelope).is_err());

    let delta = manifest.delta_manifest.as_ref().unwrap();
    let request = DeltaObjectRequest {
        mode: DeltaWireMode::AlreadyInSync,
        fallback_reason: None,
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some(delta.merkle_root_hex.clone()),
        missing_bytes: 0,
        shared_chunks: 1,
        stale_chunks: 0,
        missing_chunks: Vec::new(),
    };
    let request_envelope =
        make_rq_delta_request_envelope(&context, session, &manifest, request, 0, Vec::new())
            .unwrap();
    assert_eq!(
        validate_rq_delta_request_envelope(&context, session, &manifest, &request_envelope, true,)
            .unwrap(),
        DeltaWireMode::AlreadyInSync
    );
    let mut spoofed_request = request_envelope.clone();
    spoofed_request.request.shared_chunks = 0;
    assert!(
        validate_rq_delta_request_envelope(&context, session, &manifest, &spoofed_request, true,)
            .is_err()
    );
    assert!(
        validate_rq_delta_request_envelope(
            &context,
            replay_session,
            &manifest,
            &request_envelope,
            true,
        )
        .is_err()
    );

    let complete = make_rq_delta_complete(&context, session, &manifest).unwrap();
    validate_rq_delta_complete(&context, session, &manifest, &complete).unwrap();
    let mut tampered_complete = complete;
    tampered_complete.control_seq = 9;
    assert!(validate_rq_delta_complete(&context, session, &manifest, &tampered_complete).is_err());

    let canonical_receipt = ReceiveReceipt {
        committed: true,
        bytes_received: 0,
        files: 1,
        sha_ok: true,
        merkle_ok: true,
        symbols_accepted: 0,
        feedback_rounds: 0,
        reason: None,
        committed_paths: Vec::new(),
    };
    let proof =
        make_rq_delta_proof(&context, session, &manifest, canonical_receipt.clone()).unwrap();
    validate_rq_delta_proof(&context, session, &manifest, proof).unwrap();
    let noncanonical_receipt = ReceiveReceipt {
        committed_paths: vec!["/secret/destination/payload.bin".to_string()],
        ..canonical_receipt
    };
    let noncanonical =
        make_rq_delta_proof(&context, session, &manifest, noncanonical_receipt).unwrap();
    assert!(validate_rq_delta_proof(&context, session, &manifest, noncanonical).is_err());
}

#[test]
fn rq_delta_full_request_ports_have_one_canonical_encoding() {
    let context = SecurityContext::for_testing(0xD3_17_A0);
    let hello = rq_delta_test_hello(TransferNonce::new([0x11; 32]));
    let (_ack, handshake) = rq_delta_test_ack(&context, &hello);
    let manifest = rq_delta_manifest_for_bytes(b"payload");
    let session =
        derive_rq_delta_session(handshake, &hello.peer_id, "receiver-peer", &manifest).unwrap();
    let full = DeltaObjectRequest::full(
        manifest
            .delta_manifest
            .as_ref()
            .unwrap()
            .merkle_root_hex
            .clone(),
        None,
        "full_object_required",
    );
    let canonical = make_rq_delta_request_envelope(
        &context,
        session,
        &manifest,
        full.clone(),
        4001,
        vec![4001, 4002],
    )
    .unwrap();
    assert_eq!(
        validate_rq_delta_request_envelope(&context, session, &manifest, &canonical, false,)
            .unwrap(),
        DeltaWireMode::FullObject
    );

    for (primary, ports) in [
        (4001, vec![4002, 4001]),
        (4001, vec![4001, 4001]),
        (4001, vec![4001, 0]),
        (0, vec![4001]),
    ] {
        let malformed = make_rq_delta_request_envelope(
            &context,
            session,
            &manifest,
            full.clone(),
            primary,
            ports,
        )
        .unwrap();
        assert!(
            validate_rq_delta_request_envelope(&context, session, &manifest, &malformed, false,)
                .is_err()
        );
    }
    assert!(
        validate_rq_delta_request_envelope(&context, session, &manifest, &canonical, true,)
            .is_err()
    );
}

#[test]
fn rq_delta_manifest_is_strict_and_bounded() {
    let benchmark_bytes = 500_u64 * 1024 * 1024;
    assert!(
        benchmark_bytes.div_ceil(u64::try_from(RQ_DELTA_CHUNK_SIZE).unwrap())
            <= RQ_DELTA_MAX_MANIFEST_CHUNKS,
        "the default 500 MiB resync file must remain delta-eligible"
    );
    let manifest = rq_delta_manifest_for_bytes(b"payload");
    validate_rq_delta_manifest(&manifest).unwrap();

    let mut too_many = manifest.clone();
    let chunk = too_many
        .delta_manifest
        .as_ref()
        .unwrap()
        .chunks
        .first()
        .unwrap()
        .clone();
    too_many.delta_manifest.as_mut().unwrap().chunks =
        vec![chunk; usize::try_from(RQ_DELTA_MAX_MANIFEST_CHUNKS + 1).unwrap()];
    assert!(validate_rq_delta_manifest(&too_many).is_err());

    let context = SecurityContext::for_testing(0xD3_17_A0);
    let hello = rq_delta_test_hello(TransferNonce::new([0x11; 32]));
    let (_ack, handshake) = rq_delta_test_ack(&context, &hello);
    let session =
        derive_rq_delta_session(handshake, &hello.peer_id, "receiver-peer", &manifest).unwrap();
    let envelope = make_rq_delta_manifest_envelope(&context, session, &manifest).unwrap();
    let mut outer = serde_json::to_value(&envelope).unwrap();
    outer
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<RqDeltaManifestEnvelope>(outer).is_err());

    let mut nested = serde_json::to_value(&envelope).unwrap();
    nested["manifest"]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<RqDeltaManifestEnvelope>(nested).is_err());
}

#[test]
fn rq_delta_live_file_selects_noop_and_revalidates_source() {
    futures_lite::future::block_on(async {
        let cx = Cx::for_testing();
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("payload.bin");
        std::fs::write(&source, b"payload").unwrap();
        let (root_name, is_directory, mut entries, empty_directories) =
            collect_entries(&source).await.unwrap();
        assert!(!is_directory);
        assert!(empty_directories.is_empty());

        let mut config =
            RqConfig::default().with_symbol_auth(SecurityContext::for_testing(0xD3_17_A0));
        config.enable_delta = true;
        capture_source_metadata(
            &mut entries,
            &config.metadata_policy,
            config.preserve_hardlinks,
        )
        .await
        .unwrap();
        let metadata =
            metadata_manifest_from_source_entries(&entries, DirectoryMetadataManifest::default());
        let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
        let (size, content_id, content_sha256) =
            hash_source_entry_streaming(&entries[0], &mut hash_buf)
                .await
                .unwrap();
        let digest = EntryDigest {
            rel_path: entries[0].rel_path.clone(),
            size,
            content_id,
            content_sha256,
        };
        let merkle_root_hex = flat_merkle_root_from_digests(std::slice::from_ref(&digest));
        let mut manifest = TransferManifest {
            transfer_id: transfer_id_hex(&merkle_root_hex, size, 1),
            root_name: root_name.clone(),
            is_directory,
            total_bytes: size,
            merkle_root_hex,
            metadata: Some(metadata),
            delta_manifest: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: entries[0].rel_path.clone(),
                size,
                sha256_hex: hex_encode(&digest.content_sha256),
                members: Vec::new(),
                fragment: None,
            }],
        };
        maybe_attach_rq_delta_manifest(&cx, &mut manifest, &entries, &config)
            .await
            .unwrap();
        assert!(manifest.delta_manifest.is_some());
        validate_manifest(&manifest, &config).unwrap();

        let dest = tempfile::tempdir().unwrap();
        let destination = dest.path().join(&root_name);
        std::fs::write(&destination, b"payload").unwrap();
        let request = build_rq_receiver_delta_request(&cx, dest.path(), &config, &manifest)
            .await
            .unwrap();
        assert_eq!(request.mode, DeltaWireMode::AlreadyInSync);

        std::fs::write(&destination, b"PAYLOAD").unwrap();
        let changed = build_rq_receiver_delta_request(&cx, dest.path(), &config, &manifest)
            .await
            .unwrap();
        assert_eq!(changed.mode, DeltaWireMode::FullObject);
        assert_eq!(
            changed.fallback_reason.as_deref(),
            Some("full_object_required")
        );
        assert!(changed.receiver_merkle_root_hex.is_none());

        validate_rq_delta_source_unchanged(&cx, &manifest, &entries, &config)
            .await
            .unwrap();
        std::fs::write(&source, b"changed").unwrap();
        assert!(
            validate_rq_delta_source_unchanged(&cx, &manifest, &entries, &config)
                .await
                .is_err()
        );
    });
}

fn manifest_entry(index: u32, size: u64) -> ManifestEntry {
    ManifestEntry {
        index,
        rel_path: format!("f{index}"),
        size,
        sha256_hex: "0".repeat(64),
        members: Vec::new(),
        fragment: None,
    }
}

#[test]
fn manifest_entry_members_serde_backward_compat() {
    // E-15 S1: a pre-packing manifest entry (no `members`) must deserialize to empty
    // members AND re-serialize WITHOUT a `members` field, so the no-packing wire stays
    // byte-identical to before E-15.
    let old_json = r#"{"index":0,"rel_path":"f0","size":10,"sha256_hex":"00"}"#;
    let parsed: ManifestEntry =
        serde_json::from_str(old_json).expect("deserialize pre-packing entry");
    assert!(parsed.members.is_empty(), "missing members => empty");
    let reser = serde_json::to_string(&parsed).expect("serialize");
    assert!(
        !reser.contains("members"),
        "empty members must be skipped (byte-identical no-packing wire): {reser}"
    );
    // A packed entry round-trips with its member offset table intact.
    let packed = ManifestEntry {
        index: 1,
        rel_path: ".atp-pack-0".to_string(),
        size: 20,
        sha256_hex: "ab".repeat(32),
        members: vec![
            PackedMember {
                rel_path: "dir/a".to_string(),
                offset: 0,
                len: 10,
                sha256_hex: "aa".repeat(32),
            },
            PackedMember {
                rel_path: "dir/b".to_string(),
                offset: 10,
                len: 10,
                sha256_hex: "bb".repeat(32),
            },
        ],
        fragment: None,
    };
    let json = serde_json::to_string(&packed).expect("serialize packed");
    assert!(json.contains("members"), "packed entry serializes members");
    let back: ManifestEntry = serde_json::from_str(&json).expect("round-trip packed");
    assert_eq!(back, packed, "packed entry round-trips byte-identical");
}

#[test]
fn validate_manifest_accepts_sane_bounds() {
    let manifest = manifest_with(vec![manifest_entry(0, 100), manifest_entry(1, 200)], 300);
    assert!(validate_manifest(&manifest, &RqConfig::default()).is_ok());
}

fn one_entry_metadata_manifest(path: &str, metadata: EntryMetadata) -> RqMetadataManifest {
    let commitment_hex = rq_metadata_commitment(&[(path, &metadata)]);
    RqMetadataManifest {
        version: RQ_METADATA_MANIFEST_VERSION,
        commitment_hex,
        entries: vec![RqMetadataEntry {
            rel_path: path.to_string(),
            metadata,
        }],
        directories: None,
    }
}

#[test]
fn rq_protocol_v4_commits_metadata_and_rejects_tamper_or_policy_mismatch() {
    assert_eq!(ATP_RQ_PROTOCOL, 4, "older RQ peers must fail negotiation");
    let metadata = EntryMetadata {
        mtime_unix_secs: Some(1_700_000_000),
        mtime_nanos: Some(123_400_000),
        ..EntryMetadata::default()
    };
    let mut manifest = manifest_with(vec![manifest_entry(0, 10)], 10);
    manifest.metadata = Some(one_entry_metadata_manifest("f0", metadata));
    let preserving_receiver = RqConfig {
        metadata_policy: MetadataPolicy::full_preservation(),
        ..RqConfig::default()
    };
    validate_manifest(&manifest, &preserving_receiver)
        .expect("committed regular-file metadata validates");

    let mut stripped = manifest.clone();
    stripped.metadata = None;
    assert!(matches!(
        validate_manifest(&stripped, &preserving_receiver),
        Err(RqError::Frame(ref message)) if message.contains("missing its metadata commitment")
    ));

    let mut tampered = manifest.clone();
    tampered.metadata.as_mut().expect("metadata block").entries[0]
        .metadata
        .mtime_unix_secs = Some(1_700_000_001);
    assert!(matches!(
        validate_manifest(&tampered, &preserving_receiver),
        Err(RqError::Frame(ref message)) if message.contains("commitment mismatch")
    ));

    let mut wrong_version = manifest.clone();
    wrong_version
        .metadata
        .as_mut()
        .expect("metadata block")
        .version += 1;
    assert!(matches!(
        validate_manifest(&wrong_version, &preserving_receiver),
        Err(RqError::Frame(ref message)) if message.contains("metadata manifest version")
    ));

    let portable_receiver = RqConfig {
        metadata_policy: MetadataPolicy::portable(),
        ..RqConfig::default()
    };
    assert!(matches!(
        validate_manifest(&manifest, &portable_receiver),
        Err(RqError::Frame(ref message)) if message.contains("denied")
    ));
}

#[test]
fn rq_directory_metadata_is_optional_on_wire_and_committed_when_present() {
    let old_json = format!(
        r#"{{"version":{RQ_METADATA_MANIFEST_VERSION},"commitment_hex":"{}","entries":[]}}"#,
        "0".repeat(64)
    );
    let old: RqMetadataManifest =
        serde_json::from_str(&old_json).expect("decode metadata without directories");
    assert!(old.directories.is_none());
    let old_round_trip = serde_json::to_string(&old).expect("encode old metadata shape");
    assert!(!old_round_trip.contains("directories"));

    let root_metadata = EntryMetadata {
        file_kind: crate::net::atp::transport_common::FileKind::Directory,
        mtime_unix_secs: Some(1_700_000_000),
        ..EntryMetadata::default()
    };
    let nested_metadata = EntryMetadata {
        file_kind: crate::net::atp::transport_common::FileKind::Directory,
        mtime_unix_secs: Some(1_700_000_001),
        ..EntryMetadata::default()
    };
    let directories = DirectoryMetadataManifest {
        root: Some(root_metadata),
        entries: vec![DirectoryMetadataEntry {
            rel_path: "Dir".to_string(),
            metadata: nested_metadata,
        }],
    };
    let bare_file = EntryMetadata::default();
    let mut entry = manifest_entry(0, 10);
    entry.rel_path = "Dir/file".to_string();
    let mut manifest = manifest_with(vec![entry], 10);
    manifest.metadata = Some(RqMetadataManifest {
        version: RQ_METADATA_MANIFEST_VERSION,
        commitment_hex: rq_metadata_commitment_with_directories(
            &[("Dir/file", &bare_file)],
            Some(&directories),
        ),
        entries: Vec::new(),
        directories: Some(directories),
    });
    let preserving = RqConfig {
        metadata_policy: MetadataPolicy::full_preservation(),
        ..RqConfig::default()
    };
    validate_manifest(&manifest, &preserving).expect("directory metadata validates");

    let mut noncanonical_order = manifest.clone();
    noncanonical_order.total_bytes = 20;
    let mut alpha_file = manifest_entry(1, 10);
    alpha_file.rel_path = "Alpha/file".to_string();
    noncanonical_order.entries.push(alpha_file);
    let metadata = noncanonical_order.metadata.as_mut().expect("metadata");
    let directories = metadata.directories.as_mut().expect("directory metadata");
    let alpha_metadata = directories.entries[0].metadata.clone();
    directories.entries.push(DirectoryMetadataEntry {
        rel_path: "Alpha".to_string(),
        metadata: alpha_metadata,
    });
    let commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file), ("Alpha/file", &bare_file)],
        Some(directories),
    );
    metadata.commitment_hex = commitment_hex;
    assert!(matches!(
        validate_manifest(&noncanonical_order, &preserving),
        Err(RqError::Frame(ref message))
            if message.contains("strictly lexicographically increasing")
    ));

    assert!(matches!(
        validate_directory_metadata_manifest(
            manifest
                .metadata
                .as_ref()
                .expect("metadata")
                .directories
                .as_ref()
                .expect("directory metadata"),
            &BTreeSet::from(["Dir/file"]),
            false,
            &preserving,
        ),
        Err(RqError::Frame(ref message)) if message.contains("single-file")
    ));

    let mut explicitly_empty = manifest.clone();
    let metadata = explicitly_empty.metadata.as_mut().expect("metadata");
    metadata.directories = Some(DirectoryMetadataManifest::default());
    metadata.commitment_hex = rq_metadata_commitment(&[("Dir/file", &bare_file)]);
    assert!(matches!(
        validate_manifest(&explicitly_empty, &preserving),
        Err(RqError::Frame(ref message)) if message.contains("present but empty")
    ));

    let empty_directory_metadata = EntryMetadata {
        file_kind: crate::net::atp::transport_common::FileKind::Directory,
        ..EntryMetadata::default()
    };
    let mut empty_root = manifest.clone();
    let metadata = empty_root.metadata.as_mut().expect("metadata");
    metadata
        .directories
        .as_mut()
        .expect("directory metadata")
        .root = Some(empty_directory_metadata.clone());
    metadata.commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file)],
        metadata.directories.as_ref(),
    );
    assert!(matches!(
        validate_manifest(&empty_root, &preserving),
        Err(RqError::Frame(ref message)) if message.contains("root carries no fidelity fields")
    ));

    let mut empty_nested = manifest.clone();
    let metadata = empty_nested.metadata.as_mut().expect("metadata");
    metadata
        .directories
        .as_mut()
        .expect("directory metadata")
        .entries[0]
        .metadata = empty_directory_metadata;
    metadata.commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file)],
        metadata.directories.as_ref(),
    );
    assert!(matches!(
        validate_manifest(&empty_nested, &preserving),
        Err(RqError::Frame(ref message))
            if message.contains("entry Dir carries no fidelity fields")
    ));

    let mut explicit_empty_directory = manifest.clone();
    let metadata = explicit_empty_directory
        .metadata
        .as_mut()
        .expect("metadata");
    metadata
        .directories
        .as_mut()
        .expect("directory metadata")
        .entries
        .push(DirectoryMetadataEntry {
            rel_path: "Empty/Deep".to_string(),
            metadata: EntryMetadata {
                file_kind: crate::net::atp::transport_common::FileKind::Directory,
                ..EntryMetadata::default()
            },
        });
    metadata.commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file)],
        metadata.directories.as_ref(),
    );
    validate_manifest(&explicit_empty_directory, &preserving)
        .expect("explicit empty directory topology validates");

    let mut equal_to_content = manifest.clone();
    let metadata = equal_to_content.metadata.as_mut().expect("metadata");
    metadata
        .directories
        .as_mut()
        .expect("directory metadata")
        .entries[0]
        .rel_path = "Dir/file".to_string();
    metadata.commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file)],
        metadata.directories.as_ref(),
    );
    assert!(matches!(
        validate_manifest(&equal_to_content, &preserving),
        Err(RqError::Frame(ref message)) if message.contains("collides with")
    ));

    let mut below_content = explicit_empty_directory;
    let metadata = below_content.metadata.as_mut().expect("metadata");
    metadata
        .directories
        .as_mut()
        .expect("directory metadata")
        .entries[1]
        .rel_path = "Dir/file/empty".to_string();
    metadata.commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file)],
        metadata.directories.as_ref(),
    );
    assert!(matches!(
        validate_manifest(&below_content, &preserving),
        Err(RqError::Frame(ref message)) if message.contains("descends from logical file")
    ));

    let mut tampered = manifest.clone();
    tampered
        .metadata
        .as_mut()
        .expect("metadata")
        .directories
        .as_mut()
        .expect("directory metadata")
        .entries[0]
        .metadata
        .mtime_unix_secs = Some(1_700_000_002);
    assert!(matches!(
        validate_manifest(&tampered, &preserving),
        Err(RqError::Frame(ref message)) if message.contains("commitment mismatch")
    ));

    let mut wrong_kind = manifest.clone();
    let metadata = wrong_kind.metadata.as_mut().expect("metadata");
    metadata
        .directories
        .as_mut()
        .expect("directory metadata")
        .entries[0]
        .metadata
        .file_kind = crate::net::atp::transport_common::FileKind::Regular;
    metadata.commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file)],
        metadata.directories.as_ref(),
    );
    assert!(matches!(
        validate_manifest(&wrong_kind, &preserving),
        Err(RqError::Frame(ref message)) if message.contains("Directory")
    ));

    let mut aliased = manifest;
    let metadata = aliased.metadata.as_mut().expect("metadata");
    metadata
        .directories
        .as_mut()
        .expect("directory metadata")
        .entries[0]
        .rel_path = "dir".to_string();
    metadata.commitment_hex = rq_metadata_commitment_with_directories(
        &[("Dir/file", &bare_file)],
        metadata.directories.as_ref(),
    );
    assert!(matches!(
        validate_manifest(&aliased, &preserving),
        Err(RqError::Frame(ref message)) if message.contains("aliases implicit directory")
    ));
}

#[test]
fn rq_metadata_manifest_uses_final_packed_member_paths() {
    let a = EntryMetadata {
        mtime_unix_secs: Some(1_700_000_000),
        ..EntryMetadata::default()
    };
    let b = EntryMetadata {
        mtime_unix_secs: Some(1_700_000_001),
        ..EntryMetadata::default()
    };
    let commitment_hex = rq_metadata_commitment(&[("dir/a", &a), ("dir/b", &b)]);
    let mut packed = manifest_entry(0, 15);
    packed.rel_path = ".atp-pack-0".to_string();
    packed.members = vec![
        PackedMember {
            rel_path: "dir/a".to_string(),
            offset: 0,
            len: 10,
            sha256_hex: "a".repeat(64),
        },
        PackedMember {
            rel_path: "dir/b".to_string(),
            offset: 10,
            len: 5,
            sha256_hex: "b".repeat(64),
        },
    ];
    let mut manifest = manifest_with(vec![packed], 15);
    manifest.metadata = Some(RqMetadataManifest {
        version: RQ_METADATA_MANIFEST_VERSION,
        commitment_hex,
        entries: vec![
            RqMetadataEntry {
                rel_path: "dir/a".to_string(),
                metadata: a,
            },
            RqMetadataEntry {
                rel_path: "dir/b".to_string(),
                metadata: b,
            },
        ],
        directories: None,
    });
    let preserving_receiver = RqConfig {
        metadata_policy: MetadataPolicy::full_preservation(),
        ..RqConfig::default()
    };
    validate_manifest(&manifest, &preserving_receiver)
        .expect("packed object metadata resolves through logical member paths");
}

#[cfg(unix)]
#[test]
fn rq_receiver_accepts_and_reports_unsupported_windows_metadata() {
    let metadata = EntryMetadata {
        windows_attributes: Some(0x0000_0020),
        ..EntryMetadata::default()
    };
    let mut manifest = manifest_with(vec![manifest_entry(0, 10)], 10);
    manifest.metadata = Some(one_entry_metadata_manifest("f0", metadata.clone()));
    validate_manifest(&manifest, &RqConfig::default())
        .expect("cross-platform Windows attributes remain committed metadata");

    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("payload");
    std::fs::write(&path, b"payload").expect("write payload");
    let report = futures_lite::future::block_on(apply_rq_entry_metadata(&path, &metadata))
        .expect("unsupported cross-platform field is an explicit skip");
    assert!(
        report
            .skipped
            .iter()
            .any(|(field, _)| *field == "windows_attributes"),
        "{report:?}"
    );
}

#[cfg(windows)]
#[test]
fn rq_receiver_accepts_and_reports_unsupported_unix_metadata() {
    let metadata = EntryMetadata {
        unix_mode: Some(0o640),
        ..EntryMetadata::default()
    };
    let mut manifest = manifest_with(vec![manifest_entry(0, 10)], 10);
    manifest.metadata = Some(one_entry_metadata_manifest("f0", metadata.clone()));
    validate_manifest(&manifest, &RqConfig::default())
        .expect("cross-platform Unix permissions remain committed metadata");

    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("payload");
    std::fs::write(&path, b"payload").expect("write payload");
    let report = futures_lite::future::block_on(apply_rq_entry_metadata(&path, &metadata))
        .expect("unsupported cross-platform field is an explicit skip");
    assert!(
        report.skipped.iter().any(|(field, _)| *field == "mode"),
        "{report:?}"
    );
}

#[cfg(unix)]
#[test]
fn rq_metadata_application_reports_and_sets_unix_mode() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("payload");
    std::fs::write(&path, b"payload").expect("write payload");
    let metadata = EntryMetadata {
        unix_mode: Some(0o640),
        ..EntryMetadata::default()
    };
    let report = futures_lite::future::block_on(apply_rq_entry_metadata(&path, &metadata))
        .expect("apply RQ metadata");
    assert!(report.applied.contains(&"mode"), "{report:?}");
    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat payload")
            .permissions()
            .mode()
            & 0o7777,
        0o640
    );
}

#[cfg(windows)]
#[test]
fn rq_metadata_application_reports_windows_attributes_and_mtime() {
    use std::os::windows::fs::MetadataExt;

    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("payload");
    std::fs::write(&path, b"payload").expect("write payload");
    let metadata = EntryMetadata {
        mtime_unix_secs: Some(1_700_000_000),
        mtime_nanos: Some(123_400_000),
        windows_attributes: Some(0x0000_0021),
        ..EntryMetadata::default()
    };
    let report = futures_lite::future::block_on(apply_rq_entry_metadata(&path, &metadata))
        .expect("apply RQ metadata");
    assert!(report.applied.contains(&"mtime"), "{report:?}");
    assert!(report.applied.contains(&"windows_attributes"), "{report:?}");
    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat payload")
            .file_attributes()
            & 0x0000_0021,
        0x0000_0021
    );
    let mut permissions = std::fs::metadata(&path)
        .expect("stat payload for cleanup")
        .permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).expect("clear readonly for cleanup");
}

#[cfg(windows)]
#[test]
fn rq_readonly_metadata_is_deferred_until_after_transactional_commit() {
    let readonly = EntryMetadata {
        mtime_unix_secs: Some(1_700_000_000),
        windows_attributes: Some(0x0000_0021),
        ..EntryMetadata::default()
    };
    let writable = EntryMetadata {
        windows_attributes: Some(0x0000_0020),
        ..EntryMetadata::default()
    };
    let (before_commit, after_commit) = split_rq_metadata_for_commit(&readonly);
    assert_eq!(before_commit.mtime_unix_secs, readonly.mtime_unix_secs);
    assert_eq!(before_commit.windows_attributes, Some(0x0000_0020));
    assert_eq!(
        after_commit.expect("readonly replay").windows_attributes,
        Some(0x0000_0021)
    );

    let (before_commit, after_commit) = split_rq_metadata_for_commit(&writable);
    assert_eq!(before_commit, writable);
    assert!(after_commit.is_none());
}

#[cfg(windows)]
#[test]
fn rq_readonly_with_invalid_mtime_fails_before_destination_replacement() {
    let root = tempfile::tempdir().expect("temporary directory");
    let staging_path = root.path().join("staging");
    let out_path = root.path().join("output");
    std::fs::write(&staging_path, b"new payload").expect("write staging payload");
    std::fs::write(&out_path, b"old payload").expect("write existing payload");
    let metadata = EntryMetadata {
        mtime_unix_secs: Some(i64::MIN),
        windows_attributes: Some(0x0000_0021),
        ..EntryMetadata::default()
    };

    let error = futures_lite::future::block_on(prepare_rq_entry_metadata_for_commit(
        &staging_path,
        &metadata,
    ))
    .expect_err("invalid required mtime must fail before commit");

    assert!(error.to_string().contains("required metadata field mtime"));
    assert_eq!(
        std::fs::read(&out_path).expect("read unchanged destination"),
        b"old payload"
    );
    assert!(staging_path.exists());
}

#[cfg(windows)]
#[test]
fn rq_directory_metadata_preserves_root_and_nested_on_initial_and_update() {
    let root = tempfile::tempdir().expect("temporary directory");
    let base = root.path().join("payload");
    let nested = base.join("nested");
    std::fs::create_dir_all(&nested).expect("create destination directories");
    let directory_metadata = |seconds, nanos| EntryMetadata {
        file_kind: crate::net::atp::transport_common::FileKind::Directory,
        mtime_unix_secs: Some(seconds),
        mtime_nanos: Some(nanos),
        windows_attributes: Some(0x0000_0003),
        ..EntryMetadata::default()
    };
    let manifest = |seconds, nanos| DirectoryMetadataManifest {
        root: Some(directory_metadata(seconds, nanos)),
        entries: vec![DirectoryMetadataEntry {
            rel_path: "nested".to_string(),
            metadata: directory_metadata(seconds + 1, nanos),
        }],
    };
    let policy = MetadataPolicy::full_preservation();

    for (seconds, nanos) in [(1_700_000_000, 123_400_000), (1_700_000_100, 567_800_000)] {
        futures_lite::future::block_on(apply_rq_directory_metadata(
            &base,
            &manifest(seconds, nanos),
        ))
        .expect("apply RQ directory metadata");

        let captured_root = read_entry_metadata_sync(&base, &policy)
            .expect("capture transfer-root directory metadata");
        let captured_nested =
            read_entry_metadata_sync(&nested, &policy).expect("capture nested directory metadata");
        assert_eq!(captured_root.mtime_unix_secs, Some(seconds));
        assert_eq!(captured_root.mtime_nanos, Some(nanos));
        assert_eq!(captured_nested.mtime_unix_secs, Some(seconds + 1));
        assert_eq!(captured_nested.mtime_nanos, Some(nanos));
        assert_eq!(captured_root.windows_attributes.unwrap_or(0) & 0x3, 0x3);
        assert_eq!(captured_nested.windows_attributes.unwrap_or(0) & 0x3, 0x3);
    }

    for path in [&nested, &base] {
        let mut permissions = std::fs::metadata(path)
            .expect("directory cleanup metadata")
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions).expect("clear directory readonly for cleanup");
    }
}

#[cfg(unix)]
#[test]
fn rq_source_topology_captures_nested_empty_directories_and_keeps_links_fail_closed() {
    let empty_root = tempfile::tempdir().expect("empty transfer root");
    futures_lite::future::block_on(validate_source_compatibility(empty_root.path()))
        .expect("an explicit empty transfer root remains representable");

    let populated = tempfile::tempdir().expect("populated transfer root");
    std::fs::create_dir(populated.path().join("nested")).expect("create nested directory");
    std::fs::write(populated.path().join("nested/file"), b"payload").expect("write nested payload");
    let captured = futures_lite::future::block_on(source_metadata_manifest_with_config(
        populated.path(),
        &RqConfig::default(),
    ))
    .expect("capture file and directory metadata");
    let directories = captured.directories.expect("captured directory metadata");
    assert!(directories.root.is_some());
    assert_eq!(directories.entries.len(), 1);
    assert_eq!(directories.entries[0].rel_path, "nested");

    let nested = tempfile::tempdir().expect("nested-empty transfer root");
    std::fs::create_dir_all(nested.path().join("empty/one/two"))
        .expect("create nested empty directory");
    std::fs::create_dir(nested.path().join("second-empty")).expect("create second empty directory");
    let captured = futures_lite::future::block_on(source_metadata_manifest_with_config(
        nested.path(),
        &RqConfig::default(),
    ))
    .expect("capture nested empty directories");
    let directories = captured.directories.expect("captured directory topology");
    let paths = directories
        .entries
        .iter()
        .map(|entry| entry.rel_path.as_str())
        .collect::<BTreeSet<_>>();
    assert!(paths.contains("empty"));
    assert!(paths.contains("empty/one"));
    assert!(paths.contains("empty/one/two"));
    assert!(paths.contains("second-empty"));

    let linked = tempfile::tempdir().expect("linked transfer root");
    std::fs::write(linked.path().join("target"), b"target").expect("write target");
    std::os::unix::fs::symlink("target", linked.path().join("link"))
        .expect("create source symlink");
    assert!(matches!(
        futures_lite::future::block_on(validate_source_compatibility(linked.path())),
        Err(RqError::Source(ref message)) if message.contains("symlink")
    ));
}

#[test]
fn rq_receive_staging_creation_returns_cleanup_owner() {
    let root = tempfile::tempdir().expect("temporary directory");
    let dest = root.path().join("destination");
    let guard = futures_lite::future::block_on(create_receive_staging_guard(&dest, "rqtransfer1"))
        .expect("create guarded receive staging directory");
    let staging_dir = guard.dir().to_path_buf();
    assert!(staging_dir.starts_with(&dest));
    assert!(staging_dir.is_dir());

    drop(guard);

    assert!(!staging_dir.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn rq_requested_hardlink_fidelity_fails_before_transfer() {
    let root = tempfile::tempdir().expect("hardlink source root");
    let primary = root.path().join("a-primary");
    let secondary = root.path().join("b-secondary");
    std::fs::write(&primary, b"shared inode").expect("write hardlink primary");
    std::fs::hard_link(&primary, &secondary).expect("create hardlink secondary");
    let preserving = RqConfig {
        metadata_policy: MetadataPolicy::full_preservation(),
        preserve_hardlinks: true,
        ..RqConfig::default()
    };
    let error = futures_lite::future::block_on(validate_source_compatibility_with_config(
        root.path(),
        &preserving,
    ))
    .expect_err("requested RQ hardlink fidelity must fail closed during dry-run preflight");
    assert!(error.to_string().contains("hardlink identity"), "{error}");

    let flattened = futures_lite::future::block_on(source_metadata_manifest_with_config(
        root.path(),
        &RqConfig::default(),
    ))
    .expect("explicitly unpreserved hardlinks may flatten");
    assert_eq!(flattened.version, RQ_METADATA_MANIFEST_VERSION);
    assert_eq!(flattened.commitment_hex.len(), 64);
    assert_eq!(
        flattened
            .entries
            .iter()
            .map(|entry| entry.rel_path.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["a-primary", "b-secondary"])
    );
}

#[test]
fn parse_manifest_frame_validates_before_receiver_state() {
    let mut entries = vec![manifest_entry(0, 10), manifest_entry(1, 20)];
    entries[1].rel_path = entries[0].rel_path.clone();
    let manifest = manifest_with(entries, 30);
    let frame = json_frame(FrameType::ObjectManifest, &manifest).expect("manifest frame");

    assert!(matches!(
        parse_and_validate_manifest_frame(&frame, &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("duplicate manifest rel_path")
    ));
}

#[test]
fn validate_manifest_rejects_lying_entry_size() {
    let manifest = manifest_with(vec![manifest_entry(0, u64::MAX)], 10);
    assert!(matches!(
        validate_manifest(&manifest, &RqConfig::default()),
        Err(RqError::TooLarge { .. })
    ));
}

#[test]
fn validate_manifest_rejects_declared_sum_over_limit() {
    let config = RqConfig {
        max_transfer_bytes: 1000,
        ..RqConfig::default()
    };
    let manifest = manifest_with(vec![manifest_entry(0, 600), manifest_entry(1, 600)], 1200);
    assert!(matches!(
        validate_manifest(&manifest, &config),
        Err(RqError::TooLarge { .. })
    ));
}

#[test]
fn validate_manifest_rejects_declared_sum_overflow() {
    let config = RqConfig {
        max_transfer_bytes: u64::MAX,
        ..RqConfig::default()
    };
    let manifest = manifest_with(
        vec![manifest_entry(0, u64::MAX), manifest_entry(1, 1)],
        u64::MAX,
    );
    assert!(matches!(
        validate_manifest(&manifest, &config),
        Err(RqError::Frame(msg)) if msg.contains("declared size sum overflows")
    ));
}

#[test]
fn validate_manifest_rejects_single_file_with_multiple_entries() {
    let mut manifest = manifest_with(vec![manifest_entry(0, 10), manifest_entry(1, 20)], 30);
    manifest.is_directory = false;
    assert!(matches!(
        validate_manifest(&manifest, &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("single-file transfer")
    ));
}

#[test]
fn validate_manifest_rejects_duplicate_relative_paths() {
    let mut entries = vec![manifest_entry(0, 10), manifest_entry(1, 20)];
    entries[1].rel_path = entries[0].rel_path.clone();
    let manifest = manifest_with(entries, 30);
    assert!(matches!(
        validate_manifest(&manifest, &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("duplicate manifest rel_path")
    ));
}

#[test]
fn validate_manifest_rejects_windows_path_aliases_before_decode() {
    for rel_path in ["NUL.txt", "dir/COM1.log", "trailing.", "trailing "] {
        let mut entry = manifest_entry(0, 10);
        entry.rel_path = rel_path.to_string();
        let manifest = manifest_with(vec![entry], 10);
        assert!(
            validate_manifest(&manifest, &RqConfig::default()).is_err(),
            "Windows-unsafe path {rel_path:?} must fail closed"
        );
    }

    let mut entries = vec![manifest_entry(0, 10), manifest_entry(1, 20)];
    entries[0].rel_path = "Docs/Readme.txt".to_string();
    entries[1].rel_path = "docs/README.TXT".to_string();
    let manifest = manifest_with(entries, 30);
    assert!(matches!(
        validate_manifest(&manifest, &RqConfig::default()),
        Err(RqError::Frame(message)) if message.contains("case collision")
    ));
}

#[test]
fn validate_manifest_rejects_nonsequential_indexes() {
    let manifest = manifest_with(vec![manifest_entry(0, 10), manifest_entry(7, 20)], 30);
    assert!(matches!(
        validate_manifest(&manifest, &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("does not match position")
    ));
}

#[test]
fn validate_manifest_rejects_unsafe_relative_paths() {
    for rel_path in [
        "",
        "/abs",
        "\\abs",
        "../escape",
        "a/../escape",
        "a//b",
        "a\\b",
        "c:drive",
    ] {
        let mut entry = manifest_entry(0, 10);
        entry.rel_path = rel_path.to_string();
        let manifest = manifest_with(vec![entry], 10);
        assert!(
            matches!(
                validate_manifest(&manifest, &RqConfig::default()),
                Err(RqError::Source(msg)) if msg.contains("unsafe manifest rel_path")
            ),
            "rel_path {rel_path:?} should fail closed"
        );
    }
}

#[test]
fn validate_manifest_rejects_unsafe_transfer_id() {
    let long = "x".repeat(65);
    for transfer_id in ["", "../escape", "with/slash", "with-hyphen", long.as_str()] {
        let mut manifest = manifest_with(vec![manifest_entry(0, 10)], 10);
        manifest.transfer_id = transfer_id.to_string();
        assert!(
            matches!(
                validate_manifest(&manifest, &RqConfig::default()),
                Err(RqError::Frame(msg)) if msg.contains("unsafe manifest transfer_id")
            ),
            "transfer_id {transfer_id:?} should fail closed"
        );
    }
}

#[test]
fn validate_manifest_rejects_malformed_hash_fields() {
    let mut bad_root = manifest_with(vec![manifest_entry(0, 10)], 10);
    bad_root.merkle_root_hex = "0".repeat(63);
    assert!(matches!(
        validate_manifest(&bad_root, &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("manifest merkle_root_hex")
    ));

    let mut bad_entry = manifest_entry(0, 10);
    bad_entry.sha256_hex = "zz".repeat(32);
    assert!(matches!(
        validate_manifest(&manifest_with(vec![bad_entry], 10), &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("manifest entry sha256_hex")
    ));

    let mut bad_fragment = ManifestEntry {
        index: 0,
        rel_path: ".atp-fragment-0-0".to_string(),
        size: 10,
        sha256_hex: "00".repeat(32),
        members: Vec::new(),
        fragment: Some(LargeObjectFragment {
            rel_path: "huge.bin".to_string(),
            shard_index: 0,
            shard_count: 1,
            logical_offset: 0,
            len: 10,
            logical_size: 10,
            sha256_hex: "f".repeat(63),
        }),
    };
    let mut fragment_manifest = manifest_with(vec![bad_fragment.clone()], 10);
    fragment_manifest.is_directory = false;
    assert!(matches!(
        validate_manifest(&fragment_manifest, &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("manifest fragment sha256_hex")
    ));

    bad_fragment.fragment = None;
    bad_fragment.rel_path = ".atp-pack-0".to_string();
    bad_fragment.members = vec![PackedMember {
        rel_path: "packed/member".to_string(),
        offset: 0,
        len: 10,
        sha256_hex: "not-hex".to_string(),
    }];
    assert!(matches!(
        validate_manifest(&manifest_with(vec![bad_fragment], 10), &RqConfig::default()),
        Err(RqError::Frame(msg)) if msg.contains("manifest packed member sha256_hex")
    ));
}

#[cfg(unix)]
#[test]
fn rq_uncached_commit_guard_rejects_prefix_created_after_cached_plan() {
    let dest = tempfile::tempdir().expect("destination root");
    let outside = tempfile::tempdir().expect("outside root");
    let base = dest.path().join("payload");
    std::fs::create_dir_all(&base).expect("create destination base");
    let out_path = base.join("late/payload.txt");
    let mut verified = BTreeSet::new();
    futures_lite::future::block_on(reject_destination_symlink_prefix_cached(
        &base,
        &out_path,
        &mut verified,
    ))
    .expect("missing prefix passes planning check");

    std::os::unix::fs::symlink(outside.path(), base.join("late"))
        .expect("replace missing prefix with symlink");

    let error = futures_lite::future::block_on(reject_destination_symlink_prefix(&base, &out_path))
        .expect_err("uncached commit check must detect the new symlink");
    assert!(
        matches!(error, RqError::Source(ref message) if message.contains("existing symlink")),
        "{error:?}"
    );
}

#[cfg(unix)]
#[test]
fn rq_commit_rejects_existing_destination_symlink_prefix() {
    let dest = tempfile::tempdir().expect("dest dir");
    let outside = tempfile::tempdir().expect("outside dir");
    let base = dest.path().join("payload");
    std::fs::create_dir_all(&base).expect("create destination base");
    std::os::unix::fs::symlink(outside.path(), base.join("link"))
        .expect("create destination symlink");

    let bytes = b"must stay inside the RQ destination".to_vec();
    let staging_dir = dest.path().join(".atp-rq-test-staging");
    std::fs::create_dir_all(&staging_dir).expect("create staging dir");
    let staging_path = staging_dir.join("0");
    std::fs::write(&staging_path, &bytes).expect("write staged payload");

    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    let (size, content_id, content_sha256) =
        futures_lite::future::block_on(hash_file_streaming(&staging_path, &mut hash_buf))
            .expect("hash staged payload");
    let rel_path = "link/payload.txt".to_string();
    let sha256_hex = hex_encode(&content_sha256);
    let merkle_root_hex = flat_merkle_root_from_digests(&[EntryDigest {
        rel_path: rel_path.clone(),
        size,
        content_id,
        content_sha256,
    }]);
    let manifest = TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "payload".to_string(),
        is_directory: true,
        total_bytes: size,
        merkle_root_hex,
        metadata: None,
        delta_manifest: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path,
            size,
            sha256_hex,
            members: Vec::new(),
            fragment: None,
        }],
    };
    let mut decoders = vec![EntryDecoder {
        index: 0,
        object_id: entry_object_id(&manifest.transfer_id, 0),
        size,
        pipeline: None,
        complete: true,
        staging_path,
        staging_write_offset: 0,
        staging_file_len: size,
        staging_shared: false,
        staging_created: true,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: size,
        max_block_size: DEFAULT_MAX_BLOCK_SIZE,
        source_streaming: false,
        source_blocks: Vec::new(),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    }];

    let err = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &std::collections::BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect_err("commit must reject pre-existing symlink ancestors");
    assert!(
        matches!(err, RqError::Source(ref message) if message.contains("existing symlink")),
        "expected existing-symlink source error, got {err:?}"
    );
    assert!(
        !outside.path().join("payload.txt").exists(),
        "RQ commit must not follow a destination symlink outside dest_dir"
    );
}

#[test]
fn datagram_roundtrips() {
    let sym = Symbol::new(
        SymbolId::new(ObjectId::new(1, 2), 3, 7),
        vec![9u8; 1024],
        SymbolKind::Repair,
    );
    let dg = encode_symbol_datagram(0xABCD, 42, &sym, None);
    let parsed = parse_symbol_header(&dg, 0xABCD, false).expect("parse");
    assert_eq!(parsed.entry, 42);
    assert_eq!(parsed.sbn, 3);
    assert_eq!(parsed.esi, 7);
    assert!(matches!(parsed.kind, SymbolKind::Repair));
    assert_eq!(parsed.auth_tag, None);
    assert_eq!(parsed.payload_len, 1024);
    assert_eq!(
        &dg[parsed.header_len..parsed.header_len + 1024],
        &[9u8; 1024]
    );
}

#[test]
fn signed_datagram_roundtrips() {
    let ctx = SecurityContext::for_testing(99);
    let sym = Symbol::new(
        SymbolId::new(ObjectId::new(1, 2), 3, 7),
        vec![9u8; 1024],
        SymbolKind::Repair,
    );
    let auth = ctx.sign_symbol(&sym);
    let dg = encode_symbol_datagram(0xABCD, 42, &sym, Some(auth.tag()));
    let parsed = parse_symbol_header(&dg, 0xABCD, true).expect("parse signed");
    assert_eq!(parsed.entry, 42);
    assert_eq!(parsed.sbn, 3);
    assert_eq!(parsed.auth_tag, Some(*auth.tag()));
    assert_eq!(parsed.header_len, AUTH_DGRAM_HEADER);

    let mut received = AuthenticatedSymbol::from_parts(sym, parsed.auth_tag.expect("tag"));
    ctx.verify_authenticated_symbol(&mut received)
        .expect("tag verifies");
    assert!(received.is_verified());
}

fn source_streaming_test_decoder(
    object_id: ObjectId,
    staging_path: PathBuf,
    size: u64,
    symbol_size: u16,
) -> EntryDecoder {
    EntryDecoder {
        index: 0,
        object_id,
        size,
        pipeline: None,
        complete: false,
        staging_path,
        staging_write_offset: 0,
        staging_file_len: size,
        staging_shared: false,
        staging_created: false,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: 0,
        max_block_size: usize::try_from(size).expect("test size fits usize"),
        source_streaming: true,
        source_blocks: source_block_progress_for(
            size,
            usize::try_from(size).expect("test size fits usize"),
            symbol_size,
        )
        .expect("test source blocks"),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    }
}

fn signed_source_payload(
    ctx: &SecurityContext,
    object_id: ObjectId,
    esi: u32,
    data: Vec<u8>,
    tag: Option<AuthenticationTag>,
) -> (ParsedDatagram, Vec<u8>) {
    let sym = Symbol::new(SymbolId::new(object_id, 0, esi), data, SymbolKind::Source);
    let signed = ctx.sign_symbol(&sym);
    let auth_tag = tag.as_ref().unwrap_or_else(|| signed.tag());
    let dg = encode_symbol_datagram(0xA77E, 0, &sym, Some(auth_tag));
    let parsed = parse_symbol_header(&dg, 0xA77E, true).expect("parse signed source datagram");
    let payload = dg[parsed.header_len..parsed.header_len + parsed.payload_len].to_vec();
    (parsed, payload)
}

fn signed_source_datagram(
    ctx: &SecurityContext,
    object_id: ObjectId,
    esi: u32,
    data: Vec<u8>,
    tag: Option<AuthenticationTag>,
) -> Vec<u8> {
    let sym = Symbol::new(SymbolId::new(object_id, 0, esi), data, SymbolKind::Source);
    let signed = ctx.sign_symbol(&sym);
    let auth_tag = tag.as_ref().unwrap_or_else(|| signed.tag());
    encode_symbol_datagram(0xA77E, 0, &sym, Some(auth_tag))
}

fn udp_recv_batch(datagrams: Vec<Vec<u8>>) -> crate::net::UdpRecvBatch {
    let src_addr = "127.0.0.1:9000".parse().expect("socket addr");
    crate::net::UdpRecvBatch {
        packets: datagrams
            .into_iter()
            .map(|payload| crate::net::UdpInboundDatagram {
                src_addr,
                payload,
                possibly_truncated: false,
            })
            .collect(),
        report: crate::net::UdpBatchIoReport::default(),
    }
}

#[test]
fn plain_source_recv_batch_persists_without_pipeline_feed() {
    let object_id = entry_object_id("plain-source-batch", 0);
    let symbol_size = 4u16;
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let decoder = source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);

    let first = Symbol::new(
        SymbolId::new(object_id, 0, 0),
        vec![1, 2, 3, 4],
        SymbolKind::Source,
    );
    let second = Symbol::new(
        SymbolId::new(object_id, 0, 1),
        vec![5, 6, 7, 8],
        SymbolKind::Source,
    );
    let batch = udp_recv_batch(vec![
        encode_symbol_datagram(0xB47C, 0, &first, None),
        encode_symbol_datagram(0xB47C, 0, &second, None),
    ]);
    let cx = Cx::for_testing();
    let mut decoders = vec![decoder];

    let stats = futures_lite::future::block_on(feed_datagram_batch_to_decoders(
        &cx,
        &batch,
        0xB47C,
        false,
        None,
        &mut decoders,
        symbol_size,
        false,
    ))
    .expect("feed plain source batch");

    assert_eq!(stats.observed, 2);
    assert_eq!(stats.accepted, 2);
    assert_eq!(stats.payload_bytes, 8);
    assert_eq!(stats.pipeline_feed_micros, 0);
    assert_eq!(stats.decode_stats.attempts, 0);
    assert!(decoders[0].complete);
    assert_eq!(decoders[0].bytes_written, 8);
    assert_eq!(
        std::fs::read(staging_path).expect("read batch-staged source stream"),
        vec![1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn signed_source_streaming_persists_after_hmac_verification() {
    let ctx = SecurityContext::for_testing(31337);
    let object_id = entry_object_id("signed-source-stream", 0);
    let symbol_size = 4u16;
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder = source_streaming_test_decoder(object_id, staging_path.clone(), 8, 4);

    let (first, first_payload) = signed_source_payload(&ctx, object_id, 0, vec![1, 2, 3, 4], None);
    let accepted = futures_lite::future::block_on(feed_symbol(
        &mut decoder,
        &first,
        &first_payload,
        symbol_size,
        Some(&ctx),
    ))
    .expect("feed first source symbol");
    assert!(accepted);
    assert!(!decoder.complete);
    assert!(decoder.staging_created);
    assert_eq!(
        std::fs::read(&staging_path).expect("read staged first source symbol"),
        vec![1, 2, 3, 4, 0, 0, 0, 0]
    );

    let (second, second_payload) =
        signed_source_payload(&ctx, object_id, 1, vec![5, 6, 7, 8], None);
    let accepted = futures_lite::future::block_on(feed_symbol(
        &mut decoder,
        &second,
        &second_payload,
        symbol_size,
        Some(&ctx),
    ))
    .expect("feed second source symbol");
    assert!(accepted);
    assert!(decoder.complete);
    assert_eq!(decoder.bytes_written, 8);

    assert_eq!(
        std::fs::read(staging_path).expect("read staged source stream"),
        vec![1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn source_streaming_large_entry_cache_coalesces_and_closes_staging_file() {
    let object_id = entry_object_id("source-stream-cache", 0);
    let symbol_size = 4u16;
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);
    decoder.cache_staging_file = true;

    let first = ParsedDatagram {
        entry: 0,
        sbn: 0,
        esi: 0,
        kind: SymbolKind::Source,
        auth_tag: None,
        payload_len: 4,
        header_len: 0,
    };
    assert!(
        futures_lite::future::block_on(persist_source_symbol(
            &mut decoder,
            &first,
            &[1, 2, 3, 4],
            symbol_size,
        ))
        .expect("persist first cached source symbol")
    );
    assert!(
        decoder.staging_file.is_none(),
        "large-entry source streaming should buffer clean contiguous symbols before opening the staging file"
    );
    assert_eq!(decoder.staging_cursor, None);
    assert_eq!(decoder.staging_unflushed_bytes, 0);
    assert_eq!(decoder.source_write_buffer_offset, Some(0));
    assert_eq!(decoder.source_write_buffer, vec![1, 2, 3, 4]);

    let second = ParsedDatagram { esi: 1, ..first };
    assert!(
        futures_lite::future::block_on(persist_source_symbol(
            &mut decoder,
            &second,
            &[5, 6, 7, 8],
            symbol_size,
        ))
        .expect("persist second cached source symbol")
    );
    assert!(decoder.complete);
    assert!(
        decoder.staging_file.is_none(),
        "completed entries must release cached staging descriptors"
    );
    assert_eq!(decoder.staging_cursor, None);
    assert_eq!(decoder.staging_unflushed_bytes, 0);
    assert!(decoder.source_write_buffer.is_empty());
    assert_eq!(decoder.source_write_buffer_offset, None);
    assert_eq!(
        std::fs::read(staging_path).expect("read cached source stream"),
        vec![1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn plain_source_datagram_batch_persists_contiguous_run_once() {
    let tag = 0xA77E_2024;
    let object_id = entry_object_id("plain-source-batch-run", 0);
    let symbol_size = 4u16;
    let data: Vec<u8> = (1..=16).collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 16, symbol_size);
    decoder.cache_staging_file = true;

    let src_addr: SocketAddr = "127.0.0.1:31337".parse().expect("socket addr");
    let packets = data
        .chunks(usize::from(symbol_size))
        .enumerate()
        .map(|(esi, chunk)| {
            let symbol = Symbol::new(
                SymbolId::new(object_id, 0, u32::try_from(esi).expect("esi fits")),
                chunk.to_vec(),
                SymbolKind::Source,
            );
            crate::net::UdpInboundDatagram {
                src_addr,
                payload: encode_symbol_datagram(tag, 0, &symbol, None),
                possibly_truncated: false,
            }
        })
        .collect();
    let batch = crate::net::UdpRecvBatch {
        packets,
        report: Default::default(),
    };
    let cx = Cx::for_testing();
    let mut decoders = vec![decoder];
    let stats = futures_lite::future::block_on(feed_datagram_batch_to_decoders(
        &cx,
        &batch,
        tag,
        false,
        None,
        &mut decoders,
        symbol_size,
        true,
    ))
    .expect("feed plain source datagram batch");

    let decoder = decoders.pop().expect("decoder");
    assert_eq!(stats.observed, 4);
    assert_eq!(stats.accepted, 4);
    assert_eq!(stats.payload_bytes, 16);
    assert!(decoder.complete);
    assert_eq!(decoder.bytes_written, 16);
    assert!(
        decoder.staging_file.is_none(),
        "completed batch must release cached staging descriptor"
    );
    assert!(
        decoder.source_write_buffer.is_empty(),
        "completed batch must flush the coalesced source buffer"
    );
    assert_eq!(
        std::fs::read(staging_path).expect("read plain-source batch"),
        data
    );
}

#[test]
fn authenticated_source_datagram_batch_verifies_in_chunks_and_rejects_bad_tag() {
    let ctx = SecurityContext::for_testing(0xA17E);
    let tag = 0xA77E;
    let object_id = entry_object_id("auth-source-batch-run", 0);
    let symbol_size = 4u16;
    let symbols = RQ_AUTH_VERIFY_TARGET_CHUNK_SYMBOLS * 2;
    let data: Vec<u8> = (0..symbols * usize::from(symbol_size))
        .map(|byte| u8::try_from((byte % 251) + 1).expect("bounded byte"))
        .collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let decoder = source_streaming_test_decoder(
        object_id,
        staging_path.clone(),
        u64::try_from(data.len()).expect("test size fits"),
        symbol_size,
    );

    let bad_esi = symbols / 2;
    let bad_start = bad_esi * usize::from(symbol_size);
    let bad_symbol = Symbol::new(
        SymbolId::new(object_id, 0, u32::try_from(bad_esi).expect("esi fits")),
        data[bad_start..bad_start + usize::from(symbol_size)].to_vec(),
        SymbolKind::Source,
    );
    let good_bad_slot = ctx.sign_symbol(&bad_symbol);
    let mut bad_tag = *good_bad_slot.tag().as_bytes();
    bad_tag[0] ^= 0x80;

    let datagrams = data
        .chunks(usize::from(symbol_size))
        .enumerate()
        .map(|(esi, chunk)| {
            signed_source_datagram(
                &ctx,
                object_id,
                u32::try_from(esi).expect("esi fits"),
                chunk.to_vec(),
                (esi == bad_esi).then_some(AuthenticationTag::from_bytes(bad_tag)),
            )
        })
        .collect();
    let batch = udp_recv_batch(datagrams);
    let pool = crate::runtime::blocking_pool::BlockingPool::new(4, 4);
    let cx = Cx::new(
        crate::types::RegionId::new_for_test(51, 1),
        crate::types::TaskId::new_for_test(51, 0),
        crate::types::Budget::INFINITE,
    )
    .with_blocking_pool_handle(Some(pool.handle()));
    assert!(
        rq_auth_verify_width_for_cx(&cx, symbols) > 1,
        "test fixture must exercise chunked auth verification"
    );
    let mut decoders = vec![decoder];

    let stats = futures_lite::future::block_on(feed_datagram_batch_to_decoders(
        &cx,
        &batch,
        tag,
        true,
        Some(&ctx),
        &mut decoders,
        symbol_size,
        false,
    ))
    .expect("feed auth source datagram batch");

    let decoder = decoders.pop().expect("decoder");
    assert_eq!(stats.observed, u64::try_from(symbols).unwrap());
    assert_eq!(stats.source_observed, u64::try_from(symbols).unwrap());
    assert_eq!(stats.accepted, u64::try_from(symbols - 1).unwrap());
    assert_eq!(stats.source_accepted, u64::try_from(symbols - 1).unwrap());
    assert_eq!(stats.pipeline_feed_micros, 0);
    assert!(
        !decoder.complete,
        "tampered source must leave block incomplete"
    );
    assert_eq!(decoder.bytes_written, 0);
    assert_eq!(decoder.source_blocks[0].received_count, symbols - 1);
    assert_eq!(decoder.source_blocks[0].auth_tags[bad_esi], None);
    let staged = std::fs::read(staging_path).expect("read auth-source batch");
    assert_eq!(
        &staged[bad_start..bad_start + usize::from(symbol_size)],
        &[0, 0, 0, 0]
    );
    assert_eq!(&staged[..bad_start], &data[..bad_start]);
    assert_eq!(
        &staged[bad_start + usize::from(symbol_size)..],
        &data[bad_start + usize::from(symbol_size)..]
    );
}

#[test]
fn source_streaming_round_boundary_flush_keeps_cached_staging_file_hot() {
    let object_id = entry_object_id("source-stream-cache-flush", 0);
    let symbol_size = 4u16;
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder = source_streaming_test_decoder(
        object_id,
        staging_path,
        ENTRY_STAGING_FILE_CACHE_MIN_BYTES,
        symbol_size,
    );
    decoder.cache_staging_file = true;

    let first = ParsedDatagram {
        entry: 0,
        sbn: 0,
        esi: 0,
        kind: SymbolKind::Source,
        auth_tag: None,
        payload_len: 4,
        header_len: 0,
    };
    assert!(
        futures_lite::future::block_on(persist_source_symbol(
            &mut decoder,
            &first,
            &[1, 2, 3, 4],
            symbol_size,
        ))
        .expect("persist first cached source symbol")
    );
    assert!(decoder.staging_file.is_none());
    assert_eq!(decoder.staging_unflushed_bytes, 0);
    assert_eq!(decoder.source_write_buffer_offset, Some(0));
    assert_eq!(decoder.source_write_buffer, vec![1, 2, 3, 4]);

    futures_lite::future::block_on(flush_cached_entry_staging_files(std::slice::from_mut(
        &mut decoder,
    )))
    .expect("round-boundary flush");

    assert!(
        decoder.staging_file.is_some(),
        "round-boundary flush should not close the hot descriptor"
    );
    assert_eq!(decoder.staging_cursor, Some(4));
    assert_eq!(decoder.staging_unflushed_bytes, 0);
    assert!(decoder.source_write_buffer.is_empty());
    assert_eq!(decoder.source_write_buffer_offset, None);
}

#[test]
fn source_streaming_small_entry_cache_closes_on_round_boundary() {
    let object_id = entry_object_id("source-stream-small-cache-flush", 0);
    let symbol_size = 4u16;
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);
    decoder.cache_staging_file = true;

    let first = ParsedDatagram {
        entry: 0,
        sbn: 0,
        esi: 0,
        kind: SymbolKind::Source,
        auth_tag: None,
        payload_len: 4,
        header_len: 0,
    };
    assert!(
        futures_lite::future::block_on(persist_source_symbol(
            &mut decoder,
            &first,
            &[1, 2, 3, 4],
            symbol_size,
        ))
        .expect("persist first cached source symbol")
    );
    assert!(decoder.staging_file.is_none());
    assert_eq!(decoder.staging_cursor, None);
    assert_eq!(decoder.staging_unflushed_bytes, 0);
    assert_eq!(decoder.source_write_buffer_offset, Some(0));
    assert_eq!(decoder.source_write_buffer, vec![1, 2, 3, 4]);

    futures_lite::future::block_on(flush_cached_entry_staging_files(std::slice::from_mut(
        &mut decoder,
    )))
    .expect("round-boundary flush");

    assert!(
        decoder.staging_file.is_none(),
        "small-entry staging cache should not retain tree leaves across rounds"
    );
    assert_eq!(decoder.staging_cursor, None);
    assert_eq!(decoder.staging_unflushed_bytes, 0);
    assert!(decoder.source_write_buffer.is_empty());
    assert_eq!(decoder.source_write_buffer_offset, None);
    assert_eq!(
        std::fs::read(staging_path).expect("read staged first source symbol"),
        vec![1, 2, 3, 4, 0, 0, 0, 0]
    );
}

#[test]
fn source_streaming_staging_cache_policy_batches_small_tree_entries() {
    assert!(should_cache_entry_staging_file(
        ENTRY_STAGING_FILE_CACHE_MIN_BYTES,
        ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES,
        0,
    ));
    assert!(!should_cache_entry_staging_file(
        ENTRY_STAGING_FILE_CACHE_MIN_BYTES,
        ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES + 1,
        0,
    ));
    assert!(!should_cache_entry_staging_file(
        ENTRY_STAGING_FILE_CACHE_MIN_BYTES - 1,
        ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES,
        0,
    ));
    assert!(should_cache_entry_staging_file(
        ENTRY_STAGING_FILE_CACHE_MIN_BYTES - 1,
        ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES,
        2,
    ));
    assert!(!should_cache_entry_staging_file(
        ENTRY_STAGING_FILE_CACHE_MIN_BYTES - 1,
        ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES + 1,
        2,
    ));
    assert!(!should_cache_entry_staging_file(
        0,
        ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES,
        2,
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn e14_source_streaming_does_not_retain_one_staging_fd_per_entry() {
    fn fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .count()
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let symbol_size = 1u16;
    let parsed = ParsedDatagram {
        entry: 0,
        sbn: 0,
        esi: 0,
        kind: SymbolKind::Source,
        auth_tag: None,
        payload_len: 1,
        header_len: 0,
    };
    let before = fd_count();
    let mut decoders: Vec<EntryDecoder> = (0..1500)
        .map(|idx| {
            source_streaming_test_decoder(
                entry_object_id("e14-fd-bound", u32::try_from(idx).expect("test index fits")),
                dir.path().join(idx.to_string()),
                1,
                symbol_size,
            )
        })
        .collect();

    for (idx, decoder) in decoders.iter_mut().enumerate() {
        let payload = [u8::try_from(idx % 251).expect("bounded byte")];
        assert!(
            futures_lite::future::block_on(persist_source_symbol(
                decoder,
                &parsed,
                &payload,
                symbol_size
            ))
            .expect("persist source symbol"),
            "entry {idx} source symbol should be accepted"
        );
        assert!(decoder.complete, "entry {idx} should complete");
        assert!(decoder.staging_created, "entry {idx} should have staging");
        assert_eq!(decoder.bytes_written, 1, "entry {idx} byte count");
    }

    let after = fd_count();
    assert!(
        after <= before + 64,
        "receiver retained too many staging FDs: before={before} after={after}"
    );
}

#[test]
fn signed_source_streaming_rejects_bad_tag_before_persist() {
    let ctx = SecurityContext::for_testing(31338);
    let object_id = entry_object_id("signed-source-stream-bad-tag", 0);
    let symbol_size = 4u16;
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 4, symbol_size);

    let good = ctx.sign_symbol(&Symbol::new(
        SymbolId::new(object_id, 0, 0),
        vec![1, 2, 3, 4],
        SymbolKind::Source,
    ));
    let mut bad_tag = *good.tag().as_bytes();
    bad_tag[0] ^= 0x80;
    let (parsed, payload) = signed_source_payload(
        &ctx,
        object_id,
        0,
        vec![1, 2, 3, 4],
        Some(AuthenticationTag::from_bytes(bad_tag)),
    );

    let accepted = futures_lite::future::block_on(feed_symbol(
        &mut decoder,
        &parsed,
        &payload,
        symbol_size,
        Some(&ctx),
    ))
    .expect("feed tampered source symbol");
    assert!(!accepted);
    assert!(!decoder.complete);
    assert_eq!(decoder.bytes_written, 0);
    assert!(!decoder.staging_created);
    assert!(!staging_path.exists());
}

#[test]
fn signed_source_streaming_seeds_fec_decoder_from_staged_sources() {
    let ctx = SecurityContext::for_testing(31339);
    let object_id = entry_object_id("signed-source-stream-fec-seed", 0);
    let symbol_size = 4u16;
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);
    let mut pipeline = DecodingPipeline::with_auth(
        DecodingConfig {
            symbol_size,
            max_block_size: 8,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: std::time::Duration::from_secs(0),
            verify_auth: true,
        },
        ctx.clone(),
    );
    pipeline
        .set_object_params(object_params_for(object_id, 8, symbol_size, 8))
        .expect("set object params");
    decoder.pipeline = Some(pipeline);

    let (first, first_payload) =
        signed_source_payload(&ctx, object_id, 0, data[..4].to_vec(), None);
    assert!(
        futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &first,
            &first_payload,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed first source")
    );
    assert!(!decoder.complete);
    assert_eq!(decoder.source_blocks[0].received_count, 1);
    assert!(!decoder.source_blocks[0].pipeline_seeded[0]);

    let pool = SymbolPool::new(PoolConfig::default());
    let mut encoder = EncodingPipeline::new(
        crate::config::EncodingConfig {
            repair_overhead: 1.0,
            max_block_size: 8,
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        pool,
    );

    for encoded in encoder.encode_single_block_repair_range(object_id, 0, &data, 0, 4) {
        let sym = encoded.expect("repair encode").into_symbol();
        let auth = ctx.sign_symbol(&sym);
        let dg = encode_symbol_datagram(0xA77E, 0, &sym, Some(auth.tag()));
        let parsed = parse_symbol_header(&dg, 0xA77E, true).expect("parse signed repair");
        let payload = dg[parsed.header_len..parsed.header_len + parsed.payload_len].to_vec();
        let _ = futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &parsed,
            &payload,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed repair");
        if decoder.complete {
            break;
        }
    }

    assert!(decoder.complete, "repair fallback should finish the block");
    assert!(decoder.source_blocks[0].pipeline_seeded[0]);
    assert_eq!(
        std::fs::read(staging_path).expect("read repaired source stream"),
        data
    );
}

/// c54to7 regression (MATRIX-207): the FEC seed read-back must use the
/// SHARED-staging absolute offset (`staging_write_offset + block.start`),
/// not the entry-relative offset. A sharded large object (E-12) staged
/// every shard in one fragment; seeding a non-first shard at the raw
/// relative offset read shard 0's bytes, poisoning the seeded source
/// symbols — InconsistentEquations when redundancy caught it, a silent
/// rank-K-exact wrong solve (per-entry SHA mismatch at verify) when it
/// did not. Entry 0 (base 0) was immune, which produced the observed
/// entry-skew.
#[test]
fn signed_source_streaming_seed_reads_shard_absolute_staging_offset() {
    let ctx = SecurityContext::for_testing(31341);
    let object_id = entry_object_id("signed-source-stream-shard-seed", 1);
    let symbol_size = 4u16;
    let data = vec![11, 22, 33, 44, 55, 66, 77, 88];
    let shard_base = 8u64;
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("fragment0");
    // Shared fragment: shard 0's region holds poison bytes; this decoder
    // is the SECOND shard, staged at absolute [8, 16).
    std::fs::write(&staging_path, [0xAA; 16]).expect("pre-create shared fragment");

    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);
    decoder.staging_write_offset = shard_base;
    decoder.staging_file_len = 16;
    decoder.staging_shared = true;
    let mut pipeline = DecodingPipeline::with_auth(
        DecodingConfig {
            symbol_size,
            max_block_size: 8,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: std::time::Duration::from_secs(0),
            verify_auth: true,
        },
        ctx.clone(),
    );
    pipeline
        .set_object_params(object_params_for(object_id, 8, symbol_size, 8))
        .expect("set object params");
    decoder.pipeline = Some(pipeline);

    let (first, first_payload) =
        signed_source_payload(&ctx, object_id, 0, data[..4].to_vec(), None);
    assert!(
        futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &first,
            &first_payload,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed first source")
    );
    assert!(!decoder.complete);
    assert_eq!(decoder.source_blocks[0].received_count, 1);

    let pool = SymbolPool::new(PoolConfig::default());
    let mut encoder = EncodingPipeline::new(
        crate::config::EncodingConfig {
            repair_overhead: 1.0,
            max_block_size: 8,
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        pool,
    );

    for encoded in encoder.encode_single_block_repair_range(object_id, 0, &data, 0, 4) {
        let sym = encoded.expect("repair encode").into_symbol();
        let auth = ctx.sign_symbol(&sym);
        let dg = encode_symbol_datagram(0xA77E, 0, &sym, Some(auth.tag()));
        let parsed = parse_symbol_header(&dg, 0xA77E, true).expect("parse signed repair");
        let payload = dg[parsed.header_len..parsed.header_len + parsed.payload_len].to_vec();
        let _ = futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &parsed,
            &payload,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed repair");
        if decoder.complete {
            break;
        }
    }

    assert!(
        decoder.complete,
        "shard seed must read the staged source symbol from its ABSOLUTE \
         shared-fragment offset and finish the block"
    );
    let staged = std::fs::read(staging_path).expect("read shared fragment");
    assert_eq!(
        &staged[8..16],
        &data[..],
        "shard content must decode byte-identical from absolute-offset seeds"
    );
    assert_eq!(
        &staged[..8],
        &[0xAA; 8],
        "shard 0's region must never be touched by shard 1's decoder"
    );
}

#[test]
fn source_streaming_round_boundary_seeds_when_source_arrives_after_repair() {
    let object_id = entry_object_id("source-stream-round-boundary-seed", 0);
    let symbol_size = 4u16;
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);
    decoder.cache_staging_file = true;
    let mut pipeline = DecodingPipeline::new(DecodingConfig {
        symbol_size,
        max_block_size: 8,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: 0,
        block_timeout: std::time::Duration::from_secs(0),
        verify_auth: false,
    });
    pipeline
        .set_object_params(object_params_for(object_id, 8, symbol_size, 8))
        .expect("set object params");
    decoder.pipeline = Some(pipeline);

    let pool = SymbolPool::new(PoolConfig::default());
    let mut encoder = EncodingPipeline::new(
        crate::config::EncodingConfig {
            repair_overhead: 1.0,
            max_block_size: 8,
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        pool,
    );
    let repair = encoder
        .encode_single_block_repair_range(object_id, 0, &data, 0, 1)
        .next()
        .expect("one repair")
        .expect("repair encode")
        .into_symbol();
    let repair_parsed = ParsedDatagram {
        entry: 0,
        sbn: repair.sbn(),
        esi: repair.esi(),
        kind: repair.kind(),
        auth_tag: None,
        payload_len: repair.data().len(),
        header_len: 0,
    };
    assert!(
        futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &repair_parsed,
            repair.data(),
            symbol_size,
            None,
        ))
        .expect("feed repair first")
    );
    assert!(!decoder.complete);
    assert_eq!(decoder.source_blocks[0].received_count, 0);

    let source = ParsedDatagram {
        entry: 0,
        sbn: 0,
        esi: 0,
        kind: SymbolKind::Source,
        auth_tag: None,
        payload_len: 4,
        header_len: 0,
    };
    assert!(
        futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &source,
            &data[..4],
            symbol_size,
            None,
        ))
        .expect("feed source after repair")
    );
    assert!(
        !decoder.complete,
        "no later repair arrived to trigger seeding"
    );
    assert!(source_streaming_block_ready_to_seed(&decoder, 0));
    assert!(decoder.staging_file.is_none());
    assert_eq!(decoder.staging_unflushed_bytes, 0);
    assert_eq!(decoder.source_write_buffer_offset, Some(0));
    assert_eq!(decoder.source_write_buffer, data[..4]);

    let cx = Cx::for_testing();
    let mut decoders = vec![decoder];
    let seed_stats = futures_lite::future::block_on(
        flush_and_seed_source_streaming_round_boundary(&cx, &mut decoders, symbol_size, None),
    )
    .expect("round-boundary seed");
    assert_eq!(seed_stats.seeded, 1);
    futures_lite::future::block_on(join_all_pending_decodes(
        &cx,
        &mut decoders,
        RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
    ))
    .expect("join boundary decode");

    let decoder = decoders.pop().expect("decoder");
    assert!(decoder.complete, "round boundary seed should finish block");
    assert_eq!(decoder.bytes_written, 8);
    assert_eq!(
        std::fs::read(staging_path).expect("read round-boundary repaired stream"),
        data
    );
}

// E-9 regression: a block completed via FEC (persist_decoded_block) must not be counted a
// second time when a late source retransmit for the same block arrives. Pre-fix, FEC left
// source_blocks[sbn].complete=false, so the late source's received_count==k path added
// block.len to bytes_written AGAIN → bytes_written != size → verify_and_commit falsely rejected
// a BYTE-CORRECT transfer as "per-entry SHA-256 mismatch" (the bad-regime non-convergence).
#[test]
fn e9_single_block_fec_then_late_source_does_not_double_count() {
    let ctx = SecurityContext::for_testing(54321);
    let object_id = entry_object_id("e9-mixed-no-double-count", 0);
    let symbol_size = 4u16;
    let data = vec![10u8, 20, 30, 40, 50, 60, 70, 80]; // 8 bytes, k=2 @ symbol_size 4
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder =
        source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);

    // One real source symbol arrives (esi=0): block not yet complete.
    let (p0, pl0) = signed_source_payload(&ctx, object_id, 0, data[..4].to_vec(), None);
    assert!(
        futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &p0,
            &pl0,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed source 0")
    );
    assert!(!decoder.complete);
    assert_eq!(decoder.source_blocks[0].received_count, 1);

    // FEC completes the block (decoder emits the full block).
    futures_lite::future::block_on(persist_decoded_block(&mut decoder, 0, &data))
        .expect("persist decoded block");
    assert!(
        decoder.complete,
        "FEC completion finishes the single-block entry"
    );
    assert_eq!(
        decoder.bytes_written, 8,
        "block counted exactly once after FEC"
    );
    assert!(
        decoder.source_blocks[0].complete,
        "FEC must mark the source block complete (E-9)"
    );

    // A LATE source retransmit for esi=1 arrives AFTER FEC completion. Pre-fix this drove
    // received_count to k and DOUBLE-counted bytes_written to 16. It must be ignored now.
    let (p1, pl1) = signed_source_payload(&ctx, object_id, 1, data[4..].to_vec(), None);
    let _ = futures_lite::future::block_on(feed_symbol(
        &mut decoder,
        &p1,
        &pl1,
        symbol_size,
        Some(&ctx),
    ));
    assert_eq!(
        decoder.bytes_written, 8,
        "late source must NOT double-count bytes_written (E-9)"
    );

    assert_eq!(std::fs::read(&staging_path).expect("read staged"), data);
}

// E-9 regression (multi-block MIXED completion — the realistic bad-regime case): block 0 via
// FEC, block 1 via source, plus a late source retransmit for the already-FEC'd block 0. The
// entry must complete with bytes_written == size (each block counted ONCE) and byte-identical
// content. This directly exercises the source_blocks[sbn].complete guard that protects the
// multi-block path (where dec.complete is still false after the first block, so feed_symbol's
// dec.complete short-circuit does not hide the double-count).
#[test]
fn e9_multiblock_mixed_completion_counts_each_block_once() {
    let object_id = entry_object_id("e9-multiblock-mixed", 0);
    let symbol_size = 4u16;
    let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes; max_block_size 4 -> 2 blocks, k=1 each
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let mut decoder = EntryDecoder {
        index: 0,
        object_id,
        size: 8,
        pipeline: None,
        complete: false,
        staging_path: staging_path.clone(),
        staging_write_offset: 0,
        staging_file_len: 8,
        staging_shared: false,
        staging_created: false,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: 0,
        max_block_size: 4,
        source_streaming: true,
        source_blocks: source_block_progress_for(8, 4, symbol_size).expect("two source blocks"),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    };
    assert_eq!(decoder.source_blocks.len(), 2);

    // Block 0 completes via FEC.
    futures_lite::future::block_on(persist_decoded_block(&mut decoder, 0, &data[0..4]))
        .expect("persist decoded block 0");
    assert!(decoder.source_blocks[0].complete);
    assert!(!decoder.complete, "block 1 still pending");
    assert_eq!(decoder.bytes_written, 4);

    // A LATE source retransmit for the already-FEC'd block 0 must be ignored (no double count).
    let late = ParsedDatagram {
        entry: 0,
        sbn: 0,
        esi: 0,
        kind: SymbolKind::Source,
        auth_tag: None,
        payload_len: 4,
        header_len: 0,
    };
    let accepted = futures_lite::future::block_on(persist_source_symbol(
        &mut decoder,
        &late,
        &data[0..4],
        symbol_size,
    ))
    .expect("late source");
    assert!(
        !accepted,
        "late source for a completed block is ignored (E-9)"
    );
    assert_eq!(decoder.bytes_written, 4, "no double count for block 0");

    // Block 1 completes via source.
    let b1 = ParsedDatagram {
        entry: 0,
        sbn: 1,
        esi: 0,
        kind: SymbolKind::Source,
        auth_tag: None,
        payload_len: 4,
        header_len: 0,
    };
    assert!(
        futures_lite::future::block_on(persist_source_symbol(
            &mut decoder,
            &b1,
            &data[4..8],
            symbol_size
        ))
        .expect("block 1 source")
    );
    assert!(decoder.complete, "all blocks complete -> entry complete");
    assert_eq!(
        decoder.bytes_written, 8,
        "each block counted once; bytes_written == size"
    );

    assert_eq!(std::fs::read(&staging_path).expect("read staged"), data);
}

#[test]
fn signed_datagram_feed_reaches_k512_decode_threshold() {
    let ctx = SecurityContext::for_testing(101);
    let object_id = entry_object_id("wire-k512", 0);
    let symbol_size = 1024u16;
    let max_block_size = DEFAULT_MAX_BLOCK_SIZE;
    let data: Vec<u8> = (0usize..512 * 1024)
        .map(|i: usize| (i.wrapping_mul(1_103_515_245) >> 16) as u8)
        .collect();

    let pool = SymbolPool::new(PoolConfig::default());
    let mut encoder = EncodingPipeline::new(
        crate::config::EncodingConfig {
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            max_block_size,
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        pool,
    );
    let params = object_params_for(
        object_id,
        data.len() as u64,
        symbol_size,
        max_block_size as u64,
    );
    let mut decoder = DecodingPipeline::with_auth(
        DecodingConfig {
            symbol_size,
            max_block_size,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: std::time::Duration::from_secs(0),
            verify_auth: true,
        },
        ctx.clone(),
    );
    decoder
        .set_object_params(params)
        .expect("set object params");

    for encoded in encoder.encode_with_repair(object_id, &data, 512) {
        let sym = encoded.expect("encode").into_symbol();
        if sym.kind().is_source() && sym.esi() < 33 {
            continue;
        }
        let auth = ctx.sign_symbol(&sym);
        let dg = encode_symbol_datagram(0xABCD, 0, &sym, Some(auth.tag()));
        let parsed = parse_symbol_header(&dg, 0xABCD, true).expect("parse signed datagram");
        let payload = &dg[parsed.header_len..parsed.header_len + parsed.payload_len];
        let received = Symbol::new(
            SymbolId::new(object_id, parsed.sbn, parsed.esi),
            payload.to_vec(),
            parsed.kind,
        );
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                received,
                parsed.auth_tag.expect("auth tag"),
            ))
            .expect("feed");
        if matches!(result, SymbolAcceptResult::BlockComplete { .. }) {
            break;
        }
    }

    assert!(
        decoder.is_complete(),
        "wire-parsed K=512 symbols must decode"
    );
    let mut out = decoder.into_data().expect("decoded data");
    out.truncate(data.len());
    assert_eq!(out, data);
}

#[test]
fn signed_datagram_rejects_missing_tag() {
    let sym = Symbol::new(
        SymbolId::new(ObjectId::new(1, 2), 3, 7),
        vec![9u8; 1024],
        SymbolKind::Repair,
    );
    let dg = encode_symbol_datagram(0xABCD, 42, &sym, None);
    assert!(parse_symbol_header(&dg, 0xABCD, true).is_none());
}

#[test]
fn default_config_requires_symbol_auth_or_trusted_mode() {
    let err = RqConfig::default()
        .symbol_auth_context()
        .expect_err("default config must fail closed");
    assert!(matches!(err, RqError::Authentication(_)));
    assert!(
        RqConfig::default()
            .allow_unauthenticated_for_trusted_transport()
            .symbol_auth_context()
            .expect("explicit trusted mode")
            .is_none()
    );
    assert!(
        RqConfig::default()
            .with_symbol_auth(SecurityContext::for_testing(7))
            .symbol_auth_context()
            .expect("explicit auth context")
            .is_some()
    );
}

#[test]
fn datagram_rejects_wrong_tag() {
    let sym = Symbol::new(
        SymbolId::new(ObjectId::new(1, 2), 0, 0),
        vec![0u8; 8],
        SymbolKind::Source,
    );
    let dg = encode_symbol_datagram(0x1111, 0, &sym, None);
    assert!(parse_symbol_header(&dg, 0x2222, false).is_none());
}

#[test]
fn datagram_rejects_bad_magic() {
    let mut dg = encode_symbol_datagram(
        0x1111,
        0,
        &Symbol::new(
            SymbolId::new(ObjectId::new(1, 2), 0, 0),
            vec![0u8; 8],
            SymbolKind::Source,
        ),
        None,
    );
    dg[0] ^= 0xFF;
    assert!(parse_symbol_header(&dg, 0x1111, false).is_none());
}

#[test]
fn entry_object_id_is_deterministic_and_index_sensitive() {
    let a = entry_object_id("deadbeef", 0);
    let b = entry_object_id("deadbeef", 0);
    let c = entry_object_id("deadbeef", 1);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn source_symbol_count_has_floor_and_ceils() {
    assert_eq!(source_symbol_count(0, 1024), 1);
    assert_eq!(source_symbol_count(1, 1024), 1);
    assert_eq!(source_symbol_count(1024, 1024), 1);
    assert_eq!(source_symbol_count(1025, 1024), 2);
}

#[test]
fn source_symbol_request_rebuilds_exact_source_payload() {
    let config = RqConfig {
        symbol_size: 512,
        max_block_size: 1024,
        ..RqConfig::default()
    };
    let bytes: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let source_path = dir.path().join("source.bin");
    std::fs::write(&source_path, &bytes).expect("write source");
    let enc = EntryEncoder {
        index: 7,
        object_id: entry_object_id("source-request", 7),
        abs_path: source_path,
        source_offset: 0,
        size: bytes.len(),
        repair_cursors: Vec::new(),
    };

    let first_block_tail = futures_lite::future::block_on(source_symbol_for_request(
        &enc,
        SourceSymbolRequest {
            entry: 7,
            sbn: 0,
            esi: 1,
        },
        &config,
    ))
    .expect("source symbol");
    assert!(first_block_tail.kind().is_source());
    assert_eq!(first_block_tail.sbn(), 0);
    assert_eq!(first_block_tail.esi(), 1);
    assert_eq!(first_block_tail.data(), &bytes[512..1024]);

    let final_block = futures_lite::future::block_on(source_symbol_for_request(
        &enc,
        SourceSymbolRequest {
            entry: 7,
            sbn: 1,
            esi: 0,
        },
        &config,
    ))
    .expect("final source symbol");
    assert_eq!(&final_block.data()[..476], &bytes[1024..]);
    assert!(final_block.data()[476..].iter().all(|byte| *byte == 0));
}

#[test]
fn default_repair_overhead_is_source_first() {
    assert_eq!(
        initial_repair_target_per_block(512, DEFAULT_REPAIR_OVERHEAD),
        0
    );
}

#[test]
fn source_first_initial_repair_target_is_zero() {
    assert_eq!(initial_repair_target_per_block(512, 1.0), 0);
}

#[test]
fn source_first_feedback_repair_batch_has_lossy_straggler_cushion() {
    assert_eq!(
        repair_target_for_feedback_round(512, 0, 1.0),
        SOURCE_FIRST_FEEDBACK_REPAIR_FLOOR_PER_BLOCK
    );
    assert_eq!(
        repair_target_for_feedback_round(512, 7, 1.0),
        7 + SOURCE_FIRST_FEEDBACK_REPAIR_FLOOR_PER_BLOCK
    );
}

#[test]
fn feedback_repair_batch_is_rate_matched_and_capped() {
    assert_eq!(repair_target_for_feedback_round(512, 16, 1.03), 32);
    assert_eq!(repair_target_for_feedback_round(512, 256, 1.50), 384);
}

#[test]
fn source_retransmit_is_bounded_by_default_in_source_first_mode() {
    let config = RqConfig {
        repair_overhead: 1.0,
        ..RqConfig::default()
    };

    assert_eq!(
        source_retransmit_request_limit(&config, 1),
        Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
    );
    assert_eq!(
        source_retransmit_request_limit(&config, DEFAULT_SOURCE_RETRANSMIT_ROUNDS),
        Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
    );
    assert_eq!(
        source_retransmit_request_limit(&config, DEFAULT_SOURCE_RETRANSMIT_ROUNDS + 1),
        None
    );
}

#[test]
fn source_retransmit_stays_source_first_below_round0_loss_threshold() {
    let config = RqConfig {
        repair_overhead: 1.0,
        round0_loss_target: 0.001,
        ..RqConfig::default()
    };

    assert_eq!(
        source_retransmit_request_limit(&config, 1),
        Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
    );
    assert!(!source_retransmit_needs_fec_fallback(&config, 1, 1, 0.0));
    assert!(
        source_retransmit_needs_fec_fallback(&config, 1, 0, 0.0),
        "pending rank-only repair feedback must not wait for the source retransmit window"
    );
}

#[test]
fn round0_loss_target_uses_repair_feedback_in_lossy_cells() {
    let config = RqConfig {
        repair_overhead: 1.0,
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };

    // Loss-target cells keep sparse source requests available in EVERY
    // feedback round: after the round-0 FEC bulk, the residual is a few
    // rank-deficient blocks that only targeted systematic retransmits can
    // repair efficiently (MATRIX-207). The FEC fallback stays latched for
    // rounds whose request list saturates.
    assert_eq!(
        source_retransmit_request_limit(&config, 1),
        Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
    );
    assert_eq!(
        source_retransmit_request_limit(&config, DEFAULT_SOURCE_RETRANSMIT_ROUNDS + 5),
        Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
    );
    assert!(source_retransmit_needs_fec_fallback(&config, 1, 0, 0.0));
}

#[test]
fn source_retransmit_requires_explicit_round_budget() {
    let config = RqConfig {
        repair_overhead: 1.0,
        source_retransmit_rounds: 2,
        max_source_retransmit_requests: 17,
        ..RqConfig::default()
    };

    assert_eq!(source_retransmit_request_limit(&config, 1), Some(17));
    assert_eq!(source_retransmit_request_limit(&config, 2), Some(17));
    assert_eq!(source_retransmit_request_limit(&config, 3), None);
}

#[test]
fn source_retransmit_does_not_override_proactive_repair_mode() {
    let config = RqConfig {
        repair_overhead: 1.001,
        source_retransmit_rounds: 2,
        max_source_retransmit_requests: 17,
        ..RqConfig::default()
    };

    assert_eq!(source_retransmit_request_limit(&config, 1), None);
}

#[test]
fn source_retransmit_falls_back_to_fec_when_repair_only_saturated_or_final_round() {
    let config = RqConfig {
        repair_overhead: 1.0,
        source_retransmit_rounds: 2,
        max_source_retransmit_requests: 17,
        ..RqConfig::default()
    };

    assert!(source_retransmit_needs_fec_fallback(&config, 1, 0, 0.0));
    assert!(!source_retransmit_needs_fec_fallback(&config, 1, 16, 0.0));
    assert!(source_retransmit_needs_fec_fallback(&config, 1, 17, 0.0));
    assert!(source_retransmit_needs_fec_fallback(&config, 2, 1, 0.0));
    assert!(source_retransmit_needs_fec_fallback(&config, 2, 0, 0.0));
    assert!(source_retransmit_needs_fec_fallback(&config, 3, 0, 0.0));
}

#[test]
fn source_retransmit_fec_fallback_uses_measured_loss_with_source_requests() {
    let config = RqConfig {
        repair_overhead: 1.0,
        source_retransmit_rounds: 2,
        max_source_retransmit_requests: 8192,
        ..RqConfig::default()
    };

    assert!(
        !source_retransmit_needs_fec_fallback(&config, 1, 128, 0.001),
        "near-clean feedback should preserve source-first repair"
    );
    assert!(
        source_retransmit_needs_fec_fallback(&config, 1, 128, 0.10),
        "broken-link measured loss must start calibrated FEC repair even while source requests remain"
    );
}

#[test]
fn source_retransmit_repair_only_rounds_keep_fec_fallback_enabled() {
    let config = RqConfig {
        repair_overhead: 1.0,
        source_retransmit_rounds: 2,
        max_source_retransmit_requests: 17,
        max_feedback_rounds: 16,
        ..RqConfig::default()
    };

    assert_eq!(source_retransmit_request_limit(&config, 3), None);
    for feedback_round in (config.source_retransmit_rounds + 1)..=config.max_feedback_rounds {
        assert!(
            source_retransmit_needs_fec_fallback(&config, feedback_round, 0, 0.0),
            "repair-only feedback round {feedback_round} must keep FEC fallback enabled"
        );
    }
}

#[test]
fn source_retransmit_fec_fallback_latches_after_repair_only_feedback() {
    let config = RqConfig {
        repair_overhead: 1.0,
        source_retransmit_rounds: 2,
        max_source_retransmit_requests: 17,
        max_feedback_rounds: 16,
        ..RqConfig::default()
    };

    let mut active = false;
    for (feedback_round, requested_sources, expected_active) in [
        (1, 1, false),
        (1, 0, true),
        (2, 8, true),
        (3, 1, true),
        (config.max_feedback_rounds, 0, true),
    ] {
        active |=
            source_retransmit_needs_fec_fallback(&config, feedback_round, requested_sources, 0.0);
        assert_eq!(
            active, expected_active,
            "feedback_round={feedback_round} requested_sources={requested_sources}"
        );
    }
}

#[test]
fn round0_loss_target_keeps_clean_and_good_links_source_first() {
    for target in [0.0, 0.001] {
        let config = RqConfig {
            symbol_size: 1200,
            max_block_size: 512 * 1024,
            repair_overhead: 1.0,
            round0_loss_target: target,
            ..RqConfig::default()
        };

        assert_eq!(round0_loss_target_repair_overhead(&config), 1.0);
        assert_eq!(
            source_retransmit_request_limit(&config, 1),
            Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
        );
        assert_eq!(round0_bad_link_pacing_bps(&config), None);
    }
}

#[test]
fn small_clean_round0_forces_source_only_repair_budget() {
    let config = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.001,
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };
    let tuning = RqRoundTuning {
        repair_overhead: 1.08,
        pacing: RqSprayPacing::from_rate(
            RQ_MIN_PACING_BPS,
            config.symbol_size,
            RQ_ADAPTIVE_BURST_SYMBOLS,
            None,
            false,
        ),
    };

    let adjusted = apply_small_clean_round0_source_only(50 * 1024 * 1024, &config, tuning);

    assert!(small_clean_source_only_round0(50 * 1024 * 1024, &config));
    assert_eq!(adjusted.repair_overhead, 1.0);
    assert_eq!(
        initial_repair_target_per_block(437, adjusted.repair_overhead),
        0
    );
    assert_eq!(
        adjusted.pacing.rate_bytes_per_sec(),
        RQ_COLD_START_PACING_BPS
    );
    assert!(round0_clean_ramp_enabled(&config, adjusted.pacing));
    let mut pacer = RqSprayPacer::new_round0(
        adjusted.pacing,
        &config,
        small_clean_source_only_round0(50 * 1024 * 1024, &config),
    );
    assert!(pacer.round0_ramp.is_some());
    assert!(
        pacer.small_clean_burst.is_some(),
        "small clean UDP source-only sprays must use coarse burst pacing so sub-ms timer \
         wakes cannot stretch 50M/perfect auth to the 60s timeout floor"
    );
    let burst_symbols = adjusted
        .pacing
        .max_burst_size
        .max(u32::try_from(RQ_SEND_BATCH_PER_SOCKET).unwrap_or(u32::MAX));
    let burst_bytes =
        u64::from(adjusted.pacing.datagram_bytes).saturating_mul(u64::from(burst_symbols));
    assert!(
        duration_for_rate_window(burst_bytes, adjusted.pacing.rate_bytes_per_sec())
            > RQ_PACING_MIN_PAUSE,
        "small-clean burst pacing should sleep once per UDP batch, not once per symbol"
    );
    assert!(control_source_stream_eligible(50 * 1024 * 1024, &config));
    let fallback_udp_pacer = RqSprayPacer::new_round0(
        adjusted.pacing,
        &config,
        small_clean_source_only_round0(50 * 1024 * 1024, &config),
    );
    assert!(
        fallback_udp_pacer.round0_ramp.is_some(),
        "clean RQ fallback must still take the UDP clean-ramp path when control-source \
         streaming is unavailable"
    );

    pacer.configure_with_shared_decision(
        RqSprayPacing::from_rate(
            RQ_COLD_START_PACING_BPS / 2,
            config.symbol_size,
            RQ_ADAPTIVE_BURST_SYMBOLS,
            Some(Duration::from_millis(200)),
            true,
        ),
        None,
    );
    assert!(
        pacer.small_clean_burst.is_none(),
        "feedback/retry rounds must return to the normal per-datagram controller"
    );

    let large_clean_pacer = RqSprayPacer::new_round0(
        RqSprayPacing::cold_start(config.symbol_size),
        &config,
        false,
    );
    assert!(large_clean_pacer.round0_ramp.is_some());
    assert!(
        large_clean_pacer.small_clean_burst.is_none(),
        "large clean transfers keep the existing clean ramp without the small-transfer burst shim"
    );
}

#[test]
fn matrix145_authenticated_clean_control_source_stream_is_eligible() {
    let config = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_REPAIR_OVERHEAD,
        round0_loss_target: 0.0,
        max_transfer_bytes: 1024 * 1024 * 1024,
        ..RqConfig::default()
    }
    .with_symbol_auth(SecurityContext::for_testing(0xA7_50));
    let total_bytes = 500 * 1024 * 1024;
    let low_seed = RqSprayPacing::from_rate(
        RQ_COLD_START_PACING_BPS / 4,
        config.symbol_size,
        RQ_ADAPTIVE_BURST_SYMBOLS,
        None,
        false,
    );
    let symbol_auth_enabled = config
        .symbol_auth_context()
        .expect("auth config is valid")
        .is_some();

    assert!(!small_clean_source_only_round0(total_bytes, &config));
    assert!(symbol_auth_enabled);
    assert!(control_source_stream_eligible(total_bytes, &config));
    assert!(
        round0_clean_ramp_enabled(&config, low_seed),
        "MATRIX-145 fallback: clean authenticated UDP round 0 must not stay pinned at a low adaptive seed"
    );

    let pacer = RqSprayPacer::new_round0(low_seed, &config, false);
    assert!(pacer.round0_ramp.is_some());
    assert!(
        pacer.small_clean_burst.is_none(),
        "authenticated UDP fallback remains on the normal symbol path; only pacing should ramp"
    );
}

#[test]
fn small_clean_round0_preserves_lossy_near_clean_debug_and_large_budgets() {
    let lossy = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };
    let good = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.001,
        ..RqConfig::default()
    };
    let explicit = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.05,
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };
    let debug_drop = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.05,
        round0_loss_target: 0.0,
        debug_drop_one_in: 17,
        ..RqConfig::default()
    };
    let large_clean = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };
    let tuning = RqRoundTuning {
        repair_overhead: 1.08,
        pacing: RqSprayPacing::from_rate(
            RQ_MIN_PACING_BPS,
            lossy.symbol_size,
            RQ_ADAPTIVE_BURST_SYMBOLS,
            None,
            false,
        ),
    };

    assert!(!small_clean_source_only_round0(50 * 1024 * 1024, &lossy));
    let lossy_adjusted = apply_small_clean_round0_source_only(50 * 1024 * 1024, &lossy, tuning);
    assert_eq!(lossy_adjusted.repair_overhead, tuning.repair_overhead);
    assert_eq!(
        lossy_adjusted.pacing.rate_bytes_per_sec(),
        tuning.pacing.rate_bytes_per_sec()
    );
    assert!(!small_clean_source_only_round0(50 * 1024 * 1024, &good));
    let good_adjusted = apply_small_clean_round0_source_only(50 * 1024 * 1024, &good, tuning);
    assert_eq!(good_adjusted.repair_overhead, tuning.repair_overhead);
    assert_eq!(
        good_adjusted.pacing.rate_bytes_per_sec(),
        tuning.pacing.rate_bytes_per_sec()
    );
    assert!(!small_clean_source_only_round0(50 * 1024 * 1024, &explicit));
    let explicit_adjusted =
        apply_small_clean_round0_source_only(50 * 1024 * 1024, &explicit, tuning);
    assert_eq!(explicit_adjusted.repair_overhead, tuning.repair_overhead);
    assert_eq!(
        explicit_adjusted.pacing.rate_bytes_per_sec(),
        tuning.pacing.rate_bytes_per_sec()
    );
    assert!(!small_clean_source_only_round0(
        50 * 1024 * 1024,
        &debug_drop
    ));
    let debug_drop_adjusted =
        apply_small_clean_round0_source_only(50 * 1024 * 1024, &debug_drop, tuning);
    assert_eq!(debug_drop_adjusted.repair_overhead, tuning.repair_overhead);
    assert_eq!(
        debug_drop_adjusted.pacing.rate_bytes_per_sec(),
        tuning.pacing.rate_bytes_per_sec()
    );
    assert!(!small_clean_source_only_round0(
        RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_BYTES + 1,
        &large_clean
    ));
    let large_adjusted = apply_small_clean_round0_source_only(
        RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_BYTES + 1,
        &large_clean,
        tuning,
    );
    assert_eq!(large_adjusted.repair_overhead, tuning.repair_overhead);
    assert_eq!(
        large_adjusted.pacing.rate_bytes_per_sec(),
        tuning.pacing.rate_bytes_per_sec()
    );
}

#[test]
fn forced_round0_clean_ramp_cannot_override_lossy_config() {
    for (name, round0_loss_target) in [("good", 0.001), ("bad", 0.02), ("broken", 0.10)] {
        let config = RqConfig {
            symbol_size: 1200,
            max_block_size: 512 * 1024,
            repair_overhead: 1.0,
            round0_loss_target,
            ..RqConfig::default()
        };
        let pacing = RqSprayPacing::cold_start(config.symbol_size);

        assert!(
            !round0_clean_ramp_enabled(&config, pacing),
            "{name} must not satisfy the clean-ramp predicate"
        );
        let pacer = RqSprayPacer::new_round0(pacing, &config, true);
        assert!(
            pacer.round0_ramp.is_none(),
            "{name} must not force-enable the clean ramp on a lossy cell"
        );
        assert!(
            pacer.small_clean_burst.is_none(),
            "{name} must not force-enable the clean burst pacer on a lossy cell"
        );
    }
}

#[test]
fn control_source_stream_negotiates_for_clean_and_good_links_including_auth() {
    let clean = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };
    let auth_clean = clean
        .clone()
        .with_symbol_auth(SecurityContext::for_testing(0xA7_51));
    let good = RqConfig {
        round0_loss_target: 0.001,
        ..clean.clone()
    };
    let auth_good = good
        .clone()
        .with_symbol_auth(SecurityContext::for_testing(0xA7_52));
    let near_clean_above_good = RqConfig {
        round0_loss_target: RQ_CONTROL_SOURCE_STREAM_MAX_LOSS_TARGET * 1.5,
        ..clean.clone()
    };
    let lossy = RqConfig {
        round0_loss_target: 0.02,
        ..clean.clone()
    };
    let explicit_repair = RqConfig {
        repair_overhead: 1.05,
        ..clean.clone()
    };
    let debug_drop = RqConfig {
        debug_drop_one_in: 17,
        ..clean.clone()
    };
    let capped = RqConfig {
        max_transfer_bytes: 128 * 1024 * 1024,
        ..clean.clone()
    };

    assert!(control_source_stream_eligible(50 * 1024 * 1024, &clean));
    assert!(control_source_stream_eligible(500 * 1024 * 1024, &clean));
    assert!(!small_clean_source_only_round0(500 * 1024 * 1024, &clean));
    assert!(control_source_stream_eligible(
        50 * 1024 * 1024,
        &auth_clean
    ));
    assert!(control_source_stream_eligible(50 * 1024 * 1024, &good));
    assert!(control_source_stream_eligible(50 * 1024 * 1024, &auth_good));
    assert!(!control_source_stream_eligible(
        50 * 1024 * 1024,
        &near_clean_above_good
    ));
    assert!(!control_source_stream_eligible(50 * 1024 * 1024, &lossy));
    assert!(!control_source_stream_eligible(
        50 * 1024 * 1024,
        &explicit_repair
    ));
    assert!(!control_source_stream_eligible(
        50 * 1024 * 1024,
        &debug_drop
    ));
    assert!(!control_source_stream_eligible(500 * 1024 * 1024, &capped));
}

#[test]
fn control_source_data_frame_roundtrips_entry_offset_and_payload() {
    let frame =
        control_source_data_frame_with_auth("control-source-test", 7, 123_456, b"payload", None)
            .expect("frame");
    assert_eq!(frame.frame_type(), FrameType::ObjectData);

    let parsed =
        parse_control_source_data_frame(&frame, "control-source-test", None).expect("parse");
    assert_eq!(parsed.entry, 7);
    assert_eq!(parsed.offset, 123_456);
    assert_eq!(parsed.data, b"payload");
    let canonical = frame.to_wire_bytes().expect("canonical wire");
    let direct =
        control_source_data_wire_frame("control-source-test", 7, 123_456, b"payload", None)
            .expect("direct wire");
    assert_eq!(direct.as_ref(), canonical.as_slice());
    assert!(
        frame.encoded_len()
            <= usize::try_from(crate::net::atp::protocol::frames::MAX_FRAME_SIZE).unwrap()
    );
}

#[test]
fn control_source_data_chunk_stays_within_frame_cap() {
    let payload = vec![0u8; RQ_CONTROL_SOURCE_CHUNK_BYTES];
    let frame =
        control_source_data_frame_with_auth("control-source-test", 7, 123_456, &payload, None)
            .expect("frame");
    let canonical = frame.to_wire_bytes().expect("canonical wire");
    let direct = control_source_data_wire_frame("control-source-test", 7, 123_456, &payload, None)
        .expect("direct wire");
    let max_frame_size =
        usize::try_from(crate::net::atp::protocol::frames::MAX_FRAME_SIZE).unwrap();

    assert_eq!(RQ_CONTROL_SOURCE_FRAME_MAX_BYTES, max_frame_size);
    assert_eq!(frame.encoded_len(), max_frame_size);
    assert_eq!(canonical.len(), max_frame_size);
    assert_eq!(direct.as_ref(), canonical.as_slice());
    let too_large = vec![0u8; RQ_CONTROL_SOURCE_CHUNK_BYTES + 1];
    assert!(
        control_source_data_wire_frame("control-source-test", 7, 123_456, &too_large, None)
            .is_err()
    );
}

#[test]
fn authenticated_control_source_data_rejects_tampered_payload() {
    let context = SecurityContext::for_testing(0x145);
    let frame =
        control_source_data_frame_with_auth("matrix-145", 7, 123_456, b"payload", Some(&context))
            .expect("authenticated frame");

    let parsed = parse_control_source_data_frame(&frame, "matrix-145", Some(&context))
        .expect("authenticated parse");
    assert_eq!(parsed.entry, 7);
    assert_eq!(parsed.offset, 123_456);
    assert_eq!(parsed.data, b"payload");
    assert_eq!(
        frame.payload().len(),
        RQ_CONTROL_SOURCE_AUTH_DATA_HEADER + b"payload".len()
    );

    let mut tampered = frame.payload().to_vec();
    let last = tampered.last_mut().expect("payload byte");
    *last ^= 0x01;
    let tampered_frame = Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectData, tampered)
        .expect("tampered frame");
    assert!(matches!(
        parse_control_source_data_frame(&tampered_frame, "matrix-145", Some(&context)),
        Err(RqError::Authentication(_))
    ));
}

#[test]
fn authenticated_control_source_data_chunk_stays_within_frame_cap() {
    let ctx = SecurityContext::for_testing(0xA7_52);
    let payload = vec![0u8; RQ_CONTROL_SOURCE_AUTH_CHUNK_BYTES];
    let frame =
        control_source_data_frame_with_auth("matrix145-auth-cap", 7, 123_456, &payload, Some(&ctx))
            .expect("frame");
    let canonical = frame.to_wire_bytes().expect("canonical wire");
    let direct =
        control_source_data_wire_frame("matrix145-auth-cap", 7, 123_456, &payload, Some(&ctx))
            .expect("direct wire");
    let max_frame_size =
        usize::try_from(crate::net::atp::protocol::frames::MAX_FRAME_SIZE).unwrap();

    assert_eq!(frame.encoded_len(), max_frame_size);
    assert_eq!(canonical.len(), max_frame_size);
    assert_eq!(direct.as_ref(), canonical.as_slice());
    let too_large = vec![0u8; RQ_CONTROL_SOURCE_AUTH_CHUNK_BYTES + 1];
    assert!(
        control_source_data_wire_frame("matrix145-auth-cap", 7, 123_456, &too_large, Some(&ctx),)
            .is_err()
    );
}

#[test]
fn authenticated_control_source_data_rejects_tampered_byte_before_write() {
    let ctx = SecurityContext::for_testing(0xA7_53);
    let transfer_id = "matrix145-auth-tamper";
    let payload = b"payload".to_vec();
    let frame = control_source_data_frame_with_auth(transfer_id, 0, 0, &payload, Some(&ctx))
        .expect("signed frame");
    let mut tampered_payload = frame.payload().to_vec();
    *tampered_payload.last_mut().expect("payload byte") ^= 0x80;
    let tampered = Frame::new(
        ProtocolVersion::CURRENT,
        FrameType::ObjectData,
        tampered_payload,
    )
    .expect("tampered frame");
    let dir = tempfile::tempdir().expect("tempdir");
    let staging_path = dir.path().join("entry0");
    let decoder = source_streaming_test_decoder(
        entry_object_id(transfer_id, 0),
        staging_path.clone(),
        u64::try_from(payload.len()).expect("test payload length fits"),
        4,
    );
    let mut decoders = vec![decoder];
    let manifest = manifest_with(Vec::new(), 0);
    let mut logical = std::collections::BTreeMap::new();
    let mut logical_done = std::collections::BTreeMap::new();

    let err = futures_lite::future::block_on(apply_control_source_data_frame(
        &tampered,
        transfer_id,
        Some(&ctx),
        &mut decoders,
        &manifest,
        &mut logical,
        &mut logical_done,
    ))
    .expect_err("tampered control-source byte must reject");

    assert!(matches!(err, RqError::Authentication(_)));
    assert_eq!(decoders[0].bytes_written, 0);
    assert!(!decoders[0].complete);
    assert!(
        !staging_path.exists(),
        "tampered authenticated control-source frame must not write staging bytes"
    );
}

#[derive(Default)]
struct CountingControlIo {
    bytes: Vec<u8>,
    flushes: usize,
}

impl crate::io::AsyncRead for CountingControlIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl crate::io::AsyncWrite for CountingControlIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.bytes.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.flushes += 1;
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct PendingCloseControlIo;

impl crate::io::AsyncRead for PendingCloseControlIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl crate::io::AsyncWrite for PendingCloseControlIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct PendingDeltaControlIo;

impl crate::io::AsyncRead for PendingDeltaControlIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl crate::io::AsyncWrite for PendingDeltaControlIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[test]
fn proof_close_drain_does_not_inherit_accept_timeout() {
    let cx = Cx::for_testing();
    let mut control = FrameTransport::new(PendingCloseControlIo);
    let started = Instant::now();

    futures_lite::future::block_on(drain_sender_close_after_proof(&cx, &mut control, "test"));

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "post-Proof close drain must not wait for the 60s accept/connect timeout"
    );
}

#[test]
fn sender_handshake_ack_wait_has_typed_pre_transfer_timeout() {
    let cx = Cx::for_testing();
    let mut control = FrameTransport::new(PendingCloseControlIo);

    let error = futures_lite::future::block_on(receive_sender_handshake_ack(
        &cx,
        &mut control,
        Duration::ZERO,
    ))
    .expect_err("a stalled peer must not hold auto selection forever");

    assert!(matches!(error, RqError::HandshakeRejected(_)));
    assert!(error.to_string().contains("timed out"));
}

#[test]
fn authenticated_delta_control_stalls_hit_read_and_write_deadlines() {
    let cx = Cx::for_testing();
    let mut stalled_read = FrameTransport::new(PendingDeltaControlIo);
    let read_error = futures_lite::future::block_on(recv_delta_control_frame(
        &cx,
        &mut stalled_read,
        Duration::ZERO,
        "test read",
    ))
    .expect_err("stalled delta read must time out");
    assert!(matches!(
        read_error,
        RqError::Io(ref error) if error.kind() == std::io::ErrorKind::TimedOut
    ));

    let mut stalled_write = FrameTransport::new(PendingDeltaControlIo);
    let frame = Frame::empty(FrameType::ObjectRequest).unwrap();
    let write_error = futures_lite::future::block_on(send_delta_control_frame(
        &cx,
        &mut stalled_write,
        &frame,
        Duration::ZERO,
        "test write",
    ))
    .expect_err("stalled delta write must time out");
    assert!(matches!(
        write_error,
        RqError::Io(ref error) if error.kind() == std::io::ErrorKind::TimedOut
    ));
}

#[test]
fn frame_transport_unflushed_send_defers_flush_until_requested() {
    let frame = control_source_data_frame(7, 0, b"payload").expect("frame");
    let mut control = FrameTransport::new(CountingControlIo::default());

    let written = futures_lite::future::block_on(control.send_unflushed(&frame)).expect("send");
    assert_eq!(control.stream.flushes, 0);
    assert_eq!(control.stream.bytes.len(), written);

    futures_lite::future::block_on(control.flush()).expect("flush");
    assert_eq!(control.stream.flushes, 1);
}

#[test]
fn frame_transport_control_source_data_uses_canonical_wire_bytes_without_flush() {
    let frame = control_source_data_frame(7, 123_456, b"payload").expect("frame");
    let canonical = frame.to_wire_bytes().expect("canonical wire");
    let mut control = FrameTransport::new(CountingControlIo::default());

    let written = futures_lite::future::block_on(control.send_control_source_data_unflushed(
        "control-source-test",
        7,
        123_456,
        b"payload",
        None,
    ))
    .expect("send");

    assert_eq!(written, canonical.len());
    assert_eq!(control.stream.bytes, canonical);
    assert_eq!(control.stream.flushes, 0);
}

#[test]
fn control_source_bulk_flush_batches_multiple_data_frames() {
    let payload = vec![0u8; RQ_CONTROL_SOURCE_CHUNK_BYTES];
    let frame = control_source_data_frame(7, 0, &payload).expect("frame");
    let wire_len = frame.to_wire_bytes().expect("wire").len();

    assert!(
        RQ_CONTROL_SOURCE_FLUSH_BYTES >= wire_len * 8,
        "bulk source stream should flush groups of data frames, not every frame"
    );
    assert!(RQ_CONTROL_SOURCE_FLUSH_BYTES <= 16 * 1024 * 1024);
}

/// br-asupersync-lbfdvs: the delta-capable main send path precomputes a
/// logical digest for EVERY file and passes that full list as the seed of
/// `stream_control_source_entries`. The entry loop then emits the streamed
/// digest for every plain entry itself, so an unfiltered seed produced the
/// same rel_path twice in the ObjectComplete frame and the receiver
/// fail-closed with "duplicate ObjectComplete logical digest" — breaking
/// every authenticated single-file control-source-stream send.
#[test]
fn control_source_stream_full_precomputed_seed_does_not_duplicate_plain_digests() {
    let cx = Cx::for_testing();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("plain.bin");
    std::fs::write(&path, vec![7u8; 3072]).expect("write source");

    let entry = RqSourceEntry {
        rel_path: "plain.bin".to_string(),
        abs_path: path.clone(),
        metadata: EntryMetadata::default(),
        source_offset: 0,
        source_len: None,
        members: Vec::new(),
        fragment: None,
    };
    // Exactly what the main path does before the handshake: full digest
    // list, singletons NOT deferred.
    let (entries, precomputed, _pack_tempdir) =
        futures_lite::future::block_on(pack_small_files(vec![entry], &RqConfig::default()))
            .expect("pack");
    assert_eq!(precomputed.len(), 1, "full preflight digest list");

    let transfer_id = "lbfdvs-test-transfer";
    let manifest = TransferManifest {
        transfer_id: transfer_id.to_string(),
        root_name: "plain.bin".to_string(),
        is_directory: false,
        total_bytes: 3072,
        merkle_root_hex: sha256_hex_placeholder(),
        metadata: None,
        delta_manifest: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: "plain.bin".to_string(),
            size: 3072,
            sha256_hex: sha256_hex_placeholder(),
            members: Vec::new(),
            fragment: None,
        }],
    };
    let encoders = vec![EntryEncoder {
        index: 0,
        object_id: entry_object_id(transfer_id, 0),
        abs_path: entries[0].abs_path.clone(),
        source_offset: 0,
        size: 3072,
        repair_cursors: Vec::new(),
    }];

    let mut control = FrameTransport::new(CountingControlIo::default());
    let report = futures_lite::future::block_on(stream_control_source_entries(
        &cx,
        &mut control,
        &encoders,
        &manifest,
        &precomputed,
        transfer_id,
        None,
    ))
    .expect("stream");

    let plain_rows = report
        .logical_digests
        .iter()
        .filter(|digest| digest.rel_path == "plain.bin")
        .count();
    assert_eq!(
        plain_rows, 1,
        "plain entry must appear exactly once in ObjectComplete logical digests"
    );
    assert_eq!(report.logical_digests.len(), 1);
    assert_eq!(report.bytes_streamed, 3072);
}

/// Companion guard for br-asupersync-lbfdvs: the seed filter must KEEP
/// packed-member digests — the entry loop cannot produce them (a pack
/// entry streams the combined object, and only the seed knows the member
/// digests).
#[test]
fn control_source_stream_seed_keeps_packed_member_digests() {
    let cx = Cx::for_testing();
    let dir = tempfile::tempdir().expect("tempdir");
    let path_a = dir.path().join("a.bin");
    let path_b = dir.path().join("b.bin");
    std::fs::write(&path_a, vec![1u8; 1024]).expect("write a");
    std::fs::write(&path_b, vec![2u8; 1024]).expect("write b");

    let make_entry = |rel: &str, abs: &Path| RqSourceEntry {
        rel_path: rel.to_string(),
        abs_path: abs.to_path_buf(),
        metadata: EntryMetadata::default(),
        source_offset: 0,
        source_len: None,
        members: Vec::new(),
        fragment: None,
    };
    let (entries, precomputed, pack_tempdir) = futures_lite::future::block_on(pack_small_files(
        vec![make_entry("a.bin", &path_a), make_entry("b.bin", &path_b)],
        &RqConfig::default(),
    ))
    .expect("pack");
    assert_eq!(entries.len(), 1, "two small files coalesce into one pack");
    assert_eq!(entries[0].members.len(), 2);
    assert_eq!(precomputed.len(), 2, "member digests precomputed");

    let transfer_id = "lbfdvs-pack-transfer";
    let manifest = TransferManifest {
        transfer_id: transfer_id.to_string(),
        root_name: "tree".to_string(),
        is_directory: true,
        total_bytes: 2048,
        merkle_root_hex: sha256_hex_placeholder(),
        metadata: None,
        delta_manifest: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: entries[0].rel_path.clone(),
            size: 2048,
            sha256_hex: sha256_hex_placeholder(),
            members: entries[0].members.clone(),
            fragment: None,
        }],
    };
    let encoders = vec![EntryEncoder {
        index: 0,
        object_id: entry_object_id(transfer_id, 0),
        abs_path: entries[0].abs_path.clone(),
        source_offset: 0,
        size: 2048,
        repair_cursors: Vec::new(),
    }];

    let mut control = FrameTransport::new(CountingControlIo::default());
    let report = futures_lite::future::block_on(stream_control_source_entries(
        &cx,
        &mut control,
        &encoders,
        &manifest,
        &precomputed,
        transfer_id,
        None,
    ))
    .expect("stream");
    drop(pack_tempdir);

    let mut member_paths: Vec<&str> = report
        .logical_digests
        .iter()
        .map(|digest| digest.rel_path.as_str())
        .collect();
    member_paths.sort_unstable();
    assert_eq!(
        member_paths,
        vec!["a.bin", "b.bin"],
        "packed member digests must survive the seed filter exactly once each"
    );
}

#[test]
fn round0_bad_link_pacing_cap_is_narrow_to_bad_matrix_loss() {
    for (target, expected) in [
        (0.0, None),
        (0.001, None),
        (0.02, Some(RQ_BAD_LINK_ROUND0_PACING_BPS)),
        (0.10, Some(RQ_BROKEN_LINK_ROUND0_PACING_BPS)),
    ] {
        let config = RqConfig {
            round0_loss_target: target,
            ..RqConfig::default()
        };

        assert_eq!(round0_bad_link_pacing_bps(&config), expected);
    }
}

#[test]
fn round0_loss_target_calibrates_bad_link_repair_without_full_round_budget() {
    let config = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(7, &config, 8);

    let tuning = state.round0_tuning(&config);
    let extra_fraction = tuning.repair_overhead - 1.0;
    let loss_bar = round0_loss_target_loss_bar(&config);
    let full_round_budget = adaptive::overhead_for_target(
        fixed_block_k(&config),
        loss_bar,
        RQ_SOURCE_FEC_FALLBACK_ALPHA,
        RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
    );

    assert!(
        (1.04..=1.10).contains(&tuning.repair_overhead),
        "2% target loss should produce a byte-efficient first-flight repair budget, got {}",
        tuning.repair_overhead
    );
    assert!(
        extra_fraction < full_round_budget,
        "round-0 pre-spray should not spend the full feedback round budget: first_flight={extra_fraction} full_round={full_round_budget}"
    );
    assert!(
        adaptive::decode_fail_probability(fixed_block_k(&config), extra_fraction, loss_bar)
            <= RQ_ROUND0_TARGET_ALPHA * 1.000_001,
        "round-0 pre-spray must still hit the round-0 decode-failure target \
         (α={RQ_ROUND0_TARGET_ALPHA}; feedback rounds carry the residual, MATRIX-207)"
    );
    assert!(
        initial_repair_target_per_block(437, tuning.repair_overhead) >= 20,
        "2% loss should pre-spray enough repair symbols to cover the decode-failure target"
    );
    assert!(
        tuning.pacing.path_rate_bps <= RqSprayPacing::cold_start(config.symbol_size).path_rate_bps,
        "round-0 loss calibration must not raise sender pacing"
    );
    assert_eq!(
        tuning.pacing.rate_bytes_per_sec(),
        RQ_BAD_LINK_ROUND0_PACING_BPS,
        "2% bad-link round 0 should pace near the 50 mbit pipe instead of cold-start overrun"
    );
    assert!(
        source_retransmit_needs_fec_fallback(&config, 2, 0, 0.0),
        "repair-only rounds at the source-retransmit boundary must keep FEC fallback enabled"
    );
}

#[test]
fn large_lossy_round0_uses_bounded_parallel_encode_plan() {
    let matrix_50m = 50_u64 * 1024 * 1024;
    let large = 500_u64 * 1024 * 1024;

    let clean = RqConfig {
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };
    assert_eq!(parallel_encode_plan_for_transfer(large, &clean), None);

    let good = RqConfig {
        round0_loss_target: RQ_ROUND0_TARGET_LOSS_ENABLE_MIN / 5.0,
        ..RqConfig::default()
    };
    assert_eq!(parallel_encode_plan_for_transfer(large, &good), None);

    let bad = RqConfig {
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };
    assert_eq!(
        parallel_encode_plan_for_transfer(matrix_50m, &bad),
        Some(ParallelEncodePlan {
            max_batch_blocks: LOSSY_LARGE_PARALLEL_ENCODE_BATCH_BLOCKS
        }),
        "50M bad-link matrix cells must use the bounded lossy encode window to cap sender RSS"
    );
    assert_eq!(
        parallel_encode_plan_for_transfer(large, &bad),
        Some(ParallelEncodePlan {
            max_batch_blocks: LOSSY_LARGE_PARALLEL_ENCODE_BATCH_BLOCKS
        })
    );
    let broken = RqConfig {
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    assert_eq!(
        parallel_encode_plan_for_transfer(matrix_50m, &broken),
        Some(ParallelEncodePlan {
            max_batch_blocks: LOSSY_LARGE_PARALLEL_ENCODE_BATCH_BLOCKS
        }),
        "50M broken-link matrix cells must use the bounded lossy encode window to cap sender RSS"
    );
    assert!(should_parallel_encode_source_blocks(
        MAX_RAPTORQ_SOURCE_BLOCKS,
        parallel_encode_plan_for_transfer(large, &bad)
    ));
    assert!(!should_parallel_encode_source_blocks(
        MAX_RAPTORQ_SOURCE_BLOCKS + 1,
        parallel_encode_plan_for_transfer(large, &bad)
    ));
}

#[test]
fn small_transfer_keeps_existing_full_parallel_encode_plan() {
    let small = PARALLEL_ENCODE_MAX_BYTES;
    let config = RqConfig::default();

    assert_eq!(
        parallel_encode_plan_for_transfer(small, &config),
        Some(ParallelEncodePlan {
            max_batch_blocks: PARALLEL_ENCODE_HOST_MAX_BATCH_BLOCKS
        })
    );
}

#[test]
fn round0_loss_target_for_broken_link_is_bounded() {
    let config = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };

    let overhead = round0_loss_target_repair_overhead(&config);
    let mut state = RqAdaptiveSendState::new(7, &config, 1);
    let tuning = state.round0_tuning(&config);

    let loss_bar = round0_loss_target_loss_bar(&config);
    assert!(
        overhead > 1.0 + loss_bar,
        "broken link must receive proactive FEC above the expected-loss floor: got {overhead}, floor {}",
        1.0 + loss_bar
    );
    assert!(
        overhead < 1.25,
        "round-0 first flight must stay byte-efficient (α={RQ_ROUND0_TARGET_ALPHA} \
         relaxation, MATRIX-207): the old 1e-6 per-block target inflated round-0 \
         to +25.3% and lost the 500M/broken cell on wire time alone; got {overhead}"
    );
    assert_eq!(
        tuning.pacing.rate_bytes_per_sec(),
        RQ_BROKEN_LINK_ROUND0_PACING_BPS,
        "10% broken-link round 0 must pace near the shaped 10 mbit pipe instead of cold-start overrun"
    );
}

#[test]
fn source_retransmit_fec_fallback_uses_adaptive_overhead() {
    let config = RqConfig {
        symbol_size: 1024,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(99, &config, 4);
    state.loss_ema = 0.03;
    state.loss_bar = 0.05;
    state.pacing_loss_ema = 0.05;
    state.est.loss_p_hat = 0.05;

    let tuning = state.source_fec_fallback_tuning(&config);
    let expected = adaptive::overhead_for_target(
        fixed_block_k(&config),
        0.05,
        RQ_SOURCE_FEC_FALLBACK_ALPHA,
        RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
    );

    assert!(
        tuning.repair_overhead >= 1.0 + expected,
        "fallback must apply adaptive FEC overhead: got {}, expected at least {}",
        tuning.repair_overhead,
        1.0 + expected
    );
}

#[test]
fn measured_feedback_repair_overhead_tracks_receiver_loss() {
    assert_eq!(measured_feedback_repair_overhead(0.0), 0.0);
    assert_eq!(measured_feedback_repair_overhead(0.001), 0.0);
    assert_eq!(measured_feedback_repair_overhead(-0.10), 0.0);
    assert_eq!(measured_feedback_repair_overhead(f64::NAN), 0.0);
    assert_eq!(measured_feedback_repair_overhead(f64::INFINITY), 0.0);

    let bad = measured_feedback_repair_overhead(0.02);
    assert!(
        (0.029..=0.031).contains(&bad),
        "2% measured loss should request about 3% repair overhead, got {bad}"
    );

    let broken = measured_feedback_repair_overhead(0.10);
    assert!(
        (0.12..=0.15).contains(&broken),
        "10% measured loss should request a bounded 12-15% repair overhead, got {broken}"
    );

    assert_eq!(
        measured_feedback_repair_overhead(0.90),
        RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
        "pathological measured loss must clamp at the repair-overhead budget"
    );
}

#[test]
fn source_fec_fallback_uses_measured_loss_floor_for_feedback_rounds() {
    let config = RqConfig {
        symbol_size: 1024,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(103, &config, 4);
    state.last_round_loss_fraction = 0.10;
    state.loss_ema = 0.0;
    state.loss_bar = 0.0;
    state.pacing_loss_ema = 0.0;
    state.est.loss_p_hat = 0.0;

    let tuning = state.source_fec_fallback_tuning(&config);
    let measured = measured_feedback_repair_overhead(0.10);

    assert!(
        tuning.repair_overhead >= 1.0 + measured,
        "fallback must honor receiver-measured loss floor: got {}, expected at least {}",
        tuning.repair_overhead,
        1.0 + measured
    );
    assert!(
        repair_target_for_feedback_round(512, 0, tuning.repair_overhead) >= 66,
        "10% broken-link repair round should send enough fresh repair symbols to avoid serial RTT rounds"
    );
}

#[test]
fn source_fec_fallback_preserves_configured_broken_loss_floor() {
    let config = RqConfig {
        symbol_size: 1024,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.10,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(104, &config, 4);
    state.last_round_loss_fraction = 0.0;
    state.loss_ema = 0.0;
    state.loss_bar = 0.0;
    state.pacing_loss_ema = 0.0;
    state.est.loss_p_hat = 0.0;

    let loss_bar = state.source_fec_fallback_loss_bar(&config);
    let expected_loss_bar = round0_loss_target_loss_bar(&config);
    let tuning = state.source_fec_fallback_tuning(&config);
    let expected = adaptive::overhead_for_target(
        fixed_block_k(&config),
        expected_loss_bar,
        RQ_SOURCE_FEC_FALLBACK_ALPHA,
        RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
    );

    assert_eq!(
        loss_bar, expected_loss_bar,
        "broken-regime repair must keep the configured loss floor even when receiver loss is underreported"
    );
    assert!(
        tuning.repair_overhead >= 1.0 + expected,
        "zero reported feedback loss must not shrink broken-link repair below the configured loss target"
    );
    assert!(
        repair_target_for_feedback_round(512, 0, tuning.repair_overhead) >= 100,
        "10% broken-link repair should not devolve into low single-digit repair rounds"
    );
}

#[test]
fn measured_loss_repair_target_fills_deficit_without_whole_block_respray() {
    let block_source_n = 512;
    let measured = measured_feedback_repair_overhead(0.10);
    let repair_overhead = 1.0 + measured;

    let initial_target = initial_repair_target_per_block(block_source_n, repair_overhead);
    assert!(
        (62..=77).contains(&initial_target),
        "10% measured loss should calibrate to roughly 12-15% repair, got {initial_target}"
    );

    assert_eq!(
        repair_target_for_feedback_round(block_source_n, initial_target - 1, repair_overhead),
        initial_target,
        "feedback repair should fill only the remaining measured-loss deficit"
    );

    let follow_up_target =
        repair_target_for_feedback_round(block_source_n, initial_target, repair_overhead);
    assert_eq!(
        follow_up_target,
        initial_target + adaptive_feedback_repair_batch_per_block(block_source_n, repair_overhead),
        "once the measured-loss target is satisfied, later rounds should add one bounded batch"
    );
    assert!(
        follow_up_target < block_source_n / 3,
        "measured-loss feedback must stay bounded and never respray the whole block"
    );
}

#[test]
fn source_fec_fallback_preserves_clean_link_batching_floor() {
    let config = RqConfig {
        symbol_size: 1024,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(101, &config, 4);
    state.loss_ema = 0.0;
    state.loss_bar = 0.0;
    state.pacing_loss_ema = 0.0;
    state.est.loss_p_hat = 0.0;

    let tuning = state.source_fec_fallback_tuning(&config);

    assert_eq!(
        state.source_fec_fallback_loss_bar(&config),
        RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR
    );
    assert!(
        tuning.repair_overhead >= 1.0 + RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD,
        "clean-link fallback must preserve batching floor after E-RESYNC-16: got {}",
        tuning.repair_overhead
    );
}

#[test]
fn source_fec_fallback_keeps_near_clean_batching_floor() {
    let config = RqConfig {
        symbol_size: 1024,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        ..RqConfig::default()
    };
    let mut state = RqAdaptiveSendState::new(102, &config, 4);
    state.loss_ema = 0.001;
    state.loss_bar = 0.001;
    state.pacing_loss_ema = 0.001;
    state.est.loss_p_hat = 0.001;

    let tuning = state.source_fec_fallback_tuning(&config);
    let expected = adaptive::overhead_for_target(
        fixed_block_k(&config),
        RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR,
        RQ_SOURCE_FEC_FALLBACK_ALPHA,
        RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
    );

    assert_eq!(
        state.source_fec_fallback_loss_bar(&config),
        RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR
    );
    assert!(tuning.repair_overhead >= 1.0 + expected);
    assert!(
        tuning.repair_overhead >= 1.0 + RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD,
        "near-clean fallback should batch repair symbols, got {}",
        tuning.repair_overhead
    );
}

#[test]
fn proactive_initial_repair_target_ceilings_extra_fraction() {
    assert_eq!(initial_repair_target_per_block(512, 1.15), 77);
    assert_eq!(initial_repair_target_per_block(1, 1.01), 1);
}

#[test]
fn round0_loss_target_respects_explicit_repair_overhead_floor() {
    let config = RqConfig {
        repair_overhead: 1.25,
        round0_loss_target: 0.02,
        ..RqConfig::default()
    };

    assert!(round0_loss_target_repair_overhead(&config) >= 1.25);
}

#[test]
fn effective_block_size_preserves_k512_streaming_target_for_normal_files() {
    let config = RqConfig::default();
    let symbol_size = usize::from(config.symbol_size);
    assert_eq!(config.symbol_size, DEFAULT_SYMBOL_SIZE);

    let expected_target = symbol_size
        .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
        .min(TARGET_STREAMING_BLOCK_BYTES)
        .min(config.max_block_size);
    assert_eq!(
        expected_target.div_ceil(symbol_size),
        TARGET_SOURCE_SYMBOLS_PER_BLOCK,
        "default streaming target must stay at K512 even after symbol-size changes"
    );

    let effective = effective_max_block_size_for_largest_entry(&config, 10 * 1024 * 1024)
        .expect("10MiB should fit");
    assert_eq!(effective, expected_target);
    assert_eq!(
        max_block_source_symbol_count(10 * 1024 * 1024, config.symbol_size, effective),
        TARGET_SOURCE_SYMBOLS_PER_BLOCK
    );
}

#[test]
fn effective_block_size_grows_from_k512_only_to_fit_sbn_limit() {
    let config = RqConfig::default();
    let one_gib: usize = 1024 * 1024 * 1024;
    let symbol_size = usize::from(config.symbol_size);
    let streaming_target = symbol_size
        .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
        .min(TARGET_STREAMING_BLOCK_BYTES);
    assert_eq!(
        streaming_target.div_ceil(symbol_size),
        TARGET_SOURCE_SYMBOLS_PER_BLOCK,
        "fixture starts from the default K512 streaming target"
    );
    let min_symbol_aligned_block = one_gib
        .div_ceil(MAX_SOURCE_BLOCKS)
        .max(symbol_size)
        .div_ceil(symbol_size)
        .saturating_mul(symbol_size);
    let effective = effective_max_block_size_for_largest_entry(&config, one_gib)
        .expect("1GiB should fit default transfer geometry");
    assert_eq!(
        effective, min_symbol_aligned_block,
        "large entries should grow only enough to fit the u8 SBN limit"
    );
    assert!(
        effective > streaming_target,
        "this fixture must exercise SBN-limit growth beyond the normal streaming target"
    );
    assert!(
        one_gib.div_ceil(effective - symbol_size) > MAX_SOURCE_BLOCKS,
        "one symbol-aligned step smaller should exceed the SBN wire limit"
    );
    assert_eq!(one_gib.div_ceil(effective), MAX_SOURCE_BLOCKS);
}

#[test]
fn effective_block_size_rejects_unsplit_huge_entries() {
    // E-12: a 5 GiB logical file must be split into multiple bounded
    // RaptorQ objects before this helper runs. If an unsplit object reaches
    // this point, fail closed instead of growing K above the configured max.
    let config = RqConfig::default();
    let symbol_size = usize::from(config.symbol_size);
    let five_gib: usize = 5 * 1024 * 1024 * 1024;
    assert!(matches!(
        effective_max_block_size_for_largest_entry(&config, five_gib),
        Err(RqError::Coding(msg)) if msg.starts_with("[ASUP-E803]")
    ));

    // Entries within the configured 2 GiB default ceiling are unaffected (byte-identical).
    let one_gib: usize = 1024 * 1024 * 1024;
    assert_eq!(
        effective_max_block_size_for_largest_entry(&config, one_gib).unwrap(),
        one_gib
            .div_ceil(MAX_SOURCE_BLOCKS)
            .max(symbol_size)
            .div_ceil(symbol_size)
            .saturating_mul(symbol_size)
    );

    // One byte beyond the configured object ceiling fails closed unless it
    // has first been split into multiple objects.
    let ceiling = config.max_block_size.saturating_mul(MAX_SOURCE_BLOCKS);
    assert!(matches!(
        effective_max_block_size_for_largest_entry(&config, ceiling + 1),
        Err(RqError::Coding(msg)) if msg.starts_with("[ASUP-E803]")
    ));
}

#[test]
fn max_block_source_symbols_uses_effective_block_not_entry_size() {
    let config = RqConfig::default();
    let symbol_size = usize::from(config.symbol_size);
    let effective_k512_block = symbol_size * TARGET_SOURCE_SYMBOLS_PER_BLOCK;
    assert_eq!(
        max_block_source_symbol_count(10 * 1024 * 1024, config.symbol_size, effective_k512_block),
        TARGET_SOURCE_SYMBOLS_PER_BLOCK
    );
    assert_eq!(
        max_block_source_symbol_count(10 * 1024 * 1024, config.symbol_size, DEFAULT_MAX_BLOCK_SIZE),
        DEFAULT_MAX_BLOCK_SIZE.div_ceil(symbol_size)
    );
}

fn m1_test_encoding_config(config: &RqConfig) -> crate::config::EncodingConfig {
    crate::config::EncodingConfig {
        repair_overhead: config.repair_overhead,
        max_block_size: config.max_block_size,
        symbol_size: config.symbol_size,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

fn symbol_fingerprint(symbol: &Symbol) -> (u8, u32, SymbolKind, Vec<u8>) {
    (
        symbol.id().sbn(),
        symbol.id().esi(),
        symbol.kind(),
        symbol.data().to_vec(),
    )
}

fn collect_monolithic_symbols(
    object_id: ObjectId,
    bytes: &[u8],
    config: &RqConfig,
    repair_count: usize,
) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
    let mut pipeline = EncodingPipeline::new(
        m1_test_encoding_config(config),
        SymbolPool::new(PoolConfig::default()),
    );
    pipeline
        .encode_with_repair(object_id, bytes, repair_count)
        .map(|encoded| {
            let encoded = encoded.expect("monolithic encode succeeds");
            symbol_fingerprint(encoded.symbol())
        })
        .collect()
}

fn collect_m1_source_symbols(
    object_id: ObjectId,
    bytes: &[u8],
    config: &RqConfig,
    repair_count: usize,
) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
    let mut symbols = Vec::new();
    for block in encode_ahead_blocks(bytes.len(), config).expect("block plan") {
        let mut pipeline = EncodingPipeline::new(
            m1_test_encoding_config(config),
            SymbolPool::new(PoolConfig::default()),
        );
        for encoded in pipeline.encode_single_block_with_repair(
            object_id,
            block.sbn,
            &bytes[block.start..block.start + block.len],
            repair_count,
        ) {
            let encoded = encoded.expect("M=1 source encode succeeds");
            symbols.push(symbol_fingerprint(encoded.symbol()));
        }
    }
    symbols
}

fn collect_source_only_block_symbols(
    object_id: ObjectId,
    bytes: &[u8],
    config: &RqConfig,
) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
    let mut symbols = Vec::new();
    let symbol_size = usize::from(config.symbol_size);
    for block in encode_ahead_blocks(bytes.len(), config).expect("block plan") {
        for esi in 0..block.k {
            let symbol = source_symbol_from_block(
                object_id,
                block.sbn,
                esi,
                &bytes[block.start..block.start + block.len],
                symbol_size,
            )
            .expect("source-only symbol");
            symbols.push(symbol_fingerprint(&symbol));
        }
    }
    symbols
}

fn bonded_test_descriptor(bytes: &[u8], config: &RqConfig) -> BondTransferDescriptor {
    let entry = ManifestEntry {
        index: 0,
        rel_path: "payload.bin".to_string(),
        size: bytes.len() as u64,
        sha256_hex: hex_encode(&Sha256::digest(bytes)),
        members: Vec::new(),
        fragment: None,
    };
    let manifest = TransferManifest {
        transfer_id: "bonded-donor-spray-test".to_string(),
        root_name: "payload".to_string(),
        is_directory: false,
        total_bytes: bytes.len() as u64,
        merkle_root_hex: "00".repeat(32),
        metadata: None,
        delta_manifest: None,
        entries: vec![entry],
    };
    BondTransferDescriptor::from_manifest(
        &manifest,
        config.symbol_size,
        config.max_block_size as u64,
        None,
    )
}

fn bonded_test_assignment(donor_index: u32, donor_count: u32) -> DonorAssignment {
    DonorAssignment::new_static(
        donor_index,
        donor_count,
        vec![std::net::SocketAddr::from(([127, 0, 0, 1], 48123))],
        None,
    )
}

fn collect_bonded_donor_test_symbols(
    descriptor: &BondTransferDescriptor,
    assignment: &DonorAssignment,
    bytes: &[u8],
    config: &RqConfig,
) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
    let repair_symbols_per_block =
        bonded_initial_repair_symbols_per_block(config).expect("repair budget");
    let schedule = schedule_bonded_donor_spray(descriptor, assignment, repair_symbols_per_block)
        .expect("bonded schedule");

    let mut symbols = Vec::new();
    for block in &schedule.blocks {
        let start = usize::try_from(block.geometry.block_start).expect("test block start");
        let len = usize::try_from(block.geometry.block_bytes).expect("test block len");
        for emission in block.symbol_emissions(schedule.donor_index) {
            let symbol = encode_bonded_donor_emission(emission, &bytes[start..start + len], config)
                .expect("bonded emission encodes");
            symbols.push(symbol_fingerprint(&symbol));
        }
    }
    symbols
}

#[test]
fn bonded_donor_count_one_matches_single_source_round0_symbols() {
    let config = RqConfig {
        symbol_size: 4,
        max_block_size: 8,
        repair_overhead: 2.0,
        ..RqConfig::default()
    };
    let bytes = b"abcdefghijklmnop";
    let descriptor = bonded_test_descriptor(bytes, &config);
    let assignment = bonded_test_assignment(0, 1);
    let object_id = descriptor.entry_object_id(0);

    let actual = collect_bonded_donor_test_symbols(&descriptor, &assignment, bytes, &config);
    let expected = collect_m1_source_symbols(object_id, bytes, &config, 2);

    assert_eq!(actual, expected);
}

#[test]
fn bonded_donor_symbols_stay_inside_static_residue_class() {
    let config = RqConfig {
        symbol_size: 4,
        max_block_size: 8,
        repair_overhead: 2.0,
        ..RqConfig::default()
    };
    let bytes = b"abcdefghijklmnop";
    let descriptor = bonded_test_descriptor(bytes, &config);
    let assignment = bonded_test_assignment(1, 2);

    let symbols = collect_bonded_donor_test_symbols(&descriptor, &assignment, bytes, &config);

    assert!(
        symbols
            .iter()
            .any(|(_, _, kind, _)| *kind == SymbolKind::Source),
        "donor should keep the receiver's source-first path alive"
    );
    assert!(
        symbols
            .iter()
            .any(|(_, _, kind, _)| *kind == SymbolKind::Repair),
        "donor should emit assigned repair symbols too"
    );
    for (_, esi, _, _) in symbols {
        assert_eq!(esi % 2, 1, "donor emitted out-of-residue ESI {esi}");
    }
}

#[test]
fn bonded_donor_round0_pacing_decision_is_reported_and_bounded() {
    let config = RqConfig {
        symbol_size: 1200,
        max_block_size: 512 * 1024,
        repair_overhead: 1.0,
        round0_loss_target: 0.0,
        ..RqConfig::default()
    };

    let decision = bonded_donor_round0_pacing_decision("bonded-donor-pacing", &config, 2);
    let pacer = RqSprayPacer::new_round0(decision.pacing, &config, false);

    assert_eq!(
        decision.report.initial_rate_bytes_per_sec,
        decision.pacing.rate_bytes_per_sec()
    );
    assert_eq!(
        decision.report.final_rate_bytes_per_sec,
        decision.report.initial_rate_bytes_per_sec
    );
    assert_eq!(
        decision.report.burst_symbols,
        decision.pacing.max_burst_size
    );
    assert_eq!(decision.report.burst_bytes, decision.pacing.burst_bytes());
    assert_eq!(
        decision.report.datagram_bytes,
        decision.pacing.datagram_bytes
    );
    assert!(
        decision.report.burst_bytes < decision.report.initial_rate_bytes_per_sec,
        "donor pacing must bound a send burst below a full second of path budget"
    );
    assert_eq!(
        decision.report.clean_round0_ramp_enabled,
        pacer.round0_ramp.is_some()
    );
}

fn collect_monolithic_repair_symbols(
    object_id: ObjectId,
    bytes: &[u8],
    config: &RqConfig,
    first_repair: usize,
    repair_count: usize,
) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
    let mut pipeline = EncodingPipeline::new(
        m1_test_encoding_config(config),
        SymbolPool::new(PoolConfig::default()),
    );
    pipeline
        .encode_repair_range(object_id, bytes, first_repair, repair_count)
        .map(|encoded| {
            let encoded = encoded.expect("monolithic repair encode succeeds");
            symbol_fingerprint(encoded.symbol())
        })
        .collect()
}

fn collect_m1_repair_symbols(
    object_id: ObjectId,
    bytes: &[u8],
    config: &RqConfig,
    first_repair: usize,
    repair_count: usize,
) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
    let mut symbols = Vec::new();
    for block in encode_ahead_blocks(bytes.len(), config).expect("block plan") {
        let mut pipeline = EncodingPipeline::new(
            m1_test_encoding_config(config),
            SymbolPool::new(PoolConfig::default()),
        );
        for encoded in pipeline.encode_single_block_repair_range(
            object_id,
            block.sbn,
            &bytes[block.start..block.start + block.len],
            first_repair,
            repair_count,
        ) {
            let encoded = encoded.expect("M=1 repair encode succeeds");
            symbols.push(symbol_fingerprint(encoded.symbol()));
        }
    }
    symbols
}

#[test]
fn encode_ahead_ring_is_single_slot_fifo() {
    let mut ring = EncodeAheadRing::default();
    assert_eq!(EncodeAheadRing::CAPACITY, 1);

    let object_id = ObjectId::new_for_test(0xF204);
    let first = EncodeAheadSymbol {
        entry: 7,
        symbol: Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![1, 2, 3],
            SymbolKind::Source,
        ),
    };
    let second = EncodeAheadSymbol {
        entry: 8,
        symbol: Symbol::new(
            SymbolId::new(object_id, 0, 1),
            vec![4, 5, 6],
            SymbolKind::Source,
        ),
    };

    ring.push(first).expect("first symbol fits");
    assert!(matches!(
        ring.push(second),
        Err(RqError::Coding(message)) if message.contains("ring is full")
    ));

    let popped = ring.pop().expect("first symbol queued");
    assert_eq!(popped.entry, 7);
    assert_eq!(popped.symbol.id().esi(), 0);
    assert!(ring.is_empty());
}

#[test]
fn encode_ahead_blocks_match_monolithic_block_geometry() {
    let config = RqConfig {
        symbol_size: 4,
        max_block_size: 6,
        ..RqConfig::default()
    };

    assert_eq!(
        encode_ahead_blocks(13, &config).expect("block plan"),
        vec![
            EncodeAheadBlock {
                sbn: 0,
                start: 0,
                len: 6,
                k: 2,
            },
            EncodeAheadBlock {
                sbn: 1,
                start: 6,
                len: 6,
                k: 2,
            },
            EncodeAheadBlock {
                sbn: 2,
                start: 12,
                len: 1,
                k: 1,
            },
        ]
    );
    assert!(
        encode_ahead_blocks(0, &config)
            .expect("empty plan")
            .is_empty()
    );

    let small_blocks = RqConfig {
        symbol_size: 8,
        max_block_size: 3,
        ..RqConfig::default()
    };
    assert_eq!(
        encode_ahead_blocks(7, &small_blocks).expect("small block plan"),
        vec![
            EncodeAheadBlock {
                sbn: 0,
                start: 0,
                len: 3,
                k: 1,
            },
            EncodeAheadBlock {
                sbn: 1,
                start: 3,
                len: 3,
                k: 1,
            },
            EncodeAheadBlock {
                sbn: 2,
                start: 6,
                len: 1,
                k: 1,
            },
        ]
    );
}

#[test]
fn read_source_range_reassembles_original_bytes_on_demand() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("payload.bin");
    let bytes: Vec<u8> = (0..257).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &bytes).expect("write payload");

    let mut reassembled = Vec::new();
    for (offset, len) in [(0, 17), (17, 64), (81, 128), (209, 48)] {
        let chunk = futures_lite::future::block_on(read_source_range(&path, offset, len))
            .expect("read source chunk");
        reassembled.extend_from_slice(&chunk);
    }

    assert_eq!(reassembled, bytes);
}

#[test]
fn read_source_range_fails_closed_on_truncated_source() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, b"short").expect("write payload");

    let err = futures_lite::future::block_on(read_source_range(&path, 2, 8))
        .expect_err("range past EOF must fail");
    assert!(
        matches!(&err, RqError::Source(message) if message.contains("payload.bin")),
        "expected source-path error, got {err:?}"
    );
}

#[test]
fn source_block_progress_covers_complete_entries_or_disables_streaming() {
    let progress = source_block_progress_for(5, 2, 2).expect("complete block table");
    assert_eq!(progress.len(), 3);
    assert_eq!(
        progress
            .iter()
            .map(|block| (block.start, block.len, block.k, block.received.len()))
            .collect::<Vec<_>>(),
        vec![(0, 2, 1, 1), (2, 2, 1, 1), (4, 1, 1, 1)]
    );

    let too_many_blocks = u64::try_from(MAX_SOURCE_BLOCKS + 1).unwrap_or(u64::MAX);
    assert!(
        source_block_progress_for(too_many_blocks, 1, 1).is_none(),
        "source streaming must fall back to the decoder when the SBN envelope is incomplete"
    );
}

#[test]
fn m1_encode_ahead_source_and_initial_repair_is_byte_identical() {
    let config = RqConfig {
        symbol_size: 4,
        max_block_size: 6,
        repair_overhead: 1.0,
        ..RqConfig::default()
    };
    let object_id = ObjectId::new_for_test(0xF202);
    let bytes = b"abcdefghijklmnopq";

    assert_eq!(
        collect_m1_source_symbols(object_id, bytes, &config, 2),
        collect_monolithic_symbols(object_id, bytes, &config, 2)
    );
}

#[test]
fn source_only_block_symbols_match_pipeline_source_symbols() {
    let config = RqConfig {
        symbol_size: 4,
        max_block_size: 6,
        repair_overhead: 1.0,
        ..RqConfig::default()
    };
    let object_id = ObjectId::new_for_test(0xF205);
    let bytes = b"source-only-fast-path";

    assert_eq!(
        collect_source_only_block_symbols(object_id, bytes, &config),
        collect_m1_source_symbols(object_id, bytes, &config, 0)
    );
}

#[test]
fn m1_encode_ahead_repair_range_is_byte_identical() {
    let config = RqConfig {
        symbol_size: 4,
        max_block_size: 6,
        repair_overhead: 1.0,
        ..RqConfig::default()
    };
    let object_id = ObjectId::new_for_test(0xF203);
    let bytes = b"repair-rounds-span-blocks";

    assert_eq!(
        collect_m1_repair_symbols(object_id, bytes, &config, 1, 3),
        collect_monolithic_repair_symbols(object_id, bytes, &config, 1, 3)
    );
}

#[test]
fn object_params_match_block_plan() {
    // 3 MiB with 8 MiB blocks => 1 block; 1024-byte symbols => K=3072.
    let p = object_params_for(ObjectId::new(0, 0), 3 * 1024 * 1024, 1024, 8 * 1024 * 1024);
    assert_eq!(p.source_blocks, 1);
    assert_eq!(p.symbols_per_block, 3072);
    // 20 MiB with 8 MiB blocks => 3 blocks (8+8+4).
    let p2 = object_params_for(ObjectId::new(0, 0), 20 * 1024 * 1024, 1024, 8 * 1024 * 1024);
    assert_eq!(p2.source_blocks, 3);
    assert_eq!(p2.symbols_per_block, 8192);
}

// ─── E-12 large-entry multi-object split ───────────────────────────────

fn digest_for_bytes(rel_path: &str, bytes: &[u8]) -> EntryDigest {
    EntryDigest {
        rel_path: rel_path.to_string(),
        size: bytes.len() as u64,
        content_id: crate::atp::object::ObjectId::content(
            crate::atp::object::ContentId::from_bytes(bytes),
        ),
        content_sha256: Sha256::digest(bytes).into(),
    }
}

#[test]
fn verify_and_commit_replaces_readonly_regular_file_with_staged_metadata() {
    let dest = tempfile::tempdir().expect("dest dir");
    let staging_dir = dest.path().join(".atp-rq-regular-staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");
    let staging_path = staging_dir.join("0");
    let bytes = b"new regular-file payload".to_vec();
    std::fs::write(&staging_path, &bytes).expect("write staged payload");

    let out_path = dest.path().join("payload.bin");
    std::fs::write(&out_path, b"old readonly payload").expect("write existing output");
    let mut existing_permissions = std::fs::metadata(&out_path)
        .expect("existing output metadata")
        .permissions();
    existing_permissions.set_readonly(true);
    std::fs::set_permissions(&out_path, existing_permissions)
        .expect("make existing output readonly");

    let mut entry_metadata = EntryMetadata::default();
    #[cfg(unix)]
    {
        entry_metadata.unix_mode = Some(0o440);
    }
    #[cfg(windows)]
    {
        entry_metadata.windows_attributes = Some(0x0000_0021);
        entry_metadata.mtime_unix_secs = Some(1_700_000_000);
        entry_metadata.mtime_nanos = Some(123_400_000);
    }

    let digest = digest_for_bytes("payload.bin", &bytes);
    let manifest = TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "payload.bin".to_string(),
        is_directory: false,
        total_bytes: bytes.len() as u64,
        merkle_root_hex: flat_merkle_root_from_digests(std::slice::from_ref(&digest)),
        metadata: Some(one_entry_metadata_manifest("payload.bin", entry_metadata)),
        delta_manifest: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: "payload.bin".to_string(),
            size: bytes.len() as u64,
            sha256_hex: hex_encode(&digest.content_sha256),
            members: Vec::new(),
            fragment: None,
        }],
    };
    let mut decoders = vec![EntryDecoder {
        index: 0,
        object_id: entry_object_id(&manifest.transfer_id, 0),
        size: bytes.len() as u64,
        pipeline: None,
        complete: true,
        staging_path,
        staging_write_offset: 0,
        staging_file_len: bytes.len() as u64,
        staging_shared: false,
        staging_created: true,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: bytes.len() as u64,
        max_block_size: DEFAULT_MAX_BLOCK_SIZE,
        source_streaming: false,
        source_blocks: Vec::new(),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    }];

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &std::collections::BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect("verify regular file");

    assert!(receipt.committed, "regular transfer must commit");
    assert_eq!(std::fs::read(&out_path).expect("regular output"), bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&out_path)
                .expect("regular output metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o440
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        assert_eq!(
            std::fs::metadata(&out_path)
                .expect("regular output metadata")
                .file_attributes()
                & 0x0000_0021,
            0x0000_0021
        );
        let mut permissions = std::fs::metadata(&out_path)
            .expect("regular output cleanup metadata")
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&out_path, permissions)
            .expect("clear regular output readonly for cleanup");
    }
}

fn fragment_entry(
    index: u32,
    object_rel_path: &str,
    object_bytes: &[u8],
    fragment: LargeObjectFragment,
) -> ManifestEntry {
    ManifestEntry {
        index,
        rel_path: object_rel_path.to_string(),
        size: object_bytes.len() as u64,
        sha256_hex: hex_encode(&Sha256::digest(object_bytes)),
        members: Vec::new(),
        fragment: Some(fragment),
    }
}

fn two_fragment_manifest(a: &[u8], b: &[u8]) -> TransferManifest {
    let mut whole = Vec::with_capacity(a.len().saturating_add(b.len()));
    whole.extend_from_slice(a);
    whole.extend_from_slice(b);
    let whole_sha = hex_encode(&Sha256::digest(&whole));
    TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "huge.bin".to_string(),
        is_directory: false,
        total_bytes: whole.len() as u64,
        merkle_root_hex: flat_merkle_root_from_digests(&[digest_for_bytes("huge.bin", &whole)]),
        metadata: None,
        delta_manifest: None,
        entries: vec![
            fragment_entry(
                0,
                ".atp-fragment-0-0",
                a,
                LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 0,
                    shard_count: 2,
                    logical_offset: 0,
                    len: a.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: whole_sha.clone(),
                },
            ),
            fragment_entry(
                1,
                ".atp-fragment-0-1",
                b,
                LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 1,
                    shard_count: 2,
                    logical_offset: a.len() as u64,
                    len: b.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: whole_sha,
                },
            ),
        ],
    }
}

fn shared_fragment_decoders(
    manifest: &TransferManifest,
    staging_path: &Path,
    complete: bool,
    staging_created: bool,
) -> Vec<EntryDecoder> {
    manifest
        .entries
        .iter()
        .map(|entry| {
            let fragment = entry.fragment.as_ref().expect("fragment metadata");
            EntryDecoder {
                index: entry.index,
                object_id: entry_object_id(&manifest.transfer_id, entry.index),
                size: entry.size,
                pipeline: None,
                complete,
                staging_path: staging_path.to_path_buf(),
                staging_write_offset: fragment.logical_offset,
                staging_file_len: fragment.logical_size,
                staging_shared: true,
                staging_created,
                staging_file: None,
                staging_cursor: None,
                staging_unflushed_bytes: 0,
                cache_staging_file: false,
                bytes_written: if complete { entry.size } else { 0 },
                max_block_size: DEFAULT_MAX_BLOCK_SIZE,
                source_streaming: false,
                source_blocks: Vec::new(),
                pending_decodes: Vec::new(),
                inc: None,
                inc_digest: None,
                source_write_buffer: Vec::new(),
                source_write_buffer_offset: None,
            }
        })
        .collect()
}

#[cfg(unix)]
fn inode_for(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path).expect("metadata").ino()
}

#[test]
fn split_large_entries_plans_bounded_ranged_objects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bytes: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
    let entry = source_entry(dir.path(), "huge.bin", &bytes);
    let logical = vec![digest_for_bytes("huge.bin", &bytes)];
    let config = RqConfig {
        symbol_size: 1,
        max_block_size: 1,
        ..RqConfig::default()
    };

    let split = futures_lite::future::block_on(split_large_entries(vec![entry], &logical, &config))
        .expect("split large entry");

    assert_eq!(split.len(), 3, "600 bytes at 256-byte objects => 3 shards");
    assert_eq!(split[0].source_offset, 0);
    assert_eq!(split[0].source_len, Some(256));
    assert_eq!(split[1].source_offset, 256);
    assert_eq!(split[1].source_len, Some(256));
    assert_eq!(split[2].source_offset, 512);
    assert_eq!(split[2].source_len, Some(88));
    for (idx, shard) in split.iter().enumerate() {
        let fragment = shard.fragment.as_ref().expect("fragment metadata");
        assert_eq!(fragment.rel_path, "huge.bin");
        assert_eq!(fragment.shard_index, idx as u32);
        assert_eq!(fragment.shard_count, 3);
        assert_eq!(fragment.logical_size, bytes.len() as u64);
        assert_eq!(fragment.sha256_hex, hex_encode(&Sha256::digest(&bytes)));
    }

    let mut buf = vec![0u8; 64];
    let (range_size, _, range_sha) =
        futures_lite::future::block_on(hash_source_entry_streaming(&split[1], &mut buf))
            .expect("range hash");
    assert_eq!(range_size, 256);
    let expected_range_sha: [u8; 32] = Sha256::digest(&bytes[256..512]).into();
    assert_eq!(range_sha, expected_range_sha);
}

#[test]
fn validate_manifest_accepts_and_bounds_fragment_table() {
    let whole = b"abcdefghijklmnopqrstuvwxyz".to_vec();
    let a = &whole[..10];
    let b = &whole[10..];
    let whole_sha = hex_encode(&Sha256::digest(&whole));
    let entries = vec![
        fragment_entry(
            0,
            ".atp-fragment-0-0",
            a,
            LargeObjectFragment {
                rel_path: "huge.bin".to_string(),
                shard_index: 0,
                shard_count: 2,
                logical_offset: 0,
                len: a.len() as u64,
                logical_size: whole.len() as u64,
                sha256_hex: whole_sha.clone(),
            },
        ),
        fragment_entry(
            1,
            ".atp-fragment-0-1",
            b,
            LargeObjectFragment {
                rel_path: "huge.bin".to_string(),
                shard_index: 1,
                shard_count: 2,
                logical_offset: a.len() as u64,
                len: b.len() as u64,
                logical_size: whole.len() as u64,
                sha256_hex: whole_sha,
            },
        ),
    ];
    let manifest = TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "huge.bin".to_string(),
        is_directory: false,
        total_bytes: whole.len() as u64,
        merkle_root_hex: flat_merkle_root_from_digests(&[digest_for_bytes("huge.bin", &whole)]),
        metadata: Some(bare_metadata_manifest(["huge.bin"])),
        delta_manifest: None,
        entries,
    };
    assert!(validate_manifest(&manifest, &RqConfig::default()).is_ok());

    let mut gapped = manifest.clone();
    gapped.entries[0]
        .fragment
        .as_mut()
        .expect("fragment")
        .logical_size += 1;
    gapped.entries[1]
        .fragment
        .as_mut()
        .expect("fragment")
        .logical_offset += 1;
    gapped.entries[1]
        .fragment
        .as_mut()
        .expect("fragment")
        .logical_size += 1;
    assert!(matches!(
        validate_manifest(&gapped, &RqConfig::default()),
        Err(RqError::Frame(m)) if m.contains("not contiguous")
    ));
}

#[test]
fn verify_and_commit_reassembles_fragmented_file() {
    let dest = tempfile::tempdir().expect("dest dir");
    let staging_dir = dest.path().join(".atp-rq-fragment-staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");

    let a = b"first fragment ".to_vec();
    let b = b"second fragment".to_vec();
    let mut whole = Vec::new();
    whole.extend_from_slice(&a);
    whole.extend_from_slice(&b);
    let a_path = staging_dir.join("0");
    let b_path = staging_dir.join("1");
    std::fs::write(&a_path, &a).expect("write first shard");
    std::fs::write(&b_path, &b).expect("write second shard");

    let out_path = dest.path().join("huge.bin");
    std::fs::write(&out_path, b"old readonly fragment output")
        .expect("write existing fragmented output");
    let mut existing_permissions = std::fs::metadata(&out_path)
        .expect("existing fragmented output metadata")
        .permissions();
    existing_permissions.set_readonly(true);
    std::fs::set_permissions(&out_path, existing_permissions)
        .expect("make existing fragmented output readonly");

    let mut entry_metadata = EntryMetadata::default();
    #[cfg(unix)]
    {
        entry_metadata.unix_mode = Some(0o440);
    }
    #[cfg(windows)]
    {
        entry_metadata.windows_attributes = Some(0x0000_0021);
        entry_metadata.mtime_unix_secs = Some(1_700_000_000);
        entry_metadata.mtime_nanos = Some(123_400_000);
    }

    let whole_sha = hex_encode(&Sha256::digest(&whole));
    let manifest = TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "huge.bin".to_string(),
        is_directory: false,
        total_bytes: whole.len() as u64,
        merkle_root_hex: flat_merkle_root_from_digests(&[digest_for_bytes("huge.bin", &whole)]),
        metadata: Some(one_entry_metadata_manifest("huge.bin", entry_metadata)),
        delta_manifest: None,
        entries: vec![
            fragment_entry(
                0,
                ".atp-fragment-0-0",
                &a,
                LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 0,
                    shard_count: 2,
                    logical_offset: 0,
                    len: a.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: whole_sha.clone(),
                },
            ),
            fragment_entry(
                1,
                ".atp-fragment-0-1",
                &b,
                LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 1,
                    shard_count: 2,
                    logical_offset: a.len() as u64,
                    len: b.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: whole_sha,
                },
            ),
        ],
    };
    let mut decoders = vec![
        EntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: a.len() as u64,
            pipeline: None,
            complete: true,
            staging_path: a_path,
            staging_write_offset: 0,
            staging_file_len: a.len() as u64,
            staging_shared: false,
            staging_created: true,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: a.len() as u64,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: false,
            source_blocks: Vec::new(),
            pending_decodes: Vec::new(),
            inc: None,
            inc_digest: None,
            source_write_buffer: Vec::new(),
            source_write_buffer_offset: None,
        },
        EntryDecoder {
            index: 1,
            object_id: entry_object_id(&manifest.transfer_id, 1),
            size: b.len() as u64,
            pipeline: None,
            complete: true,
            staging_path: b_path,
            staging_write_offset: 0,
            staging_file_len: b.len() as u64,
            staging_shared: false,
            staging_created: true,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: b.len() as u64,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: false,
            source_blocks: Vec::new(),
            pending_decodes: Vec::new(),
            inc: None,
            inc_digest: None,
            source_write_buffer: Vec::new(),
            source_write_buffer_offset: None,
        },
    ];

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &std::collections::BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect("verify fragmented file");

    assert!(receipt.committed, "fragmented transfer must commit");
    assert!(receipt.sha_ok);
    assert!(receipt.merkle_ok);
    assert_eq!(receipt.files, 1);
    assert_eq!(std::fs::read(&out_path).unwrap(), whole);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&out_path)
                .expect("fragmented output metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o440
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        assert_eq!(
            std::fs::metadata(&out_path)
                .expect("fragmented output metadata")
                .file_attributes()
                & 0x0000_0021,
            0x0000_0021
        );
        let mut permissions = std::fs::metadata(&out_path)
            .expect("fragmented output cleanup metadata")
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&out_path, permissions)
            .expect("clear fragmented output readonly for cleanup");
    }
}

#[test]
fn verify_and_commit_renames_contiguous_single_file_fragment_staging() {
    let dest = tempfile::tempdir().expect("dest dir");
    let receive_staging_dir = dest.path().join(".atp-rq-staging-rqtransfer1-0");
    let fragment_dir = receive_staging_dir.join(RQ_SINGLE_FILE_FRAGMENT_STAGING_DIR);
    std::fs::create_dir_all(&fragment_dir).expect("fragment staging dir");

    let a = vec![b'a'; 4096];
    let b = vec![b'b'; 4096];
    let mut whole = Vec::with_capacity(a.len() + b.len());
    whole.extend_from_slice(&a);
    whole.extend_from_slice(&b);
    let staging_path = fragment_dir.join("0");
    std::fs::write(&staging_path, &whole).expect("write contiguous fragment staging");

    let manifest = two_fragment_manifest(&a, &b);
    let planned_staging = single_file_fragment_staging_path(&manifest, &receive_staging_dir)
        .expect("single-file fragment staging path");
    assert_eq!(planned_staging, staging_path);
    let mut decoders = shared_fragment_decoders(&manifest, &staging_path, true, true);
    #[cfg(unix)]
    let staging_inode = inode_for(&staging_path);

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect("verify contiguous fragmented file");

    assert!(receipt.committed, "fragmented transfer must commit");
    assert!(receipt.sha_ok);
    assert!(receipt.merkle_ok);
    let out_path = dest.path().join("huge.bin");
    assert_eq!(
        std::fs::read(&out_path).expect("read committed file"),
        whole
    );
    assert!(
        !staging_path.exists(),
        "rename branch must move the contiguous staging file"
    );
    #[cfg(unix)]
    assert_eq!(
        inode_for(&out_path),
        staging_inode,
        "committed file should be the renamed staging inode"
    );
}

#[test]
fn verify_and_commit_rejects_tampered_contiguous_fragment_and_cleans_staging() {
    let dest = tempfile::tempdir().expect("dest dir");
    let receive_staging_dir = dest.path().join(".atp-rq-staging-rqtransfer1-0");
    let fragment_dir = receive_staging_dir.join(RQ_SINGLE_FILE_FRAGMENT_STAGING_DIR);
    std::fs::create_dir_all(&fragment_dir).expect("fragment staging dir");

    let a = b"first verified fragment".to_vec();
    let b = b"second verified fragment".to_vec();
    let mut tampered = Vec::with_capacity(a.len() + b.len());
    tampered.extend_from_slice(&a);
    tampered.extend_from_slice(&b);
    tampered[a.len()] ^= 0x5a;
    let staging_path = fragment_dir.join("0");
    std::fs::write(&staging_path, &tampered).expect("write tampered staging");

    let manifest = two_fragment_manifest(&a, &b);
    let mut decoders = shared_fragment_decoders(&manifest, &staging_path, true, true);
    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect("verify returns fail-closed receipt");

    assert!(!receipt.committed, "tampered fragment must not commit");
    assert!(!receipt.sha_ok);
    assert!(!dest.path().join("huge.bin").exists());
    assert!(
        !staging_path.exists(),
        "failed contiguous fragment verification must clean staging"
    );
}

#[test]
fn contiguous_fragment_staging_accepts_out_of_order_datagram_writes() {
    let dest = tempfile::tempdir().expect("dest dir");
    let receive_staging_dir = dest.path().join(".atp-rq-staging-rqtransfer1-0");
    let fragment_dir = receive_staging_dir.join(RQ_SINGLE_FILE_FRAGMENT_STAGING_DIR);
    let staging_path = fragment_dir.join("0");

    let a = b"first fragment arrives second".to_vec();
    let b = b"second fragment arrives first".to_vec();
    let mut whole = Vec::with_capacity(a.len() + b.len());
    whole.extend_from_slice(&a);
    whole.extend_from_slice(&b);
    let manifest = two_fragment_manifest(&a, &b);
    let mut decoders = shared_fragment_decoders(&manifest, &staging_path, false, false);

    futures_lite::future::block_on(write_entry_staging_range(&mut decoders[1], 0, &b))
        .expect("write second fragment first");
    futures_lite::future::block_on(write_entry_staging_range(&mut decoders[0], 0, &a))
        .expect("write first fragment second");
    for decoder in &mut decoders {
        decoder.complete = true;
        decoder.bytes_written = decoder.size;
    }

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect("verify out-of-order contiguous fragments");

    assert!(receipt.committed);
    assert!(receipt.sha_ok);
    assert!(receipt.merkle_ok);
    assert_eq!(
        std::fs::read(dest.path().join("huge.bin")).expect("read committed file"),
        whole
    );
}

#[test]
fn verify_and_commit_uses_source_stream_trailer_digests_for_manifest_placeholders() {
    let dest = tempfile::tempdir().expect("dest dir");
    let staging_dir = dest.path().join(".atp-rq-trailer-staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");

    let a = b"source-stream fragment one ".to_vec();
    let b = b"source-stream fragment two".to_vec();
    let mut whole = Vec::new();
    whole.extend_from_slice(&a);
    whole.extend_from_slice(&b);
    let a_path = staging_dir.join("0");
    let b_path = staging_dir.join("1");
    std::fs::write(&a_path, &a).expect("write first staged shard");
    std::fs::write(&b_path, &b).expect("write second staged shard");

    let placeholder = sha256_hex_placeholder();
    let manifest = TransferManifest {
        transfer_id: "rqtransfer-trailer".to_string(),
        root_name: "huge.bin".to_string(),
        is_directory: false,
        total_bytes: whole.len() as u64,
        merkle_root_hex: placeholder.clone(),
        metadata: None,
        delta_manifest: None,
        entries: vec![
            ManifestEntry {
                index: 0,
                rel_path: ".atp-fragment-0-0".to_string(),
                size: a.len() as u64,
                sha256_hex: placeholder.clone(),
                members: Vec::new(),
                fragment: Some(LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 0,
                    shard_count: 2,
                    logical_offset: 0,
                    len: a.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: placeholder.clone(),
                }),
            },
            ManifestEntry {
                index: 1,
                rel_path: ".atp-fragment-0-1".to_string(),
                size: b.len() as u64,
                sha256_hex: placeholder,
                members: Vec::new(),
                fragment: Some(LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 1,
                    shard_count: 2,
                    logical_offset: a.len() as u64,
                    len: b.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: sha256_hex_placeholder(),
                }),
            },
        ],
    };

    let a_digest = digest_for_bytes(".atp-fragment-0-0", &a);
    let b_digest = digest_for_bytes(".atp-fragment-0-1", &b);
    let logical_digest = digest_for_bytes("huge.bin", &whole);
    let merkle_root_hex = flat_merkle_root_from_digests(&[logical_digest.clone()]);
    let complete = RqRoundComplete {
        round_symbols_sent: 0,
        entry_digests: vec![
            ObjectCompleteEntryDigest {
                index: 0,
                size: a_digest.size,
                sha256_hex: hex_encode(&a_digest.content_sha256),
            },
            ObjectCompleteEntryDigest {
                index: 1,
                size: b_digest.size,
                sha256_hex: hex_encode(&b_digest.content_sha256),
            },
        ],
        logical_digests: vec![ObjectCompleteLogicalDigest {
            rel_path: "huge.bin".to_string(),
            size: logical_digest.size,
            sha256_hex: hex_encode(&logical_digest.content_sha256),
        }],
        merkle_root_hex: Some(merkle_root_hex),
    };
    let completion_digests = CompletionDigestIndex::from_round_complete(&complete, &manifest, true)
        .expect("source-stream trailer digests are valid");

    let mut decoders = vec![
        EntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: a.len() as u64,
            pipeline: None,
            complete: true,
            staging_path: a_path,
            staging_write_offset: 0,
            staging_file_len: a.len() as u64,
            staging_shared: false,
            staging_created: true,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: a.len() as u64,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: true,
            source_blocks: Vec::new(),
            pending_decodes: Vec::new(),
            inc: None,
            inc_digest: Some((
                a_digest.size,
                a_digest.content_id.clone(),
                a_digest.content_sha256,
            )),
            source_write_buffer: Vec::new(),
            source_write_buffer_offset: None,
        },
        EntryDecoder {
            index: 1,
            object_id: entry_object_id(&manifest.transfer_id, 1),
            size: b.len() as u64,
            pipeline: None,
            complete: true,
            staging_path: b_path,
            staging_write_offset: 0,
            staging_file_len: b.len() as u64,
            staging_shared: false,
            staging_created: true,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: b.len() as u64,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: true,
            source_blocks: Vec::new(),
            pending_decodes: Vec::new(),
            inc: None,
            inc_digest: Some((
                b_digest.size,
                b_digest.content_id.clone(),
                b_digest.content_sha256,
            )),
            source_write_buffer: Vec::new(),
            source_write_buffer_offset: None,
        },
    ];
    let mut logical_precomputed = BTreeMap::new();
    logical_precomputed.insert(
        "huge.bin".to_string(),
        (
            logical_digest.size,
            logical_digest.content_id,
            logical_digest.content_sha256,
        ),
    );

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &logical_precomputed,
        &completion_digests,
    ))
    .expect("verify source-stream trailer digests");

    assert!(receipt.committed, "trailer digests must authorize commit");
    assert!(receipt.sha_ok);
    assert!(receipt.merkle_ok);
    assert_eq!(std::fs::read(dest.path().join("huge.bin")).unwrap(), whole);
}

#[test]
fn verify_and_commit_rejects_bad_source_stream_trailer_digest_without_commit() {
    let dest = tempfile::tempdir().expect("dest dir");
    let staging_dir = dest.path().join(".atp-rq-trailer-tamper");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");

    let payload = b"source stream payload".to_vec();
    let staging_path = staging_dir.join("0");
    std::fs::write(&staging_path, &payload).expect("write staged payload");

    let payload_digest = digest_for_bytes("payload.bin", &payload);
    let manifest = TransferManifest {
        transfer_id: "rqtransfer-trailer-bad".to_string(),
        root_name: "payload.bin".to_string(),
        is_directory: false,
        total_bytes: payload.len() as u64,
        merkle_root_hex: sha256_hex_placeholder(),
        metadata: None,
        delta_manifest: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: "payload.bin".to_string(),
            size: payload.len() as u64,
            sha256_hex: sha256_hex_placeholder(),
            members: Vec::new(),
            fragment: None,
        }],
    };
    let complete = RqRoundComplete {
        round_symbols_sent: 0,
        entry_digests: vec![ObjectCompleteEntryDigest {
            index: 0,
            size: payload_digest.size,
            sha256_hex: "ff".repeat(32),
        }],
        logical_digests: vec![ObjectCompleteLogicalDigest {
            rel_path: "payload.bin".to_string(),
            size: payload_digest.size,
            sha256_hex: hex_encode(&payload_digest.content_sha256),
        }],
        merkle_root_hex: Some(flat_merkle_root_from_digests(&[payload_digest.clone()])),
    };
    let completion_digests = CompletionDigestIndex::from_round_complete(&complete, &manifest, true)
        .expect("bad digest is still well-formed hex");

    let mut decoders = vec![EntryDecoder {
        index: 0,
        object_id: entry_object_id(&manifest.transfer_id, 0),
        size: payload.len() as u64,
        pipeline: None,
        complete: true,
        staging_path,
        staging_write_offset: 0,
        staging_file_len: payload.len() as u64,
        staging_shared: false,
        staging_created: true,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: payload.len() as u64,
        max_block_size: DEFAULT_MAX_BLOCK_SIZE,
        source_streaming: true,
        source_blocks: Vec::new(),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: Some((
            payload_digest.size,
            payload_digest.content_id,
            payload_digest.content_sha256,
        )),
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    }];

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &BTreeMap::new(),
        &completion_digests,
    ))
    .expect("verify returns a fail-closed receipt");

    assert!(!receipt.committed, "bad trailer digest must fail closed");
    assert!(!receipt.sha_ok);
    assert!(!dest.path().join("payload.bin").exists());
}

// ─── E-15 tree coalescing (pack / split) ───────────────────────────────

fn source_entry(dir: &Path, rel: &str, bytes: &[u8]) -> RqSourceEntry {
    let abs = dir.join(rel);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(&abs, bytes).expect("write source file");
    RqSourceEntry {
        rel_path: rel.to_string(),
        abs_path: abs,
        metadata: EntryMetadata::default(),
        source_offset: 0,
        source_len: None,
        members: Vec::new(),
        fragment: None,
    }
}

#[test]
fn pack_small_files_records_offsets_lens_and_member_sha() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Three small files (< PACK_THRESHOLD) -> one combined object.
    let a = vec![0xAAu8; 100];
    let b = vec![0xBBu8; 250];
    let c = vec![0xCCu8; 7];
    let entries = vec![
        source_entry(dir.path(), "d/a", &a),
        source_entry(dir.path(), "d/b", &b),
        source_entry(dir.path(), "z/c", &c),
    ];

    let config = RqConfig::default();
    let (packed, logical_digests, tempdir) =
        futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");
    let tempdir = tempdir.expect("a pack temp dir was produced");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(tempdir.path())
            .expect("pack tempdir metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "RQ pack tempdir exposed group/other permissions"
        );
    }

    assert_eq!(
        packed.len(),
        1,
        "three small files coalesce into one object"
    );
    let pack = &packed[0];
    assert_eq!(pack.rel_path, ".atp-pack-0");
    assert_eq!(pack.members.len(), 3);

    // Members appear in sorted (manifest) order with contiguous offsets.
    assert_eq!(pack.members[0].rel_path, "d/a");
    assert_eq!(pack.members[0].offset, 0);
    assert_eq!(pack.members[0].len, 100);
    assert_eq!(pack.members[1].rel_path, "d/b");
    assert_eq!(pack.members[1].offset, 100);
    assert_eq!(pack.members[1].len, 250);
    assert_eq!(pack.members[2].rel_path, "z/c");
    assert_eq!(pack.members[2].offset, 350);
    assert_eq!(pack.members[2].len, 7);

    // Per-member sha matches the file content.
    assert_eq!(pack.members[0].sha256_hex, hex_encode(&Sha256::digest(&a)));
    assert_eq!(pack.members[1].sha256_hex, hex_encode(&Sha256::digest(&b)));
    assert_eq!(pack.members[2].sha256_hex, hex_encode(&Sha256::digest(&c)));

    // The temp object is the concatenation in offset order.
    let on_disk = std::fs::read(&pack.abs_path).expect("read pack object");
    let mut expected = Vec::new();
    expected.extend_from_slice(&a);
    expected.extend_from_slice(&b);
    expected.extend_from_slice(&c);
    assert_eq!(on_disk, expected, "pack object is the member concatenation");

    // Logical digests cover every logical file (members flattened).
    assert_eq!(logical_digests.len(), 3);
    let logical_root = flat_merkle_root_from_digests(&logical_digests);
    // Same set of {rel_path, content} -> same root as the unpacked files.
    let direct: Vec<EntryDigest> = [("d/a", &a), ("d/b", &b), ("z/c", &c)]
        .into_iter()
        .map(|(rel, bytes)| EntryDigest {
            rel_path: rel.to_string(),
            size: bytes.len() as u64,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(bytes),
            ),
            content_sha256: Sha256::digest(bytes).into(),
        })
        .collect();
    assert_eq!(
        logical_root,
        flat_merkle_root_from_digests(&direct),
        "logical merkle root is invariant to packing"
    );
}

#[test]
fn pack_small_files_coalesces_tree_small_max_size_bucket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let max_tree_small = vec![0x11u8; 1024 * 1024];
    let sibling = vec![0x22u8; 1024 * 1024];
    let entries = vec![
        source_entry(dir.path(), "leaf/a.bin", &max_tree_small),
        source_entry(dir.path(), "leaf/b.bin", &sibling),
    ];

    let config = RqConfig::default();
    let (packed, logical_digests, tempdir) =
        futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");
    let _tempdir = tempdir.expect("tree_small max-size entries should pack");

    assert_eq!(packed.len(), 1);
    let pack = &packed[0];
    assert_eq!(pack.members.len(), 2);
    assert_eq!(pack.members[0].rel_path, "leaf/a.bin");
    assert_eq!(pack.members[0].offset, 0);
    assert_eq!(pack.members[0].len, max_tree_small.len() as u64);
    assert_eq!(pack.members[1].rel_path, "leaf/b.bin");
    assert_eq!(pack.members[1].offset, max_tree_small.len() as u64);
    assert_eq!(pack.members[1].len, sibling.len() as u64);
    assert_eq!(logical_digests.len(), 2);
    assert_eq!(
        std::fs::metadata(&pack.abs_path)
            .expect("packed object metadata")
            .len(),
        (max_tree_small.len() + sibling.len()) as u64
    );
}

#[test]
fn pack_small_files_leaves_large_files_unpacked_and_root_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Two files >= PACK_THRESHOLD: neither is packed, nothing materialized.
    let big1 = vec![1u8; PACK_THRESHOLD as usize];
    let big2 = vec![2u8; PACK_THRESHOLD as usize + 13];
    let entries = vec![
        source_entry(dir.path(), "big1", &big1),
        source_entry(dir.path(), "big2", &big2),
    ];

    let config = RqConfig::default();
    let (packed, logical_digests, tempdir) =
        futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");
    assert!(tempdir.is_none(), "no packing => no temp dir");
    assert_eq!(packed.len(), 2);
    assert!(packed.iter().all(|e| e.members.is_empty()));
    assert_eq!(packed[0].rel_path, "big1");
    assert_eq!(packed[1].rel_path, "big2");
    assert_eq!(logical_digests.len(), 2);
    // Byte-identical to the per-file digest path the caller would build.
    assert_eq!(logical_digests[0].size, big1.len() as u64);
    assert_eq!(logical_digests[1].size, big2.len() as u64);
}

#[test]
fn pack_small_files_single_small_file_is_not_packed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let entries = vec![source_entry(dir.path(), "only", b"tiny")];
    let config = RqConfig::default();
    let (packed, logical_digests, tempdir) =
        futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");
    assert!(tempdir.is_none(), "a lone small file is not packed");
    assert_eq!(packed.len(), 1);
    assert!(packed[0].members.is_empty());
    assert_eq!(packed[0].rel_path, "only");
    assert_eq!(logical_digests.len(), 1);
}

#[test]
fn pack_small_files_respects_configured_object_ceiling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let too_large_for_one_object = vec![0xA5u8; MAX_SOURCE_BLOCKS + 44];
    let tail = vec![0x5Au8; 20];
    let entries = vec![
        source_entry(dir.path(), "needs-split", &too_large_for_one_object),
        source_entry(dir.path(), "tail", &tail),
    ];
    let config = RqConfig {
        symbol_size: 1,
        max_block_size: 1,
        ..RqConfig::default()
    };

    let (packed, logical_digests, tempdir) =
        futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");

    assert!(
        tempdir.is_none(),
        "packing must not create an unsplittable object above the configured ceiling"
    );
    assert_eq!(packed.len(), 2);
    assert!(packed.iter().all(|entry| entry.members.is_empty()));

    let split =
        futures_lite::future::block_on(split_large_entries(packed, &logical_digests, &config))
            .expect("E-12 split after E-15 pack cap");
    assert_eq!(
        split
            .iter()
            .filter(|entry| entry.fragment.is_some())
            .count(),
        2,
        "the over-ceiling small file remains available for ranged object splitting"
    );
    assert!(split.iter().all(|entry| entry.members.is_empty()));
}

/// End-to-end (in-process) split: build a packed manifest + a staging file
/// holding the member concatenation, then verify_and_commit must split it
/// into the member files on disk, byte-identical.
#[test]
fn verify_and_commit_splits_packed_object_into_members() {
    let dest = tempfile::tempdir().expect("dest dir");
    let staging_dir = dest.path().join(".atp-rq-test-staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");

    let a = b"first-member-bytes".to_vec();
    let b = b"second member, a little longer".to_vec();
    let mut object = Vec::new();
    object.extend_from_slice(&a);
    object.extend_from_slice(&b);
    let staging_path = staging_dir.join("0");
    std::fs::write(&staging_path, &object).expect("write packed staging object");

    let members = vec![
        PackedMember {
            rel_path: "dir/a.txt".to_string(),
            offset: 0,
            len: a.len() as u64,
            sha256_hex: hex_encode(&Sha256::digest(&a)),
        },
        PackedMember {
            rel_path: "dir/sub/b.txt".to_string(),
            offset: a.len() as u64,
            len: b.len() as u64,
            sha256_hex: hex_encode(&Sha256::digest(&b)),
        },
    ];

    // Merkle root over the LOGICAL files (what the sender computes).
    let logical: Vec<EntryDigest> = [("dir/a.txt", &a), ("dir/sub/b.txt", &b)]
        .into_iter()
        .map(|(rel, bytes)| EntryDigest {
            rel_path: rel.to_string(),
            size: bytes.len() as u64,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(bytes),
            ),
            content_sha256: Sha256::digest(bytes).into(),
        })
        .collect();
    let merkle_root_hex = flat_merkle_root_from_digests(&logical);
    let object_sha = hex_encode(&Sha256::digest(&object));

    let mut a_metadata = EntryMetadata::default();
    #[cfg(unix)]
    {
        a_metadata.unix_mode = Some(0o440);
    }
    #[cfg(windows)]
    {
        a_metadata.windows_attributes = Some(0x0000_0021);
        a_metadata.mtime_unix_secs = Some(1_700_000_000);
        a_metadata.mtime_nanos = Some(123_400_000);
    }
    let bare_metadata = EntryMetadata::default();
    let metadata_commitment_hex = rq_metadata_commitment(&[
        ("dir/a.txt", &a_metadata),
        ("dir/sub/b.txt", &bare_metadata),
    ]);
    let metadata_entries = (!a_metadata.is_bare())
        .then(|| RqMetadataEntry {
            rel_path: "dir/a.txt".to_string(),
            metadata: a_metadata,
        })
        .into_iter()
        .collect();

    let out_a = dest.path().join("payload/dir/a.txt");
    let out_b = dest.path().join("payload/dir/sub/b.txt");
    std::fs::create_dir_all(out_a.parent().expect("member a parent"))
        .expect("create existing member a parent");
    std::fs::write(&out_a, b"old readonly member").expect("write existing member a");
    let mut existing_permissions = std::fs::metadata(&out_a)
        .expect("existing member a metadata")
        .permissions();
    existing_permissions.set_readonly(true);
    std::fs::set_permissions(&out_a, existing_permissions)
        .expect("make existing member a readonly");

    let manifest = TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "payload".to_string(),
        is_directory: true,
        total_bytes: object.len() as u64,
        merkle_root_hex,
        metadata: Some(RqMetadataManifest {
            version: RQ_METADATA_MANIFEST_VERSION,
            commitment_hex: metadata_commitment_hex,
            entries: metadata_entries,
            directories: None,
        }),
        delta_manifest: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: ".atp-pack-0".to_string(),
            size: object.len() as u64,
            sha256_hex: object_sha,
            members,
            fragment: None,
        }],
    };
    let mut decoders = vec![EntryDecoder {
        index: 0,
        object_id: entry_object_id(&manifest.transfer_id, 0),
        size: object.len() as u64,
        pipeline: None,
        complete: true,
        staging_path,
        staging_write_offset: 0,
        staging_file_len: object.len() as u64,
        staging_shared: false,
        staging_created: true,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: object.len() as u64,
        max_block_size: DEFAULT_MAX_BLOCK_SIZE,
        source_streaming: false,
        source_blocks: Vec::new(),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    }];

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &std::collections::BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect("verify_and_commit");

    assert!(
        receipt.committed,
        "packed transfer must commit: {receipt:?}"
    );
    assert!(receipt.sha_ok);
    assert!(receipt.merkle_ok);
    assert_eq!(receipt.files, 2, "two LOGICAL files delivered");

    assert_eq!(std::fs::read(&out_a).expect("member a"), a);
    assert_eq!(std::fs::read(&out_b).expect("member b"), b);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&out_a)
                .expect("member a metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o440
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        assert_eq!(
            std::fs::metadata(&out_a)
                .expect("member a metadata")
                .file_attributes()
                & 0x0000_0021,
            0x0000_0021
        );
        let mut permissions = std::fs::metadata(&out_a)
            .expect("member a cleanup metadata")
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&out_a, permissions).expect("clear member a readonly for cleanup");
    }
    // The synthetic packed object name must not appear on disk.
    assert!(!dest.path().join("payload/.atp-pack-0").exists());
}

#[test]
fn packed_member_streaming_helpers_reuse_small_buffers() {
    let temp = tempfile::tempdir().expect("tempdir");
    let staging_path = temp.path().join("pack-object");
    let a = b"alpha-member".to_vec();
    let b = b"beta-member-is-longer".to_vec();
    let mut packed = Vec::new();
    packed.extend_from_slice(&a);
    packed.extend_from_slice(&b);
    std::fs::write(&staging_path, &packed).expect("write packed staging object");

    let members = vec![
        PackedMember {
            rel_path: "a.txt".to_string(),
            offset: 0,
            len: a.len() as u64,
            sha256_hex: hex_encode(&Sha256::digest(&a)),
        },
        PackedMember {
            rel_path: "nested/b.txt".to_string(),
            offset: a.len() as u64,
            len: b.len() as u64,
            sha256_hex: hex_encode(&Sha256::digest(&b)),
        },
    ];

    let mut digests = Vec::new();
    let mut logical_files = 0;
    let mut verify_buf = [0u8; 3];
    let ok = futures_lite::future::block_on(hash_packed_members_streaming(
        &staging_path,
        &members,
        &mut digests,
        &mut logical_files,
        &mut verify_buf,
    ))
    .expect("streaming member verification");
    assert!(ok);
    assert_eq!(logical_files, 2);
    assert_eq!(digests.len(), 2);
    assert_eq!(digests[0].rel_path, "a.txt");
    let expected_a_sha: [u8; 32] = Sha256::digest(&a).into();
    assert_eq!(digests[0].content_sha256, expected_a_sha);
    assert_eq!(digests[1].rel_path, "nested/b.txt");
    let expected_b_sha: [u8; 32] = Sha256::digest(&b).into();
    assert_eq!(digests[1].content_sha256, expected_b_sha);

    let out_root = temp.path().join("out");
    let writes = vec![
        PackedMemberWrite {
            offset: members[0].offset,
            len: members[0].len,
            write_path: out_root.join(&members[0].rel_path),
            out_path: out_root.join(&members[0].rel_path),
            metadata: EntryMetadata::default(),
        },
        PackedMemberWrite {
            offset: members[1].offset,
            len: members[1].len,
            write_path: out_root.join(&members[1].rel_path),
            out_path: out_root.join(&members[1].rel_path),
            metadata: EntryMetadata::default(),
        },
    ];
    let mut write_buf = [0u8; 4];
    let _staging_guard = futures_lite::future::block_on(write_packed_member_batch(
        &staging_path,
        &writes,
        &mut write_buf,
    ))
    .expect("batched member commit");

    assert_eq!(std::fs::read(out_root.join("a.txt")).expect("read a"), a);
    assert_eq!(
        std::fs::read(out_root.join("nested/b.txt")).expect("read b"),
        b
    );
}

/// MATRIX-211 regression: the one-shot packed commit must slice members
/// relative to the batch SPAN (min offset), not the staging file start,
/// and must not care about member order; a single member takes the
/// streaming fallback and still commits byte-identically.
#[test]
fn packed_member_batch_oneshot_spans_and_fallback_commit_identically() {
    let temp = tempfile::tempdir().expect("tempdir");
    let staging_path = temp.path().join("pack-object");
    let pad = vec![0xEE_u8; 7];
    let a = b"span-member-a".to_vec();
    let b = b"span-member-b-longer".to_vec();
    let mut packed = Vec::new();
    packed.extend_from_slice(&pad);
    packed.extend_from_slice(&a);
    packed.extend_from_slice(&b);
    std::fs::write(&staging_path, &packed).expect("write packed staging object");
    let a_off = pad.len() as u64;
    let b_off = a_off + a.len() as u64;

    // Out-of-order members with span_start > 0 → one-shot path.
    let out_root = temp.path().join("out");
    let writes = vec![
        PackedMemberWrite {
            offset: b_off,
            len: b.len() as u64,
            write_path: out_root.join("deep/nested/b.bin"),
            out_path: out_root.join("deep/nested/b.bin"),
            metadata: EntryMetadata::default(),
        },
        PackedMemberWrite {
            offset: a_off,
            len: a.len() as u64,
            write_path: out_root.join("a.bin"),
            out_path: out_root.join("a.bin"),
            metadata: EntryMetadata::default(),
        },
    ];
    let mut write_buf = [0u8; 4];
    let _batch_guard = futures_lite::future::block_on(write_packed_member_batch(
        &staging_path,
        &writes,
        &mut write_buf,
    ))
    .expect("one-shot span commit");
    assert_eq!(std::fs::read(out_root.join("a.bin")).expect("read a"), a);
    assert_eq!(
        std::fs::read(out_root.join("deep/nested/b.bin")).expect("read b"),
        b
    );

    // Single member → streaming fallback path.
    let solo = vec![PackedMemberWrite {
        offset: a_off,
        len: a.len() as u64,
        write_path: out_root.join("solo/a-again.bin"),
        out_path: out_root.join("solo/a-again.bin"),
        metadata: EntryMetadata::default(),
    }];
    let _solo_guard = futures_lite::future::block_on(write_packed_member_batch(
        &staging_path,
        &solo,
        &mut write_buf,
    ))
    .expect("single-member fallback commit");
    assert_eq!(
        std::fs::read(out_root.join("solo/a-again.bin")).expect("read solo"),
        a
    );
}

#[test]
fn packed_member_staging_guard_cleans_unclaimed_blocking_result() {
    let temp = tempfile::tempdir().expect("tempdir");
    let staging_path = temp.path().join("pack-object");
    let a = b"member-a";
    let b = b"member-b";
    let mut packed = Vec::new();
    packed.extend_from_slice(a);
    packed.extend_from_slice(b);
    std::fs::write(&staging_path, &packed).expect("write packed object");

    let member_dir = temp.path().join("derived-members");
    let a_path = member_dir.join("a");
    let b_path = member_dir.join("b");
    let writes = vec![
        PackedMemberWrite {
            offset: 0,
            len: a.len() as u64,
            write_path: a_path.clone(),
            out_path: temp.path().join("out/a"),
            metadata: EntryMetadata::default(),
        },
        PackedMemberWrite {
            offset: a.len() as u64,
            len: b.len() as u64,
            write_path: b_path.clone(),
            out_path: temp.path().join("out/b"),
            metadata: EntryMetadata::default(),
        },
    ];
    let mut write_buf = [0u8; 4];
    let staging_guard = futures_lite::future::block_on(write_packed_member_batch(
        &staging_path,
        &writes,
        &mut write_buf,
    ))
    .expect("create derived packed members");
    assert!(staging_path.exists());
    assert!(a_path.exists());
    assert!(b_path.exists());

    drop(staging_guard);

    assert!(!staging_path.exists());
    assert!(!a_path.exists());
    assert!(!b_path.exists());
}

#[test]
fn validate_manifest_checks_packed_member_table() {
    // A well-formed packed manifest entry is accepted.
    let good_members = vec![
        PackedMember {
            rel_path: "dir/a".to_string(),
            offset: 0,
            len: 10,
            sha256_hex: "aa".repeat(32),
        },
        PackedMember {
            rel_path: "dir/b".to_string(),
            offset: 10,
            len: 5,
            sha256_hex: "bb".repeat(32),
        },
    ];
    let ok_entry = ManifestEntry {
        index: 0,
        rel_path: ".atp-pack-0".to_string(),
        size: 15,
        sha256_hex: "cc".repeat(32),
        members: good_members.clone(),
        fragment: None,
    };
    assert!(validate_manifest(&manifest_with(vec![ok_entry], 15), &RqConfig::default()).is_ok());

    // Non-contiguous offsets fail closed.
    let mut gap = good_members.clone();
    gap[1].offset = 11;
    let entry = ManifestEntry {
        index: 0,
        rel_path: ".atp-pack-0".to_string(),
        size: 15,
        sha256_hex: "cc".repeat(32),
        members: gap,
        fragment: None,
    };
    assert!(matches!(
        validate_manifest(&manifest_with(vec![entry], 15), &RqConfig::default()),
        Err(RqError::Frame(m)) if m.contains("not contiguous")
    ));

    // Member lengths must tile the object exactly.
    let entry = ManifestEntry {
        index: 0,
        rel_path: ".atp-pack-0".to_string(),
        size: 99,
        sha256_hex: "cc".repeat(32),
        members: good_members.clone(),
        fragment: None,
    };
    assert!(matches!(
        validate_manifest(&manifest_with(vec![entry], 99), &RqConfig::default()),
        Err(RqError::Frame(m)) if m.contains("members cover")
    ));

    // An unsafe member rel_path fails closed.
    let mut evil = good_members;
    evil[1].rel_path = "../escape".to_string();
    let entry = ManifestEntry {
        index: 0,
        rel_path: ".atp-pack-0".to_string(),
        size: 15,
        sha256_hex: "cc".repeat(32),
        members: evil,
        fragment: None,
    };
    assert!(matches!(
        validate_manifest(&manifest_with(vec![entry], 15), &RqConfig::default()),
        Err(RqError::Source(m)) if m.contains("unsafe manifest rel_path")
    ));
}

/// A corrupted member sha must fail closed: nothing is committed/written.
#[test]
fn verify_and_commit_rejects_packed_object_with_wrong_member_sha() {
    let dest = tempfile::tempdir().expect("dest dir");
    let staging_dir = dest.path().join(".atp-rq-test-staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");

    let a = b"member-one".to_vec();
    let b = b"member-two".to_vec();
    let mut object = Vec::new();
    object.extend_from_slice(&a);
    object.extend_from_slice(&b);
    let staging_path = staging_dir.join("0");
    std::fs::write(&staging_path, &object).expect("write packed staging object");

    // Build a correct logical merkle root, but lie about member b's sha so
    // the per-member check fails (object sha + merkle stay self-consistent).
    let logical: Vec<EntryDigest> = [("a.txt", &a), ("b.txt", &b)]
        .into_iter()
        .map(|(rel, bytes)| EntryDigest {
            rel_path: rel.to_string(),
            size: bytes.len() as u64,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(bytes),
            ),
            content_sha256: Sha256::digest(bytes).into(),
        })
        .collect();
    let merkle_root_hex = flat_merkle_root_from_digests(&logical);

    let manifest = TransferManifest {
        transfer_id: "rqtransfer1".to_string(),
        root_name: "payload".to_string(),
        is_directory: true,
        total_bytes: object.len() as u64,
        merkle_root_hex,
        metadata: None,
        delta_manifest: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: ".atp-pack-0".to_string(),
            size: object.len() as u64,
            sha256_hex: hex_encode(&Sha256::digest(&object)),
            members: vec![
                PackedMember {
                    rel_path: "a.txt".to_string(),
                    offset: 0,
                    len: a.len() as u64,
                    sha256_hex: hex_encode(&Sha256::digest(&a)),
                },
                PackedMember {
                    rel_path: "b.txt".to_string(),
                    offset: a.len() as u64,
                    len: b.len() as u64,
                    // WRONG sha for member b.
                    sha256_hex: "ff".repeat(32),
                },
            ],
            fragment: None,
        }],
    };
    let mut decoders = vec![EntryDecoder {
        index: 0,
        object_id: entry_object_id(&manifest.transfer_id, 0),
        size: object.len() as u64,
        pipeline: None,
        complete: true,
        staging_path,
        staging_write_offset: 0,
        staging_file_len: object.len() as u64,
        staging_shared: false,
        staging_created: true,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: false,
        bytes_written: object.len() as u64,
        max_block_size: DEFAULT_MAX_BLOCK_SIZE,
        source_streaming: false,
        source_blocks: Vec::new(),
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
    }];

    let receipt = futures_lite::future::block_on(verify_and_commit(
        &manifest,
        &mut decoders,
        dest.path(),
        0,
        0,
        &std::collections::BTreeMap::new(),
        &CompletionDigestIndex::default(),
    ))
    .expect("verify_and_commit returns a receipt");

    assert!(!receipt.committed, "wrong member sha must fail closed");
    assert!(!receipt.sha_ok);
    // Nothing written into place.
    assert!(!dest.path().join("payload/a.txt").exists());
    assert!(!dest.path().join("payload/b.txt").exists());
}
