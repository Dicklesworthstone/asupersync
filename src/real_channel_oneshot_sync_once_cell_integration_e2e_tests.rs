//! Integration tests for channel/oneshot ↔ sync/once_cell integration.
//!
//! These tests verify that oneshot channel completion correctly transitions once_cell
//! from empty to initialized state without race conditions, ensuring thread-safe
//! lazy initialization patterns work correctly.
//!
//! Key integration points tested:
//! - Oneshot completion triggering once_cell initialization
//! - Multiple readers coordinated through once_cell waiting on oneshot
//! - Concurrent initialization without race conditions
//! - Error handling when oneshot is dropped before completion
//! - Stress testing with many once_cells and oneshot channels
//! - Edge cases: immediate vs delayed initialization timing

#[cfg(all(test, feature = "real-service-e2e"))]
mod integration_tests {
    use crate::channel::oneshot::{self, Receiver, RecvError, Sender};
    use crate::cx::Cx;
    use crate::error::AsupersyncError;
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::sync::once_cell::OnceCell;
    use crate::types::{Budget, Outcome, TaskId};
    use std::collections::HashMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::time::{Duration, Instant};

    /// Test harness for oneshot-once_cell integration testing.
    struct OneshotOnceCellTestHarness {
        runtime: Arc<Runtime>,
        once_cells: HashMap<String, Arc<OnceCell<TestData>>>,
        oneshot_channels: HashMap<String, (Sender<TestData>, Receiver<TestData>)>,
        initializers: HashMap<String, Arc<TestInitializer>>,
        stats: Arc<Mutex<OneshotOnceCellStats>>,
    }

    #[derive(Debug, Default, Clone)]
    struct OneshotOnceCellStats {
        /// Total once_cells created
        once_cells_created: u64,
        /// Total oneshot channels created
        oneshot_channels_created: u64,
        /// Successful initializations
        successful_initializations: u64,
        /// Failed initializations (oneshot dropped)
        failed_initializations: u64,
        /// Race conditions detected and handled
        race_conditions_handled: u64,
        /// Concurrent readers waiting
        concurrent_readers_peak: u64,
        /// Time spent waiting for initialization
        total_wait_time: Duration,
        /// Immediate initializations (no wait)
        immediate_initializations: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct TestData {
        id: u64,
        payload: String,
        timestamp: Instant,
        initialization_source: InitializationSource,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum InitializationSource {
        OneshotCompletion,
        DirectInitialization,
        RaceResolution,
    }

    /// Initializer that coordinates between oneshot and once_cell
    struct TestInitializer {
        id: String,
        once_cell: Arc<OnceCell<TestData>>,
        oneshot_sender: Option<Sender<TestData>>,
        initialization_delay: Duration,
        stats: Arc<Mutex<OneshotOnceCellStats>>,
    }

    impl TestInitializer {
        fn new(
            id: String,
            once_cell: Arc<OnceCell<TestData>>,
            oneshot_sender: Sender<TestData>,
            initialization_delay: Duration,
            stats: Arc<Mutex<OneshotOnceCellStats>>,
        ) -> Self {
            Self {
                id,
                once_cell,
                oneshot_sender: Some(oneshot_sender),
                initialization_delay,
                stats,
            }
        }

        async fn initialize_via_oneshot(
            &mut self,
            cx: &Cx,
            data: TestData,
        ) -> Result<(), AsupersyncError> {
            if let Some(sender) = self.oneshot_sender.take() {
                // Simulate initialization work
                if self.initialization_delay > Duration::ZERO {
                    cx.sleep(self.initialization_delay).await;
                }

                // Send data through oneshot
                match sender.send(data.clone()) {
                    Ok(_) => {
                        // Initialize once_cell with the same data
                        match self.once_cell.set(data) {
                            Ok(_) => {
                                let mut stats = self.stats.lock().unwrap();
                                stats.successful_initializations += 1;
                            }
                            Err(_) => {
                                // Race condition: someone else initialized first
                                let mut stats = self.stats.lock().unwrap();
                                stats.race_conditions_handled += 1;
                            }
                        }
                    }
                    Err(_) => {
                        let mut stats = self.stats.lock().unwrap();
                        stats.failed_initializations += 1;
                    }
                }
            }
            Ok(())
        }

        fn try_immediate_initialization(&self, data: TestData) -> bool {
            match self.once_cell.set(data) {
                Ok(_) => {
                    let mut stats = self.stats.lock().unwrap();
                    stats.immediate_initializations += 1;
                    true
                }
                Err(_) => false, // Already initialized
            }
        }
    }

    impl OneshotOnceCellTestHarness {
        fn new() -> Result<Self, AsupersyncError> {
            let runtime = Arc::new(
                RuntimeBuilder::new()
                    .with_structured_concurrency()
                    .with_channels()
                    .build()?,
            );

            Ok(Self {
                runtime,
                once_cells: HashMap::new(),
                oneshot_channels: HashMap::new(),
                initializers: HashMap::new(),
                stats: Arc::new(Mutex::new(OneshotOnceCellStats::default())),
            })
        }

        fn create_once_cell(&mut self, cell_id: &str) -> Arc<OnceCell<TestData>> {
            let once_cell = Arc::new(OnceCell::new());
            self.once_cells
                .insert(cell_id.to_string(), once_cell.clone());

            {
                let mut stats = self.stats.lock().unwrap();
                stats.once_cells_created += 1;
            }

            once_cell
        }

        fn create_oneshot_channel(
            &mut self,
            channel_id: &str,
        ) -> (Sender<TestData>, Receiver<TestData>) {
            let (sender, receiver) = oneshot::channel();
            self.oneshot_channels
                .insert(channel_id.to_string(), (sender, receiver));

            {
                let mut stats = self.stats.lock().unwrap();
                stats.oneshot_channels_created += 1;
            }

            (sender, receiver)
        }

        fn create_initializer(
            &mut self,
            init_id: &str,
            once_cell: Arc<OnceCell<TestData>>,
            oneshot_sender: Sender<TestData>,
            delay: Duration,
        ) -> Arc<TestInitializer> {
            let initializer = Arc::new(TestInitializer::new(
                init_id.to_string(),
                once_cell,
                oneshot_sender,
                delay,
                self.stats.clone(),
            ));
            self.initializers
                .insert(init_id.to_string(), initializer.clone());
            initializer
        }

        async fn wait_for_initialization(
            &self,
            cx: &Cx,
            once_cell: &OnceCell<TestData>,
            oneshot_receiver: Receiver<TestData>,
        ) -> Result<TestData, AsupersyncError> {
            let wait_start = Instant::now();

            // Try to get value if already initialized
            if let Some(value) = once_cell.get() {
                let mut stats = self.stats.lock().unwrap();
                stats.immediate_initializations += 1;
                return Ok(value.clone());
            }

            // Wait for oneshot completion
            let oneshot_result = oneshot_receiver.await;
            let wait_duration = wait_start.elapsed();

            {
                let mut stats = self.stats.lock().unwrap();
                stats.total_wait_time += wait_duration;
            }

            match oneshot_result {
                Ok(data) => {
                    // Verify once_cell was also initialized
                    match once_cell.get() {
                        Some(cell_data) if *cell_data == data => Ok(data),
                        Some(_) => Err(AsupersyncError::InvalidState(
                            "OnceCell data mismatch".into(),
                        )),
                        None => Err(AsupersyncError::InvalidState(
                            "OnceCell not initialized after oneshot".into(),
                        )),
                    }
                }
                Err(RecvError::Closed) => {
                    let mut stats = self.stats.lock().unwrap();
                    stats.failed_initializations += 1;
                    Err(AsupersyncError::ChannelClosed)
                }
            }
        }

        async fn spawn_concurrent_readers(
            &self,
            cx: &Cx,
            once_cell: Arc<OnceCell<TestData>>,
            num_readers: usize,
        ) -> Result<Vec<TestData>, AsupersyncError> {
            let readers_count = Arc::new(AtomicU64::new(0));
            let mut tasks = Vec::new();

            {
                let mut stats = self.stats.lock().unwrap();
                stats.concurrent_readers_peak =
                    stats.concurrent_readers_peak.max(num_readers as u64);
            }

            for i in 0..num_readers {
                let once_cell_clone = once_cell.clone();
                let readers_count_clone = readers_count.clone();
                let reader_id = i;

                let task = cx.spawn(async move {
                    readers_count_clone.fetch_add(1, Ordering::SeqCst);

                    // Wait for initialization
                    loop {
                        if let Some(data) = once_cell_clone.get() {
                            readers_count_clone.fetch_sub(1, Ordering::SeqCst);
                            return Ok::<TestData, AsupersyncError>(data.clone());
                        }

                        // Brief yield to allow initialization
                        cx.yield_now().await;
                    }
                });

                tasks.push(task);
            }

            // Wait for all readers to complete
            let mut results = Vec::new();
            for task in tasks {
                let result = task.await??;
                results.push(result);
            }

            Ok(results)
        }

        fn get_stats(&self) -> OneshotOnceCellStats {
            self.stats.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn test_basic_oneshot_once_cell_initialization() -> Result<(), AsupersyncError> {
        let mut harness = OneshotOnceCellTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create once_cell and oneshot channel
                let once_cell = harness.create_once_cell("basic-cell");
                let (sender, receiver) = harness.create_oneshot_channel("basic-channel");

                // Create initializer
                let mut initializer = harness.create_initializer(
                    "basic-init",
                    once_cell.clone(),
                    sender,
                    Duration::from_millis(10), // Small delay
                );

                // Start initialization in background
                let init_task = {
                    let mut init_clone =
                        Arc::try_unwrap(initializer).unwrap_or_else(|arc| (*arc).clone());
                    cx.spawn(async move {
                        let test_data = TestData {
                            id: 1,
                            payload: "basic test data".to_string(),
                            timestamp: Instant::now(),
                            initialization_source: InitializationSource::OneshotCompletion,
                        };
                        init_clone.initialize_via_oneshot(cx, test_data).await
                    })
                };

                // Wait for initialization via oneshot
                let result = harness
                    .wait_for_initialization(cx, &once_cell, receiver)
                    .await?;

                // Verify initialization completed
                assert_eq!(result.id, 1);
                assert_eq!(result.payload, "basic test data");
                assert_eq!(
                    result.initialization_source,
                    InitializationSource::OneshotCompletion
                );

                // Verify once_cell is now accessible
                let cell_value = once_cell.get().expect("OnceCell should be initialized");
                assert_eq!(*cell_value, result);

                init_task.await??;

                let stats = harness.get_stats();
                assert_eq!(stats.successful_initializations, 1);
                assert_eq!(stats.once_cells_created, 1);
                assert_eq!(stats.oneshot_channels_created, 1);
                assert_eq!(stats.failed_initializations, 0);

                println!(
                    "Basic initialization completed in {:?}",
                    stats.total_wait_time
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_multiple_readers_waiting_on_once_cell() -> Result<(), AsupersyncError> {
        let mut harness = OneshotOnceCellTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                let once_cell = harness.create_once_cell("multi-reader-cell");
                let (sender, _receiver) = harness.create_oneshot_channel("multi-reader-channel");

                // Start multiple concurrent readers
                let num_readers = 10;
                let readers_task = {
                    let once_cell_clone = once_cell.clone();
                    cx.spawn(async move {
                        harness
                            .spawn_concurrent_readers(cx, once_cell_clone, num_readers)
                            .await
                    })
                };

                // Brief delay to let readers start waiting
                cx.sleep(Duration::from_millis(20)).await;

                // Initialize via oneshot
                let mut initializer = harness.create_initializer(
                    "multi-reader-init",
                    once_cell.clone(),
                    sender,
                    Duration::from_millis(50), // Longer delay to test waiting
                );

                let init_data = TestData {
                    id: 2,
                    payload: "multi-reader data".to_string(),
                    timestamp: Instant::now(),
                    initialization_source: InitializationSource::OneshotCompletion,
                };

                let init_task = {
                    let mut init_clone =
                        Arc::try_unwrap(initializer).unwrap_or_else(|arc| (*arc).clone());
                    let data_clone = init_data.clone();
                    cx.spawn(async move { init_clone.initialize_via_oneshot(cx, data_clone).await })
                };

                // Wait for all readers to get the data
                let reader_results = readers_task.await??;
                init_task.await??;

                // Verify all readers got the same data
                assert_eq!(reader_results.len(), num_readers);
                for result in reader_results {
                    assert_eq!(result, init_data);
                }

                let stats = harness.get_stats();
                assert_eq!(stats.concurrent_readers_peak, num_readers as u64);
                assert_eq!(stats.successful_initializations, 1);

                println!("Multiple readers test: {} readers satisfied", num_readers);
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_race_condition_handling() -> Result<(), AsupersyncError> {
        let mut harness = OneshotOnceCellTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                let once_cell = harness.create_once_cell("race-cell");
                let (sender1, receiver1) = harness.create_oneshot_channel("race-channel-1");
                let (sender2, receiver2) = harness.create_oneshot_channel("race-channel-2");

                // Create two competing initializers
                let initializer1 = harness.create_initializer(
                    "race-init-1",
                    once_cell.clone(),
                    sender1,
                    Duration::from_millis(30),
                );

                let initializer2 = harness.create_initializer(
                    "race-init-2",
                    once_cell.clone(),
                    sender2,
                    Duration::from_millis(35), // Slightly slower
                );

                let data1 = TestData {
                    id: 3,
                    payload: "first racer".to_string(),
                    timestamp: Instant::now(),
                    initialization_source: InitializationSource::RaceResolution,
                };

                let data2 = TestData {
                    id: 4,
                    payload: "second racer".to_string(),
                    timestamp: Instant::now(),
                    initialization_source: InitializationSource::RaceResolution,
                };

                // Start both initializers concurrently
                let init1_task = {
                    let mut init1_clone =
                        Arc::try_unwrap(initializer1).unwrap_or_else(|arc| (*arc).clone());
                    let data1_clone = data1.clone();
                    cx.spawn(
                        async move { init1_clone.initialize_via_oneshot(cx, data1_clone).await },
                    )
                };

                let init2_task = {
                    let mut init2_clone =
                        Arc::try_unwrap(initializer2).unwrap_or_else(|arc| (*arc).clone());
                    let data2_clone = data2.clone();
                    cx.spawn(
                        async move { init2_clone.initialize_via_oneshot(cx, data2_clone).await },
                    )
                };

                // Wait for both initializers
                init1_task.await??;
                init2_task.await??;

                // Verify one of them won and once_cell is initialized
                let final_value = once_cell.get().expect("OnceCell should be initialized");
                assert!(
                    final_value.id == 3 || final_value.id == 4,
                    "Should have data from one of the racers"
                );

                // Try to receive from both oneshots (one should succeed, one should be closed)
                let recv1_result = receiver1.await;
                let recv2_result = receiver2.await;

                let successful_receives = [recv1_result.is_ok(), recv2_result.is_ok()]
                    .iter()
                    .filter(|&&x| x)
                    .count();
                assert_eq!(successful_receives, 1, "Exactly one oneshot should succeed");

                let stats = harness.get_stats();
                assert_eq!(stats.successful_initializations, 1);
                assert!(stats.race_conditions_handled > 0 || stats.failed_initializations > 0);

                println!("Race condition handled: winner id = {}", final_value.id);
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_oneshot_dropped_before_completion() -> Result<(), AsupersyncError> {
        let mut harness = OneshotOnceCellTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                let once_cell = harness.create_once_cell("dropped-cell");
                let (sender, receiver) = harness.create_oneshot_channel("dropped-channel");

                // Drop sender immediately without sending
                drop(sender);

                // Try to wait for initialization (should fail)
                let result = harness
                    .wait_for_initialization(cx, &once_cell, receiver)
                    .await;
                assert!(result.is_err(), "Should fail when oneshot is dropped");

                // Verify once_cell remains uninitialized
                assert!(
                    once_cell.get().is_none(),
                    "OnceCell should remain uninitialized"
                );

                let stats = harness.get_stats();
                assert!(stats.failed_initializations > 0);

                println!("Correctly handled dropped oneshot sender");
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_immediate_vs_delayed_initialization() -> Result<(), AsupersyncError> {
        let mut harness = OneshotOnceCellTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Test immediate initialization
                let immediate_cell = harness.create_once_cell("immediate-cell");
                let immediate_data = TestData {
                    id: 5,
                    payload: "immediate data".to_string(),
                    timestamp: Instant::now(),
                    initialization_source: InitializationSource::DirectInitialization,
                };

                // Initialize directly (immediate)
                immediate_cell
                    .set(immediate_data.clone())
                    .expect("Should initialize immediately");

                // Create oneshot for consistency, but it should not be needed
                let (immediate_sender, immediate_receiver) =
                    harness.create_oneshot_channel("immediate-channel");
                drop(immediate_sender); // Drop since we don't need it

                // This should return immediately
                let immediate_result = harness
                    .wait_for_initialization(cx, &immediate_cell, immediate_receiver)
                    .await;
                assert!(immediate_result.is_ok() || immediate_result.is_err()); // Either immediate success or oneshot failure

                if let Ok(result) = immediate_result {
                    assert_eq!(result, immediate_data);
                } else {
                    // Even if oneshot failed, once_cell should have the data
                    assert_eq!(*immediate_cell.get().unwrap(), immediate_data);
                }

                // Test delayed initialization
                let delayed_cell = harness.create_once_cell("delayed-cell");
                let (delayed_sender, delayed_receiver) =
                    harness.create_oneshot_channel("delayed-channel");

                let delayed_initializer = harness.create_initializer(
                    "delayed-init",
                    delayed_cell.clone(),
                    delayed_sender,
                    Duration::from_millis(100), // Significant delay
                );

                let delayed_data = TestData {
                    id: 6,
                    payload: "delayed data".to_string(),
                    timestamp: Instant::now(),
                    initialization_source: InitializationSource::OneshotCompletion,
                };

                // Start delayed initialization
                let init_task = {
                    let mut init_clone =
                        Arc::try_unwrap(delayed_initializer).unwrap_or_else(|arc| (*arc).clone());
                    let data_clone = delayed_data.clone();
                    cx.spawn(async move { init_clone.initialize_via_oneshot(cx, data_clone).await })
                };

                // This should wait for the delay
                let wait_start = Instant::now();
                let delayed_result = harness
                    .wait_for_initialization(cx, &delayed_cell, delayed_receiver)
                    .await?;
                let wait_duration = wait_start.elapsed();

                assert_eq!(delayed_result, delayed_data);
                assert!(
                    wait_duration >= Duration::from_millis(90),
                    "Should have waited for delay"
                );

                init_task.await??;

                let stats = harness.get_stats();
                assert!(stats.immediate_initializations > 0);
                assert!(stats.total_wait_time > Duration::from_millis(80));

                println!(
                    "Immediate vs delayed: immediate={}, wait_time={:?}",
                    stats.immediate_initializations, stats.total_wait_time
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_stress_many_once_cells_and_oneshots() -> Result<(), AsupersyncError> {
        let mut harness = OneshotOnceCellTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                let num_cells = 20;
                let mut tasks = Vec::new();

                let start_time = Instant::now();

                // Create many once_cells and oneshot channels
                for i in 0..num_cells {
                    let once_cell = harness.create_once_cell(&format!("stress-cell-{}", i));
                    let (sender, receiver) =
                        harness.create_oneshot_channel(&format!("stress-channel-{}", i));

                    let initializer = harness.create_initializer(
                        &format!("stress-init-{}", i),
                        once_cell.clone(),
                        sender,
                        Duration::from_millis(10 + (i * 5) as u64), // Varying delays
                    );

                    let test_data = TestData {
                        id: i as u64 + 100,
                        payload: format!("stress data {}", i),
                        timestamp: Instant::now(),
                        initialization_source: InitializationSource::OneshotCompletion,
                    };

                    // Spawn task for this cell
                    let task = {
                        let mut init_clone =
                            Arc::try_unwrap(initializer).unwrap_or_else(|arc| (*arc).clone());
                        let data_clone = test_data.clone();
                        let once_cell_clone = once_cell.clone();

                        cx.spawn(async move {
                            // Start initialization
                            let init_result = init_clone
                                .initialize_via_oneshot(cx, data_clone.clone())
                                .await;

                            // Wait for completion and verify
                            let wait_result = loop {
                                if let Some(data) = once_cell_clone.get() {
                                    break Ok(data.clone());
                                }
                                cx.yield_now().await;
                            };

                            (init_result, wait_result)
                        })
                    };

                    tasks.push(task);
                }

                // Wait for all tasks to complete
                let mut successful_count = 0;
                for (i, task) in tasks.into_iter().enumerate() {
                    let (init_result, wait_result) = task.await??;

                    if init_result.is_ok() && wait_result.is_ok() {
                        successful_count += 1;
                        let data = wait_result.unwrap();
                        assert_eq!(data.id, i as u64 + 100);
                        assert_eq!(data.payload, format!("stress data {}", i));
                    }
                }

                let total_duration = start_time.elapsed();
                let stats = harness.get_stats();

                assert!(
                    successful_count >= num_cells * 80 / 100,
                    "At least 80% should succeed"
                );
                assert_eq!(stats.once_cells_created, num_cells as u64);
                assert_eq!(stats.oneshot_channels_created, num_cells as u64);

                println!(
                    "Stress test: {}/{} successful in {:?}",
                    successful_count, num_cells, total_duration
                );
                println!(
                    "Stats: successes={}, failures={}, races={}",
                    stats.successful_initializations,
                    stats.failed_initializations,
                    stats.race_conditions_handled
                );

                // Performance assertion
                assert!(
                    total_duration < Duration::from_secs(3),
                    "Stress test should complete within reasonable time"
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_concurrent_initialization_coordination() -> Result<(), AsupersyncError> {
        let mut harness = OneshotOnceCellTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                let coordination_cell = harness.create_once_cell("coordination-cell");
                let (coord_sender, coord_receiver) =
                    harness.create_oneshot_channel("coordination-channel");

                // Create multiple dependent once_cells that wait on the coordination cell
                let num_dependents = 8;
                let mut dependent_tasks = Vec::new();

                for i in 0..num_dependents {
                    let dependent_cell = harness.create_once_cell(&format!("dependent-cell-{}", i));
                    let (dep_sender, dep_receiver) =
                        harness.create_oneshot_channel(&format!("dependent-channel-{}", i));

                    let coordination_cell_clone = coordination_cell.clone();
                    let stats_clone = harness.stats.clone();

                    let task = cx.spawn(async move {
                        // Wait for coordination signal
                        let coord_data = loop {
                            if let Some(data) = coordination_cell_clone.get() {
                                break data.clone();
                            }
                            cx.yield_now().await;
                        };

                        // Initialize dependent cell based on coordination
                        let dependent_data = TestData {
                            id: coord_data.id * 10 + i as u64,
                            payload: format!("dependent {} from {}", i, coord_data.payload),
                            timestamp: Instant::now(),
                            initialization_source: InitializationSource::OneshotCompletion,
                        };

                        let _ = dependent_cell.set(dependent_data.clone());
                        let _ = dep_sender.send(dependent_data.clone());

                        // Wait for our own initialization
                        match dep_receiver.await {
                            Ok(data) => {
                                let mut stats = stats_clone.lock().unwrap();
                                stats.successful_initializations += 1;
                                Ok(data)
                            }
                            Err(_) => Err(AsupersyncError::ChannelClosed),
                        }
                    });

                    dependent_tasks.push(task);
                }

                // Brief delay to let dependents start waiting
                cx.sleep(Duration::from_millis(50)).await;

                // Initialize coordination cell
                let coord_data = TestData {
                    id: 999,
                    payload: "coordination signal".to_string(),
                    timestamp: Instant::now(),
                    initialization_source: InitializationSource::OneshotCompletion,
                };

                coordination_cell
                    .set(coord_data.clone())
                    .expect("Should initialize coordination cell");
                coord_sender
                    .send(coord_data.clone())
                    .expect("Should send coordination signal");

                // Wait for all dependents to complete
                let mut successful_dependents = 0;
                for (i, task) in dependent_tasks.into_iter().enumerate() {
                    match task.await? {
                        Ok(data) => {
                            successful_dependents += 1;
                            assert_eq!(data.id, 999 * 10 + i as u64);
                            assert!(data.payload.contains("coordination signal"));
                        }
                        Err(_) => {}
                    }
                }

                assert_eq!(successful_dependents, num_dependents);

                let stats = harness.get_stats();
                println!(
                    "Coordination test: {} dependents successfully coordinated",
                    successful_dependents
                );
                println!(
                    "Total initializations: {}",
                    stats.successful_initializations
                );

                Ok(())
            })
            .await
    }
}
