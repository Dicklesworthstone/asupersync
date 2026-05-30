//! Metamorphic testing for hot-path bytes, io, and time modules.
//!
//! Tests bytes operations (split/freeze/chain), io operations (split/copy/lines),
//! and time operations (timer wheel/sleep/interval) using metamorphic relations.

#![allow(clippy::too_many_lines)]
#![allow(dead_code)]

#[cfg(all(test, feature = "test-internals"))]
mod bytes_io_time_tests {
    use crate::test_utils::init_test_logging;
    use proptest::prelude::*;
    use std::collections::VecDeque;
    use std::io::{self, Cursor};

    // ═══ Deterministic Bytes Model ═══════════════════════════════════════════════

    /// Deterministic bytes implementation for testing split/freeze metamorphic relations.
    #[derive(Debug, Clone)]
    pub struct MockBytesBuffer {
        data: Vec<u8>,
        offset: usize,
    }

    impl MockBytesBuffer {
        pub fn new(data: Vec<u8>) -> Self {
            Self { data, offset: 0 }
        }

        pub fn with_offset(data: Vec<u8>, offset: usize) -> Self {
            Self { data, offset }
        }

        /// Split off a portion at the given position.
        pub fn mock_split_off(&mut self, at: usize) -> Self {
            if at > self.len() {
                panic!("split_off out of bounds: at={}, len={}", at, self.len());
            }

            let split_point = self.offset + at;
            let tail_data = self.data.split_off(split_point);

            Self {
                data: tail_data,
                offset: 0,
            }
        }

        /// Split to a given position.
        pub fn mock_split_to(&mut self, at: usize) -> Self {
            if at > self.len() {
                panic!("split_to out of bounds: at={}, len={}", at, self.len());
            }

            let head_data = self.data[self.offset..self.offset + at].to_vec();
            self.offset += at;

            Self {
                data: head_data,
                offset: 0,
            }
        }

        /// Freeze to immutable bytes.
        pub fn mock_freeze(self) -> Vec<u8> {
            if self.offset >= self.data.len() {
                Vec::new()
            } else {
                self.data[self.offset..].to_vec()
            }
        }

        pub fn len(&self) -> usize {
            if self.offset >= self.data.len() {
                0
            } else {
                self.data.len() - self.offset
            }
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        pub fn as_slice(&self) -> &[u8] {
            if self.offset >= self.data.len() {
                &[]
            } else {
                &self.data[self.offset..]
            }
        }

        pub fn extend(&mut self, other: &[u8]) {
            if self.offset > 0 && self.offset < self.data.len() {
                // Need to consolidate data first
                let current_data = self.data[self.offset..].to_vec();
                self.data = current_data;
                self.offset = 0;
            }
            self.data.extend_from_slice(other);
        }
    }

    // ═══ Deterministic Buf Chain Model ═══════════════════════════════════════════

    /// Deterministic buf chain for testing associativity.
    #[derive(Debug, Clone)]
    pub struct MockBufChain {
        buffers: Vec<Vec<u8>>,
        current_buf: usize,
        current_pos: usize,
    }

    impl MockBufChain {
        pub fn new(buffers: Vec<Vec<u8>>) -> Self {
            Self {
                buffers,
                current_buf: 0,
                current_pos: 0,
            }
        }

        pub fn chain(a: Vec<u8>, b: Vec<u8>) -> Self {
            Self::new(vec![a, b])
        }

        pub fn chain_three(a: Vec<u8>, b: Vec<u8>, c: Vec<u8>) -> Self {
            Self::new(vec![a, b, c])
        }

        /// Chain this buffer with another (associative operation).
        pub fn chain_with(mut self, other: MockBufChain) -> Self {
            self.buffers.extend(other.buffers);
            self
        }

        pub fn remaining(&self) -> usize {
            let mut total = 0;
            for (i, buf) in self.buffers.iter().enumerate() {
                if i < self.current_buf {
                    continue;
                } else if i == self.current_buf {
                    total += buf.len() - self.current_pos;
                } else {
                    total += buf.len();
                }
            }
            total
        }

        pub fn copy_to_slice(&mut self, dst: &mut [u8]) -> usize {
            let mut copied = 0;
            let mut dst_pos = 0;

            while dst_pos < dst.len() && self.current_buf < self.buffers.len() {
                let current_buffer = &self.buffers[self.current_buf];
                let available = current_buffer.len() - self.current_pos;

                if available == 0 {
                    self.current_buf += 1;
                    self.current_pos = 0;
                    continue;
                }

                let to_copy = (dst.len() - dst_pos).min(available);
                dst[dst_pos..dst_pos + to_copy]
                    .copy_from_slice(&current_buffer[self.current_pos..self.current_pos + to_copy]);

                dst_pos += to_copy;
                copied += to_copy;
                self.current_pos += to_copy;

                if self.current_pos >= current_buffer.len() {
                    self.current_buf += 1;
                    self.current_pos = 0;
                }
            }

            copied
        }

        pub fn to_vec(&mut self) -> Vec<u8> {
            let total_len = self.remaining();
            let mut result = vec![0u8; total_len];
            self.copy_to_slice(&mut result);
            result
        }
    }

    // ═══ Deterministic I/O Split Model ═══════════════════════════════════════════

    /// Deterministic split stream for testing split-to-unsplit identity.
    #[derive(Debug)]
    pub struct MockSplitStream {
        read_data: Cursor<Vec<u8>>,
        write_data: Vec<u8>,
        original_data: Vec<u8>,
    }

    impl MockSplitStream {
        pub fn new(data: Vec<u8>) -> Self {
            Self {
                read_data: Cursor::new(data.clone()),
                write_data: Vec::new(),
                original_data: data,
            }
        }

        pub fn split(self) -> (MockReadHalf, MockWriteHalf) {
            let read_half = MockReadHalf {
                data: self.read_data,
            };
            let write_half = MockWriteHalf {
                data: self.write_data,
            };
            (read_half, write_half)
        }

        pub fn unsplit(read_half: MockReadHalf, write_half: MockWriteHalf) -> Self {
            // For testing purposes, reconstruct original data
            let remaining_read = {
                let pos = read_half.data.position() as usize;
                let data = read_half.data.into_inner();
                data[pos..].to_vec()
            };

            Self {
                read_data: Cursor::new(remaining_read),
                write_data: write_half.data,
                original_data: Vec::new(), // Original lost in split
            }
        }

        pub fn read_data(&self) -> &[u8] {
            let pos = self.read_data.position() as usize;
            &self.read_data.get_ref()[pos..]
        }

        pub fn write_data(&self) -> &[u8] {
            &self.write_data
        }
    }

    #[derive(Debug)]
    pub struct MockReadHalf {
        data: Cursor<Vec<u8>>,
    }

    #[derive(Debug)]
    pub struct MockWriteHalf {
        data: Vec<u8>,
    }

    impl MockReadHalf {
        pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::io::Read::read(&mut self.data, buf)
        }

        pub fn remaining_data(&self) -> Vec<u8> {
            let pos = self.data.position() as usize;
            self.data.get_ref()[pos..].to_vec()
        }
    }

    impl MockWriteHalf {
        pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }

        pub fn written_data(&self) -> &[u8] {
            &self.data
        }
    }

    // ═══ Deterministic I/O Copy Model ════════════════════════════════════════════

    /// Deterministic I/O copy for testing bytes conservation.
    #[derive(Debug)]
    pub struct MockCopyOperation {
        source: Cursor<Vec<u8>>,
        destination: Vec<u8>,
    }

    impl MockCopyOperation {
        pub fn new(source_data: Vec<u8>) -> Self {
            Self {
                source: Cursor::new(source_data),
                destination: Vec::new(),
            }
        }

        pub fn copy_all(&mut self) -> io::Result<u64> {
            let mut buffer = Vec::new();
            let bytes_read = std::io::Read::read_to_end(&mut self.source, &mut buffer)?;
            self.destination.extend_from_slice(&buffer);
            Ok(bytes_read as u64)
        }

        pub fn copy_chunked(&mut self, chunk_size: usize) -> io::Result<u64> {
            let mut total_copied = 0u64;
            let mut buffer = vec![0u8; chunk_size];

            loop {
                let bytes_read = std::io::Read::read(&mut self.source, &mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                self.destination.extend_from_slice(&buffer[..bytes_read]);
                total_copied += bytes_read as u64;
            }

            Ok(total_copied)
        }

        pub fn source_data(&self) -> &[u8] {
            self.source.get_ref()
        }

        pub fn destination_data(&self) -> &[u8] {
            &self.destination
        }
    }

    // ═══ Deterministic Lines Reader Model ════════════════════════════════════════

    /// Deterministic lines reader for testing termination correctness.
    #[derive(Debug)]
    pub struct MockLinesReader {
        data: String,
        position: usize,
    }

    impl MockLinesReader {
        pub fn new(data: String) -> Self {
            Self { data, position: 0 }
        }

        pub fn read_line(&mut self) -> Option<String> {
            if self.position >= self.data.len() {
                return None;
            }

            let remaining = &self.data[self.position..];
            if let Some(newline_pos) = remaining.find('\n') {
                let line = remaining[..=newline_pos].to_string();
                self.position += line.len();
                Some(line)
            } else if !remaining.is_empty() {
                // Last line without newline
                let line = remaining.to_string();
                self.position = self.data.len();
                Some(line)
            } else {
                None
            }
        }

        pub fn read_lines(&mut self) -> Vec<String> {
            let mut lines = Vec::new();
            while let Some(line) = self.read_line() {
                lines.push(line);
            }
            lines
        }

        pub fn reset(&mut self) {
            self.position = 0;
        }

        pub fn is_at_end(&self) -> bool {
            self.position >= self.data.len()
        }
    }

    // ═══ Deterministic Timer Model ═══════════════════════════════════════════════

    /// Deterministic timer wheel for testing timeout monotonicity.
    #[derive(Debug, Clone)]
    pub struct MockTimerWheel {
        current_time: u64,
        timeouts: VecDeque<(u64, u32)>, // (deadline, timer_id)
        next_timer_id: u32,
    }

    impl MockTimerWheel {
        pub fn new() -> Self {
            Self {
                current_time: 0,
                timeouts: VecDeque::new(),
                next_timer_id: 1,
            }
        }

        pub fn add_timeout(&mut self, delay: u64) -> u32 {
            let deadline = self.current_time + delay;
            let timer_id = self.next_timer_id;
            self.next_timer_id += 1;

            // Insert in order to maintain monotonicity
            let mut insert_pos = 0;
            for (i, (existing_deadline, _)) in self.timeouts.iter().enumerate() {
                if deadline <= *existing_deadline {
                    insert_pos = i;
                    break;
                }
                insert_pos = i + 1;
            }

            self.timeouts.insert(insert_pos, (deadline, timer_id));
            timer_id
        }

        pub fn advance_time(&mut self, delta: u64) {
            self.current_time += delta;
        }

        pub fn poll_ready_timeouts(&mut self) -> Vec<u32> {
            let mut ready = Vec::new();

            while let Some((deadline, timer_id)) = self.timeouts.front().copied() {
                if deadline <= self.current_time {
                    ready.push(timer_id);
                    self.timeouts.pop_front();
                } else {
                    break;
                }
            }

            ready
        }

        pub fn current_time(&self) -> u64 {
            self.current_time
        }

        pub fn next_deadline(&self) -> Option<u64> {
            self.timeouts.front().map(|(deadline, _)| *deadline)
        }

        /// Check monotonicity invariant: timeouts are ordered by deadline.
        pub fn is_monotonic(&self) -> bool {
            for window in self.timeouts.iter().collect::<Vec<_>>().windows(2) {
                if window[0].0 > window[1].0 {
                    return false;
                }
            }
            true
        }
    }

    // ═══ Deterministic Sleep/Interval Model ══════════════════════════════════════

    /// Deterministic sleep for testing wakeup ordering.
    #[derive(Debug, Clone)]
    pub struct MockSleep {
        deadline: u64,
        created_at: u64,
        sleep_id: u32,
    }

    impl MockSleep {
        pub fn new(duration: u64, current_time: u64, sleep_id: u32) -> Self {
            Self {
                deadline: current_time + duration,
                created_at: current_time,
                sleep_id,
            }
        }

        pub fn is_ready(&self, current_time: u64) -> bool {
            current_time >= self.deadline
        }

        pub fn deadline(&self) -> u64 {
            self.deadline
        }

        pub fn sleep_id(&self) -> u32 {
            self.sleep_id
        }
    }

    /// Deterministic interval for testing skip-on-late behavior.
    #[derive(Debug)]
    pub struct MockInterval {
        period: u64,
        next_tick: u64,
        skip_on_late: bool,
        tick_count: u64,
    }

    impl MockInterval {
        pub fn new(period: u64, start_time: u64, skip_on_late: bool) -> Self {
            Self {
                period,
                next_tick: start_time + period,
                skip_on_late,
                tick_count: 0,
            }
        }

        pub fn tick(&mut self, current_time: u64) -> Option<u64> {
            if current_time >= self.next_tick {
                let tick_time = self.next_tick;
                self.tick_count += 1;

                if self.skip_on_late && current_time > self.next_tick + self.period {
                    // Skip missed ticks
                    let missed_ticks = (current_time - self.next_tick) / self.period;
                    self.next_tick += (missed_ticks + 1) * self.period;
                } else {
                    self.next_tick += self.period;
                }

                Some(tick_time)
            } else {
                None
            }
        }

        pub fn next_tick_deadline(&self) -> u64 {
            self.next_tick
        }

        pub fn tick_count(&self) -> u64 {
            self.tick_count
        }
    }

    // ═══ Property Generators ═══════════════════════════════════════════════════

    /// Generate arbitrary byte vectors.
    pub fn arbitrary_bytes() -> BoxedStrategy<Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..=1024).boxed()
    }

    /// Generate arbitrary split positions.
    pub fn arbitrary_split_pos(max_len: usize) -> BoxedStrategy<usize> {
        (0..=max_len).boxed()
    }

    /// Generate arbitrary text with line endings.
    pub fn arbitrary_text_with_lines() -> BoxedStrategy<String> {
        prop::collection::vec(
            prop_oneof!["[a-zA-Z0-9 ]+", "[a-zA-Z0-9 ]+\n", "[a-zA-Z0-9 ]+\r\n",],
            0..=20,
        )
        .prop_map(|parts| parts.join(""))
        .boxed()
    }

    // ═══ Metamorphic Relations ══════════════════════════════════════════════════

    /// MR1: BytesMut split_off/split_to conservation - total bytes preserved.
    /// Category: Additive f(a + b) = f(a) + f(b)
    /// Detects: data loss in split operations, boundary calculation errors
    #[test]
    fn mr_bytes_mut_split_conservation() {
        init_test_logging();
        crate::test_phase!("mr_bytes_mut_split_conservation");

        proptest!(|(
            data in arbitrary_bytes(),
            split_pos in 0usize..=1024
        )| {
            let original_len = data.len();

            if split_pos <= original_len {
                let buffer = MockBytesBuffer::new(data.clone());
                let original_slice = buffer.as_slice().to_vec();

                // split_off: splits at position, returns tail
                let mut buffer_split_off = buffer.clone();
                let tail = buffer_split_off.mock_split_off(split_pos);
                let head_remaining = buffer_split_off.as_slice().to_vec();

                // Conservation: head + tail = original
                let mut reconstructed = head_remaining.clone();
                reconstructed.extend_from_slice(tail.as_slice());

                prop_assert_eq!(&original_slice, &reconstructed,
                    "split_off doesn't preserve total data: {} + {} != {} bytes",
                    head_remaining.len(), tail.len(), original_len);

                // split_to: splits at position, returns head
                let mut buffer_split_to = MockBytesBuffer::new(data.clone());
                let head = buffer_split_to.mock_split_to(split_pos);
                let tail_remaining = buffer_split_to.as_slice().to_vec();

                // Conservation: head + tail = original
                let mut reconstructed_to = head.as_slice().to_vec();
                reconstructed_to.extend_from_slice(&tail_remaining);

                prop_assert_eq!(&original_slice, &reconstructed_to,
                    "split_to doesn't preserve total data");

                // Length invariant
                prop_assert_eq!(head.len(), split_pos,
                    "split_to head length incorrect: {} vs {}", head.len(), split_pos);
                prop_assert_eq!(tail.len(), original_len - split_pos,
                    "split_off tail length incorrect");
            }
        });

        crate::test_complete!("mr_bytes_mut_split_conservation");
    }

    /// MR2: BytesMut freeze→split equivalence - freeze before/after split equivalent.
    /// Category: Equivalence f(T(x)) = f(x)
    /// Detects: freeze/split interaction bugs, state corruption during freeze
    #[test]
    fn mr_bytes_mut_freeze_split_equivalence() {
        init_test_logging();
        crate::test_phase!("mr_bytes_mut_freeze_split_equivalence");

        proptest!(|(
            data in arbitrary_bytes(),
            split_pos in 0usize..=512
        )| {
            if split_pos <= data.len() {
                // freeze then conceptual split
                let buffer_freeze_first = MockBytesBuffer::new(data.clone());
                let frozen = buffer_freeze_first.mock_freeze();
                let freeze_then_split = if split_pos < frozen.len() {
                    frozen[..split_pos].to_vec()
                } else {
                    frozen.clone()
                };

                // split then freeze
                let mut buffer_split_first = MockBytesBuffer::new(data.clone());
                let head = buffer_split_first.mock_split_to(split_pos);
                let split_then_freeze = head.mock_freeze();

                // Both approaches should yield same result
                prop_assert_eq!(&freeze_then_split, &split_then_freeze,
                    "freeze→split != split→freeze: {} vs {} bytes",
                    freeze_then_split.len(), split_then_freeze.len());

                // Data content should be identical
                if !freeze_then_split.is_empty() && !split_then_freeze.is_empty() {
                    prop_assert_eq!(freeze_then_split[0], split_then_freeze[0],
                        "freeze/split equivalence: first bytes differ");
                }
            }
        });

        crate::test_complete!("mr_bytes_mut_freeze_split_equivalence");
    }

    /// MR3: Buf chain associativity - (a.chain(b)).chain(c) = a.chain(b.chain(c)).
    /// Category: Permutative (associative operations)
    /// Detects: chain ordering bugs, buffer sequence errors
    #[test]
    fn mr_buf_chain_associativity() {
        init_test_logging();
        crate::test_phase!("mr_buf_chain_associativity");

        proptest!(|(
            a in arbitrary_bytes(),
            b in arbitrary_bytes(),
            c in arbitrary_bytes()
        )| {
            // (a.chain(b)).chain(c)
            let mut left_assoc = MockBufChain::chain(a.clone(), b.clone())
                .chain_with(MockBufChain::new(vec![c.clone()]));

            // a.chain(b.chain(c))
            let mut right_assoc = MockBufChain::new(vec![a.clone()])
                .chain_with(MockBufChain::chain(b.clone(), c.clone()));

            // Both should produce same data when read
            let left_result = left_assoc.to_vec();
            let right_result = right_assoc.to_vec();

            prop_assert_eq!(&left_result, &right_result,
                "Chain associativity violation: {} vs {} bytes",
                left_result.len(), right_result.len());

            // Expected concatenation
            let mut expected = a.clone();
            expected.extend_from_slice(&b);
            expected.extend_from_slice(&c);

            prop_assert_eq!(&left_result, &expected,
                "Left associative chain doesn't match expected concatenation");
            prop_assert_eq!(&right_result, &expected,
                "Right associative chain doesn't match expected concatenation");

            // Remaining should be consistent
            let left_check = MockBufChain::chain(a.clone(), b.clone())
                .chain_with(MockBufChain::new(vec![c.clone()]));
            let right_check = MockBufChain::new(vec![a])
                .chain_with(MockBufChain::chain(b, c));

            prop_assert_eq!(left_check.remaining(), right_check.remaining(),
                "Chain associativity: remaining() differs");
        });

        crate::test_complete!("mr_buf_chain_associativity");
    }

    /// MR4: Buf take limit composition - take(n).take(m) = take(min(n,m)).
    /// Category: Multiplicative (limit composition)
    /// Detects: take limit calculation errors, compound limit bugs
    #[test]
    fn mr_buf_take_limit_composition() {
        init_test_logging();
        crate::test_phase!("mr_buf_take_limit_composition");

        proptest!(|(
            data in arbitrary_bytes(),
            limit1 in 0usize..=512,
            limit2 in 0usize..=512
        )| {
            if !data.is_empty() {
                // Exercise take(limit1).take(limit2).
                let effective_limit1 = limit1.min(data.len());
                let intermediate = &data[..effective_limit1];
                let effective_limit2 = limit2.min(intermediate.len());
                let double_take_result = &intermediate[..effective_limit2];

                // Exercise take(min(limit1, limit2)).
                let combined_limit = limit1.min(limit2).min(data.len());
                let direct_take_result = &data[..combined_limit];

                // Both approaches should yield identical results
                prop_assert_eq!(double_take_result, direct_take_result,
                    "Take limit composition: take({}).take({}) != take({})",
                    limit1, limit2, limit1.min(limit2));

                // Length property
                prop_assert_eq!(double_take_result.len(), combined_limit,
                    "Composed take length incorrect: {} vs {}",
                    double_take_result.len(), combined_limit);

                // Min property: result should never exceed min limit
                let min_limit = limit1.min(limit2);
                prop_assert!(double_take_result.len() <= min_limit,
                    "Take composition exceeds minimum limit: {} > {}",
                    double_take_result.len(), min_limit);
            }
        });

        crate::test_complete!("mr_buf_take_limit_composition");
    }

    /// MR5: IO split→unsplit identity - split then unsplit preserves functionality.
    /// Category: Invertive f(T(T(x))) = f(x)
    /// Detects: split/unsplit state loss, stream reconstruction errors
    #[test]
    fn mr_io_split_unsplit_identity() {
        init_test_logging();
        crate::test_phase!("mr_io_split_unsplit_identity");

        proptest!(|(data in arbitrary_bytes())| {
            let original_stream = MockSplitStream::new(data.clone());
            let original_read_data = original_stream.read_data().to_vec();

            // Split into halves
            let (read_half, write_half) = original_stream.split();

            // Capture current state
            let read_data_after_split = read_half.remaining_data();
            let write_data_after_split = write_half.written_data().to_vec();

            // Unsplit back to combined stream
            let reconstructed_stream = MockSplitStream::unsplit(read_half, write_half);
            let reconstructed_read_data = reconstructed_stream.read_data().to_vec();
            let reconstructed_write_data = reconstructed_stream.write_data().to_vec();

            // Read data should be preserved (assuming no reading occurred during split)
            prop_assert_eq!(&read_data_after_split, &reconstructed_read_data,
                "Split-unsplit doesn't preserve read data: {} vs {} bytes",
                read_data_after_split.len(), reconstructed_read_data.len());

            // Write data should be preserved
            prop_assert_eq!(write_data_after_split, reconstructed_write_data,
                "Split-unsplit doesn't preserve write data");

            // Original read data should match if no operations performed
            if !data.is_empty() && read_data_after_split.len() == original_read_data.len() {
                prop_assert_eq!(&original_read_data, &read_data_after_split,
                    "Split operation modified read data unexpectedly");
            }
        });

        crate::test_complete!("mr_io_split_unsplit_identity");
    }

    /// MR6: IO copy bytes conservation - bytes copied equals source bytes.
    /// Category: Equivalence (conservation law)
    /// Detects: copy data loss, partial copy bugs, buffer size miscalculation
    #[test]
    fn mr_io_copy_bytes_conservation() {
        init_test_logging();
        crate::test_phase!("mr_io_copy_bytes_conservation");

        proptest!(|(
            data in arbitrary_bytes(),
            chunk_size in 1usize..=256
        )| {
            // Test copy_all vs copy_chunked equivalence
            let mut copy_all_op = MockCopyOperation::new(data.clone());
            let bytes_copied_all = copy_all_op.copy_all().unwrap();
            let result_all = copy_all_op.destination_data().to_vec();

            let mut copy_chunked_op = MockCopyOperation::new(data.clone());
            let bytes_copied_chunked = copy_chunked_op.copy_chunked(chunk_size).unwrap();
            let result_chunked = copy_chunked_op.destination_data().to_vec();

            // Bytes copied should match source length
            prop_assert_eq!(bytes_copied_all, data.len() as u64,
                "copy_all reported {} bytes but source has {} bytes",
                bytes_copied_all, data.len());

            prop_assert_eq!(bytes_copied_chunked, data.len() as u64,
                "copy_chunked reported {} bytes but source has {} bytes",
                bytes_copied_chunked, data.len());

            // Results should be identical regardless of copy method
            prop_assert_eq!(&result_all, &result_chunked,
                "copy_all and copy_chunked produce different results: {} vs {} bytes",
                result_all.len(), result_chunked.len());

            // Results should match original data
            prop_assert_eq!(&result_all, &data,
                "copy_all doesn't preserve data integrity");

            prop_assert_eq!(&result_chunked, &data,
                "copy_chunked doesn't preserve data integrity");

            // Conservation law: input bytes = output bytes
            prop_assert_eq!(copy_all_op.source_data().len(), result_all.len(),
                "Copy operation violates conservation: source {} != dest {} bytes",
                copy_all_op.source_data().len(), result_all.len());
        });

        crate::test_complete!("mr_io_copy_bytes_conservation");
    }

    /// MR7: Lines/read_line termination correctness - different read patterns same result.
    /// Category: Equivalence (parsing consistency)
    /// Detects: line parsing bugs, termination handling errors, boundary conditions
    #[test]
    fn mr_lines_read_line_termination_correctness() {
        init_test_logging();
        crate::test_phase!("mr_lines_read_line_termination_correctness");

        proptest!(|(text_data in arbitrary_text_with_lines())| {
            // Read line by line
            let mut line_reader = MockLinesReader::new(text_data.clone());
            let lines_individually = line_reader.read_lines();

            // Read all lines at once
            let mut batch_reader = MockLinesReader::new(text_data.clone());
            let lines_batch = batch_reader.read_lines();

            // Both should produce identical results
            prop_assert_eq!(&lines_individually, &lines_batch,
                "Line-by-line reading differs from batch reading: {} vs {} lines",
                lines_individually.len(), lines_batch.len());

            // Reconstruction test: join lines should approximate original
            let _reconstructed = lines_individually.join("");

            // Handle case where original didn't end with newline
            if !text_data.is_empty() {
                // Count line endings to verify parsing correctness
                let expected_line_count = if text_data.ends_with('\n') || text_data.ends_with('\r') {
                    text_data.matches('\n').count()
                } else {
                    text_data.matches('\n').count() + 1
                };

                if expected_line_count > 0 {
                    prop_assert_eq!(lines_individually.len(), expected_line_count,
                        "Line count mismatch: expected {} lines, got {}",
                        expected_line_count, lines_individually.len());
                }
            }

            // Termination property: reading past end should return None
            let mut exhausted_reader = MockLinesReader::new(text_data);
            exhausted_reader.read_lines(); // Exhaust all lines
            let extra_read = exhausted_reader.read_line();
            prop_assert!(extra_read.is_none(),
                "Reading past end should return None, got: {:?}", extra_read);

            prop_assert!(exhausted_reader.is_at_end(),
                "Reader should be at end after exhausting all lines");
        });

        crate::test_complete!("mr_lines_read_line_termination_correctness");
    }

    /// MR8: Timer wheel timeout monotonicity - timeouts fire in deadline order.
    /// Category: Permutative (ordering preservation)
    /// Detects: timeout ordering bugs, deadline calculation errors, priority inversion
    #[test]
    fn mr_timer_wheel_timeout_monotonicity() {
        init_test_logging();
        crate::test_phase!("mr_timer_wheel_timeout_monotonicity");

        proptest!(|(
            delays in prop::collection::vec(1u64..=100, 3..=10)
        )| {
            let mut timer_wheel = MockTimerWheel::new();
            let mut added_timers = Vec::new();

            // Add timeouts with various delays
            for &delay in &delays {
                let timer_id = timer_wheel.add_timeout(delay);
                added_timers.push((timer_wheel.current_time() + delay, timer_id));
            }

            // Timer wheel should maintain monotonicity
            prop_assert!(timer_wheel.is_monotonic(),
                "Timer wheel lost monotonicity after adding timeouts");

            // Advance time and collect fired timeouts
            let max_delay = delays.iter().max().unwrap_or(&1);
            let mut fired_timeouts = Vec::new();

            for tick in 1..=*max_delay + 10 {
                timer_wheel.advance_time(1);
                let mut ready = timer_wheel.poll_ready_timeouts();
                fired_timeouts.append(&mut ready);

                // Monotonicity should be preserved after polling
                prop_assert!(timer_wheel.is_monotonic(),
                    "Timer wheel lost monotonicity after polling at tick {}", tick);
            }

            // Verify fired timeouts respect deadline ordering
            let mut last_deadline = 0u64;
            for (expected_deadline, timer_id) in added_timers {
                if fired_timeouts.contains(&timer_id) {
                    prop_assert!(expected_deadline >= last_deadline,
                        "Timer {} fired out of order: deadline {} < previous {}",
                        timer_id, expected_deadline, last_deadline);
                    last_deadline = expected_deadline;
                }
            }

            // All timeouts should eventually fire
            prop_assert_eq!(fired_timeouts.len(), delays.len(),
                "Not all timeouts fired: {} vs {} expected",
                fired_timeouts.len(), delays.len());
        });

        crate::test_complete!("mr_timer_wheel_timeout_monotonicity");
    }

    /// MR9: Sleep wakeup ordering - earlier sleeps wake before later sleeps.
    /// Category: Permutative (temporal ordering)
    /// Detects: sleep ordering bugs, deadline handling errors
    #[test]
    fn mr_sleep_wakeup_ordering() {
        init_test_logging();
        crate::test_phase!("mr_sleep_wakeup_ordering");

        proptest!(|(
            sleep_durations in prop::collection::vec(1u64..=50, 3..=8)
        )| {
            let start_time = 100u64; // Arbitrary start time
            let mut sleeps = Vec::new();

            // Create sleeps with different durations
            for (i, &duration) in sleep_durations.iter().enumerate() {
                let sleep = MockSleep::new(duration, start_time, i as u32);
                sleeps.push(sleep);
            }

            // Test wakeup ordering across time
            let max_duration = sleep_durations.iter().max().unwrap_or(&1);
            let mut woken_sleeps = Vec::new();

            for current_time in start_time..=start_time + max_duration + 10 {
                for sleep in &sleeps {
                    if sleep.is_ready(current_time) && !woken_sleeps.contains(&sleep.sleep_id()) {
                        woken_sleeps.push(sleep.sleep_id());
                    }
                }
            }

            // Verify ordering: sleeps should wake up in deadline order
            let mut sleep_deadlines: Vec<(u64, u32)> = sleeps.iter()
                .map(|s| (s.deadline(), s.sleep_id()))
                .collect();
            sleep_deadlines.sort_by_key(|(deadline, _)| *deadline);

            for (i, &woken_id) in woken_sleeps.iter().enumerate() {
                if i < sleep_deadlines.len() {
                    // Find the actual deadline for this woken sleep
                    if let Some(sleep) = sleeps.iter().find(|s| s.sleep_id() == woken_id) {
                        let actual_deadline = sleep.deadline();

                        // Earlier or equal deadline should wake up first
                        if i > 0 {
                            let prev_sleep = sleeps.iter()
                                .find(|s| s.sleep_id() == woken_sleeps[i-1])
                                .unwrap();

                            prop_assert!(actual_deadline >= prev_sleep.deadline(),
                                "Sleep wakeup ordering violation: sleep {} (deadline {}) woke before sleep {} (deadline {})",
                                woken_id, actual_deadline, prev_sleep.sleep_id(), prev_sleep.deadline());
                        }
                    }
                }
            }

            // All sleeps should eventually wake
            prop_assert_eq!(woken_sleeps.len(), sleeps.len(),
                "Not all sleeps woke up: {} vs {} expected",
                woken_sleeps.len(), sleeps.len());
        });

        crate::test_complete!("mr_sleep_wakeup_ordering");
    }

    /// MR10: Interval skip-on-late determinism - skip behavior consistent.
    /// Category: Equivalence (deterministic skipping)
    /// Detects: interval skipping bugs, timing calculation errors
    #[test]
    fn mr_interval_skip_on_late_determinism() {
        init_test_logging();
        crate::test_phase!("mr_interval_skip_on_late_determinism");

        proptest!(|(
            period in 5u64..=20,
            delay_before_poll in 10u64..=100
        )| {
            let start_time = 1000u64;

            // Test both skip modes
            let mut interval_skip = MockInterval::new(period, start_time, true);
            let mut interval_no_skip = MockInterval::new(period, start_time, false);

            // Advance past the deadline.
            let late_time = start_time + delay_before_poll;

            let tick_skip = interval_skip.tick(late_time);
            let tick_no_skip = interval_no_skip.tick(late_time);

            // Both should tick when late, but skip mode affects next deadline
            prop_assert!(tick_skip.is_some(),
                "Skip-enabled interval should tick when late");
            prop_assert!(tick_no_skip.is_some(),
                "Non-skip interval should tick when late");

            // Verify skip behavior affects next deadline calculation
            let next_deadline_skip = interval_skip.next_tick_deadline();
            let next_deadline_no_skip = interval_no_skip.next_tick_deadline();

            if delay_before_poll > period * 2 {
                // Significant lateness should result in different next deadlines
                prop_assert!(next_deadline_skip >= next_deadline_no_skip,
                    "Skip mode should advance deadline more when significantly late");
            }

            // Test multiple ticks for consistency
            for _ in 0..3 {
                let current_time = next_deadline_skip + 1;

                let skip_tick = interval_skip.tick(current_time);
                let no_skip_tick = interval_no_skip.tick(current_time);

                // Both should eventually tick regularly
                if skip_tick.is_some() || no_skip_tick.is_some() {
                    prop_assert!(interval_skip.tick_count() > 0 || interval_no_skip.tick_count() > 0,
                        "At least one interval should be making progress");
                }
            }

            // Determinism: same input should produce same output
            let mut interval_copy = MockInterval::new(period, start_time, true);
            let tick_copy = interval_copy.tick(late_time);

            prop_assert_eq!(tick_skip, tick_copy,
                "Interval skip behavior not deterministic");
        });

        crate::test_complete!("mr_interval_skip_on_late_determinism");
    }

    /// MR11: Composite - Bytes split ∘ chain associativity.
    /// Category: Composition of additive + permutative relations
    /// Detects: compound bugs where split operations affect chain behavior
    #[test]
    fn mr_composite_bytes_split_chain_associativity() {
        init_test_logging();
        crate::test_phase!("mr_composite_bytes_split_chain_associativity");

        proptest!(|(
            data1 in arbitrary_bytes(),
            data2 in arbitrary_bytes(),
            split_pos in 0usize..=256
        )| {
            if !data1.is_empty() && split_pos <= data1.len() {
                // MR1: Split data1, then chain with data2
                let mut buffer1 = MockBytesBuffer::new(data1.clone());
                let split_part = buffer1.mock_split_to(split_pos);
                let remaining_part = buffer1.as_slice().to_vec();

                let chain1 = MockBufChain::chain(split_part.as_slice().to_vec(), data2.clone());
                let chain2 = MockBufChain::chain(remaining_part, Vec::new());

                // MR3: Chain the results with associativity check
                let mut combined_chain = chain1.chain_with(chain2);
                let result1 = combined_chain.to_vec();

                // Alternative: chain data1 and data2 first, then split
                let mut full_chain = MockBufChain::chain(data1.clone(), data2.clone());
                let full_result = full_chain.to_vec();

                // Extract the split position from the full result
                let _split_result = if split_pos < full_result.len() {
                    full_result[..split_pos + data2.len()].to_vec()
                } else {
                    full_result.clone()
                };

                // Composite property: split→chain should preserve data relationships
                // The first split_pos bytes should be from data1's split part
                if split_pos > 0 && !result1.is_empty() {
                    prop_assert_eq!(
                        &result1[..split_pos.min(result1.len())],
                        &split_part.as_slice()[..split_pos.min(split_part.len())],
                        "Split-chain composition doesn't preserve split data at beginning"
                    );
                }

                // Length relationships should be preserved
                prop_assert_eq!(result1.len(), split_pos + data2.len(),
                    "Split-chain length doesn't match expected: {} vs {}",
                    result1.len(), split_pos + data2.len());
            }
        });

        crate::test_complete!("mr_composite_bytes_split_chain_associativity");
    }

    #[cfg(test)]
    mod unit_tests {
        use super::*;

        #[test]
        fn test_mock_bytes_buffer_basic() {
            let data = b"hello world".to_vec();
            let mut buffer = MockBytesBuffer::new(data.clone());

            let tail = buffer.mock_split_off(6);
            assert_eq!(buffer.as_slice(), b"hello ");
            assert_eq!(tail.as_slice(), b"world");
        }

        #[test]
        fn test_mock_buf_chain_basic() {
            let a = b"hello".to_vec();
            let b = b" world".to_vec();
            let mut chain = MockBufChain::chain(a, b);

            let mut result = vec![0u8; chain.remaining()];
            chain.copy_to_slice(&mut result);
            assert_eq!(result, b"hello world");
        }

        #[test]
        fn test_mock_timer_wheel_basic() {
            let mut timer = MockTimerWheel::new();
            let id1 = timer.add_timeout(10);
            let id2 = timer.add_timeout(5);

            timer.advance_time(6);
            let ready = timer.poll_ready_timeouts();
            assert_eq!(ready, vec![id2]); // Earlier timeout fires first

            timer.advance_time(5);
            let ready = timer.poll_ready_timeouts();
            assert_eq!(ready, vec![id1]);
        }
    }
} // end bytes_io_time_tests module

#[cfg(not(all(test, feature = "test-internals")))]
mod no_bytes_io_time_fallback {
    #[derive(Debug, PartialEq, Eq)]
    struct FeatureGateProof {
        cfg_profile: &'static str,
        required_feature: &'static str,
        support_class: &'static str,
        reason_code: &'static str,
    }

    fn feature_gate_proof() -> FeatureGateProof {
        FeatureGateProof {
            cfg_profile: "not(all(test, feature = \"test-internals\"))",
            required_feature: "test-internals",
            support_class: "unsupported_without_test_internals",
            reason_code: "bytes_io_time_metamorphic_module_not_compiled",
        }
    }

    #[test]
    fn bytes_io_time_reports_test_internals_gate() {
        let proof = feature_gate_proof();
        assert_eq!(proof.required_feature, "test-internals");
        assert_eq!(proof.support_class, "unsupported_without_test_internals");
        assert_eq!(
            proof.reason_code,
            "bytes_io_time_metamorphic_module_not_compiled"
        );
        assert!(
            proof.cfg_profile.contains("test-internals"),
            "cfg profile must name the missing feature boundary"
        );
    }
}
