//! Fuzz target for the bytes::buf::Take adapter.
//!
//! Focus:
//! - `remaining()` and `chunk()` must never expose bytes past the configured limit
//! - valid reads must shrink both the cursor position and the limit
//! - oversized reads must panic instead of silently over-reading

#![no_main]

use asupersync::bytes::Buf;
use libfuzzer_sys::fuzz_target;
use std::panic::{self, AssertUnwindSafe};

const MAX_SOURCE_LEN: usize = 256;
const MAX_OPS: usize = 64;
const MAX_LIMIT: usize = 64;

#[derive(Debug, Clone)]
struct ParsedInput {
    source: Vec<u8>,
    initial_limit: usize,
    operations: Vec<Operation>,
}

#[derive(Debug, Clone)]
enum Operation {
    Check,
    Advance(usize),
    Copy(usize),
    GetU8,
    GetU16,
    SetLimit(usize),
    OversizedAdvance(usize),
    OversizedCopy(usize),
}

#[derive(Debug, Clone)]
struct ShadowTake {
    data: Vec<u8>,
    position: usize,
    limit: usize,
}

impl ShadowTake {
    fn new(data: Vec<u8>, limit: usize) -> Self {
        Self {
            data,
            position: 0,
            limit,
        }
    }

    fn remaining(&self) -> usize {
        self.data
            .len()
            .saturating_sub(self.position)
            .min(self.limit)
    }

    fn unread(&self) -> &[u8] {
        &self.data[self.position..]
    }

    fn chunk(&self) -> &[u8] {
        let len = self.remaining();
        &self.data[self.position..self.position + len]
    }

    fn advance(&mut self, amount: usize) {
        assert!(amount <= self.remaining());
        self.position += amount;
        self.limit -= amount;
    }

    fn copy_to_slice(&mut self, dst_len: usize) -> Vec<u8> {
        assert!(dst_len <= self.remaining());
        let copied = self.data[self.position..self.position + dst_len].to_vec();
        self.advance(dst_len);
        copied
    }

    fn get_u8(&mut self) -> u8 {
        self.copy_to_slice(1)[0]
    }

    fn get_u16(&mut self) -> u16 {
        let copied = self.copy_to_slice(2);
        u16::from_be_bytes([copied[0], copied[1]])
    }

    fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let input = parse_input(data);
    run_input(input);
});

fn run_input(input: ParsedInput) {
    let ParsedInput {
        source,
        initial_limit,
        operations,
    } = input;
    let mut actual = source.as_slice().take(initial_limit);
    let mut shadow = ShadowTake::new(source.clone(), initial_limit);

    validate_state(&actual, &shadow);

    for operation in operations.into_iter().take(MAX_OPS) {
        match operation {
            Operation::Check => {}
            Operation::Advance(amount) => {
                if amount <= shadow.remaining() {
                    actual.advance(amount);
                    shadow.advance(amount);
                } else {
                    assert_advance_panics(&shadow, amount);
                }
            }
            Operation::Copy(dst_len) => {
                if dst_len <= shadow.remaining() {
                    let mut actual_dst = vec![0u8; dst_len];
                    actual.copy_to_slice(&mut actual_dst);
                    let expected_dst = shadow.copy_to_slice(dst_len);
                    assert_eq!(
                        actual_dst, expected_dst,
                        "copy_to_slice returned bytes different from the shadow model"
                    );
                } else {
                    assert_copy_panics(&shadow, dst_len);
                }
            }
            Operation::GetU8 => {
                if shadow.remaining() >= 1 {
                    let actual_value = actual.get_u8();
                    let expected_value = shadow.get_u8();
                    assert_eq!(
                        actual_value, expected_value,
                        "get_u8 diverged from the shadow model"
                    );
                } else {
                    assert_get_u8_panics(&shadow);
                }
            }
            Operation::GetU16 => {
                if shadow.remaining() >= 2 {
                    let actual_value = actual.get_u16();
                    let expected_value = shadow.get_u16();
                    assert_eq!(
                        actual_value, expected_value,
                        "get_u16 diverged from the shadow model"
                    );
                } else {
                    assert_get_u16_panics(&shadow);
                }
            }
            Operation::SetLimit(limit) => {
                actual.set_limit(limit);
                shadow.set_limit(limit);
            }
            Operation::OversizedAdvance(extra) => {
                let amount = shadow.remaining().saturating_add(1 + extra);
                assert_advance_panics(&shadow, amount);
            }
            Operation::OversizedCopy(extra) => {
                let dst_len = shadow.remaining().saturating_add(1 + extra);
                assert_copy_panics(&shadow, dst_len);
            }
        }

        validate_state(&actual, &shadow);
    }

    let inner = actual.into_inner();
    assert_eq!(
        inner,
        shadow.unread(),
        "into_inner exposed bytes inconsistent with the shadow model"
    );
}

fn validate_state<T: Buf>(actual: &asupersync::bytes::buf::Take<T>, shadow: &ShadowTake) {
    assert_eq!(
        actual.remaining(),
        shadow.remaining(),
        "remaining() diverged from the shadow model"
    );
    assert_eq!(
        actual.limit(),
        shadow.limit,
        "limit() diverged from the shadow model"
    );
    assert_eq!(
        actual.chunk(),
        shadow.chunk(),
        "chunk() exposed bytes past the expected read window"
    );
}

fn assert_advance_panics(shadow: &ShadowTake, amount: usize) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let unread = shadow.unread();
        let mut temp = unread.take(shadow.limit);
        temp.advance(amount);
    }));
    assert!(
        result.is_err(),
        "advance({amount}) with remaining={} should panic",
        shadow.remaining()
    );
}

fn assert_copy_panics(shadow: &ShadowTake, dst_len: usize) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let unread = shadow.unread();
        let mut temp = unread.take(shadow.limit);
        let mut dst = vec![0u8; dst_len];
        temp.copy_to_slice(&mut dst);
    }));
    assert!(
        result.is_err(),
        "copy_to_slice({dst_len}) with remaining={} should panic",
        shadow.remaining()
    );
}

fn assert_get_u8_panics(shadow: &ShadowTake) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let unread = shadow.unread();
        let mut temp = unread.take(shadow.limit);
        let _ = temp.get_u8();
    }));
    assert!(
        result.is_err(),
        "get_u8 with remaining={} should panic",
        shadow.remaining()
    );
}

fn assert_get_u16_panics(shadow: &ShadowTake) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let unread = shadow.unread();
        let mut temp = unread.take(shadow.limit);
        let _ = temp.get_u16();
    }));
    assert!(
        result.is_err(),
        "get_u16 with remaining={} should panic",
        shadow.remaining()
    );
}

fn parse_input(data: &[u8]) -> ParsedInput {
    let text = String::from_utf8_lossy(data);
    let mut source = Vec::new();
    let mut initial_limit = 0usize;
    let mut operations = Vec::new();

    for line in text.lines().take(MAX_OPS + 4) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("DATA:") {
            source.extend_from_slice(rest.as_bytes());
            source.truncate(MAX_SOURCE_LEN);
            continue;
        }

        if let Some(rest) = line.strip_prefix("LIMIT:") {
            initial_limit = parse_num(rest, MAX_LIMIT);
            continue;
        }

        if line == "CHECK" {
            operations.push(Operation::Check);
            continue;
        }

        if line == "GET8" {
            operations.push(Operation::GetU8);
            continue;
        }

        if line == "GET16" {
            operations.push(Operation::GetU16);
            continue;
        }

        if let Some(rest) = line.strip_prefix("ADV:") {
            operations.push(Operation::Advance(parse_num(rest, MAX_LIMIT)));
            continue;
        }

        if let Some(rest) = line.strip_prefix("COPY:") {
            operations.push(Operation::Copy(parse_num(rest, MAX_LIMIT)));
            continue;
        }

        if let Some(rest) = line.strip_prefix("SET:") {
            operations.push(Operation::SetLimit(parse_num(rest, MAX_LIMIT)));
            continue;
        }

        if let Some(rest) = line.strip_prefix("XADV:") {
            operations.push(Operation::OversizedAdvance(parse_num(rest, 7)));
            continue;
        }

        if let Some(rest) = line.strip_prefix("XCOPY:") {
            operations.push(Operation::OversizedCopy(parse_num(rest, 7)));
        }
    }

    if source.is_empty() {
        source.extend_from_slice(&data[..data.len().min(MAX_SOURCE_LEN)]);
    }

    if source.is_empty() {
        source.extend_from_slice(b"default-bytes-seed");
    }

    if initial_limit == 0 {
        initial_limit = source.len().min(8);
    }

    if operations.is_empty() {
        operations.push(Operation::Check);
        operations.push(Operation::Copy(source.len().min(initial_limit).min(4)));
        operations.push(Operation::OversizedAdvance(0));
    }

    ParsedInput {
        source,
        initial_limit,
        operations,
    }
}

fn parse_num(text: &str, max: usize) -> usize {
    text.trim()
        .parse::<usize>()
        .ok()
        .unwrap_or(0)
        .min(max)
}
