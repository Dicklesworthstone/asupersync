//! Immutable `Bytes` slicing and split invariants fuzz target.
//!
//! This harness focuses on the zero-copy view semantics in `src/bytes/bytes.rs`.
//! It exercises cheap clones, slicing, and front/back partition operations
//! against a simple shadow model so the fuzzer can validate both content and
//! pointer movement without needing access to internal fields.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::Bytes;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    source: Source,
    operations: Vec<Operation>,
}

#[derive(Debug, Clone, Arbitrary)]
enum Source {
    StaticFixture { fixture: Fixture },
    Copied { data: Vec<u8> },
    FromVec { data: Vec<u8> },
    FromString { text: String },
}

#[derive(Debug, Clone, Arbitrary)]
enum Fixture {
    Empty,
    Greeting,
    Binary,
    Repeated,
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    CloneView { index: u8 },
    Slice { index: u8, start: u16, end: u16 },
    SliceFrom { index: u8, start: u16 },
    SliceTo { index: u8, end: u16 },
    SplitTo { index: u8, at: u16 },
    SplitOff { index: u8, at: u16 },
    Truncate { index: u8, len: u16 },
    Clear { index: u8 },
    CompareClone { index: u8 },
    RebuildPair { left: u8, right: u8 },
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    if input.operations.is_empty() {
        return;
    }

    run_input(input);
});

fn run_input(input: FuzzInput) {
    let initial = build_source(input.source);
    let mut views = vec![initial.clone()];
    let mut shadows = vec![initial.as_ref().to_vec()];

    validate_pool(&views, &shadows);

    for operation in input.operations.into_iter().take(64) {
        execute_operation(operation, &mut views, &mut shadows);
        validate_pool(&views, &shadows);
    }
}

fn build_source(source: Source) -> Bytes {
    match source {
        Source::StaticFixture { fixture } => match fixture {
            Fixture::Empty => Bytes::from_static(b""),
            Fixture::Greeting => Bytes::from_static(b"hello bytes world"),
            Fixture::Binary => Bytes::from_static(b"\x00\x01\x7f\x80\xfe\xffsplit"),
            Fixture::Repeated => Bytes::from_static(b"abcabcabcabcabcabc"),
        },
        Source::Copied { data } => Bytes::copy_from_slice(&limit_vec(data)),
        Source::FromVec { data } => Bytes::from(limit_vec(data)),
        Source::FromString { text } => Bytes::from(limit_string(text)),
    }
}

fn execute_operation(operation: Operation, views: &mut Vec<Bytes>, shadows: &mut Vec<Vec<u8>>) {
    if views.is_empty() {
        views.push(Bytes::new());
        shadows.push(Vec::new());
    }

    match operation {
        Operation::CloneView { index } => {
            let idx = select_index(index, views.len());
            let cloned = views[idx].clone();
            if !cloned.is_empty() {
                assert_eq!(cloned.as_ptr(), views[idx].as_ptr());
            }
            views.push(cloned);
            shadows.push(shadows[idx].clone());
        }
        Operation::Slice { index, start, end } => {
            let idx = select_index(index, views.len());
            let len = views[idx].len();
            let (start, end) = normalized_range(len, start, end);
            let sliced = views[idx].slice(start..end);
            let expected = shadows[idx][start..end].to_vec();
            if !sliced.is_empty() {
                assert_eq!(sliced.as_ptr(), views[idx].as_ptr().wrapping_add(start));
            }
            views.push(sliced);
            shadows.push(expected);
        }
        Operation::SliceFrom { index, start } => {
            let idx = select_index(index, views.len());
            let len = views[idx].len();
            let start = normalized_index(len, start);
            let sliced = views[idx].slice(start..);
            let expected = shadows[idx][start..].to_vec();
            if !sliced.is_empty() {
                assert_eq!(sliced.as_ptr(), views[idx].as_ptr().wrapping_add(start));
            }
            views.push(sliced);
            shadows.push(expected);
        }
        Operation::SliceTo { index, end } => {
            let idx = select_index(index, views.len());
            let len = views[idx].len();
            let end = normalized_index(len, end);
            let sliced = views[idx].slice(..end);
            let expected = shadows[idx][..end].to_vec();
            if !sliced.is_empty() {
                assert_eq!(sliced.as_ptr(), views[idx].as_ptr());
            }
            views.push(sliced);
            shadows.push(expected);
        }
        Operation::SplitTo { index, at } => {
            let idx = select_index(index, views.len());
            let len = views[idx].len();
            let at = normalized_index(len, at);
            let original_ptr = views[idx].as_ptr();
            let original_shadow = shadows[idx].clone();
            let head = views[idx].split_to(at);
            let tail_shadow = original_shadow[at..].to_vec();
            let head_shadow = original_shadow[..at].to_vec();
            assert_eq!(head.as_ref(), head_shadow.as_slice());
            assert_eq!(views[idx].as_ref(), tail_shadow.as_slice());
            if !head.is_empty() {
                assert_eq!(head.as_ptr(), original_ptr);
            }
            if !views[idx].is_empty() {
                assert_eq!(views[idx].as_ptr(), original_ptr.wrapping_add(at));
            }
            let reconstructed = concat_bytes(&head, &views[idx]);
            assert_eq!(reconstructed, original_shadow);
            views.push(head);
            shadows[idx] = tail_shadow;
            shadows.push(head_shadow);
        }
        Operation::SplitOff { index, at } => {
            let idx = select_index(index, views.len());
            let len = views[idx].len();
            let at = normalized_index(len, at);
            let original_ptr = views[idx].as_ptr();
            let original_shadow = shadows[idx].clone();
            let tail = views[idx].split_off(at);
            let head_shadow = original_shadow[..at].to_vec();
            let tail_shadow = original_shadow[at..].to_vec();
            assert_eq!(views[idx].as_ref(), head_shadow.as_slice());
            assert_eq!(tail.as_ref(), tail_shadow.as_slice());
            if !views[idx].is_empty() {
                assert_eq!(views[idx].as_ptr(), original_ptr);
            }
            if !tail.is_empty() {
                assert_eq!(tail.as_ptr(), original_ptr.wrapping_add(at));
            }
            let reconstructed = concat_bytes(&views[idx], &tail);
            assert_eq!(reconstructed, original_shadow);
            views.push(tail);
            shadows[idx] = head_shadow;
            shadows.push(tail_shadow);
        }
        Operation::Truncate { index, len } => {
            let idx = select_index(index, views.len());
            let new_len = normalized_index(views[idx].len(), len);
            let original_ptr = views[idx].as_ptr();
            views[idx].truncate(new_len);
            shadows[idx].truncate(new_len);
            assert_eq!(views[idx].as_ref(), shadows[idx].as_slice());
            if !views[idx].is_empty() {
                assert_eq!(views[idx].as_ptr(), original_ptr);
            }
        }
        Operation::Clear { index } => {
            let idx = select_index(index, views.len());
            views[idx].clear();
            shadows[idx].clear();
            assert!(views[idx].is_empty());
        }
        Operation::CompareClone { index } => {
            let idx = select_index(index, views.len());
            let cloned = views[idx].clone();
            assert_eq!(cloned, views[idx]);
            assert_eq!(cloned.as_ref(), shadows[idx].as_slice());
            if !cloned.is_empty() {
                assert_eq!(cloned.as_ptr(), views[idx].as_ptr());
            }
        }
        Operation::RebuildPair { left, right } => {
            let left_idx = select_index(left, views.len());
            let right_idx = select_index(right, views.len());
            let rebuilt = concat_bytes(&views[left_idx], &views[right_idx]);
            let mut expected = shadows[left_idx].clone();
            expected.extend_from_slice(&shadows[right_idx]);
            assert_eq!(rebuilt, expected);
        }
    }
}

fn validate_pool(views: &[Bytes], shadows: &[Vec<u8>]) {
    assert_eq!(views.len(), shadows.len());
    for (view, shadow) in views.iter().zip(shadows.iter()) {
        assert_eq!(view.len(), shadow.len());
        assert_eq!(view.as_ref(), shadow.as_slice());
        if let Some(first) = shadow.first() {
            assert_eq!(view.as_ref()[0], *first);
        }
        if let Some(last) = shadow.last() {
            assert_eq!(view.as_ref()[view.len() - 1], *last);
        }
    }
}

fn concat_bytes(left: &Bytes, right: &Bytes) -> Vec<u8> {
    let mut combined = Vec::with_capacity(left.len() + right.len());
    combined.extend_from_slice(left.as_ref());
    combined.extend_from_slice(right.as_ref());
    combined
}

fn select_index(index: u8, len: usize) -> usize {
    (index as usize) % len.max(1)
}

fn normalized_index(len: usize, raw: u16) -> usize {
    if len == 0 {
        0
    } else {
        (raw as usize) % (len + 1)
    }
}

fn normalized_range(len: usize, start: u16, end: u16) -> (usize, usize) {
    let a = normalized_index(len, start);
    let b = normalized_index(len, end);
    if a <= b { (a, b) } else { (b, a) }
}

fn limit_vec(mut data: Vec<u8>) -> Vec<u8> {
    data.truncate(512);
    data
}

fn limit_string(mut text: String) -> String {
    text.truncate(512);
    text
}
