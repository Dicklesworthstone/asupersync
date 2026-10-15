//! `BytesCursor` and `reader()` state-machine fuzz target.
//!
//! This target focuses on `src/bytes/bytes.rs` cursor semantics instead of the
//! generic `Buf` trait alone. It builds derived `Bytes` views, spawns cursors
//! over them, and checks `position`, `remaining`, `chunk`, `advance`,
//! `copy_to_slice`, `get_u8`, `get_ref`, and `into_inner` against a shadow
//! model.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{Buf, Bytes, BytesCursor};
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
    SliceView { index: u8, start: u16, end: u16 },
    SpawnCursor { view_index: u8, use_reader: bool },
    CloneCursor { cursor_index: u8 },
    SetPosition { cursor_index: u8, position: u16 },
    Advance { cursor_index: u8, amount: u16 },
    GetU8 { cursor_index: u8 },
    CopyToSlice { cursor_index: u8, len: u16 },
    CheckChunk { cursor_index: u8 },
    CheckIntoInner { cursor_index: u8 },
}

#[derive(Debug, Clone)]
struct CursorShadow {
    view_index: usize,
    position: usize,
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
    let mut view_shadows = vec![initial.as_ref().to_vec()];
    let mut cursors = vec![initial.clone().reader()];
    let mut cursor_shadows = vec![CursorShadow {
        view_index: 0,
        position: 0,
    }];

    validate_state(&views, &view_shadows, &cursors, &cursor_shadows);

    for operation in input.operations.into_iter().take(96) {
        execute_operation(
            operation,
            &mut views,
            &mut view_shadows,
            &mut cursors,
            &mut cursor_shadows,
        );
        validate_state(&views, &view_shadows, &cursors, &cursor_shadows);
    }
}

fn build_source(source: Source) -> Bytes {
    match source {
        Source::StaticFixture { fixture } => match fixture {
            Fixture::Empty => Bytes::from_static(b""),
            Fixture::Greeting => Bytes::from_static(b"cursor bytes reader"),
            Fixture::Binary => Bytes::from_static(b"\x00\x01\x7f\x80\xfe\xffreader"),
            Fixture::Repeated => Bytes::from_static(b"xyzxyzxyzxyzxyzxyz"),
        },
        Source::Copied { data } => Bytes::copy_from_slice(&limit_vec(data)),
        Source::FromVec { data } => Bytes::from(limit_vec(data)),
        Source::FromString { text } => Bytes::from(limit_string(text)),
    }
}

fn execute_operation(
    operation: Operation,
    views: &mut Vec<Bytes>,
    view_shadows: &mut Vec<Vec<u8>>,
    cursors: &mut Vec<BytesCursor>,
    cursor_shadows: &mut Vec<CursorShadow>,
) {
    match operation {
        Operation::CloneView { index } => {
            let idx = select_index(index, views.len());
            let cloned = views[idx].clone();
            if !cloned.is_empty() {
                assert_eq!(cloned.as_ptr(), views[idx].as_ptr());
            }
            views.push(cloned);
            view_shadows.push(view_shadows[idx].clone());
        }
        Operation::SliceView { index, start, end } => {
            let idx = select_index(index, views.len());
            let len = views[idx].len();
            let (start, end) = normalized_range(len, start, end);
            let sliced = views[idx].slice(start..end);
            let expected = view_shadows[idx][start..end].to_vec();
            if !sliced.is_empty() {
                assert_eq!(sliced.as_ptr(), views[idx].as_ptr().wrapping_add(start));
            }
            views.push(sliced);
            view_shadows.push(expected);
        }
        Operation::SpawnCursor {
            view_index,
            use_reader,
        } => {
            let idx = select_index(view_index, views.len());
            let cursor = if use_reader {
                views[idx].clone().reader()
            } else {
                BytesCursor::new(views[idx].clone())
            };
            cursors.push(cursor);
            cursor_shadows.push(CursorShadow {
                view_index: idx,
                position: 0,
            });
        }
        Operation::CloneCursor { cursor_index } => {
            let idx = select_index(cursor_index, cursors.len());
            let cloned = cursors[idx].clone();
            assert_eq!(cloned.position(), cursor_shadows[idx].position);
            assert_eq!(
                cloned.get_ref().as_ref(),
                view_shadows[cursor_shadows[idx].view_index].as_slice()
            );
            cursors.push(cloned);
            cursor_shadows.push(cursor_shadows[idx].clone());
        }
        Operation::SetPosition {
            cursor_index,
            position,
        } => {
            let idx = select_index(cursor_index, cursors.len());
            let pos = position as usize;
            cursors[idx].set_position(pos);
            cursor_shadows[idx].position = pos;
        }
        Operation::Advance {
            cursor_index,
            amount,
        } => {
            let idx = select_index(cursor_index, cursors.len());
            let remaining = shadow_remaining(
                &view_shadows[cursor_shadows[idx].view_index],
                &cursor_shadows[idx],
            );
            let amount = (amount as usize) % (remaining + 1);
            let before_remaining = cursors[idx].remaining();
            cursors[idx].advance(amount);
            cursor_shadows[idx].position += amount;
            assert_eq!(
                before_remaining.saturating_sub(amount),
                cursors[idx].remaining()
            );
        }
        Operation::GetU8 { cursor_index } => {
            let idx = select_index(cursor_index, cursors.len());
            let shadow = &mut cursor_shadows[idx];
            let source = &view_shadows[shadow.view_index];
            if shadow.position < source.len() {
                let expected = source[shadow.position];
                let actual = cursors[idx].get_u8();
                assert_eq!(actual, expected);
                shadow.position += 1;
            }
        }
        Operation::CopyToSlice { cursor_index, len } => {
            let idx = select_index(cursor_index, cursors.len());
            let shadow = &mut cursor_shadows[idx];
            let source = &view_shadows[shadow.view_index];
            let remaining = source.len().saturating_sub(shadow.position);
            let len = (len as usize) % (remaining + 1);
            let mut dest = vec![0u8; len];
            let expected = source[shadow.position..shadow.position + len].to_vec();
            cursors[idx].copy_to_slice(&mut dest);
            assert_eq!(dest, expected);
            shadow.position += len;
        }
        Operation::CheckChunk { cursor_index } => {
            let idx = select_index(cursor_index, cursors.len());
            let shadow = &cursor_shadows[idx];
            let source = &view_shadows[shadow.view_index];
            let expected = if shadow.position >= source.len() {
                &[][..]
            } else {
                &source[shadow.position..]
            };
            assert_eq!(cursors[idx].chunk(), expected);
        }
        Operation::CheckIntoInner { cursor_index } => {
            let idx = select_index(cursor_index, cursors.len());
            let shadow = &cursor_shadows[idx];
            let cloned = cursors[idx].clone();
            let inner = cloned.into_inner();
            assert_eq!(inner.as_ref(), view_shadows[shadow.view_index].as_slice());
            assert_eq!(cursors[idx].get_ref().as_ref(), inner.as_ref());
        }
    }
}

fn validate_state(
    views: &[Bytes],
    view_shadows: &[Vec<u8>],
    cursors: &[BytesCursor],
    cursor_shadows: &[CursorShadow],
) {
    assert_eq!(views.len(), view_shadows.len());
    assert_eq!(cursors.len(), cursor_shadows.len());

    for (view, shadow) in views.iter().zip(view_shadows.iter()) {
        assert_eq!(view.as_ref(), shadow.as_slice());
        assert_eq!(view.len(), shadow.len());
    }

    for (cursor, shadow) in cursors.iter().zip(cursor_shadows.iter()) {
        let source = &view_shadows[shadow.view_index];
        let expected_remaining = source.len().saturating_sub(shadow.position);
        let expected_chunk = if shadow.position >= source.len() {
            &[][..]
        } else {
            &source[shadow.position..]
        };

        assert_eq!(cursor.get_ref().as_ref(), source.as_slice());
        assert_eq!(cursor.position(), shadow.position);
        assert_eq!(cursor.remaining(), expected_remaining);
        assert_eq!(cursor.chunk(), expected_chunk);
    }
}

fn shadow_remaining(source: &[u8], shadow: &CursorShadow) -> usize {
    source.len().saturating_sub(shadow.position)
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
