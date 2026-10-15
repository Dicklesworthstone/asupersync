#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{BufMut, BytesMut};
use libfuzzer_sys::fuzz_target;

const MAX_INITIAL_LEN: usize = 64 * 1024;
const MAX_PUT_LEN: usize = 16 * 1024;
const MAX_RESERVE: usize = 1 << 20;

#[derive(Debug, Clone, Arbitrary)]
struct BoundaryProgram {
    initial: Vec<u8>,
    ops: Vec<BoundaryOp>,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryOp {
    Reserve { additional: usize },
    SplitOff { at: usize },
    SplitTo { at: usize },
    AdvanceMut { cnt: usize },
    PutSlice { data: Vec<u8> },
    Truncate { len: usize },
    Clear,
    FreezeRoundTrip,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(program) = BoundaryProgram::arbitrary(&mut unstructured) else {
        return;
    };

    let initial_len = program.initial.len().min(MAX_INITIAL_LEN);
    let initial = &program.initial[..initial_len];
    let mut buf = BytesMut::from(initial);
    let mut model = initial.to_vec();

    for op in program.ops {
        apply_op(&mut buf, &mut model, op);
    }

    assert_eq!(buf.as_ref(), model.as_slice());
});

fn apply_op(buf: &mut BytesMut, model: &mut Vec<u8>, op: BoundaryOp) {
    match op {
        BoundaryOp::Reserve { additional } => {
            let additional = additional.min(MAX_RESERVE);
            let before = model.clone();
            let old_capacity = buf.capacity();
            buf.reserve(additional);
            assert_eq!(buf.as_ref(), before.as_slice());
            assert!(buf.capacity() >= old_capacity);
            assert!(buf.capacity() >= buf.len());
        }
        BoundaryOp::SplitOff { at } => {
            let before_buf = buf.clone();
            let before_model = model.clone();
            let result = catch_unwind(AssertUnwindSafe(|| buf.split_off(at)));

            if at <= before_model.len() {
                let tail = result.expect("split_off should succeed in bounds");
                let expected_tail = before_model[at..].to_vec();
                let expected_head = before_model[..at].to_vec();
                assert_eq!(tail.as_ref(), expected_tail.as_slice());
                assert_eq!(buf.as_ref(), expected_head.as_slice());
                let mut reconstructed = expected_head.clone();
                reconstructed.extend_from_slice(&expected_tail);
                assert_eq!(reconstructed, before_model);
                *model = expected_head;
            } else {
                assert!(result.is_err());
                assert_eq!(buf.as_ref(), before_buf.as_ref());
                assert_eq!(model.as_slice(), before_model.as_slice());
            }
        }
        BoundaryOp::SplitTo { at } => {
            let before_buf = buf.clone();
            let before_model = model.clone();
            let result = catch_unwind(AssertUnwindSafe(|| buf.split_to(at)));

            if at <= before_model.len() {
                let head = result.expect("split_to should succeed in bounds");
                let expected_head = before_model[..at].to_vec();
                let expected_tail = before_model[at..].to_vec();
                assert_eq!(head.as_ref(), expected_head.as_slice());
                assert_eq!(buf.as_ref(), expected_tail.as_slice());
                let mut reconstructed = expected_head.clone();
                reconstructed.extend_from_slice(&expected_tail);
                assert_eq!(reconstructed, before_model);
                *model = expected_tail;
            } else {
                assert!(result.is_err());
                assert_eq!(buf.as_ref(), before_buf.as_ref());
                assert_eq!(model.as_slice(), before_model.as_slice());
            }
        }
        BoundaryOp::AdvanceMut { cnt } => {
            let before_buf = buf.clone();
            let before_model = model.clone();
            let result = catch_unwind(AssertUnwindSafe(|| BufMut::advance_mut(buf, cnt)));

            if cnt == 0 {
                result.expect("advance_mut(0) should succeed");
            } else {
                assert!(result.is_err());
            }

            assert_eq!(buf.as_ref(), before_buf.as_ref());
            assert_eq!(model.as_slice(), before_model.as_slice());
        }
        BoundaryOp::PutSlice { data } => {
            let len = data.len().min(MAX_PUT_LEN);
            let data = &data[..len];
            buf.put_slice(data);
            model.extend_from_slice(data);
            assert_eq!(buf.as_ref(), model.as_slice());
        }
        BoundaryOp::Truncate { len } => {
            buf.truncate(len);
            model.truncate(len);
            assert_eq!(buf.as_ref(), model.as_slice());
        }
        BoundaryOp::Clear => {
            buf.clear();
            model.clear();
            assert!(buf.is_empty());
            assert!(model.is_empty());
        }
        BoundaryOp::FreezeRoundTrip => {
            let frozen = buf.clone().freeze();
            assert_eq!(frozen.as_ref(), model.as_slice());

            let rebuilt = BytesMut::from(frozen.as_ref());
            assert_eq!(rebuilt.as_ref(), model.as_slice());
            *buf = rebuilt;
        }
    }
}
