//! Metamorphic tests for stream combinator monad laws.
//!
//! Tests mathematical properties of stream combinators to ensure they satisfy
//! functor and monad laws, along with other algebraic properties like
//! associativity, identity, and composition.

use asupersync::stream::{Stream, StreamExt, iter};
use asupersync::test_utils;
use proptest::prelude::*;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

// ============================================================================
// Test Infrastructure
// ============================================================================

fn noop_waker() -> Waker {
    Waker::noop().clone()
}

fn stream_law_config() -> ProptestConfig {
    ProptestConfig {
        cases: 50,
        max_shrink_iters: 500,
        timeout: 3000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Synchronously collect all items from a stream.
fn collect_stream_sync<S>(stream: S) -> Vec<S::Item>
where
    S: Stream,
{
    let mut items = Vec::new();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut stream = Box::pin(stream);

    loop {
        match stream.as_mut().poll_next(&mut cx) {
            Poll::Ready(Some(item)) => items.push(item),
            Poll::Ready(None) => break,
            Poll::Pending => panic!("Stream returned Pending in test"),
        }
    }
    items
}

/// Helper function to create a flat-map like operation for streams.
/// Since the public API has no `flat_map`, this local helper models the law.
fn flat_map<S, F, Out>(stream: S, f: F) -> FlatMapStream<S, F, Out>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Out,
    Out: Stream + Unpin,
{
    FlatMapStream::new(stream, f)
}

/// A stream that implements flat-map by chaining mapped streams.
struct FlatMapStream<S, F, Out> {
    source: S,
    mapper: F,
    current: Option<Out>,
    done: bool,
}

impl<S, F, Out> FlatMapStream<S, F, Out> {
    fn new(source: S, mapper: F) -> Self {
        Self {
            source,
            mapper,
            current: None,
            done: false,
        }
    }
}

impl<S, F, Out> Unpin for FlatMapStream<S, F, Out> {}

impl<S, F, Out> Stream for FlatMapStream<S, F, Out>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Out,
    Out: Stream + Unpin,
{
    type Item = Out::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.done {
            return Poll::Ready(None);
        }

        loop {
            if let Some(current) = &mut this.current {
                match Pin::new(current).poll_next(cx) {
                    Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                    Poll::Ready(None) => {
                        this.current = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match Pin::new(&mut this.source).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    this.current = Some((this.mapper)(item));
                }
                Poll::Ready(None) => {
                    this.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ============================================================================
// Test Data Generators
// ============================================================================

/// Generate small integer vectors for stream testing.
fn arb_int_vec() -> impl Strategy<Value = Vec<i32>> {
    prop::collection::vec(any::<i32>(), 0..10)
}

/// Generate small integer vectors with constrained values.
fn arb_small_int_vec() -> impl Strategy<Value = Vec<i32>> {
    prop::collection::vec(-10i32..=10, 0..8)
}

/// Generate transformation functions as enum variants.
#[derive(Debug, Clone)]
enum TestFunction {
    Identity,
    Double,
    AddOne,
    Negate,
    Abs,
}

impl TestFunction {
    fn apply(&self, x: i32) -> i32 {
        match self {
            TestFunction::Identity => x,
            TestFunction::Double => x * 2,
            TestFunction::AddOne => x + 1,
            TestFunction::Negate => -x,
            TestFunction::Abs => x.abs(),
        }
    }
}

fn arb_test_function() -> impl Strategy<Value = TestFunction> {
    prop_oneof![
        Just(TestFunction::Identity),
        Just(TestFunction::Double),
        Just(TestFunction::AddOne),
        Just(TestFunction::Negate),
        Just(TestFunction::Abs),
    ]
}

/// Generate predicates for filter operations.
#[derive(Debug, Clone)]
enum TestPredicate {
    IsEven,
    IsPositive,
    IsNonZero,
    AlwaysTrue,
    AlwaysFalse,
}

impl TestPredicate {
    fn apply(&self, x: &i32) -> bool {
        match self {
            TestPredicate::IsEven => *x % 2 == 0,
            TestPredicate::IsPositive => *x > 0,
            TestPredicate::IsNonZero => *x != 0,
            TestPredicate::AlwaysTrue => true,
            TestPredicate::AlwaysFalse => false,
        }
    }
}

fn arb_test_predicate() -> impl Strategy<Value = TestPredicate> {
    prop_oneof![
        Just(TestPredicate::IsEven),
        Just(TestPredicate::IsPositive),
        Just(TestPredicate::IsNonZero),
        Just(TestPredicate::AlwaysTrue),
        Just(TestPredicate::AlwaysFalse),
    ]
}

// ============================================================================
// Metamorphic Relations - Functor Laws
// ============================================================================

/// MR1: Functor Identity Law
/// s.map(id) == s
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr1_functor_identity(data in arb_int_vec()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr1_functor_identity");

        let stream1 = iter(data.clone());
        let stream2 = iter(data).map(|x| x);

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Functor identity law violated: s.map(id) ≠ s");

        asupersync::test_complete!("mr1_functor_identity");
    }
}

/// MR2: Functor Composition Law
/// s.map(f).map(g) == s.map(|x| g(f(x)))
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr2_functor_composition(
        data in arb_small_int_vec(),
        f in arb_test_function(),
        g in arb_test_function()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr2_functor_composition");

        let stream1 = iter(data.clone()).map(|x| f.apply(x)).map(|x| g.apply(x));
        let stream2 = iter(data).map(|x| g.apply(f.apply(x)));

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Functor composition law violated: s.map(f).map(g) ≠ s.map(g∘f)");

        asupersync::test_complete!("mr2_functor_composition");
    }
}

// ============================================================================
// Metamorphic Relations - Monad Laws (using flat_map simulation)
// ============================================================================

/// MR3: Left Identity Law (simplified for streams)
/// iter([a]).then(f) behaves like f(a)
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr3_left_identity(
        value in -1000i32..=1000,
        multiplier in 1i32..=5
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr3_left_identity");

        // Create function that maps value to a small stream
        let f = |x: i32| iter(0..multiplier).map(move |i| x + i);

        let left = collect_stream_sync(flat_map(iter(vec![value]), f));
        let right = collect_stream_sync(f(value));

        prop_assert_eq!(left, right,
            "Left identity law violated: iter([a]).then(f) ≠ f(a)");

        asupersync::test_complete!("mr3_left_identity");
    }
}

/// MR4: Right Identity Law (simplified)
/// s.then(|x| iter([x])) == s
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr4_right_identity(data in arb_int_vec()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr4_right_identity");

        let stream1 = iter(data.clone());
        let stream2 = iter(data).then(|x| async move { x });

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Right identity law violated: s.then(unit) ≠ s");

        asupersync::test_complete!("mr4_right_identity");
    }
}

// ============================================================================
// Metamorphic Relations - Chain Laws
// ============================================================================

/// MR5: Chain Associativity
/// (s1.chain(s2)).chain(s3) == s1.chain(s2.chain(s3))
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr5_chain_associativity(
        data1 in arb_small_int_vec(),
        data2 in arb_small_int_vec(),
        data3 in arb_small_int_vec()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr5_chain_associativity");

        let left = iter(data1.clone()).chain(iter(data2.clone())).chain(iter(data3.clone()));
        let right = iter(data1).chain(iter(data2).chain(iter(data3)));

        let result1 = collect_stream_sync(left);
        let result2 = collect_stream_sync(right);

        prop_assert_eq!(result1, result2,
            "Chain associativity violated: (s1⋅s2)⋅s3 ≠ s1⋅(s2⋅s3)");

        asupersync::test_complete!("mr5_chain_associativity");
    }
}

/// MR6: Chain Identity (Empty Stream)
/// s.chain(empty) == s and empty.chain(s) == s
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr6_chain_identity(data in arb_int_vec()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr6_chain_identity");

        let stream1 = iter(data.clone());
        let stream2 = iter(data.clone()).chain(iter(Vec::<i32>::new()));
        let stream3 = iter(Vec::<i32>::new()).chain(iter(data));

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);
        let result3 = collect_stream_sync(stream3);

        prop_assert_eq!(&result1, &result2,
            "Right chain identity violated: s⋅ε ≠ s");
        prop_assert_eq!(&result1, &result3,
            "Left chain identity violated: ε⋅s ≠ s");

        asupersync::test_complete!("mr6_chain_identity");
    }
}

// ============================================================================
// Metamorphic Relations - Filter Laws
// ============================================================================

/// MR7: Filter Composition
/// s.filter(p1).filter(p2) == s.filter(|x| p1(x) && p2(x))
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr7_filter_composition(
        data in arb_small_int_vec(),
        p1 in arb_test_predicate(),
        p2 in arb_test_predicate()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr7_filter_composition");

        let stream1 = iter(data.clone()).filter(|x| p1.apply(x)).filter(|x| p2.apply(x));
        let stream2 = iter(data).filter(|x| p1.apply(x) && p2.apply(x));

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Filter composition law violated: s.filter(p1).filter(p2) ≠ s.filter(p1∧p2)");

        asupersync::test_complete!("mr7_filter_composition");
    }
}

/// MR8: Filter Identity
/// s.filter(always_true) == s
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr8_filter_identity(data in arb_int_vec()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr8_filter_identity");

        let stream1 = iter(data.clone());
        let stream2 = iter(data).filter(|_| true);

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Filter identity law violated: s.filter(⊤) ≠ s");

        asupersync::test_complete!("mr8_filter_identity");
    }
}

/// MR9: Filter Annihilation
/// s.filter(always_false) == empty
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr9_filter_annihilation(data in arb_int_vec()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr9_filter_annihilation");

        let stream = iter(data).filter(|_| false);
        let result = collect_stream_sync(stream);

        prop_assert_eq!(result, Vec::<i32>::new(),
            "Filter annihilation law violated: s.filter(⊥) ≠ ε");

        asupersync::test_complete!("mr9_filter_annihilation");
    }
}

// ============================================================================
// Metamorphic Relations - Take/Skip Laws
// ============================================================================

/// MR10: Take/Skip Duality
/// s.take(n).chain(s.skip(n)) == s (for deterministic streams)
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr10_take_skip_duality(
        data in arb_small_int_vec(),
        n in 0usize..8
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr10_take_skip_duality");

        let stream1 = iter(data.clone());
        let stream2 = iter(data.clone()).take(n).chain(iter(data).skip(n));

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Take/skip duality violated: s ≠ s.take(n)⋅s.skip(n)");

        asupersync::test_complete!("mr10_take_skip_duality");
    }
}

/// MR11: Take Idempotence
/// s.take(n).take(m) == s.take(min(n, m))
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr11_take_idempotence(
        data in arb_small_int_vec(),
        n in 0usize..8,
        m in 0usize..8
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr11_take_idempotence");

        let stream1 = iter(data.clone()).take(n).take(m);
        let stream2 = iter(data).take(n.min(m));

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Take idempotence violated: s.take({}).take({}) ≠ s.take({})", n, m, n.min(m));

        asupersync::test_complete!("mr11_take_idempotence");
    }
}

/// MR12: Skip Composition
/// s.skip(n).skip(m) == s.skip(n + m)
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr12_skip_composition(
        data in arb_small_int_vec(),
        n in 0usize..5,
        m in 0usize..5
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr12_skip_composition");

        let stream1 = iter(data.clone()).skip(n).skip(m);
        let stream2 = iter(data).skip(n + m);

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Skip composition violated: s.skip({}).skip({}) ≠ s.skip({})", n, m, n + m);

        asupersync::test_complete!("mr12_skip_composition");
    }
}

// ============================================================================
// Metamorphic Relations - Map/Filter Interaction Laws
// ============================================================================

/// MR13: Map/Filter Commutativity (when safe)
/// s.map(f).filter(p) == s.filter(|x| p(&f(x))).map(f) (if f is injective and p is compatible)
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr13_map_filter_interaction(data in arb_small_int_vec()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr13_map_filter_interaction");

        // Use simple transformations that preserve the filtering property
        let double = |x: i32| x * 2;
        let is_even = |x: &i32| *x % 2 == 0;

        let stream1 = iter(data.clone()).map(double).filter(is_even);
        let stream2 = iter(data).filter(|x| (x * 2) % 2 == 0).map(double);

        let result1 = collect_stream_sync(stream1);
        let result2 = collect_stream_sync(stream2);

        prop_assert_eq!(result1, result2,
            "Map/filter interaction violated for even predicate on doubling");

        asupersync::test_complete!("mr13_map_filter_interaction");
    }
}

// ============================================================================
// Metamorphic Relations - Fold Laws
// ============================================================================

/// MR14: Fold Associativity (for associative operations)
/// s.fold(init, op) where op is associative should be consistent
proptest! {
    #![proptest_config(stream_law_config())]

    #[test]
    fn mr14_fold_sum_associativity(data in arb_small_int_vec()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr14_fold_sum_associativity");

        // Test that folding with addition gives the same result as summing
        let stream_fold = iter(data.clone()).fold(0, |acc, x| acc + x);
        let expected_sum = data.iter().sum::<i32>();

        let result = futures_lite::future::block_on(async {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut fold_future = stream_fold;

            match Pin::new(&mut fold_future).poll(&mut cx) {
                Poll::Ready(sum) => sum,
                Poll::Pending => panic!("Fold returned Pending in test"),
            }
        });

        prop_assert_eq!(result, expected_sum,
            "Fold sum should equal iterator sum");

        asupersync::test_complete!("mr14_fold_sum_associativity");
    }
}

/// MR15: Empty Stream Laws
/// Operations on empty streams should behave consistently
#[test]
fn mr15_empty_stream_laws() {
    test_utils::init_test_logging();
    asupersync::test_phase!("mr15_empty_stream_laws");

    let empty_stream: Vec<i32> = Vec::new();

    // Map on empty is empty
    let mapped = collect_stream_sync(iter(empty_stream.clone()).map(|x| x * 2));
    assert_eq!(mapped, Vec::<i32>::new());

    // Filter on empty is empty
    let filtered = collect_stream_sync(iter(empty_stream.clone()).filter(|&x| x > 0));
    assert_eq!(filtered, Vec::<i32>::new());

    // Take on empty is empty
    let taken = collect_stream_sync(iter(empty_stream.clone()).take(5));
    assert_eq!(taken, Vec::<i32>::new());

    // Skip on empty is empty
    let skipped = collect_stream_sync(iter(empty_stream).skip(3));
    assert_eq!(skipped, Vec::<i32>::new());

    asupersync::test_complete!("mr15_empty_stream_laws");
}
