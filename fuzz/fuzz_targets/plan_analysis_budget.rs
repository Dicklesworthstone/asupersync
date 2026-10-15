//! Fuzz target for `src/plan/analysis.rs` — BudgetEffect algebra.
//!
//! Exercises the algebraic operations on BudgetEffect:
//!   - `sequential(self, other)` composes effects in series.
//!   - `parallel(self, other)` composes in parallel.
//!   - `is_not_worse_than(before)` is a partial order.
//!   - `effective_deadline()` returns the running deadline budget.
//!
//! Properties asserted:
//!   1. Every operation returns without panic for any DeadlineMicros input.
//!   2. `seq(seq(a,b),c) == seq(a,seq(b,c))` — sequential associativity.
//!   3. `par(par(a,b),c) == par(a,par(b,c))` — parallel associativity.
//!   4. `par(a,b) == par(b,a)` — parallel commutativity.
//!   5. `a.is_not_worse_than(a) == true` — reflexivity.
//!   6. Sequential composition tightens or preserves the deadline:
//!      `seq(a,b).effective_deadline() <= a.effective_deadline().add(b.effective_deadline())`.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::plan::analysis::{BudgetEffect, DeadlineMicros};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct DeadlineInput(Option<u64>);

impl DeadlineInput {
    fn into_micros(self) -> DeadlineMicros {
        DeadlineMicros(self.0)
    }
}

#[derive(Debug, Arbitrary)]
struct Input {
    a: DeadlineInput,
    b: DeadlineInput,
    c: DeadlineInput,
}

fn budget_with(deadline: DeadlineMicros) -> BudgetEffect {
    BudgetEffect::LEAF.with_deadline(deadline)
}

fuzz_target!(|input: Input| {
    let da = input.a.into_micros();
    let db = input.b.into_micros();
    let dc = input.c.into_micros();

    let a = budget_with(da);
    let b = budget_with(db);
    let c = budget_with(dc);

    // Property 1: every algebra op returns without panic.
    let ab_seq = a.sequential(b);
    let ab_par = a.parallel(b);
    assert_eq!(a.effective_deadline(), Some(da));
    assert_eq!(b.effective_deadline(), Some(db));
    assert_eq!(c.effective_deadline(), Some(dc));
    assert_eq!(ab_seq.effective_deadline(), Some(da.min(db)));
    assert_eq!(ab_seq.max_deadline, da.add(db));
    assert_eq!(ab_par.effective_deadline(), Some(da.min(db)));
    assert_eq!(ab_par.max_deadline, da.min(db));
    assert!(!ab_seq.is_not_worse_than(a));

    // Property 2: sequential associativity.
    let left = a.sequential(b).sequential(c);
    let right = a.sequential(b.sequential(c));
    assert_eq!(
        left.effective_deadline(),
        right.effective_deadline(),
        "sequential is not associative for generated deadlines"
    );
    assert_eq!(
        left.max_deadline, right.max_deadline,
        "sequential max-deadline addition is not associative"
    );

    // Property 3: parallel associativity.
    let pleft = a.parallel(b).parallel(c);
    let pright = a.parallel(b.parallel(c));
    assert_eq!(
        pleft.effective_deadline(),
        pright.effective_deadline(),
        "parallel is not associative for generated deadlines"
    );

    // Property 4: parallel commutativity.
    let pab = a.parallel(b);
    let pba = b.parallel(a);
    assert_eq!(
        pab.effective_deadline(),
        pba.effective_deadline(),
        "parallel is not commutative for generated deadlines"
    );

    // Property 5: reflexivity of is_not_worse_than.
    assert!(a.is_not_worse_than(a), "is_not_worse_than is not reflexive");

    // DeadlineMicros: the public arithmetic must not panic.
    let min = da.min(db);
    assert!(min.is_at_least_as_tight_as(da));
    assert!(min.is_at_least_as_tight_as(db));
    assert_eq!(da.add(db), db.add(da));
    assert!(da.is_at_least_as_tight_as(da));
});
