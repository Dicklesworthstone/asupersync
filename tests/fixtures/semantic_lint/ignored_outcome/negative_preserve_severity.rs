fn preserve_severity(outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
        Outcome::Ok(value) => Outcome::Ok(value),
        other => other,
    }
}

fn preserve_join_tuple(cancelled: CancelReason, value: i32) -> (Outcome<i32>, Option<i32>) {
    (Outcome::Cancelled(cancelled), Some(value))
}

fn mixed_test_vector_is_not_a_collapse() -> Vec<Outcome<i32>> {
    vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::timeout())]
}

fn outcome_argument_is_not_ignored_directly() {
    let _ = pipeline_with_final(vec![1, 2], Outcome::Ok(42), 0);
}
