fn collapse_cancelled(outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Cancelled(_) => Outcome::Ok(()),
        other => other,
    }
}
