fn preserve_severity(outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
        Outcome::Ok(value) => Outcome::Ok(value),
        other => other,
    }
}
