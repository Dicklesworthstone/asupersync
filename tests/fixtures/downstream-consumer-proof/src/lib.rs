use asupersync::{Budget, Outcome, Time};

pub fn public_surface_smoke_value() -> u64 {
    let deadline = Time::from_secs(2);
    let budget = Budget::new()
        .with_deadline(deadline)
        .with_poll_quota(8)
        .with_cost_quota(13)
        .with_priority(200);
    let outcome: Outcome<u64, &str> = Outcome::ok(
        budget
            .deadline
            .expect("downstream proof sets a deadline")
            .as_secs(),
    );

    assert!(outcome.is_ok());
    assert_eq!(budget.deadline, Some(deadline));
    assert_eq!(budget.poll_quota, 8);
    assert_eq!(budget.cost_quota, Some(13));
    assert_eq!(budget.priority, 200);

    outcome.unwrap()
}
