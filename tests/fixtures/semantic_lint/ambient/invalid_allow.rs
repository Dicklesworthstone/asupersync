fn missing_owner_does_not_suppress() {
    // asupersync-lint:allow ambient-time-or-entropy-in-lab-sensitive-code reason=operator-diagnostic
    let _snapshot = std::time::SystemTime::now();
}
