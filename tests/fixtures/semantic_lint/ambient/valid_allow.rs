fn operator_diagnostic_clock() {
    // asupersync-lint:allow ambient-time-or-entropy-in-lab-sensitive-code reason=operator-diagnostic owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
    let _snapshot = std::time::SystemTime::now();
}
