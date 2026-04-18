import re

with open("tests/metamorphic/oneshot_race.rs", "r") as f:
    content = f.read()

content = content.replace("tokio::time::sleep", "yield_sleep")

content = re.sub(r'#\[tokio::test\]\nasync fn test_receiver_drop_during_send_commit\(\) {', '#[test]\nfn test_receiver_drop_during_send_commit() {\n    block_on(async {', content)

content = re.sub(r'    assert_eq!\(tracker_data.values_sent\[0\], 42\);\n}', '    assert_eq!(tracker_data.values_sent[0], 42);\n    });\n}', content)

content = re.sub(r'#\[tokio::test\]\nasync fn test_deterministic_ordering_guarantees\(\) {', '#[test]\nfn test_deterministic_ordering_guarantees() {\n    block_on(async {', content)

content = re.sub(r'            "Race exclusivity for scenario: \{scenario:\?\}\"\);\n    }\n}', '            "Race exclusivity for scenario: {scenario:?}");\n    }\n    });\n}', content)

# Add yield_sleep function
yield_sleep_code = """
struct YieldSleep {
    end: std::time::Instant,
}
impl Future for YieldSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if std::time::Instant::now() >= self.end {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
fn yield_sleep(dur: Duration) -> YieldSleep {
    YieldSleep { end: std::time::Instant::now() + dur }
}
"""

content = content.replace("fn block_on<F: Future>(f: F) -> F::Output {", yield_sleep_code + "\nfn block_on<F: Future>(f: F) -> F::Output {")

with open("tests/metamorphic/oneshot_race.rs", "w") as f:
    f.write(content)

