fn swallowed_serialization(scenario: &serde_json::Value) {
    let _payload = serde_json::to_string(scenario).unwrap_or_default();
}

fn ignored_encode_result(frame: &mut Frame, dst: &mut Vec<u8>) {
    let _ = frame.encode(dst);
}

fn thread_join_fallback(handle: std::thread::JoinHandle<()>) {
    handle.join().unwrap_or(());
}

fn catch_unwind_masks_panic() {
    match std::panic::catch_unwind(|| panic!("setup failed")) {
        Ok(()) => {}
        Err(_) => return,
    }
}

struct Frame;

impl Frame {
    fn encode(&mut self, _dst: &mut Vec<u8>) -> Result<(), ()> {
        Ok(())
    }
}
