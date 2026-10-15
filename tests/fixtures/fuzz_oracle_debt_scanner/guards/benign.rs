fn benign_env_default() {
    let _enabled = std::env::var("FUZZ_ME").unwrap_or_default() == "1";
}

fn benign_arbitrary_shortage(result: Result<u8, ()>) {
    match result {
        Ok(_) => {}
        Err(_) => return,
    }
}

fn explicit_thread_join_assertion(handle: std::thread::JoinHandle<()>) {
    handle.join().expect("worker thread must not panic");
}
