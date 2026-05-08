#![no_main]

use libfuzzer_sys::fuzz_target;

// The types are public in asupersync::database
use asupersync::database::mysql::IsolationLevel as MySqlIsolationLevel;
use asupersync::database::postgres::IsolationLevel as PgIsolationLevel;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 {
        return;
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = MySqlIsolationLevel::from_server_string(s);
        let _ = PgIsolationLevel::from_server_string(s);
    }
});