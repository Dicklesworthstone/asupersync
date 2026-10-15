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
        let expected = ReferenceIsolationLevel::from_server_string(s);

        let mysql = MySqlIsolationLevel::from_server_string(s);
        assert_eq!(
            mysql.map(ReferenceIsolationLevel::from_mysql),
            expected,
            "MySQL isolation parser diverged from reference for {s:?}"
        );

        let postgres = PgIsolationLevel::from_server_string(s);
        assert_eq!(
            postgres.map(ReferenceIsolationLevel::from_postgres),
            expected,
            "Postgres isolation parser diverged from reference for {s:?}"
        );

        if let Some(level) = mysql {
            assert_eq!(
                MySqlIsolationLevel::from_server_string(level.as_sql()),
                Some(level),
                "MySQL canonical isolation string did not round-trip"
            );
        }

        if let Some(level) = postgres {
            assert_eq!(
                PgIsolationLevel::from_server_string(level.as_sql()),
                Some(level),
                "Postgres canonical isolation string did not round-trip"
            );
        }
    }
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferenceIsolationLevel {
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

impl ReferenceIsolationLevel {
    fn from_server_string(value: &str) -> Option<Self> {
        let normalised: String = value
            .trim()
            .chars()
            .map(|c| {
                if c == '-' || c == '_' {
                    ' '
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();

        match normalised.as_str() {
            "READ UNCOMMITTED" => Some(Self::ReadUncommitted),
            "READ COMMITTED" => Some(Self::ReadCommitted),
            "REPEATABLE READ" => Some(Self::RepeatableRead),
            "SERIALIZABLE" => Some(Self::Serializable),
            _ => None,
        }
    }

    fn from_mysql(level: MySqlIsolationLevel) -> Self {
        match level {
            MySqlIsolationLevel::ReadUncommitted => Self::ReadUncommitted,
            MySqlIsolationLevel::ReadCommitted => Self::ReadCommitted,
            MySqlIsolationLevel::RepeatableRead => Self::RepeatableRead,
            MySqlIsolationLevel::Serializable => Self::Serializable,
        }
    }

    fn from_postgres(level: PgIsolationLevel) -> Self {
        match level {
            PgIsolationLevel::ReadUncommitted => Self::ReadUncommitted,
            PgIsolationLevel::ReadCommitted => Self::ReadCommitted,
            PgIsolationLevel::RepeatableRead => Self::RepeatableRead,
            PgIsolationLevel::Serializable => Self::Serializable,
        }
    }
}
