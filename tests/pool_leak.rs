#![allow(clippy::all)]
//! Pool leak detection test — requires a database feature to compile.
#![cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]

use asupersync::cx::Cx;
use asupersync::database::pool::{AsyncConnectionManager, AsyncDbPool, DbPoolConfig};
use asupersync::runtime::{Runtime, RuntimeConfig};
use asupersync::time::{sleep, timeout, wall_now};
use asupersync::types::Outcome;
use std::time::Duration;

struct LeakManager;

impl AsyncConnectionManager for LeakManager {
    type Connection = ();
    type Error = std::io::Error;

    async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
        // Wait forever so we can cancel it
        sleep(wall_now(), Duration::from_secs(10)).await;
        Outcome::Ok(())
    }

    async fn is_valid(&self, _cx: &Cx, _conn: &mut Self::Connection) -> bool {
        sleep(wall_now(), Duration::from_secs(10)).await;
        true
    }
}

#[test]
fn test_pool_leak() {
    let runtime = Runtime::with_config(RuntimeConfig::default()).unwrap();
    runtime.block_on(async {
        let pool = AsyncDbPool::new(LeakManager, DbPoolConfig::with_max_size(1));
        let cx = Cx::current().expect("runtime task context");

        let fut = pool.get(&cx);
        // Let it run until the await point
        let _ = timeout(wall_now(), Duration::from_millis(50), fut).await;

        // Now the future is dropped. Let's check the pool stats.
        let stats = pool.stats();
        println!("Total connections: {}", stats.total);
        println!("Active: {}", stats.active);

        assert_eq!(stats.total, 0, "LEAK DETECTED!");
    });
}
