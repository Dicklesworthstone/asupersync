//! Pool leak detection test — requires a database feature to compile.
//!
//! NOTE: This test uses `#[tokio::main]` and should be migrated to use
//! asupersync's own runtime once async main support is available.
#![cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]

use asupersync::cx::Cx;
use asupersync::database::pool::{AsyncConnectionManager, AsyncDbPool, DbPoolConfig};
use asupersync::types::Outcome;
use std::time::Duration;
use tokio::time::sleep;

struct LeakManager;

impl AsyncConnectionManager for LeakManager {
    type Connection = ();
    type Error = std::io::Error;

    async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
        // Wait forever so we can cancel it
        sleep(Duration::from_secs(10)).await;
        Outcome::Ok(())
    }

    async fn is_valid(&self, _cx: &Cx, _conn: &mut Self::Connection) -> bool {
        sleep(Duration::from_secs(10)).await;
        true
    }
}

#[tokio::main]
async fn main() {
    let pool = AsyncDbPool::new(LeakManager, DbPoolConfig::with_max_size(1));
    let cx = Cx::background();

    let fut = pool.get(&cx);
    // Let it run until the await point
    let _ = tokio::time::timeout(Duration::from_millis(50), fut).await;

    // Now the future is dropped. Let's check the pool stats.
    let stats = pool.stats();
    println!("Total connections: {}", stats.total);
    println!("Active: {}", stats.active);
    if stats.total > 0 {
        println!("LEAK DETECTED!");
        std::process::exit(1);
    } else {
        println!("NO LEAK");
    }
}
