//! SQLite transactions consume the transaction handle at the type level:
//! after commit or rollback, no further transaction operation can compile.

use asupersync::cx::Cx;
use asupersync::database::SqliteTransaction;

async fn sqlite_commit_consumes_self<'a>(tx: SqliteTransaction<'a>, cx: &Cx) {
    let _ = tx.commit(cx).await;
    let _ = tx.rollback(cx).await;
}

fn main() {
    let _ = sqlite_commit_consumes_self;
}
