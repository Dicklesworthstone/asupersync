//! Postgres transactions consume the transaction handle at the type level:
//! after commit or rollback, no further transaction operation can compile.

use asupersync::cx::Cx;
use asupersync::database::PgTransaction;

async fn postgres_commit_consumes_self<'a>(tx: PgTransaction<'a>, cx: &Cx) {
    let _ = tx.commit(cx).await;
    let _ = tx.rollback(cx).await;
}

fn main() {
    let _ = postgres_commit_consumes_self;
}
