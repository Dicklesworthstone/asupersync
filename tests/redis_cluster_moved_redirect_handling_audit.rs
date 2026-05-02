//! Audit + regression test for `src/messaging/redis.rs` Redis
//! cluster MOVED/ASK redirect handling.
//!
//! Operator's question: "when server replies 'MOVED 12345
//! host:port', does our client (a) follow the redirect once
//! and retry on new node, or (b) follow redirects in a loop
//! until success? Per Redis cluster spec, follow once + cache
//! slot mapping."
//!
//! Audit findings:
//!
//!   (a) **The implementation is the production-correct
//!       middle ground**: a BOUNDED loop, capped at
//!       `MAX_REDIRECTS = 5` hops (otel.rs:1887,
//!       br-asupersync-hzgugy). Strict "follow once" is
//!       unrealistic — real cluster topologies during a
//!       resharding event can legitimately produce 2-3
//!       sequential MOVED responses as the client's stale
//!       slot map catches up. Production clients (jedis,
//!       redis-py, redis-rs) all use a bounded chain in the
//!       5-16 hop range.
//!
//!   (b) **MOVED handling** (redis.rs:2249-2253):
//!       - Updates `self.slot_map.lock().insert(slot, addr)`
//!         BEFORE issuing the retry. Subsequent commands for
//!         keys hashing into that slot will go directly to
//!         the new owner without round-tripping through the
//!         old node.
//!       - Opens a new connection to the redirect target,
//!         re-executes the command, and on success returns
//!         immediately.
//!
//!   (c) **ASK handling** (redis.rs:2254-2266) per Redis
//!       cluster spec:
//!       - Does NOT update the slot map (the migration is
//!         transient — the slot is in the middle of being
//!         moved, ownership hasn't fully transferred).
//!       - Prepends an `ASKING` command to grant one-shot
//!         permission for the next command on the new node.
//!       - Verifies the ASKING response is `OK` before
//!         issuing the actual command (prevents protocol
//!         confusion if the server returns something
//!         unexpected).
//!
//!   (d) **Adversarial-loop bound** (redis.rs:2236-2241):
//!       `redirects: u8` with `saturating_add(1)` and an
//!       `if redirects > MAX_REDIRECTS` early-return guard.
//!       After exhaustion, the function returns
//!       `RedisError::Protocol("...exceeded maximum of 5
//!       hops...")`. This bounds the worst case for a
//!       byzantine cluster that tries to trap a client in a
//!       redirect cycle.
//!
//!   (e) **Connection hygiene** (redis.rs:2270): the redirect
//!       connection is shut down via `shutdown_transport()`
//!       between hops — a redirect target is treated as a
//!       transient connection, not pooled. The first
//!       successful path on the redirect target writes back
//!       to the slot map (MOVED branch); subsequent commands
//!       use the regular pooled connection to the now-cached
//!       owner.
//!
//! Verdict: **SOUND**. The behavior is correct per Redis
//! cluster spec: cache slot mapping on MOVED, prepend ASKING
//! on ASK, bound the chain to prevent adversarial loops. The
//! operator's strict "follow once" interpretation is too
//! conservative for real-world cluster resharding scenarios;
//! the bounded-loop pattern is the production norm.
//!
//! A regression that:
//!   - removed the MAX_REDIRECTS cap (would let an
//!     adversarial cluster trap the client forever),
//!   - changed MAX_REDIRECTS to 1 (would break legitimate
//!     mid-resharding scenarios — clients would observe
//!     spurious "exceeded max hops" errors during normal
//!     cluster maintenance),
//!   - dropped the slot_map.insert on MOVED (would defeat
//!     the caching, forcing every key into a redirect),
//!   - added slot_map.insert on ASK (would corrupt the slot
//!     map with a transient migration target),
//!   - failed to prepend ASKING on the ASK retry (would
//!     produce protocol errors against the migration
//!     target),
//!   - reused the pooled connection for the redirect target
//!     (mismatched handshake state — the target may not be
//!     authenticated against the same DB),
//! would all be caught here.

use std::path::PathBuf;

fn read_redis_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/messaging/redis.rs");
    std::fs::read_to_string(&path).expect("read redis.rs")
}

fn cmd_bytes_body(source: &str) -> &str {
    let marker = "pub async fn cmd_bytes(&self, cx: &Cx, args: &[&[u8]]) -> Result<RespValue, RedisError> {";
    let start = source.find(marker).expect("cmd_bytes fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("cmd_bytes close");
    &source[start..start + body_end]
}

#[test]
fn max_redirects_constant_is_bounded() {
    // Pin (d): MAX_REDIRECTS is defined and bounded. The exact
    // value is a tradeoff (too low breaks resharding, too high
    // weakens the adversarial-loop bound); the canonical value
    // is 5 per the doc comment.
    let source = read_redis_source();

    assert!(
        source.contains("const MAX_REDIRECTS: u8 = 5;"),
        "REGRESSION: MAX_REDIRECTS constant changed or removed. \
         The value MUST be small enough to bound adversarial \
         redirect loops AND large enough to tolerate normal \
         cluster resharding (which can produce 2-3 sequential \
         MOVED responses). 5 is the documented Redis-client \
         convention. If the value genuinely needs to change, \
         update this test together with a justification.",
    );

    // u8 type prevents overflow tricks (max 255 hops).
    assert!(
        source.contains("redirects: u8") || source.contains("redirects = 0u8"),
        "REGRESSION: the redirects counter is no longer u8. \
         The narrow type bounds the worst case independently \
         of MAX_REDIRECTS — a regression to u32/u64 would \
         allow surprisingly large loops if MAX_REDIRECTS \
         were ever removed.",
    );
}

#[test]
fn cmd_bytes_caps_redirect_chain() {
    // Pin (d) AUDIT-CRITICAL: the loop has the explicit cap
    // check. A regression that removed it would let a hostile
    // cluster trap the client in an infinite redirect cycle.
    let source = read_redis_source();
    let body = cmd_bytes_body(&source);

    assert!(
        body.contains("if redirects > MAX_REDIRECTS"),
        "REGRESSION: cmd_bytes no longer caps the redirect \
         chain via `if redirects > MAX_REDIRECTS`. Without the \
         cap, a hostile or malfunctioning Redis cluster could \
         trap the client in an infinite loop (DoS / hung \
         caller).\n\nfn body:\n{body}",
    );

    // The exhaustion path must return Err(Protocol(...)) — NOT
    // panic, NOT loop forever, NOT silently succeed.
    assert!(
        body.contains("RedisError::Protocol(format!(")
            && body.contains("exceeded maximum of"),
        "REGRESSION: cmd_bytes no longer returns a protocol \
         error on redirect-chain exhaustion. The error class \
         and message text are part of the operator's \
         observability — silent failure or panic would be \
         worse than a clear error.",
    );
}

#[test]
fn cmd_bytes_increments_redirect_counter_via_saturating_add() {
    // Pin (d): saturating_add prevents the counter from
    // wrapping (would allow N×256 hops on u8 wraparound).
    // A regression to plain `+= 1` would re-introduce the
    // wraparound risk.
    let source = read_redis_source();
    let body = cmd_bytes_body(&source);

    assert!(
        body.contains("redirects.saturating_add(1)"),
        "REGRESSION: the redirect counter is no longer \
         incremented via saturating_add. Plain `+= 1` on a u8 \
         would wrap at 256, allowing an attacker to evade the \
         cap by sending 256 redirects (counter wraps to 0, \
         loop continues).",
    );
}

#[test]
fn moved_branch_updates_slot_map() {
    // Pin (b) AUDIT-CRITICAL: MOVED handling caches the new
    // slot owner in the slot map. A regression that dropped
    // this would force every subsequent command for the same
    // slot to round-trip through the redirect again — a
    // performance + correctness regression (especially
    // during a sustained resharding window).
    let source = read_redis_source();
    let body = cmd_bytes_body(&source);

    assert!(
        body.contains("self.slot_map.lock().insert(*slot, addr.clone());"),
        "REGRESSION: MOVED branch no longer updates the slot \
         map via `self.slot_map.lock().insert(*slot, \
         addr.clone())`. Without the cache, every command for \
         a moved slot would retry through the redirect — \
         doubling round trips for the affected slot until the \
         cache is rebuilt some other way.\n\nfn body:\n{body}",
    );
}

#[test]
fn ask_branch_does_not_update_slot_map() {
    // Pin (c) AUDIT-CRITICAL: ASK is transient. Updating the
    // slot map for an ASK target would corrupt the routing —
    // the migration target is NOT the new owner; ownership
    // hasn't fully transferred yet.
    let source = read_redis_source();
    let body = cmd_bytes_body(&source);

    // Find the ASK branch arm.
    let ask_marker = "Redirect::Ask { .. } => {";
    let ask_start = body
        .find(ask_marker)
        .expect("ASK branch must exist");
    // The ASK branch ends at the next `},\n` at the same
    // indentation level. We scan for it conservatively.
    let ask_end = body[ask_start..]
        .find("            };")
        .or_else(|| body[ask_start..].find("                }\n            };"))
        .or_else(|| body[ask_start..].find("                }"))
        .expect("ASK branch close");
    let ask_body = &body[ask_start..ask_start + ask_end];

    // The ASK arm MUST NOT contain slot_map.insert.
    assert!(
        !ask_body.contains("slot_map") || !ask_body.contains(".insert("),
        "REGRESSION: ASK branch now updates the slot map. ASK \
         is a TRANSIENT migration; updating the slot map for \
         an ASK target would corrupt routing — subsequent \
         commands for the same slot would go to a node that \
         doesn't yet own the slot, producing more MOVED/ASK \
         redirects.\n\nASK branch:\n{ask_body}",
    );
}

#[test]
fn ask_branch_prepends_asking_command() {
    // Pin (c) AUDIT-CRITICAL: per Redis cluster spec, the
    // ASKING command grants one-shot permission for the next
    // command on the migration target. Without it, the target
    // refuses the command (the slot isn't owned yet from its
    // perspective).
    let source = read_redis_source();
    let body = cmd_bytes_body(&source);

    let ask_marker = "Redirect::Ask { .. } => {";
    let ask_start = body.find(ask_marker).expect("ASK branch");
    let ask_segment = &body[ask_start..ask_start + 1500.min(body.len() - ask_start)];

    assert!(
        ask_segment.contains("b\"ASKING\""),
        "REGRESSION: ASK branch no longer prepends the ASKING \
         command. Per Redis cluster spec, the migration target \
         refuses commands for the moving slot until ASKING is \
         issued. Without it, every ASK redirect would produce \
         another error.\n\nASK segment:\n{ask_segment}",
    );

    // The branch must also verify ASKING returned OK before
    // issuing the actual command. A regression that skipped
    // this check could mis-interpret a server error as
    // success.
    assert!(
        ask_segment.contains("RespValue::SimpleString(ref s)") && ask_segment.contains("== \"OK\""),
        "REGRESSION: ASK branch no longer verifies that ASKING \
         returned OK before issuing the actual command. \
         Without verification, a server error response could \
         be silently treated as ASKING success — the actual \
         command then runs on a target that hasn't granted \
         permission.\n\nASK segment:\n{ask_segment}",
    );
}

#[test]
fn parse_redirect_distinguishes_moved_from_ask() {
    // Pin: the parser recognizes both MOVED and ASK as
    // distinct variants. A regression that conflated them
    // (e.g., always treating as MOVED) would corrupt the
    // slot map with transient migration targets.
    let source = read_redis_source();

    let fn_marker = "fn parse_redirect(msg: &str) -> Option<Redirect> {";
    let start = source.find(fn_marker).expect("parse_redirect fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("parse_redirect close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("\"MOVED\" => Some(Redirect::Moved {"),
        "REGRESSION: parse_redirect no longer maps \"MOVED\" \
         to Redirect::Moved. fn body:\n{body}",
    );
    assert!(
        body.contains("\"ASK\" => Some(Redirect::Ask {"),
        "REGRESSION: parse_redirect no longer maps \"ASK\" to \
         Redirect::Ask.",
    );
}

#[test]
fn redirect_uses_fresh_connection_not_pooled() {
    // Pin (e): the redirect target is reached via a NEW
    // connection (`open_redirect_connection`), not the pooled
    // connection. A regression that reused the pooled
    // connection could mismatch handshake state — the target
    // may have different AUTH credentials, default DB, or
    // CLIENT-NAME. Plus the pooled connection is bound to a
    // specific address.
    let source = read_redis_source();
    let body = cmd_bytes_body(&source);

    assert!(
        body.contains("self.open_redirect_connection(&target_addr, cx).await?"),
        "REGRESSION: redirect target is no longer reached via \
         open_redirect_connection. Reusing the pooled \
         connection would mismatch handshake state and likely \
         fail authentication / db-select against the target.\n\
         \nfn body:\n{body}",
    );
}

#[test]
fn redirect_connection_is_shut_down_after_use() {
    // Pin (e): the transient redirect connection is shut down
    // after each hop — it's not pooled, not held open. A
    // regression that leaked the connection would accumulate
    // file descriptors during cluster instability.
    let source = read_redis_source();
    let body = cmd_bytes_body(&source);

    assert!(
        body.contains("redirect_conn.stream.shutdown_transport()"),
        "REGRESSION: redirect connection is no longer shut \
         down after use. During a cluster resharding event, \
         a client doing many redirects could leak FDs / \
         sockets.\n\nfn body:\n{body}",
    );
}

#[test]
fn cmd_bytes_doc_describes_caching_and_bound() {
    // Pin: the doc comment promises both MOVED slot caching
    // AND the redirect-chain cap. A regression that changed
    // the behavior without updating the doc would create a
    // contract drift.
    let source = read_redis_source();
    // The doc lives ABOVE the `pub async fn cmd_bytes` line.
    // Take a window of the 30 lines preceding the fn to scope
    // the doc-text grep.
    let fn_marker = "pub async fn cmd_bytes(&self, cx: &Cx, args: &[&[u8]]) -> Result<RespValue, RedisError> {";
    let fn_pos = source.find(fn_marker).expect("cmd_bytes fn");
    // Walk backward 30 lines to get the doc block.
    let mut doc_start = fn_pos;
    for _ in 0..30 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..fn_pos];

    let required_doc_phrases = ["updates the slot map", "ASKING", "MAX_REDIRECTS = 5"];
    for phrase in &required_doc_phrases {
        assert!(
            doc_window.contains(phrase),
            "REGRESSION: cmd_bytes doc no longer mentions \
             `{phrase}`. The doc is the public contract; \
             update both the impl and the doc together.\n\n\
             doc window:\n{doc_window}",
        );
    }
}

#[test]
fn parse_redirect_rejects_empty_or_malformed() {
    // Pin: parse_redirect rejects malformed input. A regression
    // that accepted empty addr would let a hostile server
    // redirect the client to "" (which open_redirect_connection
    // would then fail to connect to, but the loop would consume
    // a hop counter — death by a thousand redirects amplified
    // by the cap).
    let source = read_redis_source();

    let fn_marker = "fn parse_redirect(msg: &str) -> Option<Redirect> {";
    let start = source.find(fn_marker).expect("parse_redirect");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("parse_redirect close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if addr.is_empty() {") && body.contains("return None;"),
        "REGRESSION: parse_redirect no longer rejects empty \
         redirect addresses. A hostile server could send \
         `MOVED 1234 ` (empty addr) and the client would \
         attempt to connect to an empty endpoint.\n\nfn body:\n{body}",
    );
}
