# Owned browser fetch response races and joins

`@asupersync/browser/concurrency` exposes `raceFetchResponses` over existing
`FetchStreamHandle`s. It implements the design bible's select/cancel/drain rule
at the browser fetch boundary, rather than returning from `Promise.race` while
losing requests are still running.

## Use

Start each request explicitly through a scope with the required fetch authority.
The combinator takes **already-admitted handles**, not URLs or request factories:

```ts
import { raceFetchResponses } from "@asupersync/browser/concurrency";

// primary and backup are FetchStreamHandles from successful scope.fetch calls.
const admitted = raceFetchResponses([primary, backup]);
if (admitted.outcome !== "ok") {
  // Setup does not take over cleanup on refusal.
  await Promise.all([primary.cancel(), backup.cancel()]);
  throw new Error("race setup refused");
}
const race = admitted.value;
const outcome = await race.result;
if (outcome.outcome === "ok") {
  const { index, response, fetch, body } = outcome.value;
  // Loser cleanup is complete. The winner remains owned by its original scope.
  // Use body, or pass fetch to serverSentEvents/jsonLines.
  const text = await new Response(body).text();
  const terminal = await fetch.closed;
  console.log(index, response.status, text, terminal.outcome);
}
```

A response race selects **headers**, not a completely downloaded body. HTTP 404
and 500 are ordinary responses, just as with the existing fetch API. The first
observed failure can win too. This is not first-success retry, body validation,
hedging with a delayed second request, or exactly-once execution. A pre-existing
member failure is not suppressed in favor of another live response.

## Ownership and termination

The group takes one native reader lock per member without reading any bytes.
It accepts 1..64 distinct handles, refuses locked or aliased bodies, and uses
input order for ties already ready at observer registration. Input order cannot
make distinct network completions deterministic.

Losers are cancelled in parallel. Their initiating native cancellation promises
and original fetch completion promises must settle before the winner transfers.
A cancellation/publication refusal fails the whole group and retires the
proposed winner. Failure of that winner during slow loser cleanup also prevents
successful transfer. Cleanup failure precedence is panicked, error, then
cancelled, with input order breaking ties at the same severity.

`race.cancel(reason)` before transfer cancels every member, including a selected
winner still waiting for loser cleanup. Repeated calls share one settlement
promise; the first reason wins. Invalid non-string reasons refuse without
changing the group. The composite cancellation is labelled `fetch_race_cancel`;
it is not a new task or a fabricated member ABI receipt.

After successful transfer, `race.cancel()` is inert. The caller must consume or
cancel the winning body and observe `fetch.closed`. The original owning scope
can still cancel it. Original handles' manual `read()` methods have transferred
to native streams; use the winner's `body` or `fetch.toReadableStream()`. Earlier
manual consumption is not undone: the result contains the **remaining** body.

Setup refusal releases acquired reader locks and does not cancel requests. Any
native conversion already performed cannot be reversed; the caller resumes
that body through `toReadableStream()`, not `read()`. The caller retains cleanup
responsibility for all handles on a setup refusal. Do not race the same handles
against other consumers or invoke their methods to seize back ownership.

No fetch, timer, task, retry, or network authority is created by the combinator.
There is no body buffering or read-ahead. Original fetch bounds apply; native
browser, downstream, and tee buffers remain outside those bounds. POST requests
have already been explicitly admitted and cancellation cannot roll back their
transmitted effects. Nonsettling host operations keep result/cancel pending.

## Validation scope

Run `node --experimental-vm-modules --test scripts/test_browser_fetch_combinators.mjs`
with Node 22.13 or later. Tests use the actual fetch manager and combinator with
native streams, including a real loopback HTTP race and peer disconnection.
The task ABI is explicitly doubled; these tests do not establish Rust/WASM
integration, complete workspace health, or cross-browser network compatibility.

## All-response joins

`joinFetchResponses(handles)` waits for every response header, not the complete
response bodies. It transfers an immutable array of `{ index, response, fetch,
body }` entries in **input order** regardless of completion order. HTTP error
statuses remain ordinary responses. It does not return a partially successful
array: one network failure, cancellation, or ready-body error while another
header is pending causes every member to be cancelled and drained first.

```ts
import { joinFetchResponses } from "@asupersync/browser/concurrency";

// Both handles were already admitted through their explicit owning scopes.
const admitted = joinFetchResponses([userRequest, permissionsRequest]);
if (admitted.outcome !== "ok") {
  await Promise.all([userRequest.cancel(), permissionsRequest.cancel()]);
  throw new Error("join setup refused");
}
const joined = await admitted.value.result;
if (joined.outcome === "ok") {
  // Headers have joined. Consume or cancel EVERY returned body afterwards.
  try {
    const data = await Promise.all(joined.value.map(item => new Response(item.body).json()));
    console.log(data);
  } finally {
    await Promise.all(joined.value.map(item => item.fetch.cancel()));
    await Promise.all(joined.value.map(item => item.fetch.closed));
  }
}
```

An empty join succeeds immediately with a frozen empty array, requires no
native reader support, and has inert cancellation. Nonempty joins share the
race's 64-member cap, exclusive-reader transfer, setup-refusal responsibilities,
no-read-ahead behavior, cleanup/publication refusal handling, and inability to
force nonsettling hosts. Join cancellation uses the composite label
`fetch_join_cancel`, not a new task. After a successful join, its cancellation
method is inert; original scopes and each returned fetch still own cleanup.

A joined handle can subsequently participate in a race, or a race winner can
be joined with another handle, provided no consumer currently holds its native
reader lock. These compositions do not issue another request or duplicate bytes.
