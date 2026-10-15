/** Actual request mapping/merge TypeScript and native Streams. Producer receipts
 * are explicit doubles except tests composing actual mapper owners below.
 * node --experimental-vm-modules --test scripts/test_browser_fetch_request_merge.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { createContext, SourceTextModule } from "node:vm";
const source = readFileSync(process.env.ASUPERSYNC_REQUEST_MAP_SOURCE ?? new URL("../packages/browser/src/fetch-request-map.ts", import.meta.url), "utf8");
console.log(JSON.stringify({ scenario: "owned-request-merge", source_sha256: createHash("sha256").update(source).digest("hex"),
  evidence: "actual mapping/merge source; native Streams/fetch; explicit producer receipts" }));
async function load(globals = {}) {
  const module = new SourceTextModule(stripTypeScriptTypes(source, { mode: "transform" }), {
    context: createContext({ ReadableStream, ReadableStreamDefaultReader, AbortController, AbortSignal, EventTarget, ...globals }),
  });
  await module.link(() => assert.fail("unexpected runtime dependency")); await module.evaluate(); return module.namespace;
}
const api = await load();
const ok = value => ({ outcome: "ok", value });
const err = (message = "source error") => ({ outcome: "err", failure: { code: "decode_failure", recoverability: "permanent", message } });
const cancelled = (message = "source cancelled") => ({ outcome: "cancelled", cancellation: { kind: "test", phase: "completed",
  origin_region: "merge-test-source", origin_task: null, timestamp_nanos: 0, message, truncated: false } });
const panic = (message = "source panic") => ({ outcome: "panicked", message });
const msg = o => o.outcome === "err" ? o.failure.message : o.outcome === "cancelled" ? o.cancellation.message : o.message;
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function pending(p) { let settled=false; void p.then(()=>{settled=true;},()=>{settled=true;}); await turn(); assert.equal(settled,false); }
function fixture(t) {
  const gates=[], receipts=[], handles=[], readers=[];
  const gate = () => { const g=deferred(); gates.push(g); return g; };
  function source(name, options={}) {
    const count={ pulls:0, native:0, owner:0 }, terminal=deferred(); receipts.push(terminal);
    let controller, pos=0;
    const readable=new ReadableStream({
      start(c) { controller=c; },
      pull(c) { count.pulls++; if (options.park) return;
        if (pos<(options.count ?? 3)) c.enqueue({url:`${name}/${pos++}`});
        else { c.close(); if (!options.holdTerminal) terminal.resolve(options.terminal ?? ok(undefined)); }
      },
      async cancel() { count.native++; options.onNative?.(); await options.nativeGate?.promise;
        if (!options.owned && !options.holdTerminal) terminal.resolve(cancelled());
        if (options.nativeRefuses) throw new Error("native cancellation refused");
      },
    },{highWaterMark:0});
    const owner={readable,closed:terminal.promise,async cancel() {
      assert.equal(this,owner); count.owner++; options.onOwner?.(); await options.ownerGate?.promise;
      if (!options.holdTerminal) terminal.resolve(options.terminal ?? cancelled());
      return options.cancelReceipt ?? ok(undefined);
    }};
    return { readable,owner,terminal,count,controller,input:options.owned?owner:readable };
  }
  const merge = (inputs, options) => { const admitted=api.mergeFetchRequestSources(inputs.map(x=>x.input??x), options); assert.equal(admitted.outcome,"ok"); handles.push(admitted.value); return admitted.value; };
  const reader = h => { const r=h.readable.getReader(); readers.push(r); return r; };
  t.after(async()=>{ for(const g of gates)g.resolve(); for(const r of receipts)r.resolve(ok(undefined));
    await Promise.all(handles.map(h=>h.cancel("test cleanup"))); for(const r of readers){try{r.releaseLock();}catch{}} });
  return {gate,source,merge,reader,handles};
}
const collect=async h=>{const out=[];for await(const item of h.readable)out.push(item.url);return out;};
test("merge API is exported and the empty merge is a successful identity",async t=>{
  const f=fixture(t), h=f.merge([]); assert.equal((await h.cancel()).outcome,"ok"); assert.deepEqual(await collect(h),[]); assert.equal((await h.closed).outcome,"ok");
});
for(const n of [1,2,4,64]) test(`one credit per source, no initial prefetch or refill without demand (${n})`,async t=>{
  const f=fixture(t), list=Array.from({length:n},(_,i)=>f.source(`${i}`,{count:4})),h=f.merge(list),r=f.reader(h);
  await turn(); assert.equal(list.reduce((n,s)=>n+s.count.pulls,0),0);
  assert.equal((await r.read()).value.url,"0/0"); await turn(); assert.deepEqual(list.map(s=>s.count.pulls),new Array(n).fill(1));
  // The first demand wave is now either delivered or queued, never refilled in the background.
  for(let i=1;i<n;i++) assert.equal((await r.read()).value.url,`${i}/0`);
  await h.cancel(); assert.equal(list.every(s=>!s.readable.locked),true);
});
test("a parked first source never blocks ready peers; each source retains its own order",async t=>{
  const f=fixture(t),a=f.source("slow",{park:true}),b=f.source("fast"),h=f.merge([a,b]),r=f.reader(h);
  for(let i=0;i<3;i++) assert.equal((await r.read()).value.url,`fast/${i}`);
  assert.equal(a.count.pulls,1); const last=r.read(); void last.catch(()=>{});await pending(last);a.controller.enqueue({url:"slow/0"});
  assert.equal((await last).value.url,"slow/0");a.controller.close();assert.equal((await r.read()).done,true);assert.equal((await h.closed).outcome,"ok");
});
test("already-ready peers are served before a source's second descriptor",async t=>{
  const f=fixture(t),h=f.merge([f.source("a"),f.source("b"),f.source("c")]);
  assert.deepEqual(await collect(h),["a/0","b/0","c/0","a/1","b/1","c/1","a/2","b/2","c/2"]);
});
test("descriptor identity and unadmitted body getters are never inspected",async t=>{
  const f=fixture(t),a=f.source("a",{park:true}),h=f.merge([a]),r=f.reader(h);
  const descriptor={get url(){assert.fail("url inspected");},get body(){assert.fail("body inspected");}};
  const read=r.read();a.controller.enqueue(descriptor);assert.equal((await read).value,descriptor);await h.cancel();
});
test("output lock release is not cancellation and a replacement reader recovers descriptors",async t=>{
  const f=fixture(t),a=f.source("a"),b=f.source("b"),h=f.merge([a,b]);let r=h.readable.getReader();
  assert.equal((await r.read()).value.url,"a/0");r.releaseLock();await turn();assert.equal(a.count.native+b.count.native,0);
  r=f.reader(h);const rest=[];for(;;){const v=await r.read();if(v.done)break;rest.push(v.value.url);}assert.equal(rest.length,5);assert.equal(new Set(rest).size,5);
});
test("native EOF still joins every independent producer receipt",async t=>{
  const f=fixture(t),a=f.source("a",{owned:true,count:0,holdTerminal:true}),b=f.source("b",{owned:true,count:0,holdTerminal:true}),h=f.merge([a,b]),r=f.reader(h),read=r.read();
  await pending(read);a.terminal.resolve(ok(undefined));await pending(h.closed);assert.equal(a.count.owner+b.count.owner,0);
  b.terminal.resolve(ok(undefined));assert.equal((await read).done,true);assert.equal((await h.closed).outcome,"ok");
});
test("successful producer receipts do not erase unread descriptors",async t=>{
  const f=fixture(t),a=f.source("a",{owned:true}),b=f.source("b",{owned:true});a.terminal.resolve(ok(undefined));b.terminal.resolve(ok(undefined));
  const h=f.merge([a,b]);assert.equal((await collect(h)).length,6);assert.equal((await h.closed).outcome,"ok");
});
test("cancellation starts all native and owner cleanups in parallel and joins independent barriers",async t=>{
  const f=fixture(t),native=f.gate(),owner=f.gate(); const list=[f.source("a",{owned:true,park:true,holdTerminal:true,nativeGate:native}),f.source("b",{owned:true,park:true,holdTerminal:true,ownerGate:owner})];
  const h=f.merge(list),r=f.reader(h),read=r.read();void read.catch(()=>{});await turn();const done=h.cancel("stop");assert.equal(done,h.cancel("later"));
  await pending(done);assert.deepEqual(list.map(s=>[s.count.native,s.count.owner]),[[1,1],[1,1]]);
  list.forEach(s=>s.terminal.resolve(cancelled()));await pending(done);native.resolve();await pending(done);owner.resolve();
  assert.equal((await done).outcome,"cancelled");await assert.rejects(read);assert.equal(list.every(s=>!s.readable.locked),true);
});
for(const kind of [err,cancelled,panic])test(`idle ${kind.name} producer stops and joins every source without demand`,async t=>{
  const f=fixture(t),a=f.source("a",{owned:true,holdTerminal:true}),b=f.source("b",{owned:true}),h=f.merge([a,b]);a.terminal.resolve(kind("origin"));
  const result=await h.closed;assert.equal(result.outcome,kind().outcome);assert.equal(msg(result),"origin");assert.equal(a.count.pulls+b.count.pulls,0);assert.equal(b.count.owner,1);
});
for(const first of [err,cancelled,panic])for(const last of [err,panic])test(`${first.name} cause versus ${last.name} cleanup uses monotone severity`,async t=>{
  const f=fixture(t),g=f.gate(),a=f.source("a",{owned:true,holdTerminal:true}),b=f.source("b",{owned:true,terminal:last("cleanup"),ownerGate:g}),h=f.merge([a,b]);
  a.terminal.resolve(first("origin"));await pending(h.closed);g.resolve();const result=await h.closed;
  assert.equal(result.outcome,(first===panic||first===cancelled&&last===err?first:last)().outcome);
});
test("equal-severity cleanup failures choose source input order, not settlement order",async t=>{
  const f=fixture(t),g=f.gate(),a=f.source("a",{owned:true,ownerGate:g,terminal:panic("index zero")}),b=f.source("b",{owned:true,terminal:panic("index one")}),h=f.merge([a,b]);
  void h.cancel();await pending(h.closed);g.resolve();assert.equal((await h.closed).message,"index zero");
});
test("native rejection resolves to the checked producer diagnosis, not generic cleanup error",async t=>{
  const f=fixture(t),a=f.source("a",{owned:true,holdTerminal:true}),h=f.merge([a]);a.controller.error(new Error("do not trust cause"));await pending(h.closed);
  a.terminal.resolve(err("precise decode failure"));const result=await h.closed;assert.equal(result.failure.code,"decode_failure");assert.equal(result.failure.message,"precise decode failure");
});
for(const malformed of [null,{}, {outcome:"panicked",message:7}])test(`malformed terminal ${JSON.stringify(malformed)} fails closed`,async t=>{
  const f=fixture(t),a=f.source("a",{owned:true,holdTerminal:true}),h=f.merge([a]);a.terminal.resolve(malformed);assert.equal((await h.closed).failure.code,"internal_failure");
});
test("rejected owner receipt and native cancellation refusal cannot become success",async t=>{
  for(const owned of [false,true]){const f=fixture(t),a=f.source("a",{owned,nativeRefuses:true}),h=f.merge([a]);
    if(owned)a.terminal.reject(new Error("secret")); else a.controller.error(new Error("fault"));
    assert.equal((await h.closed).outcome,"err");}
});
test("source methods and terminal envelopes are snapshotted; arbitrary exception hooks are never used",async t=>{
  const f=fixture(t),a=f.source("a",{owned:true,holdTerminal:true}),h=f.merge([a]);let tags=0,messages=0;
  a.owner.cancel=()=>assert.fail("replacement cancel");a.owner.closed=Promise.resolve(ok(undefined));
  a.terminal.resolve({get outcome(){tags++;return "panicked";},get message(){messages++;return "once";}});
  assert.equal((await h.closed).message,"once");assert.equal(tags,1);assert.equal(messages,1);assert.equal(a.count.owner,1);
});
test("raw native sources do not expose custom owner properties",async t=>{
  const f=fixture(t),a=f.source("a");for(const key of ["readable","closed","cancel"])Object.defineProperty(a.readable,key,{get(){assert.fail(key);}});
  const h=f.merge([a]);await h.cancel();assert.equal(a.count.native,1);
});
test("duplicate and aliased sources, locked inputs and invalid lists refuse without effects",async t=>{
  const f=fixture(t),a=f.source("a",{owned:true}),b=f.source("b");
  for(const list of [null,{},new Array(65).fill(a.owner),[a.owner,a.owner],[a.owner,{...a.owner}], [a.owner,null]])assert.equal(api.mergeFetchRequestSources(list).outcome,"err");
  const lock=b.readable.getReader();assert.equal(api.mergeFetchRequestSources([a.owner,b.readable]).outcome,"err");lock.releaseLock();
  assert.equal(a.readable.locked,false);assert.equal(a.count.native+a.count.owner+a.count.pulls,0);
});
test("late setup lock collision releases earlier acquisitions and disables their observers",async t=>{
  const f=fixture(t),a=f.source("a",{owned:true,holdTerminal:true}),b=f.source("b"),c=f.source("c");let held;
  const list=[a.owner,b.readable,{get readable(){held=b.readable.getReader();return c.readable;},closed:Promise.resolve(ok(undefined)),cancel:async()=>ok(undefined)}];
  assert.equal(api.mergeFetchRequestSources(list).outcome,"err");assert.equal(a.readable.locked,false);held.releaseLock();
  a.terminal.resolve(panic("not merge-owned"));a.controller.error(new Error("also not owned"));await turn();assert.equal(a.count.native+a.count.owner,0);
});
test("invalid cancellation reason preserves an active merge; late cancel is inert",async t=>{
  const f=fixture(t),a=f.source("a",{count:1}),h=f.merge([a]);assert.equal((await h.cancel({})).outcome,"err");assert.equal(a.count.native,0);
  assert.deepEqual(await collect(h),["a/0"]);assert.equal((await h.cancel()).outcome,"ok");assert.equal(a.count.native,0);
});
for(const pipe of [false,true])test(`native ${pipe?"pipeTo failure":"iteration exit"} joins every owner`,async t=>{
  const f=fixture(t),a=f.source("a",{owned:true}),b=f.source("b",{owned:true}),h=f.merge([a,b]);
  if(pipe)await assert.rejects(h.readable.pipeTo(new WritableStream({write(){throw new Error("sink failure");}})));
  else for await(const _ of h.readable)break;
  assert.equal((await h.closed).outcome,"cancelled");assert.equal(a.count.owner,1);assert.equal(b.count.owner,1);
});
for(const latePanic of [false,true])test(`actual parallel mapper owners remain joined through merge cancellation (${latePanic})`,async t=>{
  const f=fixture(t),release=f.gate(),started=f.gate(),a=f.source("a"),b=f.source("b");let settled=0,entered=0;
  const mapped=api.tryMapFetchRequests(a.readable,async()=>{if(++entered===2)started.resolve();await release.promise;settled++;return latePanic?panic("late mapper panic"):ok({url:"never"});},{concurrency:2});assert.equal(mapped.outcome,"ok");f.handles.push(mapped.value);
  const h=f.merge([mapped.value,b]),r=f.reader(h);assert.equal((await r.read()).value.url,"b/0");await started.promise;
  const done=h.cancel();await pending(done);assert.equal(settled,0);release.resolve();assert.equal((await done).outcome,latePanic?"panicked":"cancelled");assert.equal(settled,2);assert.equal((await mapped.value.closed).outcome,(await h.closed).outcome);
});
test("two real HTTP feeds are both disconnected and joined after output iteration exits",{timeout:5000},async t=>{
  const seen=[],disconnects=new Set(),done=deferred();const server=createServer((req,res)=>{seen.push(req.url);req.on("close",()=>{disconnects.add(req.url);if(disconnects.size===2)done.resolve();});res.writeHead(200);res.write(req.url);});
  await new Promise(r=>server.listen(0,"127.0.0.1",r));const origin=`http://127.0.0.1:${server.address().port}`,aborters=[],owners=[];let h;
  t.after(async()=>{aborters.forEach(c=>c.abort());server.closeAllConnections();if(h)await h.cancel();await new Promise(r=>server.close(r));});
  for(const path of ["/one","/two"]){const abort=new AbortController();aborters.push(abort);const response=await fetch(origin+path,{signal:abort.signal}),raw=response.body.getReader(),terminal=deferred();let retirement;
    const owner={readable:new ReadableStream({async pull(c){try{const next=await raw.read();if(next.done)c.close();else c.enqueue({url:origin+new TextDecoder().decode(next.value)});}catch(e){c.error(e);}},cancel:()=>raw.cancel()},{highWaterMark:0}),closed:terminal.promise,
      cancel(){return retirement??=(async()=>{await raw.cancel();abort.abort();await done.promise;terminal.resolve(cancelled());return ok(undefined);})();}};owners.push(owner);
  }
  const admitted=api.mergeFetchRequestSources(owners);assert.equal(admitted.outcome,"ok");h=admitted.value;
  for await(const request of h.readable){assert.ok(request.url.endsWith("/one")||request.url.endsWith("/two"));break;}
  assert.equal(disconnects.size,2);assert.deepEqual(seen,["/one","/two"]);assert.equal((await h.closed).outcome,"cancelled");
});

test("pre-aborted parent retires every owned source without reading",async t=>{
  const f=fixture(t),controller=new AbortController();controller.abort();
  const list=[f.source("a",{owned:true,park:true}),f.source("b",{owned:true,park:true})],h=f.merge(list,{signal:controller.signal});
  const result=await h.closed;assert.equal(result.outcome,"cancelled");assert.equal(msg(result),"request merge cancelled by signal");
  assert.deepEqual(list.map(s=>[s.count.pulls,s.count.native,s.count.owner]),[[0,1,1],[0,1,1]]);
  assert.equal(list.every(s=>!s.readable.locked),true);
});
test("parent abort joins parked reads, owner cancellation and producer completion",async t=>{
  const f=fixture(t),ownerGate=f.gate(),controller=new AbortController();
  const a=f.source("a",{owned:true,park:true,holdTerminal:true,ownerGate}),h=f.merge([a],{signal:controller.signal}),r=f.reader(h);
  const read=r.read();void read.catch(()=>{});await turn();controller.abort();await pending(h.closed);
  assert.equal(a.count.native,1);assert.equal(a.count.owner,1);a.terminal.resolve(cancelled("producer retired"));await pending(h.closed);
  ownerGate.resolve();const result=await h.closed;assert.equal(result.outcome,"cancelled");assert.equal(msg(result),"request merge cancelled by signal");
  await assert.rejects(read);assert.equal(a.readable.locked,false);
});
test("earlier parent listeners cannot suppress merge cancellation",async t=>{
  const f=fixture(t),controller=new AbortController();controller.signal.addEventListener("abort",event=>event.stopImmediatePropagation());
  const a=f.source("a",{park:true}),h=f.merge([a],{signal:controller.signal});controller.abort();
  assert.equal((await h.closed).outcome,"cancelled");assert.equal(a.count.native,1);
});
test("customized parent signal is refused before source ownership",async t=>{
  const f=fixture(t),controller=new AbortController(),a=f.source("a");
  Object.defineProperty(controller.signal,"aborted",{value:false});
  const admitted=api.mergeFetchRequestSources([a.readable],{signal:controller.signal});
  assert.equal(admitted.outcome,"err");assert.equal(a.readable.locked,false);assert.equal(a.count.pulls,0);assert.equal(a.count.native,0);
});
test("empty merge stays a successful identity even with a pre-aborted parent",async t=>{
  const f=fixture(t),controller=new AbortController();controller.abort();const h=f.merge([],{signal:controller.signal});
  assert.deepEqual(await collect(h),[]);assert.equal((await h.closed).outcome,"ok");
});
