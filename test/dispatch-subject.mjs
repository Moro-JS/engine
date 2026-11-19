// Subject for callback-scope.test.mjs: a server, in a process of its own,
// whose callbacks record what they can observe of the call that entered them
// - `this`, the arguments, the stack, the async context - and that throw, or
// queue work that throws, on request. One `EV <json>` line per observation.
//
//   node dispatch-subject.mjs <single|batch> <main|worker> <hooks|nohooks>
//
// The test runs it with the engine's two ways of entering a callback
// (MORO_ENGINE_DISPATCH unset and =scope) and compares the transcripts.
import { AsyncLocalStorage, createHook, executionAsyncId, triggerAsyncId, executionAsyncResource } from 'node:async_hooks';
import { Worker, isMainThread, workerData } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';

const [mode = 'single', where = 'main', hooks = 'nohooks'] = isMainThread ? process.argv.slice(2) : workerData;

if (where === 'worker' && isMainThread) {
  // The same subject inside a worker thread; its output comes out through
  // this process's stdout and stderr.
  const w = new Worker(fileURLToPath(import.meta.url), { workerData: [mode, where, hooks] });
  w.on('error', (e) => console.log('EV ' + JSON.stringify({ workerError: String(e && e.message) })));
} else {
  const { default: engine } = await import('../packages/engine/index.mjs');
  const log = (o) => console.log('EV ' + JSON.stringify(o));
  process.on('uncaughtException', (e) => log({ uncaught: e.message }));
  process.on('unhandledRejection', (e) => log({ unhandledRejection: e && e.message }));

  const als = new AsyncLocalStorage();
  // Async-hook events while a request is being handled, ids renumbered in
  // order of first appearance (destroy is the collector's business: left out).
  let capturing = null;
  const seen = new Map();
  const rel = (id) => {
    if (id === 0) return 0;
    if (!seen.has(id)) seen.set(id, seen.size + 1);
    return seen.get(id);
  };
  if (hooks === 'hooks') {
    createHook({
      init(id, type, trigger) { if (capturing) capturing.push(`init ${type} ${rel(id)}<-${rel(trigger)}`); },
      before(id) { if (capturing) capturing.push(`before ${rel(id)}`); },
      after(id) { if (capturing) capturing.push(`after ${rel(id)}`); },
      promiseResolve(id) { if (capturing) capturing.push(`resolve ${rel(id)}`); },
    }).enable();
  }

  let resource = null;  // the execution resource of the first callback, for identity
  const context = () => {
    const r = executionAsyncResource();
    if (resource === null) resource = r;
    return { eid: executionAsyncId(), tid: triggerAsyncId(), sameResource: r === resource, resourceIsGlobal: r === globalThis };
  };
  const names = (stack) => stack.split('\n').slice(1).map((l) => (/at (?:async )?([^\s(]+) \(/.exec(l) || [])[1] || '?');

  let n = 0;
  function handle(self, argc, reqId, path) {
    switch (path) {
      case '/this':
        log({ path, thisIsGlobal: self === globalThis, argc, ...context() });
        return engine.respond(reqId, 200, null, 'this');
      case '/stack':
        log({ path, frames: names(new Error('here').stack) });
        return engine.respond(reqId, 200, null, 'stack');
      case '/throw':
        queueMicrotask(() => engine.respond(reqId, 200, null, 'after-throw'));
        throw new Error('handler boom');
      case '/throw-symbol':
        // (String(value) throws for a Symbol: the report describes it.)
        queueMicrotask(() => engine.respond(reqId, 200, null, 'after-symbol'));
        throw Symbol('symbol boom');
      case '/throw-unanswered':
        setTimeout(() => engine.respond(reqId, 200, null, 'late'), 50);
        throw new TypeError('unanswered boom');
      case '/tick-throw':
        process.nextTick(() => { throw new Error('tick boom'); });
        return engine.respond(reqId, 200, null, 'tick');
      case '/micro-throw':
        queueMicrotask(() => { throw new Error('microtask boom'); });
        return engine.respond(reqId, 200, null, 'micro');
      case '/reject':
        engine.respond(reqId, 200, null, 'reject');
        return Promise.reject(new Error('async boom'));
      case '/als': {
        const k = ++n;
        seen.clear();
        capturing = hooks === 'hooks' ? [] : null;
        const before = als.getStore();
        als.enterWith('store-' + k);
        return (async () => {
          await null;
          const afterAwait = als.getStore();
          const ctxAfterAwait = context();
          await new Promise((r) => setImmediate(r));
          const events = capturing;
          capturing = null;
          log({ path, k, before, afterAwait, afterImmediate: als.getStore(), ctxAfterAwait: { ...ctxAfterAwait, eid: rel(ctxAfterAwait.eid), tid: rel(ctxAfterAwait.tid) }, events });
          engine.respond(reqId, 200, null, 'als');
        })();
      }
      case '/abort':
        return;  // left open: the client goes away and onAborted runs
      default:
        return engine.respond(reqId, 200, null, 'ok');
    }
  }

  let buffers = null;
  const callbacks = {
    onRequest(reqId, _methodIdx, path) {
      return handle(this, arguments.length, reqId, path);
    },
    onAborted(reqId) {
      log({ onAborted: true, thisIsGlobal: this === globalThis, argc: arguments.length, idIsNumber: typeof reqId === 'number', ...context() });
      throw new Error('abort boom');
    },
  };
  if (mode === 'batch') {
    callbacks.onRequestBatch = function (count) {
      const d = buffers.descriptors, ctl = buffers.control, paths = buffers.paths;
      let i = 0;
      for (;;) {
        const reqId = d[3 * i], pi = d[3 * i + 2];
        handle(this, arguments.length, reqId, pi === 0xffffffff ? engine.getPath(reqId) : paths[pi]);
        const next = ctl[0];
        if (next === i) return i + 1;
        if (next >= count) return count;
        i = next;
      }
    };
  }
  const sid = engine.serve(callbacks);
  if (mode === 'batch') buffers = engine.getBatchBuffers(sid);
  console.log('PORT ' + engine.listen(sid, '127.0.0.1', 0));
}
