// Callback scope: every trampoline into JS runs inside a Node callback scope,
// so a response sent from a microtask or a nextTick queued during dispatch
// goes out when the callback returns - not at the next unrelated timer.
//
// Without the scope this test hangs: the engine's plain V8 call never drains
// the microtask queue, the `.then` below never runs, and the socket times
// out. With it the reply arrives in well under the 2s budget.
import { test } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import engine from '../packages/engine/index.mjs';

function raw(port, reqLine, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const sock = net.connect(port, '127.0.0.1', () => sock.write(reqLine));
    let buf = '';
    sock.on('data', (d) => (buf += d));
    sock.on('end', () => resolve({ body: buf, ms: Date.now() - started }));
    sock.on('error', reject);
    sock.setTimeout(timeoutMs, () => {
      sock.destroy();
      reject(new Error(`no response within ${timeoutMs}ms`));
    });
  });
}

const req = (path) => `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`;

test('probe advertises callbackScope', () => {
  assert.strictEqual(engine.probe().capabilities?.callbackScope, true);
});

test('a response sent from a microtask goes out when the callback returns', async () => {
  const sid = engine.serve({
    onRequest(reqId, _method, path) {
      if (path === '/then') {
        Promise.resolve().then(() => engine.respond(reqId, 200, null, 'then'));
      } else if (path === '/await') {
        (async () => {
          await null; // a settled await: continuation is a bare microtask
          engine.respond(reqId, 200, null, 'await');
        })();
      } else if (path === '/tick') {
        process.nextTick(() => engine.respond(reqId, 200, null, 'tick'));
      } else {
        engine.respond(reqId, 200, null, 'sync');
      }
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  try {
    for (const [path, body] of [['/then', 'then'], ['/await', 'await'], ['/tick', 'tick'], ['/sync', 'sync']]) {
      const r = await raw(port, req(path));
      assert.match(r.body, /^HTTP\/1\.1 200/, `${path} should be 200`);
      assert.ok(r.body.endsWith(body), `${path} body wrong: ${JSON.stringify(r.body)}`);
      assert.ok(r.ms < 1000, `${path} took ${r.ms}ms: the queue was not drained on return`);
    }
  } finally {
    engine.close(sid);
  }
});

test('batched dispatch drains the queue too', async () => {
  const batchOn = engine.probe().capabilities?.batchDispatch === true;
  if (!batchOn) return;
  let buffers = null;
  const sid = engine.serve({
    onRequest(reqId) {
      Promise.resolve().then(() => engine.respond(reqId, 200, null, 'single'));
    },
    onRequestBatch(count) {
      const d = buffers.descriptors;
      const ctl = buffers.control;
      let i = 0;
      for (;;) {
        const reqId = d[3 * i];
        Promise.resolve().then(() => engine.respond(reqId, 200, null, 'batch'));
        const next = ctl[0];
        if (next === i) return i + 1;
        if (next >= count) return count;
        i = next;
      }
    },
    onAborted() {},
  });
  buffers = engine.getBatchBuffers(sid);
  const port = engine.listen(sid, '127.0.0.1', 0);
  try {
    const r = await raw(port, req('/'));
    assert.ok(r.body.endsWith('batch'), `batch body wrong: ${JSON.stringify(r.body)}`);
    assert.ok(r.ms < 1000, `batch took ${r.ms}ms`);
  } finally {
    engine.close(sid);
  }
});

// A handler that throws is reported on stderr and the server goes on serving;
// what it queued before throwing still runs when the callback returns, as the
// work of a handler that returned does. An exception thrown by a nextTick
// callback the handler queued is the process's uncaught exception, as for any
// nextTick callback: the engine reports and swallows only the handler's own
// throw. In a process of its own (callback-scope-subject.mjs), so the
// uncaught exception can be watched.
test('a throwing handler is reported and swallowed; its queued work runs; a throwing nextTick is uncaught', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  // A file path, not URL.pathname: a checkout under a directory with a space stays found
  const subject = fileURLToPath(new URL('./callback-scope-subject.mjs', import.meta.url));
  const modes = engine.probe().capabilities?.batchDispatch === true ? ['single', 'batch'] : ['single'];
  for (const mode of modes) {
    const child = spawn(process.execPath, [subject, mode], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    try {
      const port = await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`${mode}: subject did not start: ${err}`)), 10000);
        child.stdout.on('data', () => {
          const m = /PORT (\d+)/.exec(out);
          if (m) {
            clearTimeout(t);
            resolve(Number(m[1]));
          }
        });
      });
      const thrown = await raw(port, req('/throw'));
      assert.ok(thrown.body.endsWith('after-throw'), `${mode} /throw: ${JSON.stringify(thrown.body)}`);
      assert.ok(thrown.ms < 1000, `${mode} /throw took ${thrown.ms}ms: the queue was not drained after the throw`);
      const ticked = await raw(port, req('/tick-throw'));
      assert.ok(ticked.body.endsWith('tick-throw'), `${mode} /tick-throw: ${JSON.stringify(ticked.body)}`);
      const ok = await raw(port, req('/ok'));
      assert.ok(ok.body.endsWith('ok'), `${mode}: the server stopped serving: ${JSON.stringify(ok.body)}`);
      await new Promise((r) => setTimeout(r, 100));
      assert.match(err, /handler boom/, `${mode}: the handler's throw was not reported`);
      assert.ok(!/UNCAUGHT handler boom/.test(out), `${mode}: the handler's own throw became uncaught`);
      assert.match(out, /UNCAUGHT tick boom/, `${mode}: the nextTick callback's throw was not uncaught`);
    } finally {
      child.kill();
    }
  }
});

// What a callback sees of the call itself: `this` is the global object, and
// the execution resource (async_hooks) is one object per server, the same in
// every callback of that server and different from another server's - for
// onRequest with and without batching, and for onAborted.
test('callbacks run with this === globalThis and one execution resource per server', async () => {
  const { executionAsyncResource } = await import('node:async_hooks');
  const seen = [];
  const make = (tag, batch) => {
    let buffers = null;
    const callbacks = {
      onRequest(reqId) {
        'use strict';
        seen.push({ tag, cb: 'onRequest', self: this, res: executionAsyncResource() });
        if (seen.length % 2) engine.respond(reqId, 200, null, 'x');  // every other one is left open, then aborted
      },
      onAborted() {
        'use strict';
        seen.push({ tag, cb: 'onAborted', self: this, res: executionAsyncResource() });
      },
    };
    if (batch) {
      callbacks.onRequestBatch = function (count) {
        'use strict';
        const d = buffers.descriptors, ctl = buffers.control;
        let i = 0;
        for (;;) {
          seen.push({ tag, cb: 'onRequestBatch', self: this, res: executionAsyncResource() });
          engine.respond(d[3 * i], 200, null, 'b');
          const next = ctl[0];
          if (next === i) return i + 1;
          if (next >= count) return count;
          i = next;
        }
      };
    }
    const sid = engine.serve(callbacks);
    if (batch) buffers = engine.getBatchBuffers(sid);
    return sid;
  };
  const a = make('a', false);
  const b = make('b', false);
  const pa = engine.listen(a, '127.0.0.1', 0);
  const pb = engine.listen(b, '127.0.0.1', 0);
  try {
    for (const port of [pa, pa, pb, pb]) {
      await new Promise((resolve) => {
        const s = net.connect(port, '127.0.0.1', () => s.write('GET / HTTP/1.1\r\nHost: t\r\n\r\n'));
        s.on('data', () => s.destroy());
        s.on('close', resolve);
        setTimeout(() => s.destroy(), 200);
      });
    }
    await new Promise((r) => setTimeout(r, 200));
  } finally {
    engine.close(a);
    engine.close(b);
  }
  if (engine.probe().capabilities?.batchDispatch === true) {
    const c = make('c', true);
    const pc = engine.listen(c, '127.0.0.1', 0);
    try {
      for (let k = 0; k < 2; k++) {
        await new Promise((resolve) => {
          const s = net.connect(pc, '127.0.0.1', () => s.write('GET / HTTP/1.1\r\nHost: t\r\n\r\n'));
          s.on('data', () => s.destroy());
          s.on('close', resolve);
        });
      }
    } finally {
      engine.close(c);
    }
  }
  assert.ok(seen.some((e) => e.cb === 'onAborted'), 'no onAborted was seen');
  for (const e of seen) assert.strictEqual(e.self, globalThis, `${e.tag} ${e.cb}: this is not the global object`);
  const byTag = new Map();
  for (const e of seen) {
    if (!byTag.has(e.tag)) byTag.set(e.tag, e.res);
    assert.strictEqual(e.res, byTag.get(e.tag), `${e.tag} ${e.cb}: a different execution resource`);
  }
  assert.notStrictEqual(byTag.get('a'), byTag.get('b'));
  assert.notStrictEqual(byTag.get('a'), globalThis);
});

// The engine enters onRequest, onRequestBatch, onAborted and onWritable
// through trampolines of the loader and node::MakeCallback, or - under
// MORO_ENGINE_DISPATCH=scope - by a plain call inside a callback scope of
// its own. A callback cannot tell which: dispatch-subject.mjs records what
// one can observe (this, arguments, the async context and async-hook events,
// AsyncLocalStorage across continuations, what becomes of a throw from the
// handler, from a nextTick callback, from a microtask and of a rejected
// promise) and the two transcripts are the same, on the main thread and in a
// worker, with and without async hooks, for single and batched dispatch. One
// thing differs and is asserted: a stack taken inside the handler has one
// more frame, the trampoline's, below the handler's own.
test('a callback sees the same call through the loader trampolines as through the engine scope', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const subject = fileURLToPath(new URL('./dispatch-subject.mjs', import.meta.url));
  const paths = ['/this', '/stack', '/als', '/als', '/throw', '/throw-unanswered', '/tick-throw', '/micro-throw', '/reject', '/ok', '/abort', '/ok', '/throw-symbol'];

  const run = async (dispatch, mode, where, hooks) => {
    const env = { ...process.env };
    delete env.MORO_ENGINE_DISPATCH;
    if (dispatch === 'scope') env.MORO_ENGINE_DISPATCH = 'scope';
    const child = spawn(process.execPath, [subject, mode, where, hooks], { stdio: ['ignore', 'pipe', 'pipe'], env });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    const answers = [];
    try {
      const port = await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`subject did not start: ${err}`)), 15000);
        child.stdout.on('data', () => {
          const m = /PORT (\d+)/.exec(out);
          if (m) {
            clearTimeout(t);
            resolve(Number(m[1]));
          }
        });
      });
      for (const path of paths) {
        if (path === '/abort') {
          await new Promise((resolve) => {
            const s = net.connect(port, '127.0.0.1', () => s.write('GET /abort HTTP/1.1\r\nHost: t\r\n\r\n'));
            setTimeout(() => s.destroy(), 80);
            s.on('close', resolve);
          });
          answers.push('aborted');
        } else {
          const r = await raw(port, req(path));
          answers.push(r.body.split('\r\n\r\n')[1]);
        }
        await new Promise((r) => setTimeout(r, 40));
      }
      await new Promise((r) => setTimeout(r, 150));
    } finally {
      child.kill();
    }
    // Lines end in \r\n on Windows where the engine prints them: its reports
    // go through the C runtime's stderr, a text-mode stream there, which
    // writes every \n as \r\n.
    const events = out.split(/\r?\n/).filter((l) => l.startsWith('EV ')).map((l) => JSON.parse(l.slice(3)));
    const reports = err.split(/\r?\n/).filter((l) => l.startsWith('[morojs-engine]'));
    return { answers, events, reports };
  };

  const batchOn = engine.probe().capabilities?.batchDispatch === true;
  for (const mode of batchOn ? ['single', 'batch'] : ['single']) {
    for (const where of ['main', 'worker']) {
      for (const hooks of ['nohooks', 'hooks']) {
        const tag = `${mode}/${where}/${hooks}`;
        const viaScope = await run('scope', mode, where, hooks);
        const viaTrampoline = await run('trampoline', mode, where, hooks);

        // The one difference: the trampoline's frame, below the handler's.
        const frames = (r) => r.events.find((e) => e.path === '/stack').frames;
        const a = frames(viaScope);
        const b = frames(viaTrampoline);
        assert.strictEqual(b[0], a[0], `${tag}: the top frame changed`);
        // (With async hooks enabled Node enters every MakeCallback through a
        // trampoline of its own, which adds a second frame below ours.)
        const added = b.filter((f) => !a.includes(f));
        assert.deepStrictEqual(b.filter((f) => a.includes(f)), a, `${tag}: the handler's own frames differ`);
        assert.ok(added.length >= 1 && /^(Object\.)?dispatch(Request|Batch|Notice)$/.test(added[0]), `${tag}: the frame below the handler's is not the trampoline's: ${added}`);
        assert.deepStrictEqual(added.slice(1).filter((f) => !/^(Object\.)?callbackTrampoline$/.test(f)), [], `${tag}: unexpected frames: ${added}`);
        assert.ok(added.length <= (hooks === 'hooks' ? 2 : 1), `${tag}: too many frames were added: ${added}`);
        for (const r of [viaScope, viaTrampoline]) r.events.find((e) => e.path === '/stack').frames = null;

        assert.deepStrictEqual(viaTrampoline.answers, viaScope.answers, `${tag}: answers differ`);
        assert.deepStrictEqual(viaTrampoline.reports, viaScope.reports, `${tag}: reports on stderr differ`);
        assert.deepStrictEqual(viaTrampoline.events, viaScope.events, `${tag}: what the callbacks observed differs`);

        // And what both must show, whatever the mode.
        const ev = viaTrampoline.events;
        assert.ok(ev.some((e) => e.path === '/this' && e.thisIsGlobal === true), `${tag}: this is not the global object`);
        assert.ok(ev.some((e) => e.onAborted && e.thisIsGlobal === true && e.argc === 1), `${tag}: onAborted`);
        assert.ok(ev.some((e) => e.uncaught === 'tick boom'), `${tag}: a nextTick throw was not uncaught`);
        assert.ok(ev.some((e) => e.uncaught === 'microtask boom'), `${tag}: a microtask throw was not uncaught`);
        assert.ok(ev.some((e) => e.unhandledRejection === 'async boom'), `${tag}: the rejection was not reported`);
        assert.ok(!ev.some((e) => /handler boom|unanswered boom|abort boom/.test(e.uncaught || '')), `${tag}: a handler's own throw became uncaught`);
        assert.ok(viaTrampoline.reports.some((l) => l.endsWith('threw: Error: handler boom')), `${tag}: the throw was not reported`);
        assert.ok(viaTrampoline.reports.some((l) => l.endsWith('threw: TypeError: unanswered boom')), `${tag}: the second throw was not reported`);
        assert.ok(viaTrampoline.reports.includes('[morojs-engine] handler threw: Error: abort boom'), `${tag}: onAborted's throw was not reported`);
        assert.strictEqual(viaTrampoline.answers[4], 'after-throw', `${tag}: work queued before the throw did not run`);
        assert.strictEqual(viaTrampoline.answers[5], 'late', `${tag}: the request of a throwing handler could not be answered later`);
        assert.strictEqual(viaTrampoline.answers[12], 'after-symbol', `${tag}: a handler that threw a Symbol`);
        assert.ok(viaTrampoline.reports.some((l) => l.endsWith('threw: Symbol(symbol boom)')), `${tag}: a thrown Symbol was not reported`);
      }
    }
  }
});

// close() delivers onAborted in place, so a close() called from deep in the
// stack runs onAborted there too, with what stack is left: the callback, the
// loader's trampoline around it, or the report of what it threw may each be
// the call that runs out. Whichever it is, the abort is delivered or its
// throw reported, and close() itself does not throw. Swept over the depths
// where that happens, frame by frame, in a process of its own.
test('close() from deep in the stack: every abort delivered or reported, and close() does not throw', async () => {
  const { spawnSync } = await import('node:child_process');
  const entry = new URL('../packages/engine/index.mjs', import.meta.url).href;
  const script = `
    import net from 'node:net';
    const { default: engine } = await import(${JSON.stringify(entry)});
    const HELD = 4;
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const totals = { owed: 0, delivered: 0, closeThrew: 0, closedAt: 0, trials: 0 };
    async function trial(back) {
      let delivered = 0, closed = false, held = 0, threw = false;
      let sid;
      const deep = (n, target) => {
        if (n === target) {
          closed = true;
          try { engine.close(sid); } catch { threw = true; }
          return n;
        }
        try { return deep(n + 1, target); } catch { return n; }
      };
      const handle = (reqId, path) => {
        if (path !== '/go') { held++; return; }
        // (measured each time, by the same function at the same tier)
        const maxDepth = deep(0, -1);
        deep(0, Math.max(0, maxDepth - back));
      };
      sid = engine.serve({
        onRequest(reqId, _m, path) { handle(reqId, path); },
        onAborted() { delivered++; },
      });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const socks = [];
      const open = (path) => {
        const s = net.connect(port, '127.0.0.1', () => s.write('GET ' + path + ' HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n'));
        s.on('error', () => {});
        socks.push(s);
      };
      for (let i = 0; i < HELD; i++) open('/held');
      for (let i = 0; i < 200 && held < HELD; i++) await sleep(5);
      open('/go');
      for (let i = 0; i < 200 && !closed; i++) await sleep(5);
      if (!closed) {
        // The handler ran out of stack on its way down, before the call to
        // close(): the server is still open, holding the requests. Close it
        // from here (its aborts are owed all the same) - left open, it would
        // keep the process alive.
        engine.close(sid);
      }
      if (threw) {
        // Either the call to close() itself found no stack left (the app's
        // own call failing: close() never ran), or close() ran and something
        // it called let an exception out. Tell them apart by whether the
        // server still accepts.
        const accepting = await new Promise((r) => {
          const s = net.connect(port, '127.0.0.1', () => { s.destroy(); r(true); });
          s.on('error', () => r(false));
        });
        if (accepting) engine.close(sid);
        else totals.closeThrew++;
      }
      await sleep(20);
      for (const s of socks) s.destroy();
      totals.trials++;
      totals.owed += HELD + 1;
      totals.delivered += delivered;
      if (closed) totals.closedAt++;
    }
    for (let back = 0; back < 160; back++) await trial(back);
    console.log(JSON.stringify(totals));
  `;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 240000 });
  assert.equal(r.status, 0, r.stderr.slice(-1500));
  const totals = JSON.parse(r.stdout.trim().split('\n').pop());
  const reported = r.stderr.split(/\r?\n/).filter((l) => /^\[morojs-engine\] handler threw: /.test(l)).length;
  // (At the very top of the sweep the handler itself can run out of stack
  // before it reaches close(); everywhere else it does.)
  assert.ok(totals.closedAt >= totals.trials - 4, `close() was reached in ${totals.closedAt} of ${totals.trials} trials`);
  assert.equal(totals.closeThrew, 0, 'close() threw');
  assert.equal(totals.delivered + reported, totals.owed, `aborts neither delivered nor reported: ${JSON.stringify({ ...totals, reported })}`);
  assert.ok(reported > 0, 'the sweep never reached the depths where something runs out of stack');
});
