// worker_threads suite for @morojs/engine.
//
// The engine registers an environment cleanup hook per serve(): when a thread
// (or the process) tears its environment down with a server still open, the
// hook closes the server and reaps its uv handles before Node closes the
// loop - otherwise Node CHECK-aborts the whole process with
// "uv_loop_close() while having open handles". This is what makes the engine
// safe to run inside worker threads that can be terminate()d, exit early, or
// crash. Feature-detect via probe().capabilities.workerThreads.
//
//   - worker.terminate() with a request in flight: the process survives, the
//     client sees the connection close, 50 times in a row (no leak, no abort)
//   - process.exit() inside a worker with the server open: same
//   - two workers sharing one port with reusePort both serve
//   - a child process that process.exit()s with the server open exits 0
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Worker } from 'node:worker_threads';
import { spawnSync } from 'node:child_process';
import { loadEngine, waitFor } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — worker_threads suite skipped';

const T = { timeout: 60000 };
const CRLF = '\r\n';
const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;

// An ESM worker body: import the engine (absolute file URL, so a data: module
// can resolve it), serve, and run `body` with { engine, sid, parentPort, threadId }.
function workerSource(body, serveOptions = '{}') {
  return `
    import { parentPort, threadId } from 'node:worker_threads';
    const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
    const inflight = [];
    const sid = engine.serve({
      onRequest(reqId) { inflight.push(reqId); parentPort.postMessage({ type: 'request', reqId, threadId }); },
      onAborted() {},
    }, ${serveOptions});
    ${body}
  `;
}

function spawnWorker(src) {
  const url = new URL(`data:text/javascript,${encodeURIComponent(src)}`);
  const worker = new Worker(url, { stdout: false, stderr: false });
  const messages = [];
  const waiters = [];
  worker.on('message', (m) => {
    messages.push(m);
    for (const w of waiters.splice(0)) w();
  });
  const exit = new Promise((resolve) => worker.on('exit', resolve));
  const errors = [];
  worker.on('error', (e) => errors.push(e));
  const next = (pred) =>
    new Promise((resolve) => {
      const check = () => {
        const m = messages.find(pred);
        if (m) resolve(m);
        else waiters.push(check);
      };
      check();
    });
  return { worker, messages, next, exit, errors };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });
}

async function rawGet(port, path = '/') {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { headers: { connection: 'close' } });
  return { status: res.status, body: await res.text() };
}

describe('worker_threads', { skip }, () => {
  it('advertises the capability', T, () => {
    assert.equal(engine.probe().capabilities?.workerThreads, true);
  });

  it('terminate() with a request in flight: the process survives, the client is disconnected (x50)', T, async () => {
    const src = workerSource(`
      const port = engine.listen(sid, '127.0.0.1', 0);
      parentPort.postMessage({ type: 'listening', port });
    `);
    for (let i = 0; i < 50; i++) {
      const w = spawnWorker(src);
      const { port } = await w.next((m) => m.type === 'listening');
      const closed = new Promise((resolve) => {
        const socket = net.connect({ host: '127.0.0.1', port }, () => {
          socket.write(`GET /${i} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        });
        socket.on('close', () => resolve('close'));
        socket.on('error', () => resolve('error'));
        socket.setTimeout(10000, () => {
          socket.destroy();
          resolve('timeout');
        });
      });
      await w.next((m) => m.type === 'request'); // the handler holds it, never answers
      await w.worker.terminate();
      const code = await w.exit;
      assert.equal(code, 1, `terminate() exit code (iteration ${i})`);
      assert.notEqual(await closed, 'timeout', `client must be disconnected when the worker dies (iteration ${i})`);
      assert.deepEqual(w.errors, [], 'no worker error');
    }
  });

  it('process.exit() inside a worker with the server open: the process survives', T, async () => {
    const src = workerSource(`
      const port = engine.listen(sid, '127.0.0.1', 0);
      parentPort.postMessage({ type: 'listening', port });
      setTimeout(() => process.exit(0), 50);
    `);
    const w = spawnWorker(src);
    const { port } = await w.next((m) => m.type === 'listening');
    assert.ok(port > 0);
    assert.equal(await w.exit, 0);
    // The port is free again: the listener was actually closed, not leaked.
    await waitFor(async () => {
      try {
        await rawGet(port);
        return false;
      } catch {
        return true;
      }
    }, 5000);
  });

  // reusePort is SO_REUSEPORT, which Windows does not have: the option is
  // ignored there and a second listener on the port gets EADDRINUSE (the
  // worker throws, so this test would wait for a 'listening' that never
  // comes). MoroJS gates thread clustering to POSIX for the same reason.
  const reusePortSkip = process.platform === 'win32' && 'reusePort is POSIX-only (no SO_REUSEPORT on Windows)';
  it('two workers share one port with reusePort and both serve', { ...T, skip: reusePortSkip }, async () => {
    const port = await freePort();
    const src = workerSource(
      `
      engine.listen(sid, '127.0.0.1', ${port});
      parentPort.postMessage({ type: 'listening', port: ${port} });
      `.replace("onRequest(reqId) { inflight.push(reqId); parentPort.postMessage({ type: 'request', reqId, threadId }); }", ''),
      '{ reusePort: true }'
    ).replace(
      'onAborted() {},',
      "onAborted() {}, onRequest(reqId) { engine.respond(reqId, 200, null, String(threadId)); },"
    );
    const a = spawnWorker(src);
    const b = spawnWorker(src);
    try {
      await a.next((m) => m.type === 'listening');
      await b.next((m) => m.type === 'listening');
      const ids = new Set();
      for (let i = 0; i < 40; i++) {
        const r = await rawGet(port);
        assert.equal(r.status, 200);
        ids.add(r.body);
      }
      assert.ok(ids.size >= 1 && ids.size <= 2, `answers came from worker threads: ${[...ids]}`);
      for (const id of ids) assert.ok(Number(id) > 0, 'answered by a worker thread, not the main thread');
      // Linux's SO_REUSEPORT hashes connections across both sockets; macOS
      // can pin every accept to one socket, so only Linux asserts the spread.
      if (process.platform === 'linux') assert.equal(ids.size, 2, 'both workers answered');
    } finally {
      await a.worker.terminate();
      await b.worker.terminate();
      assert.equal(await a.exit, 1);
      assert.equal(await b.exit, 1);
    }
  });

  // io_uring is the process's transport, but a thread that cannot have a ring
  // of its own runs its servers on the epoll transport (here: the process is
  // one descriptor short of a ring at the moment the worker listens). That
  // thread's epoll state owns a libuv handle like any other and has to be
  // closed when the thread ends, or Node aborts the process over a loop with
  // an open handle.
  it('a worker whose server could not have a ring ends without taking the process down',
    { ...T, skip: engine?.probe().transport !== 'uring' && 'needs the io_uring transport (MORO_ENGINE_TRANSPORT=uring)' }, () => {
    const script = `
      import { Worker } from 'node:worker_threads';
      const src = \`
        import fs from 'node:fs';
        import { parentPort } from 'node:worker_threads';
        const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
        const sid = engine.serve({ onRequest(reqId) { engine.respond(reqId, 200, null, 'ok'); }, onAborted() {} }, {});
        const taken = [];
        try { for (;;) taken.push(fs.openSync('/dev/null', 'r')); } catch {}
        fs.closeSync(taken.pop());  // one descriptor: the ring gets it, its eventfd gets none
        let first = 'listening';
        try { engine.listen(sid, '127.0.0.1', 0); } catch (e) { first = e.code; }
        for (const fd of taken) fs.closeSync(fd);
        let port = 0;
        try { port = engine.listen(sid, '127.0.0.1', 0); } catch {}
        const status = port ? await fetch('http://127.0.0.1:' + port + '/', { headers: { connection: 'close' } }).then((r) => r.status, () => 0) : 0;
        parentPort.postMessage({ first, status });
      \`;
      const worker = new Worker(new URL('data:text/javascript,' + encodeURIComponent(src)));
      const msg = await new Promise((resolve) => worker.once('message', resolve));
      await worker.terminate();
      console.log(JSON.stringify(msg));
    `;
    const r = spawnSync('sh', ['-c', 'ulimit -n 256; exec "$0" --input-type=module -e "$SUBJECT"', process.execPath], {
      env: { ...process.env, SUBJECT: script },
      encoding: 'utf8',
      timeout: 30000,
    });
    assert.equal(r.status, 0, `the process outlives its worker (signal ${r.signal})\n${r.stderr}`);
    assert.ok(!/open handles|uv_loop_close/.test(r.stderr), r.stderr);
    assert.equal(JSON.parse(r.stdout.trim()).status, 200, 'the worker served a request once descriptors were back');
  });

  it('a process that process.exit()s with the server open exits 0 (no uv_loop_close abort)', T, () => {
    const script = `
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const sid = engine.serve({ onRequest(reqId) {}, onAborted() {} });
      engine.listen(sid, '127.0.0.1', 0);
      setTimeout(() => process.exit(0), 20);
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.ok(!/uv_loop_close|Assertion failed/.test(r.stderr), r.stderr);
  });

  // The delivery mode, batch dispatch and fast calls are switches of the
  // whole process, read from the environment. Every thread that loads the
  // engine runs its initialisation, and it used to read them again each
  // time: with the environment changed in between (process.env on the main
  // thread writes through), a worker's load rewrote what every other thread
  // was already running on - a thread with fast calls installed found
  // itself in the mode they must never be combined with.
  it('a worker that loads the engine later does not change the mode the process started in', T, () => {
    const script = `
      import { Worker } from 'node:worker_threads';
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const view = (p) => ({ notify: p.notify, asyncNotify: p.capabilities.asyncNotify, batch: p.capabilities.batchDispatch, fast: p.fastApi.reason });
      const before = view(engine.probe());
      process.env.MORO_ENGINE_NOTIFY = 'sync';
      process.env.MORO_ENGINE_BATCH = '0';
      process.env.MORO_ENGINE_FASTCALL = '0';
      const src = 'import { parentPort } from "node:worker_threads";' +
        'const { default: engine } = await import(' + JSON.stringify(${JSON.stringify(ENGINE_ENTRY)}) + ');' +
        'const p = engine.probe(); parentPort.postMessage({ notify: p.notify, asyncNotify: p.capabilities.asyncNotify, batch: p.capabilities.batchDispatch, fast: p.fastApi.reason });';
      const w = new Worker(new URL('data:text/javascript,' + encodeURIComponent(src)));
      const inWorker = await new Promise((resolve, reject) => { w.once('message', resolve); w.once('error', reject); });
      await w.terminate();
      console.log(JSON.stringify({ before, after: view(engine.probe()), inWorker }));
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      env: { ...process.env, MORO_ENGINE_NOTIFY: '', MORO_ENGINE_BATCH: '', MORO_ENGINE_FASTCALL: '' },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const { before, after, inWorker } = JSON.parse(r.stdout.trim());
    assert.equal(before.notify, 'deferred');
    assert.equal(before.batch, true);
    assert.deepEqual(after, before, 'the main thread is where it was');
    assert.deepEqual(inWorker, before, 'and the worker runs in the same mode');
  });

  // A supervisor that runs the engine only in worker threads and replaces a
  // worker that ended. Once the last thread holding the binary has gone the
  // platform may keep the library mapped (macOS does), and loading it again
  // then runs no static registration: the second worker was moved to the
  // other TLS binary, and the third could not load the engine at all
  // ("Module did not self-register"). The main thread here never loads it.
  it('a worker started after the last one ended loads the same binary again', T, () => {
    const script = `
      import { Worker } from 'node:worker_threads';
      const src = 'import { parentPort } from "node:worker_threads";' +
        'const { default: engine } = await import(' + JSON.stringify(${JSON.stringify(ENGINE_ENTRY)}) + ');' +
        'const p = engine.probe(); let port = 0;' +
        'if (p.ok) { const sid = engine.serve({ onRequest() {} }); port = engine.listen(sid, "127.0.0.1", 0); }' +
        'parentPort.postMessage({ ok: p.ok, listening: port > 0, tls: p.tls && p.tls.library, reason: p.tls && p.tls.reason });';
      const seen = [];
      for (let i = 0; i < 4; i++) {
        const w = new Worker(new URL('data:text/javascript,' + encodeURIComponent(src)));
        seen.push(await new Promise((resolve, reject) => { w.once('message', resolve); w.once('error', reject); }));
        await w.terminate();
      }
      console.log(JSON.stringify(seen));
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const seen = JSON.parse(r.stdout.trim());
    assert.equal(seen.length, 4);
    for (const w of seen) assert.deepEqual(w, { ...seen[0], ok: true, listening: true }, JSON.stringify(seen));
  });

  // worker.terminate() ends the isolate under whatever handler is running.
  // That is not a handler that threw, and is not reported as one.
  it('a handler cut short by terminate() is not reported as having thrown', T, async () => {
    const script = `
      import net from 'node:net';
      import { Worker } from 'node:worker_threads';
      const src = 'import { parentPort } from "node:worker_threads";' +
        'const { default: engine } = await import(' + JSON.stringify(${JSON.stringify(ENGINE_ENTRY)}) + ');' +
        'const sid = engine.serve({ onRequest() { parentPort.postMessage("spinning"); for (;;) {} }, onAborted() {} });' +
        'parentPort.postMessage({ port: engine.listen(sid, "127.0.0.1", 0) });';
      const w = new Worker(new URL('data:text/javascript,' + encodeURIComponent(src)));
      const { port } = await new Promise((resolve) => w.once('message', resolve));
      const s = net.connect(port, '127.0.0.1', () => s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n'));
      s.on('error', () => {});
      await new Promise((resolve) => w.once('message', resolve));
      await w.terminate();
      s.destroy();
      console.log('terminated');
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 20000 });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.equal(r.stdout.trim(), 'terminated');
    assert.ok(!/threw/.test(r.stderr), r.stderr);
  });
});
