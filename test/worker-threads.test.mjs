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

  it('two workers share one port with reusePort and both serve', T, async () => {
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
});
