// Deferred-notification suite for @morojs/engine.
//
// onAborted / onWritable are delivered on a later loop turn, never
// re-entrantly from inside a binding call. Before 1.1.6 a write failure or a
// responseBackpressureLimit trip inside respond()/write() reached onAborted
// synchronously, in the middle of the very call that failed - which is also
// what makes those entry points ineligible for V8 fast API calls (a fast
// callback must never call back into JS).
//
//   - respond() tripping responseBackpressureLimit: onAborted fires AFTER the
//     call returned, exactly once, and isAborted(reqId) is already true inside it
//   - the same through streaming write()
//   - the same over TLS
//   - engine.close() with an in-flight request delivers onAborted BEFORE
//     close() returns (the adapter drops its routing table right after)
//   - onWritable then onAborted arrive in order, neither re-entrantly
//   - MORO_ENGINE_NOTIFY=sync restores the old mode and is reported by probe()
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadEngine, waitFor } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — deferred-notification suite skipped';

const T = { timeout: 30000 };
// The cap-trip tests drive outbound backpressure over loopback; Windows'
// loopback buffers absorb the 32 MiB whole (same skip as the hardening suite).
const notifyMode = engine ? engine.probe().notify : 'deferred';
const TCAP = {
  ...T,
  skip:
    process.platform === 'win32'
      ? 'loopback absorbs the payload on Windows'
      : notifyMode === 'sync'
        ? 'MORO_ENGINE_NOTIFY=sync: re-entrant delivery is the documented behaviour of this mode'
        : false,
};
const CRLF = '\r\n';
const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url);
const tlsFixture = (n) => fileURLToPath(new URL(`./fixtures/tls/${n}`, import.meta.url));

// A server whose callbacks record, with a caller-supplied phase label, WHEN
// they ran relative to the binding call under test.
function serveTracked(onRequest, options = {}) {
  const state = { phase: 'idle', events: [], abortedInside: null, writableInside: null };
  const sid = engine.serve(
    {
      onRequest(reqId, methodIdx, path) {
        onRequest(reqId, methodIdx, path, state);
      },
      onAborted(reqId) {
        state.events.push(['aborted', reqId, state.phase, engine.isAborted(reqId)]);
      },
      onWritable(reqId) {
        state.events.push(['writable', reqId, state.phase]);
      },
    },
    options
  );
  const port = engine.listen(sid, '127.0.0.1', 0);
  return { sid, port, state, close: () => engine.close(sid) };
}

// A client that connects, PAUSES its socket (so the server's writes stall in
// the kernel buffers), and sends one request. Resolves with the socket once
// the request is written; the caller destroys it after observing the shed.
// (A paused peer whose receive buffer is full never reads the server's FIN,
// so waiting for a client-side 'close' would hang - the hardening suite's
// cap test has the same shape.)
function pausedClient(port, { tlsMode = false } = {}) {
  return new Promise((resolve, reject) => {
    const req = `GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;
    const onReady = (socket) => {
      socket.pause();
      socket.write(req, (err) => (err ? reject(err) : resolve(socket)));
    };
    const socket = tlsMode
      ? tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false }, () => onReady(socket))
      : net.connect({ host: '127.0.0.1', port }, () => onReady(socket));
    socket.on('error', () => {}); // ECONNRESET on a shed connection is the expected outcome
  });
}

describe('deferred onAborted / onWritable delivery', { skip }, () => {
  it('a respond() that trips responseBackpressureLimit delivers onAborted after the call, not inside it', TCAP, async () => {
    // 32 MiB, like the hardening suite's cap test: loopback kernel buffers
    // absorb a few MiB without the outbound queue ever crossing the cap.
    const body = 'x'.repeat(32 * 1024 * 1024);
    const srv = serveTracked((reqId, _m, _p, state) => {
      // Respond from a fresh turn so the call is the only thing on the stack.
      setImmediate(() => {
        state.phase = 'inside-respond';
        engine.respond(reqId, 200, null, body);
        state.phase = 'after-respond';
      });
    }, { responseBackpressureLimit: 64 * 1024 });
    try {
      const client = await pausedClient(srv.port);
      await waitFor(() => srv.state.events.some((e) => e[0] === 'aborted'), { timeout: 10000, message: 'no onAborted' });
      await new Promise((r) => setTimeout(r, 50)); // let any (wrong) duplicate arrive
      client.destroy();
      const aborts = srv.state.events.filter((e) => e[0] === 'aborted');
      assert.equal(aborts.length, 1, `exactly one onAborted, got ${JSON.stringify(srv.state.events)}`);
      assert.equal(aborts[0][2], 'after-respond', 'onAborted must not run inside respond()');
      assert.equal(aborts[0][3], true, 'isAborted(reqId) is already true when onAborted runs');
    } finally {
      srv.close();
    }
  });

  it('the same through streaming write(): the failing write() returns before onAborted runs', TCAP, async () => {
    const chunk = 'y'.repeat(64 * 1024);
    const srv = serveTracked((reqId, _m, _p, state) => {
      setImmediate(() => {
        engine.writeHead(reqId, 200, ['content-type', 'text/plain']);
        for (let i = 0; i < 512; i++) {
          state.phase = `inside-write-${i}`;
          engine.write(reqId, chunk);
          state.phase = `after-write-${i}`;
          if (engine.isAborted(reqId)) break; // the engine shed the connection
        }
        state.phase = 'after-loop';
      });
    }, { responseBackpressureLimit: 64 * 1024 });
    try {
      const client = await pausedClient(srv.port);
      await waitFor(() => srv.state.events.some((e) => e[0] === 'aborted'), { timeout: 10000, message: 'no onAborted' });
      await new Promise((r) => setTimeout(r, 50));
      client.destroy();
      const aborts = srv.state.events.filter((e) => e[0] === 'aborted');
      assert.equal(aborts.length, 1, JSON.stringify(srv.state.events));
      assert.ok(!aborts[0][2].startsWith('inside-write'), `onAborted ran inside write(): ${aborts[0][2]}`);
      // The shed happened inside the loop (isAborted broke it) - after-loop
      // or a later phase is the only acceptable delivery point.
      assert.ok(
        aborts[0][2] === 'after-loop' || aborts[0][2].startsWith('after-write'),
        `unexpected phase ${aborts[0][2]}`
      );
    } finally {
      srv.close();
    }
  });

  it('over TLS the shed inside respond() is delivered deferred as well', TCAP, async () => {
    const info = engine.probe();
    if (!info.capabilities?.tls) return; // TLS-less build: nothing to test
    const body = 'z'.repeat(32 * 1024 * 1024);
    const srv = serveTracked(
      (reqId, _m, _p, state) => {
        setImmediate(() => {
          state.phase = 'inside-respond';
          engine.respond(reqId, 200, null, body);
          state.phase = 'after-respond';
        });
      },
      {
        responseBackpressureLimit: 64 * 1024,
        ssl: { key_file_name: tlsFixture('localhost.key'), cert_file_name: tlsFixture('localhost.pem') },
      }
    );
    try {
      const client = await pausedClient(srv.port, { tlsMode: true });
      await waitFor(() => srv.state.events.some((e) => e[0] === 'aborted'), { timeout: 10000, message: 'no onAborted' });
      await new Promise((r) => setTimeout(r, 50));
      client.destroy();
      const aborts = srv.state.events.filter((e) => e[0] === 'aborted');
      assert.equal(aborts.length, 1, JSON.stringify(srv.state.events));
      assert.equal(aborts[0][2], 'after-respond');
    } finally {
      srv.close();
    }
  });

  it('engine.close() with an in-flight request delivers its onAborted before close() returns', T, async () => {
    let seenReq = null;
    const srv = serveTracked((reqId) => {
      seenReq = reqId; // never answered
    });
    const socket = net.connect({ host: '127.0.0.1', port: srv.port }, () => {
      socket.write(`GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
    });
    socket.on('error', () => {});
    try {
      await waitFor(() => seenReq !== null, { timeout: 10000, message: 'request never surfaced' });
      assert.equal(srv.state.events.length, 0, 'nothing delivered before close()');
      srv.state.phase = 'inside-close';
      engine.close(srv.sid);
      srv.state.phase = 'after-close';
      const aborts = srv.state.events.filter((e) => e[0] === 'aborted');
      assert.equal(aborts.length, 1, 'onAborted must already have run when close() returns');
      assert.equal(aborts[0][1], seenReq);
      assert.equal(aborts[0][2], 'inside-close');
    } finally {
      socket.destroy();
    }
  });

  it('onWritable then onAborted arrive in order, each from its own turn', T, async () => {
    const chunk = 'w'.repeat(64 * 1024);
    const srv = serveTracked((reqId, _m, _p, state) => {
      setImmediate(() => {
        engine.writeHead(reqId, 200, ['content-type', 'text/plain']);
        let i = 0;
        state.phase = 'inside-write';
        while (i < 256 && engine.write(reqId, chunk)) i++;
        state.phase = i < 256 ? 'backpressured' : 'never-backpressured';
        // Deliberately never end(): the client's disconnect must abort it.
      });
    }, { writeHighWaterMark: 1024 });
    try {
      let bytes = 0;
      const socket = net.connect({ host: '127.0.0.1', port: srv.port }, () => {
        socket.pause();
        socket.write(`GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      });
      socket.on('data', (d) => {
        bytes += d.length;
      });
      socket.on('error', () => {});
      // Loopback: the kernel drains part of the queue on its own, so the first
      // onWritable may arrive before the client reads a byte in JS. Resume
      // once backpressure was reported, read something, then disconnect.
      await waitFor(() => srv.state.phase === 'backpressured' || srv.state.phase === 'never-backpressured', { timeout: 10000, message: 'write loop never ran' });
      assert.equal(srv.state.phase, 'backpressured', 'write() must have reported backpressure');
      socket.resume();
      await waitFor(() => srv.state.events.some((e) => e[0] === 'writable'), { timeout: 10000, message: 'no onWritable' });
      await waitFor(() => bytes > 0, { timeout: 10000, message: 'client read nothing' });
      srv.state.phase = 'after-drain';
      socket.destroy(); // EOF at the server -> onAborted
      await waitFor(() => srv.state.events.some((e) => e[0] === 'aborted'), { timeout: 10000, message: 'no onAborted' });
      const kinds = srv.state.events.map((e) => e[0]);
      // Several onWritable edges may precede the abort (each drain is one);
      // none may run inside write(), and the abort must come last.
      assert.ok(kinds.length >= 2 && kinds.at(-1) === 'aborted' && kinds.slice(0, -1).every((k) => k === 'writable'), JSON.stringify(srv.state.events));
      for (const e of srv.state.events) if (e[0] === 'writable') assert.notEqual(e[2], 'inside-write', 'onWritable never runs inside write()');
      assert.equal(srv.state.events.at(-1)[2], 'after-drain');
      assert.ok(bytes > 0, 'the client drained some bytes');
    } finally {
      srv.close();
    }
  });

  it('probe() reports the delivery mode; MORO_ENGINE_NOTIFY=sync restores re-entrant delivery', T, () => {
    const script = `
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY.href)});
      const p = engine.probe();
      console.log(JSON.stringify({ notify: p.notify, asyncNotify: p.capabilities?.asyncNotify }));
    `;
    const run = (env) =>
      JSON.parse(
        spawnSync(process.execPath, ['--input-type=module', '-e', script], {
          env: { ...process.env, ...env },
          encoding: 'utf8',
        }).stdout.trim()
      );
    assert.deepEqual(run({ MORO_ENGINE_NOTIFY: '' }), { notify: 'deferred', asyncNotify: true });
    assert.deepEqual(run({ MORO_ENGINE_NOTIFY: 'sync' }), { notify: 'sync', asyncNotify: false });
  });
});

// A request is released before its handler is told that it is aborted, in
// either delivery mode: inside onAborted, and in whatever the handler does
// when that wakes it, isAborted() is true and no write is taken. Told first,
// which only delivery in place (MORO_ENGINE_NOTIFY=sync) could show, a
// streaming handler waiting for room looked again, found its request alive
// and its write refused for backpressure, and waited for an onWritable that
// could not come. Each mode in a process of its own, on every way a request
// can be aborted from outside: the client goes away, and the server closes.
describe('an aborted request is released before its handler is told', { skip }, () => {
  const subject = `
    import net from 'node:net';
    const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY.href)});
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    async function scenario(how) {
      const waiters = new Map();
      const seen = { inside: null, finished: false, writes: 0, afterAbort: null };
      const wake = (reqId) => { const w = waiters.get(reqId); if (w) { waiters.delete(reqId); w(); } };
      const sid = engine.serve({
        async onRequest(reqId) {
          engine.writeHead(reqId, 200, null);
          const piece = Buffer.alloc(65536, 0x73);
          while (!engine.isAborted(reqId) && seen.writes < 4000) {
            seen.writes++;
            if (!engine.write(reqId, piece)) await new Promise((r) => waiters.set(reqId, r));
          }
          seen.finished = true;
          seen.afterAbort = engine.isAborted(reqId);
          engine.end(reqId);
        },
        onAborted(reqId) { seen.inside = engine.isAborted(reqId); wake(reqId); },
        onWritable(reqId) { wake(reqId); },
      });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const s = net.connect(port, '127.0.0.1');
      s.on('error', () => {});
      s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n');
      s.pause();
      for (let i = 0; i < 300 && waiters.size === 0; i++) await sleep(10);  // the handler is waiting for room
      // ... and stays waiting: the kernel holds what it wrote. (Where the
      // peer's not reading never holds the writer up, as on Windows
      // loopback, a wait is only the moment a write is still on its way.)
      const writesBefore = seen.writes;
      await sleep(200);
      const waiting = waiters.size === 1 && seen.writes === writesBefore;
      if (how === 'client') s.destroy();
      else engine.close(sid);
      for (let i = 0; i < 200 && !seen.finished; i++) await sleep(10);
      s.destroy();
      if (how === 'client') engine.close(sid);
      return { how, waiting, ...seen };
    }
    const out = [await scenario('client'), await scenario('close')];
    console.log(JSON.stringify({ notify: engine.probe().notify, out }));
  `;
  for (const mode of ['deferred', 'sync']) {
    it(`a streaming handler waiting for room finishes when its request is aborted (${mode} delivery)`, T, (t) => {
      const r = spawnSync(process.execPath, ['--input-type=module', '-e', subject], {
        env: { ...process.env, MORO_ENGINE_NOTIFY: mode === 'sync' ? 'sync' : '' },
        encoding: 'utf8',
        timeout: 25000,
      });
      assert.equal(r.status, 0, r.stderr.slice(0, 2000));
      const res = JSON.parse(r.stdout.trim().split('\n').pop());
      assert.equal(res.notify, mode);
      if (process.platform === 'win32' && res.out.some((o) => !o.waiting)) {
        // A handler never waits for room there: the scenario cannot be set up.
        t.skip('outbound backpressure is not reproducible on Windows loopback');
        return;
      }
      for (const o of res.out) {
        assert.ok(o.waiting, `${o.how}: the handler was waiting for room when its request was aborted`);
        assert.equal(o.inside, true, `${o.how}: isAborted() inside onAborted`);
        assert.ok(o.finished, `${o.how}: the handler finished (after ${o.writes} writes)`);
        assert.equal(o.afterAbort, true, `${o.how}: isAborted() when the handler looked again`);
      }
    });
  }
});

// A response body given as bytes (an ArrayBuffer, a typed array, a Buffer) is
// read where the application has it. With delivery in place a handler runs
// inside the call that ends its connection, and may let go of that memory
// there (ArrayBuffer.prototype.transfer): the call has to be done with the
// bytes by then. write() without writeHead() sends the head first, and when
// the head was what ended the connection - it took the connection over
// responseBackpressureLimit, or the TLS session could not encrypt it - the
// body was still read afterwards. A build with the sanitizers is what sees
// such a read.
describe('a body is not read after its handler was told of the abort (delivery in place)', { skip }, () => {
  const subject = `
    import net from 'node:net';
    import tls from 'node:tls';
    const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY.href)});
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const ssl = { key_file_name: ${JSON.stringify(tlsFixture('localhost.key'))}, cert_file_name: ${JSON.stringify(tlsFixture('localhost.pem'))} };
    // Requests answered with write(body) - no writeHead() - and end(). 'limit':
    // pipelined, to a client that reads nothing, until the response limit
    // closes the connection - from inside one of the calls, and then as
    // likely as not the one that writes a head. 'fault': the session refuses
    // to encrypt the head (builds with fault points).
    async function round(how) {
      const seen = { how, aborted: 0, insideWrite: 0, wrote: null, requests: 0, closed: false };
      let current = null;
      const sid = engine.serve({
        onRequest(reqId) {
          seen.requests++;
          if (seen.aborted) return;
          const body = new Uint8Array(new ArrayBuffer(100));
          current = body;
          if (how === 'fault') process.env.MORO_ENGINE_TEST_FAIL_TLS_WRITE = '1';
          const wrote = engine.write(reqId, body);
          delete process.env.MORO_ENGINE_TEST_FAIL_TLS_WRITE;
          current = null;
          if (body.buffer.detached) seen.wrote = wrote;   // told inside write()
          else engine.end(reqId);
        },
        onAborted() {
          seen.aborted++;
          if (current) { seen.insideWrite++; current.buffer.transfer(0); }
        },
        onWritable() {},
      }, how === 'fault' ? { ssl } : { responseBackpressureLimit: 2048 });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const s = how === 'fault' ? tls.connect({ port, host: '127.0.0.1', rejectUnauthorized: false }) : net.connect(port, '127.0.0.1');
      s.on('error', () => {});
      s.on('close', () => { seen.closed = true; });
      await new Promise((r) => s.once(how === 'fault' ? 'secureConnect' : 'connect', r));
      if (how === 'limit') s.pause();
      else s.resume();
      s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n'.repeat(how === 'limit' ? 120000 : 1));
      // Until the handler is told, the client sees the connection go, or -
      // a client that is not reading may never see that - no request has
      // arrived for a while.
      let last = 0, since = Date.now();
      for (let i = 0; i < 1200 && !seen.aborted && !seen.closed; i++) {
        await sleep(5);
        if (seen.requests !== last) { last = seen.requests; since = Date.now(); }
        else if (last > 0 && Date.now() - since > 300) break;
      }
      await sleep(20);
      s.destroy();
      engine.close(sid);
      return seen;
    }
    const out = [];
    if (engine.probe().testFaults) out.push(await round('fault'));
    if (process.platform !== 'win32') for (let i = 0; i < 3; i++) out.push(await round('limit'));
    console.log(JSON.stringify({ notify: engine.probe().notify, out }));
  `;
  it('write() without writeHead(): the head ends the connection and the body is left alone', T, () => {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', subject], {
      env: { ...process.env, MORO_ENGINE_NOTIFY: 'sync' },
      encoding: 'utf8',
      timeout: 25000,
    });
    assert.equal(r.status, 0, `the process ended with ${r.signal ?? r.status}: ${r.stderr.slice(0, 3000)}`);
    const res = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(res.notify, 'sync');
    for (const o of res.out) {
      assert.ok(o.aborted <= 1 && o.requests > 0, `${o.how}: ${JSON.stringify(o)}`);
      if (o.how !== 'fault') continue;
      assert.deepEqual(
        { aborted: o.aborted, insideWrite: o.insideWrite, wrote: o.wrote },
        { aborted: 1, insideWrite: 1, wrote: false },
        'the handler was told inside write(), which wrote nothing and says so'
      );
    }
  });
});
