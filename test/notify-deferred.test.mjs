// Deferred-notification suite for @morojs/engine.
//
// onAborted / onWritable are delivered on a later loop turn, never
// re-entrantly from inside a binding call. Before 1.2 a write failure or a
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
