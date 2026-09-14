// Batched pipelined dispatch for @morojs/engine (capabilities.batchDispatch).
//
// A server that registers onRequestBatch receives complete pipelined
// requests as ONE call with descriptors in getBatchBuffers(); it answers
// them in order, following the control cell. This suite proves:
//   - wire parity: pipelined x20 through the batch loop is byte-identical to
//     the same requests answered one by one through onRequest
//   - the loop stops at the first async handler and the remaining slots are
//     delivered later, none dropped, none duplicated, in order
//   - a client abort mid-batch fires exactly one onAborted (the active slot)
//   - HEAD, Connection: close and HTTP/1.0 inside a batch keep their framing
//   - an Upgrade request ends a batch; the WebSocket still comes up and early
//     frames are delivered
//   - Expect: 100-continue behind a batch gets its interim response after
//     the batched responses, and a parse error behind a batch answers 400
//     after them (wire order holds)
//   - a throwing handler does not stall the rest of the batch
//   - more than 16 pipelined requests (the staging cap) and long/uncacheable
//     paths (getPath) all arrive
//   - static routes are answered inside the batch without reaching JS
//   - MORO_ENGINE_BATCH=0 turns the capability off (child process)
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { loadEngine, waitFor } from './helpers.mjs';

const engine = await loadEngine();
const caps = engine ? engine.probe().capabilities : {};
const skip = !engine
  ? '@morojs/engine native binding not usable yet — batch-dispatch suite skipped'
  : !caps.batchDispatch
    ? 'batch dispatch off (MORO_ENGINE_BATCH=0) — batch-dispatch suite skipped'
    : false;
const T = { timeout: 30000 };
const CRLF = '\r\n';
const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;
const NO_PATH = 0xffffffff;

const stripDate = (s) => s.replace(/^date: [^\r\n]*\r\n/gim, '');
const req = (path, { method = 'GET', close = false, version = '1.1', extra = '' } = {}) =>
  `${method} ${path} HTTP/${version}${CRLF}Host: t${CRLF}${extra}${close ? `Connection: close${CRLF}` : ''}${CRLF}`;

// A server whose handler is shared between the two dispatch modes. `batch`
// installs onRequestBatch with the canonical loop; every dispatch (either
// mode) goes through `handle(reqId, method, path)`.
function serveWith(handle, { batch, onAborted = () => {}, ...rest } = {}) {
  const log = { batches: [], dispatched: [] };
  const callbacks = {
    onRequest(reqId, m, path) {
      log.dispatched.push(path);
      handle(reqId, m, path);
    },
    onAborted(reqId) {
      onAborted(reqId);
    },
    onWritable() {},
    onWsOpen() {},
    onWsMessage(wsId, data, isBinary) {
      engine.wsSend(wsId, data, isBinary);
    },
    onWsClose() {},
  };
  let buffers = null;
  if (batch) {
    callbacks.onRequestBatch = (count) => {
      const { descriptors: d, control: ctl, paths } = buffers;
      log.batches.push(count);
      let i = 0;
      for (;;) {
        const reqId = d[3 * i];
        const m = d[3 * i + 1];
        const pi = d[3 * i + 2];
        const path = pi === NO_PATH ? engine.getPath(reqId) : paths[pi];
        log.dispatched.push(path);
        try {
          handle(reqId, m, path);
        } catch (e) {
          if (!/boom/.test(String(e))) throw e;
          engine.respond(reqId, 500, null, 'threw');
        }
        const next = ctl[0];
        if (next === i) return i + 1;  // async: the engine did not activate the next slot
        if (next >= count) return count;
        i = next;
      }
    };
  }
  const sid = engine.serve(callbacks, Object.keys(rest).length ? rest : undefined);
  if (batch) buffers = engine.getBatchBuffers(sid);
  const port = engine.listen(sid, '127.0.0.1', 0);
  return { sid, port, log, close: () => engine.close(sid) };
}

// Write `bytes` (possibly in several chunks with pauses) and collect the
// stream until the server closes or `until(buffered)` holds.
function exchange(port, chunks, { until = null, timeout = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1');
    let buf = '';
    let i = 0;
    const next = () => {
      if (i >= chunks.length) return;
      const c = chunks[i++];
      if (typeof c === 'number') return void setTimeout(next, c);
      sock.write(Buffer.isBuffer(c) ? c : Buffer.from(c, 'latin1'));
      next();
    };
    sock.on('connect', next);
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (until && until(buf)) {
        sock.destroy();
        resolve(buf);
      }
    });
    sock.on('close', () => resolve(buf));
    sock.on('error', () => {});
    sock.setTimeout(timeout, () => {
      sock.destroy();
      reject(new Error(`timeout; got ${buf.length} bytes`));
    });
  });
}
const responses = (n) => (buf) => (buf.match(/HTTP\/1\.[01] \d{3}/g) || []).length >= n;
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// The reference handler: sync JSON for /sync/*, async for /async/*, HEAD-able,
// throws on /throw, streams on /stream.
function handler(reqId, m, path) {
  if (path.startsWith('/async/')) {
    setTimeout(() => engine.respond(reqId, 200, ['content-type', 'text/plain'], 'async:' + path), 5);
    return;
  }
  if (path === '/throw') throw new Error('boom');
  if (path === '/stream') {
    engine.writeHead(reqId, 200, ['content-type', 'text/plain']);
    engine.write(reqId, 'a');
    engine.end(reqId, 'b');
    return;
  }
  if (path === '/nocontent') return engine.respond(reqId, 204, null, null);
  if (path === '/ws') {
    if (engine.upgradeToWebSocket(reqId) === -1) engine.respond(reqId, 400, null, 'no');
    return;
  }
  engine.respond(reqId, 200, ['content-type', 'text/plain'], 'sync:' + path + ':' + engine.getMethod(reqId));
}

describe('batched pipelined dispatch', { skip }, () => {
  it('pipelined x20 through the batch loop is byte-identical to one-by-one dispatch', T, async () => {
    const seq = serveWith(handler, { batch: false });
    const bat = serveWith(handler, { batch: true });
    try {
      const paths = [];
      for (let i = 0; i < 20; i++) paths.push(i % 4 === 3 ? `/nocontent` : `/sync/${i}`);
      const bytes = paths.map((p, i) => req(p, { close: i === 19 })).join('');
      const a = stripDate(await exchange(seq.port, [bytes]));
      const b = stripDate(await exchange(bat.port, [bytes]));
      assert.equal(b, a);
      assert.equal((b.match(/HTTP\/1\.1 /g) || []).length, 20);
      assert.deepEqual(bat.log.dispatched, paths);
      assert.ok(bat.log.batches.length >= 1 && bat.log.batches.length < 20, `batches: ${bat.log.batches}`);
    } finally {
      seq.close();
      bat.close();
    }
  });

  it('stops at the first async handler; the rest arrive later, in order, once', T, async () => {
    const bat = serveWith(handler, { batch: true });
    try {
      const paths = ['/sync/0', '/sync/1', '/async/2', '/sync/3', '/async/4', '/sync/5', '/sync/6'];
      const bytes = paths.map((p, i) => req(p, { close: i === paths.length - 1 })).join('');
      const raw = stripDate(await exchange(bat.port, [bytes]));
      const bodies = raw.split(CRLF + CRLF).slice(1).map((s) => s.split('HTTP/1.1')[0]);
      assert.deepEqual(bodies, ['sync:/sync/0:GET', 'sync:/sync/1:GET', 'async:/async/2', 'sync:/sync/3:GET', 'async:/async/4', 'sync:/sync/5:GET', 'sync:/sync/6:GET']);
      assert.deepEqual(bat.log.dispatched, paths);
      // First call carried every slot; the loop stopped at the async one, and
      // the two resumes each carried the remainder.
      assert.equal(bat.log.batches[0], 7);
      assert.deepEqual(bat.log.batches, [7, 4, 2]);
    } finally {
      bat.close();
    }
  });

  it('a client abort mid-batch fires exactly one onAborted, for the active request', T, async () => {
    const aborted = [];
    // The client goes away the moment /async/1 becomes the ACTIVE request:
    // its handler destroys the socket instead of answering. Deterministic on
    // every platform - a fixed 2 ms delay raced the server's read on a
    // loaded Windows runner (the reset arrived before the request bytes were
    // read, Windows discards unread data on RST, nothing was dispatched, so
    // there was no active request to abort), and a poll after the fact
    // misses the 5 ms window before the async handler answers.
    let s;
    const bat = serveWith(
      (reqId, m, path) => {
        if (path === '/async/1') {
          s.destroy();
          return;  // never answered: the abort is the only way this request ends
        }
        handler(reqId, m, path);
      },
      { batch: true, onAborted: (id) => aborted.push(id) }
    );
    try {
      const bytes = [req('/sync/0'), req('/async/1'), req('/sync/2'), req('/sync/3')].join('');
      s = net.connect(bat.port, '127.0.0.1', () => s.write(bytes));
      s.on('error', () => {});
      await waitFor(() => aborted.length >= 1, { message: 'no onAborted for the active request' });
      await delay(20);  // room for a second (wrong) notification to show up
      assert.equal(aborted.length, 1, JSON.stringify(aborted));
    } finally {
      bat.close();
    }
  });

  it('HEAD, Connection: close and HTTP/1.0 keep their framing inside a batch', T, async () => {
    const seq = serveWith(handler, { batch: false });
    const bat = serveWith(handler, { batch: true });
    try {
      for (const bytes of [
        req('/sync/a') + req('/sync/b', { method: 'HEAD' }) + req('/sync/c', { close: true }),
        req('/sync/a') + req('/sync/b', { version: '1.0' }),
        req('/sync/a') + req('/sync/b', { close: true }) + req('/sync/never'),
      ]) {
        const a = stripDate(await exchange(seq.port, [bytes]));
        const b = stripDate(await exchange(bat.port, [bytes]));
        assert.equal(b, a);
      }
      assert.ok(!bat.log.dispatched.includes('/sync/never'), 'nothing after Connection: close is dispatched');
    } finally {
      seq.close();
      bat.close();
    }
  });

  it('an Upgrade request ends the batch; the WebSocket comes up and early frames are echoed', T, async () => {
    const bat = serveWith(handler, { batch: true });
    try {
      const key = crypto.randomBytes(16).toString('base64');
      const upgrade = `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`;
      // masked text frame "hi" right behind the handshake
      const frame = Buffer.from([0x81, 0x82, 1, 2, 3, 4, 'h'.charCodeAt(0) ^ 1, 'i'.charCodeAt(0) ^ 2]);
      const raw = await exchange(bat.port, [req('/sync/0') + req('/sync/1') + upgrade, frame], {
        until: (b) => b.includes('\x81\x02hi'),
      });
      assert.equal((raw.match(/HTTP\/1\.1 200/g) || []).length, 2);
      assert.match(raw, /HTTP\/1\.1 101 /);
      assert.ok(raw.endsWith('\x81\x02hi'));
      assert.deepEqual(bat.log.dispatched, ['/sync/0', '/sync/1', '/ws']);
    } finally {
      bat.close();
    }
  });

  it('100-continue behind a batch is answered after the batched responses; a parse error behind a batch answers 400 after them', T, async () => {
    const bat = serveWith(handler, { batch: true });
    try {
      const post = `POST /sync/post HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 3${CRLF}Expect: 100-continue${CRLF}${CRLF}`;
      const raw = stripDate(
        await exchange(bat.port, [req('/sync/0') + req('/sync/1') + post, 30, 'xyz' + req('/sync/2', { close: true })])
      );
      const order = raw.match(/HTTP\/1\.1 \d{3}/g);
      assert.deepEqual(order, ['HTTP/1.1 200', 'HTTP/1.1 200', 'HTTP/1.1 100', 'HTTP/1.1 200', 'HTTP/1.1 200']);
      const raw2 = stripDate(await exchange(bat.port, [req('/sync/0') + req('/sync/1') + `GARBAGE${CRLF}${CRLF}`]));
      assert.deepEqual(raw2.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200', 'HTTP/1.1 200', 'HTTP/1.1 400']);
      // Head and body shipped together, twice in one batch: each request
      // still gets its interim 100, right before its own response.
      const together = `POST /sync/p HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 2${CRLF}Expect: 100-continue${CRLF}${CRLF}ab`;
      const raw3 = stripDate(await exchange(bat.port, [req('/sync/0') + together + together + req('/sync/9', { close: true })]));
      assert.deepEqual(raw3.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200', 'HTTP/1.1 100', 'HTTP/1.1 200', 'HTTP/1.1 100', 'HTTP/1.1 200', 'HTTP/1.1 200']);
    } finally {
      bat.close();
    }
  });

  it('a throwing handler does not stall the rest of the batch', T, async () => {
    const bat = serveWith(handler, { batch: true });
    try {
      const raw = stripDate(await exchange(bat.port, [req('/sync/0') + req('/throw') + req('/sync/2', { close: true })]));
      assert.deepEqual(raw.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200', 'HTTP/1.1 500', 'HTTP/1.1 200']);
    } finally {
      bat.close();
    }
  });

  it('more than 16 pipelined requests, streaming responses and uncacheable paths all arrive in order', T, async () => {
    const seq = serveWith(handler, { batch: false });
    const bat = serveWith(handler, { batch: true });
    try {
      const long = '/' + 'p'.repeat(200);  // > kPathCacheMaxLen: pathIdx 0xFFFFFFFF -> getPath()
      const paths = [];
      for (let i = 0; i < 40; i++) paths.push(i % 7 === 0 ? '/stream' : i % 11 === 0 ? long : `/sync/${i}`);
      const bytes = paths.map((p, i) => req(p, { close: i === 39 })).join('');
      const a = stripDate(await exchange(seq.port, [bytes]));
      const b = stripDate(await exchange(bat.port, [bytes]));
      assert.equal(b, a);
      assert.equal((b.match(/HTTP\/1\.1 200/g) || []).length, 40);
      assert.deepEqual(bat.log.dispatched, paths);
    } finally {
      seq.close();
      bat.close();
    }
  });

  it('static routes inside a batch are answered without reaching JS', T, async () => {
    const bat = serveWith(handler, { batch: true });
    try {
      engine.setStaticRoute(bat.sid, 0, '/static', 200, ['content-type', 'text/plain'], 'static!');
      const raw = stripDate(await exchange(bat.port, [req('/static') + req('/sync/1') + req('/static') + req('/sync/3', { close: true })]));
      const bodies = raw.split(CRLF + CRLF).slice(1).map((s) => s.split('HTTP/1.1')[0]);
      assert.deepEqual(bodies, ['static!', 'sync:/sync/1:GET', 'static!', 'sync:/sync/3:GET']);
      assert.deepEqual(bat.log.dispatched, ['/sync/1', '/sync/3']);
    } finally {
      bat.close();
    }
  });

  it('MORO_ENGINE_BATCH=0 turns the capability off and the server still serves pipelined requests', T, () => {
    const script = `
      import net from 'node:net';
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const p = engine.probe();
      let batchCalls = 0;
      const sid = engine.serve({
        onRequest(reqId, m, path) { engine.respond(reqId, 200, null, 'r:' + path); },
        onRequestBatch() { batchCalls++; return 0; },
        onAborted() {},
      });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const raw = await new Promise((res) => { const s = net.connect(port, '127.0.0.1', () => s.write('GET /a HTTP/1.1\\r\\nHost: t\\r\\n\\r\\nGET /b HTTP/1.1\\r\\nHost: t\\r\\nConnection: close\\r\\n\\r\\n')); let b=''; s.on('data', d => b += d); s.on('close', () => res(b)); });
      console.log(JSON.stringify({ cap: p.capabilities.batchDispatch, batchCalls, responses: (raw.match(/HTTP\\/1\\.1 200/g) || []).length }));
      engine.close(sid);
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      env: { ...process.env, MORO_ENGINE_BATCH: '0', MORO_ENGINE_REQUIRE_TRANSPORT: '' },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim()), { cap: false, batchCalls: 0, responses: 2 });
  });
});
