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
//   - a response sent from a microtask or nextTick of the batch call (after
//     JS left its loop) does not strand the requests staged behind it
//   - more than 16 pipelined requests (the staging cap) and long/uncacheable
//     paths (getPath) all arrive
//   - static routes are answered inside the batch without reaching JS
//   - MORO_ENGINE_BATCH=0 turns the capability off (child process)
//   - a WebSocket handshake the engine answers itself (setWsAutoUpgrade),
//     pipelined behind ordinary requests, opens the WebSocket once the batch
//     call has returned and is never handed to the HTTP handler as well
//     (child process: the server staying alive is part of what is asserted)
//   - a connection closed from inside the loop over its own batch ends the
//     loop: no slot of a connection that is gone reaches a handler
//   - across connections: a handler inside one connection's batch may answer,
//     write to or close a request that belongs to another connection (parked
//     earlier, a WebSocket, an HTTP/2 stream) and both batches stay intact
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import http2 from 'node:http2';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
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
const UPGRADE_SUBJECT = fileURLToPath(new URL('./batch-upgrade-subject.mjs', import.meta.url));

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

  it('a response sent from a microtask or nextTick of the batch call does not strand the requests behind it', T, async () => {
    // Microtasks and nextTicks run as the batch call's callback scope closes:
    // after JS has left its loop, before the engine is back in its own.
    const soon = (reqId, m, path) => {
      const send = () => engine.respond(reqId, 200, ['content-type', 'text/plain'], 'soon:' + path);
      if (path.startsWith('/micro/')) return void Promise.resolve().then(send);
      if (path.startsWith('/tick/')) return void process.nextTick(send);
      if (path.startsWith('/chain/')) return void Promise.resolve().then(() => process.nextTick(send));
      handler(reqId, m, path);
    };
    const seq = serveWith(soon, { batch: false });
    const bat = serveWith(soon, { batch: true });
    try {
      const paths = ['/micro/0', '/sync/1', '/tick/2', '/micro/3', '/chain/4', '/sync/5', '/async/6', '/micro/7', '/sync/8'];
      const bytes = paths.map((p, i) => req(p, { close: i === paths.length - 1 })).join('');
      const a = stripDate(await exchange(seq.port, [bytes]));
      const b = stripDate(await exchange(bat.port, [bytes]));
      assert.equal((b.match(/HTTP\/1\.1 200/g) || []).length, paths.length);
      assert.equal(b, a);
      // Every request reached a handler exactly once, in order.
      assert.deepEqual(bat.log.dispatched, paths);

      // The connection is not left marked busy: a later request on a fresh
      // pipelined pair is served too.
      const again = await exchange(bat.port, [req('/tick/a') + req('/sync/b', { close: true })]);
      assert.equal((again.match(/HTTP\/1\.1 200/g) || []).length, 2);
    } finally {
      seq.close();
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

  // The request-target rule belongs to the request line, so a batch sees it
  // where one-by-one dispatch does: the requests ahead are answered, the one
  // with no valid target is 400, and nothing behind it is read.
  it('a request whose target has no valid form ends a batch with 400, in both dispatch modes and behind an engine route', T, async () => {
    for (const batch of [true, false]) {
      const srv = serveWith(handler, { batch });
      try {
        engine.setStaticRoute(srv.sid, 0, '/static', 200, null, 'static!');
        for (const target of ['abc', '*x', '*?q', '?q']) {
          const raw = stripDate(await exchange(srv.port, [req('/sync/0') + req('/static') + req('/sync/2') + req(target) + req('/sync/never')]));
          assert.deepEqual(raw.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200', 'HTTP/1.1 200', 'HTTP/1.1 200', 'HTTP/1.1 400'], `${target} batch=${batch}`);
          assert.match(raw, /Connection: close\r\n\r\n$/);
        }
        assert.ok(!srv.log.dispatched.some((p) => !p.startsWith('/')), JSON.stringify(srv.log.dispatched));
        assert.ok(!srv.log.dispatched.includes('/sync/never'));
        // More of them than the staging ring has slots, and the valid forms among them.
        const many = [];
        for (let i = 0; i < 20; i++) many.push(req(`/sync/${i}`));
        const raw = stripDate(await exchange(srv.port, [many.join('') + req('http://t/abs') + req('*', { method: 'OPTIONS' }) + req('nope')]));
        assert.equal((raw.match(/HTTP\/1\.1 200/g) || []).length, 22);
        assert.equal((raw.match(/HTTP\/1\.1 400/g) || []).length, 1);
        assert.ok(raw.includes('sync:http://t/abs:GET') && raw.includes('sync:*:OPTIONS'));
      } finally {
        srv.close();
      }
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

  // ---- handshakes the engine answers itself, behind pipelined requests ----
  //
  // Upgrading calls into JS (onWsOpen, and onWsMessage for frames that came
  // with the handshake). The response call that completes the request ahead
  // of the handshake is the one place it must not happen: the binding may be
  // reading that response's body straight out of the V8 heap, where running
  // JS aborts the process. The handshake is upgraded once onRequestBatch has
  // returned, and JS's loop is told the batch is over instead of being handed
  // the handshake as one more slot.

  it('capabilities.wsAutoUpgradeBatch says engine-side upgrades are safe together with batch dispatch', T, () => {
    assert.equal(caps.wsAutoUpgradeBatch, true);
    assert.equal(caps.wsAutoUpgrade, true);
  });

  for (const bodyKind of ['string', 'buffer']) {
    it(`an Upgrade pipelined behind requests, upgraded by the engine itself, reaches onWsOpen only (${bodyKind} bodies)`, { timeout: 120000 }, () => {
      const r = spawnSync(process.execPath, [UPGRADE_SUBJECT, bodyKind], {
        env: { ...process.env, MORO_ENGINE_REQUIRE_TRANSPORT: '' },
        encoding: 'utf8',
        timeout: 110000,
      });
      assert.equal(r.signal, null, `the server process died with ${r.signal}\n${r.stderr.slice(0, 2000)}`);
      assert.equal(r.status, 0, r.stderr.slice(0, 2000));
      const { results } = JSON.parse(r.stdout.trim().split('\n').pop());
      // 2 dispatch modes x 3 ways of answering x 3 depths x 2 frame timings,
      // 2 with a static route in between, 6 handshakes the engine does not upgrade
      assert.equal(results.length, 44);
      for (const c of results) {
        if (c.kind === 'upgrade') {
          assert.equal(c.ok200, c.ahead, `${c.name}: every request ahead of the handshake is answered`);
          assert.equal(c.switched, 1, `${c.name}: the engine answered the handshake`);
          assert.equal(c.echoed, true, `${c.name}: the frame sent with (or after) the handshake is echoed`);
          assert.deepEqual(c.wsOpen, ['/ws'], `${c.name}: onWsOpen fired once`);
          assert.equal(c.wsMessages, 1, `${c.name}: the frame reached onWsMessage once`);
          assert.deepEqual(c.dispatched, c.paths, `${c.name}: the handshake is not handed to the HTTP handler`);
        } else {
          assert.deepEqual(c.statuses, c.expectedStatuses, `${c.name}: answered in order`);
          assert.deepEqual(c.wsOpen, [], `${c.name}: no WebSocket`);
          assert.deepEqual(c.dispatched, c.expected, `${c.name}: what reached the handler, once each and in order`);
        }
      }
    });
  }

  it('a connection closed from inside the loop over its own batch ends the loop', T, async () => {
    // The handler of the first slot answers and then closes the server. The
    // five requests staged behind it die with the connection: none of them
    // may reach a handler, before or after its onAborted.
    const aborted = [];
    const seen = [];
    let closed = false;
    let bat;
    bat = serveWith(
      (reqId, m, path) => {
        seen.push({ path, afterClose: closed });
        engine.respond(reqId, 200, ['content-type', 'text/plain'], 'own:' + path);
        if (!closed) {
          closed = true;
          bat.close();
        }
      },
      { batch: true, onAborted: (id) => aborted.push(id) }
    );
    const s = net.connect(bat.port, '127.0.0.1', () => s.write(Array.from({ length: 6 }, (_, i) => req(`/r${i}`)).join('')));
    s.on('error', () => {});
    try {
      await waitFor(() => closed, { message: 'the first slot never ran' });
      await delay(50);
      assert.deepEqual(seen, [{ path: '/r0', afterClose: false }], 'only the slot that closed the server reached a handler');
      assert.deepEqual(bat.log.batches, [6]);
      assert.ok(aborted.length <= 1, `at most the request that was active when the connection closed is reported: ${aborted}`);
    } finally {
      s.destroy();
    }
  });
});

// ---- across connections ----
//
// While JS is inside its loop over one connection's batch, a handler may
// answer, write to or close a request that belongs to ANOTHER connection (a
// request parked earlier, a WebSocket, an HTTP/2 stream). That must leave
// both batches exactly as they were: every slot dispatched once, in order,
// each response on its own connection, nothing stalled.

const text = (reqId, body) => engine.respond(reqId, 200, ['content-type', 'text/plain'], body);

// A batch server. `handle(reqId, path, ctx)`; ctx.parked maps a name to the
// reqId of a request that was left unanswered on purpose.
function serveAcross(handle, { http2: h2 = false, ws = {} } = {}) {
  const log = { batches: [], dispatched: [], aborted: [], wsOpen: [], wsClosed: [], cellJumps: [], releases: [] };
  // ctx.loop: the slot JS is at inside onRequestBatch, null outside the loop
  const ctx = { parked: new Map(), log, wsIds: [], loop: null };
  let buffers = null;
  const callbacks = {
    onRequest(reqId, m, path) {
      log.dispatched.push(path);
      handle(reqId, path, ctx);
    },
    onRequestBatch(count) {
      const { descriptors: d, control: ctl, paths } = buffers;
      log.batches.push(count);
      let i = 0;
      for (;;) {
        const reqId = d[3 * i];
        const pi = d[3 * i + 2];
        const path = pi === NO_PATH ? engine.getPath(reqId) : paths[pi];
        log.dispatched.push(path);
        ctx.loop = { slot: i, count };
        try {
          handle(reqId, path, ctx);
        } finally {
          ctx.loop = null;
        }
        const next = ctl[0];
        // The cell stays (the handler went async) or moves one slot forward.
        if (next !== i && next !== i + 1) log.cellJumps.push({ at: i, next, count });
        if (next === i) return i + 1;
        if (next >= count) return count;
        i = next;
      }
    },
    onAborted(reqId) {
      log.aborted.push(reqId);
    },
    onWritable() {},
    onWsOpen(wsId, path) {
      ctx.wsIds.push(wsId);
      log.wsOpen.push(path);
    },
    onWsMessage(wsId, data, isBinary) {
      if (ws.onMessage) ws.onMessage(wsId, data, isBinary, ctx);
    },
    onWsClose(wsId) {
      log.wsClosed.push(wsId);
    },
  };
  const sid = engine.serve(callbacks, h2 ? { http2: true } : undefined);
  buffers = engine.getBatchBuffers(sid);
  const port = engine.listen(sid, '127.0.0.1', 0);
  return { sid, port, log, ctx, close: () => engine.close(sid) };
}

// A raw client connection that keeps everything it receives.
function client(port) {
  const sock = net.connect(port, '127.0.0.1');
  const c = { sock, buf: '', closed: false };
  sock.on('data', (d) => (c.buf += d.toString('latin1')));
  sock.on('close', () => (c.closed = true));
  sock.on('error', () => {});
  c.ready = new Promise((r) => sock.on('connect', r));
  c.bodies = () => c.buf.split(/HTTP\/1\.1 \d{3} [^\r]*\r\n/).slice(1).map((r) => r.split(CRLF + CRLF)[1]);
  c.count = () => (c.buf.match(/HTTP\/1\.1 \d{3}/g) || []).length;
  return c;
}
const got = (c, n) => waitFor(() => c.count() >= n, { timeout: 5000, message: `fewer than ${n} responses` });

// The handler shared by the HTTP/1 tests.
//   /park/<name>            left unanswered, remembered under <name>
//   /answer-first/<name>    answers the parked request, then itself
//   /answer-after/<name>    answers itself, then the parked request
//   /answer-micro/<name>    answers itself, then the parked one from a microtask
//   anything else           answered at once with its own path
function across(reqId, path, ctx) {
  const [, verb, name] = path.split('/');
  const release = () => {
    const id = ctx.parked.get(name);
    if (id === undefined) return;
    ctx.log.releases.push(ctx.loop ? { ...ctx.loop } : 'outside the loop');
    text(id, 'parked:' + name);
  };
  if (verb === 'park') return void ctx.parked.set(name, reqId);
  if (verb === 'answer-first') {
    release();
    return void text(reqId, 'own:' + path);
  }
  if (verb === 'answer-after') {
    text(reqId, 'own:' + path);
    return void release();
  }
  if (verb === 'answer-micro') {
    text(reqId, 'own:' + path);
    return void Promise.resolve().then(release);
  }
  text(reqId, 'own:' + path);
}

describe('batched dispatch across connections', { skip }, () => {
  for (const verb of ['answer-first', 'answer-after', 'answer-micro']) {
    for (const where of [0, 1, 2]) {
      it(`HTTP/1: a parked request with two slots staged behind it, answered from slot ${where} of another connection's batch (${verb})`, T, async () => {
        const s = serveAcross(across);
        const b = client(s.port);
        const a = client(s.port);
        try {
          await Promise.all([a.ready, b.ready]);
          b.sock.write(req('/park/p') + req('/b/1') + req('/b/2'));
          await waitFor(() => s.ctx.parked.has('p'), { timeout: 5000 });
          await delay(30);
          assert.equal(b.count(), 0, 'nothing is answered on B while its first request is parked');
          const aPaths = ['/a/0', '/a/1', '/a/2', '/a/3'];
          aPaths[where] = `/${verb}/p`;
          a.sock.write(aPaths.map((p) => req(p)).join(''));
          await got(a, 4);
          await got(b, 3);
          assert.deepEqual(a.bodies(), aPaths.map((p) => 'own:' + p), 'A: its own four answers, in order');
          assert.deepEqual(b.bodies(), ['parked:p', 'own:/b/1', 'own:/b/2'], 'B: the parked answer, then its staged requests');
          assert.deepEqual([...s.log.dispatched].sort(), ['/park/p', '/b/1', '/b/2', ...aPaths].sort(), 'every request reached a handler exactly once');
          assert.deepEqual(s.log.cellJumps, [], 'the control cell only ever stays or moves one slot forward');
          // The answer really was sent from inside the loop over A's four-slot
          // batch (or, for the microtask form, after JS had left that loop).
          assert.deepEqual(s.log.releases, [verb === 'answer-micro' ? 'outside the loop' : { slot: where, count: 4 }]);
          // Neither connection is left busy.
          a.sock.write(req('/a/again'));
          b.sock.write(req('/b/again'));
          await got(a, 5);
          await got(b, 4);
          assert.equal(a.bodies()[4], 'own:/a/again');
          assert.equal(b.bodies()[3], 'own:/b/again');
        } finally {
          a.sock.destroy();
          b.sock.destroy();
          s.close();
        }
      });
    }
  }

  it('HTTP/1: a parked request with nothing behind it, answered from another batch; both connections go on', T, async () => {
    const s = serveAcross(across);
    const b = client(s.port);
    const a = client(s.port);
    try {
      await Promise.all([a.ready, b.ready]);
      b.sock.write(req('/park/q'));
      await waitFor(() => s.ctx.parked.has('q'), { timeout: 5000 });
      a.sock.write(req('/a/0') + req('/answer-first/q') + req('/a/2'));
      await got(a, 3);
      await got(b, 1);
      assert.deepEqual(a.bodies(), ['own:/a/0', 'own:/answer-first/q', 'own:/a/2']);
      assert.deepEqual(b.bodies(), ['parked:q']);
      b.sock.write(req('/b/1') + req('/b/2'));
      await got(b, 3);
      assert.deepEqual(b.bodies(), ['parked:q', 'own:/b/1', 'own:/b/2']);
      assert.deepEqual(s.log.cellJumps, []);
    } finally {
      a.sock.destroy();
      b.sock.destroy();
      s.close();
    }
  });

  it('HTTP/1: two connections that answer each other\'s parked request from inside their batches', T, async () => {
    const s = serveAcross(across);
    const a = client(s.port);
    const b = client(s.port);
    const c = client(s.port);
    try {
      await Promise.all([a.ready, b.ready, c.ready]);
      a.sock.write(req('/park/a') + req('/a/1') + req('/answer-first/b') + req('/a/3'));
      await waitFor(() => s.ctx.parked.has('a'), { timeout: 5000 });
      b.sock.write(req('/park/b') + req('/answer-after/a') + req('/b/2'));
      await waitFor(() => s.ctx.parked.has('b'), { timeout: 5000 });
      // C releases A; A's staged /answer-first/b then releases B, whose staged
      // /answer-after/a answers a request that is long gone (a no-op).
      c.sock.write(req('/c/0') + req('/answer-after/a') + req('/c/2'));
      await got(c, 3);
      await got(a, 4);
      await got(b, 3);
      assert.deepEqual(c.bodies(), ['own:/c/0', 'own:/answer-after/a', 'own:/c/2']);
      assert.deepEqual(a.bodies(), ['parked:a', 'own:/a/1', 'own:/answer-first/b', 'own:/a/3']);
      assert.deepEqual(b.bodies(), ['parked:b', 'own:/answer-after/a', 'own:/b/2']);
      assert.equal(s.log.dispatched.length, 10, 'ten requests, ten dispatches');
      assert.deepEqual(s.log.cellJumps, []);
    } finally {
      for (const x of [a, b, c]) x.sock.destroy();
      s.close();
    }
  });

  it('HTTP/1: the parked request\'s peer goes away in the same tick as the batch that answers it (x40)', T, async () => {
    const s = serveAcross(across);
    try {
      for (let round = 0; round < 40; round++) {
        const name = 'r' + round;
        const b = client(s.port);
        const a = client(s.port);
        await Promise.all([a.ready, b.ready]);
        b.sock.write(req('/park/' + name) + req('/b/1') + req('/b/2'));
        await waitFor(() => s.ctx.parked.has(name), { timeout: 5000 });
        // B's reset and A's batch reach the server together; which one the
        // loop sees first is up to the kernel, and both orders must hold.
        if (round % 2) {
          b.sock.resetAndDestroy();
          a.sock.write(req('/a/0') + req(`/answer-first/${name}`) + req('/a/2'));
        } else {
          a.sock.write(req('/a/0') + req(`/answer-first/${name}`) + req('/a/2'));
          b.sock.resetAndDestroy();
        }
        await got(a, 3);
        assert.deepEqual(a.bodies(), ['own:/a/0', `own:/answer-first/${name}`, 'own:/a/2'], `round ${round}`);
        a.sock.destroy();
      }
      await delay(100);
      assert.deepEqual(s.log.cellJumps, []);
      // B's staged requests are either never dispatched (it was gone first) or
      // dispatched once each (its answer went out first); never twice.
      const b1 = s.log.dispatched.filter((p) => p === '/b/1').length;
      const b2 = s.log.dispatched.filter((p) => p === '/b/2').length;
      assert.ok(b1 <= 40 && b2 <= b1, `/b/1 x${b1}, /b/2 x${b2}`);
      assert.ok(s.log.aborted.length <= 40, `at most one abort per parked request, saw ${s.log.aborted.length}`);
      // The server still serves.
      const z = client(s.port);
      await z.ready;
      z.sock.write(req('/z/0') + req('/z/1'));
      await got(z, 2);
      assert.deepEqual(z.bodies(), ['own:/z/0', 'own:/z/1']);
      z.sock.destroy();
    } finally {
      s.close();
    }
  });

  it('WebSocket: written to and closed from a batch loop; a parked request answered from a message callback', T, async () => {
    const wsHandle = (reqId, path, ctx) => {
      if (path === '/ws') return void engine.upgradeToWebSocket(reqId);
      if (path === '/ws-send') {
        engine.wsSend(ctx.wsIds[0], 'from-batch', false);
        return void text(reqId, 'own:' + path);
      }
      if (path === '/ws-close') {
        text(reqId, 'own:' + path);
        return void engine.wsClose(ctx.wsIds[0], 1000, 'bye');
      }
      across(reqId, path, ctx);
    };
    const s = serveAcross(wsHandle, {
      ws: {
        onMessage(wsId, data, isBinary, ctx) {
          // answer the request parked on B from inside the WebSocket's read
          const id = ctx.parked.get('w');
          if (id !== undefined) text(id, 'parked:w');
          engine.wsSend(wsId, data, isBinary);
        },
      },
    });
    const w = client(s.port);
    const a = client(s.port);
    const b = client(s.port);
    try {
      await Promise.all([w.ready, a.ready, b.ready]);
      const key = crypto.randomBytes(16).toString('base64');
      w.sock.write(`GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`);
      await waitFor(() => /HTTP\/1\.1 101 /.test(w.buf) && s.ctx.wsIds.length === 1, { timeout: 5000 });
      b.sock.write(req('/park/w') + req('/b/1') + req('/b/2'));
      await waitFor(() => s.ctx.parked.has('w'), { timeout: 5000 });
      // a masked text frame "hi": its callback answers B's parked request
      w.sock.write(Buffer.from([0x81, 0x82, 1, 2, 3, 4, 'h'.charCodeAt(0) ^ 1, 'i'.charCodeAt(0) ^ 2]));
      await got(b, 3);
      assert.deepEqual(b.bodies(), ['parked:w', 'own:/b/1', 'own:/b/2']);
      await waitFor(() => w.buf.includes('\x81\x02hi'), { timeout: 5000 });
      // now a batch on A that writes to the WebSocket from one slot and closes it from another
      a.sock.write(req('/a/0') + req('/ws-send') + req('/a/2') + req('/ws-close') + req('/a/4'));
      await got(a, 5);
      assert.deepEqual(a.bodies(), ['own:/a/0', 'own:/ws-send', 'own:/a/2', 'own:/ws-close', 'own:/a/4']);
      await waitFor(() => w.closed, { timeout: 5000 });
      assert.ok(w.buf.includes('\x81\x0afrom-batch'), 'the frame sent from the batch loop arrived on the WebSocket');
      assert.ok(!a.buf.includes('from-batch') && !b.buf.includes('from-batch'), 'and on no other connection');
      assert.deepEqual(s.log.cellJumps, []);
      assert.deepEqual(s.log.dispatched, ['/ws', '/park/w', '/b/1', '/b/2', '/a/0', '/ws-send', '/a/2', '/ws-close', '/a/4']);
    } finally {
      for (const x of [w, a, b]) x.sock.destroy();
      s.close();
    }
  });

  // HTTP/2 requests of one client session, sent in the same tick so that they
  // arrive in one read and form one batch.
  function h2Together(session, paths) {
    return Promise.all(
      paths.map(
        (p) =>
          new Promise((resolve, reject) => {
            const stream = session.request({ ':path': p });
            let body = '';
            stream.on('data', (d) => (body += d));
            stream.on('end', () => resolve(body));
            stream.on('error', reject);
            stream.end();
          })
      )
    );
  }

  it('HTTP/2: a parked HTTP/1 request (two slots staged behind it) answered from an HTTP/2 batch loop', T, async () => {
    const s = serveAcross(across, { http2: true });
    const session = http2.connect(`http://127.0.0.1:${s.port}`);
    session.on('error', () => {});
    const b = client(s.port);
    try {
      await b.ready;
      b.sock.write(req('/park/h') + req('/b/1') + req('/b/2'));
      await waitFor(() => s.ctx.parked.has('h'), { timeout: 5000 });
      const paths = ['/h/0', '/answer-first/h', '/h/2', '/h/3'];
      const bodies = await h2Together(session, paths);
      assert.deepEqual(bodies, paths.map((p) => 'own:' + p), 'each stream got its own answer');
      assert.deepEqual(s.log.releases, [{ slot: 1, count: 4 }], 'sent from slot 1 of a four-stream HTTP/2 batch');
      await got(b, 3);
      assert.deepEqual(b.bodies(), ['parked:h', 'own:/b/1', 'own:/b/2']);
      assert.deepEqual([...s.log.dispatched].sort(), ['/park/h', '/b/1', '/b/2', ...paths].sort(), 'every request dispatched exactly once');
      assert.deepEqual(s.log.cellJumps, []);
    } finally {
      session.destroy();
      b.sock.destroy();
      s.close();
    }
  });

  it('HTTP/2: a parked stream answered from an HTTP/1 batch loop, and from a later HTTP/2 batch on its own connection', T, async () => {
    const s = serveAcross(across, { http2: true });
    const session = http2.connect(`http://127.0.0.1:${s.port}`);
    session.on('error', () => {});
    const a = client(s.port);
    try {
      await a.ready;
      // first batch: a stream that parks between two that answer
      const first = h2Together(session, ['/h/0', '/park/s1', '/h/2']);
      await waitFor(() => s.ctx.parked.has('s1'), { timeout: 5000 });
      a.sock.write(req('/a/0') + req('/answer-first/s1') + req('/a/2'));
      await got(a, 3);
      assert.deepEqual(a.bodies(), ['own:/a/0', 'own:/answer-first/s1', 'own:/a/2']);
      assert.deepEqual(await first, ['own:/h/0', 'parked:s1', 'own:/h/2']);
      assert.deepEqual(s.log.releases, [{ slot: 1, count: 3 }], 'sent from slot 1 of a three-slot HTTP/1 batch');

      // second: park again, then release it from a later batch of the same session
      const parked = h2Together(session, ['/park/s2', '/h/4']);
      await waitFor(() => s.ctx.parked.has('s2'), { timeout: 5000 });
      const later = await h2Together(session, ['/h/5', '/answer-after/s2', '/h/7', '/answer-micro/none', '/h/9']);
      assert.deepEqual(later, ['own:/h/5', 'own:/answer-after/s2', 'own:/h/7', 'own:/answer-micro/none', 'own:/h/9']);
      assert.deepEqual(await parked, ['parked:s2', 'own:/h/4']);
      assert.deepEqual(s.log.releases[1], { slot: 1, count: 5 }, 'sent from slot 1 of a five-stream HTTP/2 batch');
      const expected = ['/h/0', '/park/s1', '/h/2', '/a/0', '/answer-first/s1', '/a/2', '/park/s2', '/h/4', '/h/5', '/answer-after/s2', '/h/7', '/answer-micro/none', '/h/9'];
      assert.deepEqual([...s.log.dispatched].sort(), [...expected].sort(), 'every request dispatched exactly once');
      assert.deepEqual(s.log.cellJumps, []);
    } finally {
      session.destroy();
      a.sock.destroy();
      s.close();
    }
  });

  it('interleaved load: 8 pipelining connections and an HTTP/2 session keep answering each other\'s parked requests', T, async () => {
    // Every connection sends rounds of [park, x, release-of-someone-else, y].
    const s = serveAcross(across, { http2: true });
    const session = http2.connect(`http://127.0.0.1:${s.port}`);
    session.on('error', () => {});
    const N = 8;
    const ROUNDS = 25;
    const conns = Array.from({ length: N }, () => client(s.port));
    try {
      await Promise.all(conns.map((c) => c.ready));
      const expectedBodies = conns.map(() => []);
      let sent = 0;
      for (let r = 0; r < ROUNDS; r++) {
        // each connection parks, with two requests staged behind
        conns.forEach((c, i) => {
          c.sock.write(req(`/park/c${i}r${r}`) + req(`/x/${i}/${r}`) + req(`/y/${i}/${r}`));
          expectedBodies[i].push(`parked:c${i}r${r}`, `own:/x/${i}/${r}`, `own:/y/${i}/${r}`);
          sent += 3;
        });
        await waitFor(() => conns.every((_, i) => s.ctx.parked.has(`c${i}r${r}`)), { timeout: 5000 });
        // the HTTP/2 session releases them all in one batch, alternating before/after/microtask
        const verbs = ['answer-first', 'answer-after', 'answer-micro'];
        const paths = conns.map((_, i) => `/${verbs[(i + r) % 3]}/c${i}r${r}`);
        const bodies = await h2Together(session, paths);
        sent += paths.length;
        assert.deepEqual(bodies, paths.map((p) => 'own:' + p), `round ${r}: HTTP/2 answers`);
        await Promise.all(conns.map((c, i) => got(c, expectedBodies[i].length)));
      }
      conns.forEach((c, i) => assert.deepEqual(c.bodies(), expectedBodies[i], `connection ${i}: every answer, in order`));
      assert.equal(s.log.dispatched.length, sent, 'as many dispatches as requests');
      assert.equal(new Set(s.log.dispatched).size, sent, 'no request dispatched twice');
      assert.deepEqual(s.log.cellJumps, []);
    } finally {
      session.destroy();
      conns.forEach((c) => c.sock.destroy());
      s.close();
    }
  });
});

// A response a handler gives before it returns is complete once it is framed;
// its bytes may still be waiting on the peer. The batch stops handing slots
// over when that queue reaches the write high-water mark - the loop is told
// its batch is over, as it is ahead of an engine-side upgrade - and the slots
// still staged, and whatever is parsed after them, are delivered once the
// peer has read.
describe('batched dispatch and a peer that is not reading', { skip }, () => {
  // These need the server's write queue to back up behind a paused peer,
  // which Windows loopback (it absorbs tens of megabytes) does not give. The
  // sizes leave room for the 10 MB or so a Linux loopback pair takes.
  const needsBackpressure = { skip: process.platform === 'win32' && 'outbound backpressure is not reproducible on Windows loopback' };
  const MB = 1024 * 1024;
  const BIG = Buffer.alloc(MB, 0x61);
  const paused = async (port) => {
    const sock = net.connect(port, '127.0.0.1');
    await new Promise((resolve) => sock.once('connect', resolve));
    sock.pause();
    sock.on('error', () => {});
    return sock;
  };
  // Resume `sock` and collect until at least `minBytes` have arrived and the
  // line has then been quiet for a moment; the latin1 text read.
  const readAll = (sock, minBytes, timeout = 30000) =>
    new Promise((resolve) => {
      const chunks = [];
      let size = 0;
      let quiet = null;
      const done = () => {
        clearTimeout(timer);
        clearTimeout(quiet);
        resolve(Buffer.concat(chunks).toString('latin1'));
      };
      const timer = setTimeout(done, timeout);
      sock.on('data', (d) => {
        chunks.push(d);
        size += d.length;
        if (size >= minBytes) {
          clearTimeout(quiet);
          quiet = setTimeout(done, 250);
        }
      });
      sock.on('close', done);
      sock.resume();
    });

  for (const batch of [true, false]) {
    it(`pipelined requests are not handed over while the responses already given are unread; all are served in order once they are read (${batch ? 'batch loop' : 'one by one'})`, { timeout: 60000, ...needsBackpressure }, async () => {
      let n = 0;
      const srv = serveWith((reqId) => engine.respond(reqId, 200, ['x-n', String(n++)], BIG), { batch });
      const sock = await paused(srv.port);
      try {
        const N = 72;
        sock.write(Array.from({ length: 48 }, (_, i) => req(`/r${i}`)).join(''));
        await delay(300);
        sock.write(Array.from({ length: N - 48 }, (_, i) => req(`/r${48 + i}`)).join(''));
        await delay(300);
        const whileUnread = srv.log.dispatched.length;
        assert.ok(whileUnread <= 24, `${whileUnread} of ${N} requests reached a handler with nothing read`);
        const text = await readAll(sock, N * MB);
        const order = [...text.matchAll(/x-n: (\d+)\r\n/g)].map((m) => Number(m[1]));
        assert.deepEqual(order, Array.from({ length: N }, (_, i) => i));
        assert.deepEqual(srv.log.dispatched, Array.from({ length: N }, (_, i) => `/r${i}`), 'each request handed over once, in order');
      } finally {
        sock.destroy();
        srv.close();
      }
    });
  }

  it('responses the engine gives itself (static routes) wait on the peer like any other', { timeout: 60000, ...needsBackpressure }, async () => {
    const srv = serveWith((reqId, m, path) => engine.respond(reqId, 200, null, 'js:' + path), { batch: true });
    const sock = await paused(srv.port);
    try {
      engine.setStaticRoute(srv.sid, 0, '/static', 200, ['content-type', 'text/plain'], BIG);
      sock.write(req('/static').repeat(48) + req('/js'));
      await delay(500);
      assert.deepEqual(srv.log.dispatched, [], 'the request behind 48 unread megabytes has not been handed over');
      const text = await readAll(sock, 48 * MB);
      assert.equal((text.match(/HTTP\/1\.1 200 OK/g) || []).length, 49);
      assert.ok(text.endsWith('js:/js'));
      assert.deepEqual(srv.log.dispatched, ['/js']);
    } finally {
      sock.destroy();
      srv.close();
    }
  });

  // Once the last response of a connection has been given, the exchange is
  // over: a request that arrives while that response is still being written
  // is dropped like one that arrives after it, not answered behind a
  // response that said "close". (The staged requests of a batch were already
  // parsed against a fresh parser, so without this the next read was too.
  // The high-water mark is set above the response so that intake is not
  // simply paused for the unread bytes.)
  for (const [label, last] of [
    ['Connection: close', req('/big', { close: true })],
    ['HTTP/1.0', req('/big', { version: '1.0' })],
  ]) {
    it(`a request that arrives while the last response (${label}) is still being written is not handed over`, { timeout: 60000, ...needsBackpressure }, async () => {
      const srv = serveWith((reqId, m, path) => engine.respond(reqId, 200, null, path === '/big' ? Buffer.alloc(4 * MB, 0x62) : 'small'), {
        batch: true,
        writeHighWaterMark: 64 * MB,
      });
      const sock = await paused(srv.port);
      try {
        sock.write(last);
        await delay(250);
        sock.write(req('/after') + req('/after'));
        await delay(150);
        const text = await readAll(sock, 4 * MB);
        assert.deepEqual(text.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200']);
        assert.deepEqual(srv.log.dispatched, ['/big']);
      } finally {
        sock.destroy();
        srv.close();
      }
    });
  }

  it('a request rejected while another is being answered stays rejected, whatever arrives before its turn', T, async () => {
    const srv = serveWith(
      (reqId, m, path) => void setTimeout(() => engine.respond(reqId, 200, null, 'late:' + path), 150),
      { batch: true }
    );
    try {
      // The second request has no Host: rejected when it is parsed, behind
      // the first one's handler. The line sent next is not the rest of it.
      const raw = await exchange(srv.port, [req('/first') + `GET /rejected HTTP/1.1${CRLF}X-A: b${CRLF}${CRLF}`, 40, `Host: t${CRLF}${CRLF}`, 40, req('/after')]);
      assert.deepEqual(raw.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200', 'HTTP/1.1 400']);
      assert.deepEqual(srv.log.dispatched, ['/first']);
    } finally {
      srv.close();
    }
  });
});

// ---- what the engine keeps of a batch across calls ----
//
// Two things outlive one onRequestBatch call. The buffers: the engine writes
// descriptors and the control cell through pointers into storage JS also
// holds, so that storage must stay the engine's whatever JS does with the
// ArrayBuffers. And the ids of requests still staged behind one a handler is
// holding: they were assigned when the requests were parsed and are in no
// registry until their turn comes, so by then the number may have been given
// to someone else.
describe('batch buffers and staged ids over time', { skip }, () => {
  const child = (script, { args = [], env = {} } = {}) =>
    spawnSync(process.execPath, [...args, '--input-type=module', '-e', script], {
      env: { ...process.env, ...env },
      encoding: 'utf8',
      timeout: 30000,
    });

  // ArrayBuffer.prototype.transfer (or a transfer list) takes the storage
  // away from the buffers getBatchBuffers() returned; with the result dropped
  // and collected, nothing in JS owns it. The engine went on writing each
  // batch's descriptors into that freed memory. Child process: collection on
  // demand needs --expose-gc, and --single-threaded-gc frees on this thread,
  // so the allocator hands the same blocks to the next buffers of that size.
  //
  // And getBatchBuffers() called again after that hands out working buffers
  // (it built views over the detached buffers and the process aborted): new
  // storage, which the next batch is delivered in.
  it('the engine writes only into storage it holds, after JS transferred the buffers away', T, () => {
    const script = `
      import net from 'node:net';
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      let batches = 0;
      let again = null;
      const seen = [];
      const sid = engine.serve({
        onRequest() {},
        onRequestBatch(count) {
          batches++;
          for (let i = 0; i < count; i++) {
            seen.push(again.paths[again.descriptors[3 * i + 2]]);
            engine.respond(again.descriptors[3 * i], 200, null, 'ok');
            if (again.control[0] !== i + 1) break;
          }
          return count;
        },
        onAborted() {},
      });
      const port = engine.listen(sid, '127.0.0.1', 0);
      {
        const b = engine.getBatchBuffers(sid);
        // ArrayBuffer.prototype.transfer is Node 22+; structuredClone detaches on 20 as well
        const away = (ab) => (typeof ab.transfer === 'function' ? ab.transfer() : structuredClone(ab, { transfer: [ab] }));
        away(b.descriptors.buffer);
        away(b.control.buffer);
      }
      for (let i = 0; i < 4; i++) { globalThis.gc(); await sleep(10); }
      again = engine.getBatchBuffers(sid);
      const lengths = [again.descriptors.length, again.control.length];
      const others = [];
      for (let i = 0; i < 2000; i++) {
        // zero-filled and not: allocators keep the two kinds of request apart
        others.push(new Uint8Array(new ArrayBuffer(192)).fill(0xaa), Buffer.allocUnsafeSlow(192).fill(0xaa));
        others.push(new Uint8Array(new ArrayBuffer(4)).fill(0xaa), Buffer.allocUnsafeSlow(4).fill(0xaa));
      }
      const s = net.connect(port, '127.0.0.1', () => s.write('GET /one HTTP/1.1\\r\\nHost: t\\r\\n\\r\\nGET /two HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n'));
      s.on('error', () => {});
      for (let i = 0; i < 100 && seen.length < 2; i++) await sleep(10);
      const overwritten = others.filter((o) => o.some((v) => v !== 0xaa)).length;
      console.log(JSON.stringify({ batches, overwritten, lengths, seen }));
      s.destroy();
      engine.close(sid);
    `;
    const r = child(script, { args: ['--expose-gc', '--single-threaded-gc'] });
    assert.equal(r.status, 0, `status ${r.status} signal ${r.signal}\n${r.stderr.slice(-800)}`);
    assert.deepEqual(JSON.parse(r.stdout.trim()), { batches: 1, overwritten: 0, lengths: [48, 1], seen: ['/one', '/two'] });
  });

  // The same in the middle of a batch: the loop transfers both buffers away,
  // asks for them again and reads on from the new views - the descriptors
  // and the control cell carried over, the rest of the batch delivered.
  it('a batch loop that transfers the buffers away and asks for them again reads on', T, () => {
    const script = `
      import net from 'node:net';
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const away = (ab) => (typeof ab.transfer === 'function' ? ab.transfer() : structuredClone(ab, { transfer: [ab] }));
      const answered = [];
      let bufs;
      const sid = engine.serve({
        onRequest(id, _m, path) { answered.push(path); engine.respond(id, 200, null, path); },
        onRequestBatch(count) {
          let i = 0;
          for (;;) {
            const id = bufs.descriptors[3 * i], pi = bufs.descriptors[3 * i + 2];
            const path = pi === 0xffffffff ? engine.getPath(id) : bufs.paths[pi];
            if (path === '/p3') {
              away(bufs.descriptors.buffer);
              away(bufs.control.buffer);
              bufs = engine.getBatchBuffers(sid);
            }
            answered.push(path);
            engine.respond(id, 200, null, path);
            const next = bufs.control[0];
            if (next === i) return i + 1;
            if (next >= count) return count;
            i = next;
          }
        },
        onAborted() {},
      });
      bufs = engine.getBatchBuffers(sid);
      const port = engine.listen(sid, '127.0.0.1', 0);
      const pipe = (pre) => new Promise((res) => {
        const s = net.connect(port, '127.0.0.1', () => s.write(Array.from({ length: 10 }, (_, k) => 'GET ' + pre + k + ' HTTP/1.1\\r\\nHost: x\\r\\n' + (k === 9 ? 'Connection: close\\r\\n' : '') + '\\r\\n').join('')));
        let got = '';
        s.on('data', (d) => (got += d));
        s.on('error', () => {});
        s.on('close', () => res((got.match(/HTTP\\/1\\.1 200/g) || []).length));
      });
      const first = await pipe('/p');
      const second = await pipe('/q');
      console.log(JSON.stringify({ first, second, answered }));
      engine.close(sid);
    `;
    const r = child(script);
    assert.equal(r.status, 0, `status ${r.status} signal ${r.signal}\n${r.stderr.slice(-800)}`);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.first, 10);
    assert.equal(out.second, 10);
    assert.deepEqual(out.answered, [...Array.from({ length: 10 }, (_, k) => '/p' + k), ...Array.from({ length: 10 }, (_, k) => '/q' + k)]);
  });

  // The 32-bit id counter comes round after 2^32 requests on a thread. An id
  // that is registered is skipped; one that is only staged was not, so a
  // request parsed in between could be given the same number, and when the
  // staged request's turn came, registering it took the id away from that
  // request: the response its handler then gave went to the other
  // connection. A test build wraps the counter early (fault points,
  // MORO_ENGINE_TEST_ID_PERIOD) so the lap takes sixty requests.
  const noFaultPoints = engine?.probe?.().testFaults
    ? false
    : 'needs a build with fault points (tools/build.mjs --sanitize)';
  for (const [name, pipeline] of [
    ['activated when the held response completes', ['/hold', '/second']],
    ['activated from inside the batch loop', ['/hold', '/sync', '/second']],
  ]) {
    it(`a staged request whose id was given out again gets a new one (${name})`, { ...T, skip: noFaultPoints }, () => {
      const script = `
        import net from 'node:net';
        const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
        const PERIOD = 64;
        const pipeline = ${JSON.stringify(pipeline)};
        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
        const seen = [];
        const ids = {};
        let buf;
        function handle(reqId, path) {
          seen.push(path + '#' + reqId);
          if (path === '/hold' || path === '/victim' || path === '/second') ids[path] = reqId;
          else engine.respond(reqId, 200, null, 'own:' + path);
        }
        const sid = engine.serve({
          onRequest(reqId, m, path) { handle(reqId, path); },
          onRequestBatch(count) {
            let i = 0;
            for (;;) {
              const reqId = buf.descriptors[3 * i], pi = buf.descriptors[3 * i + 2];
              handle(reqId, pi === 0xffffffff ? engine.getPath(reqId) : buf.paths[pi]);
              const next = buf.control[0];
              if (next === i) return i + 1;
              if (next >= count) return count;
              i = next;
            }
          },
          onAborted() {},
        });
        buf = engine.getBatchBuffers(sid);
        const port = engine.listen(sid, '127.0.0.1', 0);
        const get = (p) => 'GET ' + p + ' HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n';
        const open = () => new Promise((r) => { const s = net.connect(port, '127.0.0.1', () => r(s)); s.got = ''; s.on('data', (d) => (s.got += d)); s.on('error', () => {}); });
        const a = await open(), b = await open();
        // /hold is held; the rest stay staged, ids assigned. /second has a
        // method, a header and a body of its own: all of it must still be
        // there when it is handed over under its new id.
        a.write(pipeline.slice(0, -1).map(get).join('') + 'POST /second HTTP/1.1\\r\\nHost: t\\r\\nX-Tag: tag-2\\r\\nContent-Length: 5\\r\\n\\r\\nBODY2');
        while (!ids['/hold']) await sleep(5);
        const stagedSecond = ids['/hold'] + pipeline.length - 1;
        // B: requests answered at once, until the next id to be given out is
        // the one /second was staged with. That one is held too.
        for (;;) {
          const last = Number(seen[seen.length - 1].split('#')[1]);
          const next = last + 1 >= PERIOD ? 1 : last + 1;
          if (seen.length > pipeline.length && (next === stagedSecond || (next === ids['/hold'] && stagedSecond === ids['/hold'] + 1))) break;
          const n = seen.length;
          b.write(get('/n'));
          while (seen.length === n) await sleep(1);
        }
        b.write(get('/victim'));
        while (!ids['/victim']) await sleep(5);
        engine.respond(ids['/hold'], 200, null, 'own:/hold');   // /second's turn comes
        while (!ids['/second']) await sleep(5);
        engine.respond(ids['/victim'], 200, null, 'own:/victim');
        const second = ids['/second'];
        engine.respond(second, 200, null, ['own:/second', engine.getMethod(second), engine.getHeader(second, 'x-tag'), Buffer.from(engine.getBody(second)).toString()].join(' '));
        await sleep(100);
        const bodies = (s) => s.got.split('\\r\\n\\r\\n').slice(1).map((x) => x.split('HTTP/1.1')[0]).filter((x) => x !== 'own:/n');
        console.log(JSON.stringify({
          sameId: ids['/victim'] === ids['/second'],
          victimGotStagedId: ids['/victim'] === stagedSecond,
          a: bodies(a), b: bodies(b),
          deliveries: seen.filter((x) => x.startsWith('/second')).length,
        }));
        a.destroy(); b.destroy();
        engine.close(sid);
      `;
      const r = child(script, { env: { MORO_ENGINE_TEST_ID_PERIOD: '64' } });
      assert.equal(r.status, 0, `status ${r.status} signal ${r.signal}\n${r.stderr.slice(-800)}`);
      assert.deepEqual(JSON.parse(r.stdout.trim()), {
        sameId: false,
        victimGotStagedId: true,   // the collision was really set up
        a: pipeline.map((p) => (p === '/second' ? 'own:/second POST tag-2 BODY2' : 'own:' + p)),
        b: ['own:/victim'],
        deliveries: 1,
      });
    });
  }
});

// The same bound for a peer that is gone instead of slow. A client that
// pipelines requests and resets its connection has its first response fail
// at the socket; that response, and any queued behind it before the failure
// is acted on, still count as output the peer has not taken, so the requests
// behind are not handed over to be answered into memory. (The engine counts
// those bytes itself on the libuv transport: on Windows libuv's own queue
// size never includes a write the socket has refused.)
describe('batched dispatch and a peer that has reset the connection', { skip }, () => {
  const MB = 1024 * 1024;
  const BIG = Buffer.alloc(MB, 0x61);
  for (const batch of [true, false]) {
    it(`requests pipelined behind a response that could not be written are not handed over (${batch ? 'batch loop' : 'one by one'})`, T, async () => {
      const srv = serveWith((reqId) => engine.respond(reqId, 200, null, BIG), { batch });
      const sock = net.connect(srv.port, '127.0.0.1');
      sock.on('error', () => {});
      try {
        await new Promise((resolve) => sock.once('connect', resolve));
        const N = 48;
        sock.write(Array.from({ length: N }, (_, i) => req(`/r${i}`)).join(''));
        sock.resetAndDestroy();
        const read = waitFor(() => srv.log.dispatched.length > 0, { timeout: 5000, message: 'the requests sent ahead of the reset were never read' });
        // (Windows may discard what a socket had received when the reset
        // arrives; then there is nothing to hand over at all.)
        if (process.platform === 'win32') await read.catch(() => {});
        else await read;
        await new Promise((resolve) => setTimeout(resolve, 300));
        assert.ok(srv.log.dispatched.length <= 2, `${srv.log.dispatched.length} of ${N} requests reached a handler behind a megabyte nobody will read`);
      } finally {
        sock.destroy();
        srv.close();
      }
    });
  }
});
