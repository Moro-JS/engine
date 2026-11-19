// Transport selection diagnostics for @morojs/engine.
//
//   - probe().transport is 'uv' or 'uring', with a non-empty transportReason
//   - io_uring is OPT-IN (MORO_ENGINE_TRANSPORT=uring): without the variable
//     a Linux host reports 'uv' with an "opt-in" reason; with it, 'uring' when
//     the probe passes or the failing step (EPERM / ENOSYS / EINVAL / a
//     self-test stage) when it does not
//   - MORO_ENGINE_TRANSPORT=uv in a child forces 'uv' with that reason
//   - off Linux the reason is 'platform'
//   - the transport never changes what a request sees (one round trip)
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine ? false : '@morojs/engine native binding not usable yet — transport suite skipped';
const T = { timeout: 30000 };
const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;

describe('transport selection', { skip }, () => {
  it('probe() reports the transport and a reason', T, () => {
    const p = engine.probe();
    assert.ok(['uv', 'uring', 'epoll'].includes(p.transport), `transport: ${p.transport}`);
    assert.equal(typeof p.transportReason, 'string');
    assert.ok(p.transportReason.length > 0);
    if (p.transport === 'uring') assert.equal(p.transportReason, 'ok');
    if (process.platform !== 'linux') {
      assert.equal(p.transport, 'uv');
      assert.equal(p.transportReason, 'platform');
    } else if (process.env.MORO_ENGINE_TRANSPORT === 'uv') {
      assert.equal(p.transport, 'uv');
      assert.equal(p.transportReason, 'MORO_ENGINE_TRANSPORT=uv');
    } else if (process.env.MORO_ENGINE_TRANSPORT !== 'uring') {
      assert.equal(p.transport, 'epoll');
      assert.match(p.transportReason, /default|MORO_ENGINE_TRANSPORT=epoll/);
    }
    console.log(`transport: ${p.transport} (${p.transportReason})`);
  });

  it('without MORO_ENGINE_TRANSPORT a Linux host runs epoll; io_uring stays opt-in', T, () => {
    const script = `
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const p = engine.probe();
      console.log(JSON.stringify({ transport: p.transport, reason: p.transportReason }));
    `;
    const env = { ...process.env, MORO_ENGINE_REQUIRE_TRANSPORT: '' };
    delete env.MORO_ENGINE_TRANSPORT;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.transport, process.platform === 'linux' ? 'epoll' : 'uv');
    if (process.platform === 'linux') assert.match(out.reason, /default.*opt-in/);
  });

  it('MORO_ENGINE_TRANSPORT=uv forces libuv', T, () => {
    const script = `
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const p = engine.probe();
      console.log(JSON.stringify({ transport: p.transport, reason: p.transportReason }));
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      env: { ...process.env, MORO_ENGINE_TRANSPORT: 'uv', MORO_ENGINE_REQUIRE_TRANSPORT: '' },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.transport, 'uv');
    if (process.platform === 'linux') assert.equal(out.reason, 'MORO_ENGINE_TRANSPORT=uv');
  });

  it('serves one request on whichever transport is active', T, async () => {
    const sid = engine.serve({
      onRequest(reqId) {
        engine.respond(reqId, 200, ['content-type', 'text/plain'], `via ${engine.probe().transport}`);
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const raw = await new Promise((resolve, reject) => {
        const s = net.connect(port, '127.0.0.1', () => s.write('GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n'));
        let b = '';
        s.on('data', (d) => (b += d));
        s.on('end', () => resolve(b));
        s.on('error', reject);
        s.setTimeout(5000, () => reject(new Error('timeout')));
      });
      assert.match(raw, /^HTTP\/1\.1 200/);
      assert.ok(raw.endsWith(`via ${engine.probe().transport}`), raw);
    } finally {
      engine.close(sid);
    }
  });
});

// A ring that stops taking submissions at run time (docs/THREAT_MODEL.md,
// threat 6). No peer can provoke it, so the sanitizer build has a fault point
// for it and the subject (test/ring-death-subject.mjs) switches it on: with
// requests in flight, a WebSocket open, a response the kernel is still
// sending, and a second server in the middle of closing. Every peer must see
// its connection end, each in-flight request gets one onAborted and the
// WebSocket one onWsClose(1006), the server that was listening answers the
// next request on the same port, and the process ends by itself once both
// servers are closed.
describe('an io_uring ring that dies at run time', { skip }, () => {
  const SUBJECT = fileURLToPath(new URL('./ring-death-subject.mjs', import.meta.url));
  const p = engine?.probe() ?? {};
  const skipHere =
    p.transport !== 'uring' ? 'needs the io_uring transport (MORO_ENGINE_TRANSPORT=uring)'
    : !p.testFaults ? 'needs the fault points of the sanitizer build (node tools/build.mjs --sanitize)'
    : false;
  for (const [mode, what] of [
    ['quiet', 'found out by the loop'],
    ['inline', 'found out by a response, in a burst that fills the submission queue'],
  ]) {
    it(`${what}: peers are closed, callbacks fire once, the server carries on`, { timeout: 120000, skip: skipHere }, () => {
      const r = spawnSync(process.execPath, [SUBJECT, mode], { encoding: 'utf8', timeout: 100000 });
      assert.equal(r.status, 0, `the process survives and ends by itself (signal ${r.signal})\n${r.stderr.slice(0, 4000)}`);
      const out = JSON.parse(r.stdout.trim().split('\n').pop());
      assert.equal(out.ended, out.opened, 'every peer saw its connection end');
      assert.equal(out.aborted, out.inFlight, 'one onAborted per request that was in flight');
      assert.deepEqual(out.wsCodes, [1006]);
      assert.equal(out.next, '200', 'the next request on the same port is answered');
    });
  }
});

import { spawn } from 'node:child_process';

// What one connection is served in one turn of the loop is bounded (epoll:
// one read per socket per turn; io_uring: the same amount of what its receive
// has completed; libuv: its second read of a stream in one turn is declined,
// or, on Windows, the stream is stopped until the next turn).
// A peer that sends without pause - here megabytes of one-byte WebSocket
// messages, each of them a call into the application - then shares the loop
// with its timers and with every other connection, instead of holding it for
// as long as it has bytes to send.
describe('one connection\'s share of a loop turn', { skip }, () => {
  // The sender: a child process, so that it keeps the socket full while this
  // one is busy with the messages.
  const SENDER = `
    const net = require('node:net');
    const unit = Buffer.from([0x82, 0x81, 0, 0, 0, 0, 0x61]);
    const chunk = Buffer.concat(Array.from({ length: 9362 }, () => unit));
    let left = 64;  // x 64 KiB
    const s = net.connect(Number(process.argv[1]), '127.0.0.1', () => {
      s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n');
      s.once('data', () => {
        s.on('data', () => {});
        const pump = () => { while (left-- > 0) if (!s.write(chunk)) return s.once('drain', pump); s.end(); };
        pump();
      });
    });
    s.on('error', () => process.exit(0));
    s.on('close', () => process.exit(0));
  `;

  it('a flood of small messages is delivered a read\'s worth per turn', { timeout: 120000 }, async () => {
    let messages = 0;
    let inTurn = 0;
    let most = 0;
    let closed = false;
    const sid = engine.serve(
      {
        onRequest(reqId) { if (engine.upgradeToWebSocket(reqId) === -1) engine.respond(reqId, 400, null, ''); },
        onAborted() {},
        onWritable() {},
        onWsOpen() {},
        onWsMessage() { messages++; inTurn++; },
        onWsClose() { closed = true; },
      },
      { wsBackpressureLimit: 0 }
    );
    // One callback per loop turn: the most messages any turn delivered.
    let turning = true;
    const turn = () => {
      if (inTurn > most) most = inTurn;
      inTurn = 0;
      if (turning) setImmediate(turn);
    };
    setImmediate(turn);
    try {
      const port = engine.listen(sid, '127.0.0.1', 0);
      const child = spawn(process.execPath, ['-e', SENDER, String(port)], { stdio: 'ignore' });
      await new Promise((resolve) => child.on('exit', resolve));
      for (let i = 0; i < 1000 && !closed; i++) await new Promise((r) => setTimeout(r, 10));
      assert.equal(messages, 64 * 9362, 'every message was delivered');
      // A message is seven bytes on the wire: 64 KiB is 9362 of them. Three
      // reads' worth leaves room for the turn in which a connection goes
      // from one way of being read to the other.
      assert.ok(most <= 3 * 9362, `one loop turn delivered ${most} messages (${Math.round((most * 7) / 1024)} KiB) of one connection's input`);
    } finally {
      turning = false;
      engine.close(sid);
    }
  });

  // The libuv transport has two ways of keeping a stream to one read per
  // turn, and Windows uses the one the other platforms do not: the stream
  // stops reading and an idle handle starts it again.
  // MORO_ENGINE_TEST_UV_READ_RESTART=1 selects it here as well, so the same
  // flood, in a process of its own with that set, runs the code Windows runs:
  // every message arrives, in order (a counter in each), a read's worth per
  // turn, and the server then closes and the process ends by itself.
  const onLibuv = engine && (engine.probe().transport ?? 'uv') === 'uv';
  const restartSkip = !onLibuv ? 'the libuv transport only' : process.platform === 'win32' ? 'the only way there is on Windows: the case above' : false;
  it('... also with the stream stopped and started again, the way Windows bounds it', { timeout: 120000, skip: restartSkip }, () => {
    const subject = `
      import { spawn } from 'node:child_process';
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const SENDER = ${JSON.stringify(`
        const net = require('node:net');
        let n = 0;
        const chunk = () => { const b = Buffer.alloc(6553 * 10); for (let i = 0; i < 6553; i++) { b[i * 10] = 0x82; b[i * 10 + 1] = 0x84; b.writeUInt32BE(n++, i * 10 + 6); } return b; };
        let left = 64;  // x 64 KiB of ten-byte frames, each message its own number (mask key 0)
        const s = net.connect(Number(process.argv[1]), '127.0.0.1', () => {
          s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n');
          s.once('data', () => {
            s.on('data', () => {});
            const pump = () => { while (left-- > 0) if (!s.write(chunk())) return s.once('drain', pump); s.end(); };
            pump();
          });
        });
        s.on('error', () => process.exit(0));
        s.on('close', () => process.exit(0));
      `)};
      let messages = 0, inOrder = true, inTurn = 0, most = 0, closed = false;
      const sid = engine.serve({
        onRequest(reqId) { if (engine.upgradeToWebSocket(reqId) === -1) engine.respond(reqId, 400, null, ''); },
        onAborted() {}, onWritable() {}, onWsOpen() {},
        onWsMessage(wsId, data) { if (Buffer.from(data).readUInt32BE(0) !== messages) inOrder = false; messages++; inTurn++; },
        onWsClose() { closed = true; },
      }, { wsBackpressureLimit: 0 });
      let turning = true;
      const turn = () => { if (inTurn > most) most = inTurn; inTurn = 0; if (turning) setImmediate(turn); };
      setImmediate(turn);
      const port = engine.listen(sid, '127.0.0.1', 0);
      const child = spawn(process.execPath, ['-e', SENDER, String(port)], { stdio: 'ignore' });
      await new Promise((resolve) => child.on('exit', resolve));
      for (let i = 0; i < 1000 && !closed; i++) await new Promise((r) => setTimeout(r, 10));
      turning = false;
      engine.close(sid);
      console.log(JSON.stringify({ messages, inOrder, most, closed }));
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', subject], {
      encoding: 'utf8',
      timeout: 100000,
      env: { ...process.env, MORO_ENGINE_TEST_UV_READ_RESTART: '1' },
    });
    assert.equal(r.status, 0, `the process ends by itself (signal ${r.signal})\n${r.stderr.slice(0, 2000)}`);
    const out = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(out.messages, 64 * 6553, 'every message was delivered');
    assert.ok(out.inOrder, 'in the order they were sent');
    assert.ok(out.closed, 'and the end of the stream after them');
    assert.ok(out.most <= 3 * 6554, `one loop turn delivered ${out.most} messages (${Math.round((out.most * 10) / 1024)} KiB) of one connection's input`);
  });
});

// A process that has closed its last server holds nothing of the transport's:
// the descriptors a transport opens for itself when the first listener
// arrives (the io_uring ring and its eventfd, the spare descriptor the accept
// path keeps for the descriptor limit) go back with the last one, however
// many servers came and went in between.
describe('descriptors the transport holds', { skip }, () => {
  const subject = `
    import fs from 'node:fs';
    import net from 'node:net';
    const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const dir = fs.existsSync('/proc/self/fd') ? '/proc/self/fd' : '/dev/fd';
    const count = () => fs.readdirSync(dir).length;
    // One exchange of node's own first, so that whatever it opens for its sockets is in the baseline.
    await new Promise((resolve) => {
      const srv = net.createServer((s) => s.end()).listen(0, '127.0.0.1', () => {
        const c = net.connect(srv.address().port, '127.0.0.1');
        c.on('data', () => {});
        c.on('close', () => srv.close(resolve));
      });
    });
    await sleep(50);
    const before = count();
    let served = 0;
    for (let i = 0; i < 4; i++) {
      const sid = engine.serve({ onRequest(reqId) { engine.respond(reqId, 200, null, 'ok'); }, onAborted() {}, onWritable() {} }, {});
      const port = engine.listen(sid, '127.0.0.1', 0);
      await new Promise((resolve) => {
        const c = net.connect(port, '127.0.0.1', () => c.write('GET / HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n'));
        c.on('data', () => { served++; c.destroy(); });
        c.on('close', resolve);
      });
      engine.close(sid);
      await sleep(i % 2 ? 0 : 50);  // the next server arrives both before and after the loop has turned
    }
    await sleep(200);
    console.log(JSON.stringify({ before, after: count(), served }));
  `;
  it('are returned when the last server is closed', { ...T, skip: process.platform === 'win32' && 'needs a descriptor table to list' }, () => {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', subject], { encoding: 'utf8', timeout: 20000 });
    assert.equal(r.status, 0, r.stderr.slice(0, 2000));
    const out = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(out.served, 4, 'every server answered its request');
    assert.equal(out.after, out.before, 'descriptors held after the last close()');
  });
});
