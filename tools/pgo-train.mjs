#!/usr/bin/env node
// PGO training workload: exercise every hot path of the engine binary the
// loader resolves (point MORO_ENGINE_BINARY at an instrumented build) so the
// LLVM profile covers what production sees, then exit through process.exit(0)
// so the profile runtime's atexit hook flushes the .profraw files.
//
//   node tools/pgo-train.mjs [--seconds=N] [--no-suites]
//
// Workload (in-process servers, one raw-socket client each, pipelined at
// depth 1 and depth 10):
//   - respond()            JSON hello (the benchmark shape)
//   - respondPrepared()    same via a template
//   - static route         answered inside the engine
//   - writeHead/write/end  chunked streaming
//   - HEAD, 404, an empty 204
//   - WebSocket echo (text frames)
//   - TLS (when the build has it)
// then, unless --no-suites, the whole node --test suite set as a child (same
// MORO_ENGINE_BINARY), which covers the error/limit/edge paths a throughput
// workload never reaches.

import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const seconds = parseFloat(args.find((a) => a.startsWith('--seconds='))?.slice('--seconds='.length) ?? '4');
const runSuites = !args.includes('--no-suites');

const { default: engine } = await import(new URL('../packages/engine/index.mjs', import.meta.url));
const info = engine.probe();
if (!info.ok) {
  console.error(`engine failed to load: ${info.error}`);
  process.exit(1);
}
console.log(`training against ${process.env.MORO_ENGINE_BINARY || '(default binary)'}; fastApi=${info.fastApi?.installed}`);

const CRLF = '\r\n';
const BODY = '{"hello":"world"}';
const HEADERS = ['content-type', 'application/json'];

// A server with every response shape, keyed by path. Batched dispatch is
// registered when the binary has it, so the profile covers the staging ring
// and the descriptor loop as well as single dispatch (a request that stands
// alone still arrives as a batch of one).
let tpl = 0;
let batchBuffers = null;
function handle(reqId, methodIdx, path) {
    switch (path) {
      case '/':
        engine.respond(reqId, 200, HEADERS, BODY);
        return;
      case '/tpl':
        engine.respondPrepared(reqId, tpl, BODY);
        return;
      case '/empty':
        engine.respondPreparedEmpty(reqId, tpl);
        return;
      case '/stream':
        engine.writeHeadPrepared(reqId, tpl);
        engine.write(reqId, '{"part":');
        engine.write(reqId, '1}');
        engine.endWith(reqId, '\n');
        return;
      case '/nocontent':
        engine.respond(reqId, 204, null, null);
        return;
      case '/big':
        engine.respond(reqId, 200, ['content-type', 'text/plain'], 'x'.repeat(65536));
        return;
      default:
        engine.respond(reqId, 404, ['content-type', 'text/plain'], 'not found');
    }
}
const callbacks = {
  onRequest: handle,
  onAborted() {},
  onWritable() {},
  onWsOpen() {},
  onWsMessage(wsId, data, isBinary) {
    engine.wsSend(wsId, data, isBinary);
  },
  onWsClose() {},
};
if (info.capabilities?.batchDispatch) {
  callbacks.onRequestBatch = (count) => {
    const d = batchBuffers.descriptors;
    const ctl = batchBuffers.control;
    const paths = batchBuffers.paths;
    let i = 0;
    for (;;) {
      const reqId = d[3 * i];
      const pi = d[3 * i + 2];
      handle(reqId, d[3 * i + 1], pi === 0xffffffff ? engine.getPath(reqId) : paths[pi]);
      const next = ctl[0];
      if (next === i) return i + 1;
      if (next >= count) return count;
      i = next;
    }
  };
}
const sid = engine.serve(callbacks);
if (callbacks.onRequestBatch) batchBuffers = engine.getBatchBuffers(sid);
const port = engine.listen(sid, '127.0.0.1', 0);
tpl = engine.prepareResponse(sid, 200, HEADERS);
engine.setStaticRoute(sid, 0, '/static', 200, HEADERS, BODY);
engine.setStaticRoute(sid, 5, '/static', 200, HEADERS, BODY);
const phase = (name) => console.log(`training: ${name}`);

// Drive one connection with a pipelined request block for `ms` milliseconds.
function hammer(port, block, ms, { connect = (cb) => net.connect(port, '127.0.0.1', cb) } = {}) {
  return new Promise((resolve) => {
    const sock = connect(() => sock.write(block));
    let bytes = 0;
    const deadline = Date.now() + ms;
    sock.on('data', (d) => {
      bytes += d.length;
      if (Date.now() > deadline) {
        sock.destroy();
        resolve(bytes);
      } else {
        sock.write(block);
      }
    });
    sock.on('error', () => resolve(bytes));
    sock.on('close', () => resolve(bytes));
  });
}

const req = (method, path) => `${method} ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;
const paths = ['/', '/tpl', '/static', '/empty', '/stream', '/nocontent', '/big', '/missing'];
const perPhase = (seconds * 1000) / (paths.length * 3);

phase('pipelined request shapes');
for (const path of paths) {
  await hammer(port, req('GET', path), perPhase);
  await hammer(port, req('GET', path).repeat(10), perPhase);
  await hammer(port, req('HEAD', path), perPhase / 2);
}
// Connection-per-request shape (accept path).
phase('connection per request');
for (let i = 0; i < 300; i++) {
  await new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(`GET / HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`));
    s.resume(); // read (and discard) the response so the server's FIN is seen and 'close' fires
    s.on('close', resolve);
    s.on('error', resolve);
  });
}

// WebSocket echo.
phase('websocket echo');
await new Promise((resolve) => {
  const key = crypto.randomBytes(16).toString('base64');
  const sock = net.connect(port, '127.0.0.1', () => {
    sock.write(`GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`);
  });
  const frame = () => {
    const payload = Buffer.from('ping-pong-payload');
    const mask = crypto.randomBytes(4);
    const out = Buffer.alloc(2 + 4 + payload.length);
    out[0] = 0x81;
    out[1] = 0x80 | payload.length;
    mask.copy(out, 2);
    for (let i = 0; i < payload.length; i++) out[6 + i] = payload[i] ^ mask[i % 4];
    return out;
  };
  let upgraded = false;
  let n = 0;
  sock.on('data', () => {
    if (!upgraded) {
      upgraded = true;
      sock.write(Buffer.concat([frame(), frame(), frame()]));
      return;
    }
    if (++n > 2000) {
      sock.destroy();
      resolve();
    } else {
      sock.write(frame());
    }
  });
  sock.on('error', resolve);
  sock.on('close', resolve);
  setTimeout(() => {
    sock.destroy();
    resolve();
  }, Math.max(1000, seconds * 250));
});

// TLS request path (when the binary terminates TLS).
phase('tls');
if (info.capabilities?.tls) {
  const fx = (n) => fileURLToPath(new URL(`../test/fixtures/tls/${n}`, import.meta.url));
  const tsid = engine.serve(
    {
      onRequest(reqId) {
        engine.respond(reqId, 200, HEADERS, BODY);
      },
      onAborted() {},
    },
    { ssl: { key_file_name: fx('localhost.key'), cert_file_name: fx('localhost.pem') } }
  );
  const tport = engine.listen(tsid, '127.0.0.1', 0);
  await hammer(tport, req('GET', '/'), Math.max(500, seconds * 150), {
    connect: (cb) => tls.connect({ host: '127.0.0.1', port: tport, rejectUnauthorized: false }, cb),
  });
  engine.close(tsid);
}
engine.close(sid);

if (runSuites) {
  console.log('running the node --test suites against the instrumented binary ...');
  const r = spawnSync('npm', ['run', '-s', 'test:suites'], { cwd: root, stdio: 'inherit', env: process.env, shell: process.platform === 'win32' });
  if (r.status !== 0) {
    console.error('suites failed under the instrumented binary');
    process.exit(2);
  }
}

console.log('training done');
// process.exit (not a natural drain) so the profile runtime's atexit flush
// runs with the isolate still alive - an unref'd-handle drain can race it.
process.exit(0);
