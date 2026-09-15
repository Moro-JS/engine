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
