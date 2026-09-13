// Lingering close (RFC 9112 §9.6): after the last response of a
// Connection: close exchange the engine half-closes (its FIN rides with the
// response bytes) and keeps the socket open, discarding input, until the
// peer's FIN - so a request the peer had already written into the socket is
// absorbed instead of answered with a RST, and the peer never loses the
// response to that RST. A peer that never closes is cut at the deadline.
import { test } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import engine from '../packages/engine/index.mjs';

const REQ = 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n';

function serve() {
  const sid = engine.serve({
    onRequest(reqId) {
      engine.respond(reqId, 200, ['content-type', 'text/plain'], 'hello');
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  assert.ok(port > 0);
  return { sid, port };
}

test('a request written after the response is absorbed: FIN, never RST', async () => {
  const { sid, port } = serve();
  try {
    // Replicates autocannon: the next request goes out the instant the
    // response is parsed, before the client has processed the FIN.
    const events = await new Promise((resolve, reject) => {
      const ev = [];
      const s = net.connect({ host: '127.0.0.1', port, allowHalfOpen: true });
      s.on('connect', () => s.write(REQ));
      let gotData = false;
      s.on('data', (d) => {
        if (!gotData) {
          gotData = true;
          assert.match(String(d), /^HTTP\/1\.1 200/);
          s.write(REQ); // stray request into the half-closed socket
          ev.push('data');
        }
      });
      s.on('end', () => {
        ev.push('end');
        s.end(); // our FIN: the server may now close
      });
      s.on('error', (e) => {
        ev.push(`error:${e.code}`);
      });
      s.on('close', () => {
        ev.push('close');
        resolve(ev);
      });
      s.setTimeout(5000, () => reject(new Error('timeout')));
    });
    assert.deepStrictEqual(events, ['data', 'end', 'close']);
  } finally {
    engine.close(sid);
  }
});

test('the peer\'s FIN closes the lingering connection promptly', async () => {
  const { sid, port } = serve();
  try {
    const t0 = Date.now();
    await new Promise((resolve, reject) => {
      const s = net.connect({ host: '127.0.0.1', port }); // allowHalfOpen false: auto-ends on FIN
      s.on('connect', () => s.write(REQ));
      s.on('data', () => {}); // a paused socket never reads the FIN
      s.on('close', resolve);
      s.on('error', reject);
      s.setTimeout(5000, () => reject(new Error('timeout')));
    });
    assert.ok(Date.now() - t0 < 1000, 'closed well inside the linger deadline');
  } finally {
    engine.close(sid);
  }
});

test('a peer that never closes is cut at the linger deadline', async () => {
  const { sid, port } = serve();
  try {
    const t0 = Date.now();
    const result = await new Promise((resolve, reject) => {
      const s = net.connect({ host: '127.0.0.1', port, allowHalfOpen: true });
      s.on('connect', () => s.write(REQ));
      s.on('data', () => {}); // read, so the FIN is seen
      let ended = false;
      s.on('end', () => {
        ended = true; // the server's FIN came with the response; we never send ours
      });
      // After the deadline the server has closed the socket outright. Our
      // side only notices when it writes: the first write draws a RST, the
      // second fails on the reset socket and closes it.
      const poke = setInterval(() => {
        if (!s.destroyed) s.write('x');
      }, 250);
      s.on('error', () => {});
      s.on('close', () => {
        clearInterval(poke);
        resolve({ ended, ms: Date.now() - t0 });
      });
      setTimeout(() => {
        clearInterval(poke);
        s.destroy();
        reject(new Error('the server never closed the lingering connection'));
      }, 8000).unref();
    });
    assert.ok(result.ended, 'server FIN was delivered with the response');
    // kLingerMs (2 s) at the sweep's 1 s granularity: closed between 2 and ~3.5 s.
    assert.ok(result.ms >= 1500 && result.ms < 5000, `closed after ${result.ms} ms`);
  } finally {
    engine.close(sid);
  }
});
