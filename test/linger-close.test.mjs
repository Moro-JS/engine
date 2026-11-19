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

// A request the server has rejected ends the connection's HTTP input, from
// the moment the error response is written or queued - not only once it has
// been flushed and the connection is lingering. The response may sit behind
// earlier ones the peer has not read yet; whatever the peer sends in that
// window is dropped like the input of a lingering connection, and never read
// as the rest of the rejected request or as a new one.
const BIG = Buffer.alloc(4 * 1024 * 1024, 0x61);
const getReq = (path) => `GET ${path} HTTP/1.1\r\nHost: t\r\n\r\n`;

function serveLogged(options) {
  const paths = [];
  const sid = engine.serve({
    onRequest(reqId, _m, path) {
      paths.push(path);
      engine.respond(reqId, 200, null, path === '/big' ? BIG : 'small');
    },
    onAborted() {},
  }, options);
  return { sid, port: engine.listen(sid, '127.0.0.1', 0), paths };
}

// Two ways for the error response to end up behind unread ones: with the
// default write high-water mark the requests behind the first large response
// wait for the peer to read, and the rejection is found then, together with
// whatever arrived meanwhile; with a mark far above the responses nothing
// waits, and the error response is queued at once.
const MARKS = [
  ['default write high-water mark', undefined],
  ['high-water mark above the queued responses', { writeHighWaterMark: 64 * 1024 * 1024 }],
];

// Send `first` without reading anything, then `later` (`times` times), then
// read to the end: the status codes received, in order.
async function unreadThenRead(port, first, later, times = 1) {
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const s = net.connect({ host: '127.0.0.1', port });
  await new Promise((resolve) => s.once('connect', resolve));
  s.pause();
  s.on('error', () => {});
  s.write(Buffer.from(first, 'latin1'));
  await pause(250);
  for (let i = 0; i < times; i++) {
    s.write(Buffer.from(later, 'latin1'));
    await pause(60);
  }
  await pause(150);
  const chunks = [];
  s.on('data', (d) => chunks.push(d));
  s.resume();
  await new Promise((resolve) => {
    s.on('close', resolve);
    setTimeout(resolve, 8000).unref();
  });
  s.destroy();
  const raw = Buffer.concat(chunks).toString('latin1');
  // Status lines only: the bodies here are runs of 'a' and cannot contain one.
  return [...raw.matchAll(/HTTP\/1\.1 (\d{3}) [^\r\n]*\r\n/g)].map((m) => Number(m[1]));
}

for (const [label, options] of MARKS) {
  test(`a request answered 400 for its missing Host is not completed by a Host line sent afterwards (${label})`, async () => {
    const { sid, port, paths } = serveLogged(options);
    try {
      const statuses = await unreadThenRead(
        port,
        getReq('/big') + getReq('/big') + 'GET /rejected HTTP/1.1\r\nX-A: b\r\n\r\n',
        'Host: t\r\n\r\n'
      );
      assert.deepStrictEqual(statuses, [200, 200, 400]);
      assert.ok(!paths.includes('/rejected'), 'the handler ran for a request the client was told is rejected');
    } finally {
      engine.close(sid);
    }
  });

  test(`one error response, however much the peer sends after it (${label})`, async () => {
    const { sid, port, paths } = serveLogged(options);
    try {
      const statuses = await unreadThenRead(port, getReq('/big') + getReq('/big') + 'BAD LINE\r\n\r\n', getReq('/after'), 5);
      assert.deepStrictEqual(statuses, [200, 200, 400]);
      assert.ok(!paths.includes('/after'));
    } finally {
      engine.close(sid);
    }
  });
}
