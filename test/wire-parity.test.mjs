// Wire-parity harness for @morojs/engine.
//
// Three ways to send the same response - respond(status, headers, body), a
// prepared template (respondPrepared), and a static route answered inside the
// engine - must produce byte-identical streams (Date line excepted) across:
//   status   {200, 201, 204, 304, 404, 500}
//   headers  {none, one, three, an app Content-Length (HEAD/bodyless only)}
//   body     {empty, ASCII, Latin-1, two-byte UTF-16 source, Buffer with 0x00/0xFF}
//   method   {GET, HEAD}
//   framing  {HTTP/1.1 keep-alive, HTTP/1.1 Connection: close, HTTP/1.0,
//             HTTP/1.1 keep-alive pipelined x5}
// Later phases (fast calls, batched dispatch, the io_uring transport) reuse
// this matrix: whatever path a response takes, the bytes may not change.
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — wire-parity suite skipped';

const T = { timeout: 120000 };
const CRLF = '\r\n';
const GET = 0;
const HEAD = 5;

const STATUSES = [200, 201, 204, 304, 404, 500];
const HEADER_SETS = [
  { name: 'none', headers: null },
  { name: 'one', headers: ['content-type', 'text/plain'] },
  { name: 'three', headers: ['content-type', 'application/json', 'x-a', '1', 'cache-control', 'no-store'] },
  { name: 'app-cl', headers: ['content-length', '1234', 'x-cl', 'y'] },
];
const BODIES = [
  { name: 'empty', body: '' },
  { name: 'ascii', body: 'hello, world' },
  { name: 'latin1', body: 'café crème' },
  { name: 'two-byte', body: '€ 12 世界' },
  { name: 'buffer', body: Buffer.from([0x62, 0x69, 0x6e, 0x00, 0xff, 0x0a]) },
];

// Every (status, headers, body) combination, addressed by path index.
const COMBOS = [];
for (const status of STATUSES)
  for (const h of HEADER_SETS)
    for (const b of BODIES) COMBOS.push({ status, hname: h.name, headers: h.headers, bname: b.name, body: b.body });

const comboIndex = (path) => parseInt(path.slice('/c/'.length), 10);

const stripDate = (s) => s.replace(/^date: [^\r\n]*\r\n/gim, '');

// Count complete responses in a stream (Content-Length framing; HEAD and
// bodyless statuses carry no body). Used to know when a keep-alive exchange
// is complete without waiting for a close.
function countResponses(buf, head) {
  let n = 0;
  let pos = 0;
  for (;;) {
    const he = buf.indexOf('\r\n\r\n', pos);
    if (he < 0) return n;
    const headBlock = buf.slice(pos, he);
    const status = parseInt(headBlock.match(/^HTTP\/1\.[01] (\d{3})/)?.[1] ?? '0', 10);
    const cl = parseInt(headBlock.match(/\r\ncontent-length:\s*(\d+)/i)?.[1] ?? '0', 10);
    const bodyless = head || status === 204 || status === 304 || (status >= 100 && status < 200);
    const bodyLen = bodyless ? 0 : cl;
    if (buf.length < he + 4 + bodyLen) return n;
    n++;
    pos = he + 4 + bodyLen;
  }
}

function exchange(port, requestBytes, { expectClose, responses, head }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(requestBytes, 'latin1'));
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (!expectClose && countResponses(buf, head) >= responses) {
        sock.destroy();
        resolve(buf);
      }
    });
    sock.on('end', () => resolve(buf));
    sock.on('close', () => resolve(buf));
    sock.on('error', reject);
    sock.setTimeout(8000, () => reject(new Error(`timeout: ${JSON.stringify(buf.slice(0, 200))}`)));
  });
}

const FRAMINGS = [
  { name: 'http/1.1 keep-alive', line: (m, p) => `${m} ${p} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`, expectClose: false, n: 1 },
  { name: 'http/1.1 close', line: (m, p) => `${m} ${p} HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`, expectClose: true, n: 1 },
  { name: 'http/1.0', line: (m, p) => `${m} ${p} HTTP/1.0${CRLF}Host: t${CRLF}${CRLF}`, expectClose: true, n: 1 },
  { name: 'http/1.1 pipelined x5', line: (m, p) => `${m} ${p} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`.repeat(5), expectClose: false, n: 5 },
];

describe('wire parity: respond() vs respondPrepared() vs static route', { skip }, () => {
  it(`${COMBOS.length} combos x GET/HEAD x ${FRAMINGS.length} framings are byte-identical`, T, async () => {
    // Server A: respond() per request.
    const sidA = engine.serve({
      onRequest(reqId, _m, path) {
        const c = COMBOS[comboIndex(path)];
        engine.respond(reqId, c.status, c.headers, c.body);
      },
      onAborted() {},
    });
    const portA = engine.listen(sidA, '127.0.0.1', 0);

    // Server B: one template per (status, headers), body per request.
    const tplIds = new Map();
    const sidB = engine.serve({
      onRequest(reqId, _m, path) {
        const c = COMBOS[comboIndex(path)];
        engine.respondPrepared(reqId, tplIds.get(`${c.status}|${c.hname}`), c.body);
      },
      onAborted() {},
    });
    const portB = engine.listen(sidB, '127.0.0.1', 0);
    for (const status of STATUSES)
      for (const h of HEADER_SETS) tplIds.set(`${status}|${h.name}`, engine.prepareResponse(sidB, status, h.headers));

    // Server C: every combo registered as a static route for GET and HEAD.
    let jsHits = 0;
    const sidC = engine.serve({
      onRequest(reqId) {
        jsHits++;
        engine.respond(reqId, 599, null, 'static route missed');
      },
      onAborted() {},
    });
    const portC = engine.listen(sidC, '127.0.0.1', 0);
    COMBOS.forEach((c, i) => {
      engine.setStaticRoute(sidC, GET, `/c/${i}`, c.status, c.headers, c.body);
      engine.setStaticRoute(sidC, HEAD, `/c/${i}`, c.status, c.headers, c.body);
    });

    try {
      let exchanges = 0;
      for (let i = 0; i < COMBOS.length; i++) {
        const c = COMBOS[i];
        for (const method of ['GET', 'HEAD']) {
          for (const f of FRAMINGS) {
            const reqBytes = f.line(method, `/c/${i}`);
            const opts = { expectClose: f.expectClose, responses: f.n, head: method === 'HEAD' };
            const [a, b, s] = await Promise.all([
              exchange(portA, reqBytes, opts),
              exchange(portB, reqBytes, opts),
              exchange(portC, reqBytes, opts),
            ]);
            const label = `${method} ${c.status} headers=${c.hname} body=${c.bname} ${f.name}`;
            assert.ok(a.length > 0, `${label}: no response from respond()`);
            assert.equal(stripDate(b), stripDate(a), `${label}: respondPrepared() bytes differ`);
            assert.equal(stripDate(s), stripDate(a), `${label}: static route bytes differ`);
            exchanges++;
          }
        }
      }
      assert.equal(jsHits, 0, 'static routes never reached JS');
      assert.equal(exchanges, COMBOS.length * 2 * FRAMINGS.length);
    } finally {
      engine.close(sidA);
      engine.close(sidB);
      engine.close(sidC);
    }
  });
});
