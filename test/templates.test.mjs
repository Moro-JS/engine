// Prepared response templates for @morojs/engine.
//
//   - prepareResponse()/respondPrepared() round trip
//   - an invalid tplId answers 500 with an empty body and keeps keep-alive
//   - a template's Content-Length is honoured on HEAD, ignored for a GET body
//   - releaseTemplates() invalidates ids and restarts numbering at 1
//   - ids are per server
//   - the 4096-per-server cap throws a RangeError, release clears it
//   - respondPreparedEmpty / writeHeadPrepared / endWith behave like their
//     respond / writeHead / end twins
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — templates suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';

function serveWith(onRequest, options) {
  const sid = engine.serve({ onRequest, onAborted() {} }, options);
  const port = engine.listen(sid, '127.0.0.1', 0);
  return { sid, port, close: () => engine.close(sid) };
}

// One raw exchange on a fresh connection; the response is returned verbatim
// (latin1) once the server closes (every request here says Connection: close
// unless `keepAlive`).
function exchange(port, requestBytes, { keepAlive = false, responses = 1, head = false } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(requestBytes, 'latin1'));
    let buf = '';
    const done = () => {
      sock.destroy();
      resolve(buf);
    };
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (keepAlive && countResponses(buf, head) >= responses) done();
    });
    sock.on('end', () => resolve(buf));
    sock.on('error', reject);
    sock.setTimeout(5000, () => reject(new Error(`timeout; got ${JSON.stringify(buf)}`)));
  });
}

// Count complete responses in a keep-alive stream (Content-Length framing,
// bodyless statuses, HEAD).
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

function parse(raw) {
  const he = raw.indexOf('\r\n\r\n');
  const head = raw.slice(0, he);
  const lines = head.split('\r\n');
  const status = parseInt(lines[0].split(' ')[1], 10);
  const headers = {};
  for (const l of lines.slice(1)) {
    const i = l.indexOf(':');
    headers[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim();
  }
  return { status, headers, body: raw.slice(he + 4) };
}

const req = (method, path, extra = 'Connection: close') =>
  `${method} ${path} HTTP/1.1${CRLF}Host: t${CRLF}${extra ? extra + CRLF : ''}${CRLF}`;

describe('prepared response templates', { skip }, () => {
  it('advertises the capability', T, () => {
    assert.equal(engine.probe().capabilities?.responseTemplates, true);
  });

  it('prepareResponse + respondPrepared round trip', T, async () => {
    let tpl = 0;
    const srv = serveWith((reqId) => engine.respondPrepared(reqId, tpl, 'payload'));
    try {
      tpl = engine.prepareResponse(srv.sid, 201, ['content-type', 'text/plain', 'x-t', '1']);
      assert.equal(tpl, 1, 'ids are dense from 1');
      const r = parse(await exchange(srv.port, req('GET', '/')));
      assert.equal(r.status, 201);
      assert.equal(r.headers['content-type'], 'text/plain');
      assert.equal(r.headers['x-t'], '1');
      assert.equal(r.headers['content-length'], '7');
      assert.equal(r.body, 'payload');
    } finally {
      srv.close();
    }
  });

  it('an invalid tplId answers 500 with an empty body and keeps the connection alive', T, async () => {
    let good = 0;
    const srv = serveWith((reqId, _m, path) => {
      if (path === '/zero') engine.respondPrepared(reqId, 0, 'x');
      else if (path === '/never') engine.respondPrepared(reqId, 424242, 'x');
      else engine.respondPrepared(reqId, good, 'ok');
    });
    try {
      good = engine.prepareResponse(srv.sid, 200, null);
      // Two requests on ONE keep-alive socket: the bad one, then a good one.
      const raw = await exchange(srv.port, req('GET', '/zero', '') + req('GET', '/good', ''), {
        keepAlive: true,
        responses: 2,
      });
      const he = raw.indexOf('\r\n\r\n');
      const first = parse(raw.slice(0, he + 4));
      assert.equal(first.status, 500);
      assert.equal(first.headers['content-length'], '0');
      assert.ok(!/connection: close/i.test(raw.slice(0, he)), 'keep-alive must survive an invalid id');
      const second = parse(raw.slice(he + 4));
      assert.equal(second.status, 200);
      assert.equal(second.body, 'ok');
      const r2 = parse(await exchange(srv.port, req('GET', '/never')));
      assert.equal(r2.status, 500);
      assert.equal(r2.body, '');
    } finally {
      srv.close();
    }
  });

  it("a template's Content-Length is honoured on HEAD and ignored for a GET body", T, async () => {
    let tpl = 0;
    const srv = serveWith((reqId) => engine.respondPrepared(reqId, tpl, 'abc'));
    try {
      tpl = engine.prepareResponse(srv.sid, 200, ['content-length', '1234', 'x-k', 'v']);
      const head = parse(await exchange(srv.port, req('HEAD', '/')));
      assert.equal(head.status, 200);
      assert.equal(head.headers['content-length'], '1234');
      assert.equal(head.body, '');
      const get = parse(await exchange(srv.port, req('GET', '/')));
      assert.equal(get.headers['content-length'], '3', 'the actual body length wins for a body-carrying reply');
      assert.equal(get.body, 'abc');
    } finally {
      srv.close();
    }
  });

  it('releaseTemplates() invalidates every id and restarts at 1', T, async () => {
    let tpl = 0;
    const srv = serveWith((reqId) => engine.respondPrepared(reqId, tpl, 'body'));
    try {
      tpl = engine.prepareResponse(srv.sid, 200, ['x-gen', 'one']);
      engine.prepareResponse(srv.sid, 200, ['x-gen', 'two']);
      assert.equal(tpl, 1);
      engine.releaseTemplates(srv.sid);
      const stale = parse(await exchange(srv.port, req('GET', '/')));
      assert.equal(stale.status, 500, 'a released id is invalid');
      const again = engine.prepareResponse(srv.sid, 200, ['x-gen', 'three']);
      assert.equal(again, 1, 'numbering restarts');
      const fresh = parse(await exchange(srv.port, req('GET', '/')));
      assert.equal(fresh.status, 200);
      assert.equal(fresh.headers['x-gen'], 'three');
    } finally {
      srv.close();
    }
  });

  it('template ids are per server', T, async () => {
    let foreign = 0;
    const a = serveWith((reqId) => engine.respondPrepared(reqId, 1, 'a'));
    const b = serveWith((reqId) => engine.respondPrepared(reqId, foreign, 'b'));
    try {
      foreign = engine.prepareResponse(a.sid, 200, ['x-owner', 'a']);
      const fromA = parse(await exchange(a.port, req('GET', '/')));
      assert.equal(fromA.status, 200);
      assert.equal(fromA.headers['x-owner'], 'a');
      const fromB = parse(await exchange(b.port, req('GET', '/')));
      assert.equal(fromB.status, 500, "server A's id means nothing to server B");
    } finally {
      a.close();
      b.close();
    }
  });

  it('the 4096-per-server cap throws a RangeError; releaseTemplates() clears it', T, () => {
    const srv = serveWith(() => {});
    try {
      for (let i = 1; i <= 4096; i++) assert.equal(engine.prepareResponse(srv.sid, 200, null), i);
      assert.throws(() => engine.prepareResponse(srv.sid, 200, null), RangeError);
      engine.releaseTemplates(srv.sid);
      assert.equal(engine.prepareResponse(srv.sid, 200, null), 1);
    } finally {
      srv.close();
    }
  });

  it('prepareResponse with an unknown serverId throws', T, () => {
    assert.throws(() => engine.prepareResponse(999999, 200, null), /invalid serverId/);
  });

  it('respondPreparedEmpty, writeHeadPrepared and endWith mirror their twins', T, async () => {
    const strip = (s) => s.replace(/^date:.*\r\n/gim, '');
    let tpl = 0;
    const headers = ['content-type', 'text/plain', 'x-m', '1'];
    const srv = serveWith((reqId, _m, path) => {
      if (path === '/empty-prepared') engine.respondPreparedEmpty(reqId, tpl);
      else if (path === '/empty-respond') engine.respond(reqId, 200, headers, '');
      else if (path === '/stream-prepared') {
        engine.writeHeadPrepared(reqId, tpl);
        engine.write(reqId, 'ab');
        engine.endWith(reqId, 'cd');
      } else if (path === '/stream-respond') {
        engine.writeHead(reqId, 200, headers);
        engine.write(reqId, 'ab');
        engine.end(reqId, 'cd');
      }
    });
    try {
      tpl = engine.prepareResponse(srv.sid, 200, headers);
      const e1 = strip(await exchange(srv.port, req('GET', '/empty-prepared')));
      const e2 = strip(await exchange(srv.port, req('GET', '/empty-respond')));
      assert.equal(e1, e2, 'respondPreparedEmpty == respond(..., "")');
      assert.match(e1, /content-length: 0/i);
      const s1 = strip(await exchange(srv.port, req('GET', '/stream-prepared')));
      const s2 = strip(await exchange(srv.port, req('GET', '/stream-respond')));
      assert.equal(s1, s2, 'writeHeadPrepared+write+endWith == writeHead+write+end');
      assert.match(s1, /transfer-encoding: chunked/i);
      assert.ok(s1.endsWith(`2${CRLF}ab${CRLF}2${CRLF}cd${CRLF}0${CRLF}${CRLF}`), JSON.stringify(s1));
    } finally {
      srv.close();
    }
  });
});
