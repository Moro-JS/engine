// RFC 6455 WebSocket protocol conformance suite for @morojs/engine.
//
// Unlike test/websocket-unit.cpp (which unit-tests src/websocket.h in isolation),
// this suite drives the REAL running engine over a raw TCP socket. Every frame
// the client sends is crafted byte-for-byte here (no `ws` library), so protocol
// violations and adversarial framing can be exercised directly against the
// engine's native parser + framer + I/O path.
//
// The engine handles the handshake, ping/pong, close handshake, and connection
// failure natively (see src/websocket.h / src/server.h). The fixture server
// upgrades every request and echoes text/binary messages back verbatim.
//
// When the native binding is not usable (binary missing, probe().ok false, or
// serve()/upgradeToWebSocket() absent) the whole suite reports SKIPPED, never
// FAILED, and the process exits 0. Run with: node --test
//
// Behaviors that are RFC-permissible but engine-specific are documented inline
// and asserted as the ACTUAL behavior. On a protocol error the engine sends a
// Close frame with the failure's status code first (RFC 6455 §7.1.7: 1002,
// 1007 for invalid UTF-8, 1009 for a message over the size limit), reports
// the same code to onWsClose, then half-closes and reads until the peer has
// closed too (§7.1.1) - see the "connection failure" and "closes the server
// starts" tests.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const skip =
  engine && typeof engine.upgradeToWebSocket === 'function' && typeof engine.wsSend === 'function'
    ? false
    : '@morojs/engine native binding not usable for WebSocket testing ' +
      '(binary missing, probe().ok false, or upgradeToWebSocket()/wsSend() not implemented) — WS conformance suite skipped';

// Generous per-test ceiling; individual frame reads have their own timeouts.
const T = { timeout: 30000 };

// ---------------------------------------------------------------------------
// RFC 6455 constants
// ---------------------------------------------------------------------------

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'; // §1.3
const OP = { CONT: 0x0, TEXT: 0x1, BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };
const CRLF = '\r\n';

// §4.2.2 step 5.4: base64(SHA1(key + GUID)). Computed independently of the
// engine so the handshake test verifies the engine, not our own helper.
function computeAccept(key) {
  return crypto.createHash('sha1').update(key + GUID).digest('base64');
}

// ---------------------------------------------------------------------------
// Client-side frame encoder — client frames MUST be masked (§5.1 / §5.3).
// Every knob (fin, rsv, opcode, mask on/off, mask key, forced length form) is
// exposed so the adversarial tests can violate exactly one rule at a time.
// ---------------------------------------------------------------------------

function toBuf(payload) {
  if (Buffer.isBuffer(payload)) return payload;
  if (payload instanceof Uint8Array) return Buffer.from(payload);
  return Buffer.from(String(payload), 'utf8');
}

function buildFrame({ fin = true, rsv = 0, opcode, mask = true, payload = Buffer.alloc(0), maskKey } = {}) {
  const body = toBuf(payload);
  const len = body.length;

  const header = [];
  header.push(((fin ? 0x80 : 0) | ((rsv & 0x7) << 4) | (opcode & 0x0f)) & 0xff);

  const maskBit = mask ? 0x80 : 0x00;
  if (len < 126) {
    header.push(maskBit | len);
  } else if (len <= 0xffff) {
    header.push(maskBit | 126, (len >> 8) & 0xff, len & 0xff);
  } else {
    // 64-bit extended length, big-endian (§5.2). Test payloads stay < 2^32,
    // so the high 32 bits are always zero.
    const hi = Math.floor(len / 2 ** 32);
    const lo = len >>> 0;
    header.push(
      maskBit | 127,
      (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
      (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff
    );
  }

  if (!mask) return Buffer.concat([Buffer.from(header), body]);

  const key = maskKey ? Buffer.from(maskKey) : crypto.randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = body[i] ^ key[i & 3]; // §5.3
  return Buffer.concat([Buffer.from(header), key, masked]);
}

// ---------------------------------------------------------------------------
// Frame decoder for server-to-client frames (never masked, §5.1). Returns the
// decoded frame and how many bytes it consumed, or null if `buf` holds an
// incomplete frame. Tolerates (but never expects) a mask bit.
// ---------------------------------------------------------------------------

function tryDecodeFrame(buf) {
  if (buf.length < 2) return null;
  const b0 = buf[0];
  const b1 = buf[1];
  const fin = (b0 & 0x80) !== 0;
  const rsv = (b0 >> 4) & 0x7;
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  let len = b1 & 0x7f;
  let offset = 2;
  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    offset = 4;
  } else if (len === 127) {
    if (buf.length < 10) return null;
    len = Number(buf.readBigUInt64BE(2));
    offset = 10;
  }
  let maskKey = null;
  if (masked) {
    if (buf.length < offset + 4) return null;
    maskKey = buf.subarray(offset, offset + 4);
    offset += 4;
  }
  if (buf.length < offset + len) return null;
  let payload = Buffer.from(buf.subarray(offset, offset + len));
  if (masked) for (let i = 0; i < len; i++) payload[i] ^= maskKey[i & 3];
  return { fin, rsv, opcode, masked, payload, consumed: offset + len };
}

// ---------------------------------------------------------------------------
// Raw byte-level TCP client with WebSocket helpers layered on top. Manages its
// own growing buffer so frame boundaries are under test control.
// ---------------------------------------------------------------------------

// allowHalfOpen: the client does not answer the server's FIN with its own
// (what a peer that is still sending looks like to the server).
function openWs(port, host = '127.0.0.1', { allowHalfOpen = false } = {}) {
  return new Promise((resolveConnect, rejectConnect) => {
    const socket = net.connect({ host, port, allowHalfOpen });
    socket.setNoDelay(true);

    let connected = false;
    let closed = false;
    let ended = false;   // the server's FIN arrived
    let errored = null;  // a socket error after connect (ECONNRESET, EPIPE)
    let buf = Buffer.alloc(0);
    const waiters = new Set();
    const pump = () => {
      for (const w of [...waiters]) w();
    };

    socket.on('connect', () => {
      connected = true;
      resolveConnect(client);
    });
    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      pump();
    });
    socket.on('end', () => {
      ended = true;
      pump();
    });
    socket.on('error', (err) => {
      if (!connected) rejectConnect(err);
      else errored = err;
    });
    socket.on('close', () => {
      closed = true;
      pump();
    });

    // Wait until check() returns a value !== undefined, resolving with it.
    // On socket close with no value: reject (rejectOnClose) or resolve(undefined).
    function waitFor(check, { timeout = 5000, rejectOnClose = true, label = 'condition' } = {}) {
      return new Promise((resolve, reject) => {
        let done = false;
        const settle = (fn) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          waiters.delete(w);
          fn();
        };
        const w = () => {
          const r = check();
          if (r !== undefined) return settle(() => resolve(r));
          if (closed) {
            if (rejectOnClose) settle(() => reject(new Error(`socket closed before ${label} was met`)));
            else settle(() => resolve(undefined));
          }
        };
        const timer = setTimeout(
          () => settle(() => reject(new Error(`${label} not met within ${timeout}ms`))),
          timeout
        );
        waiters.add(w);
        w();
      });
    }

    const client = {
      socket,
      get closed() {
        return closed;
      },
      get ended() {
        return ended;
      },
      get errored() {
        return errored;
      },
      destroy() {
        socket.destroy();
      },
      send(bytes) {
        return new Promise((resolve, reject) => {
          if (closed) return reject(new Error('socket already closed'));
          socket.write(Buffer.from(bytes), (err) => (err ? reject(err) : resolve()));
        });
      },
      sendFrame(opts) {
        return this.send(buildFrame(opts));
      },
      // Read the HTTP handshake response head (up to and including CRLFCRLF).
      readHandshake({ timeout = 5000 } = {}) {
        return waitFor(
          () => {
            const idx = buf.indexOf('\r\n\r\n');
            if (idx === -1) return undefined;
            const head = buf.subarray(0, idx + 4).toString('latin1');
            buf = buf.subarray(idx + 4);
            return head;
          },
          { timeout, label: 'handshake response' }
        );
      },
      // Decode the next complete server frame, consuming it from the buffer.
      // allowClose: resolve undefined (instead of rejecting) if the socket
      // closes with no further complete frame buffered.
      nextFrame({ timeout = 5000, allowClose = false } = {}) {
        return waitFor(
          () => {
            const f = tryDecodeFrame(buf);
            if (!f) return undefined;
            buf = buf.subarray(f.consumed);
            return f;
          },
          { timeout, rejectOnClose: !allowClose, label: 'next frame' }
        );
      },
      waitClose({ timeout = 5000 } = {}) {
        return waitFor(() => (closed ? true : undefined), { timeout, label: 'socket close' });
      },
      waitEnd({ timeout = 5000 } = {}) {
        return waitFor(() => (ended ? true : undefined), { timeout, label: 'the server FIN' });
      },
      remainingBytes() {
        return buf.length;
      },
    };
  });
}

// ---------------------------------------------------------------------------
// Fixture WebSocket server: upgrade every request, echo messages verbatim,
// record open/message/close events (helpers.startFixtureServer does not wire
// the WS callbacks, so this suite starts serve() directly).
// ---------------------------------------------------------------------------

// `hooks` replaces what a callback does after the event is recorded:
// onRequest(reqId), onWsMessage(wsId, data, isBinary), onWsClose(wsId, code).
function startWsServer(serveOptions, hooks = {}) {
  const events = { opens: [], messages: [], closes: [], rejected: [], requests: [] };

  const callbacks = {
    onRequest(reqId) {
      events.requests.push(reqId);
      if (hooks.onRequest) return hooks.onRequest(reqId);
      const wsId = engine.upgradeToWebSocket(reqId);
      if (wsId === -1) {
        // Not a valid upgrade request (§4.2.1): keep it HTTP and answer 400.
        events.rejected.push(reqId);
        engine.respond(reqId, 400, ['content-type', 'text/plain'], 'not a websocket upgrade');
      }
    },
    onAborted() {},
    onWritable() {},
    onWsOpen(wsId, path) {
      events.opens.push({ wsId, path });
    },
    onWsMessage(wsId, data, isBinary) {
      const size = isBinary ? data.byteLength : Buffer.byteLength(data, 'utf8');
      events.messages.push({ wsId, isBinary, size });
      if (hooks.onWsMessage) return hooks.onWsMessage(wsId, data, isBinary);
      engine.wsSend(wsId, data, isBinary); // echo verbatim
    },
    onWsClose(wsId, code) {
      events.closes.push({ wsId, code });
      if (hooks.onWsClose) hooks.onWsClose(wsId, code);
    },
  };

  const serverId = engine.serve(callbacks, serveOptions);
  let port = engine.listen(serverId, '127.0.0.1', 0);
  if (!Number.isInteger(port) || port <= 0) {
    // Fallback: probe a few fixed ports if ephemeral binding is unavailable.
    let bound = 0;
    for (let attempt = 0; attempt < 25 && !bound; attempt++) {
      const candidate = 20000 + Math.floor(Math.random() * 5001);
      try {
        const p = engine.listen(serverId, '127.0.0.1', candidate);
        if (Number.isInteger(p) && p > 0) bound = p;
      } catch {
        /* try another */
      }
    }
    if (!bound) throw new Error('could not bind a fixture WS port');
    port = bound;
  }

  let closed = false;
  return {
    serverId,
    port,
    events,
    close() {
      if (closed) return;
      closed = true;
      engine.close(serverId);
    },
  };
}

// Standard upgrade request. Toggle key/version presence and values for the
// handshake-rejection tests.
function upgradeRequest(
  path = '/',
  { key, version = '13', includeKey = true, includeVersion = true, host = '127.0.0.1', extra = '', method = 'GET', httpVersion = '1.1' } = {}
) {
  const k = key ?? crypto.randomBytes(16).toString('base64');
  let req = `${method} ${path} HTTP/${httpVersion}${CRLF}Host: ${host}${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}`;
  if (includeKey) req += `Sec-WebSocket-Key: ${k}${CRLF}`;
  if (includeVersion) req += `Sec-WebSocket-Version: ${version}${CRLF}`;
  req += extra;
  req += CRLF;
  return { req, key: k };
}

function parseHead(head) {
  const lines = head.split('\r\n').filter((l) => l.length > 0);
  const statusLine = lines[0] || '';
  const m = /^HTTP\/1\.\d (\d{3})/.exec(statusLine);
  const status = m ? Number(m[1]) : null;
  const headers = {};
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
  }
  return { statusLine, status, headers };
}

// Open a client, drive the handshake to completion (101), assert the accept
// key + headers, and return { client, key, head, server }.
async function connectAndHandshake(server, path = '/', reqOpts = {}) {
  const client = await openWs(server.port);
  const { req, key } = upgradeRequest(path, reqOpts);
  await client.send(req);
  const head = parseHead(await client.readHandshake());
  return { client, key, head };
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForEvent(predicate, { timeout = 3000, interval = 5, message = 'event not observed' } = {}) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await delay(interval);
  }
  if (predicate()) return;
  throw new Error(message);
}

// ---------------------------------------------------------------------------

describe('@morojs/engine RFC 6455 WebSocket conformance', { skip }, () => {
  let server;
  before(() => {
    server = startWsServer();
  });
  after(() => {
    if (server) server.close();
  });

  // ---- Handshake (§4.2.2) ----

  it('handshake: valid Upgrade gets 101 with correct Sec-WebSocket-Accept', T, async () => {
    const client = await openWs(server.port);
    try {
      const key = crypto.randomBytes(16).toString('base64');
      const { req } = upgradeRequest('/chat', { key });
      await client.send(req);
      const head = parseHead(await client.readHandshake());

      assert.equal(head.status, 101, `expected 101 Switching Protocols, got ${head.statusLine}`);
      assert.match(head.statusLine, /^HTTP\/1\.1 101 /);
      assert.equal((head.headers['upgrade'] || '').toLowerCase(), 'websocket');
      assert.equal((head.headers['connection'] || '').toLowerCase(), 'upgrade');
      assert.equal(
        head.headers['sec-websocket-accept'],
        computeAccept(key),
        'Sec-WebSocket-Accept must be base64(SHA1(key + GUID))'
      );
      // The RFC 6455 §1.3 worked example, verified end-to-end for good measure.
      assert.equal(computeAccept('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
      await waitForEvent(() => server.events.opens.length > 0, { message: 'onWsOpen never fired' });
      assert.equal(server.events.opens.at(-1).path, '/chat', 'onWsOpen must receive the request path');
    } finally {
      client.destroy();
    }
  });

  it('handshake rejection: missing Sec-WebSocket-Key is NOT upgraded (no 101)', T, async () => {
    const client = await openWs(server.port);
    try {
      const { req } = upgradeRequest('/', { includeKey: false });
      await client.send(req);
      const head = parseHead(await client.readHandshake());
      assert.notEqual(head.status, 101, 'a request without Sec-WebSocket-Key must not be upgraded');
      assert.equal(head.status, 400, 'engine fixture answers a non-upgrade with 400');
    } finally {
      client.destroy();
    }
  });

  it('handshake rejection: malformed Sec-WebSocket-Key (not 16-byte base64) is NOT upgraded', T, async () => {
    // RFC 6455 §4.1: the key must be the base64 of a 16-byte nonce - exactly
    // 24 bytes, 22 alphabet chars + "==". Anything else is refused (§4.2.1).
    const badKeys = [
      'short',                          // wrong length
      'x'.repeat(24),                   // 24 bytes but no "==" padding
      'dGhlIHNhbXBsZSBub25jZQ=',        // 23 bytes (truncated)
      'dGhlIHNhbXBsZSBub25jZQ==x',      // 25 bytes
      '!!!!!!!!!!!!!!!!!!!!!!==',       // padding right, alphabet wrong
    ];
    for (const bad of badKeys) {
      const client = await openWs(server.port);
      try {
        const { req } = upgradeRequest('/', { key: bad });
        await client.send(req);
        const head = parseHead(await client.readHandshake());
        assert.notEqual(head.status, 101, `key ${JSON.stringify(bad)} must not be upgraded`);
        assert.equal(head.status, 400, 'engine fixture answers a non-upgrade with 400');
      } finally {
        client.destroy();
      }
    }
  });

  it('handshake rejection: Sec-WebSocket-Version != 13 is NOT upgraded (no 101)', T, async () => {
    const client = await openWs(server.port);
    try {
      const { req } = upgradeRequest('/', { version: '8' });
      await client.send(req);
      const head = parseHead(await client.readHandshake());
      assert.notEqual(head.status, 101, 'a wrong Sec-WebSocket-Version must not be upgraded');
      assert.equal(head.status, 400);
    } finally {
      client.destroy();
    }
  });

  // RFC 6455 §4.2.1 item 1: the handshake is "an HTTP/1.1 or higher GET
  // request". Anything else that carries the upgrade headers is an ordinary
  // request: upgradeToWebSocket() answers -1 and the application responds.
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']) {
    it(`handshake rejection: ${method} with a full set of upgrade headers is NOT upgraded (§4.2.1)`, T, async () => {
      const opens = server.events.opens.length;
      const client = await openWs(server.port);
      try {
        const extra = method === 'POST' || method === 'PUT' ? `Content-Length: 0${CRLF}` : '';
        const { req } = upgradeRequest('/', { method, extra });
        await client.send(req);
        const head = parseHead(await client.readHandshake());
        assert.equal(head.status, 400, `${method} must not be switched to the WebSocket protocol`);
        assert.equal(server.events.opens.length, opens);
      } finally {
        client.destroy();
      }
    });
  }

  it('handshake rejection: an HTTP/1.0 request with upgrade headers is NOT upgraded (§4.2.1)', T, async () => {
    const client = await openWs(server.port);
    try {
      const { req } = upgradeRequest('/', { httpVersion: '1.0' });
      await client.send(req);
      const head = parseHead(await client.readHandshake());
      assert.equal(head.status, 400, 'HTTP/1.0 cannot carry an Upgrade');
    } finally {
      client.destroy();
    }
  });

  // §11.3.1 / §11.3.5: Sec-WebSocket-Key and Sec-WebSocket-Version "MUST NOT
  // appear more than once in an HTTP request".
  it('handshake rejection: two Sec-WebSocket-Key lines are NOT upgraded (§11.3.1)', T, async () => {
    for (const second of [crypto.randomBytes(16).toString('base64'), null]) {
      const client = await openWs(server.port);
      try {
        const key = crypto.randomBytes(16).toString('base64');
        // a different second key, and the same key twice
        const { req } = upgradeRequest('/', { key, extra: `Sec-WebSocket-Key: ${second ?? key}${CRLF}` });
        await client.send(req);
        const head = parseHead(await client.readHandshake());
        assert.equal(head.status, 400, 'a request with two keys must not be upgraded');
      } finally {
        client.destroy();
      }
    }
  });

  it('handshake rejection: two Sec-WebSocket-Version lines are NOT upgraded, whatever their order (§11.3.5)', T, async () => {
    for (const [first, second] of [['8', '13'], ['13', '8'], ['13', '13']]) {
      const client = await openWs(server.port);
      try {
        const { req } = upgradeRequest('/', { version: first, extra: `Sec-WebSocket-Version: ${second}${CRLF}` });
        await client.send(req);
        const head = parseHead(await client.readHandshake());
        assert.equal(head.status, 400, `versions ${first} then ${second} must not be upgraded`);
      } finally {
        client.destroy();
      }
    }
  });

  // ---- Echo round-trips ----

  it('echo: masked text round-trips exactly, incl. multibyte UTF-8', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      const messages = ['hello world', 'café ✓ 🌍 — Ω≈ç√∫', ''];
      for (const msg of messages) {
        await client.sendFrame({ opcode: OP.TEXT, payload: Buffer.from(msg, 'utf8') });
        const f = await client.nextFrame();
        assert.equal(f.opcode, OP.TEXT, 'echoed frame must be a text frame');
        assert.equal(f.fin, true);
        assert.equal(f.masked, false, 'server-to-client frames must NOT be masked (§5.1)');
        assert.equal(f.payload.toString('utf8'), msg, 'text payload must round-trip byte-identical');
      }
    } finally {
      client.destroy();
    }
  });

  it('echo: masked binary round-trips exactly, incl. 0x00 and 0xFF', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      const payload = Buffer.alloc(256);
      for (let i = 0; i < 256; i++) payload[i] = i; // spans 0x00..0xFF
      await client.sendFrame({ opcode: OP.BINARY, payload });
      const f = await client.nextFrame();
      assert.equal(f.opcode, OP.BINARY, 'echoed frame must be a binary frame');
      assert.equal(f.masked, false);
      assert.equal(Buffer.compare(f.payload, payload), 0, 'binary payload must round-trip byte-identical');
    } finally {
      client.destroy();
    }
  });

  it('frame sizes: 125 / 126 / 65535 / 65536 length boundaries round-trip', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      for (const size of [125, 126, 65535, 65536]) {
        const payload = Buffer.alloc(size);
        for (let i = 0; i < size; i++) payload[i] = (i * 31 + 7) & 0xff;
        await client.sendFrame({ opcode: OP.BINARY, payload });
        const f = await client.nextFrame({ timeout: 10000 });
        assert.equal(f.opcode, OP.BINARY);
        assert.equal(f.payload.length, size, `echoed payload length must be ${size}`);
        assert.equal(Buffer.compare(f.payload, payload), 0, `size ${size} must round-trip byte-identical`);
      }
    } finally {
      client.destroy();
    }
  });

  // ---- Fragmentation (§5.4) ----

  it('fragmentation: text split across (fin=0 text) + (fin=1 continuation) reassembles', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      await client.sendFrame({ opcode: OP.TEXT, fin: false, payload: Buffer.from('Hel', 'utf8') });
      await client.sendFrame({ opcode: OP.CONT, fin: true, payload: Buffer.from('lo world', 'utf8') });
      const f = await client.nextFrame();
      assert.equal(f.opcode, OP.TEXT, 'reassembled message is delivered as one text frame');
      assert.equal(f.fin, true);
      assert.equal(f.payload.toString('utf8'), 'Hello world', 'fragments must be reassembled in order');
    } finally {
      client.destroy();
    }
  });

  it('interleaved control: a Ping between two fragments gets a Pong BEFORE the message', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      // Send all three in one write; the engine must surface the ping's pong
      // immediately (§5.4/§5.5), ahead of the still-incomplete data message.
      await client.send(
        Buffer.concat([
          buildFrame({ opcode: OP.TEXT, fin: false, payload: Buffer.from('Hel', 'utf8') }),
          buildFrame({ opcode: OP.PING, payload: Buffer.from('mid', 'utf8') }),
          buildFrame({ opcode: OP.CONT, fin: true, payload: Buffer.from('lo', 'utf8') }),
        ])
      );

      const first = await client.nextFrame();
      assert.equal(first.opcode, OP.PONG, 'the Pong must arrive before the reassembled message');
      assert.equal(first.payload.toString('utf8'), 'mid', 'Pong must echo the Ping payload (§5.5.3)');

      const second = await client.nextFrame();
      assert.equal(second.opcode, OP.TEXT, 'reassembled data message follows the Pong');
      assert.equal(second.payload.toString('utf8'), 'Hello');
    } finally {
      client.destroy();
    }
  });

  // ---- Ping / Pong (§5.5.2 / §5.5.3) ----

  it('ping/pong: server answers a client Ping with a Pong echoing the payload', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      const payload = Buffer.from('ping-payload-123', 'utf8');
      await client.sendFrame({ opcode: OP.PING, payload });
      const f = await client.nextFrame();
      assert.equal(f.opcode, OP.PONG, 'a Ping must be answered with a Pong');
      assert.equal(f.fin, true);
      assert.equal(Buffer.compare(f.payload, payload), 0, 'Pong payload must equal the Ping payload (§5.5.3)');
    } finally {
      client.destroy();
    }
  });

  // ---- Close handshake (§5.5.1 / §7) ----

  it('close: client Close(1000) -> server echoes a Close frame and the socket closes', T, async () => {
    const before = server.events.closes.length;
    const { client } = await connectAndHandshake(server);
    try {
      const wsId = server.events.opens.at(-1).wsId;
      const closePayload = Buffer.concat([Buffer.from([0x03, 0xe8]), Buffer.alloc(0)]); // code 1000
      await client.sendFrame({ opcode: OP.CLOSE, payload: closePayload });

      const f = await client.nextFrame();
      assert.equal(f.opcode, OP.CLOSE, 'server must echo a Close frame (§5.5.1)');
      assert.equal(f.masked, false);
      assert.ok(f.payload.length >= 2, 'echoed Close carries a 2-byte status code');
      assert.equal(f.payload.readUInt16BE(0), 1000, 'echoed Close code must be 1000');

      await client.waitClose();
      assert.equal(client.closed, true, 'the TCP socket must close after the close handshake');

      await waitForEvent(() => server.events.closes.length > before, { message: 'onWsClose never fired' });
      assert.equal(server.events.closes.at(-1).code, 1000, 'onWsClose must report code 1000');
      assert.equal(server.events.closes.at(-1).wsId, wsId);
    } finally {
      client.destroy();
    }
  });

  it('close code parsing: Close(1001, reason) -> onWsClose sees 1001', T, async () => {
    const before = server.events.closes.length;
    const { client } = await connectAndHandshake(server);
    try {
      const reason = Buffer.from('going away', 'utf8');
      const closePayload = Buffer.concat([Buffer.from([0x03, 0xe9]), reason]); // code 1001
      await client.sendFrame({ opcode: OP.CLOSE, payload: closePayload });

      const f = await client.nextFrame();
      assert.equal(f.opcode, OP.CLOSE);
      assert.equal(f.payload.readUInt16BE(0), 1001, 'echoed Close code must be 1001');
      assert.equal(f.payload.subarray(2).toString('utf8'), 'going away', 'reason is echoed back');

      await waitForEvent(() => server.events.closes.length > before, { message: 'onWsClose never fired' });
      assert.equal(server.events.closes.at(-1).code, 1001, 'onWsClose must report close code 1001 (§7.4)');
      await client.waitClose();
    } finally {
      client.destroy();
    }
  });

  // ---- Protocol violations: fail the connection (§7.1.7) ----
  //
  // On a protocol error the engine sends a 1002 Close frame (bytes
  // 88 02 03 EA - §7.1.7 SHOULD) and then closes the TCP connection once it
  // flushes, surfacing close code 1002 to onWsClose. Each case asserts:
  // (a) the 1002 Close frame arrives on the wire, (b) the socket then ends,
  // and (c) onWsClose reports 1002. Each frame violates exactly ONE rule
  // (all are otherwise well-formed + masked), so the intended rule is the
  // one under test.

  async function assertConnectionFailed(makeBadFrame, label, expectedCode = 1002) {
    const before = server.events.closes.length;
    const { client } = await connectAndHandshake(server);
    try {
      await waitForEvent(() => server.events.opens.length > 0);
      const wsId = server.events.opens.at(-1).wsId;
      try {
        await client.send(makeBadFrame());
      } catch {
        // The server may slam the socket shut mid-write — that is itself a pass.
      }

      // The Close frame (e.g. 88 02 03 EA for 1002) must precede the close.
      const closeFrame = await client.nextFrame({ timeout: 5000, allowClose: true });
      assert.equal(closeFrame.opcode, OP.CLOSE, `${label}: engine must send a Close frame first (§7.1.7)`);
      assert.equal(
        closeFrame.payload.readUInt16BE(0),
        expectedCode,
        `${label}: on-wire Close code must be ${expectedCode}`
      );

      await client.waitClose({ timeout: 5000 });
      assert.equal(client.closed, true, `${label}: engine must close the connection`);

      await waitForEvent(() => server.events.closes.length > before, {
        message: `${label}: onWsClose never fired`,
      });
      const last = server.events.closes.at(-1);
      assert.equal(last.wsId, wsId, `${label}: close event must be for this connection`);
      assert.equal(
        last.code,
        expectedCode,
        `${label}: failure must surface close code ${expectedCode} (§7.1.7/§7.4.1)`
      );
    } finally {
      client.destroy();
    }
  }

  it('violation: unmasked client frame fails the connection (§5.1)', T, async () => {
    await assertConnectionFailed(
      () => buildFrame({ opcode: OP.TEXT, mask: false, payload: Buffer.from('unmasked', 'utf8') }),
      'unmasked frame'
    );
  });

  it('violation: reserved opcode 0x3 fails the connection (§5.2)', T, async () => {
    await assertConnectionFailed(
      () => buildFrame({ opcode: 0x3, payload: Buffer.from('reserved', 'utf8') }),
      'reserved opcode'
    );
  });

  it('violation: RSV1 set with no extension negotiated fails the connection (§5.2)', T, async () => {
    await assertConnectionFailed(
      () => buildFrame({ opcode: OP.TEXT, rsv: 0x4, payload: Buffer.from('rsv', 'utf8') }),
      'RSV bit set'
    );
  });

  it('violation: control frame > 125 bytes fails the connection (§5.5)', T, async () => {
    await assertConnectionFailed(
      () => buildFrame({ opcode: OP.PING, payload: Buffer.alloc(126, 0x61) }),
      'oversized control frame'
    );
  });

  it('violation: fragmented control frame (fin=0 Ping) fails the connection (§5.5)', T, async () => {
    await assertConnectionFailed(
      () => buildFrame({ opcode: OP.PING, fin: false, payload: Buffer.from('frag', 'utf8') }),
      'fragmented control frame'
    );
  });

  it('violation: continuation with no message in progress fails the connection (§5.4)', T, async () => {
    await assertConnectionFailed(
      () => buildFrame({ opcode: OP.CONT, fin: true, payload: Buffer.from('orphan', 'utf8') }),
      'orphan continuation'
    );
  });

  it('violation: invalid UTF-8 in a text message fails the connection with 1007 (§8.1)', T, async () => {
    await assertConnectionFailed(
      () => buildFrame({ opcode: OP.TEXT, payload: Buffer.from([0xff, 0xfe, 0xfd]) }),
      'invalid UTF-8',
      1007 // §7.4.1: Invalid frame payload data
    );
  });

  // §7.4.1: reserved/undefined close status codes MUST NOT appear on the wire.
  // A Close carrying one is a protocol error and fails the connection (1002).
  const closeFrame = (code) =>
    buildFrame({ opcode: OP.CLOSE, payload: Buffer.from([(code >> 8) & 0xff, code & 0xff]) });
  for (const bad of [0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000]) {
    it(`violation: Close with reserved code ${bad} fails the connection (§7.4.1)`, T, async () => {
      await assertConnectionFailed(() => closeFrame(bad), `close code ${bad}`);
    });
  }

  it('valid Close codes (1000, 1011, 3000, 4999) are accepted, not failed', T, async () => {
    for (const code of [1000, 1011, 3000, 4999]) {
      const before = server.events.closes.length;
      const { client } = await connectAndHandshake(server);
      try {
        await waitForEvent(() => server.events.opens.length > 0);
        await client.sendFrame({
          opcode: OP.CLOSE,
          payload: Buffer.from([(code >> 8) & 0xff, code & 0xff]),
        });
        const f = await client.nextFrame();
        assert.equal(f.opcode, OP.CLOSE, `code ${code}: server echoes a Close (clean handshake, not a failure)`);
        await waitForEvent(() => server.events.closes.length > before, {
          message: `code ${code}: onWsClose never fired`,
        });
        assert.equal(server.events.closes.at(-1).code, code, `onWsClose must report ${code}`);
      } finally {
        client.destroy();
      }
    }
  });

  it('DoS: a flood of Ping frames on a never-reading socket is shed, not buffered without bound', T, async () => {
    // Regression for the Pong-queue OOM: the engine bounds its outgoing queue
    // and sheds a peer that floods Pings while never reading the Pongs.
    const { client } = await connectAndHandshake(server);
    try {
      await waitForEvent(() => server.events.opens.length > 0);
      const ping = buildFrame({ opcode: OP.PING, payload: Buffer.alloc(1024, 0x61) });
      // Fire far more Pings than the ~1MB backpressure limit can hold as Pongs.
      for (let i = 0; i < 20000 && !client.closed; i++) {
        try {
          await client.send(ping);
        } catch {
          break; // server slammed the socket — that is the shed we want
        }
      }
      await client.waitClose({ timeout: 5000 });
      assert.equal(client.closed, true, 'engine must shed a Ping-flooding, non-reading peer');
    } finally {
      client.destroy();
    }
  });

  // ---- Connection reuse & larger payloads ----

  // ---- Pipelined frames: one read, one write ----
  //
  // A client that writes several frames back to back lands them in one TCP
  // segment. The engine answers every frame the read buffer holds into one
  // corked write (feedWebSocket), so the echoes must all arrive, in order,
  // byte-identical - and a Close frame inside the batch must be answered after
  // the frames ahead of it, with the socket closing only once everything is
  // out.

  it('pipelined: sixteen masked frames in one segment all echo, in order', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      const frames = [];
      const batch = [];
      for (let i = 0; i < 16; i++) {
        const isBinary = i % 3 === 2;
        const payload = isBinary
          ? Buffer.from([i, 0x00, 0xff, i * 7])
          : Buffer.from(`frame ${i} ${'x'.repeat(i * 9)}`, 'utf8');
        frames.push({ opcode: isBinary ? OP.BINARY : OP.TEXT, payload });
        batch.push(buildFrame({ opcode: isBinary ? OP.BINARY : OP.TEXT, payload }));
      }
      await client.send(Buffer.concat(batch));
      for (let i = 0; i < 16; i++) {
        const f = await client.nextFrame();
        assert.equal(f.opcode, frames[i].opcode, `frame ${i}: opcode must match`);
        assert.equal(f.fin, true);
        assert.equal(f.masked, false, 'server frames are never masked (§5.1)');
        assert.ok(f.payload.equals(frames[i].payload), `frame ${i}: payload must round-trip in order`);
      }
    } finally {
      client.destroy();
    }
  });

  it('pipelined: a Ping and a Close inside a batch are answered in order, then the socket closes', T, async () => {
    const before = server.events.closes.length;
    const { client } = await connectAndHandshake(server);
    try {
      const wsId = server.events.opens.at(-1).wsId;
      const batch = Buffer.concat([
        buildFrame({ opcode: OP.TEXT, payload: Buffer.from('one') }),
        buildFrame({ opcode: OP.PING, payload: Buffer.from('ping!') }),
        buildFrame({ opcode: OP.TEXT, payload: Buffer.from('two') }),
        buildFrame({ opcode: OP.CLOSE, payload: Buffer.from([0x03, 0xe8]) }),
        // Anything after a Close in the same segment must be ignored (§5.5.1)
        buildFrame({ opcode: OP.TEXT, payload: Buffer.from('ignored') }),
      ]);
      await client.send(batch);
      const a = await client.nextFrame();
      assert.equal(a.opcode, OP.TEXT);
      assert.equal(a.payload.toString(), 'one');
      const p = await client.nextFrame();
      assert.equal(p.opcode, OP.PONG, 'the Ping is answered where it stood in the batch');
      assert.equal(p.payload.toString(), 'ping!');
      const b = await client.nextFrame();
      assert.equal(b.opcode, OP.TEXT);
      assert.equal(b.payload.toString(), 'two');
      const c = await client.nextFrame();
      assert.equal(c.opcode, OP.CLOSE, 'the Close is echoed after the frames ahead of it');
      assert.equal(c.payload.readUInt16BE(0), 1000);
      await client.waitClose();
      assert.equal(client.closed, true, 'the TCP socket closes once the batch is out');
      await waitForEvent(() => server.events.closes.length > before, { message: 'onWsClose never fired' });
      assert.equal(server.events.closes.at(-1).code, 1000);
      assert.equal(
        server.events.messages.filter((m) => m.wsId === wsId).length,
        2,
        'only the two frames ahead of the Close reach onWsMessage; the one after it must not'
      );
    } finally {
      client.destroy();
    }
  });

  // ---- Engine-side upgrades (capabilities.wsAutoUpgrade) ----

  describe('wsAutoUpgrade: the engine performs the handshake itself', { skip: typeof engine.setWsAutoUpgrade !== 'function' }, () => {
    let auto;
    before(() => {
      auto = startWsServer();
      engine.setWsAutoUpgrade(auto.serverId, true);
    });
    after(() => {
      if (auto) auto.close();
    });

    it('a valid handshake gets its 101 and onWsOpen without onRequest ever running', T, async () => {
      const requestsBefore = auto.events.requests.length;
      const client = await openWs(auto.port);
      try {
        const key = crypto.randomBytes(16).toString('base64');
        const { req } = upgradeRequest('/room?org=42&x=y', { key, extra: `X-Token: abc${CRLF}Cookie: a=1${CRLF}Cookie: b=2${CRLF}` });
        await client.send(req);
        const head = parseHead(await client.readHandshake());
        assert.equal(head.status, 101);
        assert.equal(head.headers['sec-websocket-accept'], computeAccept(key));
        await waitForEvent(() => auto.events.opens.length > 0, { message: 'onWsOpen never fired' });
        const open = auto.events.opens.at(-1);
        assert.equal(open.path, '/room', 'onWsOpen gets the request path');
        assert.equal(auto.events.requests.length, requestsBefore, 'onRequest must not see an engine-side upgrade');

        // The handshake stays readable on the socket
        const flat = engine.wsGetHeaders(open.wsId);
        assert.ok(Array.isArray(flat) && flat.length >= 2);
        const headers = {};
        for (let i = 0; i + 1 < flat.length; i += 2) headers[flat[i]] = headers[flat[i]] ? headers[flat[i]] + ', ' + flat[i + 1] : flat[i + 1];
        assert.equal(headers['x-token'], 'abc', 'custom header, name lowercased');
        assert.equal(headers['sec-websocket-key'], key);
        assert.equal(headers['cookie'], 'a=1, b=2', 'every line is kept, in order');
        assert.equal(engine.wsGetQuery(open.wsId), 'org=42&x=y');
        assert.equal(engine.wsGetRemoteAddress(open.wsId), '127.0.0.1');

        // ...and the socket echoes like any other
        await client.sendFrame({ opcode: OP.TEXT, payload: Buffer.from('hi') });
        const f = await client.nextFrame();
        assert.equal(f.payload.toString(), 'hi');
      } finally {
        client.destroy();
      }
    });

    it('frames pipelined with the handshake still arrive, in order', T, async () => {
      const client = await openWs(auto.port);
      try {
        const { req } = upgradeRequest('/');
        await client.send(Buffer.concat([
          Buffer.from(req),
          buildFrame({ opcode: OP.TEXT, payload: Buffer.from('first') }),
          buildFrame({ opcode: OP.BINARY, payload: Buffer.from([1, 2, 3]) }),
        ]));
        const head = parseHead(await client.readHandshake());
        assert.equal(head.status, 101);
        const a = await client.nextFrame();
        assert.equal(a.opcode, OP.TEXT);
        assert.equal(a.payload.toString(), 'first');
        const b = await client.nextFrame();
        assert.equal(b.opcode, OP.BINARY);
        assert.ok(b.payload.equals(Buffer.from([1, 2, 3])));
      } finally {
        client.destroy();
      }
    });

    it('an invalid handshake and a plain request still reach onRequest', T, async () => {
      const before = auto.events.requests.length;
      let client = await openWs(auto.port);
      try {
        const { req } = upgradeRequest('/', { key: 'not-a-16-byte-nonce' });
        await client.send(req);
        const head = parseHead(await client.readHandshake());
        assert.equal(head.status, 400, 'the fixture answers a non-upgrade request with 400');
      } finally {
        client.destroy();
      }
      client = await openWs(auto.port);
      try {
        await client.send(`GET /plain HTTP/1.1${CRLF}Host: 127.0.0.1${CRLF}${CRLF}`);
        const head = parseHead(await client.readHandshake());
        assert.equal(head.status, 400);
      } finally {
        client.destroy();
      }
      assert.equal(auto.events.requests.length, before + 2, 'both went through onRequest');
    });

    it('an unsupported Sec-WebSocket-Version is answered 426 naming version 13, without reaching onRequest (§4.2.2, §4.4)', T, async () => {
      for (const version of ['8', '14', '8, 13']) {
        const before = auto.events.requests.length;
        const opens = auto.events.opens.length;
        const client = await openWs(auto.port);
        try {
          const { req } = upgradeRequest('/', { version });
          await client.send(req);
          const head = parseHead(await client.readHandshake());
          assert.equal(head.status, 426, `version ${version}: ${head.statusLine}`);
          assert.match(head.statusLine, /^HTTP\/1\.1 426 Upgrade Required$/);
          assert.equal(head.headers['sec-websocket-version'], '13');
          assert.equal((head.headers['upgrade'] || '').toLowerCase(), 'websocket', 'a 426 names the protocol to upgrade to (RFC 9110 §15.5.22)');
          assert.equal(head.headers['content-length'], '0');
          assert.equal(auto.events.requests.length, before, 'the engine answered; onRequest did not run');
          assert.equal(auto.events.opens.length, opens);
          // The connection is still an HTTP connection: a handshake with the
          // version the 426 named succeeds on it.
          const again = upgradeRequest('/retry');
          await client.send(again.req);
          const second = parseHead(await client.readHandshake());
          assert.equal(second.status, 101);
          assert.equal(second.headers['sec-websocket-accept'], computeAccept(again.key));
        } finally {
          client.destroy();
        }
      }
    });

    it('a request that is not a GET, or is HTTP/1.0, reaches onRequest whatever upgrade headers it carries', T, async () => {
      for (const opts of [{ method: 'POST', extra: `Content-Length: 0${CRLF}` }, { method: 'DELETE' }, { httpVersion: '1.0' }]) {
        const before = auto.events.requests.length;
        const opens = auto.events.opens.length;
        const client = await openWs(auto.port);
        try {
          const { req } = upgradeRequest('/', opts);
          await client.send(req);
          const head = parseHead(await client.readHandshake());
          assert.equal(head.status, 400, `${JSON.stringify(opts)}: the fixture's own answer to a request it could not upgrade`);
          assert.equal(auto.events.requests.length, before + 1, 'the application saw it as an ordinary request');
          assert.equal(auto.events.opens.length, opens);
        } finally {
          client.destroy();
        }
      }
    });

    it('the accessors answer undefined once the socket is closed', T, async () => {
      const { client } = await connectAndHandshake(auto);
      const wsId = auto.events.opens.at(-1).wsId;
      assert.equal(engine.wsGetRemoteAddress(wsId), '127.0.0.1');
      client.destroy();
      await waitForEvent(() => auto.events.closes.some((c) => c.wsId === wsId), { message: 'onWsClose never fired' });
      assert.equal(engine.wsGetHeaders(wsId), undefined);
      assert.equal(engine.wsGetQuery(wsId), undefined);
      assert.equal(engine.wsGetRemoteAddress(wsId), undefined);
    });
  });

  // ---- Closes the server starts (wsClose) ----

  describe('closes the server starts', () => {
    // One server whose message handler does what the current test says.
    let local;
    let action;
    before(() => {
      local = startWsServer(undefined, { onWsMessage: (wsId, data, isBinary) => action(wsId, data, isBinary) });
    });
    after(() => {
      if (local) local.close();
    });
    async function closeWith(fn) {
      action = fn;
      const { client } = await connectAndHandshake(local);
      await client.sendFrame({ opcode: OP.TEXT, payload: 'go' });
      return client;
    }

    // §5.5: "All control frames MUST have a payload length of 125 bytes or
    // less". Two of them are the status code, so a reason has 123.
    it('a reason longer than 123 bytes is cut so the Close stays a legal control frame (§5.5)', T, async () => {
      for (const [reason, expected] of [
        ['r'.repeat(200), 'r'.repeat(123)],
        ['r'.repeat(123), 'r'.repeat(123)],
        // 122 ASCII bytes, then two-byte characters: byte 123 would split one
        ['r'.repeat(122) + 'éé', 'r'.repeat(122)],
        // 121 bytes, then a three-byte and a four-byte character
        ['r'.repeat(120) + '€𝄞', 'r'.repeat(120) + '€'],
      ]) {
        const client = await closeWith((wsId) => engine.wsClose(wsId, 1001, reason));
        try {
          const f = await client.nextFrame();
          assert.equal(f.opcode, OP.CLOSE);
          assert.ok(f.payload.length <= 125, `Close payload of ${f.payload.length} bytes`);
          assert.equal(f.payload.readUInt16BE(0), 1001);
          assert.equal(f.payload.subarray(2).toString('utf8'), expected, 'cut at a character boundary');
          assert.equal(client.remainingBytes(), 0, 'one frame, nothing behind it');
        } finally {
          client.destroy();
        }
      }
    });

    // §7.4.1 / §7.4.2: 1005, 1006 and 1015 "MUST NOT be set as a status code
    // in a Close control frame by an endpoint"; 0-999 are not used; nothing is
    // defined from 5000 up. The frame that goes out is legal whatever
    // wsClose() was given: 1005 ("no status code was present") is a Close with
    // no status, anything else that cannot be sent goes out as 1011.
    // onWsClose reports the code as it was passed.
    it('wsClose(code) sends the code when it may appear on the wire, 1011 when it may not, and no status for 1005 (§7.4.1, §7.4.2)', T, async () => {
      for (const [code, onWire] of [
        [1005, null],
        [1006, 1011],
        [1015, 1011],
        [1004, 1011],
        [0, 1011],
        [999, 1011],
        [1016, 1011],
        [2999, 1011],
        [5000, 1011],
        [65535, 1011],
        [70000, 1011], // not 70000 mod 65536
        [-1, 1011],
        [1000, 1000],
        [1001, 1001],
        [1011, 1011],
        [1013, 1013],
        [3000, 3000],
        [4999, 4999],
      ]) {
        const before = local.events.closes.length;
        const client = await closeWith((wsId) => engine.wsClose(wsId, code, 'why'));
        try {
          const f = await client.nextFrame();
          assert.equal(f.opcode, OP.CLOSE, `wsClose(${code})`);
          if (onWire === null) {
            assert.equal(f.payload.length, 0, `wsClose(${code}): no status code, and so no reason`);
          } else {
            assert.equal(f.payload.readUInt16BE(0), onWire, `wsClose(${code})`);
            assert.equal(f.payload.subarray(2).toString(), 'why');
          }
          await client.waitClose();
          assert.deepEqual(local.events.closes.slice(before).map((c) => c.code), [code], 'onWsClose reports the code as passed');
        } finally {
          client.destroy();
        }
      }
    });

    it('wsSend() answers false for a payload it cannot send, and sends nothing', T, async () => {
      const results = [];
      const client = await closeWith((wsId) => {
        for (const bad of [42, {}, undefined, null, true, [1, 2], Symbol.iterator]) results.push(engine.wsSend(wsId, bad, false));
        results.push(engine.wsSend(wsId, 'text', false));
        results.push(engine.wsSend(wsId, Buffer.from('bytes'), true));
      });
      try {
        const a = await client.nextFrame();
        assert.equal(a.opcode, OP.TEXT);
        assert.equal(a.payload.toString(), 'text', 'the first frame on the wire is the first payload that could be sent');
        const b = await client.nextFrame();
        assert.equal(b.opcode, OP.BINARY);
        assert.equal(b.payload.toString(), 'bytes');
        assert.deepEqual(results, [false, false, false, false, false, false, false, true, true]);
        assert.equal(client.remainingBytes(), 0);
        assert.equal(client.closed, false, 'the socket is unaffected');
      } finally {
        client.destroy();
      }
    });

    // RFC 6455 §7.1.1: to close cleanly the server half-closes and reads
    // until the peer has closed too. A peer that is still sending when the
    // server's Close goes out must receive that Close: closed outright, its
    // bytes in flight are answered with a RST, and the RST discards what the
    // peer had not read yet - the Close frame and its status code.
    it('a Close for a message over the size limit reaches a client that is still uploading it (1009, every time)', { timeout: 60000 }, async () => {
      const small = startWsServer({ wsMaxMessageSize: 1024 * 1024 }, { onWsMessage() {} });
      const trials = 15;
      let seen = 0;
      const lost = [];
      try {
        for (let t = 0; t < trials; t++) {
          const { client } = await connectAndHandshake(small);
          try {
            // 4 MiB against a 1 MiB limit: the server answers after the frame
            // header, with megabytes still on their way.
            client.socket.write(buildFrame({ opcode: OP.BINARY, payload: Buffer.alloc(4 * 1024 * 1024, 1), maskKey: [0, 0, 0, 0] }));
            await client.waitClose({ timeout: 10000 }).catch(() => {});
            const f = await client.nextFrame({ allowClose: true, timeout: 500 }).catch(() => undefined);
            if (f && f.opcode === OP.CLOSE && f.payload.readUInt16BE(0) === 1009) seen++;
            else lost.push(client.errored ? client.errored.code : 'EOF without a Close');
          } finally {
            client.destroy();
          }
        }
        assert.equal(seen, trials, `the client lost the Close frame in ${trials - seen} of ${trials} uploads: ${lost}`);
        assert.equal(small.events.closes.length, trials);
        assert.ok(small.events.closes.every((c) => c.code === 1009));
      } finally {
        small.close();
      }
    });

    it('after its Close the server sends FIN, drops what the peer still sends, and closes when the peer does', T, async () => {
      let delivered = 0;
      action = (wsId) => {
        delivered++;
        engine.wsClose(wsId, 4001, 'policy');
      };
      // allowHalfOpen: this client decides when its own side closes
      const client = await openWs(local.port, '127.0.0.1', { allowHalfOpen: true });
      try {
        await client.send(upgradeRequest('/').req);
        assert.equal(parseHead(await client.readHandshake()).status, 101);
        await client.sendFrame({ opcode: OP.TEXT, payload: 'go' });
        const f = await client.nextFrame();
        assert.equal(f.opcode, OP.CLOSE);
        assert.equal(f.payload.readUInt16BE(0), 4001);
        await client.waitEnd();
        // The peer keeps sending for a while: no reset, nothing delivered.
        for (let i = 0; i < 10; i++) {
          await client.sendFrame({ opcode: OP.TEXT, payload: 'x'.repeat(4096) });
          await delay(10);
        }
        assert.equal(client.errored, null, `the connection was reset: ${client.errored}`);
        assert.equal(client.closed, false, 'the server waits for the peer to close');
        assert.equal(delivered, 1, 'frames that follow the server Close are not delivered');
        // The peer answers with its own Close and closes: the server is done.
        await client.sendFrame({ opcode: OP.CLOSE, payload: Buffer.from([0x0f, 0xa1]) });
        client.socket.end();
        await client.waitClose();
        assert.equal(client.errored, null);
      } finally {
        client.destroy();
      }
    });

    it('a peer that never closes its side is cut at the linger deadline', T, async () => {
      action = (wsId) => engine.wsClose(wsId, 1000, '');
      const client = await openWs(local.port, '127.0.0.1', { allowHalfOpen: true });
      try {
        await client.send(upgradeRequest('/').req);
        assert.equal(parseHead(await client.readHandshake()).status, 101);
        await client.sendFrame({ opcode: OP.TEXT, payload: 'go' });
        assert.equal((await client.nextFrame()).opcode, OP.CLOSE);
        await client.waitEnd();
        // The peer never sends its FIN; it keeps writing a little. While the
        // server lingers the bytes are taken; once it has closed, a write is
        // answered with a reset. 2 s of linger, checked by a sweep that runs
        // at most once a second.
        const t0 = Date.now();
        while (!client.closed && Date.now() - t0 < 8000) {
          client.socket.write(buildFrame({ opcode: OP.PING, payload: 'still here' }));
          await delay(50);
        }
        const waited = Date.now() - t0;
        assert.equal(client.closed, true, 'the server kept a half-closed WebSocket for more than 8 s');
        assert.ok(waited >= 500 && waited < 5000, `cut after ${waited} ms`);
      } finally {
        client.destroy();
      }
    });
  });

  // ---- onWsClose: once per socket, whatever the callback does ----

  describe('onWsClose fires once, also when the callback calls back into the engine', () => {
    it('wsClose() from inside the onWsClose of a socket whose peer went away does not fire it again; the accessors still answer', T, async () => {
      const calls = [];
      const local = startWsServer(undefined, {
        onWsClose(wsId, code) {
          const headers = engine.wsGetHeaders(wsId);
          calls.push({ code, headers: Array.isArray(headers) && headers.includes('x-who'), address: engine.wsGetRemoteAddress(wsId) });
          engine.wsClose(wsId, 1000, ''); // a "make sure it is closed" cleanup
        },
      });
      try {
        const { client } = await connectAndHandshake(local, '/', { extra: `X-Who: me${CRLF}` });
        client.destroy(); // FIN, no Close frame
        await waitForEvent(() => calls.length > 0, { message: 'onWsClose never fired' });
        await delay(100);
        assert.deepEqual(calls, [{ code: 1006, headers: true, address: '127.0.0.1' }]);
        assert.equal(local.events.closes.length, 1);
      } finally {
        local.close();
      }
    });

    it('wsSend() from inside onWsClose answers false on every way a socket closes', T, async () => {
      const results = [];
      const local = startWsServer(undefined, {
        onWsMessage: (wsId) => engine.wsClose(wsId, 1001, ''),
        onWsClose(wsId, code) {
          results.push([code, engine.wsSend(wsId, 'x', false)]);
        },
      });
      try {
        const a = await connectAndHandshake(local);
        a.client.destroy(); // the peer goes away
        await waitForEvent(() => results.length === 1, { message: 'no onWsClose for a peer that went away' });
        const b = await connectAndHandshake(local);
        await b.client.sendFrame({ opcode: OP.CLOSE }); // the peer's Close frame
        await waitForEvent(() => results.length === 2, { message: 'no onWsClose for a Close frame' });
        b.client.destroy();
        const c = await connectAndHandshake(local);
        await c.client.sendFrame({ opcode: OP.TEXT, payload: 'close me' }); // the server's own wsClose()
        await waitForEvent(() => results.length === 3, { message: 'no onWsClose for wsClose()' });
        c.client.destroy();
        const d = await connectAndHandshake(local);
        await d.client.sendFrame({ opcode: 0x3 }); // a protocol error
        await waitForEvent(() => results.length === 4, { message: 'no onWsClose for a protocol error' });
        d.client.destroy();
        assert.deepEqual(results, [[1006, false], [1005, false], [1001, false], [1002, false]]);
      } finally {
        local.close();
      }
    });

    // A broadcast that reaches a client which has just gone: the peer's reset
    // is on the socket, the loop has not read it yet, and the send is what
    // finds the error. The close is reported once wsSend() has returned,
    // never from inside it: there the binding may be reading a string
    // payload straight out of the V8 heap, and V8 ends the process if JS
    // runs under that. The bytes payload goes first: it is not read that
    // way, so a callback made inside the send fails this test instead.
    //
    // MORO_ENGINE_NOTIFY=sync is the mode in which notifications are
    // delivered where they arise: there the close is reported from inside
    // the send that found the reset, and the binding copies the payload
    // first so that it may be. The test then asserts that - once, for both
    // payload kinds, with the process still running.
    it('a send that finds the connection reset reports the close after wsSend() has returned', T, async () => {
      const insideSend = engine.probe().notify === 'sync';
      let sending = false;
      const seen = [];
      const local = startWsServer(undefined, {
        onWsClose: (wsId, code) => seen.push({ wsId, code, insideSend: sending }),
      });
      try {
        for (const payload of [Buffer.alloc(64 * 1024, 0x61), 'a'.repeat(64 * 1024)]) {
          const kind = typeof payload === 'string' ? 'string' : 'bytes';
          const opened = local.events.opens.length;
          const { client } = await connectAndHandshake(local);
          await waitForEvent(() => local.events.opens.length > opened, { message: 'onWsOpen never fired' });
          const { wsId } = local.events.opens.at(-1);
          client.socket.resetAndDestroy(); // RST; over loopback it is on the server's socket when this returns
          sending = true;
          try {
            engine.wsSend(wsId, payload, kind === 'bytes');
            engine.wsSend(wsId, payload, kind === 'bytes');
          } finally {
            sending = false;
          }
          await waitForEvent(() => seen.some((e) => e.wsId === wsId), { message: `${kind}: onWsClose never fired` });
          await delay(50);
          assert.deepEqual(
            seen.filter((e) => e.wsId === wsId),
            [{ wsId, code: 1006, insideSend }],
            `${kind}: one onWsClose(1006), delivered ${insideSend ? 'inside' : 'outside'} wsSend()`
          );
        }
      } finally {
        local.close();
      }
    });
  });

  // ---- Send backpressure (wsBackpressureLimit, default 1 MiB) ----
  //
  // The limit sheds a consumer that is not keeping up: one that still had
  // bytes of an earlier send waiting when the next send arrived. A message
  // larger than the limit is not, by itself, a slow consumer - it is over
  // the limit the moment it is queued, whatever its reader does.

  describe('send backpressure sheds a consumer that is not draining, not a large message', () => {
    const MiB = 1024 * 1024;
    // For the peers that do not read: far more than the kernel's socket
    // buffers take on their own (a few MiB on each side at most), so most of
    // the message is certain to be waiting in the engine's write queue.
    const STALLED = 24 * MiB;

    it('a client that is reading receives 1, 2 and 8 MiB messages and stays open', { timeout: 60000 }, async () => {
      const results = [];
      const local = startWsServer(undefined, {
        onWsMessage(wsId, data) {
          results.push(engine.wsSend(wsId, Buffer.alloc(Number(data), 0x5a), true));
        },
      });
      try {
        const { client } = await connectAndHandshake(local);
        try {
          for (const size of [1 * MiB, 2 * MiB, 8 * MiB, 16]) {
            await client.sendFrame({ opcode: OP.TEXT, payload: String(size) });
            const f = await client.nextFrame({ timeout: 30000 });
            assert.equal(f.opcode, OP.BINARY, `${size} bytes: a ${f.opcode === OP.CLOSE ? `Close ${f.payload.readUInt16BE(0)}` : 'frame'} arrived instead of the message`);
            assert.equal(f.payload.length, size);
            assert.ok(f.payload.equals(Buffer.alloc(size, 0x5a)), `${size} bytes arrived intact`);
          }
          await delay(50); // room for a deferred shed to show up
          assert.equal(client.remainingBytes(), 0, 'nothing follows the messages');
          assert.equal(client.closed, false, 'the socket stays open');
          assert.deepEqual(local.events.closes, []);
          // wsSend() still reports a queue over the high-water mark for the
          // large ones; the last, small one went straight out.
          assert.equal(results.length, 4);
          assert.equal(results[3], true);
        } finally {
          client.destroy();
        }
      } finally {
        local.close();
      }
    });

    it('a client that is not reading is shed with 1013 by the next send, and onWsClose fires once', { timeout: 60000 }, async () => {
      const results = [];
      const local = startWsServer(undefined, {
        onWsMessage(wsId, data) {
          if (data === 'large') results.push(engine.wsSend(wsId, Buffer.alloc(STALLED, 1), true));
          else results.push(engine.wsSend(wsId, 'second', false), engine.wsSend(wsId, 'third', false));
        },
      });
      try {
        const { client } = await connectAndHandshake(local);
        try {
          client.socket.pause(); // the peer stops reading
          await client.sendFrame({ opcode: OP.TEXT, payload: 'large' });
          await waitForEvent(() => results.length === 1, { message: 'the large send never ran' });
          await delay(150);
          assert.deepEqual(local.events.closes, [], 'one message with nothing queued ahead of it does not shed the socket');
          assert.equal(results[0], false, 'wsSend() reports the queue over the high-water mark');

          // The next send finds the first still queued: the consumer is slow.
          await client.sendFrame({ opcode: OP.TEXT, payload: 'more' });
          await waitForEvent(() => local.events.closes.length > 0, { message: 'a consumer with unsent data was not shed by the next send' });
          await delay(50);
          assert.deepEqual(local.events.closes.map((c) => c.code), [1013], 'onWsClose fires once, with 1013');
          assert.deepEqual(results, [false, false, false]);

          // When the peer does read, what was queued arrives in order - the
          // message, the send that shed the socket - ending with the Close
          // that says why. The send after the shed was refused, not queued.
          client.socket.resume();
          const a = await client.nextFrame({ timeout: 30000 });
          assert.equal(a.opcode, OP.BINARY);
          assert.equal(a.payload.length, STALLED);
          assert.equal((await client.nextFrame()).payload.toString(), 'second');
          const close = await client.nextFrame();
          assert.equal(close.opcode, OP.CLOSE);
          assert.equal(close.payload.readUInt16BE(0), 1013);
          await client.waitClose();
          assert.equal(local.events.closes.length, 1);
        } finally {
          client.destroy();
        }
      } finally {
        local.close();
      }
    });

    // One segment of small messages, each answered with a larger one, from a
    // peer that reads nothing: the replies stop being queued where the limit
    // is reached. The shed itself is delivered on the next loop turn, and
    // every reply of the read used to be queued in between - a few kilobytes
    // sent held the product of the message count and the reply size.
    //
    // Under MORO_ENGINE_NOTIFY=sync the shed is not put off to the next loop
    // turn: the send that reaches the limit closes the socket (1013) before
    // it returns. A closed socket delivers nothing more in any mode, so the
    // messages behind that one in the read are discarded with the
    // connection: the handler is given none of them.
    it('the replies to one read of small messages stop at the limit for a peer that is not reading', { timeout: 60000 }, async () => {
      const shedInPlace = engine.probe().notify === 'sync';
      const REPLY = 32 * 1024;
      const COUNT = 2000; // 64 MiB of replies for 14 kB sent
      const reply = Buffer.alloc(REPLY, 0x52);
      let refused = 0;
      let closedInsideSend = 0;
      let local;
      local = startWsServer(undefined, {
        onWsMessage(wsId) {
          const closesBefore = local.events.closes.length;
          if (!engine.wsSend(wsId, reply, true)) refused++;
          if (local.events.closes.length > closesBefore) closedInsideSend++;
        },
      });
      const socket = net.connect({ host: '127.0.0.1', port: local.port });
      try {
        let received = 0;
        let tail = Buffer.alloc(0);
        await new Promise((resolve, reject) => {
          socket.once('error', reject);
          socket.once('connect', () => socket.write(upgradeRequest().req));
          socket.once('data', (d) => {
            assert.match(d.toString('latin1'), /^HTTP\/1\.1 101 /);
            socket.pause(); // the peer stops reading
            resolve();
          });
        });
        socket.write(Buffer.concat(Array.from({ length: COUNT }, () => buildFrame({ opcode: OP.TEXT, payload: 'q' }))));
        await waitForEvent(() => local.events.closes.length > 0, { timeout: 15000, message: 'the consumer was never shed' });
        assert.deepEqual(local.events.closes.map((c) => c.code), [1013]);
        if (shedInPlace) {
          const delivered = local.events.messages.length;
          assert.equal(closedInsideSend, 1, 'the send that reached the limit closed the socket before it returned');
          assert.ok(refused >= 1 && refused < delivered, `sends were refused from the high-water mark on (${refused})`);
          assert.ok(delivered > 1 && delivered < COUNT / 2, `delivery stopped at the shed (${delivered} of ${COUNT})`);
          await delay(300);
          assert.equal(local.events.messages.length, delivered, 'nothing is delivered on the closed socket afterwards');
        } else {
          assert.equal(closedInsideSend, 0, 'the shed is delivered after the read, never inside a send');
          assert.equal(local.events.messages.length, COUNT, 'every message of the read was delivered');
          assert.ok(refused > COUNT / 2, `most replies were refused (${refused} of ${COUNT})`);
        }

        // What the engine kept for this peer is what the peer can still read:
        // the kernel's buffers, the limit, and little more.
        const closed = new Promise((resolve) => socket.once('close', resolve));
        socket.on('data', (d) => {
          received += d.length;
          tail = Buffer.concat([tail, d]).subarray(-4);
        });
        socket.on('error', () => {});
        socket.resume();
        await closed;
        assert.ok(
          received < 24 * MiB,
          `${(received / MiB).toFixed(1)} MiB had been queued for a peer over a ${1} MiB limit (${COUNT} replies of ${REPLY} bytes)`
        );
        assert.deepEqual([...tail], [0x88, 0x02, 0x03, 0xf5], 'the Close(1013) is the last thing sent');
      } finally {
        socket.destroy();
        local.close();
      }
    });

    // The same segment from a peer that resets the connection behind it: the
    // first reply finds the socket dead, and nothing is kept for it. Queued,
    // the replies of the whole read were held until the transport reported
    // the failed write on a later pass of the loop. (The epoll transport
    // learns of the reset before it reads and delivers none of the burst.)
    it('the replies to one read of small messages are not held for a peer that has reset the connection', { timeout: 60000 }, async () => {
      const REPLY = 64 * 1024;
      const COUNT = 4000; // 256 MiB of replies for 28 kB sent
      const reply = Buffer.alloc(REPLY, 0x52);
      let base = 0;
      let peak = 0;
      let seen = 0;
      const local = startWsServer(undefined, {
        onWsMessage(wsId) {
          engine.wsSend(wsId, reply, true);
          if ((++seen & 127) === 0) peak = Math.max(peak, process.memoryUsage().rss);
        },
      });
      try {
        const { client } = await connectAndHandshake(local);
        const burst = Buffer.concat(Array.from({ length: COUNT }, () => buildFrame({ opcode: OP.TEXT, payload: 'q' })));
        base = process.memoryUsage().rss;
        client.socket.write(burst);
        client.socket.resetAndDestroy(); // the RST is on the server's socket before the engine reads the burst
        await waitForEvent(() => local.events.closes.length > 0, { timeout: 15000, message: 'onWsClose never fired' });
        peak = Math.max(peak, process.memoryUsage().rss);
        assert.deepEqual(local.events.closes.map((c) => c.code), [1006]);
        const grew = (peak - base) / MiB;
        assert.ok(grew < 96, `resident memory grew by ${grew.toFixed(0)} MiB answering a connection that was already reset`);
      } finally {
        local.close();
      }
    });

    it('a peer that stops reading with one large message in flight is closed by responseTimeoutMs', { timeout: 60000 }, async () => {
      let sent = null;
      const local = startWsServer({ responseTimeoutMs: 1000 }, {
        onWsMessage(wsId) {
          sent = engine.wsSend(wsId, Buffer.alloc(STALLED, 2), true);
        },
      });
      try {
        const { client } = await connectAndHandshake(local);
        try {
          client.socket.pause();
          await client.sendFrame({ opcode: OP.TEXT, payload: 'go' });
          await waitForEvent(() => sent !== null, { message: 'the send never ran' });
          const t0 = Date.now();
          await delay(300);
          assert.deepEqual(local.events.closes, [], 'not shed for its size');
          // No drain progress for the whole budget: the delivery deadline
          // closes the connection (a sweep every 500 ms at this setting).
          await waitForEvent(() => local.events.closes.length > 0, { timeout: 8000, message: 'a stalled peer kept its message queued past the response timeout' });
          const waited = Date.now() - t0;
          assert.deepEqual(local.events.closes.map((c) => c.code), [1006], 'closed by the deadline, not shed with 1013');
          assert.ok(waited >= 700 && waited < 5000, `closed after ${waited} ms`);
          await delay(50);
          assert.equal(local.events.closes.length, 1);
        } finally {
          client.destroy();
        }
      } finally {
        local.close();
      }
    });
  });

  it('connection reuse: two sequential messages on one connection both echo', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      await client.sendFrame({ opcode: OP.TEXT, payload: Buffer.from('first', 'utf8') });
      const f1 = await client.nextFrame();
      assert.equal(f1.opcode, OP.TEXT);
      assert.equal(f1.payload.toString('utf8'), 'first');

      await client.sendFrame({ opcode: OP.TEXT, payload: Buffer.from('second', 'utf8') });
      const f2 = await client.nextFrame();
      assert.equal(f2.opcode, OP.TEXT);
      assert.equal(f2.payload.toString('utf8'), 'second');

      assert.equal(client.closed, false, 'connection must stay open across messages');
    } finally {
      client.destroy();
    }
  });

  it('slow-read defense: a STEADY slow WS consumer of a large frame is NOT shed (H-2, wsBackpressureLimit off)', { timeout: 60000 }, async () => {
    // Same root cause as the HTTP slow-read case: one large wsSend() is a
    // single queued write. With wsBackpressureLimit:0 (unlimited) only
    // responseTimeoutMs governs the drain, so a steadily-reading slow consumer
    // must survive on queue-shrinkage progress, not write completion.
    const local = startWsServer({ responseTimeoutMs: 1000, wsBackpressureLimit: 0 });
    const size = 12 * 1024 * 1024;
    try {
      const received = await new Promise((resolve, reject) => {
        const s = net.connect({ host: '127.0.0.1', port: local.port }, () => {
          const key = crypto.randomBytes(16).toString('base64');
          s.write(
            `GET / HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}` +
              `Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}` +
              `Sec-WebSocket-Version: 13${CRLF}${CRLF}`
          );
        });
        s.pause();
        let handshakeDone = false;
        let buf = Buffer.alloc(0);
        let frameBytes = 0;
        const payload = Buffer.alloc(size, 0x7a);
        // Expected echo: 10-byte header (127 extended length) + payload.
        const expected = 10 + size;
        const pull = setInterval(() => {
          const chunk = s.read(256 * 1024) ?? s.read();
          if (!chunk) return;
          if (!handshakeDone) {
            buf = Buffer.concat([buf, chunk]);
            const idx = buf.indexOf('\r\n\r\n');
            if (idx === -1) return;
            const head = buf.subarray(0, idx).toString('latin1');
            if (!/^HTTP\/1\.1 101/.test(head)) {
              clearInterval(pull);
              s.destroy();
              return reject(new Error(`expected 101, got: ${head.split('\r\n')[0]}`));
            }
            handshakeDone = true;
            frameBytes += buf.length - (idx + 4);
            buf = Buffer.alloc(0);
            // Now send the large frame the server will echo back.
            s.write(buildFrame({ opcode: OP.BINARY, payload }));
            return;
          }
          frameBytes += chunk.length;
          if (frameBytes >= expected) {
            clearInterval(pull);
            clearTimeout(guard);
            s.destroy();
            resolve(frameBytes);
          }
        }, 120);
        const guard = setTimeout(() => {
          clearInterval(pull);
          s.destroy();
          reject(new Error(`did not receive full echo: got ${frameBytes}/${expected}`));
        }, 40000);
        s.on('close', () => {
          if (frameBytes < expected) {
            clearInterval(pull);
            clearTimeout(guard);
            reject(new Error(`WS connection closed mid-frame at ${frameBytes}/${expected} (H-2 false positive)`));
          }
        });
        s.on('error', () => {});
      });
      assert.ok(received >= 10 + size, 'the full echoed frame must arrive uncut');
      assert.equal(local.events.closes.length, 0, 'a steadily-draining slow WS consumer must never be shed');
    } finally {
      local.close();
    }
  });

  it('larger message (~300 KB) round-trips intact', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      const size = 300 * 1024;
      const payload = Buffer.alloc(size);
      for (let i = 0; i < size; i++) payload[i] = (i * 131 + 17) & 0xff;
      await client.sendFrame({ opcode: OP.BINARY, payload });
      const f = await client.nextFrame({ timeout: 15000 });
      assert.equal(f.opcode, OP.BINARY);
      assert.equal(f.payload.length, size, 'echoed length must match');
      assert.equal(Buffer.compare(f.payload, payload), 0, 'large payload must round-trip byte-identical');
    } finally {
      client.destroy();
    }
  });

  // A large message is written from the application's bytes behind a frame
  // header of its own, not copied into a frame first: among small frames of
  // the same read it keeps its place, and sent to a socket that is not being
  // read it is queued whole behind what that socket already has waiting.
  it('large and small messages in one segment echo in order', T, async () => {
    const { client } = await connectAndHandshake(server);
    try {
      const sizes = [3, 40000, 17, 32768, 32767, 0, 200000, 125, 65536, 1];
      const payloads = sizes.map((n, i) => {
        const p = Buffer.alloc(n);
        for (let k = 0; k < n; k++) p[k] = (k * 31 + i * 7 + 3) & 0xff;
        return p;
      });
      await client.send(Buffer.concat(payloads.map((payload) => buildFrame({ opcode: OP.BINARY, payload }))));
      for (let i = 0; i < payloads.length; i++) {
        const f = await client.nextFrame({ timeout: 15000 });
        assert.equal(f.opcode, OP.BINARY, `frame ${i}`);
        assert.equal(f.payload.length, sizes[i], `frame ${i}: length`);
        assert.ok(f.payload.equals(payloads[i]), `frame ${i}: payload must round-trip in its place`);
      }
    } finally {
      client.destroy();
    }
  });

  it('large messages sent to a socket that is not being read arrive whole and in order once it reads', { timeout: 60000 }, async () => {
    const messages = Array.from({ length: 24 }, (_, i) => {
      const n = i % 4 === 3 ? 50 + i : 150000 + i * 4099;
      const p = Buffer.alloc(n);
      for (let k = 0; k < n; k++) p[k] = (k * 17 + i * 29 + 5) & 0xff;
      return p;
    });
    const ids = [];
    const local = startWsServer({ wsBackpressureLimit: 0 }, {
      onWsMessage(wsId) {
        for (const other of ids) if (other !== wsId) for (const m of messages) engine.wsSend(other, m, true);
      },
    });
    try {
      const reader = await connectAndHandshake(local);
      const writer = await connectAndHandshake(local);
      try {
        await waitForEvent(() => local.events.opens.length === 2);
        for (const o of local.events.opens) ids.push(o.wsId);
        reader.client.socket.pause();  // the kernel's buffers fill and the rest queues in the engine
        await writer.client.sendFrame({ opcode: OP.TEXT, payload: 'go' });
        await delay(300);
        reader.client.socket.resume();
        for (let i = 0; i < messages.length; i++) {
          const f = await reader.client.nextFrame({ timeout: 30000 });
          assert.equal(f.opcode, OP.BINARY, `message ${i}`);
          assert.equal(f.payload.length, messages[i].length, `message ${i}: length`);
          assert.ok(f.payload.equals(messages[i]), `message ${i}: intact and in its place`);
        }
      } finally {
        reader.client.destroy();
        writer.client.destroy();
      }
    } finally {
      local.close();
    }
  });

  // A large binary message is delivered as an ArrayBuffer over the memory it
  // was received into. The application owns it from then on: buffers kept
  // past the callback hold their own bytes whatever arrives afterwards, on
  // this socket or another, whole frames or fragments.
  it('large binary messages kept by the application keep their bytes', { timeout: 60000 }, async () => {
    const kept = [];
    const local = startWsServer({ wsMaxMessageSize: 8 * 1024 * 1024 }, {
      onWsMessage(wsId, data, isBinary) {
        if (isBinary) kept.push(data);
        engine.wsSend(wsId, isBinary ? String(data.byteLength) : 'text', false);
      },
    });
    const make = (n, seed) => {
      const p = Buffer.alloc(n);
      for (let k = 0; k < n; k++) p[k] = (k * 13 + seed * 31 + 7) & 0xff;
      return p;
    };
    try {
      const a = await connectAndHandshake(local);
      const b = await connectAndHandshake(local);
      try {
        const sizes = [300000, 20000, 1 << 20, 17000, 70000, 16385, 100, 2 * 1024 * 1024 + 5];
        const sent = [];
        for (let i = 0; i < sizes.length; i++) {
          const client = (i % 2 ? b : a).client;
          const payload = make(sizes[i], i);
          sent.push(payload);
          if (i % 3 === 2) {
            // three fragments, the middle one empty now and then
            const cut = Math.floor(sizes[i] / 3);
            await client.send(buildFrame({ fin: false, opcode: OP.BINARY, payload: payload.subarray(0, cut) }));
            await client.send(buildFrame({ fin: false, opcode: OP.CONT, payload: i % 2 ? Buffer.alloc(0) : payload.subarray(cut, 2 * cut) }));
            await client.send(buildFrame({ fin: true, opcode: OP.CONT, payload: i % 2 ? payload.subarray(cut) : payload.subarray(2 * cut) }));
          } else {
            await client.send(buildFrame({ opcode: OP.BINARY, payload }));
          }
          const f = await client.nextFrame({ timeout: 20000 });
          assert.equal(f.payload.toString(), String(sizes[i]), `message ${i}: length seen by the handler`);
        }
        // A text message in between does not come as a buffer.
        await a.client.send(buildFrame({ opcode: OP.TEXT, payload: 't'.repeat(50000) }));
        assert.equal((await a.client.nextFrame({ timeout: 20000 })).payload.toString(), 'text');
        assert.equal(kept.length, sizes.length);
        for (let i = 0; i < sizes.length; i++) {
          assert.ok(kept[i] instanceof ArrayBuffer, `message ${i} is an ArrayBuffer`);
          assert.equal(kept[i].byteLength, sizes[i], `message ${i}: length`);
          assert.ok(Buffer.from(kept[i]).equals(sent[i]), `message ${i}: its bytes, after everything that followed`);
        }
        // The buffers are the application's: writing to one changes no other.
        new Uint8Array(kept[0]).fill(0xee);
        for (let i = 1; i < sizes.length; i++) assert.ok(Buffer.from(kept[i]).equals(sent[i]), `message ${i} untouched`);
      } finally {
        a.client.destroy();
        b.client.destroy();
      }
    } finally {
      local.close();
    }
  });

  // One Node callback scope per read: the microtasks a frame handler queues
  // run after the last frame of the read (as Node's own 'data' callback would
  // run them for the frames of one segment), and before the next read.
  describe('frames of one read share a callback scope', () => {
    it('microtasks queued by frame handlers run after the read, before the next one', T, async () => {
      const order = [];
      const callbacks = {
        onRequest(reqId) {
          engine.upgradeToWebSocket(reqId);
        },
        onAborted() {},
        onWritable() {},
        onWsOpen() {},
        onWsMessage(wsId, data) {
          order.push(`msg:${data}`);
          Promise.resolve().then(() => {
            order.push(`micro:${data}`);
            engine.wsSend(wsId, `m:${data}`, false);
          });
          engine.wsSend(wsId, data, false);
        },
        onWsClose() {},
      };
      const serverId = engine.serve(callbacks, {});
      const port = engine.listen(serverId, '127.0.0.1', 0);
      const client = await openWs(port);
      try {
        const { req } = upgradeRequest('/');
        await client.send(req);
        assert.equal(parseHead(await client.readHandshake()).status, 101);
        // two frames in one write: one read on the server
        await client.send(
          Buffer.concat([
            buildFrame({ opcode: 0x1, payload: Buffer.from('a') }),
            buildFrame({ opcode: 0x1, payload: Buffer.from('b') }),
          ])
        );
        const got = [];
        for (let i = 0; i < 4; i++) got.push((await client.nextFrame({ timeout: 2000 })).payload.toString());
        assert.deepEqual(got, ['a', 'b', 'm:a', 'm:b']);
        assert.deepEqual(order, ['msg:a', 'msg:b', 'micro:a', 'micro:b']);
        // a later read: its microtasks run on its own return
        await client.sendFrame({ opcode: 0x1, payload: Buffer.from('c') });
        const later = [];
        for (let i = 0; i < 2; i++) later.push((await client.nextFrame({ timeout: 2000 })).payload.toString());
        assert.deepEqual(later, ['c', 'm:c']);
        assert.deepEqual(order.slice(4), ['msg:c', 'micro:c']);
      } finally {
        client.destroy();
        engine.close(serverId);
      }
    });
  });
});
