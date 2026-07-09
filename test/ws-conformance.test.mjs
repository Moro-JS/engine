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
// and asserted as the ACTUAL behavior (see the "connection failure" tests: the
// engine hard-closes the TCP socket on a protocol error rather than sending a
// 1002 Close frame first — RFC 6455 §7.1.7 makes the Close frame a SHOULD, and
// the engine still surfaces close code 1002 to onWsClose).

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

function openWs(port, host = '127.0.0.1') {
  return new Promise((resolveConnect, rejectConnect) => {
    const socket = net.connect({ host, port });
    socket.setNoDelay(true);

    let connected = false;
    let closed = false;
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
    socket.on('error', (err) => {
      if (!connected) rejectConnect(err);
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
      get closed() {
        return closed;
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

function startWsServer(serveOptions) {
  const events = { opens: [], messages: [], closes: [], rejected: [] };

  const callbacks = {
    onRequest(reqId) {
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
      engine.wsSend(wsId, data, isBinary); // echo verbatim
    },
    onWsClose(wsId, code) {
      events.closes.push({ wsId, code });
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
  { key, version = '13', includeKey = true, includeVersion = true, host = '127.0.0.1', extra = '' } = {}
) {
  const k = key ?? crypto.randomBytes(16).toString('base64');
  let req = `GET ${path} HTTP/1.1${CRLF}Host: ${host}${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}`;
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
});
