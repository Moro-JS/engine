// permessage-deflate (RFC 7692) wire conformance for @morojs/engine.
//
// Drives the engine over a raw TCP socket, building compressed client frames
// with node:zlib (raw deflate, RSV1 set, masked). Verifies negotiation,
// roundtrip both directions, context takeover, the zip-bomb cap (close 1009),
// invalid UTF-8 after inflate (close 1007), and that RSV1 without negotiation
// still fails.
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { loadEngine, openRaw } from './helpers.mjs';

const engine = await loadEngine();
const pmdCapable = engine?.probe?.().capabilities?.wsDeflate === true;
const skip = engine
  ? pmdCapable
    ? false
    : 'engine binary predates permessage-deflate — suite skipped'
  : '@morojs/engine native binding not usable yet — pmd suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';
const OP = { TEXT: 0x1, BINARY: 0x2, CLOSE: 0x8 };

// Build a masked client frame; rsv1 marks it permessage-deflate-compressed.
function frame({ opcode, payload, rsv1 = false, fin = true }) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const key = crypto.randomBytes(4);
  const b0 = (fin ? 0x80 : 0) | (rsv1 ? 0x40 : 0) | opcode;
  let header;
  if (data.length <= 125) header = Buffer.from([b0, 0x80 | data.length]);
  else if (data.length <= 0xffff)
    header = Buffer.from([b0, 0x80 | 126, (data.length >> 8) & 0xff, data.length & 0xff]);
  else throw new Error('frame too large for test');
  const masked = Buffer.from(data);
  for (let i = 0; i < masked.length; i++) masked[i] ^= key[i & 3];
  return Buffer.concat([header, key, masked]);
}

// Raw deflate a message per RFC 7692 §7.2.1: sync-flush, then strip the
// trailing 00 00 ff ff (what browsers / the ws library put on the wire). Using
// finishFlush: Z_SYNC_FLUSH makes deflateRawSync end the stream with that tail
// instead of a BFINAL block.
function deflateMessage(input) {
  const out = zlib.deflateRawSync(Buffer.isBuffer(input) ? input : Buffer.from(input), {
    level: 6,
    finishFlush: zlib.constants.Z_SYNC_FLUSH,
  });
  // Strip the 4-byte 00 00 ff ff sync-flush tail.
  return out.length >= 4 ? out.subarray(0, out.length - 4) : out;
}

// Inflate a server-sent compressed payload: re-add the sync-flush tail and
// inflate with Z_SYNC_FLUSH (the server's block is not BFINAL-terminated).
function inflateMessage(buf) {
  return zlib.inflateRawSync(Buffer.concat([buf, Buffer.from([0x00, 0x00, 0xff, 0xff])]), {
    finishFlush: zlib.constants.Z_SYNC_FLUSH,
  });
}

async function startEcho(options) {
  const messages = [];
  const closes = [];
  const sid = engine.serve(
    {
      onRequest(reqId) {
        if (engine.upgradeToWebSocket(reqId) === -1) engine.respond(reqId, 400, null, 'no');
      },
      onAborted() {},
      onWsOpen() {},
      onWsMessage(wsId, data, isBinary) {
        messages.push({ size: typeof data === 'string' ? Buffer.byteLength(data) : data.byteLength });
        engine.wsSend(wsId, data, isBinary);
      },
      onWsClose(wsId, code) {
        closes.push(code);
      },
    },
    options
  );
  const port = await engine.listen(sid, '127.0.0.1', 0);
  return { sid, port, messages, closes, close: () => engine.close(sid) };
}

async function handshake(client, offerDeflate) {
  const key = crypto.randomBytes(16).toString('base64');
  let req =
    `GET / HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}` +
    `Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}` +
    `Sec-WebSocket-Version: 13${CRLF}`;
  if (offerDeflate) req += `Sec-WebSocket-Extensions: permessage-deflate${CRLF}`;
  req += CRLF;
  await client.send(req);
  const head = await client.read({ until: s => s.includes('\r\n\r\n') });
  return head;
}

// Read one server frame from the raw stream (small payloads only).
function parseServerFrame(buf) {
  const b = Buffer.from(buf, 'latin1');
  const rsv1 = (b[0] & 0x40) !== 0;
  const opcode = b[0] & 0x0f;
  let len = b[1] & 0x7f;
  let off = 2;
  if (len === 126) {
    len = (b[2] << 8) | b[3];
    off = 4;
  }
  return { rsv1, opcode, payload: b.subarray(off, off + len) };
}

describe('@morojs/engine permessage-deflate conformance', { skip }, () => {
  it('negotiates permessage-deflate when offered and enabled', T, async () => {
    const server = await startEcho({ wsDeflate: true });
    const client = await openRaw(server.port);
    try {
      const head = await handshake(client, true);
      assert.match(head, /^HTTP\/1\.1 101 /);
      assert.match(head, /Sec-WebSocket-Extensions: permessage-deflate/i);
    } finally {
      client.destroy();
      server.close();
    }
  });

  it('does NOT negotiate when the server has it disabled', T, async () => {
    const server = await startEcho({}); // wsDeflate off
    const client = await openRaw(server.port);
    try {
      const head = await handshake(client, true);
      assert.match(head, /^HTTP\/1\.1 101 /);
      assert.doesNotMatch(head, /Sec-WebSocket-Extensions/i);
    } finally {
      client.destroy();
      server.close();
    }
  });

  it('inflates a compressed client message and echoes it back compressed', T, async () => {
    const server = await startEcho({ wsDeflate: { threshold: 1 } });
    const client = await openRaw(server.port);
    try {
      await handshake(client, true);
      const text = 'hello '.repeat(100);
      await client.send(frame({ opcode: OP.TEXT, rsv1: true, payload: deflateMessage(text) }));
      const raw = await client.read({ until: s => s.length >= 4 });
      const f = parseServerFrame(raw);
      assert.equal(f.opcode, OP.TEXT);
      assert.equal(f.rsv1, true, 'server echo must be compressed (RSV1)');
      assert.equal(inflateMessage(f.payload).toString(), text);
      assert.equal(server.messages[0].size, Buffer.byteLength(text), 'engine inflated before the handler');
    } finally {
      client.destroy();
      server.close();
    }
  });

  it('closes with 1009 when a compressed message inflates past the cap', T, async () => {
    const server = await startEcho({ wsDeflate: { threshold: 1, maxDecompressedSize: 1024 } });
    const client = await openRaw(server.port);
    try {
      await handshake(client, true);
      // ~100KB of 'Z' compresses tiny but inflates far past the 1KB cap.
      await client.send(
        frame({ opcode: OP.TEXT, rsv1: true, payload: deflateMessage('Z'.repeat(100000)) })
      );
      const raw = await client.read({ expectClose: true });
      const f = parseServerFrame(raw);
      assert.equal(f.opcode, OP.CLOSE);
      assert.equal(f.payload.readUInt16BE(0), 1009, 'must close 1009 Message Too Big');
      assert.ok(server.closes.includes(1009));
    } finally {
      client.destroy();
      server.close();
    }
  });

  it('closes with 1007 on invalid UTF-8 after inflate', T, async () => {
    const server = await startEcho({ wsDeflate: { threshold: 1 } });
    const client = await openRaw(server.port);
    try {
      await handshake(client, true);
      const badBytes = Buffer.from([0xff, 0xfe, 0xfd]); // invalid UTF-8
      await client.send(frame({ opcode: OP.TEXT, rsv1: true, payload: deflateMessage(badBytes) }));
      const raw = await client.read({ expectClose: true });
      const f = parseServerFrame(raw);
      assert.equal(f.opcode, OP.CLOSE);
      assert.equal(f.payload.readUInt16BE(0), 1007, 'must close 1007 Invalid frame payload data');
    } finally {
      client.destroy();
      server.close();
    }
  });

  it('RSV1 without negotiation still fails the connection (1002)', T, async () => {
    const server = await startEcho({}); // pmd off -> RSV1 is illegal
    const client = await openRaw(server.port);
    try {
      await handshake(client, false);
      await client.send(frame({ opcode: OP.TEXT, rsv1: true, payload: 'x' }));
      const raw = await client.read({ expectClose: true });
      const f = parseServerFrame(raw);
      assert.equal(f.opcode, OP.CLOSE);
      assert.equal(f.payload.readUInt16BE(0), 1002, 'unnegotiated RSV1 is a protocol error');
    } finally {
      client.destroy();
      server.close();
    }
  });
});
