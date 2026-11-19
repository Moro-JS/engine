#!/usr/bin/env node
// PGO training workload: exercise the paths of the engine binary the loader
// resolves (point MORO_ENGINE_BINARY at an instrumented build) so the profile
// covers what production runs. A profile only helps the code it saw: a path
// that never runs here is compiled as cold code in every published binary.
//
//   node tools/pgo-train.mjs [--seconds=N] [--no-suites] [--only=a,b]
//   node tools/pgo-train.mjs --group=<name> [--seconds=N]   one group, in this process
//
// The workload is split into groups (TRAINING_GROUPS). Each group runs in its
// own process and, when MORO_PGO_PROFILE_DIR is set (tools/pgo.mjs sets it),
// writes its raw profiles into its own directory there. tools/pgo.mjs then
// merges the groups by `share`, not by how many requests each got through:
// every group is scaled so that it contributes its share of the merged
// counts. The shares decide what the code all protocols run through (the
// read loop, the write queue, the callback scope) is laid out for, and which
// call sites count as hot, so they are tuned by measurement (instructions per
// request, every protocol).
//
// Every phase is a fixed number of requests, not a length of time: two runs
// record nearly the same counts, on a fast machine or a slow one, so two
// builds of the same source come out nearly the same. --seconds scales the
// numbers (4, the default, is the tuned size: about ten seconds of load
// besides the suites).
//
// In-process servers, raw-socket clients:
//   http1          pipelined at depth 1 and depth 10, then 64 keep-alive
//                  connections with one request in flight on each, then a
//                  connection per request:
//                    respond()            JSON hello (the benchmark shape)
//                    respondPrepared()    same via a template
//                    static route         answered inside the engine
//                    parameter route      answered inside the engine
//                    writeHead/write/end  chunked streaming
//                    HEAD, 404, an empty 204
//   http1-requests what a framework reads from a request: bodies with
//                  Content-Length and chunked (getBody, getBodyText), a
//                  browser's header set (getHeaders, getHeader, getQuery),
//                  and the thirty headers the same request has behind a
//                  CDN and a proxy
//   websocket      text echo, binary frames at each length encoding, a
//                  fragmented message, one publisher fanned out to 32
//                  subscribers
//   ws-deflate     the echo and the fan-out with permessage-deflate
//   tls            the request shapes above over TLS, new connections (the
//                  handshake), WebSocket over TLS
//   http2          prior knowledge and over TLS: GET and POST, a response
//                  larger than one frame, and node's own client for
//                  Huffman-coded and dynamic-table header blocks
//   uring, uv      Linux, where the groups above run on epoll: a mix of all
//                  of them on the io_uring transport (where the kernel and
//                  the sandbox allow it; MORO_PGO_REQUIRE=uring makes its
//                  absence a failure) and on the libuv one
//   suites         the whole node --test suite set (same MORO_ENGINE_BINARY),
//                  which covers the error, limit and edge paths a throughput
//                  workload never reaches
// Each group exits through process.exit(0) so the profile runtime's atexit
// hook flushes the .profraw files.

import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { delimiter, dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// `share`: the part of the merged profile's counts the group contributes
// (tools/pgo.mjs scales the shares of the groups that ran to a sum of 1).
// Tuned on instructions per request (callgrind, Linux arm64) across 28
// workloads: HTTP/1.1 carries a little over half, so the shared code keeps
// the shape it had when HTTP/1.1 was all that was trained; the suites carry a
// fifth, which is what keeps once-per-request call sites above the profile's
// hot threshold (with less, the static and parameter routes lose inlining);
// each other protocol gets enough to be compiled as hot code; the request
// shapes' share is where a request with thirty headers parses fastest (0.10
// to 0.12; at 0.07 and at 0.16 it costs 0.5 to 1.4% more). Retune with
// measurements when a group's workload or the engine's hot paths change.
// `weight`: what stands in for the share where a profile's size cannot be
// read (MSVC): how many times the group's profile is merged, worked out from
// the sizes the groups have on Linux.
// `transport`: the group runs with MORO_ENGINE_TRANSPORT set to it, and is
// skipped where that transport cannot be brought up.
export const TRAINING_GROUPS = [
  { name: 'http1', share: 0.55, weight: 16 },
  { name: 'http1-requests', share: 0.12, weight: 1 },
  { name: 'websocket', share: 0.05, weight: 8 },
  { name: 'ws-deflate', share: 0.025, weight: 8 },
  { name: 'tls', share: 0.07, weight: 4 },
  { name: 'http2', share: 0.05, weight: 2 },
  { name: 'uring', share: 0.01, weight: 1, transport: 'uring', platform: 'linux' },
  { name: 'uv', share: 0.01, weight: 1, transport: 'uv', platform: 'linux' },
  { name: 'suites', share: 0.2, weight: 2 },
];

const CRLF = '\r\n';
const BODY = '{"hello":"world"}';
const HEADERS = ['content-type', 'application/json'];

async function runGroup(group, scale) {
  const { default: engine } = await import(new URL('../packages/engine/index.mjs', import.meta.url));
  const info = engine.probe();
  if (!info.ok) throw new Error(`engine failed to load: ${info.error}`);
  const caps = info.capabilities ?? {};
  const fx = (n) => fileURLToPath(new URL(`../test/fixtures/tls/${n}`, import.meta.url));
  const ssl = { key_file_name: fx('localhost.key'), cert_file_name: fx('localhost.pem') };
  const phase = (name) => console.log(`training [${group.name}]: ${name}`);
  const skipped = (why) => (phase(`${why} - skipped`), false);
  // A phase's size: `base` at the default scale, never less than one.
  const n = (base) => Math.max(1, Math.round(base * scale));

  // A server with every response shape, keyed by path. Batched dispatch is
  // registered when the binary has it, so the profile covers the staging ring
  // and the descriptor loop as well as single dispatch (a request that stands
  // alone still arrives as a batch of one).
  function startServer(options) {
    const server = { sid: 0, port: 0, tpl: 0 };
    let batchBuffers = null;
    const subscribers = new Set();
    const publishers = new Set();
    function handle(reqId, methodIdx, path) {
      switch (path) {
        case '/':
          engine.respond(reqId, 200, HEADERS, BODY);
          return;
        case '/tpl':
          engine.respondPrepared(reqId, server.tpl, BODY);
          return;
        case '/empty':
          engine.respondPreparedEmpty(reqId, server.tpl);
          return;
        case '/stream':
          engine.writeHeadPrepared(reqId, server.tpl);
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
        case '/echo': {
          // What a body parser does: take the bytes, answer with their size.
          const body = engine.getBody(reqId);
          engine.respond(reqId, 200, HEADERS, String(body ? body.byteLength : 0));
          return;
        }
        case '/text':
          engine.respondPrepared(reqId, server.tpl, engine.getBodyText ? (engine.getBodyText(reqId) ?? '') : '');
          return;
        case '/hdr': {
          // What a framework's request object does on first use.
          const all = engine.getHeaders(reqId);
          engine.getQuery(reqId);
          engine.respondPrepared(reqId, server.tpl, engine.getHeader(reqId, 'user-agent') ?? String(all.length));
          return;
        }
        case '/ws':
        case '/sub':
        case '/pub':
          if (engine.upgradeToWebSocket(reqId) !== -1) return;
        // not an upgrade request: fall through to the 404
        default:
          engine.respond(reqId, 404, ['content-type', 'text/plain'], 'not found');
      }
    }
    const callbacks = {
      onRequest: handle,
      onAborted() {},
      onWritable() {},
      onWsOpen(wsId, path) {
        if (path === '/sub') subscribers.add(wsId);
        else if (path === '/pub') publishers.add(wsId);
      },
      onWsMessage(wsId, data, isBinary) {
        if (publishers.has(wsId)) for (const s of subscribers) engine.wsSend(s, data, isBinary);
        engine.wsSend(wsId, data, isBinary);
      },
      onWsClose(wsId) {
        subscribers.delete(wsId);
        publishers.delete(wsId);
      },
    };
    if (caps.batchDispatch) {
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
    server.sid = engine.serve(callbacks, options);
    if (callbacks.onRequestBatch) batchBuffers = engine.getBatchBuffers(server.sid);
    server.port = engine.listen(server.sid, '127.0.0.1', 0);
    server.tpl = engine.prepareResponse(server.sid, 200, HEADERS);
    engine.setStaticRoute(server.sid, 0, '/static', 200, HEADERS, BODY);
    engine.setStaticRoute(server.sid, 5, '/static', 200, HEADERS, BODY);
    engine.setStaticRoute(server.sid, 0, '/plain', 200, null, '');
    engine.setStaticRoute(server.sid, 1, '/plain', 200, null, '');
    if (caps.paramRoutes) engine.setParamRoute(server.sid, 0, '/user/', '', 200, null);
    return server;
  }

  const plainConnect = (p) => (cb) => net.connect(p, '127.0.0.1', cb);
  const tlsConnect = (p, alpn) => (cb) => tls.connect({ host: '127.0.0.1', port: p, rejectUnauthorized: false, ALPNProtocols: alpn }, cb);

  // The length of one response on the wire, learnt from a first exchange on a
  // connection of its own (every response to the same request is as long).
  function responseLength(connect, request) {
    const headOnly = request.startsWith('HEAD ');
    return new Promise((resolve, reject) => {
      let buf = Buffer.alloc(0);
      const sock = connect(() => sock.write(request));
      sock.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        const end = buf.indexOf('\r\n\r\n');
        if (end === -1) return;
        const head = buf.subarray(0, end).toString('latin1');
        let total = end + 4;
        const length = /\r\ncontent-length: (\d+)/i.exec(head);
        if (headOnly) {
          // no body, whatever the head says
        } else if (length) {
          total += Number(length[1]);
        } else if (/\r\ntransfer-encoding: chunked/i.test(head)) {
          const last = buf.indexOf('\r\n0\r\n\r\n', end);
          if (last === -1) return;
          total = last + 7;
        }
        if (buf.length < total) return;
        sock.destroy();
        resolve(total);
      });
      sock.on('error', reject);
    });
  }

  // `rounds` times on each of `connections` keep-alive connections: send
  // `depth` copies of the request in one write, wait for all the responses.
  // Depth 1 over 64 connections is the shape a closed-loop load generator
  // drives: every read carries exactly one request, so the batch loop stages
  // one slot, answers it and flushes one write per request.
  async function requests(connect, request, { depth = 1, rounds, connections = 1 }) {
    const want = (await responseLength(connect, request)) * depth;
    const block = request.repeat(depth);
    await Promise.all(
      Array.from(
        { length: connections },
        () =>
          new Promise((resolve, reject) => {
            let got = 0;
            let left = rounds;
            const sock = connect(() => sock.write(block));
            sock.on('data', (d) => {
              got += d.length;
              if (got < want) return;
              got -= want;
              if (--left === 0) {
                sock.destroy();
                resolve();
              } else {
                sock.write(block);
              }
            });
            sock.on('error', reject);
            sock.on('close', () => (left === 0 ? resolve() : reject(new Error(`the server closed a training connection (${request.split(CRLF)[0]})`))));
          })
      )
    );
  }

  // One request per connection: the accept path and, over TLS, a full
  // handshake (no session is offered, so nothing is resumed).
  async function connectionPerRequest(connect, count) {
    for (let i = 0; i < count; i++) {
      await new Promise((resolve) => {
        const s = connect(() => s.write(`GET / HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`));
        s.resume(); // read (and discard) the response so the server's FIN is seen and 'close' fires
        s.on('close', resolve);
        s.on('error', resolve);
      });
    }
  }

  const req = (method, path) => `${method} ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;
  const JSON_BODY = JSON.stringify({ id: 42, name: 'training', tags: ['a', 'b', 'c'], active: true });
  const post = (path) => `POST ${path} HTTP/1.1${CRLF}Host: t${CRLF}Content-Type: application/json${CRLF}Content-Length: ${JSON_BODY.length}${CRLF}${CRLF}${JSON_BODY}`;
  const postChunked =
    `POST /echo HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}Content-Type: application/octet-stream${CRLF}${CRLF}` +
    `100${CRLF}${'x'.repeat(256)}${CRLF}`.repeat(4) +
    `0${CRLF}${CRLF}`;
  // The header set a browser sends: most requests carry ten headers, not one.
  const browserGet =
    `GET /hdr?page=2&sort=name HTTP/1.1${CRLF}Host: localhost:3000${CRLF}Connection: keep-alive${CRLF}` +
    `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36${CRLF}` +
    `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8${CRLF}Accept-Encoding: gzip, deflate, br${CRLF}` +
    `Accept-Language: en-US,en;q=0.9${CRLF}Cache-Control: no-cache${CRLF}Cookie: sid=0123456789abcdef; theme=dark${CRLF}` +
    `Referer: http://localhost:3000/${CRLF}Sec-Fetch-Mode: navigate${CRLF}${CRLF}`;
  // The same request as it arrives behind a CDN and a proxy: thirty headers.
  const proxiedGet = (path) =>
    browserGet.replace('/hdr?page=2&sort=name', path).slice(0, -2) +
    [
      'Sec-Fetch-Dest: document',
      'Sec-Fetch-Site: same-origin',
      'Sec-Fetch-User: ?1',
      'Sec-CH-UA: "Chromium";v="130", "Not?A_Brand";v="99"',
      'Sec-CH-UA-Mobile: ?0',
      'Sec-CH-UA-Platform: "macOS"',
      'Upgrade-Insecure-Requests: 1',
      'Pragma: no-cache',
      'DNT: 1',
      'Priority: u=0, i',
      'If-None-Match: W/"5e1f-19a2b3c4d5e"',
      'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2lnbmF0dXJl',
      'X-Forwarded-For: 198.51.100.23, 203.0.113.9',
      'X-Forwarded-Proto: https',
      'X-Forwarded-Host: www.example.test',
      'X-Real-IP: 198.51.100.23',
      'X-Request-ID: 0b6f8f0e-2f6c-4d0e-9a55-5d1c6f3e7a21',
      'Forwarded: for=198.51.100.23;proto=https;host=www.example.test',
      'Via: 1.1 edge-fra1, 1.1 proxy-2',
      'CDN-Loop: edge; count=1',
    ]
      .map((h) => h + CRLF)
      .join('') +
    CRLF;
  const PATHS = ['/', '/tpl', '/static', '/empty', '/stream', '/nocontent', '/big', '/missing'];

  // ---- HTTP/1.1 ----
  async function trainHttp1() {
    const s = startServer({});
    const connect = plainConnect(s.port);
    phase('pipelined request shapes');
    for (const path of PATHS) {
      // A 64 KiB response is a tenth as many requests for the same bytes.
      const k = path === '/big' ? 0.1 : 1;
      await requests(connect, req('GET', path), { rounds: n(2500 * k) });
      await requests(connect, req('GET', path), { depth: 10, rounds: n(1000 * k) });
      await requests(connect, req('HEAD', path), { rounds: n(1250) });
    }
    // The engine-answered routes (static, empty static, parameter) and a
    // JS-answered one, GET and POST.
    phase('64 keep-alive connections');
    const shapes = [req('GET', '/plain'), req('GET', '/static'), req('POST', '/plain'), req('GET', '/')];
    if (caps.paramRoutes) shapes.push(req('GET', '/user/42'));
    for (const shape of shapes) await requests(connect, shape, { rounds: n(250), connections: 64 });
    phase('connection per request');
    await connectionPerRequest(connect, n(300));
    engine.close(s.sid);
  }

  async function trainHttp1Requests() {
    const s = startServer({});
    const connect = plainConnect(s.port);
    phase('request bodies and headers');
    for (const shape of [post('/echo'), post('/text'), postChunked, browserGet, proxiedGet('/tpl'), proxiedGet('/hdr?page=2'), proxiedGet('/static')]) {
      await requests(connect, shape, { rounds: n(2500) });
      await requests(connect, shape, { depth: 10, rounds: n(1000) });
    }
    for (const shape of [post('/echo'), browserGet, proxiedGet('/tpl')]) await requests(connect, shape, { rounds: n(250), connections: 64 });
    engine.close(s.sid);
  }

  // ---- WebSocket ----
  // A masked client frame; `first` is the first header byte (FIN, RSV1, opcode).
  function wsFrame(first, payload) {
    const len = payload.length;
    const head =
      len < 126
        ? Buffer.from([first, 0x80 | len])
        : len < 65536
          ? Buffer.from([first, 0x80 | 126, len >> 8, len & 255])
          : Buffer.from([first, 0x80 | 127, 0, 0, 0, 0, len >>> 24, (len >>> 16) & 255, (len >>> 8) & 255, len & 255]);
    // A fixed key: the same bytes on the wire in every run.
    const mask = Buffer.from([0x37, 0xfa, 0x21, 0x3d]);
    const out = Buffer.allocUnsafe(head.length + 4 + len);
    head.copy(out);
    mask.copy(out, head.length);
    for (let i = 0; i < len; i++) out[head.length + 4 + i] = payload[i] ^ mask[i & 3];
    return out;
  }
  // A permessage-deflate message (RFC 7692: raw deflate, sync flush, the
  // four-byte tail stripped, RSV1 set).
  function wsDeflated(payload) {
    const z = zlib.deflateRawSync(payload, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
    return wsFrame(0xc1, z.subarray(0, z.length - 4));
  }
  // Counts the complete frames a server sent, whatever their size.
  function frameCounter(onFrames) {
    let buf = Buffer.alloc(0);
    return (d) => {
      buf = buf.length ? Buffer.concat([buf, d]) : d;
      let count = 0;
      for (;;) {
        if (buf.length < 2) break;
        let len = buf[1] & 127;
        let head = 2;
        if (len === 126) {
          if (buf.length < 4) break;
          len = buf.readUInt16BE(2);
          head = 4;
        } else if (len === 127) {
          if (buf.length < 10) break;
          len = buf.readUInt32BE(6);
          head = 10;
        }
        if (buf.length < head + len) break;
        buf = buf.subarray(head + len);
        count++;
      }
      if (count) onFrames(count);
    };
  }
  // The upgraded socket. Throws when the server did not answer 101 (or did
  // not agree to the extension): a phase that got a 404 here would leave the
  // frame path unprofiled without anything failing.
  function wsOpen(connect, path, { deflate = false } = {}) {
    return new Promise((resolve, reject) => {
      const sock = connect(() => {
        sock.write(
          `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==${CRLF}Sec-WebSocket-Version: 13${CRLF}` +
            (deflate ? `Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits${CRLF}` : '') +
            CRLF
        );
      });
      let head = Buffer.alloc(0);
      const onData = (d) => {
        head = Buffer.concat([head, d]);
        if (head.indexOf('\r\n\r\n') === -1) return;
        sock.off('data', onData);
        const text = head.toString('latin1');
        if (/^HTTP\/1\.1 101 /.test(text) && (!deflate || /permessage-deflate/i.test(text))) return resolve(sock);
        sock.destroy();
        reject(new Error(`WebSocket upgrade on ${path}${deflate ? ' with permessage-deflate' : ''} was not accepted`));
      };
      sock.on('data', onData);
      sock.on('error', reject);
    });
  }
  // `rounds` times: send `batch`, wait for the `expect` frames it is answered with.
  async function wsLoop(connect, path, batch, expect, rounds, options) {
    const sock = await wsOpen(connect, path, options);
    await new Promise((resolve, reject) => {
      let got = 0;
      let left = rounds;
      sock.on(
        'data',
        frameCounter((count) => {
          got += count;
          if (got < expect) return;
          got -= expect;
          if (--left === 0) {
            sock.destroy();
            resolve();
          } else {
            sock.write(batch);
          }
        })
      );
      sock.on('error', reject);
      sock.on('close', () => (left === 0 ? resolve() : reject(new Error(`the server closed the training WebSocket on ${path}`))));
      sock.write(batch);
    });
  }
  // Text that compresses the way application JSON does.
  function jsonMessage(bytes, seed) {
    const words = ['id', 'user', 'name', 'email', 'created', 'status', 'active', 'total', 'amount', 'items', 'page', 'token', 'value', 'type', 'error', 'result'];
    let x = (seed * 2654435761) >>> 0;
    const next = () => (x = (x * 1664525 + 1013904223) >>> 0) >>> 8;
    let s = '{';
    while (s.length < bytes) s += `"${words[next() % words.length]}":"${words[next() % words.length]}${next() % 100000}",`;
    return Buffer.from(s.slice(0, bytes - 1) + '}');
  }
  // One publisher, `count` subscribers: every message the publisher sends is
  // sent to each of them and echoed.
  async function wsFanOut(connect, count, message, rounds, options) {
    const subs = await Promise.all(Array.from({ length: count }, () => wsOpen(connect, '/sub', options)));
    for (const s of subs) {
      s.resume();
      s.on('error', () => {});
    }
    await wsLoop(connect, '/pub', message, 1, rounds, options);
    for (const s of subs) s.destroy();
  }
  async function wsShapes(connect, k) {
    const text = wsFrame(0x81, Buffer.from('ping-pong-payload'));
    // Small text frames one at a time, then sixteen to a segment.
    await wsLoop(connect, '/ws', text, 1, n(6000 * k));
    await wsLoop(connect, '/ws', Buffer.concat(Array.from({ length: 16 }, () => text)), 16, n(1500 * k));
    // Binary at the 16-bit and the 64-bit length encodings, and a message in three fragments.
    await wsLoop(connect, '/ws', wsFrame(0x82, Buffer.alloc(1200, 0x5a)), 1, n(3000 * k));
    await wsLoop(connect, '/ws', wsFrame(0x82, Buffer.alloc(70000, 0x5a)), 1, n(150 * k));
    const part = Buffer.from('fragment-of-a-message ');
    await wsLoop(connect, '/ws', Buffer.concat([wsFrame(0x01, part), wsFrame(0x00, part), wsFrame(0x80, part)]), 1, n(2000 * k));
    await wsFanOut(connect, 32, wsFrame(0x81, jsonMessage(200, 1)), n(1500 * k));
  }
  async function trainWebSocket() {
    const s = startServer({});
    phase('echo, binary, fragments, fan-out');
    await wsShapes(plainConnect(s.port), 1);
    engine.close(s.sid);
  }
  async function trainWsDeflate() {
    if (!caps.wsDeflate) return skipped('this binary has no permessage-deflate');
    const s = startServer({ wsDeflate: true });
    const connect = plainConnect(s.port);
    const options = { deflate: true };
    phase('permessage-deflate echo and fan-out');
    // Above the default compression threshold (1024 bytes), and below it.
    const big = Buffer.concat(Array.from({ length: 4 }, (_, i) => wsDeflated(jsonMessage(1500, i + 1))));
    const small = Buffer.concat(Array.from({ length: 4 }, (_, i) => wsDeflated(jsonMessage(200, i + 9))));
    await wsLoop(connect, '/ws', big, 4, n(1200), options);
    await wsLoop(connect, '/ws', small, 4, n(1200), options);
    await wsFanOut(connect, 16, wsDeflated(jsonMessage(1500, 5)), n(600), options);
    engine.close(s.sid);
  }

  // ---- TLS ----
  async function trainTls() {
    if (!caps.tls) return skipped('this binary does not terminate TLS');
    const s = startServer({ ssl });
    const connect = tlsConnect(s.port, ['http/1.1']);
    phase('request shapes');
    for (const shape of [req('GET', '/'), req('GET', '/tpl'), post('/echo'), browserGet]) {
      await requests(connect, shape, { rounds: n(1500) });
      await requests(connect, shape, { depth: 10, rounds: n(600) });
    }
    await requests(connect, req('GET', '/big'), { rounds: n(250) });
    await requests(connect, req('GET', '/stream'), { rounds: n(1500) });
    await requests(connect, req('GET', '/'), { rounds: n(250), connections: 16 });
    phase('handshakes');
    await connectionPerRequest(connect, n(1200));
    phase('websocket');
    await wsShapes(connect, 0.25);
    engine.close(s.sid);
  }

  // ---- HTTP/2 ----
  // A bare client: pre-encoded HEADERS frames, `streams` of them in flight at a
  // time, `rounds` times. Its header blocks are static-table references and
  // plain literals, so it runs at the server's speed; node's own client
  // (below) sends what real clients send, Huffman-coded strings and
  // dynamic-table entries, more slowly.
  function h2Rounds(connect, rounds, { path = '/', body = null, streams = 32 } = {}) {
    return new Promise((resolve, reject) => {
      const frame = (type, flags, id, payload) => {
        const f = Buffer.allocUnsafe(9 + payload.length);
        f.writeUIntBE(payload.length, 0, 3);
        f[3] = type;
        f[4] = flags;
        f.writeUInt32BE(id, 5);
        payload.copy(f, 9);
        return f;
      };
      // Literal field without indexing, name from the static table.
      const lit = (index, value) => Buffer.concat([Buffer.from(index < 15 ? [index, value.length] : [0x0f, index - 15, value.length]), Buffer.from(value)]);
      const block = Buffer.concat([
        Buffer.from([body ? 0x83 : 0x82, 0x86]), // :method POST | GET, :scheme http
        path === '/' ? Buffer.from([0x84]) : lit(4, path), // :path
        lit(1, 'localhost'), // :authority
        ...(body ? [lit(31, 'application/json'), lit(28, String(body.length))] : []), // content-type, content-length
      ]);
      const u32 = (v) => {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(v);
        return b;
      };
      let nextId = 1;
      const round = () => {
        const out = [];
        for (let i = 0; i < streams; i++, nextId += 2) {
          out.push(frame(1, body ? 0x4 : 0x5, nextId, block)); // HEADERS, END_HEADERS [| END_STREAM]
          if (body) out.push(frame(0, 0x1, nextId, body)); // DATA, END_STREAM
        }
        return Buffer.concat(out);
      };
      let buf = Buffer.alloc(0);
      let ended = 0;
      let unacked = 0;
      let left = rounds;
      let done = false;
      const sock = connect(() => {
        sock.write(
          Buffer.concat([
            Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
            frame(4, 0, 0, Buffer.from([0, 4, 0, 0x10, 0, 0])), // SETTINGS: INITIAL_WINDOW_SIZE = 1 MiB
            frame(8, 0, 0, u32(0x40000000)), // WINDOW_UPDATE: room on the connection
            round(),
          ])
        );
      });
      const finish = (err) => {
        if (done) return;
        done = true;
        sock.destroy();
        if (err) reject(err);
        else resolve();
      };
      sock.on('data', (d) => {
        buf = buf.length ? Buffer.concat([buf, d]) : d;
        const out = [];
        while (buf.length >= 9) {
          const len = buf.readUIntBE(0, 3);
          if (buf.length < 9 + len) break;
          const type = buf[3];
          const flags = buf[4];
          if (type === 4 && !(flags & 1)) out.push(frame(4, 1, 0, Buffer.alloc(0))); // acknowledge SETTINGS
          if (type === 0) unacked += len;
          if ((type === 0 || type === 1) && flags & 1) ended++;
          if (type === 7 || type === 3) return finish(new Error(`the server ended the HTTP/2 training ${type === 7 ? 'connection (GOAWAY)' : 'stream (RST_STREAM)'} on ${path}`));
          buf = buf.subarray(9 + len);
        }
        if (unacked > 0x10000000) {
          out.push(frame(8, 0, 0, u32(unacked))); // give back what was consumed
          unacked = 0;
        }
        if (ended >= streams) {
          ended -= streams;
          if (--left === 0) return finish();
          out.push(round());
        }
        if (out.length) sock.write(Buffer.concat(out));
      });
      sock.on('error', finish);
      sock.on('close', () => finish(new Error(`the server closed the HTTP/2 training connection on ${path}`)));
    });
  }
  // `total` requests through node's client, 32 in flight.
  function h2NodeClient(authority, options, total) {
    return new Promise((resolve, reject) => {
      const session = http2.connect(authority, options);
      let started = 0;
      let open = 0;
      let done = false;
      const finish = (err) => {
        if (done) return;
        done = true;
        session.destroy();
        if (err) reject(err);
        else resolve();
      };
      const one = () => {
        if (done) return;
        if (started === total) {
          if (open === 0) finish();
          return;
        }
        const i = started++;
        open++;
        const posting = i % 4 === 3;
        const stream = session.request({
          ':method': posting ? 'POST' : 'GET',
          ':path': posting ? '/echo' : i % 4 === 1 ? '/hdr?page=2' : '/',
          'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
          accept: 'application/json, text/plain, */*',
          'accept-encoding': 'gzip, deflate, br',
          cookie: 'sid=0123456789abcdef; theme=dark',
          ...(posting ? { 'content-type': 'application/json' } : {}),
        });
        stream.resume();
        stream.on('error', () => {});
        stream.on('close', () => {
          open--;
          one();
        });
        stream.end(posting ? JSON_BODY : undefined);
      };
      session.on('error', finish);
      session.on('connect', () => {
        for (let i = 0; i < 32; i++) one();
      });
    });
  }
  async function trainHttp2() {
    if (!caps.http2) return skipped('this binary has no HTTP/2');
    const body = Buffer.from(JSON_BODY);
    phase('prior knowledge');
    const h2c = startServer({ http2: true });
    const connect = plainConnect(h2c.port);
    await h2Rounds(connect, n(400), {});
    await h2Rounds(connect, n(4000), { streams: 1 });
    await h2Rounds(connect, n(300), { path: '/tpl' });
    await h2Rounds(connect, n(300), { path: '/echo', body });
    await h2Rounds(connect, n(300), { path: '/stream' });
    await h2Rounds(connect, n(150), { path: '/big', streams: 4 });
    await h2NodeClient(`http://127.0.0.1:${h2c.port}`, {}, n(4000));
    engine.close(h2c.sid);
    if (caps.tls) {
      phase('over TLS');
      const h2s = startServer({ ssl, http2: true });
      const tconnect = tlsConnect(h2s.port, ['h2']);
      await h2Rounds(tconnect, n(400), {});
      await h2Rounds(tconnect, n(300), { path: '/tpl' });
      await h2Rounds(tconnect, n(300), { path: '/echo', body });
      await h2Rounds(tconnect, n(150), { path: '/big', streams: 4 });
      await h2NodeClient(`https://127.0.0.1:${h2s.port}`, { rejectUnauthorized: false }, n(4000));
      engine.close(h2s.sid);
    }
  }

  // ---- one transport, a mix of every protocol ----
  async function trainTransportMix() {
    const s = startServer({});
    const connect = plainConnect(s.port);
    phase('HTTP/1.1');
    for (const shape of [req('GET', '/'), req('GET', '/tpl'), req('GET', '/static'), req('GET', '/stream'), post('/echo'), browserGet]) {
      await requests(connect, shape, { rounds: n(1500) });
      await requests(connect, shape, { depth: 10, rounds: n(600) });
    }
    await requests(connect, req('GET', '/big'), { rounds: n(250) });
    for (const shape of [req('GET', '/plain'), req('GET', '/'), post('/echo')]) await requests(connect, shape, { rounds: n(150), connections: 64 });
    await connectionPerRequest(connect, n(200));
    phase('websocket');
    await wsShapes(connect, 0.25);
    engine.close(s.sid);
    if (caps.tls) {
      phase('TLS');
      const t = startServer({ ssl });
      const tconnect = tlsConnect(t.port, ['http/1.1']);
      await requests(tconnect, req('GET', '/'), { rounds: n(1500) });
      await requests(tconnect, req('GET', '/'), { depth: 10, rounds: n(600) });
      await requests(tconnect, req('GET', '/big'), { rounds: n(150) });
      await connectionPerRequest(tconnect, n(50));
      engine.close(t.sid);
    }
    if (caps.http2) {
      phase('HTTP/2');
      const h2c = startServer({ http2: true });
      await h2Rounds(plainConnect(h2c.port), n(300), {});
      await h2Rounds(plainConnect(h2c.port), n(100), { path: '/big', streams: 4 });
      engine.close(h2c.sid);
    }
  }

  console.log(`training [${group.name}] against ${process.env.MORO_ENGINE_BINARY || '(default binary)'}; transport=${info.transport} fastApi=${info.fastApi?.installed}`);
  if (group.transport && info.transport !== group.transport) {
    // Not an error: a container's seccomp profile or an older kernel refuses
    // the ring, and a published binary there runs the default transport too.
    return skipped(`the ${group.transport} transport is not available here (got ${info.transport}: ${info.transportReason ?? 'no reason given'})`);
  }
  const run = {
    http1: trainHttp1,
    'http1-requests': trainHttp1Requests,
    websocket: trainWebSocket,
    'ws-deflate': trainWsDeflate,
    tls: trainTls,
    http2: trainHttp2,
    uring: trainTransportMix,
    uv: trainTransportMix,
  }[group.name];
  if (!run) throw new Error(`no workload for group ${group.name}`);
  // Nothing here waits on a clock, so a phase the server stops answering
  // would wait for ever: the group fails instead.
  const watchdog = setTimeout(() => {
    console.error(`training [${group.name}]: no end after ${Math.round(600 * Math.max(1, scale))} s - giving up`);
    process.exit(2);
  }, 600_000 * Math.max(1, scale));
  const trained = (await run()) !== false;
  clearTimeout(watchdog);
  return trained;
}

function flag(args, name, fallback = null) {
  const hit = args.find((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (!hit) return fallback;
  return hit.includes('=') ? hit.slice(hit.indexOf('=') + 1) : true;
}

async function main(args) {
  const seconds = parseFloat(flag(args, 'seconds', '4'));
  const one = flag(args, 'group');
  if (one) {
    const group = TRAINING_GROUPS.find((g) => g.name === one);
    if (!group) throw new Error(`unknown group "${one}" (known: ${TRAINING_GROUPS.map((g) => g.name).join(', ')})`);
    const trained = await runGroup(group, seconds / 4);
    console.log(`training [${group.name}]: ${trained ? 'done' : 'nothing trained'}`);
    // process.exit (not a natural drain) so the profile runtime's atexit flush
    // runs with the isolate still alive - an unref'd-handle drain can race it.
    // 3: nothing was trained (the parent discards the profile of loading the
    // addon that this process still writes).
    process.exit(trained ? 0 : 3);
  }

  const only = flag(args, 'only');
  const required = (process.env.MORO_PGO_REQUIRE ?? '').split(',').filter(Boolean);
  const wanted = TRAINING_GROUPS.filter(
    (g) => (!g.platform || g.platform === process.platform) && (!only || only.split(',').includes(g.name)) && !(g.name === 'suites' && args.includes('--no-suites'))
  );
  const profileDir = process.env.MORO_PGO_PROFILE_DIR || '';
  // The suites and every group run under the node that runs this script,
  // whatever `node` is first on PATH: the profile is for that node's ABI.
  const PATH = `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? ''}`;
  for (const group of wanted) {
    const env = { ...process.env, PATH };
    if (profileDir) {
      // One directory per group; %p-%m: one file per process (the suites
      // spawn many). MSVC's profile runtime writes its .pgc files where
      // VCPROFILE_PATH says.
      mkdirSync(join(profileDir, group.name), { recursive: true });
      env.LLVM_PROFILE_FILE = join(profileDir, group.name, 'moro-%p-%m.profraw');
      env.VCPROFILE_PATH = join(profileDir, group.name);
    }
    let r;
    if (group.name === 'suites') {
      // The package's own test:suites line, through the shell and with the
      // PATH above (no npm needed: a training node may be a bare binary).
      console.log('training [suites]: the node --test suites against the instrumented binary ...');
      const script = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts['test:suites'];
      r = spawnSync(script, { cwd: root, stdio: 'inherit', env, shell: true });
    } else {
      if (group.transport) {
        env.MORO_ENGINE_TRANSPORT = group.transport;
        delete env.MORO_ENGINE_REQUIRE_TRANSPORT;
      }
      r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), `--group=${group.name}`, `--seconds=${seconds}`], { cwd: root, stdio: 'inherit', env });
    }
    if (r.status === 3 && group.name !== 'suites' && !required.includes(group.name)) {
      if (profileDir) rmSync(join(profileDir, group.name), { recursive: true, force: true });
      continue;
    }
    if (r.status !== 0) {
      console.error(`training [${group.name}] failed (${r.error ? r.error.message : r.signal ? `signal ${r.signal}` : r.status === 3 ? 'nothing trained, and MORO_PGO_REQUIRE names it' : `exit ${r.status}`})`);
      process.exit(2);
    }
  }
  console.log('training done');
}

// Run only as the entry point: tools/pgo.mjs imports TRAINING_GROUPS.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`training failed: ${err.stack || err.message}`);
    process.exit(2);
  });
}
