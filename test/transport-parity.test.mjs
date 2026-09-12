// Transport parity for @morojs/engine: the bytes on the wire may not depend
// on the I/O transport. A subject process is started once per transport
// (MORO_ENGINE_TRANSPORT=uv, and =uring where the kernel allows it) and the
// same scripted exchanges are driven against each:
//   single keep-alive request, pipelined batch of five mixed responses, HEAD,
//   Expect: 100-continue, 400 / 413 / 431 rejections, HTTP/1.0, Latin-1 body,
//   a prepared template, a static route, a WebSocket handshake + echo +
//   close, and one request over TLS.
// Every raw stream is normalised (Date line stripped) and compared
// byte-for-byte across transports. Off Linux (or when io_uring is
// unavailable) the comparison is uv-vs-uv from two processes, which still
// proves the streams are deterministic; the io_uring CI lanes make it
// uv-vs-uring.
//
// Run with: node --test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine ? false : '@morojs/engine native binding not usable yet — transport-parity suite skipped';
const T = { timeout: 60000 };
const SUBJECT = fileURLToPath(new URL('./transport-parity-subject.mjs', import.meta.url));
const CA = fileURLToPath(new URL('./fixtures/tls/ca.pem', import.meta.url));
const CRLF = '\r\n';

function startSubject(transport) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SUBJECT], {
      env: { ...process.env, MORO_ENGINE_TRANSPORT: transport, MORO_ENGINE_REQUIRE_TRANSPORT: '' },
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    let out = '';
    const timer = setTimeout(() => reject(new Error(`subject (${transport}) did not start`)), 15000);
    child.stdout.on('data', (d) => {
      out += d;
      const nl = out.indexOf('\n');
      if (nl < 0) return;
      clearTimeout(timer);
      const info = JSON.parse(out.slice(0, nl));
      if (info.error) return reject(new Error(info.error));
      resolve({ child, ...info, stop: () => new Promise((r) => { child.once('exit', r); child.stdin.write('exit\n'); setTimeout(() => child.kill('SIGKILL'), 3000).unref(); }) });
    });
    child.once('exit', (code) => { clearTimeout(timer); reject(new Error(`subject (${transport}) exited ${code}`)); });
  });
}

// Collect everything the server sends until it closes the socket. `script`
// is a list of steps: a string/Buffer to write, or {waitFor: substring} to
// wait until the buffered stream contains it before continuing.
function exchange(port, script, { secure = false } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let buffered = Buffer.alloc(0);
    const sock = secure
      ? tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: readFileSync(CA) })
      : net.connect(port, '127.0.0.1');
    sock.setNoDelay(true);
    let i = 0;
    let waiting = null;
    const step = () => {
      while (i < script.length) {
        const s = script[i++];
        if (typeof s === 'object' && s !== null && !Buffer.isBuffer(s) && s.waitFor !== undefined) {
          if (buffered.toString('latin1').includes(s.waitFor)) continue;
          waiting = s.waitFor;
          return;
        }
        sock.write(Buffer.isBuffer(s) ? s : Buffer.from(s, 'latin1'));
      }
    };
    sock.on(secure ? 'secureConnect' : 'connect', step);
    sock.on('data', (d) => {
      chunks.push(d);
      buffered = Buffer.concat(chunks);
      if (waiting !== null && buffered.toString('latin1').includes(waiting)) { waiting = null; step(); }
    });
    sock.on('close', () => resolve(Buffer.concat(chunks)));
    sock.on('error', (e) => { if (chunks.length === 0) reject(e); });
    sock.setTimeout(8000, () => { sock.destroy(); resolve(Buffer.concat(chunks)); });
  });
}

const req = (method, path, extra = '', { version = '1.1', close = true } = {}) =>
  `${method} ${path} HTTP/${version}${CRLF}Host: t${CRLF}${extra}${close ? `Connection: close${CRLF}` : ''}${CRLF}`;

function wsFrame(opcode, payload, fin = true) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const key = Buffer.from([0x11, 0x22, 0x33, 0x44]);
  const head = [(fin ? 0x80 : 0) | opcode];
  if (body.length < 126) head.push(0x80 | body.length);
  else head.push(0x80 | 126, body.length >> 8, body.length & 0xff);
  const masked = Buffer.alloc(body.length);
  for (let j = 0; j < body.length; j++) masked[j] = body[j] ^ key[j & 3];
  return Buffer.concat([Buffer.from(head), key, masked]);
}
const WS_KEY = 'dGhlIHNhbXBsZSBub25jZQ==';

const SCENARIOS = {
  'single keep-alive then close': [req('GET', '/plain', '', { close: false }), { waitFor: 'hello, transport' }, req('GET', '/plain')],
  'pipelined x5 mixed': [
    req('GET', '/plain', '', { close: false }) + req('GET', '/nocontent', '', { close: false }) +
      req('GET', '/notmod', '', { close: false }) + req('GET', '/chunked', '', { close: false }) + req('GET', '/plain'),
  ],
  'HEAD': [req('HEAD', '/plain')],
  'HEAD chunked': [req('HEAD', '/chunked')],
  '100-continue': [
    `POST /echo HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 5${CRLF}Expect: 100-continue${CRLF}Connection: close${CRLF}${CRLF}`,
    { waitFor: '100 Continue' },
    'abcde',
  ],
  'POST body no expect': [`POST /echo HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 3${CRLF}Connection: close${CRLF}${CRLF}xyz`],
  '400 bad request line': [`GARBAGE${CRLF}${CRLF}`],
  '505 unsupported version': [`GET /plain HTTP/9.9${CRLF}Host: t${CRLF}${CRLF}`],
  '413 body too large': [`POST /echo HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 4096${CRLF}${CRLF}` + 'x'.repeat(4096)],
  '431 head too large': [`GET /plain HTTP/1.1${CRLF}Host: t${CRLF}X-Big: ${'y'.repeat(3000)}${CRLF}${CRLF}`],
  'HTTP/1.0': [req('GET', '/plain', '', { version: '1.0', close: false })],
  'latin1 body': [req('GET', '/latin1')],
  'template': [req('GET', '/tpl')],
  'static route': [req('GET', '/static')],
  '404': [req('GET', '/missing')],
  'websocket echo + close': [
    `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${WS_KEY}${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`,
    { waitFor: '101 ' },
    wsFrame(0x1, 'ping-text'),
    wsFrame(0x2, Buffer.from([0, 1, 2, 250, 255])),
    { waitFor: 'ping-text' },
    wsFrame(0x8, Buffer.from([0x03, 0xe8, 0x62, 0x79, 0x65])), // 1000 "bye"
  ],
};

const stripDate = (buf) => buf.toString('latin1').replace(/^date: [^\r\n]*\r\n/gim, '');

async function runAll(subject) {
  const out = {};
  for (const [name, script] of Object.entries(SCENARIOS)) out[name] = stripDate(await exchange(subject.port, script));
  if (subject.tlsPort) out['TLS single request'] = stripDate(await exchange(subject.tlsPort, [req('GET', '/plain')], { secure: true }));
  return out;
}

describe('transport parity', { skip }, () => {
  const subjects = [];
  let streams = {};
  before(async () => {
    const host = engine.probe();
    const wanted = ['uv'];
    if (process.platform === 'linux' && host.transport === 'uring') wanted.push('uring');
    else wanted.push('uv'); // a second uv process: still proves determinism
    for (const t of wanted) {
      const s = await startSubject(t);
      subjects.push(s);
      streams[`${t}#${subjects.length}`] = await runAll(s);
    }
    console.log(`transport parity: ${subjects.map((s) => `${s.transport} (${s.reason})`).join(' vs ')}`);
  });
  after(async () => {
    for (const s of subjects) await s.stop();
  });

  it('subjects ran on the transports the lane pinned', T, () => {
    assert.equal(subjects[0].transport, 'uv');
    if (process.platform === 'linux' && engine.probe().transport === 'uring') assert.equal(subjects[1].transport, 'uring');
  });

  it('every scenario produced a response on both subjects', T, () => {
    const [a, b] = Object.values(streams);
    for (const name of Object.keys(a)) {
      assert.ok(a[name].length > 0, `${name}: empty stream (first subject)`);
      assert.ok(b[name].length > 0, `${name}: empty stream (second subject)`);
    }
  });

  it('the responses carry the expected status and bodies', T, () => {
    const a = Object.values(streams)[0];
    assert.match(a['single keep-alive then close'], /^HTTP\/1\.1 200 [\s\S]*hello, transportHTTP\/1\.1 200 [\s\S]*hello, transport$/);
    assert.equal((a['pipelined x5 mixed'].match(/HTTP\/1\.1 /g) || []).length, 5);
    assert.match(a['pipelined x5 mixed'], /204[\s\S]*304[\s\S]*first-\r\n[\s\S]*second-\r\n[\s\S]*third\r\n0\r\n\r\n/);
    assert.match(a['HEAD'], /^HTTP\/1\.1 200 /);
    assert.ok(!a['HEAD'].includes('hello, transport'), 'HEAD must not carry a body');
    assert.match(a['100-continue'], /^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 200 [\s\S]*echo:abcde$/);
    assert.match(a['POST body no expect'], /echo:xyz$/);
    assert.match(a['400 bad request line'], /^HTTP\/1\.[01] 400 /);
    assert.match(a['505 unsupported version'], /^HTTP\/1\.1 505 /);
    assert.match(a['413 body too large'], /^HTTP\/1\.1 413 /);
    assert.match(a['431 head too large'], /^HTTP\/1\.1 (431|400) /);
    assert.match(a['HTTP/1.0'], /^HTTP\/1\.[01] 200 /);
    assert.ok(a['latin1 body'].endsWith('cafÃ© crÃ¨me'), 'Latin-1 source is UTF-8 on the wire');
    assert.match(a['template'], /templated$/);
    assert.match(a['static route'], /static-body$/);
    assert.match(a['404'], /^HTTP\/1\.1 404 /);
    const ws = a['websocket echo + close'];
    assert.match(ws, /^HTTP\/1\.1 101 /);
    const accept = crypto.createHash('sha1').update(WS_KEY + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    assert.ok(ws.includes(accept), 'Sec-WebSocket-Accept');
    assert.ok(ws.includes('\x81\x09ping-text'), 'text echo frame');
    assert.ok(ws.includes('\x82\x05\x00\x01\x02\xfa\xff'), 'binary echo frame');
    assert.ok(ws.includes('\x88\x05\x03\xe8bye'), 'close frame echoed with 1000 bye');
    if ('TLS single request' in a) assert.match(a['TLS single request'], /^HTTP\/1\.1 200 [\s\S]*hello, transport$/);
  });

  it('byte streams are identical across transports (Date excepted)', T, () => {
    const [[na, a], [nb, b]] = Object.entries(streams);
    for (const name of Object.keys(a)) {
      assert.equal(a[name], b[name], `${name}: ${na} vs ${nb} differ`);
    }
  });
});
