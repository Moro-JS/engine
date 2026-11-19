// Child process for test/probe-transport.test.mjs: a server on the io_uring
// transport whose ring stops taking submissions while it is busy (the fault
// point of the sanitizer build, MORO_ENGINE_TEST_FAIL_URING_ENTER).
//
//   node ring-death-subject.mjs quiet    the loop finds out on its own turn
//   node ring-death-subject.mjs inline   a response finds out, in the middle
//                                        of a burst that fills the submission
//                                        queue
//
// Prints one JSON line and ends by itself once its servers are closed.
import net from 'node:net';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const info = engine?.probe() ?? {};
const mode = process.argv[2] || 'quiet';
if (info.transport !== 'uring' || !info.testFaults) {
  console.log(JSON.stringify({ skipped: `transport ${info.transport}, testFaults ${info.testFaults}` }));
  process.exit(0);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const big = Buffer.alloc(4 << 20, 0x61);
const held = [];
let aborted = 0;
let requests = 0;
const wsCodes = [];
const callbacks = {
  onRequest(reqId, m, path) {
    requests++;
    if (path === '/s') return engine.respond(reqId, 200, null, 'ok');
    if (path === '/big') return engine.respond(reqId, 200, null, big);
    if (path === '/ws') {
      if (engine.upgradeToWebSocket(reqId) === -1) engine.respond(reqId, 400, null, '');
      return;
    }
    held.push(reqId);
  },
  onAborted() { aborted++; },
  onWritable() {},
  onWsOpen() {},
  onWsMessage() {},
  onWsClose(wsId, code) { wsCodes.push(code); },
};
const sid = engine.serve(callbacks, {});
const port = engine.listen(sid, '127.0.0.1', 0);
const closing = engine.serve(callbacks, {});
const closingPort = engine.listen(closing, '127.0.0.1', 0);

let opened = 0;
let ended = 0;
function peer(p, text, { pause = false } = {}) {
  return new Promise((resolve) => {
    const s = net.connect(p, '127.0.0.1', () => {
      opened++;
      if (pause) s.pause();
      s.write(text);
      resolve(s);
    });
    s.on('error', () => {});
    s.on('close', () => { ended++; });
    if (!pause) s.on('data', () => {});
  });
}
const get = (path, extra = '') => `GET ${path} HTTP/1.1\r\nHost: t\r\n${extra}\r\n`;
const handshake =
  'GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
  'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n';

// More held requests than the submission queue has entries (1024), each with
// a request pipelined behind it so that its response takes the queued path.
const N = mode === 'inline' ? 1100 : 3;
const peers = [];
for (let i = 0; i < N; i++) peers.push(await peer(port, get('/hold') + get('/s')));
peers.push(await peer(port, handshake));                      // a WebSocket
peers.push(await peer(port, get('/s')));                      // an idle keep-alive connection
peers.push(await peer(port, get('/big'), { pause: true }));   // a send the kernel is holding
peers.push(await peer(closingPort, get('/hold')));            // a connection of the server that closes
for (let w = 0; w < 500 && (held.length < N + 1 || requests < N + 3); w++) await sleep(10);
const inFlight = held.length;

process.env.MORO_ENGINE_TEST_FAIL_URING_ENTER = '1';  // the ring dies now
engine.close(closing);  // its connection and its listener wait for completions that will not come
if (mode === 'inline') for (const reqId of held) engine.respond(reqId, 200, null, 'late');
for (const s of peers) s.resume();
for (let w = 0; w < 500 && ended < opened; w++) await sleep(10);
delete process.env.MORO_ENGINE_TEST_FAIL_URING_ENTER;

// The server that was listening still is, on the same port.
const next = await new Promise((resolve) => {
  const s = net.connect(port, '127.0.0.1', () => s.write(get('/s', 'Connection: close\r\n')));
  let b = '';
  s.on('data', (d) => (b += d));
  s.on('close', () => resolve(b.slice(9, 12) || 'closed'));
  s.on('error', (e) => resolve(e.code));
  s.setTimeout(3000, () => { s.destroy(); resolve('timeout'); });
});
engine.close(sid);
console.log(JSON.stringify({ opened, ended, inFlight, aborted, wsCodes, next }));
