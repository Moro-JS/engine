// Child process for test/batch-dispatch.test.mjs: WebSocket handshakes
// pipelined behind ordinary requests, against servers on which the engine
// performs the upgrade itself (setWsAutoUpgrade). The parent runs this in a
// process of its own because what is under test includes the process staying
// alive; it prints one JSON line with the outcome of every case and exits 0.
//
// argv[2]: 'string' or 'buffer' - what the handlers pass to respond() as the
// body (a string body is read straight out of the V8 heap by the binding, a
// Buffer is not; the two take different paths through a response call).
import net from 'node:net';
import crypto from 'node:crypto';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
if (!engine) {
  console.log(JSON.stringify({ error: 'engine not loadable' }));
  process.exit(2);
}
const bodyKind = process.argv[2] === 'buffer' ? 'buffer' : 'string';
const CRLF = '\r\n';
const NO_PATH = 0xffffffff;
const body = (text) => (bodyKind === 'buffer' ? Buffer.from(text) : text);
const req = (path) => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;
const handshake = ({ key = crypto.randomBytes(16).toString('base64'), version = '13' } = {}) =>
  `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}` +
  `Sec-WebSocket-Key: ${key}${CRLF}Sec-WebSocket-Version: ${version}${CRLF}${CRLF}`;
// masked text frame "hi"; the echo is the unmasked 81 02 'h' 'i'
const FRAME = Buffer.from([0x81, 0x82, 1, 2, 3, 4, 'h'.charCodeAt(0) ^ 1, 'i'.charCodeAt(0) ^ 2]);
const ECHO = '\x81\x02hi';

// A server with engine-side upgrades on. `batch`: the canonical onRequestBatch
// loop, or one onRequest call per request. A request is answered when its
// path says: /sync/* at once, /micro/* from a microtask of the dispatch,
// /timer/* from a timer. /ws only reaches the handler when the engine turned
// the handshake down, and is answered 400.
function serve({ batch }) {
  const log = { dispatched: [], wsOpen: [], wsMessages: 0 };
  let buffers = null;
  const handle = (reqId, path) => {
    log.dispatched.push(path);
    if (path === '/ws') return void engine.respond(reqId, 400, ['content-type', 'text/plain'], body('refused'));
    const send = () => engine.respond(reqId, 200, ['content-type', 'text/plain'], body('own:' + path));
    if (path.startsWith('/micro/')) return void Promise.resolve().then(send);
    if (path.startsWith('/timer/')) return void setTimeout(send, 1);
    send();
  };
  const callbacks = {
    onRequest: (reqId, m, path) => handle(reqId, path),
    onAborted() {},
    onWritable() {},
    onWsOpen: (wsId, path) => log.wsOpen.push(path),
    onWsMessage(wsId, data, isBinary) {
      log.wsMessages++;
      engine.wsSend(wsId, data, isBinary);
    },
    onWsClose() {},
  };
  if (batch) {
    callbacks.onRequestBatch = (count) => {
      const { descriptors: d, control: ctl, paths } = buffers;
      let i = 0;
      for (;;) {
        const reqId = d[3 * i];
        const pi = d[3 * i + 2];
        handle(reqId, pi === NO_PATH ? engine.getPath(reqId) : paths[pi]);
        const next = ctl[0];
        if (next === i) return i + 1;
        if (next >= count) return count;
        i = next;
      }
    };
  }
  const sid = engine.serve(callbacks);
  if (batch) buffers = engine.getBatchBuffers(sid);
  engine.setWsAutoUpgrade(sid, true);
  const port = engine.listen(sid, '127.0.0.1', 0);
  return { sid, port, log, close: () => engine.close(sid) };
}

// One connection: `first` in one write, then (when `afterUpgrade` is given)
// those bytes once the 101 has arrived. Resolves with everything received
// when `done(buffered)` holds or after `timeout`.
function exchange(port, first, { afterUpgrade = null, done, timeout = 3000 }) {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(first));
    let buf = '';
    let sent = false;
    const finish = () => {
      clearTimeout(timer);
      sock.destroy();
      resolve(buf);
    };
    const timer = setTimeout(finish, timeout);
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (afterUpgrade && !sent && /HTTP\/1\.1 101 /.test(buf)) {
        sent = true;
        sock.write(afterUpgrade);
      }
      if (done(buf)) finish();
    });
    sock.on('error', () => {});
    sock.on('close', finish);
  });
}

const results = [];
const count = (raw, re) => (raw.match(re) || []).length;

// The handshake behind `ahead` requests, each answered the way `timing`
// says, with the first WebSocket frame in the same segment as the handshake
// or sent once the 101 is in.
for (const batch of [true, false]) {
  for (const timing of ['sync', 'micro', 'timer']) {
    for (const ahead of [1, 2, 9]) {
      for (const frame of ['same segment', 'after the 101']) {
        const s = serve({ batch });
        const paths = Array.from({ length: ahead }, (_, i) => `/${timing}/${i}`);
        const head = Buffer.from(paths.map(req).join('') + handshake(), 'latin1');
        const raw = await exchange(s.port, frame === 'same segment' ? Buffer.concat([head, FRAME]) : head, {
          afterUpgrade: frame === 'same segment' ? null : FRAME,
          done: (b) => b.endsWith(ECHO),
        });
        results.push({
          kind: 'upgrade',
          name: `${batch ? 'batch loop' : 'one by one'}, ${ahead} ahead answered ${timing}, frame ${frame}`,
          ahead,
          paths,
          ok200: count(raw, /HTTP\/1\.1 200 /g),
          switched: count(raw, /HTTP\/1\.1 101 /g),
          echoed: raw.endsWith(ECHO),
          wsOpen: s.log.wsOpen,
          wsMessages: s.log.wsMessages,
          dispatched: s.log.dispatched,
        });
        s.close();
      }
    }
  }
}

// An engine-answered route between the requests and the handshake: the
// response call that completes the request ahead of it answers the static
// route too, and the handshake is next.
for (const timing of ['sync', 'micro']) {
  const s = serve({ batch: true });
  engine.setStaticRoute(s.sid, 0, '/static', 200, ['content-type', 'text/plain'], 'static!');
  const paths = [`/${timing}/0`];
  const raw = await exchange(s.port, Buffer.concat([Buffer.from(req(paths[0]) + req('/static') + handshake(), 'latin1'), FRAME]), {
    done: (b) => b.endsWith(ECHO),
  });
  results.push({
    kind: 'upgrade',
    name: `batch loop, a static route between a request answered ${timing} and the handshake`,
    ahead: 2,
    paths,
    ok200: count(raw, /HTTP\/1\.1 200 /g),
    switched: count(raw, /HTTP\/1\.1 101 /g),
    echoed: raw.endsWith(ECHO),
    wsOpen: s.log.wsOpen,
    wsMessages: s.log.wsMessages,
    dispatched: s.log.dispatched,
  });
  s.close();
}

// A handshake the engine does not upgrade, behind two requests and with one
// more request after it. One with a key that is not 16 bytes of base64 is an
// ordinary request: it reaches the handler, once, in its place. One that
// asks for a protocol version other than 13 is answered 426 by the engine
// and reaches no handler. Either way the connection goes on being served.
for (const [what, bad, status, reachesHandler] of [
  ['a malformed key', { key: 'short' }, 400, true],
  ['an unsupported version', { version: '8' }, 426, false],
]) {
  for (const timing of ['sync', 'micro', 'timer']) {
    const s = serve({ batch: true });
    const paths = [`/${timing}/0`, `/${timing}/1`];
    const raw = await exchange(s.port, Buffer.from(paths.map(req).join('') + handshake(bad) + req('/sync/after'), 'latin1'), {
      done: (b) => count(b, /HTTP\/1\.1 \d{3} /g) >= 4,
    });
    results.push({
      kind: 'refused',
      name: `batch loop, a handshake with ${what} behind two requests answered ${timing}`,
      statuses: (raw.match(/HTTP\/1\.1 \d{3}/g) || []).map((l) => Number(l.slice(9))),
      expectedStatuses: [200, 200, status, 200],
      wsOpen: s.log.wsOpen,
      dispatched: s.log.dispatched,
      expected: reachesHandler ? [...paths, '/ws', '/sync/after'] : [...paths, '/sync/after'],
    });
    s.close();
  }
}

// The results are one line of some 12 kB, and stdout is a pipe: exit once it
// has been written. (A write to a pipe may complete later - where the pipe
// holds 8 kB, as the one spawnSync makes on macOS does under Node 20 - and
// process.exit() drops what is still queued.)
process.stdout.write(JSON.stringify({ bodyKind, results }) + '\n', () => process.exit(0));
