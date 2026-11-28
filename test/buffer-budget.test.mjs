// The buffer budget (capabilities.bufferBudget, the memoryBudget option):
// what all the connections of a thread hold in buffers together is bounded,
// where every other limit bounds one connection. probe().bufferBudget reports
// the count, the thread's share and the connections closed for it, which is
// what these tests watch, together with what a peer sees: a request that
// does not fit is told 503, a WebSocket message 1013, and a peer that fills
// the budget and then moves nothing is closed at the sweep.
//
// One server at a time: the budget belongs to the thread, and the figures a
// thread's share is made from are set afresh when its last server has closed.
import { describe, it } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import http2 from 'node:http2';
import engine from '../packages/engine/index.mjs';

const CRLF = '\r\n';
const KiB = 1024;
const MiB = 1024 * KiB;
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const budget = () => engine.probe().bufferBudget;

async function waitFor(predicate, message, timeout = 4000) {
  const end = Date.now() + timeout;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > end) assert.fail(`${message} (bufferBudget: ${JSON.stringify(budget())})`);
    await delay(10);
  }
}

// A raw client: everything it received, and whether the server closed it.
function connect(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1');
    const c = { socket: s, received: Buffer.alloc(0), closed: false };
    c.text = () => c.received.toString('latin1');
    c.status = () => (c.received.length >= 12 ? Number(c.text().slice(9, 12)) : 0);
    s.on('data', (d) => (c.received = Buffer.concat([c.received, d])));
    s.on('error', () => {});
    s.on('close', () => (c.closed = true));
    s.once('error', reject);
    s.once('connect', () => resolve(c));
  });
}

const upload = (path, declared, sent) =>
  `POST ${path} HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${declared}${CRLF}${CRLF}` + 'x'.repeat(sent);

// Requests of `size` bytes that a handler keeps (the handler counts them:
// `held()` says how many it has), opened one after another until `enough()`.
// A complete request in a handler's hands is never closed for the budget;
// one that is still arriving when the thread runs short is told 503, and
// another is simply sent in its place. (To take a thread OVER its share
// this way the requests must be of 16 KiB or less, which are never refused:
// a larger one that arrives in more than one read - on the io_uring
// transport every request of more than a receive buffer does - is refused
// by the read that crosses the line, every time.)
async function holdRequests(server, held, enough, size, opened) {
  for (let tries = 0; !enough() && tries < 200; tries++) {
    const c = await connect(server.port);
    opened.push(c);
    const was = held();
    c.socket.write(upload('/hold', size, size));
    await waitFor(() => held() > was || c.status() === 503 || c.closed, 'a request is taken by its handler or refused');
  }
  assert.ok(enough(), `enough requests are held (bufferBudget: ${JSON.stringify(budget())})`);
}

// A server whose thread's share is exactly `memoryBudget`: one thread, and
// limits small enough that the largest message is below it.
function serve(callbacks, options = {}) {
  const sid = engine.serve(
    { onAborted() {}, ...callbacks },
    { maxBodySize: 256 * KiB, wsMaxMessageSize: 64 * KiB, memoryBudget: MiB, ...options }
  );
  const port = engine.listen(sid, '127.0.0.1', 0);
  return { sid, port, close: () => engine.close(sid) };
}

const echoSize = {
  onRequest(reqId) {
    const body = engine.getBody(reqId);
    engine.respond(reqId, 200, ['content-type', 'text/plain'], String(body ? body.byteLength : 0));
  },
};

const skip = engine.probe().capabilities.bufferBudget ? false : 'this engine build has no buffer budget';

// The cases that need response bytes to wait in the engine's write queue
// behind a peer that takes none, or takes them slowly. Wherever the system
// takes only what fits its socket buffers the rest of a large response is
// queued in the engine, and counted. Windows does not work that way: Winsock
// reports a send complete once it has copied it into the socket's kernel
// buffer, and it copies the first two sends outstanding on a socket whatever
// their size (Microsoft, "Design issues - Sending small data segments over
// TCP with Winsock"; libuv src/win/tcp.c, uv__tcp_try_write and
// uv__tcp_write). One response of any size is then held by the system and
// none of it by the engine: there is nothing in the queue to count, to see
// drain or to close a peer for, and the budget's rules for unread responses
// begin with the third send outstanding on a connection (docs/API.md,
// "Memory"). The rules themselves are the same there.
const needsQueuedResponse = process.platform === 'win32' && 'Winsock takes a whole send into the socket buffer: one large response leaves nothing queued in the engine';

describe('buffer budget: what the probe reports', { skip }, () => {
  it('a thread with no server has no share; a server gives it one', async () => {
    assert.equal(budget().limit, Infinity);
    assert.equal(budget().held, 0);
    const server = serve(echoSize);
    try {
      assert.equal(budget().limit, MiB);
      assert.deepEqual(Object.keys(budget()).sort(), [
        'connections',
        'evicted',
        'held',
        'limit',
        'receiveBuffer',
        'resized',
        'shed',
        'sockets',
      ]);
    } finally {
      server.close();
    }
    await waitFor(() => budget().limit === Infinity, 'the share goes with the last server');
  });

  it('without the option the budget is an eighth of the memory the process may use', () => {
    const sid = engine.serve({ onRequest() {}, onAborted() {} });
    try {
      engine.listen(sid, '127.0.0.1', 0);
      const { limit } = budget();
      assert.ok(Number.isFinite(limit) && limit >= 16 * MiB, `a finite share, at least the largest message: ${limit}`);
    } finally {
      engine.close(sid);
    }
  });

  it('the share is never below the largest message a connection may send', () => {
    // wsMaxMessageSize is 16 MiB unless set: that is the least.
    const sid = engine.serve({ onRequest() {}, onAborted() {} }, { memoryBudget: MiB });
    try {
      engine.listen(sid, '127.0.0.1', 0);
      assert.equal(budget().limit, 16 * MiB);
    } finally {
      engine.close(sid);
    }
  });

  it('memoryBudget: Infinity is no budget', () => {
    const sid = engine.serve({ onRequest() {}, onAborted() {} }, { memoryBudget: Infinity });
    try {
      engine.listen(sid, '127.0.0.1', 0);
      assert.equal(budget().limit, Infinity);
    } finally {
      engine.close(sid);
    }
  });
});

describe('buffer budget: requests still arriving', { skip }, () => {
  it('counts a body as it arrives and nothing once the request is answered', async () => {
    const server = serve(echoSize);
    try {
      const c = await connect(server.port);
      c.socket.write(upload('/one', 200 * KiB, 100 * KiB));
      await waitFor(() => budget().held >= 100 * KiB, 'the part of the body that arrived is counted');
      assert.ok(budget().held <= 300 * KiB, `no more than the body's buffer: ${budget().held}`);
      c.socket.write('y'.repeat(100 * KiB));
      await waitFor(() => c.status() === 200, 'the request is answered');
      await waitFor(() => budget().held === 0, 'an answered request holds nothing');
      c.socket.destroy();
    } finally {
      server.close();
    }
  });

  it('a body that does not fit is answered 503 and its connection closed; the ones that fit complete', async () => {
    const server = serve(echoSize);
    try {
      const shedBefore = budget().shed;
      const clients = [];
      for (let i = 0; i < 12; i++) {
        const c = await connect(server.port);
        c.socket.write(upload(`/u${i}`, 250 * KiB, 200 * KiB));
        clients.push(c);
        await delay(15);
      }
      await waitFor(() => clients.filter((c) => c.status() === 503).length === 8, 'eight of twelve are refused');
      const refused = clients.filter((c) => c.status() === 503);
      const holding = clients.filter((c) => c.status() === 0);
      assert.equal(holding.length, 4, 'four 250 KiB bodies fit in 1 MiB');
      assert.ok(refused.every((c) => /connection: close/i.test(c.text())), 'the 503 ends the connection');
      await waitFor(() => refused.every((c) => c.closed), 'the refused connections are closed');
      assert.equal(budget().shed, shedBefore + 8);
      assert.ok(budget().held <= MiB, `the count stays within the share: ${budget().held}`);
      for (const c of holding) c.socket.write('y'.repeat(50 * KiB));
      await waitFor(() => holding.every((c) => c.status() === 200), 'the bodies that fit are served');
      assert.ok(holding.every((c) => c.text().endsWith(String(250 * KiB))));
      await waitFor(() => budget().held === 0, 'nothing is held afterwards');
      for (const c of holding) c.socket.destroy();
    } finally {
      server.close();
    }
  });

  it('a request of a few kilobytes is served while the budget is full', async () => {
    const server = serve(echoSize);
    try {
      const big = [];
      for (let i = 0; i < 4; i++) {
        const c = await connect(server.port);
        c.socket.write(upload(`/big${i}`, 250 * KiB, 240 * KiB));
        big.push(c);
      }
      await waitFor(() => budget().held >= 960 * KiB, 'the budget is taken');
      const over = await connect(server.port);
      over.socket.write(upload('/over', 250 * KiB, 200 * KiB));
      await waitFor(() => over.status() === 503, 'a large body no longer fits');
      // A complete small request, and one that arrives in two pieces (so
      // that it is held for a moment, and counted).
      const small = await connect(server.port);
      small.socket.write(upload('/small', 8 * KiB, 8 * KiB));
      await waitFor(() => small.status() === 200, 'a small request is answered');
      const halves = await connect(server.port);
      halves.socket.write(upload('/halves', 12 * KiB, 6 * KiB));
      await delay(60);
      halves.socket.write('y'.repeat(6 * KiB));
      await waitFor(() => halves.status() === 200, 'a small request in two pieces is answered');
      for (const c of [...big, small, halves]) c.socket.destroy();
    } finally {
      server.close();
    }
  });

  it('a chunked body is counted and refused like any other', async () => {
    const server = serve(echoSize);
    try {
      const chunk = (n) => n.toString(16) + CRLF + 'x'.repeat(n) + CRLF;
      const clients = [];
      for (let i = 0; i < 8; i++) {
        const c = await connect(server.port);
        c.socket.write(`POST /c${i} HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}`);
        for (let k = 0; k < 5; k++) c.socket.write(chunk(40 * KiB));
        clients.push(c);
        await delay(15);
      }
      await waitFor(() => clients.some((c) => c.status() === 503), 'chunked bodies past the share are refused');
      assert.ok(budget().held <= MiB + 64 * KiB, `the count stays at the share: ${budget().held}`);
      const holding = clients.filter((c) => c.status() === 0);
      assert.ok(holding.length >= 1 && holding.length < 8);
      for (const c of holding) c.socket.write('0' + CRLF + CRLF);
      await waitFor(() => holding.every((c) => c.status() === 200), 'the ones that fit complete');
      for (const c of clients) c.socket.destroy();
    } finally {
      server.close();
    }
  });
});

describe('buffer budget: peers that hold it and move nothing', { skip }, () => {
  it('are closed at the sweep once the budget is nearly spent, and not before', async () => {
    const server = serve(echoSize);
    try {
      // Half the share, held by two connections that then stop: not closed.
      const evictedBefore = budget().evicted;
      const idle = [];
      for (let i = 0; i < 2; i++) {
        const c = await connect(server.port);
        c.socket.write(upload(`/idle${i}`, 250 * KiB, 240 * KiB));
        idle.push(c);
      }
      await waitFor(() => budget().held >= 480 * KiB, 'half the share is held');
      await delay(2600);
      assert.ok(idle.every((c) => !c.closed), 'a stalled connection is left alone while there is room');
      assert.equal(budget().evicted, evictedBefore);
      // Two more take it past seven eighths, and keep sending.
      const moving = [];
      for (let i = 0; i < 2; i++) {
        const c = await connect(server.port);
        c.socket.write(upload(`/moving${i}`, 250 * KiB, 200 * KiB));
        moving.push(c);
      }
      const drip = setInterval(() => moving.forEach((c) => c.socket.write('z'.repeat(64))), 100);
      try {
        await waitFor(() => idle.every((c) => c.closed), 'the connections that stopped are closed', 6000);
        assert.equal(budget().evicted, evictedBefore + 2);
        assert.equal(idle[0].received.length, 0, 'closed without a response');
        // The ones still sending are not, then or later: there is room again.
        await delay(2200);
        assert.ok(moving.every((c) => !c.closed), 'a connection still sending is not closed');
        assert.equal(budget().evicted, evictedBefore + 2);
      } finally {
        clearInterval(drip);
      }
      for (const c of moving) c.socket.destroy();
    } finally {
      server.close();
    }
  });

  it('a request a handler is holding is not one of them', async () => {
    let heldReq = 0;
    const server = serve({
      onRequest(reqId, _method, path) {
        if (path === '/held') heldReq = reqId;
        else engine.respond(reqId, 200, null, 'ok');
      },
    });
    try {
      // A complete 250 KiB request the handler takes its time over, and
      // three more that fill the budget and stall.
      const held = await connect(server.port);
      held.socket.write(upload('/held', 250 * KiB, 250 * KiB));
      await waitFor(() => heldReq !== 0, 'the handler has the request');
      const stalled = [];
      for (let i = 0; i < 3; i++) {
        const c = await connect(server.port);
        c.socket.write(upload(`/s${i}`, 250 * KiB, 240 * KiB));
        stalled.push(c);
      }
      await waitFor(() => stalled.every((c) => c.closed), 'the stalled connections are closed', 6000);
      assert.ok(!held.closed, 'the request in the handler is not');
      engine.respond(heldReq, 200, null, 'late');
      await waitFor(() => held.status() === 200, 'and is answered when the handler is done');
      held.socket.destroy();
    } finally {
      server.close();
    }
  });
});

describe('buffer budget: responses a peer does not read', { skip }, () => {
  it('are counted, and the peers that take none of them are closed at the sweep once the thread is short', { skip: needsQueuedResponse }, async () => {
    // Larger than what the kernel takes for a peer that is not reading (on
    // Linux up to some 10 MiB between the two sockets' buffers), so that
    // most of it stays queued in the engine.
    const big = Buffer.alloc(24 * MiB, 0x61);
    const server = serve(
      {
        onRequest(reqId, _method, path) {
          engine.respond(reqId, 200, ['content-type', 'text/plain'], path === '/big' ? big : 'ok');
        },
      },
      { memoryBudget: 4 * MiB }
    );
    try {
      // Clients that ask and never read: what the socket does not take stays
      // queued in the engine. Nothing says, when a response is queued, that
      // its peer will not read it, so none of them is closed there: they go
      // at the sweep that finds the thread short and nothing of theirs moved.
      const before = budget();
      const clients = [];
      for (let i = 0; i < 6; i++) {
        const c = await connect(server.port);
        c.socket.pause();
        c.socket.write(`GET /big HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        clients.push(c);
        await delay(40);
      }
      assert.ok(budget().held > 4 * MiB, `the responses queued are counted: ${budget().held}`);
      assert.equal(budget().shed, before.shed, 'no connection is closed where its response is queued');
      await waitFor(() => budget().evicted >= before.evicted + 6, 'the peers that read nothing are closed at the sweep', 6000);
      await waitFor(() => budget().held <= 4 * MiB, 'and what they held is given back');
      // A reader is served as always.
      const reader = await connect(server.port);
      reader.socket.write(`GET /small HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      await waitFor(() => reader.status() === 200, 'a small response is still given');
      for (const c of [...clients, reader]) c.socket.destroy();
      await waitFor(() => budget().held === 0, 'closed connections are counted out');
    } finally {
      server.close();
    }
  });

  it('HTTP/2: responses held behind windows the peer never opens', async () => {
    const big = Buffer.alloc(512 * KiB, 0x62);
    const server = serve(
      {
        onRequest(reqId) {
          engine.respond(reqId, 200, ['content-type', 'text/plain'], big);
        },
      },
      { http2: true, memoryBudget: 4 * MiB }
    );
    const sessions = [];
    const before = budget();
    try {
      let closed = 0;
      for (let i = 0; i < 6; i++) {
        // A stream window of zero: every response body waits in the session.
        const session = http2.connect(`http://127.0.0.1:${server.port}`, { settings: { initialWindowSize: 0 } });
        session.on('error', () => {});
        session.on('close', () => closed++);
        sessions.push(session);
        await new Promise((r) => session.once('remoteSettings', r));
        for (let k = 0; k < 4; k++) {
          const stream = session.request({ ':path': `/s${i}/${k}` });
          stream.on('error', () => {});
          stream.end();
        }
        await delay(40);
      }
      assert.ok(budget().held > 4 * MiB, `the responses held are counted: ${budget().held}`);
      assert.equal(budget().shed, before.shed, 'no session is closed where its responses are held');
      // 12 MiB against a share of 4. Which rule gets there first depends on
      // the clock: the sweep closes every session that has moved nothing
      // while the thread is nearly out of room, all six; the look a thread
      // at twice its share takes four times a second (1.2.5) closes the ones
      // owed most until the thread is within its share again, five of them,
      // and the sixth then holds 2 MiB of a share with room in it.
      await waitFor(
        () => budget().evicted >= before.evicted + 5 && closed >= 5 && budget().held <= budget().limit,
        'the sessions that open no window are closed until the thread is within its share',
        6000
      );
    } finally {
      for (const s of sessions) s.destroy();
      server.close();
    }
    await waitFor(() => budget().held === 0, 'closed sessions are counted out');
  });
});

describe('buffer budget: HTTP/2 request bodies', { skip }, () => {
  // A stream that declares a length and has sent a sixteenth of it has the
  // whole of it set aside: 250 KiB each here, for 20 KiB sent.
  const declared = 250 * KiB;
  const open = async (port) => {
    const session = http2.connect(`http://127.0.0.1:${port}`);
    const s = { session, goaway: false, closed: false, status: 0, body: '' };
    session.on('error', () => {});
    session.on('goaway', () => (s.goaway = true));
    session.on('close', () => (s.closed = true));
    await new Promise((r) => session.once('remoteSettings', r));
    s.stream = session.request({ ':method': 'POST', ':path': '/up', 'content-length': declared });
    s.stream.on('error', () => {});
    s.stream.on('response', (h) => (s.status = h[':status']));
    s.stream.on('data', (d) => (s.body += d));
    s.stream.write(Buffer.alloc(20 * KiB, 0x78));
    return s;
  };

  it('are counted while they arrive, and no longer once the request is with its handler and answered', async () => {
    const server = serve(echoSize, { http2: true });
    const sessions = [];
    // Where it happens, not at the sweep that counts everything a second later.
    const soon = 600;
    try {
      const before = budget();
      for (let i = 0; i < 3; i++) {
        sessions.push(await open(server.port));
        await waitFor(() => budget().held >= (i + 1) * declared, `the room set aside for body ${i + 1} is counted`, soon);
      }
      assert.ok(budget().held <= 3 * declared + 200 * KiB, `and little else: ${budget().held}`);
      assert.equal(budget().shed, before.shed);
      // The first is completed: what was set aside for it is the handler's.
      sessions[0].stream.end(Buffer.alloc(declared - 20 * KiB, 0x78));
      await waitFor(() => sessions[0].status === 200 && sessions[0].body === String(declared), 'the first body is answered');
      await waitFor(() => budget().held < 2 * declared + 100 * KiB, 'its room is counted out', soon);
      // The second is abandoned by its peer, the third closed with its session.
      sessions[1].stream.close(http2.constants.NGHTTP2_CANCEL);
      await waitFor(() => budget().held < declared + 100 * KiB, 'a stream that is reset is counted out', soon);
      sessions[2].session.destroy();
      await waitFor(() => budget().held < 100 * KiB, 'and so is a session that goes', soon);
    } finally {
      for (const s of sessions) s.session.destroy();
      server.close();
    }
    await waitFor(() => budget().held === 0, 'closed sessions are counted out');
  });

  it('a session whose bodies do not fit is closed with GOAWAY; the ones that fit complete', async () => {
    const server = serve(echoSize, { http2: true });
    const sessions = [];
    try {
      const before = budget();
      // Four fit in the megabyte; the fifth and the sixth do not.
      for (let i = 0; i < 6; i++) {
        sessions.push(await open(server.port));
        await delay(60);
      }
      await waitFor(() => budget().shed >= before.shed + 2, 'two sessions are closed for the room they needed');
      const refused = sessions.filter((s) => s.goaway || s.closed);
      await waitFor(() => sessions.filter((s) => s.closed).length >= 2, 'their peers see them closed');
      assert.ok(sessions.filter((s) => s.goaway).length >= 2, 'and were told GOAWAY first');
      assert.ok(budget().held <= MiB + 64 * KiB, `the count stays at the share: ${budget().held}`);
      const fit = sessions.filter((s) => !s.closed);
      assert.equal(fit.length, 4, `${refused.length} refused`);
      for (const s of fit) s.stream.end(Buffer.alloc(declared - 20 * KiB, 0x78));
      await waitFor(() => fit.every((s) => s.status === 200 && s.body === String(declared)), 'the four that fit are answered');
      assert.equal(budget().shed, before.shed + 2);
    } finally {
      for (const s of sessions) s.session.destroy();
      server.close();
    }
    await waitFor(() => budget().held === 0, 'closed sessions are counted out');
  });
});

// A response is never the reason its connection is closed while its peer is
// taking it: what a handler gives a reading peer arrives, whatever its size
// against the thread's share, as it did before there was a budget.
describe('buffer budget: responses a peer is reading', { skip }, () => {
  // A client on a slow link: it takes what its socket has buffered (some
  // tens of kilobytes) every `every` ms, and nothing in between.
  function slowClient(port, every) {
    return new Promise((resolve, reject) => {
      const s = net.connect(port, '127.0.0.1');
      const c = { socket: s, received: 0, closed: false };
      s.on('error', () => {});
      s.on('close', () => (c.closed = true));
      s.on('readable', () => {});
      const t = setInterval(() => {
        for (let d = s.read(); d !== null; d = null) c.received += d.length;
      }, every);
      c.stop = () => clearInterval(t);
      s.once('error', reject);
      s.once('connect', () => resolve(c));
    });
  }

  it('a response many times the share is delivered whole, with other requests being served meanwhile', { timeout: 60000 }, async () => {
    const big = Buffer.alloc(24 * MiB, 0x61);
    const server = serve({
      onRequest(reqId, _method, path) {
        engine.respond(reqId, 200, ['content-type', 'text/plain'], path === '/big' ? big : 'ok');
      },
    });
    try {
      const before = budget();
      assert.equal(before.limit, MiB);
      const other = await connect(server.port);
      const ticking = setInterval(() => other.socket.write(`GET /small HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`), 2);
      try {
        const reader = await connect(server.port);
        reader.socket.write(`GET /big HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        await waitFor(() => reader.received.length >= big.length || reader.closed, 'the response arrives or the connection ends', 30000);
        assert.ok(reader.received.length >= big.length, `received ${reader.received.length} of ${big.length} bytes; closed: ${reader.closed}`);
        assert.equal(reader.closed, false);
        reader.socket.destroy();
      } finally {
        clearInterval(ticking);
      }
      assert.deepEqual([budget().shed, budget().evicted], [before.shed, before.evicted], 'nothing was closed for the budget');
      other.socket.destroy();
    } finally {
      server.close();
    }
  });

  it('a request pipelined behind it is not refused for the bytes of that response', { timeout: 60000 }, async () => {
    const big = Buffer.alloc(24 * MiB, 0x62);
    const server = serve({
      onRequest(reqId, _method, path) {
        if (path === '/big') return engine.respond(reqId, 200, null, big);
        const body = engine.getBody(reqId);
        engine.respond(reqId, 200, null, `echo:${body ? body.byteLength : 0}`);
      },
    });
    try {
      const before = budget();
      const c = await connect(server.port);
      // 40 KiB of request behind the large response: more than a request may
      // hold when the thread is short - and the thread is over its share,
      // by nothing but the response this same connection is reading.
      c.socket.write(`GET /big HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}` + upload('/after', 40 * KiB, 40 * KiB));
      await waitFor(() => c.text().endsWith(`echo:${40 * KiB}`) || c.closed, 'both responses arrive or the connection ends', 30000);
      assert.ok(c.text().endsWith(`echo:${40 * KiB}`), `received ${c.received.length} bytes; closed: ${c.closed}`);
      assert.deepEqual([budget().shed, budget().evicted], [before.shed, before.evicted]);
      c.socket.destroy();
    } finally {
      server.close();
    }
  });

  // The stall rule asks whether anything moved since the sweep before. A
  // download whose queue is draining has moved, and that is seen with or
  // without a response timeout to see it for. (What moves is what the
  // kernel takes from the engine's queue, and a kernel takes in steps - on
  // Linux a socket is writable again once a third of its send buffer is
  // free, over a megabyte when the buffer has grown - so the client here
  // reads some two megabytes a second: a step in every sweep interval.)
  for (const responseTimeoutMs of [0, 30000]) {
    it(`a slow download that keeps moving is not closed while the thread is short (responseTimeoutMs ${responseTimeoutMs})`, { timeout: 60000, skip: needsQueuedResponse }, async () => {
      const limit = 128 * MiB; // an eighth of it is more than the download drains by while it is watched
      const download = Buffer.alloc(40 * MiB, 0x63);
      let heldReqs = 0;
      const server = serve(
        {
          onRequest(reqId, _method, path) {
            if (path === '/download') return engine.respond(reqId, 200, null, download);
            heldReqs++; // /hold: a handler that keeps its request
          },
        },
        // (No idle timeout: with the response timeout off it is what bounds
        // a response still draining, and this is not about either.)
        { memoryBudget: limit, maxBodySize: 2 * MiB, idleTimeoutMs: 0, requestTimeoutMs: 0, responseTimeoutMs }
      );
      const holders = [];
      try {
        const before = budget();
        assert.equal(before.limit, limit);
        const dl = await slowClient(server.port, 30);
        try {
          dl.socket.write(`GET /download HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          await waitFor(() => budget().held > 8 * MiB, 'most of the download is queued in the engine');
          // Requests their handlers keep, until less than an eighth of the
          // share is left: the thread is short, and stays within its share.
          await holdRequests(server, () => heldReqs, () => budget().held >= limit - 3 * MiB, MiB, holders);
          const short = () => budget().held > limit - limit / 8 && budget().held <= limit;
          assert.ok(short(), `the thread is short: ${JSON.stringify(budget())}`);
          const at = dl.received;
          await delay(3600); // three sweeps and more
          assert.equal(dl.closed, false, `the download was closed with ${dl.received} of ${download.length} bytes; ${JSON.stringify(budget())}`);
          assert.ok(dl.received > at && dl.received < download.length, `and it went on: ${at} -> ${dl.received}`);
          assert.equal(budget().evicted, before.evicted);
          assert.ok(budget().held > limit - limit / 8, `the thread was short throughout: ${JSON.stringify(budget())}`);
        } finally {
          dl.stop();
        }
        dl.socket.destroy();
      } finally {
        for (const h of holders) h.socket.destroy();
        server.close();
      }
    });

    it(`HTTP/2: a response whose windows keep opening is not closed while the thread is short (responseTimeoutMs ${responseTimeoutMs})`, { timeout: 60000 }, async () => {
      const limit = 64 * MiB;
      const download = Buffer.alloc(40 * MiB, 0x63);
      let heldReqs = 0;
      const server = serve(
        {
          onRequest(reqId, _method, path) {
            if (path === '/download') return engine.respond(reqId, 200, null, download);
            heldReqs++; // /hold
          },
        },
        { http2: true, memoryBudget: limit, maxBodySize: 2 * MiB, idleTimeoutMs: 0, requestTimeoutMs: 0, responseTimeoutMs }
      );
      const holders = [];
      const session = http2.connect(`http://127.0.0.1:${server.port}`);
      session.on('error', () => {});
      try {
        const before = budget();
        let received = 0;
        let closed = false;
        session.on('close', () => (closed = true));
        const stream = session.request({ ':path': '/download' });
        stream.on('error', () => {});
        stream.end();
        // Takes what has been buffered for it every 100 ms, and nothing in
        // between: its windows open a little at a time.
        const take = setInterval(() => {
          for (let chunk; (chunk = stream.read()) !== null; ) received += chunk.length;
        }, 100);
        try {
          await waitFor(() => budget().held > 8 * MiB, 'most of the download waits in the session');
          await holdRequests(server, () => heldReqs, () => budget().held >= limit - 4 * MiB, MiB, holders);
          assert.ok(budget().held > limit - limit / 8 && budget().held <= limit, `the thread is short: ${JSON.stringify(budget())}`);
          const at = received;
          await delay(3600); // three sweeps and more
          assert.equal(closed, false, `the session was closed with ${received} of ${download.length} bytes; ${JSON.stringify(budget())}`);
          assert.ok(received > at && received < download.length, `and it went on: ${at} -> ${received}`);
          assert.equal(budget().evicted, before.evicted);
          assert.ok(budget().held > limit - limit / 8, `the thread was short throughout: ${JSON.stringify(budget())}`);
        } finally {
          clearInterval(take);
        }
      } finally {
        session.destroy();
        for (const h of holders) h.socket.destroy();
        server.close();
      }
    });
  }

  // Whether a response is moving is the kernel's to say. The engine's own
  // queue shrinks when the socket takes more, and a socket takes in steps
  // (a megabyte and more, once its send buffer has grown): for a peer that
  // reads a quarter of a megabyte a second the queue stands still for
  // sweeps on end, while every one of its acknowledgments takes something
  // off what the kernel holds for it.
  //
  // Linux only. What a server can see of a peer's reading is what that
  // peer's TCP stack tells it, and the one on macOS - the client here, over
  // loopback - announces a window only once a quarter of its receive buffer
  // has been read: at this pace that is a second or two of nothing at all,
  // which no server can tell from a peer that has stopped.
  const linuxOnly = process.platform === 'linux' ? false : 'what the reading peer reports of itself is not steady on this platform';
  it('a peer that reads a quarter of a megabyte a second is not closed while the thread is short; one that reads nothing is', { timeout: 90000, skip: linuxOnly }, async () => {
    const limit = 64 * MiB;
    const download = Buffer.alloc(8 * MiB, 0x63);
    let heldReqs = 0;
    const server = serve(
      {
        onRequest(reqId, _method, path) {
          if (path === '/download') return engine.respond(reqId, 200, null, download);
          heldReqs++; // /hold
        },
      },
      { memoryBudget: limit, maxBodySize: 2 * MiB, idleTimeoutMs: 0, requestTimeoutMs: 0 }
    );
    const holders = [];
    let reader = null;
    try {
      const before = budget();
      // Requests their handlers keep: with them alone the thread has less
      // than an eighth of its share left, whatever becomes of the downloads.
      const short = () => budget().held > limit - limit / 8;
      await holdRequests(server, () => heldReqs, () => budget().held >= limit - limit / 8 + 2 * MiB, MiB, holders);
      // Two peers ask for 8 MiB each. One takes 26 KiB every tenth of a
      // second; the other takes nothing.
      reader = await new Promise((resolve, reject) => {
        const s = net.connect(server.port, '127.0.0.1');
        const c = { socket: s, received: 0, closed: false, timer: null };
        const take = (n) => {
          const d = (n ? s.read(n) : null) ?? s.read();
          if (d !== null) c.received += d.length;
          return d !== null;
        };
        c.pace = (n, every) => {
          clearInterval(c.timer);
          c.timer = setInterval(() => {
            if (n) take(n);
            else while (take(0));
          }, every);
        };
        s.on('error', () => {});
        s.on('close', () => (c.closed = true));
        s.on('readable', () => {});
        s.once('error', reject);
        s.once('connect', () => resolve(c));
      });
      reader.pace(26 * KiB, 100);
      const silent = await connect(server.port);
      silent.socket.pause();
      const get = `GET /download HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;
      reader.socket.write(get);
      silent.socket.write(get);
      await waitFor(() => budget().held > limit, 'both responses are queued');
      await waitFor(() => budget().evicted > before.evicted, 'the peer that takes nothing is closed at the sweep', 8000);
      assert.equal(budget().evicted, before.evicted + 1);
      silent.socket.resume(); // (a socket that is not read does not see its end either)
      await waitFor(() => silent.closed, 'and it was that one');
      assert.ok(silent.received.length < download.length);
      assert.equal(reader.closed, false, `the peer that was reading was closed with ${reader.received} of ${download.length} bytes`);
      // Seven sweeps and more of the slow one, the thread short throughout.
      await delay(7500);
      assert.ok(short(), `the thread was short throughout: ${JSON.stringify(budget())}`);
      assert.equal(reader.closed, false, `the peer that was reading was closed with ${reader.received} of ${download.length} bytes; ${JSON.stringify(budget())}`);
      assert.equal(budget().evicted, before.evicted + 1);
      assert.ok(reader.received > MiB && reader.received < 4 * MiB, `it read at its own pace: ${reader.received}`);
      // And it gets the rest.
      reader.pace(0, 5);
      await waitFor(() => reader.received > download.length || reader.closed, 'the download completes', 30000);
      assert.equal(reader.closed, false);
      assert.deepEqual([budget().shed, budget().evicted], [before.shed, before.evicted + 1]);
      silent.socket.destroy();
    } finally {
      if (reader) {
        clearInterval(reader.timer);
        reader.socket.destroy();
      }
      for (const h of holders) h.socket.destroy();
      server.close();
    }
  });
});

// What a request is refused for is what it has sent, not the storage it was
// parsed into: a request state comes from a pool with the capacity earlier
// requests grew its buffers to.
describe('buffer budget: a small request and the state it is parsed in', { skip }, () => {
  it('a request of two kilobytes is served while the thread is over its share, whatever its state held before', async () => {
    let heldReqs = 0;
    const server = serve(
      {
        onRequest(reqId, _method, path) {
          if (path === '/hold') return void heldReqs++;
          const body = engine.getBody(reqId);
          engine.respond(reqId, 200, null, String(body ? body.byteLength : 0));
        },
      },
      { maxBodySize: 64 * KiB, maxHeadSize: 16 * KiB, wsMaxMessageSize: 16 * KiB, memoryBudget: 400 * KiB }
    );
    const others = [];
    try {
      assert.equal(budget().limit, 400 * KiB);
      // Over the share: requests their handlers keep, and bodies still arriving.
      await holdRequests(server, () => heldReqs, () => budget().held > budget().limit - 48 * KiB, 12 * KiB, others);
      for (let i = 0; i < 6; i++) {
        const c = await connect(server.port);
        c.socket.write(upload('/fill', 15000, 12000));
        others.push(c);
        await delay(10);
      }
      await waitFor(() => budget().held > budget().limit, 'the thread is over its share');
      // Requests that are served as they come, and leave the state and the
      // body buffer they used in their pools with the capacity they grew
      // them to: bodies of 60 KiB that arrive whole, and a head of 15 KiB in
      // two pieces (within what a request may hold while the thread is short).
      for (let i = 0; i < 4; i++) {
        const c = await connect(server.port);
        c.socket.write(upload('/warm', 60 * KiB, 60 * KiB));
        await waitFor(() => c.status() !== 0 || c.closed, 'a whole body is answered, or refused when it came in pieces');
        c.socket.destroy();
      }
      {
        const c = await connect(server.port);
        const head = `GET /warm HTTP/1.1${CRLF}Host: t${CRLF}X-Big: ${'h'.repeat(15000)}${CRLF}${CRLF}`;
        c.socket.write(head.slice(0, 9 * KiB));
        await delay(30);
        c.socket.write(head.slice(9 * KiB));
        await waitFor(() => c.status() === 200, 'a head of 15 KiB in two pieces is answered');
        c.socket.destroy();
        await delay(30);
      }
      const shedBefore = budget().shed;
      // Small requests that arrive in two pieces, so that each is held, and
      // counted, between the two.
      for (const [name, first, second, want] of [
        ['a body of 2000 bytes', upload('/small', 2000, 1000), 'a'.repeat(1000), '2000'],
        ['a head in two pieces', `GET /small HTTP/1.1${CRLF}Host: t${CRLF}X-A: 1`, `${CRLF}${CRLF}`, '0'],
        ['a body of 12 KiB', upload('/small', 12 * KiB, 6 * KiB), 'b'.repeat(6 * KiB), String(12 * KiB)],
      ]) {
        const c = await connect(server.port);
        c.socket.write(first);
        await delay(50);
        assert.equal(c.closed, false, `${name}: not closed after its first piece (${c.text().slice(0, 12)})`);
        c.socket.write(second);
        await waitFor(() => c.status() !== 0 || c.closed, `${name}: an answer`);
        assert.equal(c.status(), 200, `${name}: ${c.text().slice(0, 12) || 'closed without an answer'}`);
        assert.ok(c.text().endsWith(`${CRLF}${CRLF}${want}`), name);
        c.socket.destroy();
      }
      assert.equal(budget().shed, shedBefore, 'none of them was refused');
      // A body that is not small is still refused.
      const large = await connect(server.port);
      large.socket.write(upload('/large', 60 * KiB, 40 * KiB));
      await waitFor(() => large.status() === 503, 'a body of 40 KiB arriving is told 503');
      large.socket.destroy();
    } finally {
      for (const c of others) c.socket.destroy();
      server.close();
    }
  });
});

// A request reaches a handler only while its connection is open. A handler
// that is given one keeps its id, and answers it when it pleases.
describe('buffer budget: a connection closed for it and the requests it has sent', { skip }, () => {
  const NO_PATH = 0xffffffff;
  // The sequence: the victim does not read. Its first request is with a
  // handler while the thread goes over its share; the test then answers it,
  // outside a read, which brings the request pipelined behind it to its
  // handler. That one is answered at once with `large(room)` - more than
  // the sockets have room for, so that part of it stays queued - and the
  // victim's third request is written there and then, so that the victim's
  // own read is the next thing the server does.
  //
  // `measured`: how much stays queued is chosen, not left to what the two
  // sockets take on this machine at this moment. A connection of its own
  // asks for responses of 50 KiB, reading none, until one does not go out
  // whole: that is what the sockets take. The victim then asks for all but
  // the last few of as many, and `room` is what is left for it.
  async function run({ batch, first, large, options, measured = false }) {
    const seen = { first: 0, r2: 0, r2Aborted: false, shedAtR2: -1, aborted: [] };
    let victim = null;
    let buffers = null;
    let room = 0;
    let sent = 0;
    const chunk = Buffer.alloc(50 * KiB, 0x64);
    let heldReqs = 0;
    let chunks = 0;
    const handle = (reqId, path) => {
      if (path === '/hold') return void heldReqs++;
      if (path === '/chunk') {
        chunks++;
        return void engine.respond(reqId, 200, null, chunk);
      }
      if (path === '/first') return void (seen.first = reqId);
      if (path === '/r') {
        const body = large(room);
        sent += body.length;
        engine.respond(reqId, 200, null, body);
        victim.socket.write(`GET /r2 HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        return;
      }
      if (path === '/r2') {
        // Kept, and answered by the test once it has looked at how the
        // request came to be here.
        seen.r2 = reqId;
        seen.r2Aborted = engine.isAborted(reqId);
        seen.shedAtR2 = budget().shed;
        return;
      }
      engine.respond(reqId, 200, null, 'ok');
    };
    const callbacks = {
      onRequest: (reqId, _m, path) => handle(reqId, path),
      onAborted: (reqId) => seen.aborted.push(reqId),
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
    const server = serve(callbacks, { maxBodySize: 64 * KiB, maxHeadSize: 16 * KiB, wsMaxMessageSize: 16 * KiB, memoryBudget: 400 * KiB, ...options });
    if (batch) buffers = engine.getBatchBuffers(server.sid);
    const others = [];
    const askChunk = async (c) => {
      const was = chunks;
      c.socket.write(`GET /chunk HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      await waitFor(() => chunks > was, 'a chunk is asked for');
    };
    try {
      victim = await connect(server.port);
      victim.socket.pause();
      if (measured) {
        const gauge = await connect(server.port);
        gauge.socket.pause();
        for (let settled = false; !settled; ) {
          assert.ok(chunks < 2000, `the sockets fill: ${JSON.stringify(budget())}`);
          await askChunk(gauge);
          if (budget().held === 0) continue;
          await delay(40);
          settled = budget().held !== 0;
        }
        const taken = chunks * chunk.length - budget().held;
        gauge.socket.destroy();
        await waitFor(() => budget().held === 0, 'the measuring connection is gone');
        chunks = 0;
        const fill = Math.max(0, Math.floor((taken - 160 * KiB) / chunk.length));
        while (chunks < fill) await askChunk(victim);
        assert.equal(budget().held, 0, 'what the victim asked for so far went out whole');
        room = taken - fill * chunk.length;
        sent += fill * chunk.length;
      }
      // Over the share, by requests their handlers keep.
      await holdRequests(server, () => heldReqs, () => budget().held > budget().limit, 12 * KiB, others);
      const shedBefore = budget().shed;
      victim.socket.write(`GET /first HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}GET /r HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      await waitFor(() => seen.first !== 0, 'the first request is with its handler');
      await delay(60);
      sent += first.length;
      engine.respond(seen.first, 200, null, first);
      await delay(400);
      // What must hold, whatever was decided about the victim: a request is
      // not handed to a handler in the read that closed its connection.
      let answered = false;
      const answerR2 = () => {
        if (seen.r2 === 0 || answered) return;
        assert.equal(seen.r2Aborted, false, 'the request handed over was live');
        assert.equal(seen.shedAtR2, shedBefore, 'a request was handed to a handler behind the close of its connection for the budget');
        answered = true;
        if (!seen.aborted.includes(seen.r2)) engine.respond(seen.r2, 200, null, 'late');
      };
      answerR2();
      // And a request that was handed over is answered once its peer reads,
      // or its handler was told that the peer is gone.
      victim.socket.resume();
      const late = () => victim.received.subarray(-4).toString('latin1') === 'late';
      await waitFor(() => (answerR2(), victim.closed || late()), `the victim is answered or closed (${victim.received.length} of some ${sent} bytes)`, 20000);
      if (seen.r2 !== 0 && !late()) {
        assert.ok(seen.aborted.includes(seen.r2), 'a request that reached a handler and was not answered is reported aborted');
      }
      victim.socket.destroy();
    } finally {
      for (const c of others) c.socket.destroy();
      server.close();
    }
    await waitFor(() => budget().limit === Infinity, 'the server is gone');
  }

  for (const batch of [true, false]) {
    it(`its next request, arriving while part of a response to it is queued, is not handed to a handler behind the close (${batch ? 'batch' : 'one-by-one'} dispatch)`, { timeout: 60000 }, async () => {
      // A mark above the response, so that the request is not kept back for
      // the write queue whatever the socket takes of 12 MiB.
      const large = Buffer.alloc(12 * MiB, 0x62);
      await run({ batch, first: Buffer.alloc(100 * KiB, 0x61), large: () => large, options: { writeHighWaterMark: 16 * MiB } });
    });
  }

  it('the same at the default write high-water mark, with what is queued between 16 KiB and the mark', { timeout: 60000 }, async () => {
    // Below the mark the next request is read while the response before it
    // is still queued: some 130 KiB of it here, with the mark at 256.
    await run({ batch: true, measured: true, first: Buffer.from('ok'), large: (room) => Buffer.alloc(room + 130 * KiB, 0x62), options: {} });
  });
});

describe('buffer budget: WebSocket messages being reassembled', { skip }, () => {
  // A client-to-server frame (masked, with a zero key: the payload is as given).
  const frame = (opcode, fin, payload) => {
    const head = [(fin ? 0x80 : 0) | opcode];
    if (payload.length < 126) head.push(0x80 | payload.length);
    else head.push(0x80 | 126, payload.length >> 8, payload.length & 0xff);
    return Buffer.concat([Buffer.from(head), Buffer.alloc(4), payload]);
  };

  it('a message that does not fit is closed with 1013', async () => {
    let opened = 0;
    const closes = [];
    const sid = engine.serve(
      {
        onRequest(reqId) {
          engine.respond(reqId, 200, null, 'http');
        },
        onAborted() {},
        onWsOpen() {
          opened++;
        },
        onWsMessage() {},
        onWsClose(_id, code) {
          closes.push(code);
        },
      },
      { maxBodySize: 64 * KiB, wsMaxMessageSize: 400 * KiB, memoryBudget: MiB }
    );
    engine.setWsAutoUpgrade(sid, true);
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      assert.equal(budget().limit, MiB);
      const clients = [];
      for (let i = 0; i < 6; i++) {
        const c = await connect(port);
        c.socket.write(
          `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}` +
            `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`
        );
        clients.push(c);
      }
      await waitFor(() => opened === 6, 'six sockets are open');
      // Fragments with no end: 300 KiB each, 32 KiB at a time.
      const piece = Buffer.alloc(32 * KiB, 0x63);
      for (const c of clients) {
        c.mark = c.received.length;
        c.socket.write(frame(0x2, false, piece));
      }
      for (let round = 0; round < 9; round++) {
        await delay(20);
        for (const c of clients) if (!c.closed) c.socket.write(frame(0x0, false, piece));
      }
      await waitFor(() => closes.length >= 1, 'a socket is closed for the message it was sending');
      assert.ok(closes.every((code) => code === 1013), `closed with 1013: ${closes}`);
      // The peer is told so: a Close frame carrying 1013.
      const told = clients.filter((c) => {
        const after = c.received.subarray(c.mark);
        return after.length >= 4 && after[0] === 0x88 && after.readUInt16BE(2) === 1013;
      });
      assert.ok(told.length >= 1, 'the Close frame carries 1013');
      assert.ok(budget().held <= MiB + 64 * KiB, `the count stays at the share: ${budget().held}`);
      for (const c of clients) c.socket.destroy();
      await waitFor(() => budget().held === 0, 'closed sockets are counted out');
    } finally {
      engine.close(sid);
    }
  });

  it('an idle socket is not closed for a message it has delivered; one that stopped in the middle of a message is', async () => {
    const opened = [];
    const closes = new Map();
    const messages = [];
    let heldReqs = 0;
    const server = serve(
      {
        onRequest() {
          heldReqs++; // /hold: a handler that keeps its request
        },
        onWsOpen(id) {
          opened.push(id);
        },
        onWsMessage(id, data) {
          messages.push(data.byteLength ?? data.length);
        },
        onWsClose(id, code) {
          closes.set(id, code);
        },
      },
      // A sweep every quarter of a second, and no timeout that could close
      // a quiet socket here.
      { wsMaxMessageSize: 400 * KiB, idleTimeoutMs: 0, requestTimeoutMs: 0, responseTimeoutMs: 500 }
    );
    engine.setWsAutoUpgrade(server.sid, true);
    const holders = [];
    try {
      const before = budget();
      const open = async () => {
        const c = await connect(server.port);
        const n = opened.length;
        c.socket.write(
          `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}` +
            `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`
        );
        await waitFor(() => opened.length > n, 'a socket is open');
        c.id = opened[n];
        return c;
      };
      const whole = frame(0x2, true, Buffer.alloc(12 * KiB, 0x64));
      // One has sent a message of 12 KiB, in two pieces, and is quiet: the
      // buffer the message was put together in keeps its storage.
      const quiet = await open();
      quiet.socket.write(whole.subarray(0, 5 * KiB));
      await delay(30);
      quiet.socket.write(whole.subarray(5 * KiB));
      await waitFor(() => messages.length === 1, 'the message is delivered');
      assert.equal(messages[0], 12 * KiB);
      // The other has sent 8 of the 12 KiB of one, and no more.
      const stopped = await open();
      stopped.socket.write(whole.subarray(0, 8 * KiB));
      // Requests their handlers keep, until less than an eighth of the
      // share is left.
      await holdRequests(server, () => heldReqs, () => budget().held > MiB - MiB / 8 + 16 * KiB, 100 * KiB, holders);
      await waitFor(() => closes.has(stopped.id), 'the socket that stopped in the middle of a message is closed at the sweep');
      assert.equal(closes.get(stopped.id), 1006);
      await delay(1200); // four sweeps and more
      assert.ok(budget().held > MiB - MiB / 8, `the thread was short throughout: ${JSON.stringify(budget())}`);
      assert.equal(closes.has(quiet.id), false, `the quiet socket was closed (${closes.get(quiet.id)})`);
      assert.equal(quiet.closed, false);
      assert.equal(budget().evicted, before.evicted + 1);
      assert.equal(budget().shed, before.shed);
      quiet.socket.destroy();
      stopped.socket.destroy();
    } finally {
      for (const h of holders) h.socket.destroy();
      server.close();
    }
  });
});
