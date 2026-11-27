// A loop turn has a time slice (the epoll transport, 1.2.4): when the sockets
// that are ready ask for more work than fits in it, the turn ends there, the
// loop goes round to its timers and its poll, and the sockets not yet served
// wait their turn - the ones that have just arrived ahead of the ones that
// were served a moment ago, and none of them timed out for the time it
// waits. probe().turns counts the turns that were cut and the sockets
// waiting.
//
// The handlers here are slow on purpose (a busy wait): what is tested is what
// the loop does when its work does not fit, and that needs work that does
// not fit.
import { describe, it } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import http2 from 'node:http2';
import engine from '../packages/engine/index.mjs';

const CRLF = '\r\n';
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const turns = () => engine.probe().turns;

async function waitFor(predicate, message, timeout = 15000) {
  const end = Date.now() + timeout;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > end) assert.fail(`${message} (turns: ${JSON.stringify(turns())})`);
    await delay(5);
  }
}

function connect(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1');
    const c = { socket: s, received: '', answers: 0, at: 0, closed: false };
    s.setNoDelay(true);
    s.on('data', (d) => {
      c.received += d.toString('latin1');
      c.answers = c.received.split('HTTP/1.1 200').length - 1;
      c.at = performance.now();
    });
    s.on('close', () => (c.closed = true));
    s.on('error', () => {});
    s.once('error', reject);
    s.once('connect', () => resolve(c));
  });
}

const spin = (ms) => {
  const until = performance.now() + ms;
  while (performance.now() < until);
};
const get = (path) => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;

const probe = engine.probe();
const skip = probe.transport !== 'epoll' || !probe.turns ? 'the time slice is the epoll transport\'s' : false;

describe('time slice', { skip }, () => {
  it('a loop that keeps up never cuts a turn', async () => {
    const sid = engine.serve({
      onRequest(reqId) {
        engine.respond(reqId, 200, null, 'ok');
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const before = turns().cut;
      const clients = await Promise.all(Array.from({ length: 100 }, () => connect(port)));
      for (let round = 1; round <= 5; round++) {
        for (const c of clients) c.socket.write(get('/fast'));
        await waitFor(() => clients.every((c) => c.answers === round), `round ${round} is answered`);
      }
      assert.equal(turns().cut, before, 'no turn was cut');
      assert.equal(turns().waiting, 0);
      for (const c of clients) c.socket.destroy();
    } finally {
      engine.close(sid);
    }
  });

  it('a turn that does not fit is cut, timers run meanwhile, and every request is answered', async () => {
    const sid = engine.serve({
      onRequest(reqId) {
        spin(4);
        engine.respond(reqId, 200, null, 'slow');
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const before = turns().cut;
      const clients = await Promise.all(Array.from({ length: 150 }, () => connect(port)));
      // 150 requests of 4 ms: six tenths of a second of work, all of it ready
      // in one turn.
      const start = performance.now();
      for (const c of clients) c.socket.write(get('/slow'));
      // A timer due long before that work is done fires long before it is.
      let fired = 0;
      setTimeout(() => (fired = performance.now() - start), 100);
      let sawWaiting = 0;
      const watch = setInterval(() => (sawWaiting = Math.max(sawWaiting, turns().waiting)), 20);
      await waitFor(() => clients.every((c) => c.answers === 1), 'every request is answered');
      clearInterval(watch);
      const took = performance.now() - start;
      assert.ok(took >= 500, `the work took its time: ${took.toFixed(0)} ms`);
      assert.ok(turns().cut > before, 'turns were cut');
      assert.ok(sawWaiting > 0, 'sockets were seen waiting for a later turn');
      assert.ok(fired > 0 && fired < 350, `the 100 ms timer fired after ${fired.toFixed(0)} ms, not after the whole burst`);
      await waitFor(() => turns().waiting === 0, 'nothing is left waiting');
      for (const c of clients) c.socket.destroy();
    } finally {
      engine.close(sid);
    }
  });

  it('a connection that arrives while others wait is served ahead of them', async () => {
    const sid = engine.serve({
      onRequest(reqId, _method, path) {
        if (path === '/slow') spin(4);
        engine.respond(reqId, 200, null, path);
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const busy = await Promise.all(Array.from({ length: 200 }, () => connect(port)));
      const start = performance.now();
      // Three requests each, sent as the previous one is answered: the busy
      // sockets keep coming back for more.
      for (const c of busy) {
        c.socket.write(get('/slow'));
        c.socket.on('data', () => {
          if (c.answers < 3 && c.answers === c.sent) {
            c.sent++;
            c.socket.write(get('/slow'));
          }
        });
        c.sent = 1;
      }
      await waitFor(() => turns().waiting > 0, 'the loop is behind');
      const newcomer = await connect(port);
      const asked = performance.now();
      newcomer.socket.write(get('/quick'));
      await waitFor(() => newcomer.answers === 1, 'the newcomer is answered');
      const waited = performance.now() - asked;
      const busyDone = busy.filter((c) => c.answers === 3).length;
      assert.ok(busyDone < busy.length, 'the newcomer was answered while busy sockets still had work waiting');
      assert.ok(waited < 400, `the newcomer waited ${waited.toFixed(0)} ms (the burst is ${(200 * 3 * 4)} ms of work)`);
      await waitFor(() => busy.every((c) => c.answers === 3), 'every request of the busy sockets is answered', 30000);
      const total = performance.now() - start;
      assert.ok(total >= 2000, `the busy sockets' work took its time: ${total.toFixed(0)} ms`);
      await waitFor(() => turns().waiting === 0, 'nothing is left waiting');
      for (const c of [...busy, newcomer]) c.socket.destroy();
    } finally {
      engine.close(sid);
    }
  });

  it('a connection is not timed out for the time it waits for its turn', async () => {
    // An idle timeout of half a second, and 1.6 s of work that is all there
    // at once: the sockets at the end of it wait three times the timeout
    // with their request unread. The request was sent; it is the server that
    // has not looked.
    const sid = engine.serve(
      {
        onRequest(reqId) {
          spin(8);
          engine.respond(reqId, 200, null, 'slow');
        },
        onAborted() {},
      },
      { idleTimeoutMs: 500 }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const clients = await Promise.all(Array.from({ length: 200 }, () => connect(port)));
      const start = performance.now();
      for (const c of clients) c.socket.write(get('/slow'));
      await waitFor(() => clients.every((c) => c.answers === 1 || c.closed), 'every connection is answered or closed', 30000);
      const took = performance.now() - start;
      const dropped = clients.filter((c) => c.answers === 0).length;
      assert.equal(dropped, 0, `${dropped} of ${clients.length} connections were closed with their request unanswered`);
      assert.ok(took >= 1500, `the last of them waited well past the timeout: ${took.toFixed(0)} ms`);
      for (const c of clients) c.socket.destroy();
    } finally {
      engine.close(sid);
    }
  });

  it('a request whose last bytes are waiting for their turn is not timed out', async () => {
    const sid = engine.serve(
      {
        onRequest(reqId) {
          spin(8);
          engine.respond(reqId, 200, null, 'slow');
        },
        onAborted() {},
      },
      { idleTimeoutMs: 0, requestTimeoutMs: 500 }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const clients = await Promise.all(Array.from({ length: 200 }, () => connect(port)));
      // Most of a head, read at once (the loop is keeping up), and the rest
      // of it a moment later, from all of them together: 1.6 s of work, and
      // a request that has begun for every socket that waits.
      for (const c of clients) c.socket.write(`GET /slow HTTP/1.1${CRLF}Host: t${CRLF}`);
      await delay(80);
      assert.equal(turns().waiting, 0);
      for (const c of clients) c.socket.write(CRLF);
      await waitFor(() => clients.every((c) => c.received.length > 0 || c.closed), 'every request is answered or refused', 30000);
      const refused = clients.filter((c) => c.answers === 0);
      assert.equal(refused.length, 0, `${refused.length} of ${clients.length} requests were not answered; the first: ${JSON.stringify(refused[0]?.received.slice(0, 12))}`);
      for (const c of clients) c.socket.destroy();
    } finally {
      engine.close(sid);
    }
  });

  it('a body whose last bytes are waiting for their turn is not closed as one that has stopped arriving', async (t) => {
    if (!engine.probe().capabilities.bufferBudget) return t.skip('this engine build has no buffer budget');
    const KiB = 1024;
    const budget = () => engine.probe().bufferBudget;
    const kept = [];
    const sid = engine.serve(
      {
        onRequest(reqId, _method, path) {
          if (path === '/hold') return void kept.push(reqId);
          spin(8);
          engine.respond(reqId, 200, null, 'slow');
        },
        onAborted() {},
      },
      // A sweep every quarter of a second, and no timeout of its own that
      // could close a socket here.
      { memoryBudget: 8192 * KiB, maxBodySize: 256 * KiB, wsMaxMessageSize: 64 * KiB, idleTimeoutMs: 0, requestTimeoutMs: 0, responseTimeoutMs: 500 }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    const post = (path, declared, sent) => `POST ${path} HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${declared}${CRLF}${CRLF}` + 'x'.repeat(sent);
    const holders = [];
    try {
      assert.equal(budget().limit, 8192 * KiB);
      // The thread is brought to within an eighth of its share by requests
      // their handler keeps: from there on, at each sweep, a connection that
      // holds bytes and has moved none for a sweep interval is closed.
      while (budget().held < 7400 * KiB) {
        assert.ok(holders.length < 100, `the share fills: ${JSON.stringify(budget())}`);
        const c = await connect(port);
        holders.push(c);
        const was = kept.length;
        c.socket.write(post('/hold', 250 * KiB, 250 * KiB));
        await waitFor(() => kept.length > was || c.closed || c.received.length > 0, 'a request is kept by its handler, or refused');
      }
      const clients = await Promise.all(Array.from({ length: 120 }, () => connect(port)));
      const evicted = budget().evicted;
      // Five of the six kilobytes of a body, read at once; the last one a
      // moment later, from all of them together: a second of work.
      for (const c of clients) c.socket.write(post('/slow', 6 * KiB, 5 * KiB));
      await delay(80);
      assert.equal(turns().waiting, 0);
      for (const c of clients) c.socket.write('x'.repeat(KiB));
      await waitFor(() => clients.every((c) => c.received.length > 0 || c.closed), 'every request is answered or closed', 30000);
      const unanswered = clients.filter((c) => c.answers === 0).length;
      assert.equal(unanswered, 0, `${unanswered} of ${clients.length} requests were not answered`);
      assert.equal(budget().evicted, evicted, 'none was closed as a connection that had stopped moving');
      for (const c of clients) c.socket.destroy();
    } finally {
      for (const reqId of kept) {
        if (!engine.isAborted(reqId)) engine.respond(reqId, 200, null, 'kept');
      }
      for (const c of holders) c.socket.destroy();
      engine.close(sid);
    }
  });

  it('a request that arrives a byte at a time is still timed out while the loop is behind', async () => {
    // What a waiting socket is not charged for is the wait, and only that. A
    // peer that sends its request a byte at a time is given a turn for every
    // byte, and the time its request takes is its own.
    const sid = engine.serve(
      {
        onRequest(reqId) {
          spin(2);
          engine.respond(reqId, 200, null, 'slow');
        },
        onAborted() {},
      },
      { requestTimeoutMs: 500 }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      // A hundred sockets that ask again as soon as they are answered: 200 ms
      // of work a round, for as long as the test needs the loop behind.
      const busy = await Promise.all(Array.from({ length: 100 }, () => connect(port)));
      let asking = true;
      for (const c of busy) {
        c.socket.on('data', () => asking && c.socket.write(get('/slow')));
        c.socket.write(get('/slow'));
      }
      await waitFor(() => turns().waiting > 0, 'the loop is behind');
      const slow = await connect(port);
      const asked = performance.now();
      slow.socket.write('GET /drip HTTP/1.1\r\nHost: t\r\nX-Pad: ');
      const drip = setInterval(() => !slow.closed && slow.socket.write('a'), 5);
      let waitingThroughout = true;
      const watch = setInterval(() => (waitingThroughout = waitingThroughout && (slow.closed || turns().waiting > 0)), 20);
      try {
        await waitFor(() => slow.closed, 'the slow request is refused and its connection closed', 4000);
      } finally {
        clearInterval(drip);
        clearInterval(watch);
        asking = false;
      }
      const after = performance.now() - asked;
      assert.match(slow.received, /^HTTP\/1\.1 408 /, 'it is answered 408');
      assert.ok(after >= 500, `not before its budget: ${after.toFixed(0)} ms`);
      assert.ok(waitingThroughout, 'the loop was behind all the while');
      for (const c of busy) c.socket.destroy();
    } finally {
      engine.close(sid);
    }
  });

  it('a response its peer is taking is not cut short for the time its socket waits; one its peer is not taking is', async () => {
    // A response timeout of half a second, and a round over the sockets
    // that wait which is longer. Nothing pushes a waiting socket's queue, and
    // nothing reads the frame that opens an HTTP/2 window: a peer that takes
    // its response as fast as it comes must not look like one that has
    // stopped. One that has stopped is cut at the timeout all the same.
    const size = 24 * 1024 * 1024;
    const big = Buffer.alloc(size, 0x62);
    const medium = Buffer.alloc(160 * 1024, 0x63); // two and a half HTTP/2 windows
    const sid = engine.serve(
      {
        onRequest(reqId, _method, path) {
          if (path === '/big') return engine.respond(reqId, 200, null, big);
          if (path === '/medium') return engine.respond(reqId, 200, null, medium);
          spin(4);
          engine.respond(reqId, 200, null, 'slow');
        },
        onAborted() {},
      },
      { responseTimeoutMs: 500, http2: true }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    const download = (reads) =>
      new Promise((resolve) => {
        const s = net.connect(port, '127.0.0.1');
        const d = { socket: s, got: 0, closed: false };
        s.on('error', () => {});
        s.on('close', () => (d.closed = true));
        if (reads) s.on('data', (chunk) => (d.got += chunk.length));
        else s.pause();
        s.once('connect', () => {
          s.write(get('/big'));
          resolve(d);
        });
      });
    const busy = await Promise.all(Array.from({ length: 200 }, () => connect(port)));
    let session = null;
    let watch = null;
    try {
      // Two hundred sockets with four requests each, sent as the one before
      // is answered: 3.2 s of work, 0.8 s a round.
      for (const c of busy) {
        c.sent = 1;
        c.socket.on('data', () => {
          if (c.answers < 4 && c.answers === c.sent) {
            c.sent++;
            c.socket.write(get('/slow'));
          }
        });
        c.socket.write(get('/slow'));
      }
      await waitFor(() => turns().waiting > 0, 'the loop is behind');
      const reader = await download(true);
      session = http2.connect(`http://127.0.0.1:${port}`);
      session.on('error', () => {});
      const stream = { got: 0, done: false, failed: false };
      const req = session.request({ ':path': '/medium' });
      req.on('data', (chunk) => (stream.got += chunk.length));
      req.on('end', () => (stream.done = true));
      req.on('error', () => (stream.failed = true));
      req.end();
      // The peer that reads nothing: its socket is paused, so it is the
      // server's count of open connections that says when it was cut.
      const stopped = await download(false);
      const asked = performance.now();
      let cutAfter = 0;
      let behindThen = false;
      watch = setInterval(() => {
        if (cutAfter === 0 && engine.probe().connections.open === busy.length + 2) {
          cutAfter = performance.now() - asked;
          behindThen = turns().waiting > 0;
        }
      }, 10);
      await waitFor(() => (reader.got >= size || reader.closed) && (stream.done || stream.failed), 'both downloads end', 30000);
      assert.ok(reader.got >= size, `the HTTP/1.1 peer has all of its response (${reader.got} of ${size} bytes)`);
      assert.ok(stream.done && stream.got === medium.length, `the HTTP/2 peer has all of its response (${stream.got} of ${medium.length} bytes)`);
      await waitFor(() => cutAfter !== 0, 'the peer that reads nothing is closed', 5000);
      assert.ok(cutAfter >= 500 && cutAfter < 2000, `at its deadline: after ${cutAfter.toFixed(0)} ms`);
      assert.ok(behindThen, 'while the loop was still behind');
      reader.socket.destroy();
      stopped.socket.destroy();
    } finally {
      clearInterval(watch);
      if (session) session.destroy();
      engine.close(sid);
      for (const c of busy) c.socket.destroy();
    }
  });

  it('connections that keep arriving do not hold back the ones that were there before them', async () => {
    const cost = { '/work': 50, '/brief': 2 };
    const sid = engine.serve({
      onRequest(reqId, _method, path) {
        if (cost[path]) spin(cost[path]);
        engine.respond(reqId, 200, null, path);
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    const all = [];
    let flood = null;
    try {
      const burst = await Promise.all(Array.from({ length: 100 }, () => connect(port)));
      all.push(...burst);
      for (const c of burst) c.socket.write(get('/brief'));
      await waitFor(() => turns().waiting > 0, 'the loop is behind');
      // From here on two new connections whenever the loop comes round to
      // its timers, each with a slice's worth of work: twice what the loop
      // can do, so the queue of them only grows. And three clients with
      // nothing but a quick question, each of them connecting just ahead of
      // two of those.
      const early = [];
      let tick = 0;
      const arrive = (path) => {
        const s = net.connect(port, '127.0.0.1');
        const c = { socket: s, answers: 0, asked: performance.now(), waited: 0 };
        s.on('error', () => {});
        s.on('data', () => {
          if (c.answers++ === 0) c.waited = performance.now() - c.asked;
        });
        s.on('connect', () => s.write(get(path)));
        all.push(c);
        return c;
      };
      flood = setInterval(() => {
        if (tick % 4 === 2 && early.length < 3) early.push(arrive('/early'));
        arrive('/work');
        arrive('/work');
        tick++;
      }, 25);
      await waitFor(() => early.length === 3 && early.every((c) => c.answers > 0), 'the clients that came early are answered while newer connections keep arriving', 6000);
      const worst = Math.max(...early.map((c) => c.waited));
      assert.ok(worst < 2500, `the longest any of them waited: ${worst.toFixed(0)} ms`);
    } finally {
      clearInterval(flood);
      engine.close(sid);
      for (const c of all) c.socket.destroy();
    }
  });

  it('the newest is not kept behind all the others when a turn has time for many', async () => {
    const cost = { '/brief': 2 };
    const sid = engine.serve({
      onRequest(reqId, _method, path) {
        if (cost[path]) spin(cost[path]);
        engine.respond(reqId, 200, null, path);
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    const all = [];
    try {
      // Connected and quiet until they are needed.
      const others = await Promise.all(Array.from({ length: 300 }, () => connect(port)));
      const newest = await connect(port);
      const burst = await Promise.all(Array.from({ length: 100 }, () => connect(port)));
      all.push(...others, newest, ...burst);
      for (const c of burst) c.socket.write(get('/brief'));
      await waitFor(() => turns().waiting > 0, 'the loop is behind');
      // 600 ms of work in requests of 2 ms, and then one more socket.
      for (const c of others) c.socket.write(get('/brief'));
      await delay(1);
      const asked = performance.now();
      newest.socket.write(get('/newest'));
      await waitFor(() => newest.answers === 1, 'the newest is answered', 30000);
      const waited = performance.now() - asked;
      const othersDone = others.filter((c) => c.answers === 1).length;
      assert.ok(othersDone < 200, `the newest was answered after ${waited.toFixed(0)} ms, with ${othersDone} of the 300 before it answered`);
    } finally {
      engine.close(sid);
      for (const c of all) c.socket.destroy();
    }
  });

  it('a connection closed while it waits is forgotten, and the rest are served', async () => {
    const sid = engine.serve({
      onRequest(reqId) {
        spin(4);
        engine.respond(reqId, 200, null, 'slow');
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const clients = await Promise.all(Array.from({ length: 160 }, () => connect(port)));
      for (const c of clients) c.socket.write(get('/slow'));
      await waitFor(() => turns().waiting > 0, 'the loop is behind');
      // Half of them go away, and the server is told to close some itself.
      const leaving = clients.filter((_, i) => i % 2 === 1);
      for (const c of leaving) c.socket.destroy();
      const staying = clients.filter((_, i) => i % 2 === 0);
      await waitFor(() => staying.every((c) => c.answers === 1), 'the connections that stayed are answered', 30000);
      await waitFor(() => turns().waiting === 0, 'nothing is left waiting');
      await waitFor(() => engine.probe().connections.open === staying.length, 'the closed connections are gone');
      for (const c of staying) c.socket.destroy();
    } finally {
      engine.close(sid);
    }
  });

  it('closing the server while sockets wait leaves nothing behind', async () => {
    const sid = engine.serve({
      onRequest(reqId) {
        spin(4);
        engine.respond(reqId, 200, null, 'slow');
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    const clients = await Promise.all(Array.from({ length: 120 }, () => connect(port)));
    for (const c of clients) c.socket.write(get('/slow'));
    await waitFor(() => turns().waiting > 0, 'the loop is behind');
    engine.close(sid);
    await waitFor(() => turns().waiting === 0, 'the waiting sockets went with the server');
    await waitFor(() => engine.probe().connections.open === 0, 'no connection is left');
    for (const c of clients) c.socket.destroy();
    // The loop is not left spinning for sockets that are gone: a server
    // started now serves as usual.
    const again = engine.serve({
      onRequest(reqId) {
        engine.respond(reqId, 200, null, 'ok');
      },
      onAborted() {},
    });
    const port2 = engine.listen(again, '127.0.0.1', 0);
    try {
      const c = await connect(port2);
      c.socket.write(get('/after'));
      await waitFor(() => c.answers === 1, 'a new server answers');
      c.socket.destroy();
    } finally {
      engine.close(again);
    }
  });
});
