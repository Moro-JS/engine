// The socket budget (1.2.5, Linux): what the kernel queues for a thread's
// connections to read is bounded with them. While the connections fit with
// the receive buffer the system gives a socket, no socket is touched; past
// that, each one's buffer is set to its part of the budget (twice the
// thread's buffer budget), smaller as more arrive and never below 16 KiB, and
// raised again at the sweep when the crowd has gone.
//
// probe().bufferBudget reports the thread's connections, its socket budget,
// the buffer a connection may have now and how often a socket's buffer was
// set, which is what these tests watch - together with requests and bodies
// going through sockets whose buffers have been made small.
import { describe, it } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';
import engine from '../packages/engine/index.mjs';

const CRLF = '\r\n';
const KiB = 1024;
const MiB = 1024 * KiB;
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const budget = () => engine.probe().bufferBudget;

const skip = engine.probe().capabilities?.socketBudget ? false : 'the socket budget is Linux\'s';

// The receive buffer the system gives a socket (tcp_rmem's middle figure),
// and the buffer `conns` connections may have in a budget of `sockets`.
const systemBuffer = skip ? 0 : Number(fs.readFileSync('/proc/sys/net/ipv4/tcp_rmem', 'utf8').trim().split(/\s+/)[1]);
function expected(sockets, conns) {
  if (conns <= Math.floor(sockets / systemBuffer)) return 0;
  const each = Math.floor(sockets / conns);
  let size = 16 * KiB;
  while (size < 128 * KiB && size * 2 <= each) size *= 2;
  return size;
}

async function waitFor(predicate, message, timeout = 5000) {
  const end = Date.now() + timeout;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > end) assert.fail(`${message} (bufferBudget: ${JSON.stringify(budget())})`);
    await delay(10);
  }
}

function connect(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1');
    const c = { socket: s, received: Buffer.alloc(0), closed: false };
    s.on('data', (d) => (c.received = Buffer.concat([c.received, d])));
    s.on('error', () => {});
    s.on('close', () => (c.closed = true));
    s.once('error', reject);
    s.once('connect', () => resolve(c));
  });
}
const open = (port, n) => Promise.all(Array.from({ length: n }, () => connect(port)));

// Answers every request with the SHA-256 of its body and the body's length.
function serve(options) {
  const sid = engine.serve(
    {
      onRequest(reqId) {
        const raw = engine.getBody(reqId);
        const body = raw ? Buffer.from(raw) : Buffer.alloc(0);
        engine.respond(reqId, 200, null, `${body.length} ${crypto.createHash('sha256').update(body).digest('hex')}`);
      },
      onAborted() {},
    },
    // A sweep every 250 ms, and no timeout that closes an idle connection.
    { idleTimeoutMs: 0, requestTimeoutMs: 0, responseTimeoutMs: 500, maxBodySize: 4 * MiB, ...options }
  );
  return { sid, port: engine.listen(sid, '127.0.0.1', 0) };
}

async function post(c, body) {
  const before = c.received.length;
  c.socket.write(`POST /sum HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}`);
  c.socket.write(body);
  await waitFor(() => c.received.subarray(before).includes('\r\n\r\n') && /\d+ [0-9a-f]{64}$/.test(c.received.toString('latin1')), 'the upload is answered', 20000);
  return c.received.subarray(before).toString('latin1').split('\r\n\r\n')[1];
}

describe('socket budget', { skip }, () => {
  it('a server whose connections fit leaves every socket to the system', async () => {
    const server = serve({ memoryBudget: 64 * MiB });
    try {
      const before = budget();
      assert.equal(before.sockets, 128 * MiB, 'twice the buffer budget');
      const clients = await open(server.port, 40);
      await waitFor(() => budget().connections === 40, 'the connections are counted');
      assert.equal(budget().receiveBuffer, 0);
      await delay(600);  // two sweeps
      assert.equal(budget().resized, before.resized, 'no socket was touched');
      for (const c of clients) c.socket.destroy();
      await waitFor(() => budget().connections === 0, 'the count goes down with them');
    } finally {
      engine.close(server.sid);
    }
  });

  it('past what fits, every connection has its part of the budget, down to 16 KiB', async () => {
    const server = serve({ memoryBudget: MiB });
    try {
      const { sockets, resized } = budget();
      assert.equal(sockets, 2 * MiB);
      const clients = [];
      for (const total of [64, 140, 200]) {
        clients.push(...(await open(server.port, total - clients.length)));
        await waitFor(() => budget().connections === total, `${total} connections are counted`);
        assert.equal(budget().receiveBuffer, expected(sockets, total), `the buffer of each of ${total}`);
      }
      assert.equal(budget().receiveBuffer, 16 * KiB, 'never below 16 KiB');
      assert.ok(budget().resized - resized >= 200, 'every socket was set, the ones open before the crowd too');
      for (const c of clients) c.socket.destroy();
      await waitFor(() => budget().connections === 0, 'the connections are gone');
    } finally {
      engine.close(server.sid);
    }
  });

  it('requests and large bodies go through sockets with small buffers unchanged', { timeout: 60000 }, async () => {
    const server = serve({ memoryBudget: MiB });
    try {
      const clients = await open(server.port, 160);
      await waitFor(() => budget().connections === 160, 'the connections are counted');
      assert.equal(budget().receiveBuffer, 16 * KiB);
      // Larger than the buffers, so they arrive a buffer at a time: on the
      // loopback interface that is five buffers a second, a few seconds here.
      const bodies = Array.from({ length: 8 }, (_, i) => crypto.randomBytes(150 * KiB + i * 1000));
      const answers = await Promise.all(bodies.map((b, i) => post(clients[i * 20], b)));
      answers.forEach((a, i) => {
        assert.equal(a, `${bodies[i].length} ${crypto.createHash('sha256').update(bodies[i]).digest('hex')}`);
      });
      // And a second request on the same connections.
      assert.equal(await post(clients[0], Buffer.from('again')), `5 ${crypto.createHash('sha256').update('again').digest('hex')}`);
      for (const c of clients) c.socket.destroy();
      await waitFor(() => budget().connections === 0, 'the connections are gone');
    } finally {
      engine.close(server.sid);
    }
  });

  it('when the crowd has gone, the buffers that were set are raised once and then left alone', async () => {
    const server = serve({ memoryBudget: MiB });
    try {
      const clients = await open(server.port, 160);
      await waitFor(() => budget().connections === 160, 'the connections are counted');
      const staying = clients.slice(0, 4);
      for (const c of clients.slice(4)) c.socket.destroy();
      await waitFor(() => budget().connections === 4, 'four are left');
      assert.equal(budget().receiveBuffer, 0, 'four connections fit');
      const before = budget().resized;
      await waitFor(() => budget().resized === before + 4, 'the four are raised at the sweep');
      await delay(800);  // three more sweeps
      assert.equal(budget().resized, before + 4, 'and not set again');
      assert.equal(await post(staying[0], Buffer.alloc(300 * KiB, 7)), `${300 * KiB} ${crypto.createHash('sha256').update(Buffer.alloc(300 * KiB, 7)).digest('hex')}`);
      for (const c of staying) c.socket.destroy();
      await waitFor(() => budget().connections === 0, 'the connections are gone');
    } finally {
      engine.close(server.sid);
    }
  });

  it('a count that moves about a boundary does not set every socket at every sweep', async () => {
    const server = serve({ memoryBudget: MiB });
    try {
      const sockets = budget().sockets;
      // 2 MiB over 64 connections is 32 KiB each; over 60 it is still 32 KiB,
      // over 70 it is 16 KiB.
      const clients = await open(server.port, 70);
      await waitFor(() => budget().connections === 70, 'the connections are counted');
      assert.equal(budget().receiveBuffer, expected(sockets, 70));
      for (const c of clients.splice(60)) c.socket.destroy();
      await waitFor(() => budget().connections === 60, 'ten have gone');
      assert.equal(budget().receiveBuffer, expected(sockets, 60));
      assert.ok(expected(sockets, 60) > expected(sockets, 70), 'the boundary is between them');
      await delay(600);
      const settled = budget().resized;
      await delay(800);
      assert.equal(budget().resized, settled, 'one step of room is not a reason to set a socket again');
      for (const c of clients) c.socket.destroy();
      await waitFor(() => budget().connections === 0, 'the connections are gone');
    } finally {
      engine.close(server.sid);
    }
  });

  it('the servers of a thread share one count', async () => {
    const a = serve({ memoryBudget: 4 * MiB });
    const b = serve({ memoryBudget: 4 * MiB });
    try {
      const sockets = budget().sockets;
      assert.equal(sockets, 8 * MiB);
      const half = Math.floor(sockets / systemBuffer / 2) + 8;  // neither server is crowded alone
      const clients = [...(await open(a.port, half)), ...(await open(b.port, half))];
      await waitFor(() => budget().connections === 2 * half, 'both servers\' connections are counted');
      assert.equal(budget().receiveBuffer, expected(sockets, 2 * half));
      assert.notEqual(budget().receiveBuffer, 0);
      for (const c of clients) c.socket.destroy();
      await waitFor(() => budget().connections === 0, 'the connections are gone');
    } finally {
      engine.close(a.sid);
      engine.close(b.sid);
    }
  });

  it('memoryBudget: Infinity is no socket budget either', async () => {
    const server = serve({ memoryBudget: Infinity });
    try {
      const before = budget();
      assert.equal(before.sockets, Infinity);
      const clients = await open(server.port, 200);
      await waitFor(() => budget().connections === 200, 'the connections are counted');
      assert.equal(budget().receiveBuffer, 0);
      await delay(600);
      assert.equal(budget().resized, before.resized);
      for (const c of clients) c.socket.destroy();
      await waitFor(() => budget().connections === 0, 'the connections are gone');
    } finally {
      engine.close(server.sid);
    }
  });
});
