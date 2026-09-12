// Connection-churn soak for @morojs/engine: the-benchmarker's shape (one
// request per connection, Connection: close) at concurrency 256, plus a
// slice of clients that abort mid-request and a slice that never read
// their response (shed by responseTimeoutMs). The engine runs in a CHILD
// process (test/soak/churn-server.mjs) so the parent's client sockets and
// their garbage never enter the measurement. Checks what a leak or a
// lifetime bug would show:
//   - every completed response is byte-correct
//   - onAborted fired once for every aborted/shed request (no more, no less)
//   - the server's fd count returns to its baseline (Linux: /proc/self/fd)
//   - the server's RSS is steady across full passes: three passes, and pass
//     3 adds < 16 MiB over pass 2 (the first pass absorbs allocator warm-up;
//     a real per-connection leak keeps growing pass after pass)
//
//   node test/soak/churn.mjs [--connections=N] [--concurrency=C]
//   (SOAK_CONNECTIONS env also honoured; CI 20000, nightly 100000)
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const args = Object.fromEntries(process.argv.slice(2).map(a => { const [k, v] = a.replace(/^--/, '').split('='); return [k, v ?? true]; }));
const TOTAL = parseInt(args.connections || process.env.SOAK_CONNECTIONS || '20000', 10);
const CONC = parseInt(args.concurrency || '256', 10);
const ABORT_EVERY = 10;   // 10% abort mid-request
const NOREAD_EVERY = 20;  // 5% never read (shed by responseTimeoutMs)
const BODY = 'soak-' + 'x'.repeat(200);
const SERVER = fileURLToPath(new URL('./churn-server.mjs', import.meta.url));

// ---- server child ----
const child = spawn(process.execPath, ['--expose-gc', SERVER], { stdio: ['pipe', 'pipe', 'inherit'], env: process.env });
const port = await new Promise((resolve, reject) => {
  let out = '';
  child.stdout.on('data', (d) => {
    out += d;
    const m = /PORT (\d+)/.exec(out);
    if (m) resolve(parseInt(m[1], 10));
    if (/ERROR/.test(out)) reject(new Error(out.trim()));
  });
  child.on('exit', (c) => reject(new Error(`server exited ${c}`)));
});
const stop = () => { try { child.stdin.write('exit\n'); } catch {} setTimeout(() => child.kill('SIGKILL'), 2000).unref(); };

function stats() {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => s.write('GET /__stats HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n'));
    let b = '';
    s.on('data', (d) => (b += d));
    s.on('close', () => { const he = b.indexOf('\r\n\r\n'); try { resolve(JSON.parse(b.slice(he + 4))); } catch (e) { reject(new Error('bad stats: ' + b)); } });
    s.on('error', reject);
    s.setTimeout(5000, () => { s.destroy(); reject(new Error('stats timeout')); });
  });
}

const base = await stats();
console.log(`churn soak: 3 x ${TOTAL} connections, concurrency ${CONC}, transport ${base.transport}, server pid ${child.pid}`);

let ok = 0, bad = 0, expectAborted = 0, done = 0, inflight = 0, next = 0;

function one(i) {
  return new Promise((resolve) => {
    const kind = i % ABORT_EVERY === 0 ? 'abort' : i % NOREAD_EVERY === 0 ? 'noread' : 'normal';
    const path = kind === 'abort' ? '/slow' : kind === 'noread' ? '/big' : '/';
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(`GET ${path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n`);
      if (kind === 'abort') { expectAborted++; setTimeout(() => sock.destroy(), 2); }
      if (kind === 'noread') { expectAborted++; sock.pause(); }  // never reads; the engine sheds it
    });
    let buf = '';
    sock.on('data', d => { if (kind !== 'noread') buf += d.toString('latin1'); });
    const finish = () => {
      if (kind === 'normal') {
        const he = buf.indexOf('\r\n\r\n');
        const body = he >= 0 ? buf.slice(he + 4) : '';
        if (buf.startsWith('HTTP/1.1 200') && body === BODY) ok++; else bad++;
      }
      resolve();
    };
    sock.on('close', finish);
    sock.on('error', () => {});
    sock.setTimeout(5000, () => sock.destroy());
  });
}

function pass() {
  done = 0; inflight = 0; next = 0;
  return new Promise((resolve) => {
    const pump = () => {
      while (inflight < CONC && next < TOTAL) {
        const i = next++;
        inflight++;
        one(i).then(() => {
          inflight--; done++;
          if (done === TOTAL) resolve(); else pump();
        });
      }
    };
    pump();
  });
}
const settle = () => new Promise(r => setTimeout(r, 1500)); // sheds (responseTimeoutMs=500) + closes drain

const t0 = Date.now();
await pass();  // warm-up
await settle();
const s1 = await stats();
await pass();
await settle();
const s2 = await stats();
await pass();
const secs = (Date.now() - t0) / 1000 - 3;
await settle();
const s3 = await stats();
stop();

const mb = (b) => Math.round(b / 1048576);
console.log(`3 x ${TOTAL} connections in ${secs.toFixed(1)}s (${Math.round(3 * TOTAL / secs)} conn/s): ok=${ok} bad=${bad} served=${s3.served} aborted=${s3.aborted} expectedAborted~${expectAborted} server rss after passes ${mb(s1.rss)} / ${mb(s2.rss)} / ${mb(s3.rss)} MB; server fds ${base.fds}->${s1.fds}->${s3.fds}`);
let failed = false;
const fail = (m) => { console.error('FAIL: ' + m); failed = true; };
if (bad > 0) fail(`${bad} malformed responses`);
if (ok === 0) fail('no successful responses');
// Aborts: each aborting/non-reading client should produce exactly one onAborted
// (an abort racing the response may complete instead - allow 10% slack).
if (s3.aborted > expectAborted) fail(`more onAborted (${s3.aborted}) than aborting clients (${expectAborted})`);
if (s3.aborted < expectAborted * 0.9) fail(`too few onAborted (${s3.aborted} of ${expectAborted})`);
if (mb(s3.rss) - mb(s2.rss) > 16) fail(`server RSS grew ${mb(s3.rss) - mb(s2.rss)} MB from pass 2 to pass 3 (steady state expected)`);
if (base.fds >= 0 && s3.fds > base.fds + 8) fail(`server fd leak: ${base.fds} -> ${s3.fds}`);
process.exit(failed ? 1 : 0);
