// V8 fast API calls for @morojs/engine.
//
// The hot entry points carry a fast-call target (src/fast_api.h). This suite
// proves, on whatever ABI it runs, that (1) the targets are installed, (2) an
// optimised caller actually takes the fast path (hit counters exposed by
// probe().fastCallStats under MORO_ENGINE_FASTCALL_STATS=1), (3) arguments a
// fast target cannot take (a Buffer, a cons string) fall back to the regular
// callback, and (4) the bytes on the wire are identical whichever path ran.
//
// Optimisation is forced with V8 natives syntax, enabled at runtime through
// v8.setFlagsFromString so `node --test` needs no flags: code containing
// %OptimizeFunctionOnNextCall is compiled AFTER the flag flips (new Function).
//
// Run with: node --test

// Must be set before the addon loads (helpers' loadEngine imports lazily).
process.env.MORO_ENGINE_FASTCALL_STATS = '1';

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import v8 from 'node:v8';
import { spawnSync } from 'node:child_process';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const info = engine ? engine.probe() : null;
const skip = !engine
  ? '@morojs/engine native binding not usable yet — fast-api suite skipped'
  : !info.fastApi?.compiled
    ? 'engine built without fast API targets (--no-fast-api) — fast-api suite skipped'
    : false;

const T = { timeout: 60000 };
// Under a kill switch (MORO_ENGINE_FASTCALL=0, MORO_ENGINE_NOTIFY=sync) the
// plain callbacks are installed instead: the fast-path assertions are skipped
// with the reason, and the install test checks the reason matches the env.
const fastOn = !!info?.fastApi?.installed;
const TF = { ...T, skip: fastOn ? false : `fast calls not installed (${info?.fastApi?.reason}) - fast-path assertions skipped` };
const CRLF = '\r\n';
const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;

v8.setFlagsFromString('--allow-natives-syntax');
// Build `hot` inside a natives-enabled function so the native call sites see a
// CONSTANT callee (a module-scope const captured by a closure), which is what
// lets the optimiser dispatch to the fast target.
const makeOptimised = (paramNames, body) =>
  new Function(
    ...paramNames,
    `
    ${body}
    %PrepareFunctionForOptimization(hot);
    return hot;
  `
  );
const optimise = new Function('f', '%OptimizeFunctionOnNextCall(f);');

const stats = () => engine.probe().fastCallStats;

function exchange(port, requestBytes) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(requestBytes, 'latin1'));
    let buf = '';
    sock.on('data', (d) => (buf += d.toString('latin1')));
    sock.on('end', () => resolve(buf));
    sock.on('close', () => resolve(buf));
    sock.on('error', reject);
    sock.setTimeout(8000, () => reject(new Error('timeout')));
  });
}
const req = (path) => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`;
const stripDate = (s) => s.replace(/^date: [^\r\n]*\r\n/gim, '');

describe('V8 fast API calls', { skip }, () => {
  it('fast targets are installed on this ABI (or the kill switch in force is reported)', T, () => {
    if (process.env.MORO_ENGINE_FASTCALL === '0') {
      assert.equal(info.fastApi.installed, false);
      assert.equal(info.fastApi.reason, 'env-disabled');
      assert.equal(info.capabilities.fastCalls, false);
      return;
    }
    if (process.env.MORO_ENGINE_NOTIFY === 'sync') {
      assert.equal(info.fastApi.installed, false);
      assert.equal(info.fastApi.reason, 'sync-notify');
      assert.equal(info.capabilities.fastCalls, false);
      return;
    }
    assert.equal(info.fastApi.installed, true, `not installed: ${info.fastApi.reason}`);
    assert.equal(info.fastApi.reason, 'ok');
    assert.equal(info.capabilities.fastCalls, true);
    assert.equal(info.fastApi.compiledV8, info.fastApi.runtimeV8);
    assert.ok(stats(), 'fastCallStats present under MORO_ENGINE_FASTCALL_STATS=1');
    for (const fn of ['respondPrepared', 'respondPreparedEmpty', 'writeHeadPrepared', 'write', 'end', 'endWith', 'isAborted']) {
      assert.ok(stats()[fn], `stats for ${fn}`);
    }
  });

  it('an optimised caller takes the fast path for isAborted()', TF, () => {
    const before = stats().isAborted;
    const hot = makeOptimised(
      ['isAborted'],
      `function hot(reqId) { return isAborted(reqId); }`
    )(engine.isAborted);
    hot(1);
    hot(2);
    optimise(hot);
    for (let i = 0; i < 50; i++) assert.equal(hot(1000 + i), true, 'an unknown reqId is aborted');
    const after = stats().isAborted;
    assert.ok(after.fast > before.fast, `fast hits did not increase: ${JSON.stringify({ before, after })}`);
  });

  it('respondPrepared: a sequential one-byte body goes fast; Buffer and cons bodies go slow; bytes identical', TF, async () => {
    const respondPrepared = engine.respondPrepared;
    let tpl = 0;
    const hot = makeOptimised(
      ['respondPrepared'],
      `function hot(reqId, tplId, body) { respondPrepared(reqId, tplId, body); }`
    )(respondPrepared);
    const asciiBody = '{"hello":"world"}';
    const latin1Body = 'café crème'; // one-byte string with bytes >= 0x80
    const consBody = 'x'.repeat(20) + 'y'.repeat(20); // ConsString: not sequential
    const bufferBody = Buffer.from(latin1Body, 'utf8');
    let served = 0;
    const sid = engine.serve({
      onRequest(reqId, _m, path) {
        served++;
        if (path === '/ascii') hot(reqId, tpl, asciiBody);
        else if (path === '/latin1') hot(reqId, tpl, latin1Body);
        else if (path === '/cons') hot(reqId, tpl, consBody);
        else if (path === '/buffer') hot(reqId, tpl, bufferBody);
        else if (path === '/latin1-slow') engine.respond(reqId, 200, ['content-type', 'text/plain'], latin1Body);
        else if (path === '/cons-slow') engine.respond(reqId, 200, ['content-type', 'text/plain'], consBody);
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      tpl = engine.prepareResponse(sid, 200, ['content-type', 'text/plain']);
      // Warm the call site through real requests, then force optimisation.
      await exchange(port, req('/ascii'));
      await exchange(port, req('/ascii'));
      optimise(hot);
      const before = stats().respondPrepared;
      const ascii = await exchange(port, req('/ascii'));
      const afterAscii = stats().respondPrepared;
      assert.ok(afterAscii.fast > before.fast, `ascii body must take the fast path: ${JSON.stringify({ before, afterAscii })}`);
      assert.ok(ascii.endsWith(asciiBody), ascii);

      const latin1 = await exchange(port, req('/latin1'));
      const afterLatin1 = stats().respondPrepared;
      assert.ok(afterLatin1.fast > afterAscii.fast, 'a Latin-1 one-byte body still takes the fast path');
      const latin1Slow = await exchange(port, req('/latin1-slow'));
      assert.equal(stripDate(latin1), stripDate(latin1Slow), 'Latin-1 bytes: fast path == respond()');
      assert.ok(latin1.endsWith(Buffer.from(latin1Body, 'utf8').toString('latin1')), 'UTF-8 encoded on the wire');

      const slowBefore = stats().respondPrepared.slow;
      const cons = await exchange(port, req('/cons'));
      const buf = await exchange(port, req('/buffer'));
      const slowAfter = stats().respondPrepared.slow;
      assert.ok(slowAfter >= slowBefore + 1, `cons/Buffer bodies must use the regular callback: ${JSON.stringify(stats().respondPrepared)}`);
      const consSlow = await exchange(port, req('/cons-slow'));
      assert.equal(stripDate(cons), stripDate(consSlow), 'cons string bytes: prepared == respond()');
      assert.equal(stripDate(buf), stripDate(latin1Slow), 'Buffer body bytes == string body bytes');
      assert.equal(served, 8);
    } finally {
      engine.close(sid);
    }
  });

  it('write / end / endWith / respondPreparedEmpty / writeHeadPrepared take the fast path when optimised', TF, async () => {
    const { write, end, endWith, respondPreparedEmpty, writeHeadPrepared } = engine;
    let tpl = 0;
    const hotStream = makeOptimised(
      ['writeHeadPrepared', 'write', 'endWith'],
      `function hot(reqId, tplId) { writeHeadPrepared(reqId, tplId); write(reqId, 'ab'); write(reqId, 'cd'); endWith(reqId, 'ef'); }`
    )(writeHeadPrepared, write, endWith);
    const hotEnd = makeOptimised(
      ['writeHeadPrepared', 'end'],
      `function hot(reqId, tplId) { writeHeadPrepared(reqId, tplId); end(reqId); }`
    )(writeHeadPrepared, end);
    const hotEmpty = makeOptimised(
      ['respondPreparedEmpty'],
      `function hot(reqId, tplId) { respondPreparedEmpty(reqId, tplId); }`
    )(respondPreparedEmpty);
    const sid = engine.serve({
      onRequest(reqId, _m, path) {
        if (path === '/stream') hotStream(reqId, tpl);
        else if (path === '/end') hotEnd(reqId, tpl);
        else if (path === '/empty') hotEmpty(reqId, tpl);
        else if (path === '/stream-slow') {
          engine.writeHead(reqId, 200, ['content-type', 'text/plain']);
          engine.write(reqId, 'ab');
          engine.write(reqId, 'cd');
          engine.end(reqId, 'ef');
        }
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      tpl = engine.prepareResponse(sid, 200, ['content-type', 'text/plain']);
      for (const p of ['/stream', '/end', '/empty']) {
        await exchange(port, req(p));
        await exchange(port, req(p));
      }
      optimise(hotStream);
      optimise(hotEnd);
      optimise(hotEmpty);
      const before = stats();
      const stream = await exchange(port, req('/stream'));
      await exchange(port, req('/end'));
      await exchange(port, req('/empty'));
      const after = stats();
      for (const fn of ['writeHeadPrepared', 'write', 'endWith', 'end', 'respondPreparedEmpty']) {
        assert.ok(after[fn].fast > before[fn].fast, `${fn} fast hits: ${JSON.stringify({ b: before[fn], a: after[fn] })}`);
      }
      const slow = await exchange(port, req('/stream-slow'));
      assert.equal(stripDate(stream), stripDate(slow), 'streamed bytes: fast path == regular path');
    } finally {
      engine.close(sid);
    }
  });

  it('kill switches: MORO_ENGINE_FASTCALL=0 and MORO_ENGINE_NOTIFY=sync leave plain callbacks; stats absent without the env', T, () => {
    const script = `
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const p = engine.probe();
      console.log(JSON.stringify({ installed: p.fastApi.installed, reason: p.fastApi.reason, cap: p.capabilities.fastCalls, hasStats: p.fastCallStats !== undefined }));
    `;
    const run = (env) => {
      const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
        env: { ...process.env, MORO_ENGINE_FASTCALL_STATS: '', MORO_ENGINE_FASTCALL: '', MORO_ENGINE_NOTIFY: '', ...env },
        encoding: 'utf8',
      });
      assert.equal(r.status, 0, r.stderr);
      return JSON.parse(r.stdout.trim());
    };
    assert.deepEqual(run({}), { installed: true, reason: 'ok', cap: true, hasStats: false });
    assert.deepEqual(run({ MORO_ENGINE_FASTCALL: '0' }), { installed: false, reason: 'env-disabled', cap: false, hasStats: false });
    assert.deepEqual(run({ MORO_ENGINE_NOTIFY: 'sync' }), { installed: false, reason: 'sync-notify', cap: false, hasStats: false });
    assert.equal(run({ MORO_ENGINE_FASTCALL_STATS: '1' }).hasStats, true);
  });
});
