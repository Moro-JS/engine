// Transport selection diagnostics for @morojs/engine.
//
//   - probe().transport is 'uv' or 'uring', with a non-empty transportReason
//   - io_uring is OPT-IN (MORO_ENGINE_TRANSPORT=uring): without the variable
//     a Linux host reports 'uv' with an "opt-in" reason; with it, 'uring' when
//     the probe passes or the failing step (EPERM / ENOSYS / EINVAL / a
//     self-test stage) when it does not
//   - MORO_ENGINE_TRANSPORT=uv in a child forces 'uv' with that reason
//   - off Linux the reason is 'platform'
//   - the transport never changes what a request sees (one round trip)
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine ? false : '@morojs/engine native binding not usable yet — transport suite skipped';
const T = { timeout: 30000 };
const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;

describe('transport selection', { skip }, () => {
  it('probe() reports the transport and a reason', T, () => {
    const p = engine.probe();
    assert.ok(p.transport === 'uv' || p.transport === 'uring', `transport: ${p.transport}`);
    assert.equal(typeof p.transportReason, 'string');
    assert.ok(p.transportReason.length > 0);
    if (p.transport === 'uring') assert.equal(p.transportReason, 'ok');
    if (process.platform !== 'linux') {
      assert.equal(p.transport, 'uv');
      assert.equal(p.transportReason, 'platform');
    } else if (process.env.MORO_ENGINE_TRANSPORT !== 'uring') {
      assert.equal(p.transport, 'uv');
      assert.match(p.transportReason, /opt-in|MORO_ENGINE_TRANSPORT=uv/);
    }
    console.log(`transport: ${p.transport} (${p.transportReason})`);
  });

  it('without MORO_ENGINE_TRANSPORT a Linux host stays on libuv (opt-in)', T, () => {
    const script = `
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const p = engine.probe();
      console.log(JSON.stringify({ transport: p.transport, reason: p.transportReason }));
    `;
    const env = { ...process.env, MORO_ENGINE_REQUIRE_TRANSPORT: '' };
    delete env.MORO_ENGINE_TRANSPORT;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.transport, 'uv');
    if (process.platform === 'linux') assert.match(out.reason, /opt-in/);
  });

  it('MORO_ENGINE_TRANSPORT=uv forces libuv', T, () => {
    const script = `
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const p = engine.probe();
      console.log(JSON.stringify({ transport: p.transport, reason: p.transportReason }));
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      env: { ...process.env, MORO_ENGINE_TRANSPORT: 'uv', MORO_ENGINE_REQUIRE_TRANSPORT: '' },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim());
    assert.equal(out.transport, 'uv');
    if (process.platform === 'linux') assert.equal(out.reason, 'MORO_ENGINE_TRANSPORT=uv');
  });

  it('serves one request on whichever transport is active', T, async () => {
    const sid = engine.serve({
      onRequest(reqId) {
        engine.respond(reqId, 200, ['content-type', 'text/plain'], `via ${engine.probe().transport}`);
      },
      onAborted() {},
    });
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const raw = await new Promise((resolve, reject) => {
        const s = net.connect(port, '127.0.0.1', () => s.write('GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n'));
        let b = '';
        s.on('data', (d) => (b += d));
        s.on('end', () => resolve(b));
        s.on('error', reject);
        s.setTimeout(5000, () => reject(new Error('timeout')));
      });
      assert.match(raw, /^HTTP\/1\.1 200/);
      assert.ok(raw.endsWith(`via ${engine.probe().transport}`), raw);
    } finally {
      engine.close(sid);
    }
  });
});
