// Which TLS library the engine runs, and the notice about an old bundled one.
//
// Two binaries ship per platform and ABI: one carries BoringSSL, one links the
// OpenSSL of the running node. The loader picks one per thread, before the
// first probe()/serve():
//
//   - BoringSSL by default; probe().tls names the library, the pinned upstream
//     version and its date, and why this binary was loaded
//   - MORO_ENGINE_TLS=openssl|boringssl|auto ('node' = openssl) and selectTls()
//     choose by name; a wrong name is an error, never a silent default
//   - node's OpenSSL specially configured (OPENSSL_CONF, --openssl-* options,
//     FIPS) selects OpenSSL by itself; asking for BoringSSL by name overrides
//   - a BoringSSL binary that is absent falls back to the OpenSSL one with the
//     reason reported - unless BoringSSL was asked for by name
//   - selectTls() after the binding is loaded cannot swap it and throws
//   - both libraries terminate TLS and choose AES-128-GCM for a stock client
//   - a TLS configuration BoringSSL has no support for is served by OpenSSL
//     without being asked (at load when selectTls() is given the ssl options,
//     else at the first serve()); never when BoringSSL was named, and never
//     once the thread holds anything of the BoringSSL binary
//   - a bundled TLS library older than 180 days is announced once per process
//     (MORO_ENGINE_TLS_STALE), only by a server that terminates TLS, never on
//     OpenSSL, and not at all under MORO_ENGINE_TLS_AGE_WARNING=0
//
// Every case runs in a child process: the choice is made once per process.
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
const skip = engine ? false : '@morojs/engine native binding not usable yet — TLS library suite skipped';
const T = { timeout: 60000 };
const root = fileURLToPath(new URL('..', import.meta.url));
const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;
const FIXTURES = fileURLToPath(new URL('./fixtures/tls/', import.meta.url));
const PIN = JSON.parse(readFileSync(join(root, 'tools', 'boringssl.json'), 'utf8'));

// A clean slate for the child: nothing inherited that chooses a library or a binary.
function cleanEnv(extra = {}) {
  const env = { ...process.env, ...extra };
  for (const k of ['MORO_ENGINE_TLS', 'MORO_ENGINE_BINARY', 'MORO_ENGINE_REQUIRE_TLS', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'MORO_ENGINE_TLS_AGE_WARNING', 'NODE_OPTIONS']) {
    if (!(k in extra)) delete env[k];
  }
  return env;
}

// Run `body` (the text of an async function body; `engine` is in scope) in a
// child and return what it prints as JSON.
function child(body, { env = {}, args = [], entry = ENGINE_ENTRY } = {}) {
  const script = `
    const { default: engine } = await import(${JSON.stringify(entry)});
    const out = await (async () => { ${body} })();
    console.log('@@' + JSON.stringify(out ?? null));
  `;
  const r = spawnSync(process.execPath, [...args, '--input-type=module', '-e', script], { env: cleanEnv(env), encoding: 'utf8' });
  const line = r.stdout.split('\n').find((l) => l.startsWith('@@'));
  assert.ok(line, `child printed no result (exit ${r.status}):\n${r.stdout}\n${r.stderr}`);
  return { value: JSON.parse(line.slice(2)), stderr: r.stderr, status: r.status };
}

const probeTls = (opts) => child('const p = engine.probe(); return { ok: p.ok, tls: p.tls, error: p.error };', opts).value;

// Which binaries this checkout or install has: asked of the loader by name.
const has = (library) => probeTls({ env: { MORO_ENGINE_TLS: library } }).ok === true;
const haveBoring = engine ? has('boringssl') : false;
const haveOpenssl = engine ? has('openssl') : false;
const needBoring = haveBoring ? false : 'no BoringSSL binary in this build (tools/build.mjs --tls=openssl)';
const needBoth = haveBoring && haveOpenssl ? false : 'needs both binaries (tools/build.mjs builds both by default)';

describe('TLS library selection', { skip }, () => {
  it('probe().tls names the library, its version and why it was loaded', T, () => {
    const p = engine.probe();
    assert.ok(p.tls, 'probe().tls missing');
    assert.ok(['boringssl', 'openssl'].includes(p.tls.library), p.tls.library);
    assert.equal(typeof p.tls.version, 'string');
    assert.ok(p.tls.version.length > 0);
    assert.equal(typeof p.tls.reason, 'string');
    if (p.tls.library === 'boringssl') {
      assert.match(p.tls.version, /^0\.\d{8}\.\d+$/);
      assert.match(p.tls.date, /^\d{4}-\d{2}-\d{2}$/);
    } else {
      assert.equal(p.tls.date, undefined);
    }
    console.log(`tls: ${p.tls.library} ${p.tls.version} (${p.tls.reason})`);
  });

  it('BoringSSL is the default, at the version tools/boringssl.json pins', { ...T, skip: needBoring }, () => {
    const { ok, tls } = probeTls();
    assert.equal(ok, true);
    assert.equal(tls.library, 'boringssl');
    assert.equal(tls.reason, 'default');
    if (!process.env.MORO_BORINGSSL_PIN) assert.equal(tls.version, PIN.tag);
    assert.equal(tls.date, `${tls.version.slice(2, 6)}-${tls.version.slice(6, 8)}-${tls.version.slice(8, 10)}`);
  });

  it('MORO_ENGINE_TLS=openssl loads the binary on node\'s OpenSSL', { ...T, skip: needBoth }, () => {
    for (const name of ['openssl', 'node', 'OpenSSL']) {
      const { ok, tls } = probeTls({ env: { MORO_ENGINE_TLS: name } });
      assert.equal(ok, true);
      assert.equal(tls.library, 'openssl');
      assert.equal(tls.reason, 'MORO_ENGINE_TLS');
      assert.equal(tls.version, process.versions.openssl.replace(/\+.*$/, ''));
    }
    assert.equal(probeTls({ env: { MORO_ENGINE_TLS: 'auto' } }).tls.library, 'boringssl');
  });

  it('an unknown MORO_ENGINE_TLS is an error, not a default', T, () => {
    const p = probeTls({ env: { MORO_ENGINE_TLS: 'libressl' } });
    assert.equal(p.ok, false);
    assert.match(p.error, /MORO_ENGINE_TLS must be "boringssl", "openssl" or "auto", got "libressl"/);
  });

  it('a configured OpenSSL selects OpenSSL by itself', { ...T, skip: needBoth }, (t) => {
    // An empty config file that exists: node reads OPENSSL_CONF at startup.
    const confDir = mkdtempSync(join(tmpdir(), 'moro-openssl-conf-'));
    t.after(() => rmSync(confDir, { recursive: true, force: true }));
    const cnf = join(confDir, 'openssl.cnf');
    writeFileSync(cnf, '');
    const conf = probeTls({ env: { OPENSSL_CONF: cnf } });
    assert.equal(conf.tls.library, 'openssl');
    assert.match(conf.tls.reason, /node's OpenSSL is configured \(OPENSSL_CONF\)/);

    const flag = probeTls({ args: ['--openssl-legacy-provider'] });
    assert.equal(flag.tls.library, 'openssl');
    assert.match(flag.tls.reason, /--openssl-legacy-provider/);

    const viaNodeOptions = probeTls({ env: { NODE_OPTIONS: '--openssl-shared-config' } });
    assert.equal(viaNodeOptions.tls.library, 'openssl');
    assert.match(viaNodeOptions.tls.reason, /--openssl-shared-config/);

    // Asking for BoringSSL by name wins over the inference.
    const named = probeTls({ env: { OPENSSL_CONF: cnf, MORO_ENGINE_TLS: 'boringssl' } });
    assert.equal(named.tls.library, 'boringssl');
    assert.equal(named.tls.reason, 'MORO_ENGINE_TLS');

    // The same options given through node's configuration file take effect
    // like the flags and show in neither execArgv nor NODE_OPTIONS.
    const nodeConfig = join(confDir, 'node.config.json');
    writeFileSync(nodeConfig, JSON.stringify({ nodeOptions: { 'openssl-config': cnf } }));
    const probeWithFile = spawnSync(process.execPath, ['--experimental-config-file=' + nodeConfig, '-e', '0'], { env: cleanEnv(), encoding: 'utf8' });
    if (probeWithFile.status !== 0) return t.diagnostic('this node has no --experimental-config-file');
    const viaFile = probeTls({ args: ['--experimental-config-file=' + nodeConfig] });
    assert.equal(viaFile.tls.library, 'openssl');
    assert.match(viaFile.tls.reason, /--openssl-config in .*node\.config\.json/);
    // A configuration file that says nothing about OpenSSL changes nothing.
    writeFileSync(nodeConfig, JSON.stringify({ nodeOptions: { 'max-http-header-size': 16384 } }));
    assert.equal(probeTls({ args: ['--experimental-config-file=' + nodeConfig] }).tls.library, 'boringssl');
  });

  // What the operator told node about every TLS server of the process holds
  // for a server here whose own ssl options do not say otherwise.
  for (const library of ['boringssl', 'openssl']) {
    const handshakes = `
      const tls = await import('node:tls');
      const { readFileSync } = await import('node:fs');
      const fx = (n) => readFileSync(${JSON.stringify(FIXTURES)} + n);
      const identity = { key: fx('localhost.key'), cert: fx('localhost.pem') };
      const start = (ssl) => {
        const sid = engine.serve({ onRequest(id) { engine.respond(id, 200, null, 'ok'); }, onAborted() {} }, { ssl });
        return { sid, port: engine.listen(sid, '127.0.0.1', 0) };
      };
      const connect = (port, version) => new Promise((resolve) => {
        // The client names its own list: the flags under test would otherwise shape it too.
        const offered = 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';
        const s = tls.connect({ host: '127.0.0.1', port, ca: fx('ca.pem'), servername: 'localhost', minVersion: version, maxVersion: version, ciphers: offered }, () => {
          resolve(s.getCipher().name);
          s.destroy();
        });
        s.on('error', () => resolve(null));
      });
    `;

    it(`${library}: node --tls-min-v1.3 is the floor of a server that names none`, { ...T, skip: needBoth }, () => {
      const body = `${handshakes}
        const plain = start(identity);
        const own = start({ ...identity, minVersion: 'TLSv1.2' });
        const out = {
          default12: await connect(plain.port, 'TLSv1.2'), default13: await connect(plain.port, 'TLSv1.3'),
          own12: await connect(own.port, 'TLSv1.2'),
        };
        // updateSsl() builds a new context: the floor goes into that one too.
        engine.updateSsl(plain.sid, { key: fx('rsa.key'), cert: fx('rsa.pem') });
        out.updated12 = await connect(plain.port, 'TLSv1.2');
        out.updated13 = await connect(plain.port, 'TLSv1.3');
        engine.close(plain.sid); engine.close(own.sid);
        return out;
      `;
      const withFlag = child(body, { args: ['--tls-min-v1.3'], env: { MORO_ENGINE_TLS: library } }).value;
      assert.equal(withFlag.default12, null, 'TLS 1.2 refused under --tls-min-v1.3');
      assert.ok(withFlag.default13);
      assert.ok(withFlag.own12, "the app's own minVersion wins, as it does for node's servers");
      assert.equal(withFlag.updated12, null, 'still refused after updateSsl()');
      assert.ok(withFlag.updated13);
      const without = child(body, { env: { MORO_ENGINE_TLS: library } }).value;
      assert.ok(without.default12, 'no flag: the default floor is TLS 1.2');
      // And the ceiling: --tls-max-v1.2.
      const capped = child(body, { args: ['--tls-max-v1.2'], env: { MORO_ENGINE_TLS: library } }).value;
      assert.ok(capped.default12);
      assert.equal(capped.default13, null, 'TLS 1.3 refused under --tls-max-v1.2');
      assert.equal(capped.updated13, null, 'still refused after updateSsl()');
    });

    it(`${library}: node --tls-cipher-list is the cipher list of a server that names none`, { ...T, skip: needBoth }, () => {
      const body = `${handshakes}
        const plain = start(identity);
        const own = start({ ...identity, ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256' });
        const out = { default12: await connect(plain.port, 'TLSv1.2'), default13: await connect(plain.port, 'TLSv1.3'), own12: await connect(own.port, 'TLSv1.2') };
        engine.close(plain.sid); engine.close(own.sid);
        return out;
      `;
      const list = 'TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-GCM-SHA384';
      const withFlag = child(body, { args: ['--tls-cipher-list=' + list], env: { MORO_ENGINE_TLS: library } }).value;
      assert.equal(withFlag.default12, 'ECDHE-ECDSA-AES256-GCM-SHA384');
      assert.equal(withFlag.default13, 'TLS_AES_256_GCM_SHA384');
      assert.equal(withFlag.own12, 'ECDHE-ECDSA-AES128-GCM-SHA256', "the app's own list wins");
      const without = child(body, { env: { MORO_ENGINE_TLS: library } }).value;
      assert.equal(without.default12, 'ECDHE-ECDSA-AES128-GCM-SHA256');
      assert.equal(without.default13, 'TLS_AES_128_GCM_SHA256');
    });
  }

  it('selectTls() chooses before the load and cannot swap after it', { ...T, skip: needBoth }, () => {
    const { value } = child(`
      const chosen = engine.selectTls('openssl');
      const first = engine.probe().tls;
      const same = engine.selectTls('openssl');
      const auto = engine.selectTls('auto');
      let code = null, message = null;
      try { engine.selectTls('boringssl'); } catch (e) { code = e.code; message = e.message; }
      let invalid = null;
      try { engine.selectTls('gnutls'); } catch (e) { invalid = e.code; }
      return { chosen, first, same, auto, code, message, invalid, after: engine.probe().tls.library };
    `);
    assert.equal(value.chosen, 'openssl');
    assert.equal(value.first.library, 'openssl');
    assert.equal(value.first.reason, 'selectTls()');
    assert.equal(value.same, 'openssl');
    assert.equal(value.auto, 'openssl');
    assert.equal(value.code, 'MORO_ENGINE_TLS_LOADED');
    assert.match(value.message, /came after the binding was loaded with openssl/);
    assert.equal(value.invalid, 'MORO_ENGINE_TLS_INVALID');
    assert.equal(value.after, 'openssl');
  });

  it('selectTls() wins over MORO_ENGINE_TLS, and is a named export', { ...T, skip: needBoth }, () => {
    const { value } = child(
      `
      const { selectTls } = await import(${JSON.stringify(ENGINE_ENTRY)});
      selectTls('boringssl');
      return engine.probe().tls;
    `,
      { env: { MORO_ENGINE_TLS: 'openssl' } }
    );
    assert.equal(value.library, 'boringssl');
    assert.equal(value.reason, 'selectTls()');
  });

  // A copy of the loader beside a build/ that holds only the OpenSSL binary:
  // what an install looks like when the BoringSSL binary is not there.
  it('a missing BoringSSL binary falls back to OpenSSL, unless it was asked for by name', { ...T, skip: needBoth }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'moro-tls-fallback-'));
    try {
      mkdirSync(join(dir, 'packages', 'engine'), { recursive: true });
      mkdirSync(join(dir, 'build'));
      // A stand-in for the repository: the loader reads build/ only there.
      cpSync(join(root, 'package.json'), join(dir, 'package.json'));
      for (const f of ['index.js', 'index.mjs', 'package.json']) {
        cpSync(join(root, 'packages', 'engine', f), join(dir, 'packages', 'engine', f));
      }
      const from = engine.probe();
      assert.ok(existsSync(join(root, 'build')), 'this test needs the local build/ directory');
      const suffix = `_${from.abi}.node`;
      // Every libc flavor present (a CI artifact directory holds gnu and musl
      // side by side); the loader picks its own by name.
      const plain = readdirSync(join(root, 'build')).filter((f) => f.endsWith(suffix) && f.includes(`_${process.platform}_${process.arch}`));
      assert.ok(plain.length > 0, `no OpenSSL binary for ABI ${from.abi} in build/`);
      for (const f of plain) cpSync(join(root, 'build', f), join(dir, 'build', f));
      const entry = pathToFileURL(join(dir, 'packages', 'engine', 'index.mjs')).href;

      const fallen = probeTls({ entry });
      assert.equal(fallen.ok, true);
      assert.equal(fallen.tls.library, 'openssl');
      assert.equal(fallen.tls.reason, 'fallback');
      assert.match(fallen.tls.fallbackReason, /_boringssl\.node/);

      const named = probeTls({ entry, env: { MORO_ENGINE_TLS: 'boringssl' } });
      assert.equal(named.ok, false, 'BoringSSL by name must not be served by another library');
      assert.match(named.error, /_boringssl\.node/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  for (const library of ['boringssl', 'openssl']) {
    it(`${library}: terminates TLS and gives a stock client AES-128-GCM`, { ...T, skip: needBoth }, () => {
      const { value } = child(
        `
        const https = await import('node:https');
        const { readFileSync } = await import('node:fs');
        const fx = (n) => ${JSON.stringify(FIXTURES)} + n;
        const sid = engine.serve(
          { onRequest(id) { engine.respond(id, 200, null, 'hello'); }, onAborted() {} },
          { ssl: { key_file_name: fx('localhost.key'), cert_file_name: fx('localhost.pem') } }
        );
        const port = engine.listen(sid, '127.0.0.1', 0);
        const result = await new Promise((resolve, reject) => {
          const req = https.get({ host: '127.0.0.1', port, path: '/', ca: readFileSync(fx('ca.pem')), servername: 'localhost', agent: false }, (res) => {
            let body = '';
            res.on('data', (c) => (body += c));
            res.on('end', () => resolve({ status: res.statusCode, body, cipher: res.socket.getCipher().name, protocol: res.socket.getProtocol() }));
          });
          req.on('error', reject);
        });
        engine.close(sid);
        return { ...result, library: engine.probe().tls.library };
      `,
        { env: { MORO_ENGINE_TLS: library } }
      );
      assert.equal(value.library, library);
      assert.equal(value.status, 200);
      assert.equal(value.body, 'hello');
      assert.equal(value.protocol, 'TLSv1.3');
      assert.equal(value.cipher, 'TLS_AES_128_GCM_SHA256');
    });
  }
});

// A configuration OpenSSL takes and BoringSSL has no support for. Up to 1.1.19
// it was served; an update must not turn it into a server that will not start.
// (A TLS 1.3 CCM suite stands in for the family: Ed448 and DSA keys, brainpool
// groups, DHE-only cipher lists.)
describe('where the binary is loaded from', { skip }, () => {
  // An install has no platform package here, and something called "build"
  // sitting next to @morojs in node_modules: the loader must not take a
  // binary from it. In the repository the same relative path is build/.
  it('an installed copy does not load a binary from node_modules/build', T, () => {
    const dir = mkdtempSync(join(tmpdir(), 'moro-engine-install-'));
    try {
      const pkg = join(dir, 'node_modules', '@morojs', 'engine');
      mkdirSync(pkg, { recursive: true });
      for (const f of ['index.js', 'index.mjs', 'package.json']) cpSync(join(root, 'packages', 'engine', f), join(pkg, f));
      mkdirSync(join(dir, 'node_modules', 'build'));
      for (const f of readdirSync(join(root, 'build'))) {
        if (f.endsWith(`_${process.versions.modules}.node`) || f.endsWith(`_${process.versions.modules}_boringssl.node`)) {
          cpSync(join(root, 'build', f), join(dir, 'node_modules', 'build', f));
        }
      }
      const entry = pathToFileURL(join(pkg, 'index.mjs')).href;
      const installed = child('const p = engine.probe(); return { ok: p.ok, error: p.error ?? null };', { entry }).value;
      assert.equal(installed.ok, false, 'no platform package: there is nothing to load');
      assert.doesNotMatch(String(installed.error), /node_modules[\\/]build/);

      // The checkout itself still finds its local build.
      assert.equal(probeTls().ok, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // An install as npm lays it out: the meta package and, beside it, the
  // platform package stamped `version`, carrying this build's binaries.
  function install(dir, version) {
    const scope = join(dir, 'node_modules', '@morojs');
    const pkg = join(scope, 'engine');
    mkdirSync(pkg, { recursive: true });
    for (const f of ['index.js', 'index.mjs', 'package.json']) cpSync(join(root, 'packages', 'engine', f), join(pkg, f));
    const libc = process.platform === 'linux' ? (existsSync('/etc/alpine-release') ? '-musl' : '-gnu') : '';
    const name = `engine-${process.platform}-${process.arch}${libc}`;
    mkdirSync(join(scope, name));
    writeFileSync(join(scope, name, 'package.json'), JSON.stringify({ name: `@morojs/${name}`, version }));
    for (const f of readdirSync(join(root, 'build'))) {
      if (f.endsWith(`_${process.versions.modules}.node`) || f.endsWith(`_${process.versions.modules}_boringssl.node`)) {
        cpSync(join(root, 'build', f), join(scope, name, f));
      }
    }
    return { entry: pathToFileURL(join(pkg, 'index.mjs')).href };
  }
  const probeBinary = (entry) =>
    child(
      `const seen = []; process.on('warning', (w) => seen.push(w.code));
       const p = engine.probe(); engine.probe();
       await new Promise((r) => setImmediate(r));
       return { ok: p.ok, version: p.version, binary: p.binary ?? null, warnings: seen };`,
      { entry }
    ).value;

  it('probe().binary names the file that was loaded', T, () => {
    const p = engine.probe();
    assert.equal(typeof p.binary?.path, 'string');
    assert.ok(existsSync(p.binary.path), p.binary.path);
    assert.match(p.binary.path, /\.node$/);
  });

  it('a platform package of this release is reported with its version, and nothing is said', T, () => {
    const dir = mkdtempSync(join(tmpdir(), 'moro-engine-same-'));
    try {
      const { entry } = install(dir, engine.version);
      const p = probeBinary(entry);
      assert.equal(p.ok, true);
      assert.equal(p.binary.version, engine.version);
      assert.match(p.binary.path, /@morojs[\\/]engine-[a-z0-9-]+[\\/]moro_engine_/);
      assert.deepEqual(p.warnings, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a platform package of another release is not loaded', T, () => {
    const dir = mkdtempSync(join(tmpdir(), 'moro-engine-other-'));
    try {
      const { entry } = install(dir, '1.1.5');
      const p = child('const p = engine.probe(); return { ok: p.ok, error: p.error ?? null };', { entry }).value;
      assert.equal(p.ok, false);
      assert.match(p.error, /1\.1\.5, not /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // The platform package is absent from the application, and a package of
  // that name sits where plain module resolution would still find it: above
  // the application, on NODE_PATH, in the home directory's module folder.
  it('a platform package outside the installation is not loaded', T, () => {
    const dir = mkdtempSync(join(tmpdir(), 'moro-engine-outside-'));
    try {
      const app = join(dir, 'srv', 'app');
      const { entry } = install(app, engine.version);
      const scope = join(app, 'node_modules', '@morojs');
      const name = readdirSync(scope).find((d) => d !== 'engine');
      const probeOk = (env) => child('const p = engine.probe(); return { ok: p.ok };', { entry, env }).value.ok;
      assert.equal(probeOk({}), true, 'installed beside the meta package: loaded');

      for (const [where, env] of [
        [join(dir, 'node_modules', '@morojs'), {}],
        [join(dir, 'elsewhere', '@morojs'), { NODE_PATH: join(dir, 'elsewhere') }],
        [join(dir, 'home', '.node_modules', '@morojs'), { HOME: join(dir, 'home'), USERPROFILE: join(dir, 'home') }],
      ]) {
        mkdirSync(where, { recursive: true });
        cpSync(join(scope, name), join(where, name), { recursive: true });
      }
      rmSync(join(scope, name), { recursive: true, force: true });
      assert.equal(probeOk({}), false, 'a node_modules above the application');
      assert.equal(probeOk({ NODE_PATH: join(dir, 'elsewhere') }), false, 'NODE_PATH');
      assert.equal(probeOk({ HOME: join(dir, 'home'), USERPROFILE: join(dir, 'home') }), false, 'the home directory');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('a TLS configuration BoringSSL does not support', { skip }, () => {
  const CCM = 'TLS_AES_128_CCM_SHA256';
  const PRELUDE = `
    const fx = (n) => ${JSON.stringify(FIXTURES)} + n;
    const cb = { onRequest(id) { engine.respond(id, 200, null, 'hello'); }, onAborted() {} };
    const ssl = (extra = {}) => ({ key_file_name: fx('localhost.key'), cert_file_name: fx('localhost.pem'), ...extra });
    const attempt = (fn) => { try { return { ok: fn() }; } catch (e) { return { error: e.message }; } };
  `;

  it('is served by OpenSSL without being asked, and probe() says why', { ...T, skip: needBoth }, () => {
    const { value } = child(`
      ${PRELUDE}
      const tls = await import('node:tls');
      const { readFileSync } = await import('node:fs');
      const sid = engine.serve(cb, { ssl: ssl({ ciphersuites: ${JSON.stringify(CCM)} }) });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const seen = await new Promise((resolve, reject) => {
        const s = tls.connect({ host: '127.0.0.1', port, ca: readFileSync(fx('ca.pem')), servername: 'localhost', ciphers: ${JSON.stringify(CCM)} }, () => {
          s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\nConnection: close\\r\\n\\r\\n');
        });
        let data = '';
        s.on('data', (c) => (data += c));
        s.on('end', () => resolve({ cipher: s.getCipher().name, status: data.slice(0, 12) }));
        s.on('error', reject);
      });
      engine.close(sid);
      return { ...seen, tls: engine.probe().tls };
    `);
    assert.equal(value.status, 'HTTP/1.1 200');
    assert.equal(value.cipher, CCM);
    assert.equal(value.tls.library, 'openssl');
    assert.equal(value.tls.reason, 'fallback');
    assert.match(value.tls.fallbackReason, /^BoringSSL did not accept the TLS configuration \(.*TLS_AES_128_CCM_SHA256/);
  });

  it('a certificate with a key type BoringSSL does not have (Ed448) is served the same way', { ...T, skip: needBoth }, () => {
    const { value } = child(`
      ${PRELUDE}
      const tls = await import('node:tls');
      const sid = engine.serve(cb, { ssl: { key_file_name: fx('ed448.key'), cert_file_name: fx('ed448.pem') } });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const seen = await new Promise((resolve, reject) => {
        const s = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', rejectUnauthorized: false }, () => {
          s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\nConnection: close\\r\\n\\r\\n');
        });
        let data = '';
        s.on('data', (c) => (data += c));
        s.on('end', () => resolve({ key: s.getPeerCertificate().asn1Curve ?? s.getPeerX509Certificate().publicKey.asymmetricKeyType, status: data.slice(0, 12) }));
        s.on('error', reject);
      });
      engine.close(sid);
      return { ...seen, tls: engine.probe().tls };
    `);
    assert.equal(value.status, 'HTTP/1.1 200');
    assert.equal(value.key, 'ed448');
    assert.equal(value.tls.library, 'openssl');
    assert.equal(value.tls.reason, 'fallback');
    assert.match(value.tls.fallbackReason, /^BoringSSL did not accept the TLS configuration \(ssl: /);
  });

  it('is settled at load when the caller passes the ssl options to selectTls()', { ...T, skip: needBoth }, () => {
    const { value } = child(`
      ${PRELUDE}
      engine.selectTls('auto', ssl({ ciphersuites: ${JSON.stringify(CCM)} }));
      const before = engine.probe().tls;
      const { respond, listen } = engine; // held before any server exists: fine, the library is settled
      const sid = engine.serve(cb, { ssl: ssl({ ciphersuites: ${JSON.stringify(CCM)} }) });
      engine.close(sid);
      return { before, after: engine.probe().tls, held: typeof respond + typeof listen };
    `);
    assert.equal(value.before.library, 'openssl');
    assert.equal(value.before.reason, 'fallback');
    assert.match(value.before.fallbackReason, /BoringSSL did not accept the TLS configuration/);
    assert.deepEqual(value.after, value.before);
  });

  it('ssl options BoringSSL accepts leave it on BoringSSL', { ...T, skip: needBoring }, () => {
    const { value } = child(`
      ${PRELUDE}
      engine.selectTls('auto', ssl({ ciphersuites: 'TLS_AES_256_GCM_SHA384' }));
      return engine.probe().tls;
    `);
    assert.equal(value.library, 'boringssl');
    assert.equal(value.reason, 'default');
  });

  it('BoringSSL asked for by name refuses it, and nothing is substituted', { ...T, skip: needBoring }, () => {
    const { value } = child(
      `
      ${PRELUDE}
      const r = attempt(() => engine.serve(cb, { ssl: ssl({ ciphersuites: ${JSON.stringify(CCM)} }) }));
      return { ...r, tls: engine.probe().tls };
    `,
      { env: { MORO_ENGINE_TLS: 'boringssl' } }
    );
    assert.match(value.error, /is not a TLS 1\.3 suite of the bundled TLS library \(BoringSSL\)/);
    assert.doesNotMatch(value.error, /MORO_ENGINE_TLS=openssl/);
    assert.equal(value.tls.library, 'boringssl');
  });

  it('a thread already serving on BoringSSL keeps it: the refusal stands and names the way out', { ...T, skip: needBoth }, () => {
    const { value } = child(`
      ${PRELUDE}
      const first = engine.serve(cb, { ssl: ssl() });
      const r = attempt(() => engine.serve(cb, { ssl: ssl({ ciphersuites: ${JSON.stringify(CCM)} }) }));
      engine.close(first);
      return { ...r, tls: engine.probe().tls };
    `);
    assert.match(value.error, /is not a TLS 1\.3 suite of the bundled TLS library/);
    assert.match(value.error, /MORO_ENGINE_TLS=openssl selects it/);
    assert.equal(value.tls.library, 'boringssl');
  });

  it('native functions taken from the module before the first server pin the binary too', { ...T, skip: needBoth }, () => {
    const { value } = child(`
      ${PRELUDE}
      const { respond } = engine;
      const r = attempt(() => engine.serve(cb, { ssl: ssl({ ciphersuites: ${JSON.stringify(CCM)} }) }));
      return { ...r, tls: engine.probe().tls, held: typeof respond };
    `);
    assert.match(value.error, /MORO_ENGINE_TLS=openssl selects it/);
    assert.equal(value.tls.library, 'boringssl');
  });

  it('a configuration wrong for both libraries is the plain error, on BoringSSL', { ...T, skip: needBoth }, () => {
    const { value } = child(`
      ${PRELUDE}
      const r = attempt(() => engine.serve(cb, { ssl: ssl({ ciphersuites: 'TLS_NOT_A_SUITE' }) }));
      const ok = engine.serve(cb, { ssl: ssl() });
      engine.close(ok);
      return { ...r, tls: engine.probe().tls };
    `);
    assert.match(value.error, /ssl\.ciphersuites 'TLS_NOT_A_SUITE' is invalid/);
    assert.doesNotMatch(value.error, /MORO_ENGINE_TLS=openssl/);
    assert.equal(value.tls.library, 'boringssl');
    assert.equal(value.tls.reason, 'default');
  });

  it('a plaintext server never triggers any of it', { ...T, skip: needBoring }, () => {
    const { value } = child(`
      ${PRELUDE}
      const r = attempt(() => engine.serve(cb, { maxHeaders: -5 }));
      return { ...r, tls: engine.probe().tls };
    `);
    assert.equal(value.tls.library, 'boringssl');
    assert.equal(value.tls.reason, 'default');
  });
});

describe('notice about an old bundled TLS library', { skip }, () => {
  // The child moves its clock to `days` after the pinned snapshot, creates
  // servers, and reports the warnings its process emitted.
  const SERVERS = `
    const fx = (n) => ${JSON.stringify(FIXTURES)} + n;
    const cb = { onRequest() {}, onAborted() {} };
    const tlsServer = () => engine.close(engine.serve(cb, { ssl: { key_file_name: fx('localhost.key'), cert_file_name: fx('localhost.pem') } }));
    const plainServer = () => engine.close(engine.serve(cb, {}));
    const warnings = [];
    process.on('warning', (w) => { if (w.code === 'MORO_ENGINE_TLS_STALE') warnings.push(w.message); });
    const settle = () => new Promise((r) => setTimeout(r, 50));
  `;
  const aged = (days, body, env = {}) =>
    child(
      `
      const pinned = Date.parse(engine.probe().tls.date ? engine.probe().tls.date + 'T00:00:00Z' : '2026-01-01T00:00:00Z');
      Date.now = () => pinned + ${days} * 86400000;
      ${SERVERS}
      ${body}
      await settle();
      return warnings;
    `,
      { env }
    );

  it('a TLS server on a build older than 180 days warns, once', { ...T, skip: needBoring }, () => {
    const { value } = aged(181, 'tlsServer(); tlsServer(); tlsServer();');
    assert.equal(value.length, 1, JSON.stringify(value));
    assert.match(value[0], /BoringSSL 0\.\d{8}\.\d+\) is 181 days old/);
    assert.match(value[0], /update @morojs\/engine/);
  });

  it('a build inside the window says nothing', { ...T, skip: needBoring }, () => {
    assert.deepEqual(aged(180, 'tlsServer();').value, []);
    assert.deepEqual(aged(0, 'tlsServer();').value, []);
  });

  it('a server that does not terminate TLS says nothing', { ...T, skip: needBoring }, () => {
    assert.deepEqual(aged(400, 'plainServer(); plainServer();').value, []);
  });

  it('MORO_ENGINE_TLS_AGE_WARNING=0 turns it off', { ...T, skip: needBoring }, () => {
    assert.deepEqual(aged(400, 'tlsServer();', { MORO_ENGINE_TLS_AGE_WARNING: '0' }).value, []);
  });

  it('the OpenSSL binary never warns: its library is node\'s to keep current', { ...T, skip: needBoth }, () => {
    assert.deepEqual(aged(4000, 'tlsServer();', { MORO_ENGINE_TLS: 'openssl' }).value, []);
  });

  it('worker threads share the one notice', { ...T, skip: needBoring }, () => {
    const { value, stderr } = aged(
      400,
      `
      const { Worker } = await import('node:worker_threads');
      tlsServer();
      const worker = (n) => new Promise((resolve, reject) => {
        const w = new Worker(
          \`
          const { parentPort, workerData } = require('node:worker_threads');
          Date.now = () => workerData.now;
          import(workerData.entry).then(({ default: engine }) => {
            const fx = (n) => workerData.fixtures + n;
            engine.close(engine.serve({ onRequest() {}, onAborted() {} }, { ssl: { key_file_name: fx('localhost.key'), cert_file_name: fx('localhost.pem') } }));
            setTimeout(() => parentPort.postMessage('done'), 50);
          });
          \`,
          { eval: true, execArgv: [], workerData: { now: Date.now(), entry: ${JSON.stringify(ENGINE_ENTRY)}, fixtures: ${JSON.stringify(FIXTURES)} } }
        );
        w.once('message', () => resolve(w.terminate()));
        w.once('error', reject);
      });
      await worker(1);
      await worker(2);
    `
    );
    assert.equal(value.length, 1);
    assert.equal(stderr.split('MORO_ENGINE_TLS_STALE').length - 1, 1, `expected one notice on stderr:\n${stderr}`);
  });
});
