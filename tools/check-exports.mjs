#!/usr/bin/env node
// Export-drift gate: the native surface has to be declared in FOUR places
// (src/binding.cpp Initialize, the NATIVE_API allow-list in
// packages/engine/index.js, the ESM re-exports in index.mjs, and index.d.ts),
// the capability flags in TWO (setCap() in binding.cpp, EngineCapabilities in
// index.d.ts), and every serve() option the binding parses must be typed in
// ServeOptions. This script diffs them and exits 1 on any drift, so a new
// export can never ship half-registered (a name missing from NATIVE_API reads
// as undefined without loading the addon; a name missing from index.mjs is
// invisible to ESM consumers).
//
// Run: node tools/check-exports.mjs   (also `npm run check:exports`, CI `unit`)

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(root, p), 'utf8');

const binding = read('src/binding.cpp');
const loaderJs = read('packages/engine/index.js');
const loaderMjs = read('packages/engine/index.mjs');
const dts = read('packages/engine/index.d.ts');

const all = (re, text, group = 1) => {
  const out = [];
  for (const m of text.matchAll(re)) out.push(m[group]);
  return out;
};
const uniq = (a) => [...new Set(a)];

// ---- native function exports ------------------------------------------------

// binding.cpp: NODE_SET_METHOD(exports, "name", Fn) today; a `{"name", ...}`
// row inside a kExports[] table is accepted too (the fast-call registration
// table replaces the NODE_SET_METHOD list).
const bindingFns = uniq([
  ...all(/NODE_SET_METHOD\(exports,\s*"(\w+)"/g, binding),
  ...all(/^\s*\{"(\w+)",\s*[A-Za-z_]\w*/gm, binding.slice(binding.indexOf('kExports[]') === -1 ? binding.length : binding.indexOf('kExports[]'))),
]).filter((n) => n !== 'probe'); // probe is served by the loader itself

const nativeApiBlock = loaderJs.slice(loaderJs.indexOf('const NATIVE_API = new Set(['));
const nativeApi = uniq(all(/'(\w+)'/g, nativeApiBlock.slice(0, nativeApiBlock.indexOf('])'))));

const mjsExports = uniq(all(/^export (?:const|let) (\w+) =/gm, loaderMjs)).filter((n) => n !== 'probe');

const dtsFns = uniq(all(/^export function (\w+)\(/gm, dts)).filter((n) => n !== 'probe');
const declareBlock = dts.slice(dts.indexOf('declare const engine: {'));
const dtsDeclared = uniq(all(/^\s+(\w+): typeof \w+;/gm, declareBlock.slice(0, declareBlock.indexOf('};')))).filter(
  (n) => n !== 'probe'
);

// ---- capability flags ---------------------------------------------------------

const bindingCaps = uniq(all(/setCap\("(\w+)"/g, binding));
const capsBlock = dts.slice(dts.indexOf('export interface EngineCapabilities {'));
const dtsCaps = uniq(all(/^\s+(\w+): boolean;/gm, capsBlock.slice(0, capsBlock.indexOf('\n}'))));

// ---- serve() options ------------------------------------------------------------

// Top-level: getNum("x") plus the hand-parsed opts->Get(ctx, str(iso, "x")).
const bindingOptsTop = uniq([
  ...all(/getNum\("(\w+)"/g, binding),
  ...all(/opts->Get\(ctx,\s*str\(iso,\s*"(\w+)"\)\)/g, binding),
]);
const bindingOptsWsDeflate = uniq(all(/get(?:BoolW|IntW|SizeW)\("(\w+)"/g, binding));
const bindingOptsSsl = uniq(all(/get(?:Str|Bytes|Bool)\("(\w+)"/g, binding));

// index.d.ts ServeOptions: keys by brace depth (comment lines stripped).
function parseServeOptions(text) {
  const start = text.indexOf('export interface ServeOptions {');
  const lines = text.slice(start).split('\n').slice(1);
  const top = [];
  const nested = {}; // key -> [keys]
  let depth = 0;
  let current = null;
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('/**') || line.startsWith('*') || line.startsWith('//')) continue;
    if (depth === 0 && line === '}') break;
    const key = line.match(/^(\w+)\??:/)?.[1];
    if (depth === 0 && key) {
      // The nested block may open on this line (`ssl?: {`) or on a later
      // continuation line (`wsDeflate?:` / `| boolean` / `| {`): remember the
      // key and attribute whatever opens at depth 1 next to it.
      top.push(key);
      current = key;
    } else if (depth === 1 && key && current) {
      (nested[current] ||= []).push(key);
    }
    const before = depth;
    for (const ch of line) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
    // Only a block CLOSING back to the top level ends the attribution - a
    // continuation line such as `| boolean` between the key and its `{` must
    // not (that is how wsDeflate's union type is laid out).
    if (before > 0 && depth === 0) current = null;
  }
  return { top, nested };
}
const dtsOpts = parseServeOptions(dts);

// ---- diff ---------------------------------------------------------------------

let failed = false;
function compare(label, expected, actual, expectedName, actualName) {
  const e = new Set(expected);
  const a = new Set(actual);
  const missing = expected.filter((x) => !a.has(x));
  const extra = actual.filter((x) => !e.has(x));
  if (missing.length || extra.length) {
    failed = true;
    console.error(`DRIFT ${label}:`);
    if (missing.length) console.error(`  in ${expectedName} but not in ${actualName}: ${missing.join(', ')}`);
    if (extra.length) console.error(`  in ${actualName} but not in ${expectedName}: ${extra.join(', ')}`);
  } else {
    console.log(`ok   ${label} (${expected.length})`);
  }
}

compare('native functions: binding vs NATIVE_API', bindingFns, nativeApi, 'src/binding.cpp', 'index.js NATIVE_API');
compare('native functions: binding vs index.mjs', bindingFns, mjsExports, 'src/binding.cpp', 'index.mjs exports');
compare('native functions: binding vs index.d.ts functions', bindingFns, dtsFns, 'src/binding.cpp', 'index.d.ts');
compare('native functions: binding vs index.d.ts default export', bindingFns, dtsDeclared, 'src/binding.cpp', 'index.d.ts declare const engine');
compare('capabilities: setCap vs EngineCapabilities', bindingCaps, dtsCaps, 'src/binding.cpp', 'index.d.ts EngineCapabilities');
compare('serve options (top level)', bindingOptsTop, dtsOpts.top, 'src/binding.cpp', 'index.d.ts ServeOptions');
compare('serve options (ssl.*)', bindingOptsSsl, dtsOpts.nested.ssl || [], 'src/binding.cpp', 'index.d.ts ServeOptions.ssl');
compare('serve options (wsDeflate.*)', bindingOptsWsDeflate, dtsOpts.nested.wsDeflate || [], 'src/binding.cpp', 'index.d.ts ServeOptions.wsDeflate');

if (failed) {
  console.error('\nexport drift detected - see docs/API.md "Adding a native export"');
  process.exit(1);
}
console.log('no export drift');
