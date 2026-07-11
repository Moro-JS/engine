// Bench result recorder / gate. Reads 3 per-run average throughputs
// (autocannon `requests.average`) from run.sh, takes the median of the
// three, and either reports, records it as the machine's baseline, or
// gates at >= GATE_RATIO of the recorded baseline.
//
// Baselines are per-machine (hostname+cpu) because absolute req/s numbers
// are meaningless across hosts: the ship gate runs on the machine that
// recorded the baseline; anywhere else this degrades to a report.
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import os from 'os';

const GATE_RATIO = 0.95;

const args = process.argv.slice(2);
const get = flag => {
  const i = args.indexOf(flag);
  return i === -1 ? null : args[i + 1];
};
const mode = get('--mode') || 'engine';
const action = get('--action') || 'report';
const results = args
  .slice(args.indexOf('--results') + 1)
  .map(Number)
  .filter(n => Number.isFinite(n) && n > 0)
  .sort((a, b) => a - b);

if (results.length === 0) {
  console.error('no valid results');
  process.exit(1);
}
const median = results[Math.floor(results.length / 2)];

const machineId = `${os.hostname()}/${os.cpus()[0]?.model ?? 'unknown'}/${os.arch()}`;
const file = join(dirname(fileURLToPath(import.meta.url)), 'baselines.json');
// Per-machine baselines are gitignored; start empty on a fresh clone so
// --record can create the file and --gate degrades to a skip.
const db = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : { baselines: [] };

const baseline = db.baselines.find(b => b.machine === machineId && b.mode === mode);

console.log(`mode=${mode} median=${Math.round(median)} req/s (runs: ${results.map(Math.round).join(', ')})`);

if (action === 'record') {
  if (baseline) {
    baseline.rps = Math.round(median);
    baseline.node = process.version;
  } else {
    db.baselines.push({ machine: machineId, mode, rps: Math.round(median), node: process.version });
  }
  writeFileSync(file, JSON.stringify(db, null, 2) + '\n');
  console.log(`recorded baseline for ${machineId}`);
} else if (action === 'gate') {
  if (!baseline) {
    console.log(`no baseline recorded for ${machineId} - gate skipped (run with --record first)`);
    process.exit(0);
  }
  const ratio = median / baseline.rps;
  const verdict = ratio >= GATE_RATIO ? 'PASS' : 'FAIL';
  console.log(
    `gate: ${Math.round(median)} vs baseline ${baseline.rps} = ${(ratio * 100).toFixed(1)}% (need >= ${GATE_RATIO * 100}%) -> ${verdict}`
  );
  if (verdict === 'FAIL') process.exit(1);
}
