#!/usr/bin/env node
// Locker CLI: node bin/locker.mjs [--gate] [--write] <files...>
// Exit code 1 when any file is Not safe (after gating, if --gate is given).
import { readFileSync, writeFileSync } from 'node:fs';
import { check, insertGate } from '../src/locker-core.js';

const args = process.argv.slice(2);
const gate = args.includes('--gate'), write = args.includes('--write'), json = args.includes('--json');
const paths = args.filter((a) => !a.startsWith('--'));
if (!paths.length) { console.error('usage: locker [--gate [--write]] [--json] <files...>'); process.exit(2); }
let notSafe = 0;
const out = [];
for (const p of paths) {
  let src = readFileSync(p, 'utf8');
  let r = check(src, p);
  if (gate && r.findings.some((f) => f.fix)) {
    const g = insertGate(src, p);
    src = g.source;
    if (write) writeFileSync(p, src); else if (!json) process.stdout.write(`--- ${p} (gated)\n${src}\n`);
    r = check(src, p);
  }
  if (r.verdict === 'Not safe') notSafe++;
  out.push(r);
  if (!json) {
    console.log(`${r.verdict === 'Safe' ? '✔' : '✖'} ${p} [${r.language}] ${r.verdict}`);
    for (const f of r.findings) console.log(`   ${p}:${f.line}:${f.col} ${f.rule} ${f.message}`);
  }
}
if (json) console.log(JSON.stringify(out, null, 2));
process.exit(notSafe ? 1 : 0);
