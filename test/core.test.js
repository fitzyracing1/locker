import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check, insertGate, knownStamp, ResidualStore, detectLanguage, summarize } from '../src/locker-core.js';
import { extractCode, aiFix, buildPrompt } from '../src/ai.js';
import { lineDiff } from '../src/diff.js';
import { SAMPLES } from '../samples/samples.js';

const has = (cmd) => { try { execFileSync(cmd, ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } };

test('detects languages', () => {
  assert.equal(detectLanguage('a.py'), 'python');
  assert.equal(detectLanguage('A.java'), 'java');
  assert.equal(detectLanguage('x', 'package main\nfunc main() {}'), 'go');
  assert.equal(detectLanguage('x', '#include <stdio.h>'), 'c');
});

const expected = {
  'express-orders.js': ['unverified-long', 'unverified-endpoint', 'long-literal'],
  'flask_accounts.py': ['unverified-long', 'unverified-endpoint'],
  'Transfer.java': ['unverified-long', 'unverified-long'],
  'handler.go': ['unverified-long'],
  'serial.c': ['unverified-long'],
  'known_stamp.py': ['unverified-long'],
};

for (const [name, rules] of Object.entries(expected)) {
  test(`${name} is Not safe and Insert gate makes it Safe`, () => {
    const r = check(SAMPLES[name], name);
    assert.equal(r.verdict, 'Not safe');
    assert.deepEqual(r.findings.map((f) => f.rule), rules);
    const g = insertGate(SAMPLES[name], name);
    assert.ok(g.changed >= 1);
    assert.equal(check(g.source, name).verdict, 'Safe', g.source);
    // idempotent: gating again changes nothing
    assert.equal(insertGate(g.source, name).changed, 0);
  });
}

test('verified code is Safe', () => {
  assert.equal(check(SAMPLES['safe_gate.js'], 'safe_gate.js').verdict, 'Safe');
  assert.equal(check('const n = parseInt("42", 10);', 'a.js').verdict, 'Safe');
  const guarded = 'const raw = req.query.id;\nif (!/^\\d+$/.test(raw)) throw new Error("bad");\nconst id = parseInt(raw, 10);';
  assert.equal(check(guarded, 'a.js').verdict, 'Safe');
  const py = 'try:\n    n = int(sys.argv[1])\nexcept ValueError:\n    sys.exit(1)\n';
  assert.equal(check(py, 'a.py').verdict, 'Safe');
});

test('URLs are not mistaken for comments', () => {
  const r = check('const { id } = req.params;\nfetch(`https://x.test/items/${id}`);', 'a.js');
  assert.equal(r.findings[0].rule, 'unverified-endpoint');
});

test('JS long literal is reported and becomes BigInt', () => {
  const src = 'const big = 12345678901234567890;';
  const r = check(src, 'a.js');
  assert.equal(r.findings[0].rule, 'long-literal');
  assert.match(insertGate(src, 'a.js').source, /12345678901234567890n/);
  assert.equal(check('const ok = 9007199254740991;', 'a.js').verdict, 'Safe');
});

test('gated JS runs and fails closed', async () => {
  const g = insertGate('export function get(req) { const id = parseInt(req.params.id, 10); return `/orders/${id}`; }', 'x.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'locker-'));
  const f = join(dir, 'g.mjs'); writeFileSync(f, g.source);
  const mod = await import(f);
  assert.equal(mod.get({ params: { id: '42' } }), '/orders/42');
  assert.equal(mod.get({ params: { id: '18446744073709551' } }), '/orders/18446744073709551');
  assert.throws(() => mod.get({ params: { id: '42 OR 1=1' } }), /Locker/);
  assert.throws(() => mod.get({ params: { id: '99999999999999999999' } }), /Locker/);
});

test('gated Python compiles and fails closed', { skip: !has('python3') }, () => {
  const g = insertGate(SAMPLES['known_stamp.py'], 'known_stamp.py');
  const dir = mkdtempSync(join(tmpdir(), 'locker-'));
  const f = join(dir, 'k.py'); writeFileSync(f, g.source);
  assert.equal(execFileSync('python3', [f, '5']).toString().trim(), '2');
  assert.throws(() => execFileSync('python3', [f, '5; rm'], { stdio: 'pipe' }));
});

test('gated C compiles and fails closed', { skip: !has('cc') }, () => {
  const g = insertGate(SAMPLES['serial.c'], 'serial.c');
  const dir = mkdtempSync(join(tmpdir(), 'locker-'));
  writeFileSync(join(dir, 's.c'), g.source);
  execFileSync('cc', ['-Wall', '-o', join(dir, 's'), join(dir, 's.c')]);
  assert.equal(execFileSync(join(dir, 's'), ['77']).toString().trim(), 'serial 77');
  assert.throws(() => execFileSync(join(dir, 's'), ['77abc'], { stdio: 'pipe' }));
});

test('known stamp: four cases only', () => {
  assert.equal(knownStamp(null, 1), -1);
  assert.equal(knownStamp(0, 3), -1);
  assert.equal(knownStamp(5, 1), 0);
  assert.equal(knownStamp(5, 3), 2);
  assert.throws(() => knownStamp(5, 2));
});

test('parallel makes longs out of date until closed', () => {
  const s = new ResidualStore();
  s.write('a', 9, 3);
  assert.equal(s.read('a'), 2);
  s.openParallel();
  assert.throws(() => s.read('a'), /Not safe/);
  s.closeParallel();
  assert.equal(s.read('a'), 2);
});

test('AI is optional and pluggable', async () => {
  assert.equal(await aiFix('x', [], 'js', {}), null);
  const fake = async (url, init) => {
    assert.equal(url, 'https://ai.test/v1');
    assert.match(init.headers.authorization, /Bearer k/);
    return { ok: true, json: async () => ({ choices: [{ message: { content: 'Here:\n```js\nconst a = 1;\n```' } }] }) };
  };
  assert.equal(await aiFix('x', [], 'js', { url: 'https://ai.test/v1', key: 'k' }, fake), 'const a = 1;\n');
  assert.equal(extractCode('plain'), 'plain\n');
  assert.equal(buildPrompt('s', [{ line: 1, rule: 'r', message: 'm' }], 'js').length, 2);
});

test('summary and diff helpers', () => {
  const rs = Object.entries(SAMPLES).map(([n, s]) => check(s, n));
  const sum = summarize(rs);
  assert.equal(sum.files, 7); assert.equal(sum.notSafe, 6); assert.equal(sum.verdict, 'Not safe');
  assert.deepEqual(lineDiff('a\nb', 'a\nc').map((x) => x.t), ['ctx', 'del', 'add']);
});

test('CLI exits 1 on Not safe and 0 after --gate', () => {
  const dir = mkdtempSync(join(tmpdir(), 'locker-'));
  const f = join(dir, 'o.js'); writeFileSync(f, SAMPLES['express-orders.js']);
  assert.throws(() => execFileSync('node', ['bin/locker.mjs', f], { stdio: 'pipe' }));
  execFileSync('node', ['bin/locker.mjs', '--gate', '--write', f], { stdio: 'pipe' });
  execFileSync('node', ['bin/locker.mjs', f], { stdio: 'pipe' });
});
