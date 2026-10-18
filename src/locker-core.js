// Locker core: a static sandbox checker for long-integer sources.
// A long integer, or a string that is really a long, must be verified before
// it is used. That check is what isolates the endpoint. Pure functions only,
// no I/O: the same module runs in the browser and in Node.

export const MAX_SAFE = 9007199254740991n; // 2^53 - 1

const SOURCES = [
  /\breq(?:uest)?\s*\.\s*(?:query|params|body|args|form|values|json|cookies|headers|GET|POST)\b/,
  /\bprocess\s*\.\s*(?:env|argv)\b/,
  /\bos\s*\.\s*(?:environ|getenv)\b/,
  /\bsys\s*\.\s*argv\b/,
  /\binput\s*\(/,
  /\bprompt\s*\(/,
  /\blocation\s*\.\s*(?:search|hash)\b/,
  /\bURLSearchParams\b|\bsearchParams\s*\.\s*get\b/,
  /\bgetParameter\s*\(|\bgetHeader\s*\(|\bgetenv\s*\(|\bargv\s*\[/,
  /\bFormValue\s*\(|\bURL\s*\.\s*Query\s*\(\)|\bPathValue\s*\(|\bos\s*\.\s*Args\b/,
  /\bscanf\s*\(|\bfgets\s*\(|\bgets\s*\(/,
  /\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters)\b/,
  /\bctx\s*\.\s*(?:params|query|request)\b/,
  /\bargs\s*\[\s*\d+\s*\]/,
];

const GATE_CALL = /\b(?:verifyLong|verify_long|LockerGate\s*\.\s*verifyLong|lockerVerifyInt64|lockerVerifyInt|locker_verify_long)\s*\(/;
// Signs that a value was checked before use.
const VERIFY_HINTS = [
  GATE_CALL,
  /Number\s*\.\s*isSafeInteger\s*\(/,
  /\.\s*test\s*\(/, /\bfullmatch\s*\(/, /\bre\s*\.\s*match\s*\(/, /\.\s*isdigit\s*\(\s*\)/, /\.\s*isdecimal\s*\(\s*\)/,
  /\bmatches\s*\(\s*"/, /\bexcept\s+(?:\(?\s*ValueError|OverflowError)/, /\bcatch\s*\(\s*NumberFormatException/,
  /\berr\s*!=\s*nil\b/, /\berrno\b/, /\bendptr\b|\bend\s*==\s*/, /\bisNaN\s*\(/, /\bNumber\s*\.\s*isInteger\s*\(/,
];

export function detectLanguage(name = '', source = '') {
  const ext = (name.match(/\.([a-z0-9]+)$/i) || [])[1]?.toLowerCase();
  const byExt = { js: 'js', mjs: 'js', cjs: 'js', jsx: 'js', ts: 'js', tsx: 'js', py: 'python', java: 'java', kt: 'java', go: 'go', c: 'c', h: 'c', cc: 'c', cpp: 'c' };
  if (ext && byExt[ext]) return byExt[ext];
  if (/^\s*package\s+\w+\s*$/m.test(source) && /\bfunc\b/.test(source)) return 'go';
  if (/#include\s*</.test(source)) return 'c';
  if (/\bpublic\s+(?:static\s+)?(?:class|void)\b/.test(source)) return 'java';
  if (/^\s*(?:def |import |from \S+ import )/m.test(source) && !/[{};]\s*$/m.test(source.split('\n').find(l => /def /.test(l)) || '')) return 'python';
  return 'js';
}

const ARG = String.raw`((?:[^,()]|\((?:[^()]|\([^()]*\))*\))+)`; // one argument, up to two levels of nested calls
const ARGS = String.raw`((?:[^()]|\((?:[^()]|\([^()]*\))*\))+)`;
const P = (head, tail = '') => new RegExp(String.raw`\b(?:${head})\s*\(\s*` + ARG + tail + String.raw`\)`, 'g');
const PARSERS = {
  js: [P('parseInt', String.raw`(?:,\s*\d+\s*)?`), P('Number'), P('BigInt'), P('parseFloat')].map((re) => ({ re, kind: 'parse' })),
  python: [{ re: new RegExp(String.raw`\bint\s*\(\s*` + ARGS + String.raw`\)`, 'g'), kind: 'parse' }],
  java: [{ re: P(String.raw`Long\s*\.\s*(?:parseLong|valueOf)|Integer\s*\.\s*(?:parseInt|valueOf)|new\s+BigInteger`), kind: 'parse' }],
  go: [{ re: P(String.raw`strconv\s*\.\s*(?:Atoi|ParseInt|ParseUint)`, String.raw`(?:,[^)]*)?`), kind: 'parse' }],
  c: [{ re: P('atoi|atol|atoll|strtol|strtoll|strtoul|strtoull', String.raw`(?:,[^)]*)?`), kind: 'parse' }],
};

const ASSIGN = {
  js: /^\s*(?:const|let|var)\s+(?:\{([^}]+)\}|([A-Za-z_$][\w$]*))\s*=\s*(.+)$/,
  python: /^\s*([A-Za-z_]\w*)\s*(?::\s*\w+)?\s*=\s*(.+)$/,
  java: /^\s*(?:final\s+)?[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*=\s*(.+)$/,
  go: /^\s*([A-Za-z_]\w*)(?:\s*,\s*([A-Za-z_]\w*))?\s*:?=\s*(.+)$/,
  c: /^\s*(?:const\s+)?(?:unsigned\s+)?(?:char\s*\*|long long|long|int|int64_t|size_t)\s*\*?\s*([A-Za-z_]\w*)\s*=\s*(.+)$/,
};

const isSource = (expr) => SOURCES.some((r) => r.test(expr));
const ID_NAME = /(?:^|[._\[\s'"])(?:\w*_?id|\w*Id|snowflake|account|order|tweet|user|serial|nonce|amount|balance)\b/i;
const strip = (s, lang) => lang === 'python' ? s.replace(/(^|\s)#.*$/, '$1') : s.replace(/(^|\s)\/\/.*$/, '$1');

function varsIn(expr) { return new Set((expr.match(/[A-Za-z_$][\w$]*/g) || [])); }

/**
 * Check one source file. Returns { language, verdict, findings }.
 * verdict: 'Safe' | 'Not safe'. Findings carry line (1-based), rule, message, fix.
 */
export function check(source, name = 'pasted') {
  const language = detectLanguage(name, source);
  const lines = source.split(/\r?\n/);
  const tainted = new Map(); // var -> line where it was tainted
  const verified = new Set();
  const findings = [];
  const near = (i, span = 3) => lines.slice(Math.max(0, i - span), Math.min(lines.length, i + span + 1)).join('\n');

  lines.forEach((raw, i) => {
    const line = strip(raw, language);
    if (!line.trim()) return;
    // verification of a named variable anywhere marks it verified from here on
    for (const v of tainted.keys()) {
      const vre = new RegExp(`\\b${v.replace(/\$/g, '\\$')}\\b`);
      if (vre.test(line) && VERIFY_HINTS.some((h) => h.test(line)) && !new RegExp(`^\\s*(?:const|let|var)?\\s*${v}\\s*=`).test(line)) verified.add(v);
    }
    const am = line.match(ASSIGN[language]);
    if (am) {
      const names = language === 'js' ? (am[1] ? am[1].split(',').map((s) => s.split(':').pop().trim()) : [am[2]]) : language === 'go' ? [am[1]] : [am[1]];
      const rhs = am[am.length - 1];
      const rhsTainted = isSource(rhs) || [...varsIn(rhs)].some((v) => tainted.has(v) && !verified.has(v));
      for (const n of names) {
        if (!n) continue;
        if (GATE_CALL.test(rhs)) { verified.add(n); tainted.delete(n); continue; }
        if (rhsTainted && !PARSERS[language].some((p) => new RegExp(p.re.source).test(rhs))) { tainted.set(n, i + 1); verified.delete(n); }
      }
    }
    // parse calls on external strings
    for (const p of PARSERS[language]) {
      for (const m of line.matchAll(p.re)) {
        const arg = m[1].trim();
        if (GATE_CALL.test(m[0])) continue;
        const fromSource = isSource(arg);
        const fromVar = [...varsIn(arg)].find((v) => tainted.has(v) && !verified.has(v));
        if (!fromSource && !fromVar) continue;
        const ctx = near(i);
        let guarded = VERIFY_HINTS.some((h) => h.test(ctx.replace(m[0], '')));
        if (language === 'go' && /,\s*_\s*:?=/.test(line)) guarded = false;
        if (language === 'c' && /\bato(?:i|l|ll)\s*\(/.test(m[0])) guarded = false;
        if (guarded) continue;
        findings.push({
          line: i + 1, col: m.index + 1, rule: 'unverified-long', severity: 'Not safe', match: m[0],
          message: `${fromSource ? 'External string' : `"${fromVar}" (external, line ${tainted.get(fromVar)})`} is turned into a long by ${m[0].split('(')[0].trim()}() without verification. A malformed or out-of-range value reaches the endpoint.`,
          fix: 'insert-gate',
        });
      }
    }
    // JS precision loss: long digit literals and Number()/parseInt on id-like values
    if (language === 'js') {
      for (const m of line.matchAll(/(?<![\w."'`])(\d{16,})(?![\w"'`n])/g)) {
        if (BigInt(m[1]) > MAX_SAFE) findings.push({ line: i + 1, col: m.index + 1, rule: 'long-literal', severity: 'Not safe', match: m[1], message: `Literal ${m[1]} is above 2^53-1. As a JS number it is silently rounded to ${Number(m[1])}.`, fix: 'bigint-literal' });
      }
      for (const m of line.matchAll(/\bJSON\s*\.\s*parse\s*\(([^)]*)\)/g)) {
        if (ID_NAME.test(line) || /\bid\b/i.test(near(i, 2))) findings.push({ line: i + 1, col: m.index + 1, rule: 'json-long', severity: 'Review', match: m[0], message: 'JSON.parse turns long ids into rounded numbers. Keep ids as strings and verify them with verifyLong() before use.', fix: null });
      }
    }
    // tainted value interpolated straight into an endpoint, path or query
    const endpoint = line.match(/(`[^`]*\$\{\s*([^}]+?)\s*\}[^`]*`)|(f["'][^"']*\{([^}]+)\}[^"']*["'])|(["'][^"']*\/["']\s*\+\s*([\w$.\[\]'"]+))/);
    if (endpoint) {
      const expr = (endpoint[2] || endpoint[4] || endpoint[6] || '').trim();
      const tpl = endpoint[1] || endpoint[3] || endpoint[5] || '';
      const looksEndpoint = /\/|SELECT|INSERT|UPDATE|DELETE|WHERE|http|:\/\//i.test(tpl);
      const bad = expr && !GATE_CALL.test(expr) && (isSource(expr) || [...varsIn(expr)].some((v) => tainted.has(v) && !verified.has(v)));
      if (looksEndpoint && bad && !VERIFY_HINTS.some((h) => h.test(near(i, 2)))) {
        findings.push({ line: i + 1, col: (endpoint.index || 0) + 1, rule: 'unverified-endpoint', severity: 'Not safe', match: expr, message: `"${expr}" goes into an endpoint (${tpl.slice(0, 40)}${tpl.length > 40 ? '…' : ''}) without being verified as a long. The endpoint is not isolated.`, fix: 'insert-gate' });
      }
    }
  });
  findings.sort((a, b) => a.line - b.line || a.col - b.col);
  const verdict = findings.some((f) => f.severity === 'Not safe') ? 'Not safe' : findings.length ? 'Review' : 'Safe';
  return { name, language, verdict, findings, lines: lines.length };
}

const GATES = {
  js: `// Locker gate: verify a long before use. Fails closed.
function verifyLong(value, { min = 0n, max = 9223372036854775807n } = {}) {
  const s = String(value ?? '').trim();
  if (!/^-?\\d{1,19}$/.test(s)) throw new RangeError('Locker: not a verified long: ' + JSON.stringify(s.slice(0, 32)));
  const n = BigInt(s);
  if (n < BigInt(min) || n > BigInt(max)) throw new RangeError('Locker: long out of range');
  return n <= 9007199254740991n && n >= -9007199254740991n ? Number(n) : n;
}
`,
  python: `# Locker gate: verify a long before use. Fails closed.
def verify_long(value, lo=0, hi=2**63 - 1):
    import re as _re
    s = str(value if value is not None else "").strip()
    if not _re.fullmatch(r"-?\\d{1,19}", s):
        raise ValueError("Locker: not a verified long: %r" % s[:32])
    n = int(s)
    if not lo <= n <= hi:
        raise ValueError("Locker: long out of range")
    return n
`,
  java: `
// Locker gate: verify a long before use. Fails closed.
final class LockerGate {
    private LockerGate() {}
    static long verifyLong(String value) {
        String s = value == null ? "" : value.trim();
        if (!s.matches("-?\\\\d{1,19}")) throw new IllegalArgumentException("Locker: not a verified long");
        long n = Long.parseLong(s); // safe: format verified above
        if (n < 0) throw new IllegalArgumentException("Locker: long out of range");
        return n;
    }
}
`,
  go: `
// Locker gate: verify a long before use. Fails closed.
func lockerVerifyInt64(s string) (int64, error) {
	if len(s) == 0 || len(s) > 19 {
		return 0, fmt.Errorf("locker: not a verified long")
	}
	for i, r := range s {
		if (r < '0' || r > '9') && !(i == 0 && r == '-') {
			return 0, fmt.Errorf("locker: not a verified long")
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func lockerVerifyInt(s string) (int, error) {
	n, err := lockerVerifyInt64(s)
	return int(n), err
}

func lockerMust(err error) {
	if err != nil {
		panic(err) // a failed check never reaches the endpoint
	}
}
`,
  c: `
/* Locker gate: verify a long before use. Fails closed. */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
static long long locker_verify_long(const char *s) {
    char *end = NULL;
    if (s == NULL || *s == '\\0') { fprintf(stderr, "locker: not a verified long\\n"); exit(2); }
    errno = 0;
    long long n = strtoll(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\\0') { fprintf(stderr, "locker: not a verified long\\n"); exit(2); }
    return n;
}
`,
};

/** Insert gate: local, deterministic rewrite of unsafe spots. Returns { source, changed }. */
export function insertGate(source, name = 'pasted') {
  const result = check(source, name);
  const { language } = result;
  const lines = source.split(/\r?\n/);
  let changed = 0;
  const gateName = { js: 'verifyLong', python: 'verify_long', java: 'LockerGate.verifyLong', go: 'lockerVerifyInt', c: 'locker_verify_long' }[language];
  const byLine = new Map();
  for (const f of result.findings) if (f.fix) (byLine.get(f.line) || byLine.set(f.line, []).get(f.line)).push(f);
  const goMust = [];
  for (const [ln, fs] of byLine) {
    let l = lines[ln - 1];
    for (const f of fs) {
      if (f.rule === 'unverified-long') {
        let arg = f.match.slice(f.match.indexOf('(') + 1, -1);
        if (language !== 'python' && language !== 'java') arg = arg.replace(/,\s*\d+\s*$/, '').replace(/,\s*&?\w+\s*,\s*\d+\s*$/, '').replace(/,\s*(?:NULL|0)\s*,\s*\d+\s*$/, '');
        if (language === 'go') {
          const g = /ParseInt|ParseUint/.test(f.match) ? 'lockerVerifyInt64' : 'lockerVerifyInt';
          arg = arg.split(',')[0];
          l = l.replace(f.match, `${g}(${arg.trim()})`);
          if (/,\s*_\s*(:?=)/.test(l)) { l = l.replace(/,\s*_\s*(:?=)/, ', lockerErr $1'); goMust.push(ln); }
        } else {
          l = l.replace(f.match, `${gateName}(${arg.trim()})`);
        }
        changed++;
      } else if (f.rule === 'unverified-endpoint' && (language === 'js' || language === 'python')) {
        const e = f.match.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = language === 'js' ? new RegExp(`\\$\\{\\s*${e}\\s*\\}`) : new RegExp(`\\{\\s*${e}\\s*\\}`);
        if (re.test(l)) { l = l.replace(re, language === 'js' ? `\${${gateName}(${f.match})}` : `{${gateName}(${f.match})}`); changed++; }
        else { const plus = new RegExp(`\\+\\s*${e}`); if (plus.test(l)) { l = l.replace(plus, `+ ${gateName}(${f.match})`); changed++; } }
      }
    }
    lines[ln - 1] = l;
  }
  for (const f of result.findings) {
    if (f.rule === 'long-literal' && language === 'js') {
      lines[f.line - 1] = lines[f.line - 1].replace(new RegExp(`(?<![\\w."'\`])${f.match}(?![\\w"'\`n])`), `${f.match}n`);
      changed++;
    }
  }
  for (const ln of goMust.sort((a, b) => b - a)) {
    const indent = lines[ln - 1].match(/^\s*/)[0];
    lines.splice(ln, 0, `${indent}lockerMust(lockerErr)`);
  }
  if (!changed) return { source, changed: 0 };
  let out = lines.join('\n');
  const usesGate = new RegExp(gateName.replace('.', '\\.') + '|lockerVerifyInt').test(out);
  const hasGate = /function verifyLong|def verify_long|class LockerGate|func lockerVerifyInt64|locker_verify_long\(const/.test(out);
  if (usesGate && !hasGate) out = placeGate(out, language);
  return { source: out, changed };
}

function placeGate(src, language) {
  const gate = GATES[language];
  const lines = src.split('\n');
  if (language === 'java' || language === 'go') {
    if (language === 'go' && !/"fmt"/.test(src)) src = src.replace(/import\s*\(/, 'import (\n\t"fmt"').replace(/import\s+"([^"]+)"/, 'import (\n\t"fmt"\n\t"$1"\n)');
    if (language === 'go' && !/"strconv"/.test(src)) src = src.replace(/import\s*\(/, 'import (\n\t"strconv"');
    return src.replace(/\s*$/, '\n') + gate;
  }
  // after imports / includes / shebang
  let at = 0;
  const head = language === 'python' ? /^(?:#!|from\s|import\s|\s*$|#)/ : language === 'c' ? /^(?:#include|\s*$)/ : /^(?:#!|import\s|['"]use strict|\s*$|const\s+\w+\s*=\s*require\()/;
  while (at < lines.length && head.test(lines[at])) at++;
  while (at > 0 && !lines[at - 1].trim()) at--;
  lines.splice(at, 0, (at ? '\n' : '') + gate);
  return lines.join('\n');
}

// ---- the known stamp (residual rule) ----
// Four cases only: null and zero-b are -1, aligned 1 is 0, aligned 3 is 2.
export function knownStamp(b, aligned) {
  if (b === null || b === undefined) return -1;
  if (Number(b) === 0) return -1;
  if (aligned === 1) return 0;
  if (aligned === 3) return 2;
  throw new RangeError('known stamp: only null, zero-b, aligned 1 and aligned 3 are defined');
}

/** Residual store: open parallel and every long goes out of date; read refuses. Close parallel and residuals refresh. */
export class ResidualStore {
  constructor() { this.values = new Map(); this.parallel = false; this.generation = 0; }
  write(key, b, aligned) { this.values.set(key, { b, aligned, stamp: knownStamp(b, aligned), gen: this.generation }); }
  openParallel() { this.parallel = true; this.generation++; }
  closeParallel() { this.parallel = false; for (const [k, v] of this.values) this.values.set(k, { ...v, stamp: knownStamp(v.b, v.aligned), gen: this.generation }); }
  read(key) {
    const v = this.values.get(key);
    if (!v) throw new Error('known stamp: no such residual');
    if (this.parallel || v.gen !== this.generation) throw new Error('Not safe: residual out of date (parallel open)');
    return v.stamp;
  }
}

export function summarize(results) {
  const notSafe = results.filter((r) => r.verdict === 'Not safe').length;
  return { files: results.length, notSafe, findings: results.reduce((a, r) => a + r.findings.length, 0), verdict: notSafe ? 'Not safe' : results.some((r) => r.verdict === 'Review') ? 'Review' : 'Safe' };
}
