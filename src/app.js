import { check, insertGate, ResidualStore, summarize } from './locker-core.js';
import { aiFix } from './ai.js';
import { lineDiff } from './diff.js';
import { SAMPLES } from '../samples/samples.js';

const $ = (id) => document.getElementById(id);
const code = $('code'), gutter = $('gutter'), fname = $('fname');
let files = [];          // { name, source, result }
let current = 0;
let pending = null;      // rewrite awaiting apply
const cls = (v) => (v === 'Not safe' ? 'ns' : v === 'Safe' ? 's' : v === 'Review' ? 'r' : '');
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

for (const n of Object.keys(SAMPLES)) $('sample').append(new Option(n, n));

function setFiles(list) { files = list.map((f) => ({ ...f, result: check(f.source, f.name) })); current = 0; show(); }
function cur() { return files[current]; }

function show() {
  const f = cur();
  code.value = f.source; fname.value = f.name;
  renderTabs(); analyze(false);
}

function renderTabs() {
  $('tabs').innerHTML = '';
  if (files.length < 2) return;
  files.forEach((f, i) => {
    const t = document.createElement('span');
    t.className = 'tab' + (i === current ? ' on' : '');
    t.innerHTML = `<span class="dot ${cls(f.result.verdict)}"></span>${esc(f.name)}`;
    t.onclick = () => { current = i; show(); };
    $('tabs').append(t);
  });
}

function analyze(fromEdit = true) {
  const f = cur();
  if (fromEdit) { f.source = code.value; f.name = fname.value || 'pasted'; }
  f.result = check(f.source, f.name);
  const r = f.result;
  $('lang').textContent = r.language;
  const bad = new Set(r.findings.map((x) => x.line));
  gutter.innerHTML = f.source.split('\n').map((_, i) => (bad.has(i + 1) ? `<span class="bad">${i + 1}</span>` : i + 1)).join('\n');
  const stamp = $('stamp');
  stamp.textContent = r.verdict; stamp.className = 'stamp ' + cls(r.verdict);
  const all = summarize(files.map((x) => x.result));
  const n = r.findings.filter((x) => x.severity === 'Not safe').length;
  $('summary').innerHTML = r.verdict === 'Safe'
    ? `<b>${esc(r.name)}</b>: every long-integer source is verified before use.<br>${files.length > 1 ? `${all.notSafe} of ${all.files} files not safe.` : ''}`
    : `<b>${esc(r.name)}</b>: ${n} unverified long source${n === 1 ? '' : 's'}${r.findings.length > n ? `, ${r.findings.length - n} to review` : ''}.<br>Endpoints are not isolated until each is verified.${files.length > 1 ? `<br>${all.notSafe} of ${all.files} files not safe.` : ''}`;
  $('findings').innerHTML = '';
  for (const x of r.findings) {
    const li = document.createElement('li');
    li.className = x.severity === 'Not safe' ? 'NotSafe' : 'Review';
    li.innerHTML = `<div class="meta">line ${x.line} · ${x.rule} · ${x.severity}</div><code>${esc(x.match)}</code><div>${esc(x.message)}</div>`;
    li.onclick = () => jump(x.line);
    $('findings').append(li);
  }
  $('gate').disabled = $('ai').disabled = !r.findings.some((x) => x.fix);
  renderTabs();
}

function jump(line) {
  const lines = code.value.split('\n');
  const start = lines.slice(0, line - 1).join('\n').length + (line > 1 ? 1 : 0);
  code.focus(); code.setSelectionRange(start, start + lines[line - 1].length);
  code.scrollTop = Math.max(0, (line - 4) * 19.5);
}

function proposeRewrite(next, title, note) {
  const f = cur();
  const before = f.result;
  const after = check(next, f.name);
  pending = next;
  $('fixbox').hidden = false;
  $('fixTitle').textContent = title;
  $('fixNote').textContent = note;
  const d = lineDiff(f.source, next);
  $('diff').innerHTML = d.filter((x, i) => x.t !== 'ctx' || d.slice(Math.max(0, i - 2), i + 3).some((y) => y.t !== 'ctx'))
    .map((x) => `<span class="${x.t}">${x.t === 'add' ? '+ ' : x.t === 'del' ? '- ' : '  '}${esc(x.s)}</span>`).join('');
  $('recheck').textContent = `Checked again: ${after.verdict} (${before.findings.length} → ${after.findings.length} findings)`;
  $('recheck').style.color = after.verdict === 'Safe' ? 'var(--green)' : 'var(--amber)';
}

$('gate').onclick = () => {
  const f = cur();
  const g = insertGate(f.source, f.name);
  proposeRewrite(g.source, 'Insert gate', `Local rewrite: ${g.changed} spot${g.changed === 1 ? '' : 's'} now go through a verify-long gate that fails closed.`);
};

function aiCfg() { try { return JSON.parse(localStorage.getItem('locker.ai') || '{}'); } catch { return {}; } }
function aiLabel() { const c = aiCfg(); $('aiSettings').textContent = globalThis.LockerAI ? 'AI: plugin' : c.url ? 'AI: on' : 'AI: off'; }
aiLabel();

$('ai').onclick = async () => {
  const f = cur();
  $('ai').textContent = 'Asking AI…'; $('ai').disabled = true;
  try {
    const out = await aiFix(f.source, f.result.findings, f.result.language, aiCfg());
    if (out) {
      const again = check(out, f.name);
      if (again.verdict === 'Safe') proposeRewrite(out, 'Fix with AI', 'AI rewrite, checked again by Locker.');
      else { const g = insertGate(out, f.name); proposeRewrite(g.source, 'Fix with AI + Insert gate', 'The AI rewrite still had unverified longs, so Locker added gates to it.'); }
    } else {
      const g = insertGate(f.source, f.name);
      proposeRewrite(g.source, 'Insert gate (AI off)', 'No AI endpoint is configured, so Locker did the same check locally. Configure one under "AI" if you want model rewrites.');
    }
  } catch (e) {
    const g = insertGate(f.source, f.name);
    proposeRewrite(g.source, 'Insert gate (AI did not answer)', `AI failed (${e.message}). Locker inserted gates locally instead.`);
  } finally { $('ai').textContent = 'Fix with AI'; $('ai').disabled = false; }
};

$('apply').onclick = () => { if (pending != null) { cur().source = pending; code.value = pending; pending = null; $('fixbox').hidden = true; analyze(); } };
$('discard').onclick = () => { pending = null; $('fixbox').hidden = true; };

let t;
code.addEventListener('input', () => { clearTimeout(t); t = setTimeout(analyze, 180); });
code.addEventListener('scroll', () => { gutter.scrollTop = code.scrollTop; });
fname.addEventListener('change', () => analyze());
code.addEventListener('keydown', (e) => { if (e.key === 'Tab') { e.preventDefault(); document.execCommand('insertText', false, '    '); } });

$('sample').onchange = (e) => { const n = e.target.value; if (n) setFiles([{ name: n, source: SAMPLES[n] }]); e.target.value = ''; };
$('files').onchange = async (e) => {
  const list = await Promise.all([...e.target.files].map(async (f) => ({ name: f.name, source: await f.text() })));
  if (list.length) setFiles(list);
};

// AI settings
$('aiSettings').onclick = () => { const c = aiCfg(); $('aiUrl').value = c.url || ''; $('aiModel').value = c.model || ''; $('aiKey').value = c.key || ''; $('aiDialog').showModal(); };
$('aiDialog').addEventListener('close', () => {
  const v = $('aiDialog').returnValue;
  if (v === 'save') localStorage.setItem('locker.ai', JSON.stringify({ url: $('aiUrl').value.trim(), model: $('aiModel').value.trim(), key: $('aiKey').value.trim() }));
  if (v === 'clear') localStorage.removeItem('locker.ai');
  aiLabel();
});

// Known stamp panel
const store = new ResidualStore();
const klog = (s) => { $('klog').textContent += s + '\n'; $('klog').scrollTop = 1e9; };
$('kwrite').onclick = () => {
  const raw = $('kb').value.trim();
  const b = raw === '' || raw === 'null' ? null : Number(raw);
  try { store.write('r', b, Number($('ka').value)); klog(`write b=${raw || 'null'} aligned=${$('ka').value} → stamp ${store.values.get('r').stamp}`); } catch (e) { klog('refused: ' + e.message); }
};
$('kpar').onclick = () => {
  if (store.parallel) { store.closeParallel(); $('kpar').textContent = 'Open parallel'; klog('parallel closed: residuals refreshed'); }
  else { store.openParallel(); $('kpar').textContent = 'Close parallel'; klog('parallel open: every long is out of date'); }
};
$('kread').onclick = () => { try { klog(`read → ${store.read('r')}`); } catch (e) { klog(e.message); } };

// Share card
$('share').onclick = () => {
  const r = cur().result;
  const c = document.createElement('canvas'); c.width = 1200; c.height = 630;
  const g = c.getContext('2d');
  g.fillStyle = '#0f1117'; g.fillRect(0, 0, 1200, 630);
  g.fillStyle = '#f2c14e'; g.font = '700 64px system-ui'; g.fillText('Locker', 80, 140);
  g.fillStyle = '#9097a8'; g.font = '30px system-ui'; g.fillText('Every long verified before use.', 80, 195);
  g.fillStyle = '#e8eaf0'; g.font = '34px ui-monospace, monospace'; g.fillText(`${r.name} · ${r.language}`, 80, 330);
  g.fillText(`${r.findings.length} finding${r.findings.length === 1 ? '' : 's'}`, 80, 385);
  g.save(); g.translate(860, 360); g.rotate(-0.12);
  const col = { 'Not safe': '#e5484d', Safe: '#3dd68c', Review: '#f5a524' }[r.verdict];
  g.strokeStyle = col; g.lineWidth = 10; g.strokeRect(-230, -80, 460, 160);
  g.fillStyle = col; g.font = '800 72px ui-monospace, monospace'; g.textAlign = 'center'; g.fillText(r.verdict.toUpperCase(), 0, 26);
  g.restore();
  const a = document.createElement('a'); a.download = 'locker-card.png'; a.href = c.toDataURL('image/png'); a.click();
};

const start = new URLSearchParams(location.search).get('sample') || 'express-orders.js';
setFiles([{ name: start, source: SAMPLES[start] || SAMPLES['express-orders.js'] }]);
if (new URLSearchParams(location.search).has('gate')) $('gate').click();
