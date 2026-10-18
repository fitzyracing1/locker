// Optional, pluggable AI fixer. Locker works without it: callers fall back to insertGate.
export function buildPrompt(source, findings, language) {
  const list = findings.map((f) => `- line ${f.line} [${f.rule}]: ${f.message}`).join('\n');
  return [
    { role: 'system', content: 'You fix code so that every long integer, or string that is really a long, is verified (format and range) before it is used, so a failed check never reaches an endpoint. Fail closed. Keep behavior otherwise identical. Reply with only the full rewritten file in one fenced code block.' },
    { role: 'user', content: `Language: ${language}\nLocker findings:\n${list}\n\nFile:\n\`\`\`\n${source}\n\`\`\`` },
  ];
}

export function extractCode(text) {
  const m = String(text || '').match(/```[\w+-]*\n([\s\S]*?)```/);
  return (m ? m[1] : String(text || '')).replace(/\s*$/, '\n');
}

/** Returns rewritten source or null when no provider is configured / it fails. */
export async function aiFix(source, findings, language, cfg = {}, fetchImpl = globalThis.fetch) {
  if (globalThis.LockerAI && typeof globalThis.LockerAI.fix === 'function') {
    const out = await globalThis.LockerAI.fix(source, findings, language);
    return out ? extractCode(out) : null;
  }
  if (!cfg.url) return null;
  const res = await fetchImpl(cfg.url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(cfg.key ? { authorization: `Bearer ${cfg.key}` } : {}) },
    body: JSON.stringify({ model: cfg.model || undefined, temperature: 0, messages: buildPrompt(source, findings, language) }),
  });
  if (!res.ok) throw new Error(`AI endpoint answered ${res.status}`);
  const data = await res.json();
  const text = data?.choices?.[0]?.message?.content ?? data?.output_text ?? '';
  return text ? extractCode(text) : null;
}
