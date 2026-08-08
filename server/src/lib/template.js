/** Deep-substitute placeholders in a JSON body template.
 *  Vars keys sudah berupa placeholder lengkap, mis. '<USER>', '<PASS>', '<OTP>'. */
function applyTemplate(template, vars = {}) {
  if (template == null) return template;
  if (typeof template === 'string') {
    let out = template;
    for (const [k, v] of Object.entries(vars)) {
      out = out.split(k).join(v);
    }
    return out;
  }
  if (Array.isArray(template)) return template.map((x) => applyTemplate(x, vars));
  if (typeof template === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(template)) {
      const nk = typeof k === 'string' ? applyTemplate(k, vars) : k;
      out[nk] = applyTemplate(v, vars);
    }
    return out;
  }
  return template;
}

/** Return a stable sign of a response body (for diff-based detection). */
function fingerprint(res) {
  const body = typeof res.body === 'string' ? res.body : String(res.body);
  const status = res.status || 0;
  const loc = (res.headers && res.headers.location) || '';
  return `${status}|${(loc || '').slice(0, 60)}|${(body || '').slice(0, 80)}`;
}

module.exports = { applyTemplate, fingerprint };