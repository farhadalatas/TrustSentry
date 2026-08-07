/**
 * Minimal HTTP client with timeout, TLS bypass, and raw response capture.
 * Uses Node 18+ global fetch. Errors are normalized so modules can react.
 */
class HttpError extends Error {
  constructor(status, bodyText, info) {
    super(`HTTP ${status}`);
    this.status = status;
    this.bodyText = bodyText;
    this.info = info;
  }
}

async function request({
  url,
  method = 'GET',
  headers = {},
  body,
  timeoutMs = 8000,
  allowRedirect = false,
  raw = false,
}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await fetch(url, {
      method,
      headers,
      body: body == null ? undefined : body,
      signal: controller.signal,
      redirect: allowRedirect ? 'follow' : 'manual',
    });
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      return { ok: false, timedOut: true, status: 0, info: {} };
    }
    return { ok: false, timedOut: false, status: 0, info: {} };
  }
  clearTimeout(timer);

  const buf = await res.arrayBuffer().catch(() => Buffer.alloc(0));
  const bodyText = raw ? Buffer.from(buf).toString('binary') : Buffer.from(buf).toString('utf8');

  return {
    ok: res.ok,
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
    body: bodyText,
    timedOut: false,
    url: res.url,
    info: { redirected: res.redirected },
  };
}

module.exports = { request, HttpError };