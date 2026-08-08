/**
 * Minimal HTTP client with timeout and normalized error captures.
 * Uses Node 18+ global fetch.
 */
async function request({
  url,
  method = 'GET',
  headers = {},
  body,
  timeoutMs = 8000,
  allowRedirect = false,
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
    return {
      ok: false,
      timedOut: err.name === 'AbortError',
      status: 0,
      headers: {},
      body: '',
      info: {},
    };
  }
  clearTimeout(timer);

  const buf = await res.arrayBuffer().catch(() => Buffer.alloc(0));
  const bodyText = Buffer.from(buf).toString('utf8');

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

module.exports = { request };