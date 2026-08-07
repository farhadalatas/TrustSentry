const API = '/api';

async function post(path, body) {
  const res = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data.error && data.error.message) || `HTTP ${res.status}`);
  return data;
}

function streamRun(runId, handlers) {
  const es = new EventSource(`${API}/runs/${runId}/stream`);
  es.onmessage = (msg) => {
    try {
      handlers.onEvent(JSON.parse(msg.data));
    } catch {
      /* ignore malformed */
    }
  };
  es.onerror = () => es.close();
  return () => es.close();
}

export { post, streamRun, API };