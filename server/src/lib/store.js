const fs = require('node:fs');
const path = require('node:path');

const DATA_DIR = path.join(__dirname, '..', '..', 'data');
const FILE = path.join(DATA_DIR, 'runs.json');

function load() {
  try {
    return JSON.parse(fs.readFileSync(FILE, 'utf8'));
  } catch {
    return {};
  }
}

let cache = load();
let dirty = false;

function saveSoon() {
  if (dirty) return;
  dirty = true;
  setImmediate(() => {
    dirty = false;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(FILE, JSON.stringify(cache, null, 2));
    } catch (err) {
      console.error('[store] gagal menyimpan:', err.message);
    }
  });
}

function persistRun(runId, { target, findings, summary, requests, finishedAt }) {
  cache[runId] = {
    runId,
    target,
    finishedAt: finishedAt || new Date().toISOString(),
    summary,
    requests,
    findings,
  };
  saveSoon();
}

function listRuns() {
  return Object.values(cache)
    .sort((a, b) => (b.finishedAt || '').localeCompare(a.finishedAt || ''))
    .map(({ runId, target, finishedAt, summary, requests }) => ({ runId, target, finishedAt, summary, requests }));
}

function getRun(runId) {
  return cache[runId] || null;
}

module.exports = { persistRun, listRuns, getRun };