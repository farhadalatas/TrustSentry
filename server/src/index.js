const express = require('express');
const cors = require('cors');
const { randomUUID } = require('node:crypto');

const { validateTarget } = require('./lib/scope.js');
const { Run, BudgetError, RunStoppedError } = require('./lib/runner.js');
const { runRecon } = require('./modules/recon.js');
const { runBruteforce } = require('./modules/bruteforce.js');
const { runOtp } = require('./modules/otp.js');
const { runInjection } = require('./modules/injection.js');
const { runSession, decodeJwt } = require('./modules/session.js');
const { runFuzz } = require('./modules/fuzz.js');
const { runLogic } = require('./modules/logic.js');
const { runScan, TOOLS } = require('./modules/cli.js');
const { renderReport, renderHtml } = require('./modules/reporting.js');
const { persistRun, listRuns, getRun } = require('./lib/store.js');
const { getCatalog, recommendTools } = require('./modules/catalog.js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// In-memory registry of active runs (single-user local tool).
const runs = new Map();

app.get('/api/health', (_req, res) => res.json({ ok: true, now: new Date().toISOString() }));

app.post('/api/runs', async (req, res) => {
  const cfg = req.body || {};

  // Hard guardrail: user must explicitly confirm authorized/own scope.
  if (cfg.authorized !== true) {
    return res.status(422).json({
      error: { code: 'AUTH_REQUIRED', message: 'Konfirmasi otorisasi wajib (authorized: true). Hanya untuk target yang lo pegang izinnya.' },
    });
  }

  let target;
  try {
    target = await validateTarget(cfg.target, { allowPrivate: cfg.allowPrivate });
  } catch (e) {
    return res.status(400).json({ error: { code: 'TARGET_INVALID', message: e.message } });
  }

  const runId = randomUUID().slice(0, 12);
  const run = new Run(runId, cfg);
  run.target = target;
  run.cfg = cfg;
  runs.set(runId, run);

  // Persist events so late SSE subscribers can replay the run history.
  run._history = [];
  run.on('event', (ev) => { run._history.push(ev); });

  res.status(202).json({ runId });

  //Execute in background without blocking the response.
  executeRun(run, cfg).catch((err) => {
    run.addFinding({
      type: 'run-error',
      severity: 'INFO',
      title: 'Run gagal: ' + err.message,
      evidence: { error: err.message },
    });
    run.emitEvent('error', { message: err.message });
  });
});

async function executeRun(run, cfg) {
  run.emitEvent('start', { runId: run.runId, target: cfg.target });
  const ctx = {
    target: run.target,
    config: cfg,
    findings: run.findings,
    emitEvent: run.emitEvent.bind(run),
    addFinding: run.addFinding.bind(run),
    http: run.http.bind(run),
    cfg,
  };

  for (const m of cfg.modules || []) {
    try {
      switch (m) {
        case 'recon': await runRecon(ctx, cfg); break;
        case 'bruteforce': await runBruteforce(ctx, cfg); break;
        case 'otp': await runOtp(ctx, cfg); break;
        case 'injection': await runInjection(ctx, cfg); break;
        case 'session': await runSession(ctx, cfg); break;
        case 'fuzz': await runFuzz(ctx, cfg); break;
        case 'logic': await runLogic(ctx, cfg); break;
        case 'cli': await runCli(ctx, cfg); break;
        default: run.emitEvent('warn', { message: `module tak dikenal: ${m}` });
      }
    } catch (e) {
      if (e instanceof BudgetError || e instanceof RunStoppedError) {
        run.emitEvent('warn', { message: e.message });
      } else {
        console.error(`[module ${m} ERROR]`, e);
        run.emitEvent('error', { module: m, message: e.message });
      }
    }
  }

  const { summarize } = require('./modules/reporting.js');
  const summary = summarize(run.findings);
  persistRun(run.runId, {
    target: cfg.target,
    requests: run.requests,
    findings: run.findings,
    summary,
    finishedAt: new Date().toISOString(),
  });
  await run.finish({ counts: summary, modules: cfg.modules || [] });
}

async function runCli(ctx, cfg) {
  ctx.emitEvent('module', { name: 'cli', label: 'CLI tool: ' + (cfg.cli && cfg.cli.toolName || 'nmap') });
  ctx.emitEvent('progress', { note: 'Menjalankan CLI tool...' });
  const res = await runScan(ctx, cfg.cli || {});
  ctx.addFinding({
    type: 'cli-output',
    severity: 'INFO',
    title: `Output ${cfg.cli && cfg.cli.toolName}: exit ${res.code}`,
    evidence: { exitCode: res.code, output: res.output },
    recommendation: 'Analisis output di atas untuk konfirmasi temuan.',
  });
}

/** SSE endpoint: live-stream events of a run. */
app.get('/api/runs/:id/stream', (req, res) => {
  const run = runs.get(req.params.id);
  if (!run) return res.status(404).end();
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.write(`retry: 2000\n\n`);
  for (const ev of run._history) res.write(`data: ${JSON.stringify(ev)}\n\n`);

  const listener = (ev) => { res.write(`data: ${JSON.stringify(ev)}\n\n`); };
  run.on('event', listener);
  req.on('close', () => run.off('event', listener));
});

app.get('/api/runs/:id', (req, res) => {
  const run = runs.get(req.params.id);
  if (!run) return res.status(404).json({ error: { code: 'NOT_FOUND' } });
  const { summarize } = require('./modules/reporting.js');
  res.json({
    runId: run.runId,
    requests: run.requests,
    finished: run.finished,
    findings: run.findings,
    summary: summarize(run.findings),
  });
});

app.post('/api/runs/:id/stop', (req, res) => {
  const run = runs.get(req.params.id);
  if (!run) return res.status(404).end();
  run.stopRequested = true;
  res.json({ stopped: true });
});

app.get('/api/history', (_req, res) => {
  res.json({ runs: listRuns() });
});

app.get('/api/history/:id', (req, res) => {
  const run = getRun(req.params.id);
  if (!run) return res.status(404).json({ error: { code: 'NOT_FOUND' } });
  res.json(run);
});

app.get('/api/runs/:id/report', (req, res) => {
  const run = runs.get(req.params.id);
  if (!run) return res.status(404).end();
  const meta = { target: run.cfg.target, date: new Date().toISOString() };
  if (req.query.format === 'html') {
    res.type('html').send(renderHtml(run.findings, meta));
  } else {
    res.type('json').send(renderReport(run.findings, meta));
  }
});

app.post('/api/jwt/decode', (req, res) => {
  const jwt = decodeJwt(req.body && req.body.token);
  if (!jwt) return res.status(400).json({ error: { code: 'JWT_INVALID' } });
  res.json(jwt);
});

app.get('/api/tools', async (_req, res) => {
  res.json({ tools: TOOLS });
});

app.get('/api/catalog', async (_req, res) => {
  try {
    res.json(await getCatalog());
  } catch (e) {
    res.status(500).json({ error: { code: 'CATALOG_ERROR', message: e.message } });
  }
});

app.get('/api/recommend', async (req, res) => {
  try {
    const { tools } = await getCatalog();
    const out = recommendTools(req.query.q || '', tools);
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: { code: 'RECOMMEND_ERROR', message: e.message } });
  }
});

const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || '127.0.0.1';
app.listen(PORT, HOST, () => {
  console.log(`[trustsentry] server listening on http://${HOST}:${PORT}`);
});