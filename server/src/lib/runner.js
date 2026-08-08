const { EventEmitter } = require('node:events');
const { request } = require('./http.js');

class RunStoppedError extends Error {
  constructor() {
    super('RUN_STOPPED');
    this.name = 'RunStoppedError';
  }
}

class BudgetError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BudgetError';
  }
}

const DEFAULTS = {
  maxRequests: 200,
  minDelayMs: 150,
  concurrency: 1,
};

class Run extends EventEmitter {
  constructor(runId, config = {}) {
    super();
    this.runId = runId;
    this.config = config;
    this.requests = 0;
    this.startedAt = Date.now();
    this.finished = false;
    this.stopRequested = false;
    this.findings = [];
    const budget = config.budget || {};
    this.maxRequests = budget.maxRequests ?? DEFAULTS.maxRequests;
    this.minDelayMs = budget.minDelayMs ?? DEFAULTS.minDelayMs;
  }

  emitEvent(type, data) {
    const event = { ts: new Date().toISOString(), type, data };
    this.emit('event', event);
  }

  addFinding(raw) {
    const finding = {
      type: raw.type || raw.typeId || 'finding',
      severity: raw.severity || raw.sev || 'INFO',
      title: raw.title || '',
      evidence: raw.evidence,
      recommendation: raw.recommendation,
    };
    this.findings.push(finding);
    this.emitEvent('finding', finding);
    return finding;
  }

  /** Bounded HTTP request that respects global budget + rate. */
  async http({ url, ...opts }) {
    if (this.stopRequested) {
      throw new RunStoppedError();
    }
    this.requests += 1;
    if (this.requests > this.maxRequests) {
      throw new BudgetError(
        `BUDGET_EXCEEDED: global budget ${this.maxRequests} request terlampaui`
      );
    }
    if (this.minDelayMs > 0) {
      await new Promise((r) => setTimeout(r, this.minDelayMs));
    }
    this.emitEvent('request', { n: this.requests, url, method: opts.method || 'GET' });
    const res = await request({ url, ...opts });
    return res;
  }

  async finish(summary) {
    this.finished = true;
    this.emitEvent('done', {
      runId: this.runId,
      durationMs: Date.now() - this.startedAt,
      requests: this.requests,
      findings: this.findings,
      summary,
    });
  }
}

module.exports = { Run, RunStoppedError, BudgetError, DEFAULTS };