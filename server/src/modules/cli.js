const { execFile, spawn } = require('node:child_process');

const TOOLS = [
  { name: 'nmap', bin: 'nmap', desc: 'Network/port discovery' },
  { name: 'sqlmap', bin: 'sqlmap', desc: 'SQL injection automation' },
  { name: 'hydra', bin: 'hydra', desc: 'Online brute-force' },
  { name: 'nuclei', bin: 'nuclei', desc: 'Template-based vuln scan' },
  { name: 'nikto', bin: 'nikto', desc: 'Web server scanner' },
];

function whichBin(bin) {
  return new Promise((resolve) => {
    execFile('which', [bin], (err, stdout) => resolve(err ? null : stdout.trim()));
  });
}

async function detectTools(ctx) {
  const status = [];
  for (const t of TOOLS) {
    status.push({ ...t, installed: !!(await whichBin(t.bin)) });
  }
  ctx.addFinding({
    type: 'cli-tooling',
    severity: 'INFO',
    title: 'Status tools CLI (Kali-style)',
    evidence: { tools: status },
    recommendation: 'Install tool yang dibutuhkan untuk module tambahan (sudo apt install ...).',
  });
  return status;
}

function runCli(tool, args, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    const child = spawn(tool, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, output: out.slice(0, 20000) });
    });
    child.on('error', (err) => reject(err));
  });
}

async function runScan(ctx, cfg) {
  const tool = cfg.toolName;
  const found = await whichBin(tool);
  if (!found) {
    throw new Error(`TOOL_NOT_FOUND: '${tool}' tidak terinstall. Jalankan 'sudo apt install ${tool}' atau gunakan module inti.`);
  }
  const args = buildArgs(tool, ctx.target.url, cfg);
  return runCli(tool, args, ctx.config.budget && ctx.config.budget.timeoutMs);
}

function buildArgs(tool, url, cfg) {
  const host = url.hostname;
  switch (tool) {
    case 'nmap': return ['-sV', '-p', cfg.ports || '80,443,22,3000,8080', host, '--max-retries=1'];
    case 'nuclei': return ['-u', url.toString(), '-severity', cfg.severity || 'high', '-silent', '-no-color'];
    case 'nikto': return ['-h', url.toString(), '-nointeractive', '-Tuning', 'x'];
    case 'sqlmap': return ['-u', url.toString(), '--batch', '--forms', '--level', '1', '--risk', '1', '--threads', '1'];
    case 'hydra': return ['-L', cfg.userWordlist || '/dev/null', '-P', cfg.passWordlist || '/dev/null', host, 'http-post-form', cfg.form || '/login:user=^USER^&pass=^PASS^:F=incorrect'];
    default: return [];
  }
}

module.exports = { detectTools, runScan, buildArgs, TOOLS };