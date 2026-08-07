// Jalankan backend + frontend bersamaan di satu terminal. Ctrl+C untuk stop.
const { spawn } = require('node:child_process');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const procs = [];

function run(name, cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: 'inherit', env: { ...process.env, ...opts.env }, cwd: opts.cwd || ROOT });
  p.on('exit', (code) => {
    console.log(`[${name}] exit code ${code}`);
    shutdown();
  });
  procs.push(p);
}

function shutdown() {
  for (const p of procs) {
    try { p.kill('SIGTERM'); } catch {}
  }
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

console.log('==============================================');
console.log('  Auth Pentest Toolkit');
console.log('  Backend : http://localhost:4000');
console.log('  UI      : http://localhost:5173');
console.log('  Ctrl+C  untuk menghentikan keduanya');
console.log('==============================================');

run('backend', 'node', [path.join(ROOT, 'server/src/index.js')], { env: { PORT: '4000' } });
run('frontend', 'npm', ['run', 'dev', '--', '--port', '5173', '--host'], { cwd: path.join(ROOT, 'web') });