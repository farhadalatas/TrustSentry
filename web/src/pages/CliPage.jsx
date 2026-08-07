import { useState } from 'react';
import { post } from '../lib/api.js';

export default function CliPage({ config, onRun, running }) {
  const [tool, setTool] = useState('nmap');
  const [ports, setPorts] = useState('80,443,22,3000,8080');

  function launch() {
    onRun({ ...config, modules: ['cli'], cli: { toolName: tool, ports } });
  }

  return (
    <div className="card">
      <h2>CLI Tools (Kali-style)</h2>
      <p className="note">
        Backend menjalankan binary CLI di mesin ini. Pastikan tool terinstall:
        <code> sudo apt install nmap nuclei nikto sqlmap hydra </code>
      </p>
      <label>Tool</label>
      <select value={tool} onChange={(e) => setTool(e.target.value)}>
        <option value="nmap">nmap</option>
        <option value="nuclei">nuclei</option>
        <option value="nikto">nikto</option>
        <option value="sqlmap">sqlmap</option>
        <option value="hydra">hydra</option>
      </select>
      {tool === 'nmap' && (
        <label>Ports<input value={ports} onChange={(e) => setPorts(e.target.value)} /></label>
      )}
      <br />
      <button type="button" disabled={running} onClick={launch}>Jalankan {tool}</button>
      <p className="note">Hasil muncul di tab &#34;Hasil Live&#34;. Konfigurasi target & otorisasi harus terisi di tab Target.</p>
    </div>
  );
}