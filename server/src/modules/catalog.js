const { execFile } = require('node:child_process');

// Katalog tool kategori legit (recon/web/testing). Kategori ofensif
// (phishing/RAT/payload/DoS/wireless/keylogger) SENGATI TIDAK disertakan.
const CATEGORIES = [
  { id: 'recon', label: 'Information Gathering' },
  { id: 'web', label: 'Web & Vulnerability' },
  { id: 'crack', label: 'Password / Hash Cracking' },
  { id: 'wordlist', label: 'Wordlist' },
  { id: 'exploit', label: 'Exploit Framework' },
  { id: 'reverse', label: 'Reverse Engineering' },
  { id: 'stegano', label: 'Steganography' },
  { id: 'forensic', label: 'Forensics / IR' },
  { id: 'ad', label: 'Active Directory' },
  { id: 'cloud', label: 'Cloud Security' },
  { id: 'mobile', label: 'Mobile Security' },
];

const TOOLS = [
  // recon
  { name: 'nmap', bin: 'nmap', category: 'recon', tags: ['recon', 'scan', 'network'], desc: 'Network & port discovery', install: 'apt install nmap' },
  { name: 'subfinder', bin: 'subfinder', category: 'recon', tags: ['recon', 'subdomain'], desc: 'Passive subdomain enumeration', install: 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' },
  { name: 'httpx', bin: 'httpx', category: 'recon', tags: ['recon', 'probe'], desc: 'HTTP probing / webserver detection', install: 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest' },
  { name: 'amass', bin: 'amass', category: 'recon', tags: ['recon', 'subdomain'], desc: 'In-depth subdomain enumeration', install: 'apt install amass' },
  { name: 'gobuster', bin: 'gobuster', category: 'recon', tags: ['recon', 'directory'], desc: 'Directory/brute-force fuzzing', install: 'apt install gobuster' },
  { name: 'dnsx', bin: 'dnsx', category: 'recon', tags: ['recon', 'dns'], desc: 'DNS resolution toolkit', install: 'go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest' },
  { name: 'whois', bin: 'whois', category: 'recon', tags: ['recon', 'osint'], desc: 'Domain WHOIS lookup', install: 'apt install whois' },
  { name: 'whatweb', bin: 'whatweb', category: 'recon', tags: ['recon', 'fingerprint'], desc: 'Web tech fingerprinting', install: 'apt install whatweb' },
  // web
  { name: 'nikto', bin: 'nikto', category: 'web', tags: ['web', 'scanner'], desc: 'Web server scanner', install: 'apt install nikto' },
  { name: 'nuclei', bin: 'nuclei', category: 'web', tags: ['web', 'template', 'cve'], desc: 'Template-based vuln scanner', install: 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' },
  { name: 'ffuf', bin: 'ffuf', category: 'web', tags: ['web', 'fuzz', 'directory'], desc: 'Fast web fuzzer', install: 'apt install ffuf' },
  { name: 'wpscan', bin: 'wpscan', category: 'web', tags: ['web', 'wordpress'], desc: 'WordPress scanner', install: 'apt install wpscan' },
  { name: 'sqlmap', bin: 'sqlmap', category: 'web', tags: ['web', 'sqli', 'injection'], desc: 'SQL injection automation', install: 'apt install sqlmap' },
  { name: 'dalfox', bin: 'dalfox', category: 'web', tags: ['web', 'xss'], desc: 'XSS scanner & testing', install: 'go install github.com/hahwul/dalfox/v2@latest' },
  // crack
  { name: 'hashcat', bin: 'hashcat', category: 'crack', tags: ['crack', 'hash'], desc: 'GPU hash cracker', install: 'apt install hashcat' },
  { name: 'john', bin: 'john', category: 'crack', tags: ['crack', 'hash'], desc: 'John the Ripper', install: 'apt install john' },
  { name: 'hydra', bin: 'hydra', category: 'crack', tags: ['crack', 'bruteforce'], desc: 'Online service login brute-force', install: 'apt install hydra' },
  { name: 'cewl', bin: 'cewl', category: 'crack', tags: ['crack', 'wordlist'], desc: 'Spider site untuk custom wordlist', install: 'apt install cewl' },
  // wordlist
  { name: 'crunch', bin: 'crunch', category: 'wordlist', tags: ['wordlist'], desc: 'Generate wordlist', install: 'apt install crunch' },
  { name: 'wfuzz', bin: 'wfuzz', category: 'wordlist', tags: ['wordlist', 'fuzz'], desc: 'Web fuzzer + wordlist', install: 'apt install wfuzz' },
  // exploit
  { name: 'msfconsole', bin: 'msfconsole', category: 'exploit', tags: ['exploit', 'framework'], desc: 'Metasploit Framework', install: 'apt install metasploit-framework' },
  { name: 'searchsploit', bin: 'searchsploit', category: 'exploit', tags: ['exploit', 'cve'], desc: 'Searchable Exploit-DB', install: 'apt install exploitdb' },
  // reverse
  { name: 'radare2', bin: 'r2', category: 'reverse', tags: ['reverse', 'binary'], desc: 'Binary analysis framework', install: 'apt install radare2' },
  { name: 'ghidra', bin: 'analyzeHeadless', category: 'reverse', tags: ['reverse', 'decompile'], desc: 'NSA reverse-engineering suite', install: 'download from ghidra-sre.org' },
  { name: 'strings', bin: 'strings', category: 'reverse', tags: ['reverse', 'strings'], desc: 'Print printable strings of a binary', install: 'apt install binutils' },
  { name: 'binwalk', bin: 'binwalk', category: 'reverse', tags: ['reverse', 'firmware'], desc: 'Firmware analysis / extract', install: 'apt install binwalk' },
  { name: 'apktool', bin: 'apktool', category: 'reverse', tags: ['reverse', 'android'], desc: 'Decompile Android APK', install: 'apt install apktool' },
  // stegano
  { name: 'steghide', bin: 'steghide', category: 'stegano', tags: ['stegano'], desc: 'Hide/extract file in images', install: 'apt install steghide' },
  { name: 'exiftool', bin: 'exiftool', category: 'stegano', tags: ['stegano', 'metadata'], desc: 'Read/write metadata', install: 'apt install exiftool' },
  // forensic
  { name: 'foremost', bin: 'foremost', category: 'forensic', tags: ['forensic', 'carve'], desc: 'File carving', install: 'apt install foremost' },
  { name: 'volatility', bin: 'volatility3', category: 'forensic', tags: ['forensic', 'memory'], desc: 'Memory forensics', install: 'pip install volatility3' },
  // ad
  { name: 'impacket', bin: 'GetSPNUsers.py', category: 'ad', tags: ['ad', 'windows'], desc: 'Active Directory / Kerberos toolkit', install: 'pip install impacket' },
  { name: 'crackmapexec', bin: 'crackmapexec', category: 'ad', tags: ['ad', 'windows'], desc: 'SMB/AD lateral toolkit', install: 'apt install crackmapexec' },
  { name: 'bloodhound', bin: 'bloodhound-python', category: 'ad', tags: ['ad', 'windows'], desc: 'AD attack path visualization', install: 'pip install bloodhound' },
  { name: 'evil-winrm', bin: 'evil-winrm', category: 'ad', tags: ['ad', 'windows'], desc: 'WinRM shell', install: 'gem install evil-winrm' },
  // cloud
  { name: 'scoutsuite', bin: 'scout', category: 'cloud', tags: ['cloud', 'aws'], desc: 'Cloud security posture scanner', install: 'pip install scoutsuite' },
  // mobile
  { name: 'frida', bin: 'frida', category: 'mobile', tags: ['mobile', 'hook'], desc: 'Dynamic instrumentation', install: 'pip install frida-tools' },
  { name: 'appium', bin: 'appium', category: 'mobile', tags: ['mobile', 'automation'], desc: 'Mobile app automation', install: 'npm i -g appium' },
];

function whichBin(bin) {
  return new Promise((resolve) => {
    execFile('which', [bin], (err, stdout) => resolve(err ? null : stdout.trim()));
  });
}

async function getCatalog() {
  const tools = await Promise.all(
    TOOLS.map(async (t) => ({ ...t, installed: !!(await whichBin(t.bin)) }))
  );
  const categories = CATEGORIES.map((c) => ({
    ...c,
    count: tools.filter((t) => t.category === c.id).length,
  }));
  return { categories, tools };
}

function searchTools(query, tools) {
  const q = (query || '').trim().toLowerCase();
  if (!q) return tools;
  return tools.filter(
    (t) =>
      t.name.toLowerCase().includes(q) ||
      t.desc.toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q) ||
      (t.tags || []).some((tag) => tag.toLowerCase().includes(q))
  );
}

// Keyword-based recommendation (offline, deterministic). Mirip pola hackingtool
// yang pakai stdlib matcher saat tidak ada model.
const INTENT_RULES = [
  { keys: ['subdomain', 'osint', 'dns', 'recon'], tools: ['subfinder', 'amass', 'dnsx', 'httpx'] },
  { keys: ['port', 'scan', 'network'], tools: ['nmap'] },
  { keys: ['directory', 'path', 'brute', 'fuzz'], tools: ['ffuf', 'gobuster', 'wfuzz'] },
  { keys: ['web', 'vuln', 'cve', 'template'], tools: ['nuclei', 'nikto', 'dalfox'] },
  { keys: ['sql', 'injection', 'sqli'], tools: ['sqlmap'] },
  { keys: ['xss'], tools: ['dalfox'] },
  { keys: ['wordpress', 'wp'], tools: ['wpscan'] },
  { keys: ['hash', 'crack', 'hashcat', 'password'], tools: ['hashcat', 'john', 'hydra'] },
  { keys: ['login', 'brute', 'credential'], tools: ['hydra', 'medusa'] },
  { keys: ['wordlist', 'generate'], tools: ['crunch', 'wwfuzz'] },
  { keys: ['forensic', 'memory', 'carve', 'dump'], tools: ['foremost', 'volatility'] },
  { keys: ['stegano', 'hidden'], tools: ['steghide', 'exiftool'] },
  { keys: ['active', 'domain', 'kerberos', 'windows'], tools: ['impacket', 'crackmapexec', 'bloodhound'] },
  { keys: ['reverse', 'binary', 'decompile', 'malware'], tools: ['ghidra', 'radare2', 'binwalk', 'strings'] },
  { keys: ['cloud', 'aws', 'azure'], tools: ['scoutsuite'] },
  { keys: ['mobile', 'android', 'hook'], tools: ['frida', 'apktool'] },
];

function recommendTools(query, tools) {
  const q = (query || '').toLowerCase().replace(/[^\w\s-]/g, ' ').trim();
  const forTools = [];
  const matched = [];
  for (const rule of INTENT_RULES) {
    const hit = rule.keys.some((k) => {
      if (!k) return false;
      try {
        return new RegExp(`\\b${escapeReg(k)}\\b`).test(q);
      } catch {
        return q.includes(k);
      }
    });
    if (hit) {
      matched.push(rule);
      for (const t of rule.tools) {
        const tool = tools.find((x) => x.name === t);
        if (tool && !forTools.includes(tool)) forTools.push(tool);
      }
    }
  }
  return { intent: matched.flatMap((r) => r.keys), tools: forTools };
}

function escapeReg(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// kategori yang di-exclude (out of scope) untuk coverage report
const NOT_TESTED_CATEGORIES = [
  'Phishing Attack Tools',
  'Remote Administration Tools (RAT)',
  'Payload Creation',
  'DDoS / Availability Attacks',
  'Wireless Attack (MITM / Rogue AP)',
  'Keylogger / Credential Harvesting',
];

module.exports = { getCatalog, searchTools, recommendTools, NOT_TESTED_CATEGORIES, TOOLS };