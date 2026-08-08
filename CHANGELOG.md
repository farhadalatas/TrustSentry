# Changelog

All notable changes are grouped by impact ("Added / Changed / Fixed / Security").
Versions follow [Semantic Versioning](https://semver.org). This project is intended for
**authorized security testing only**.

## [0.1.0] - 2026-08-08

Initial release of TrustSentry — a web-based security testing toolkit for
authentication workflows (register, login, OTP, reset-password).

### Added
- Web UI (React + Vite) with tabs: Target & Config, Live Results, Tool Catalog, JWT Tool, CLI Tools, Riwayat, Report
- Live scan results streamed over SSE (request-by-request progress + findings)
- Auth-testing modules:
  - Recon & fingerprint (security headers audit, framework detection, WAF probe)
  - Brute-force & rate-limit (user enumeration, password spraying, rate-limit bypass via proxy-header spoof, timing-attack analysis)
  - OTP / 2FA (bounded brute-force, coercion/type-juggling bypass vectors, replay/expiry, resend-cooldown abuse)
  - Injection (SQLi error+time based, NoSQLi, email CRLF injection, reflected XSS)
  - Session & JWT (cookie flags audit, JWT decode & security analysis)
  - Endpoint fuzzing (ffuf-style path discovery)
  - Business logic (disposable-email detection, register race-condition / TOCTOU)
- Kali-style CLI tool integration (nmap, nuclei, nikto, sqlmap, hydra) with install detection and whitelisted binaries
- Tool catalog with natural-language tool recommendation
- Professional report export: HTML, JSON and PDF (risk summary, severity-colored findings, evidence appendix, out-of-scope coverage section)
- Run history persistence (local JSON store, pruned to latest 100 runs)
- Scope & budget guardrails: explicit `authorized` confirmation, SSRF scope check, global request budget and rate
- GitHub Actions CI (integration tests + web build)

### Fixed
- `applyTemplate` placeholder substitution (placeholders such as `<USER>`/`<PASS>`/`<OTP>` were never replaced, which silently disabled several checks)
- User-enumeration detection reporting when responses were identical instead of different
- JWT findings losing their severity level (e.g. `alg: none`)
- Email CRLF injection payload sending literal backslashes instead of real CR/LF
- Server bound to all interfaces with no auth instead of localhost
- CLI module accepting arbitrary binaries

### Security
- Bind to `127.0.0.1` by default (override with `HOST`)
- CLI `toolName` whitelisted to the built-in tool list before execution
- Typed `BudgetError` / `RunStoppedError` instead of string-matching exception messages
- Sensitive categories (phishing / RAT / payload / DoS / wireless / keylogger) intentionally out of scope and reported in the coverage section

[0.1.0]: https://github.com/farhadalatas/TrustSentry/releases/tag/v0.1.0