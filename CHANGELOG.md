# Changelog

All notable changes to RedChain will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.1.0] - 2026-03-28

### Added
- **Nuclei Agent** (`nuclei_agent.py`) — 7000+ templated vulnerability scans with automatic tech-stack-aware template selection (WordPress, Jenkins, Apache, nginx, etc.)
- **Subdomain Takeover Agent** (`takeover_agent.py`) — 20-service CNAME fingerprint database (GitHub Pages, AWS S3, Azure, Netlify, Vercel, Heroku, Shopify...)
- **Default Credential Agent** (`credential_agent.py`) — SSH, FTP, HTTP Basic Auth, and web form brute-force against 30+ top default credential pairs
- **Passive DNS history** via HackerTarget in `osint_agent.py`
- **Threat Intelligence fully wired** — VirusTotal, AbuseIPDB, GreyNoise now actually called in pipeline
- **Dynamic MITRE ATT&CK mapping** in `report_agent.py` — keyword-driven per-finding (no longer always TA0001)
- **Nuclei + Takeover + Credential findings** in Markdown and JSON reports
- **Wildcard + exclusion scope validation** in `cli.py` (`*.staging.example.com`, `"excluded": [...]`)
- **Cross-platform ping** via `get_ping_cmd()` in `utils.py` (`-c` Unix / `-n` Windows)
- **Proxychains cross-platform helper** — proxychains4 (Linux), proxychains (macOS), skip (Windows)
- **`get_redchain_home()`** — centralized `~/.redchain/` data directory
- **SOCKS5 proxy graceful degradation** — returns None if `httpx[socks]` not installed
- **Nuclei + subfinder** added to `redchain update` and `Dockerfile`
- **`paramiko`** added to Docker image for SSH credential testing
- **Comprehensive test suite** — 152 tests covering all agents, cross-platform utils, scope validation, report generation

### Fixed
- **CVE version normalization** — strips distro suffixes (`7.4p1`, `1.2.3-4ubuntu5`) before CVE lookup
- **ExploitDB disk cache** — 24h TTL prevents repeated downloads
- **Proxy CLI** — removed broken `os.environ` proxy vars; agents use `make_httpx_transport()` properly
- **Subdomain agent** — cross-platform ping, proxy-aware httpx transport
- **AXFR zone transfer** — records now captured and stored in OSINT results
- **Duplicate subfinder call** — removed from `osint_agent.py`

### Changed
- **9-phase pipeline**: OSINT → Subdomain → Takeover → WebApp → Nuclei → Scanner → Credential → CVE → Report
- **Updated `redchain update`** — now installs nuclei, subfinder, gobuster, cvemap + runs `nuclei -update-templates`
- **`check_dependencies`** — now shows optional tools (nuclei, testssl.sh, paramiko)
- **README** — full command reference with every flag, all scan profiles, Docker examples, power combos

---

## [2.0.0] - 2026-03-21

### Added
- **Multi-LLM Support** — Gemini, OpenAI, and Ollama adapters via `--llm-provider`
- **Internationalization (i18n)** — Reports in 10 languages via `--language`
- **Plugin Architecture** — Community plugins with auto-discovery from `~/.redchain/plugins/`
- **Scan Profiles** — `--profile quick|full|stealth|compliance`
- **Docker Support** — Full `Dockerfile` and `docker-compose.yml`
- **JSON/CSV Export** — `--output json` and `--output csv`
- **Compliance Mapping** — OWASP Top 10 and MITRE ATT&CK mapping
- **CVSS Severity Classification** — Critical/High/Medium/Low/Info
- **Proxy Support** — `--proxy` flag for HTTP/SOCKS5
- **Concurrency Control** — `--threads` flag
- **GitHub Actions CI** — Automated testing

### Fixed
- Duplicate `scanner_node()` in `graph.py`
- DYLD path set on all platforms (now macOS-only)
- No error handling in LangGraph nodes

### Changed
- Centralized utilities in `utils.py`
- `config.py` includes all API keys, LLM settings, threat intel
- `report_agent.py` uses LLM adapter layer with multi-format output

---

## [1.0.0] - Initial Release

### Features
- LangGraph-based autonomous red team pipeline
- OSINT, subdomain enumeration, scanning, CVE matching
- AI-generated kill chain narrative via Gemini
- PDF and Markdown report generation
