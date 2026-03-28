# Changelog

All notable changes to RedChain will be documented in this file.

## [2.0.0] - 2026-03-21

### Added
- **Multi-LLM Support** — Gemini, OpenAI, and Ollama adapters via `--llm-provider`
- **Internationalization (i18n)** — Reports in 10 languages via `--language` (en, es, fr, de, ja, zh, ar, pt, ko, hi)
- **Plugin Architecture** — Community plugins with auto-discovery from `~/.redchain/plugins/`
- **Scan Profiles** — `--profile quick|full|stealth|compliance`
- **Docker Support** — Full `Dockerfile` and `docker-compose.yml` with all tools pre-installed
- **JSON/CSV Export** — `--output json` and `--output csv` alongside PDF and Markdown
- **Advanced OSINT** — VirusTotal, AbuseIPDB, and GreyNoise threat intelligence integrations
- **Compliance Mapping** — OWASP Top 10 and MITRE ATT&CK technique mapping in reports
- **CVSS Severity Classification** — Automatic Critical/High/Medium/Low/Info classification
- **Professional HTML Report Template** — Gradient headers, stat cards, severity badges
- **Proxy Support** — `--proxy` flag for HTTP/SOCKS5 proxies
- **Concurrency Control** — `--threads` flag for parallel operation limits
- **GitHub Actions CI** — Automated testing on Python 3.11/3.12/3.13

### Fixed
- **Duplicate `scanner_node()`** in `graph.py` — removed dead code
- **DYLD path set on all platforms** — now macOS-only via `setup_platform_env()`
- **Duplicate imports** in `scanner_agent.py` — removed second `import nmap` and `from config`
- **No error handling in LangGraph nodes** — added try/except to all 6 nodes

### Changed
- **Centralized utilities** — `utils.py` replaces 4× duplicated platform code
- **Agent refactoring** — `osint_agent.py`, `scanner_agent.py`, `webapp_agent.py` use shared utils
- **`config.py` rewrite** — now includes all API keys, LLM settings, and threat intel keys
- **`report_agent.py` rewrite** — uses LLM adapter layer, compliance mapping, multi-format output
- **`report/generator.py` rewrite** — professional template, JSON/CSV generators, severity helpers
- **`graph.py` rewrite** — state validation, error tracking, graceful degradation

### Documentation
- Added `CONTRIBUTING.md`
- Added `SECURITY.md`
- Added `CHANGELOG.md`
- Added `LICENSE` (MIT)
- Updated `.env.example` with all new API keys

## [1.0.0] - Initial Release

### Features
- LangGraph-based autonomous red team pipeline
- OSINT, subdomain enumeration, scanning, CVE matching
- AI-generated kill chain narrative via Gemini
- PDF and Markdown report generation
