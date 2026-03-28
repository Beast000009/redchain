<p align="center">
  <h1 align="center">🔴 RedChain</h1>
  <p align="center"><strong>Autonomous AI Red Team Agent</strong></p>
  <p align="center">
    LangGraph-powered penetration testing pipeline with multi-LLM support, active exploitation, subdomain takeover detection, nuclei scanning, default credential testing, threat intelligence, and AI-generated kill chain reports.
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python" alt="Python 3.11+"/>
    <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"/>
    <img src="https://img.shields.io/badge/docker-supported-blue?logo=docker" alt="Docker"/>
    <img src="https://img.shields.io/badge/LLM-Gemini%20%7C%20OpenAI%20%7C%20Ollama-purple" alt="Multi-LLM"/>
    <img src="https://img.shields.io/badge/i18n-10%20languages-orange" alt="i18n"/>
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows%20WSL2-lightgrey" alt="Cross-Platform"/>
  </p>
</p>

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Pipeline Phases](#pipeline-phases)
- [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Docker (Recommended)](#docker-recommended-for-teams)
  - [Kali Linux (Easiest)](#kali-linux-easiest)
  - [macOS](#macos)
  - [Linux (Ubuntu/Debian)](#linux-ubuntudebian)
  - [Linux (Arch)](#linux-arch)
  - [Windows (WSL2)](#windows-wsl2)
- [Configuration](#configuration)
- [Usage](#usage)
- [Multi-LLM Support](#multi-llm-support)
- [Report Formats](#report-formats)
- [Plugin System](#plugin-system)
- [Project Structure](#project-structure)
- [Supported Languages](#supported-languages)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---------|-------------|
| 🤖 **AI Kill Chain Reports** | Gemini / GPT-4o / Ollama-generated penetration test narratives |
| 🔍 **OSINT** | theHarvester, crt.sh, Amass, Shodan, Passive DNS, Google Dorks |
| 🌐 **Subdomain Enumeration** | Multi-tool discovery with alive-host validation |
| 🕸️ **Web App Fingerprinting** | WhatWeb, Nikto, Gobuster, WAF detection (wafw00f) |
| ⚡ **Nuclei Scanning** | 7000+ templates, tech-stack-aware template selection |
| 🎯 **Subdomain Takeover** | 20-service fingerprint database (GitHub, AWS S3, Azure, Vercel…) |
| 🔑 **Default Credential Testing** | SSH, FTP, HTTP Basic Auth, form login — 30 top credential pairs |
| 🛡️ **Vulnerability Scanning** | Nmap deep scan + 20 high-value scripts (ssl-heartbleed, ftp-anon, smtp-relay…) |
| 🐛 **CVE Matching** | Version-normalized CVE lookup via cvemap, NVD, Vulners |
| 🔮 **Threat Intelligence** | VirusTotal, AbuseIPDB, GreyNoise — fully wired into pipeline |
| 📊 **Compliance Mapping** | Dynamic OWASP Top 10 & MITRE ATT&CK mapping per finding |
| 🌍 **10 Languages** | Reports in EN, ES, FR, DE, JA, ZH, AR, PT, KO, HI |
| 🔌 **Plugin System** | Extend RedChain with community scanners |
| 🐳 **Docker** | One-command deployment with all tools pre-installed |
| ⚡ **Scan Profiles** | Quick, Full, Stealth, Compliance modes |
| 🌐 **Cross-Platform** | macOS, Linux, Windows WSL2 — platform-aware ping, proxy, paths |

---

## Architecture

```
┌──────────┐  ┌───────────┐  ┌──────────┐  ┌────────┐  ┌─────────┐  ┌──────────┐  ┌──────┐  ┌────────┐
│  OSINT   │─▶│ Subdomain │─▶│ Takeover │─▶│ WebApp │─▶│ Nuclei  │─▶│ Scanner  │─▶│ CVE  │─▶│ Report │
│  Agent   │  │  Agent    │  │  Agent   │  │ Agent  │  │  Agent  │  │  Agent   │  │Agent │  │ Agent  │
└──────────┘  └───────────┘  └──────────┘  └────────┘  └─────────┘  └──────────┘  └──────┘  └────────┘
     │              │              │             │             │            │            │          │
     ▼              ▼              ▼             ▼             ▼            ▼            ▼          ▼
theHarvester   subfinder      20 CNAME       wafw00f       7000+        nmap +       cvemap    Gemini/
crt.sh         amass          fingerprints   whatweb       templates    20 scripts   NVD        OpenAI/
Shodan         Passive DNS                   nikto         tech-aware   ExploitDB+  Vulners    Ollama
HackerTarget   AXFR capture                 gobuster      proxy/stealth proxychains           PDF/MD/
GreyNoise      DNS/HTTP/ping                              aware        aware                  JSON/CSV
VT/AbuseIPDB   checks
```

Orchestrated by **LangGraph** with error isolation, state validation, and graceful degradation per node.

---

## Pipeline Phases

| Phase | Agent | What it does |
|-------|-------|-------------|
| **1** | `osint_agent` | theHarvester, crt.sh, Amass, Shodan, Passive DNS (HackerTarget), Google Dorks, AXFR zone transfer capture, Threat Intel (VT/AbuseIPDB/GreyNoise) |
| **2** | `subdomain_agent` | subfinder + alive-host validation (DNS → Ping → HTTP), cross-platform ping |
| **2.5** | `takeover_agent` | Checks 20 cloud services (GitHub Pages, AWS S3, Heroku, Azure, Netlify, Vercel, Shopify, etc.) for dangling CNAME takeover |
| **3** | `webapp_agent` | WAF detection (wafw00f), tech fingerprinting (WhatWeb), vulnerability scanning (Nikto), directory brute-forcing (Gobuster) |
| **3.5** | `nuclei_agent` | Templated scanning — auto-selects templates by tech stack (WordPress→wordpress, Jenkins→default-logins…), proxy/stealth-aware |
| **4** | `scanner_agent` | Nmap deep scan with 20+ scripts (ssl-heartbleed, ftp-anon, smtp-open-relay, ms-sql-info, ldap-rootdse…), ExploitDB + GHDB mapping |
| **4.5** | `credential_agent` | Tests SSH, FTP, HTTP Basic Auth, and web forms against 30 top default credential pairs |
| **5** | `cve_agent` | Version-normalized CVE lookup (strips `7.4p1` → `7.4`) via cvemap with NVD/Vulners fallback |
| **6** | `report_agent` | AI kill chain narrative, dynamic MITRE ATT&CK mapping, OWASP mapping, PDF/MD/JSON/CSV |

---

## Installation

### Quick Start

```bash
git clone https://github.com/Beast000009/redchain.git
cd redchain
pip install .        # Installs 'redchain' as a system command
cp .env.example .env # Add your API keys
redchain update      # Install/update all external tools
redchain man         # View full manual
redchain scan -t scanme.nmap.org --no-scope-check  # Test scan
```

> **No virtual environment needed.** `pip install .` registers the `redchain` command globally.
> All API keys are optional — RedChain gracefully skips phases with missing keys.

---

### Docker (Recommended for teams)

All tools come pre-installed. No system setup needed.

```bash
# Clone and configure
git clone https://github.com/Beast000009/redchain.git
cd redchain
cp .env.example .env

# Build the image (~4GB, includes nmap, nikto, gobuster, subfinder, nuclei, etc.)
docker build -t redchain .

# Run a scan
docker run --rm -v ./reports:/app/reports --env-file .env \
  redchain scan -t target.com --no-scope-check

# Or use Docker Compose
docker compose run --rm redchain scan -t target.com --no-scope-check

# View manual inside container
docker run --rm redchain man
```

---

### Kali Linux (Easiest)

Kali comes with **most tools pre-installed** (nmap, nikto, whatweb, amass, gobuster, theharvester, seclists, whois, dnsutils).

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install any missing tools
sudo apt install -y python3-venv subfinder wafw00f

# Install Go tools
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

# Clone and setup RedChain
git clone https://github.com/Beast000009/redchain.git
cd redchain
python3 -m venv .venv
source .venv/bin/activate
pip install .

# Optional: SSH credential testing support
pip install paramiko

# Configure API keys
cp .env.example .env
nano .env

# Verify
redchain scan --help
```

> **💡 Tip:** On Kali, you run as root by default, so Nmap OS detection (`-O`) is automatically enabled.

> **💡 Tip:** Kali already has SecLists at `/usr/share/seclists/`. Use with:
> ```bash
> redchain scan -t target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
> ```

---

### macOS

#### Prerequisites

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.11+ and Go
brew install python@3.12 go
```

#### Step 1 — Install System Tools

```bash
# Core scanning tools
brew install nmap amass subfinder gobuster

# Python tools
pip3 install theHarvester wafw00f

# WhatWeb via Ruby gem
brew install whatweb || sudo gem install whatweb

# Nikto
brew install nikto

# SecLists wordlists
brew install seclists
```

#### Step 2 — Install Go Tools

```bash
# Add Go bin to PATH
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# CVE lookups
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest

# Subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Nuclei (templated scanning — highly recommended)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

#### Step 3 — Setup RedChain

```bash
git clone https://github.com/Beast000009/redchain.git
cd redchain

python3 -m venv .venv
source .venv/bin/activate

pip install .

# Optional: SSH credential testing
pip install paramiko

cp .env.example .env
# Edit .env with your API keys

redchain --help
redchain scan --help
```

---

### Linux (Ubuntu/Debian)

#### Step 1 — System Dependencies

```bash
sudo apt update && sudo apt install -y \
  python3 python3-pip python3-venv \
  nmap \
  amass \
  nikto \
  whatweb \
  gobuster \
  theharvester \
  subfinder \
  seclists \
  git curl wget \
  dnsutils whois \
  golang-go \
  ruby ruby-dev \
  libpango1.0-dev libcairo2-dev libgdk-pixbuf2.0-dev
```

> **Note:** On Ubuntu 22.04+, `subfinder` or `amass` may not be in default repos. Install via Go:
> ```bash
> go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
> sudo snap install amass
> ```

#### Step 2 — Install Python Tools

```bash
pip3 install wafw00f theHarvester paramiko
```

#### Step 3 — Install Go Tools

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

#### Step 4 — Setup RedChain

```bash
git clone https://github.com/Beast000009/redchain.git
cd redchain

python3 -m venv .venv
source .venv/bin/activate
pip install .

cp .env.example .env
# Edit .env with your API keys

redchain --help
```

---

### Linux (Arch)

```bash
# System tools
sudo pacman -S python python-pip nmap nikto whois dnsutils go git ruby curl wget

# AUR tools (via yay)
yay -S amass subfinder gobuster whatweb seclists

# Python tools
pip install wafw00f theHarvester paramiko

# Go tools
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Setup RedChain
git clone https://github.com/Beast000009/redchain.git
cd redchain
python -m venv .venv
source .venv/bin/activate
pip install .
cp .env.example .env
redchain --help
```

---

### Windows (WSL2)

RedChain works natively on **WSL2**. Full Windows native support is not available for all tools.

#### Step 1 — Install WSL2

```powershell
# Run in PowerShell as Administrator
wsl --install -d Ubuntu-24.04
```

Restart your computer, then open **Ubuntu** from the Start menu.

#### Step 2 — Follow Linux Setup

Inside WSL2, follow the [Linux (Ubuntu/Debian)](#linux-ubuntudebian) instructions above.

#### Step 3 — Docker Alternative (Easier)

If you have **Docker Desktop for Windows** with WSL2 backend enabled:

```powershell
git clone https://github.com/Beast000009/redchain.git
cd redchain
docker build -t redchain .
docker run --rm -v ./reports:/app/reports --env-file .env redchain scan -t target.com --no-scope-check
```

---

## Configuration

### API Keys (`.env`)

Copy `.env.example` to `.env` and add your API keys. **All keys are optional** — RedChain skips integrations with missing keys.

```bash
cp .env.example .env
```

```env
# LLM Provider (choose one)
GEMINI_API_KEY=your_key_here        # Google AI Studio → https://aistudio.google.com/apikey
OPENAI_API_KEY=your_key_here        # OpenAI → https://platform.openai.com/api-keys

# LLM Selection
LLM_PROVIDER=gemini                 # gemini | openai | ollama
# LLM_MODEL=gemini-2.5-flash       # Override default model

# Security Tools
SHODAN_API_KEY=your_key_here        # https://account.shodan.io
VULNERS_API_KEY=your_key_here       # https://vulners.com
NVD_API_KEY=your_key_here           # https://nvd.nist.gov/developers/request-an-api-key

# Threat Intelligence (all three are now fully used in pipeline)
VIRUSTOTAL_API_KEY=your_key_here    # https://www.virustotal.com/gui/my-apikey
ABUSEIPDB_API_KEY=your_key_here     # https://www.abuseipdb.com/account/api
GREYNOISE_API_KEY=your_key_here     # https://viz.greynoise.io/account/api-key
```

### Scope File (`scope.json`)

Define authorized targets. Supports exact match, wildcard, CIDR, and exclusions:

```json
{
  "allowed": [
    "example.com",
    "*.staging.example.com",
    "192.168.1.0/24",
    "10.0.0.1"
  ],
  "excluded": [
    "prod.example.com",
    "10.0.1.5"
  ]
}
```

Use `--no-scope-check` to bypass (for authorized testing only).

---

## Usage

### Command Overview

```
redchain --help               # Show top-level commands
redchain scan --help          # Full scan options
redchain man                  # Full interactive manual
redchain update               # Install/update all tools
```

---

### `redchain scan` — All Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | — | Single target: domain, IP, CIDR, or URL |
| `--file` | `-f` | — | Path to file with one target per line |
| `--output` | `-o` | `both` | `pdf \| md \| json \| csv \| both` |
| `--profile` | `-p` | `full` | `quick \| full \| stealth \| compliance` |
| `--ports` | — | `0` (auto) | `50 \| 100 \| 200 \| 1000` |
| `--threads` | — | `10` | Parallel worker count |
| `--llm-provider` | — | `gemini` | `gemini \| openai \| ollama` |
| `--llm-model` | — | auto | Override model name |
| `--language` | `-l` | `en` | Report language |
| `--proxy` | — | — | `http://` or `socks5://` proxy |
| `--wordlist` | `-w` | built-in | Custom wordlist for Gobuster |
| `--stealth` | `-s` | false | Enable stealth mode |
| `--no-scope-check` | — | false | Bypass scope validation |
| `--config` | `-c` | `.env` | Path to custom env file |

---

### Target Types

```bash
# Domain
redchain scan -t example.com

# IP address
redchain scan -t 192.168.1.10

# IPv6
redchain scan -t "2001:db8::1"

# CIDR range (scans all hosts)
redchain scan -t 10.0.0.0/24

# URL (automatically strips to domain)
redchain scan -t https://example.com/login?id=1

# Subdomain
redchain scan -t api.staging.example.com

# Multiple targets from file (one per line)
redchain scan -f targets.txt

# Bypass scope check (for authorized testing)
redchain scan -t example.com --no-scope-check
```

---

### Scan Profiles

```bash
# quick — skip OSINT, minimal nmap, top-50 ports (~2 min)
redchain scan -t example.com --profile quick

# full — all phases, top-200 ports (default, ~10-15 min)
redchain scan -t example.com --profile full

# stealth — slow timing, WAF-aware, low threads, top-100 ports
redchain scan -t example.com --profile stealth

# compliance — full scan + OWASP/NIST mapping emphasis
redchain scan -t example.com --profile compliance

# Mix: quick pipeline but thorough port scan
redchain scan -t example.com --profile quick --ports 1000

# Full pipeline with all 1000 ports
redchain scan -t example.com --profile full --ports 1000
```

---

### Port Control

```bash
# Top 50 ports (~30s/host) — fastest
redchain scan -t 10.0.0.0/24 --ports 50

# Top 100 ports (~1 min/host)
redchain scan -t example.com --ports 100

# Top 200 ports (~2 min/host) — profile default
redchain scan -t example.com --ports 200

# All 1000 ports (~5-10 min/host) — deepest
redchain scan -t example.com --ports 1000
```

---

### Output Formats

```bash
# Markdown only
redchain scan -t example.com --output md

# JSON only (for pipeline/SIEM integration)
redchain scan -t example.com --output json

# CSV only (for spreadsheet import)
redchain scan -t example.com --output csv

# PDF only
redchain scan -t example.com --output pdf

# PDF + Markdown (default)
redchain scan -t example.com --output both
```

---

### LLM Providers

```bash
# Gemini (default) — requires GEMINI_API_KEY in .env
redchain scan -t example.com --llm-provider gemini

# Gemini with specific model
redchain scan -t example.com --llm-provider gemini --llm-model gemini-2.0-flash

# OpenAI GPT-4o — requires OPENAI_API_KEY in .env
redchain scan -t example.com --llm-provider openai

# OpenAI with cheaper model
redchain scan -t example.com --llm-provider openai --llm-model gpt-4o-mini

# Ollama — completely offline, no API key needed
ollama pull llama3.1
redchain scan -t example.com --llm-provider ollama

# Ollama with custom model
redchain scan -t example.com --llm-provider ollama --llm-model mistral

# No API key — still generates full raw MD/JSON/CSV reports
redchain scan -t example.com --output md  # raw report, no AI narrative
```

---

### Report Language

```bash
redchain scan -t example.com --language en   # English (default)
redchain scan -t example.com --language es   # Español
redchain scan -t example.com --language fr   # Français
redchain scan -t example.com --language de   # Deutsch
redchain scan -t example.com --language ja   # 日本語
redchain scan -t example.com --language zh   # 中文
redchain scan -t example.com --language ar   # العربية
redchain scan -t example.com --language pt   # Português
redchain scan -t example.com --language ko   # 한국어
redchain scan -t example.com --language hi   # हिन्दी
```

---

### Proxy & Stealth

```bash
# Route through Tor (anonymized scan)
redchain scan -t example.com --proxy socks5://127.0.0.1:9050

# Route through Burp Suite proxy (for manual review)
redchain scan -t example.com --proxy http://127.0.0.1:8080

# Corporate proxy
redchain scan -t example.com --proxy http://proxy.corp.local:3128

# Stealth profile + proxy + low threads (maximum evasion)
redchain scan -t example.com --profile stealth --proxy socks5://127.0.0.1:9050 --threads 2

# Stealth flag only (no proxy)
redchain scan -t example.com --stealth
```

---

### Custom Wordlists (Directory Busting)

```bash
# SecLists common.txt
redchain scan -t example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Large directory list
redchain scan -t example.com -w /usr/share/wordlists/dirb/big.txt

# API-specific wordlist
redchain scan -t example.com -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Kali SecLists path
redchain scan -t example.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

---

### Custom Config & Scope

```bash
# Use a different .env file (e.g. client-specific keys)
redchain scan -t client.com --config /path/to/client.env

# Use custom scope file
# (edit scope.json first, then run without --no-scope-check)
redchain scan -t staging.client.com   # validated against scope.json

# Force bypass scope for lab/authorized pentests
redchain scan -t scanme.nmap.org --no-scope-check
```

---

### Concurrency

```bash
# Default 10 threads
redchain scan -t example.com

# Aggressive — more parallel tasks (faster on large CIDR)
redchain scan -t 10.0.0.0/24 --threads 30

# Conservative — good for stealth or slow targets
redchain scan -t example.com --threads 3

# Single-threaded (debugging)
redchain scan -t example.com --threads 1
```

---

### Power Combos (Real-World Scenarios)

```bash
# Bug bounty — quick recon, JSON output for toolchain
redchain scan -t target.com --profile quick --output json --no-scope-check

# Full external pentest with Gemini AI report in French PDF
redchain scan -t client.com --profile full --output pdf --language fr

# Internal network sweep — all hosts in CIDR, all 1000 ports
redchain scan -t 192.168.1.0/24 --profile full --ports 1000 --threads 20

# Red team engagement — stealth, Tor proxy, compliance report
redchain scan -t bank.com \
  --profile stealth \
  --proxy socks5://127.0.0.1:9050 \
  --output both \
  --language en \
  --threads 2

# Air-gapped lab — Ollama LLM, no internet, markdown report
redchain scan -t 10.10.10.10 \
  --llm-provider ollama \
  --llm-model llama3.1 \
  --output md \
  --no-scope-check

# Compliance audit — full scope, OWASP/NIST focus, PDF+JSON
redchain scan -t corp.internal \
  --profile compliance \
  --output both \
  --language en \
  --ports 200

# Quick check for a specific API endpoint
redchain scan -t https://api.example.com/v2 \
  --profile quick \
  --output json \
  --no-scope-check
```

---

### Docker Usage

```bash
# Minimal scan (no API keys)
docker run --rm -v ./reports:/app/reports \
  redchain scan -t scanme.nmap.org --no-scope-check --profile quick

# With API keys from .env file
docker run --rm \
  -v ./reports:/app/reports \
  --env-file .env \
  redchain scan -t example.com --no-scope-check

# Full pentest in Docker with all options
docker run --rm \
  -v ./reports:/app/reports \
  -v ./scope.json:/app/scope.json \
  --env-file .env \
  redchain scan -t example.com \
  --profile full \
  --output both \
  --language ja \
  --ports 200

# Docker Compose
docker compose run --rm redchain scan -t example.com --no-scope-check

# Run manual inside container
docker run --rm redchain man

# View help inside container
docker run --rm redchain scan --help

# Check tool versions inside container
docker run --rm --entrypoint="" redchain sh -c \
  "nmap --version; nuclei -version; subfinder -version"
```

---

### Update & Maintenance

```bash
# Install / update all external tools
# (gobuster, cvemap, subfinder, nuclei + templates, nikto, whatweb)
redchain update

# Check which tools are installed
redchain scan --help   # runs deps check automatically before scan

# Pull latest Nikto signatures
git -C /opt/nikto pull   # (Linux/macOS)

# Manually update nuclei templates
nuclei -update-templates

# Verify Python package health
pip show redchain
```

---

## Multi-LLM Support

| Provider | Model (Default) | API Key Required | Offline |
|----------|----------------|------------------|---------| 
| **Gemini** | `gemini-2.5-flash` | ✅ `GEMINI_API_KEY` | ❌ |
| **OpenAI** | `gpt-4o` | ✅ `OPENAI_API_KEY` | ❌ |
| **Ollama** | `llama3.1` | ❌ None | ✅ Air-gapped |

```bash
# Gemini (default)
redchain scan -t target.com --llm-provider gemini

# OpenAI
redchain scan -t target.com --llm-provider openai --llm-model gpt-4o-mini

# Ollama (local, no internet needed)
ollama pull llama3.1
redchain scan -t target.com --llm-provider ollama
```

---

## Report Formats

| Format | Flag | Contents |
|--------|------|----------|
| **PDF** | `--output pdf` | Professional styled report with severity badges |
| **Markdown** | `--output md` | Full narrative + tables + takeover/nuclei/creds sections |
| **JSON** | `--output json` | Machine-readable structured data including all new findings |
| **CSV** | `--output csv` | Spreadsheet-friendly vulnerability list |
| **Both** | `--output both` | PDF + Markdown (default) |

Reports include:
- Executive Summary (AI-generated)
- Kill Chain Narrative
- Attack Path ASCII diagram
- CVE findings with CVSS scores
- **Nuclei templated scan findings**
- **Subdomain takeover vulnerabilities** (with CNAME details)
- **Default credential hits** (username/password table)
- OWASP Top 10 mapping (keyword-driven)
- MITRE ATT&CK technique mapping (dynamic, per-finding)
- Remediation plan with priorities
- Web app fingerprinting details (Nikto, Gobuster)

---

## Plugin System

Extend RedChain with community plugins. Drop a `.py` file in `~/.redchain/plugins/`:

```python
from plugins import RedChainPlugin

class MasscanPlugin(RedChainPlugin):
    name = "masscan_scanner"
    description = "Fast port scanning with masscan"
    version = "1.0.0"
    phase = "scan"  # osint | scan | exploit | report | post

    def run(self, state):
        # Your scanning logic here
        return {"masscan_results": [...]}

    def get_requirements(self):
        return ["masscan"]
```

Plugins are auto-discovered on startup.

---

## Project Structure

```
redchain/
├── cli.py                      # CLI entry point (Typer)
├── config.py                   # Configuration (Pydantic Settings)
├── utils.py                    # Cross-platform utilities (ping, proxy, paths)
├── models.py                   # Pydantic data models
├── agents/
│   ├── osint_agent.py          # Phase 1: OSINT + Threat Intel + Passive DNS
│   ├── subdomain_agent.py      # Phase 2: Subdomain enumeration (cross-platform)
│   ├── takeover_agent.py       # Phase 2.5: Subdomain takeover (20 services)   ← NEW
│   ├── webapp_agent.py         # Phase 3: Web app fingerprinting
│   ├── nuclei_agent.py         # Phase 3.5: Nuclei templated scanning           ← NEW
│   ├── scanner_agent.py        # Phase 4: Nmap + ExploitDB (disk-cached)
│   ├── credential_agent.py     # Phase 4.5: Default credential testing          ← NEW
│   ├── cve_agent.py            # Phase 5: CVE matching (version-normalized)
│   ├── report_agent.py         # Phase 6: AI report + dynamic MITRE mapping
│   └── threat_intel.py         # VirusTotal / AbuseIPDB / GreyNoise
├── orchestrator/
│   └── graph.py                # LangGraph pipeline (9-phase)
├── llm/
│   ├── __init__.py             # LLM adapter factory
│   ├── gemini_adapter.py       # Google Gemini
│   ├── openai_adapter.py       # OpenAI / Azure
│   └── ollama_adapter.py       # Ollama (offline)
├── i18n/
│   └── __init__.py             # 10-language support
├── plugins/
│   ├── __init__.py             # Plugin base class
│   └── loader.py               # Auto-discovery
├── report/
│   └── generator.py            # PDF/MD/JSON/CSV generation
├── tests/                      # Unit tests
├── Dockerfile                  # Container support
├── docker-compose.yml          # One-command deployment
├── requirements.txt            # Python dependencies
├── pyproject.toml              # Linting & tooling config
├── .env.example                # API key template
└── scope.json                  # Authorized targets
```

---

## Supported Languages

| Code | Language | Flag |
|------|----------|------|
| `en` | English | `--language en` |
| `es` | Español | `--language es` |
| `fr` | Français | `--language fr` |
| `de` | Deutsch | `--language de` |
| `ja` | 日本語 | `--language ja` |
| `zh` | 中文 | `--language zh` |
| `ar` | العربية | `--language ar` |
| `pt` | Português | `--language pt` |
| `ko` | 한국어 | `--language ko` |
| `hi` | हिन्दी | `--language hi` |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, plugin authoring, and PR guidelines.

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and responsible use policy.

---

## License

[MIT License](LICENSE) — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

RedChain is designed for **authorized security testing only**. Always obtain **written permission** before scanning any target. Unauthorized scanning is illegal. The authors are not responsible for misuse of this tool.
