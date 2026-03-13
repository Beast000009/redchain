# RedChain - Autonomous AI Red Team Agent

RedChain is an open-source autonomous AI red team agent that takes a target (domain, IP, CIDR, URL, or `targets.txt` file) and autonomously chains OSINT, subdomain enumeration, port scanning, CVE matching, and LLM-generated kill chain narratives into a final PDF + Markdown report.

It leverages LangGraph as a state machine to orchestrate tools like Shodan, Nmap, Subfinder, theHarvester, and NVD APIs, finally synthesizing a narrative using Google's Gemini 2.0 Flash model.

## Features
- **Phase 1: OSINT** (theHarvester, crt.sh, WHOIS, Shodan)
- **Phase 2: Subdomain Enum** (Subfinder, DNS Resolution)
- **Phase 3: Scanning** (Nmap Port Scan, OS Fingerprinting, Banner Grabbing)
- **Phase 4: CVE Matching** (NVD API v2, Vulners API)
- **Phase 5: Reporting** (Gemini AI Kill Chain narrative, WeasyPrint PDF, Markdown)

## Prerequisites & Installation

### 1. External dependencies
RedChain relies on several external system binaries being installed and available in your `$PATH`.
- `nmap` (Requires sudo for OS detection/SYN scans)
- `theHarvester`
- `subfinder`

On macOS/Ubuntu, you can install the core tools via:
```bash
# macOS
brew install nmap
brew install projectdiscovery/q/subfinder
brew install theharvester

# Ubuntu
sudo apt install nmap subfinder theharvester
```

*(Note: WeasyPrint also requires `pango` and `libffi` binaries. On macOS, `brew install pango libffi`)*

### 2. Python Environment Setup
```bash
git clone https://github.com/your-username/redchain.git
cd redchain

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install Python requirements
pip install -r requirements.txt
```

### 3. API Keys Configuration
Copy the `.env.example` to `.env` and fill in your keys:
```bash
cp .env.example .env
```
Add your keys:
- `GEMINI_API_KEY`: Required for the final report narrative. (Google AI Studio)
- `SHODAN_API_KEY`: Optional but highly recommended.
- `VULNERS_API_KEY`: Optional.
- `NVD_API_KEY`: Optional (helps avoid basic rate limits).

## Usage

You can target a domain, an IP, a CIDR block, a URL, or a file containing multiple targets.

**By default, RedChain checks targets against an allowed `scope.json` file. Use `--no-scope-check` for lab/CTF usage.**

```bash
# Full recon on a domain (lab, no scope check)
python cli.py --target example.com --no-scope-check --output both

# IP scan only (Skips OSINT & Subdomain phases)
python cli.py --target 10.10.10.5 --no-scope-check --stealth

# Authorised engagement with scope file
python cli.py --target target.com --output pdf

# Multi-target sweep
python cli.py --file targets.txt --no-scope-check --output md
```

### Arguments
- `--target` / `-t`: Single target to scan
- `--file` / `-f`: Path to `targets.txt`
- `--output` / `-o`: Output format (`pdf`, `md`, `both`)
- `--stealth` / `-s`: Enable stealth mode (slower Nmap -T2 scan)
- `--config` / `-c`: Custom path to `.env` file
- `--no-scope-check`: Bypass scope.json validation

## Defining Target Scope (`scope.json`)
For official engagements, create a `scope.json` file in the root directory:
```json
{
    "allowed": [
        "example.com",
        "10.0.0.0/24"
    ]
}
```

## How It Works
1. **Target Classification**: Automatically determines if input is an IP, CIDR, Domain, or URL.
2. **LangGraph Pipeline**: 
    - *Domains* follow the full path: OSINT -> Subdomains -> Scanner -> CVE -> Report.
    - *IPs/CIDRs* skip DNS/OSINT and inject straight to Scanner -> CVE -> Report.
3. **Data Aggregation**: Everything goes into a massive compiled state schema dict.
4. **AI Generation**: Gemini receives the heavily sanitized JSON schema and writes the report using the Cyber Kill Chain structure. Output is JSON, mapped to Jinja2, spun to PDF via WeasyPrint.
