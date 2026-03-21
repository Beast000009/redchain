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

The easiest way to install or update all required tools is via the built-in update command:
```bash
python3 cli.py update
```

#### Platform install matrix
If you prefer to install manually, here are the required commands per platform:

| Tool         | macOS                          | Linux (Kali/Debian)        |
|--------------|-------------------------------|----------------------------|
| nmap         | brew install nmap              | apt install nmap           |
| theHarvester | brew install theharvester      | apt install theharvester   |
| subfinder    | brew install subfinder         | apt install subfinder      |
| amass        | brew install amass             | apt install amass          |
| gobuster     | brew install gobuster          | apt install gobuster       |
| nikto        | brew install nikto             | apt install nikto          |
| whatweb      | gem install whatweb            | apt install whatweb        |
| wafw00f      | pip install wafw00f            | pip install wafw00f        |
| wordlists    | brew install seclists          | apt install seclists       |
| cvemap       | go install ...cvemap@latest    | go install ...cvemap@latest|

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

## Detailed User Guide and Execution

RedChain is executed via the `cli.py` entry point. It accepts various target types including domains, IPs, CIDR blocks, URLs, or a text file containing multiple targets.

### Basic Syntax
```bash
python cli.py [OPTIONS]
```

### Core Execution Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--target` | `-t` | The target to scan (Domain, IP, CIDR, URL). Automatically classified. | None |
| `--file` | `-f` | Path to a text file containing multiple targets (one per line). | None |
| `--output` | `-o` | Reporting output format: `pdf`, `md`, or `both`. | `both` |
| `--stealth` | `-s` | Executes Nmap slower (`-T2` instead of `-T4`) to evade detection. | False |
| `--config` | `-c` | Provide a custom `.env` file path for API keys. | None |
| `--no-scope-check` | N/A | Bypass the `scope.json` validation completely. Required for ad-hoc / lab scans. | False |
| `--wordlist` | `-w` | Path to a wordlist for `gobuster` directory busting on live web servers. | None |

### Use Cases & Examples

**1. Full Domain Reconnaissance (Lab Mode)**
Scans a domain, running the full OSINT -> Subdomain -> Scanner -> CVE -> Report pipeline. The `--no-scope-check` flag prevents the application from blocking the scan if it's not in `scope.json`.
```bash
python cli.py --target example.com --no-scope-check
```

**2. Direct IP / Network Scanning**
When given an IP or CIDR block, RedChain skips the OSINT/Subdomain phases and proceeds directly to port scanning, exploit discovery, and CVE matching.
```bash
# Single IP Scan with stealth mode enabled
python cli.py --target 10.10.10.5 --stealth --no-scope-check

# Subnet Sweep
python cli.py --target 192.168.1.0/24 --no-scope-check
```

**3. Directory Busting Extraction**
Provide a wordlist via `-w` to automatically run `gobuster` against any discovered active web ports (80, 443, 8080, 8443) on live hosts.
```bash
python cli.py --target example.com --wordlist /usr/share/wordlists/dirb/common.txt --no-scope-check
```

**4. Bulk Target Execution**
Provide a file named `targets.txt` (containing domains or IPs on separate lines) to run RedChain against multiple assets sequentially.
```bash
python cli.py --file targets.txt --output pdf --no-scope-check
```

**5. Authorized Engagements with Scope Validation**
For official pentests, define allowed targets in `scope.json` and run the tool without `--no-scope-check`. RedChain will validate the target against the scope file before proceeding.
```bash
python cli.py --target client-target.com --output both
```

## Defining Target Scope (`scope.json`)
For official engagements, create a `scope.json` file in the root directory. This acts as a safety measure preventing out-of-scope scanning:
```json
{
    "allowed": [
        "example.com",
        "10.0.0.0/24"
    ]
}
```

## Internal Architecture How-To
1. **Target Classification**: Automatically parses string inputs to determine if the target is an IP, CIDR, Domain, or URL.
2. **LangGraph Pipeline**: 
    - *Domains* follow the full path: OSINT -> Subdomains -> Scanner -> Exploit Discovery -> CVE -> Report.
    - *IPs/CIDRs* follow the direct path: Scanner -> Exploit Discovery -> CVE -> Report.
3. **Data Aggregation**: All agent outputs perfectly cascade dynamically into a continuous state dictionary.
4. **AI Generation**: Gemini 2.0 Flash is fed the contextualized JSON schema and authors a highly narrative Cyber Kill Chain report.
5. **PDF Export**: Output is transformed via Jinja2 templates and rendered to a polished PDF automatically via WeasyPrint.
