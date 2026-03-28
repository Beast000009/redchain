#!/usr/bin/env python3
import os
import sys

# Add the project root to sys.path early so utils can be found
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from utils import IS_MAC, IS_LINUX, IS_WINDOWS, IS_WSL, find_tool, require_sudo, setup_platform_env

# Platform-guarded environment setup (only sets DYLD on macOS)
setup_platform_env()

import typer
import json
import ipaddress
import urllib.parse
from typing import List, Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
import shutil

from config import run_config, settings
from i18n import SUPPORTED_LANGUAGES

app = typer.Typer(help="RedChain - Autonomous AI Red Team Agent")
console = Console()

MANUAL_PAGE = """
[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]
[bold red]  🔴 REDCHAIN v2.0 — MANUAL[/bold red]
[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]

[bold]NAME[/bold]
    redchain — Autonomous AI Red Team Agent

[bold]SYNOPSIS[/bold]
    redchain scan [OPTIONS]
    redchain update
    redchain man

[bold]COMMANDS[/bold]
    [green]scan[/green]        Run the full pentest pipeline on targets
    [green]update[/green]      Update external tools (nmap, nikto, gobuster, etc.)
    [green]man[/green]         Show this manual page

[bold]SCAN OPTIONS[/bold]
    [yellow]-t, --target[/yellow]        TARGET    Single target: domain, IP, CIDR, or URL
    [yellow]-f, --file[/yellow]          PATH      File with one target per line
    [yellow]-o, --output[/yellow]        FORMAT    Output: pdf | md | json | csv | both (default: both)
    [yellow]-s, --stealth[/yellow]                 Enable stealth mode (slow scan, low footprint)
    [yellow]-c, --config[/yellow]        PATH      Path to custom .env config file
    [yellow]-w, --wordlist[/yellow]      PATH      Wordlist for directory brute-forcing
    [yellow]-l, --language[/yellow]      LANG      Report language: en es fr de ja zh ar pt ko hi
    [yellow]-p, --profile[/yellow]       PROFILE   Scan profile: quick | full | stealth | compliance
    [yellow]--ports[/yellow]             N         Nmap port count: 50 | 100 | 200 | 1000 (default: auto)
    [yellow]--llm-provider[/yellow]      PROVIDER  AI backend: gemini | openai | ollama
    [yellow]--llm-model[/yellow]         MODEL     Override LLM model (e.g. gpt-4o, llama3.1)
    [yellow]--threads[/yellow]           N         Concurrency limit (default: 10)
    [yellow]--proxy[/yellow]             URL       HTTP/SOCKS5 proxy (e.g. socks5://127.0.0.1:9050)
    [yellow]--no-scope-check[/yellow]              Bypass scope.json validation

[bold]PORT SCANNING MODES[/bold]
    [green]--ports 50[/green]    ⚡ Fast — top 50 ports (~30 sec per host)
    [green]--ports 100[/green]   🔄 Standard — top 100 ports (~1 min per host)
    [green]--ports 200[/green]   📋 Deep — top 200 ports (~2 min per host)
    [green]--ports 1000[/green]  🔬 Full — all 1000 nmap ports (~5-10 min per host)
    [dim]Default: auto (50 for quick, 100 for stealth, 200 for full/compliance)[/dim]

[bold]SCAN PROFILES[/bold]
    [green]quick[/green]       ⚡ Fast recon — skip OSINT, top-50 ports
    [green]full[/green]        🔄 All 6 phases enabled, top-200 ports (default)
    [green]stealth[/green]     🐢 Slow scans, WAF evasion, top-100 ports
    [green]compliance[/green]  📋 Full scan + OWASP/NIST mapping, top-200 ports

[bold]LLM PROVIDERS[/bold]
    [green]gemini[/green]      Google Gemini (default) — requires GEMINI_API_KEY
    [green]openai[/green]      OpenAI / Azure — requires OPENAI_API_KEY
    [green]ollama[/green]      Local Ollama — no API key, works offline/air-gapped

[bold]PIPELINE PHASES[/bold]
    1. [cyan]OSINT[/cyan]           theHarvester, crt.sh, Amass, Subfinder, Shodan, Dorks
    2. [cyan]Subdomain[/cyan]       Multi-tool discovery + alive-host validation
    3. [cyan]WebApp[/cyan]          WhatWeb, Nikto, Gobuster, WAF detection (wafw00f)
    4. [cyan]Scanner[/cyan]         Nmap deep scan + service version detection
    5. [cyan]CVE[/cyan]             NVD, Vulners, cvemap — auto CVE-to-service matching
    6. [cyan]Report[/cyan]          AI kill chain narrative + PDF/MD/JSON/CSV generation

[bold]EXAMPLES[/bold]
    [dim]# Basic domain scan[/dim]
    redchain scan -t example.com --no-scope-check

    [dim]# Quick scan with top-50 ports (fastest)[/dim]
    redchain scan -t target.com --profile quick --no-scope-check

    [dim]# Deep scan with all 1000 ports[/dim]
    redchain scan -t target.com --ports 1000 --no-scope-check

    [dim]# Scan IP range with stealth profile[/dim]
    redchain scan -t 10.0.0.0/24 --profile stealth --proxy socks5://127.0.0.1:9050

    [dim]# Scan with OpenAI and Japanese reports[/dim]
    redchain scan -t target.com --llm-provider openai --language ja

    [dim]# Offline scan with Ollama (air-gapped)[/dim]
    redchain scan -t target.com --llm-provider ollama --llm-model llama3.1

    [dim]# Compliance audit with CSV export[/dim]
    redchain scan -t target.com --profile compliance --output csv

    [dim]# Scan from file with custom wordlist[/dim]
    redchain scan -f targets.txt -w /usr/share/seclists/Discovery/Web-Content/big.txt

    [dim]# Docker scan[/dim]
    docker run --rm -v ./reports:/app/reports --env-file .env redchain scan -t target.com

[bold]ENVIRONMENT VARIABLES[/bold]
    GEMINI_API_KEY        Google Gemini API key
    OPENAI_API_KEY        OpenAI API key
    SHODAN_API_KEY        Shodan API key
    VULNERS_API_KEY       Vulners API key
    NVD_API_KEY           NVD API key (recommended for rate limits)
    VIRUSTOTAL_API_KEY    VirusTotal threat intel
    ABUSEIPDB_API_KEY     AbuseIPDB threat intel
    GREYNOISE_API_KEY     GreyNoise threat intel

[bold]FILES[/bold]
    .env                  API keys configuration
    scope.json            Authorized targets definition
    reports/              Generated report output directory
    ~/.redchain/plugins/  Community plugin directory

[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]
"""


@app.command()
def man():
    """Show the full RedChain manual with all commands, options, and examples."""
    console.print(MANUAL_PAGE)


def classify_target(target: str) -> str:
    """Classifies the target as domain, ip, cidr, or url."""
    # Check URL
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urllib.parse.urlparse(target)
        target = parsed.netloc or parsed.path  # fallback if missing //
        target = target.split(':')[0] # remove port if present
        
    # Check CIDR
    if '/' in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return "cidr"
        except ValueError:
            pass

    # Check IP
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    # Default to domain
    return "domain"

def validate_scope(target: str, scope_file: str) -> bool:
    """Validates the target against the scope.json file (supports CIDR, wildcards, exclusions)."""
    if not os.path.exists(scope_file):
        console.print(f"[bold yellow]Warning:[/bold yellow] Scope file '{scope_file}' not found.")
        return False

    try:
        with open(scope_file, "r") as f:
            scope_data = json.load(f)

        allowed_targets = scope_data.get("allowed", [])
        excluded_targets = scope_data.get("excluded", [])

        # Check exclusions first
        for excl in excluded_targets:
            if target == excl or target.endswith("." + excl):
                console.print(f"[bold red]Target '{target}' is explicitly EXCLUDED in scope.json[/bold red]")
                return False

        # Exact match
        if target in allowed_targets:
            return True

        for allowed in allowed_targets:
            # Wildcard: *.example.com
            if allowed.startswith("*."):
                parent = allowed[2:]
                if target.endswith("." + parent) or target == parent:
                    return True
                continue

            # Subdomain: target is a subdomain of allowed
            if target.endswith("." + allowed) or target == allowed:
                return True

        # Check if target IP is in allowed CIDR
        try:
            target_ip = ipaddress.ip_address(target)
            for allowed in allowed_targets:
                try:
                    if '/' in allowed and target_ip in ipaddress.ip_network(allowed, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass

    except Exception as e:
        console.print(f"[bold red]Error parsing scope file:[/bold red] {e}")

    return False

import subprocess
import httpx
import re

@app.command()
def update():
    """Update all external RedChain dependencies and tools."""
    console.print("[bold cyan]Updating external tools...[/bold cyan]")
    
    console.print("[yellow]Updating Python tools (wafw00f) via pip...[/yellow]")
    os.system("pip install --upgrade wafw00f")
    
    if IS_LINUX and find_tool("apt"):
        console.print("[yellow]Updating Debian packages (amass, whatweb, nikto, gobuster, nmap, dirb, seclists, theharvester, subfinder)...[/yellow]")
        os.system("sudo apt update && sudo apt install -y amass whatweb nikto gobuster nmap dirb seclists theharvester subfinder")
    elif IS_MAC and find_tool("brew"):
        console.print("[yellow]Updating macOS Homebrew packages...[/yellow]")
        os.system("brew install nmap nikto amass theharvester subfinder gobuster seclists || brew upgrade nmap nikto amass theharvester subfinder gobuster seclists")
        console.print("[yellow]Updating Ruby tools (whatweb) via gem...[/yellow]")
        os.system("sudo gem install whatweb")
        
    console.print("[yellow]Updating Go tools (gobuster, cvemap, subfinder, nuclei)...[/yellow]")
    if not IS_MAC or not find_tool("gobuster"):
        os.system("go install github.com/OJ/gobuster/v3@latest")

    os.system("go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest")
    os.system("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    os.system("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    # Update nuclei templates
    if find_tool("nuclei"):
        console.print("[yellow]Updating nuclei templates...[/yellow]")
        os.system("nuclei -update-templates -silent")

    console.print("[bold green]Tools update complete![/bold green]")

def check_for_updates():
    """Checks online if an update for core tools (like cvemap) is available."""
    try:
        console.print("[cyan]Checking for external tool updates online...[/cyan]")
        with httpx.Client(timeout=3.0) as client:
            resp = client.get("https://api.github.com/repos/projectdiscovery/cvemap/releases/latest")
            if resp.status_code == 200:
                latest_version = resp.json().get("tag_name", "")
                
                try:
                    local_out = subprocess.check_output(["cvemap", "-version"], stderr=subprocess.STDOUT, text=True)
                    match = re.search(r'v\d+\.\d+\.\d+', local_out)
                    local_version = match.group(0) if match else "unknown"
                except Exception:
                    local_version = "not installed"
                    
                if latest_version and local_version != latest_version:
                    if typer.confirm(f"Update available for external tools (e.g. cvemap Local: {local_version} -> Online: {latest_version}). Do you want to run the update feature now?"):
                        update()
    except Exception as e:
        console.print(f"[dim]Could not check for updates online: {e}[/dim]")

from rich.table import Table

def check_dependencies():
    """Checks if required CLI tools are installed in the system PATH."""
    console.print("\n[bold cyan]Checking Required Dependencies...[/bold cyan]")
    
    tools = {
        "nmap": "Port Scanning & OS Detection",
        "theHarvester": "Email & OSINT gathering",
        "subfinder": "Subdomain Discovery",
        "amass": "Passive Enumeration",
        "wafw00f": "WAF Detection",
        "whatweb": "Web Tech Fingerprinting",
        "nikto": "Web Vulnerability Scanner",
        "gobuster": "Directory Brute-forcing"
    }
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Status", justify="center")
    table.add_column("Tool")
    table.add_column("Purpose")
    
    missing = False
    for tool, desc in tools.items():
        if shutil.which(tool):
            table.add_row("[green]✓[/green]", tool, desc)
        else:
            table.add_row("[red]✗[/red]", f"[red]{tool}[/red]", desc)
            missing = True
            
    # Optional tools
    optional_tools = {
        "cvemap":  "Fast local CVE Lookups",
        "nuclei":  "Templated Vuln Scanning (7000+ templates)",
        "testssl.sh": "SSL/TLS Deep Analysis",
        "paramiko": "SSH credential testing (pip)",
    }
    for tool, desc in optional_tools.items():
        if shutil.which(tool):
            table.add_row("[green]✓[/green]", f"{tool} (Optional)", desc)
        else:
            table.add_row("[yellow]-[/yellow]", f"[yellow]{tool} (Optional)[/yellow]", f"{desc} (not installed)")
            
    console.print(table)
    if not shutil.which("cvemap"):
         console.print("[dim]cvemap not found — install with: go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest[/dim]")
         
    if missing:
        console.print("[bold yellow]Warning:[/bold yellow] Some required tools are missing. It is highly recommended to run [bold cyan]`python3 cli.py update`[/bold cyan] before scanning.\n")
    else:
        console.print("[green]All required dependencies met![/green]\n")

# ── Scan Profiles ─────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    "quick": {
        "description": "Fast scan — skip OSINT, minimal nmap",
        "stealth": False,
        "threads": 20,
    },
    "full": {
        "description": "Full pipeline — all phases enabled",
        "stealth": False,
        "threads": 10,
    },
    "stealth": {
        "description": "Stealth mode — slow scans, WAF-aware",
        "stealth": True,
        "threads": 5,
    },
    "compliance": {
        "description": "Compliance scan — OWASP/NIST mapping focus",
        "stealth": False,
        "threads": 10,
    },
}


@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Single target (domain, IP, CIDR, URL)"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Path to targets.txt"),
    output: str = typer.Option("both", "--output", "-o", help="Output format: pdf | md | json | csv | both"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Enable stealth mode (slower scan)"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to custom .env config"),
    no_scope_check: bool = typer.Option(False, "--no-scope-check", help="Bypass scope validation"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", "-w", help="Path to wordlist for directory busting"),
    llm_provider: str = typer.Option("gemini", "--llm-provider", help="LLM provider: gemini | openai | ollama"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Override default LLM model name"),
    language: str = typer.Option("en", "--language", "-l", help="Report language (en, es, fr, de, ja, zh, ar, pt, ko, hi)"),
    threads: int = typer.Option(10, "--threads", help="Concurrency limit for parallel operations"),
    profile: str = typer.Option("full", "--profile", "-p", help="Scan profile: quick | full | stealth | compliance"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/SOCKS5 proxy for outbound traffic"),
    ports: int = typer.Option(0, "--ports", help="Nmap port count: 50 | 100 | 200 | 1000 (0=auto based on profile)"),
):
    """
    Run the RedChain autonomous pentest on targets.
    """
    check_dependencies()
    check_for_updates()
    
    if config_path and config_path.exists():
        from dotenv import load_dotenv
        load_dotenv(config_path)

    # Apply scan profile defaults
    if profile in SCAN_PROFILES:
        profile_cfg = SCAN_PROFILES[profile]
        if not stealth:
            stealth = profile_cfg.get("stealth", False)
        threads = threads or profile_cfg.get("threads", 10)
        console.print(f"[cyan]Using scan profile: {profile} — {profile_cfg['description']}[/cyan]")

    # Apply runtime config
    run_config.output_format = output
    run_config.stealth = stealth
    run_config.llm_provider = llm_provider
    run_config.llm_model = llm_model
    run_config.language = language
    run_config.threads = threads
    run_config.profile = profile
    run_config.proxy = proxy
    run_config.ports = ports

    # Validate language
    if language not in SUPPORTED_LANGUAGES:
        console.print(f"[yellow]Warning: Language '{language}' not fully supported. Falling back to English.[/yellow]")
        run_config.language = "en"

    # Set proxy — store in run_config; agents use make_httpx_transport(proxy) for proper httpx support
    # Note: setting HTTP_PROXY/HTTPS_PROXY env vars does NOT work for httpx AsyncClient
    if proxy:
        console.print(f"[cyan]Using proxy: {proxy} (agents will route via httpx transport or proxychains)[/cyan]")

    targets_to_scan = []
    if target:
        targets_to_scan.append(target)
    if file and file.exists():
        with open(file, "r") as f:
            targets_to_scan.extend([line.strip() for line in f if line.strip()])

    if not targets_to_scan:
        console.print("[bold red]Error:[/bold red] Must provide --target or --file")
        raise typer.Exit(code=1)
        
    wordlist_str = str(wordlist.absolute()) if wordlist and wordlist.exists() else None
    if wordlist and not wordlist.exists():
        console.print(f"[bold yellow]Warning:[/bold yellow] Wordlist '{wordlist}' not found. Directory busting will be skipped.")

    for current_target in targets_to_scan:
        target_type = classify_target(current_target)
        
        # Clean URL if it was classified as such or just passed
        if current_target.startswith("http://") or current_target.startswith("https://"):
            parsed = urllib.parse.urlparse(current_target)
            current_target = parsed.netloc.split(':')[0]
            if not current_target:
                current_target = parsed.path.split('/')[0]

        console.print(Panel.fit(
            f"Starting RedChain against [bold cyan]{current_target}[/bold cyan] ({target_type})\n"
            f"[dim]Provider: {llm_provider} | Language: {SUPPORTED_LANGUAGES.get(language, language)} | "
            f"Profile: {profile} | Threads: {threads}[/dim]",
            title="RedChain Init"
        ))

        if not no_scope_check:
            is_valid = validate_scope(current_target, "scope.json")
            if not is_valid:
                confirm = typer.confirm(f"Target '{current_target}' NOT in scope (or scope.json missing). Continue anyway?")
                if not confirm:
                    console.print("[yellow]Skipping target.[/yellow]")
                    continue

        console.print("[cyan]Target validated, launching orchestrator...[/cyan]")
        
        from orchestrator.graph import run_workflow
        run_workflow(current_target, target_type, wordlist_str)

if __name__ == "__main__":
    app()
