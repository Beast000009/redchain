import os
import sys

# macOS Homebrew Library Path Fallback (Essential for WeasyPrint/Pango)
os.environ['DYLD_FALLBACK_LIBRARY_PATH'] = '/opt/homebrew/lib:' + os.environ.get('DYLD_FALLBACK_LIBRARY_PATH', '')

import typer
import json
import ipaddress
import urllib.parse
from typing import List, Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
import shutil
import platform

PLATFORM = platform.system()
IS_MAC = PLATFORM == "Darwin"
IS_LINUX = PLATFORM == "Linux"
IS_WINDOWS = PLATFORM == "Windows"

def find_tool(name: str) -> str | None:
    return shutil.which(name)

def require_sudo() -> bool:
    return os.geteuid() == 0 if not IS_WINDOWS else False

# Add the project root to sys.path so modules can find each other
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import run_config

app = typer.Typer(help="RedChain - Autonomous AI Red Team Agent")
console = Console()

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
    """Validates the target against the scope.json file."""
    if not os.path.exists(scope_file):
        console.print(f"[bold yellow]Warning:[/bold yellow] Scope file '{scope_file}' not found.")
        return False

    try:
        with open(scope_file, "r") as f:
            scope_data = json.load(f)
            
        allowed_targets = scope_data.get("allowed", [])
        
        # Simple string matching for now (can be expanded to regex/CIDR matching)
        if target in allowed_targets:
            return True
        
        # Check against subdomains if allowed specifies a domain
        for allowed in allowed_targets:
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
        
    console.print("[yellow]Updating Go tools (gobuster, cvemap)...[/yellow]")
    if not IS_MAC or not find_tool("gobuster"):
        os.system("go install github.com/OJ/gobuster/v3@latest")
        
    os.system("go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest")
    
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

import shutil
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
    if shutil.which("cvemap"):
        table.add_row("[green]✓[/green]", "cvemap (Optional)", "Fast local CVE Lookups")
    else:
        table.add_row("[yellow]-[/yellow]", "[yellow]cvemap (Optional)[/yellow]", "Fast local CVE Lookups (using fallback APIs)")
            
    console.print(table)
    if not shutil.which("cvemap"):
         console.print("[dim]cvemap not found — install with: go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest[/dim]")
         
    if missing:
        console.print("[bold yellow]Warning:[/bold yellow] Some required tools are missing. It is highly recommended to run [bold cyan]`python3 cli.py update`[/bold cyan] before scanning.\n")
    else:
        console.print("[green]All required dependencies met![/green]\n")

@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Single target (domain, IP, CIDR, URL)"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Path to targets.txt"),
    output: str = typer.Option("both", "--output", "-o", help="Output format: pdf | md | both"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Enable stealth mode (slower scan)"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to custom .env config"),
    no_scope_check: bool = typer.Option(False, "--no-scope-check", help="Bypass scope validation"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", "-w", help="Path to wordlist for directory busting"),
):
    """
    Run the RedChain autonomous pentest on targets.
    """
    check_dependencies()
    check_for_updates()
    
    if config_path and config_path.exists():
        # Update settings logic if custom config provided (using python-dotenv could be simpler here)
        from dotenv import load_dotenv
        load_dotenv(config_path)

    run_config.output_format = output
    run_config.stealth = stealth

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

        console.print(Panel.fit(f"Starting RedChain against [bold cyan]{current_target}[/bold cyan] ({target_type})", title="RedChain Init"))

        if not no_scope_check:
            is_valid = validate_scope(current_target, "scope.json")
            if not is_valid:
                confirm = typer.confirm(f"Target '{current_target}' NOT in scope (or scope.json missing). Continue anyway?")
                if not confirm:
                    console.print("[yellow]Skipping target.[/yellow]")
                    continue

        # TODO: Launch workflow
        console.print("[cyan]Target validated, launching orchestrator...[/cyan]")
        
        # Run workflow:
        from orchestrator.graph import run_workflow
        run_workflow(current_target, target_type, wordlist_str)

if __name__ == "__main__":
    app()
