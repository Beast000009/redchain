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

@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Single target (domain, IP, CIDR, URL)"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Path to targets.txt"),
    output: str = typer.Option("both", "--output", "-o", help="Output format: pdf | md | both"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Enable stealth mode (slower scan)"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to custom .env config"),
    no_scope_check: bool = typer.Option(False, "--no-scope-check", help="Bypass scope validation"),
):
    """
    Run the RedChain autonomous pentest on targets.
    """
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
        run_workflow(current_target, target_type)

if __name__ == "__main__":
    app()
