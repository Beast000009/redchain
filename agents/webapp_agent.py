import asyncio
import subprocess
import json
import re
import time
import shutil
import os
import sys
from pathlib import Path
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from pydantic import BaseModel, Field, field_validator

# Setup import from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import find_tool, require_sudo
from config import run_config as settings

console = Console()

# ── Pydantic Models ──────────────────────────────────────────────────────────

class WafResult(BaseModel):
    detected: bool = False
    waf_name: str = ""
    manufacturer: str = ""
    confidence: str = ""

class WhatWebResult(BaseModel):
    server: str = ""
    powered_by: str = ""
    cms: str = ""
    cms_version: str = ""
    frameworks: list[str] = []
    php_version: str = ""
    jquery_version: str = ""
    title: str = ""
    emails: list[str] = []
    login_form: bool = False
    redirect_to: str = ""
    cookies: list[str] = []
    raw_plugins: dict = {}

class NiktoFinding(BaseModel):
    id: str
    osvdb: str = ""
    method: str = ""
    url: str = ""
    description: str = ""
    category: str = ""   # interesting_file/misconfig/vuln/info

class GobusterFinding(BaseModel):
    path: str
    status_code: int
    size: int = 0
    redirect_to: str = ""
    is_interesting: bool = False
    reason: str = ""   # why flagged as interesting

class WebAppResult(BaseModel):
    host: str
    url_http: str = ""
    url_https: str = ""
    http_alive: bool = False
    https_alive: bool = False
    waf: Optional[WafResult] = None
    whatweb: Optional[WhatWebResult] = None
    nikto_findings: list[NiktoFinding] = []
    gobuster_dirs: list[GobusterFinding] = []
    gobuster_files: list[GobusterFinding] = []
    gobuster_vhosts: list[str] = []
    interesting_paths: list[str] = []   # aggregated high-value paths
    login_pages: list[str] = []
    backup_files: list[str] = []
    exposed_files: list[str] = []       # .env, .git, config files
    tech_stack: list[str] = []          # aggregated from whatweb+nikto
    risk_flags: list[str] = []          # human readable risk notes
    scan_errors: dict[str, str] = {}
    aggressive_scan: bool = True        # False if WAF detected

# ── Helpers ──────────────────────────────────────────────────────────────────

def _check_alive(url: str) -> bool:
    """Quick HTTP HEAD check — is the host serving web traffic?"""
    try:
        r = httpx.head(url, timeout=5, follow_redirects=True, verify=False)
        return r.status_code < 500
    except Exception:
        return False

def _flag_interesting(path: str, status: int) -> tuple[bool, str]:
    """Return (is_interesting, reason) for a gobuster result."""
    high_value = [
        ".env", ".git", "config", "backup", "admin", "login",
        "dashboard", "wp-admin", "phpmyadmin", "console",
        ".sql", ".db", ".bak", ".old", ".zip", "secret",
        "api", "swagger", "graphql", "actuator", "debug",
        "upload", "uploads", "shell", "cmd", "exec",
        "robots.txt", "sitemap.xml", ".htaccess",
    ]
    path_lower = path.lower()
    for keyword in high_value:
        if keyword in path_lower:
            return True, f"contains '{keyword}'"
    if status == 401:
        return True, "auth required — potential restricted area"
    return False, ""

# ── Per-Tool Functions ────────────────────────────────────────────────────────

def _run_wafw00f(url: str, result: WebAppResult) -> None:
    """Detect WAF before running any active tools."""
    host_safe = result.host.replace(".", "_")
    output_file = f"/tmp/waf_{host_safe}.json"
    
    wafw00f_path = shutil.which("wafw00f")
    if wafw00f_path:
        try:
            subprocess.run(["wafw00f", "-a", "-o", output_file, "-f", "json", url], 
                           capture_output=True, timeout=60)
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list) and len(data) > 0:
                        waf_info = data[0]
                        fw = waf_info.get("firewall", "None")
                        if fw != "None":
                            result.waf = WafResult(
                                detected=True,
                                waf_name=fw,
                                manufacturer=waf_info.get("manufacturer", ""),
                                confidence="automated"
                            )
                            result.aggressive_scan = False
                            return # Successfully detected
                        else:
                            result.waf = WafResult(detected=False)
                            return
        except Exception as e:
            result.scan_errors["wafw00f"] = str(e)
    
    # Fallback to manual HTTPx heuristic
    try:
        r = httpx.get(f"{url}/?id=1'%20OR%201=1--", timeout=5, verify=False)
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        body = r.text.lower()
        
        waf_detected = False
        waf_name = ""
        
        # Check standard WAF headers
        if "server" in headers and "cloudflare" in headers["server"]:
            waf_detected = True
            waf_name = "Cloudflare"
        elif "x-sucuri-id" in headers:
            waf_detected = True
            waf_name = "Sucuri"
        elif any(h.startswith("x-fw-") or h.startswith("x-waf-") for h in headers.keys()):
            waf_detected = True
            waf_name = "Generic Firewall Header"
            
        # Check standard WAF blocks in body
        if "access denied" in body and r.status_code in [403, 406]:
             waf_detected = True
             waf_name = "Generic Block Page"
             
        if waf_detected:
            result.waf = WafResult(detected=True, waf_name=waf_name, confidence="heuristic")
            result.aggressive_scan = False
        else:
            result.waf = WafResult(detected=False)
            
    except Exception as e:
        result.scan_errors["wafw00f_fallback"] = str(e)

def _run_whatweb(url: str, result: WebAppResult) -> None:
    """CMS, framework, server, version detection."""
    host_safe = result.host.replace(".", "_")
    output_file = f"/tmp/whatweb_{host_safe}.json"
    
    whatweb_path = find_tool("whatweb")
    if whatweb_path:
        try:
            subprocess.run([whatweb_path, f"--log-json={output_file}", "--aggression=3", "--quiet", url],
                          capture_output=True, timeout=120)
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    
                target_data = data[0] if isinstance(data, list) and len(data) > 0 else data if isinstance(data, dict) else {}
                plugins = target_data.get("plugins", {})
                
                ww_res = WhatWebResult(raw_plugins=plugins)
                
                if "HTTPServer" in plugins:
                    ww_res.server = ", ".join(plugins["HTTPServer"].get("string", []))
                
                if "X-Powered-By" in plugins:
                    ww_res.powered_by = ", ".join(plugins["X-Powered-By"].get("string", []))
                    
                if "PHP" in plugins:
                    ww_res.php_version = ", ".join(plugins["PHP"].get("version", []))
                    
                if "WordPress" in plugins:
                    ww_res.cms = "WordPress"
                    ww_res.cms_version = ", ".join(plugins["WordPress"].get("version", []))
                elif "Joomla" in plugins:
                    ww_res.cms = "Joomla"
                elif "Drupal" in plugins:
                    ww_res.cms = "Drupal"
                    
                if "JQuery" in plugins:
                    ww_res.jquery_version = ", ".join(plugins["JQuery"].get("version", []))
                    
                if "Title" in plugins:
                    ww_res.title = ", ".join(plugins["Title"].get("string", []))
                    
                if "Email" in plugins:
                    ww_res.emails = plugins["Email"].get("string", [])
                    
                if "PasswordField" in plugins:
                    ww_res.login_form = True
                    
                if "RedirectLocation" in plugins:
                    ww_res.redirect_to = ", ".join(plugins["RedirectLocation"].get("string", []))
                    
                if "Cookies" in plugins:
                    ww_res.cookies = plugins["Cookies"].get("string", [])
                    
                result.whatweb = ww_res
                return
        except Exception as e:
            result.scan_errors["whatweb"] = str(e)

    # Fallback to header parsing
    try:
        r = httpx.head(url, timeout=10, follow_redirects=True, verify=False)
        headers = r.headers
        ww_res = WhatWebResult()
        
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        generator = headers.get("x-generator", "")
        
        if server: ww_res.server = server
        if powered: ww_res.powered_by = powered
            
        result.whatweb = ww_res
        result.tech_stack = [x for x in [server, powered, generator] if x]
    except Exception as e:
        result.scan_errors["whatweb_fallback"] = str(e)


def _run_nikto(url: str, result: WebAppResult) -> None:
    """Vulnerability scan + misconfig detection."""
    nikto_path = find_tool("nikto")
    if not nikto_path:
        result.scan_errors["nikto"] = "nikto binary not found"
        return
        
    host_safe = result.host.replace(".", "_")
    output_file = f"/tmp/nikto_{host_safe}.json"
    
    cmd = [nikto_path, "-h", url, "-Format", "json", "-output", output_file, "-Tuning", "1234578", "-timeout", "10", "-nointeractive", "-maxtime", "120s"]
    if not result.aggressive_scan:
        cmd.extend(["-Pause", "2"])
        
    try:
        start_time = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=140)
        run_time = time.time() - start_time
        
        if run_time < 5.0 and proc.returncode != 0:
            result.scan_errors["nikto"] = f"Failed, exited too fast ({run_time:.1f}s)"
            return
            
        findings = []
        parsed_json = False
        
        if Path(output_file).exists():
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                
                items = data.get("vulnerabilities", []) or data.get("items", [])
                
                for item in items:
                    desc_orig = item.get("msg", item.get("description", ""))
                    desc = desc_orig.lower()
                    cat = "info"
                    
                    if any(x in desc for x in ["backup", ".bak", ".old"]):
                        cat = "interesting_file"
                    elif any(x in desc for x in ["directory", "listing"]):
                        cat = "misconfig"
                    elif any(x in desc for x in ["xss", "injection", "rce", "sql"]):
                        cat = "vuln"
                    
                    finding = NiktoFinding(
                        id=str(item.get("id", "")),
                        osvdb=str(item.get("osvdb", "")),
                        method=item.get("method", ""),
                        url=item.get("url", ""),
                        description=desc_orig,
                        category=cat
                    )
                    findings.append(finding)
                if findings: parsed_json = True
            except Exception:
                pass
            
        if not parsed_json and proc.stdout:
            for line in proc.stdout.splitlines():
                if line.startswith("+ OSVDB-") or line.startswith("+ "):
                    desc = line.strip("+ ").strip()
                    cat = "info"
                    d = desc.lower()
                    if any(x in d for x in ["backup", ".bak", ".old"]): cat = "interesting_file"
                    elif any(x in d for x in ["directory", "listing"]): cat = "misconfig"
                    elif any(x in d for x in ["xss", "injection", "rce", "sql"]): cat = "vuln"
                    findings.append(NiktoFinding(id="", osvdb="", method="", url="", description=desc, category=cat))
                    
        result.nikto_findings = findings
            
    except subprocess.TimeoutExpired:
        result.scan_errors["nikto"] = "nikto run timed out (>120s)"
    except Exception as e:
        result.scan_errors["nikto"] = str(e)


def _run_gobuster(url: str, domain: str, result: WebAppResult, user_wordlist: str = None) -> None:
    """Dir + file + vhost brute force."""
    gobuster_path = find_tool("gobuster")
    if not gobuster_path: return

    def _resolve_wordlist() -> str:
        # If user provided -w flag, use that first
        if user_wordlist and os.path.exists(user_wordlist):
            return user_wordlist
        
        candidates = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt", 
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/local/share/seclists/Discovery/Web-Content/common.txt",
            os.path.expanduser("~/wordlists/common.txt"),
            "/tmp/redchain_wordlist.txt",
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        # Download fallback wordlist if none found
        url_dl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        dest = "/tmp/redchain_wordlist.txt"
        try:
            import urllib.request
            urllib.request.urlretrieve(url_dl, dest)
            return dest
        except Exception:
            return None

    selected_wordlist = _resolve_wordlist()
    if not selected_wordlist:
        return
        
    host_safe = result.host.replace(".", "_")
    
    def parse_gobuster(filepath: str) -> list[GobusterFinding]:
        findings = []
        if not Path(filepath).exists():
            return findings
            
        with open(filepath, "r") as f:
            for line in f:
                match = re.search(r"(/[\S]*)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?(?:.*\[-->\s+(.*)\])?", line)
                if match:
                    path = match.group(1)
                    status = int(match.group(2))
                    size = int(match.group(3)) if match.group(3) else 0
                    redirect = match.group(4) if match.group(4) else ""
                    
                    is_int, reason = _flag_interesting(path, status)
                    
                    findings.append(GobusterFinding(
                        path=path,
                        status_code=status,
                        size=size,
                        redirect_to=redirect,
                        is_interesting=is_int,
                        reason=reason
                    ))
        return findings

    # Mode 1: Dir
    if gobuster_path:
        out_dir = f"/tmp/gobuster_dir_{host_safe}.txt"
        cmd = ["gobuster", "dir", "-u", url, "-w", selected_wordlist, "-x", "php,html,txt,json,xml,bak,old,zip,tar.gz,sql,conf,config", "-o", out_dir, "--timeout", "10s", "-b", "404,403", "-q"]
        
        if not result.aggressive_scan:
             cmd.extend(["-t", "5", "--delay", "500ms"])
        else:
             cmd.extend(["-t", "30"])
             
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            result.gobuster_dirs = parse_gobuster(out_dir)
        except subprocess.TimeoutExpired:
            result.scan_errors["gobuster_dir"] = "Timeout"
        except Exception as e:
            result.scan_errors["gobuster_dir"] = str(e)
            
    # Mode 2: Files
    if gobuster_path:
        out_files = f"/tmp/gobuster_files_{host_safe}.txt"
        cmd = ["gobuster", "dir", "-u", url, "-w", selected_wordlist, "-x", "bak,old,backup,zip,tar,gz,sql,db,sqlite,log,conf,config,env,.env,ini,xml,yaml,yml,json,key,pem,cert", "-o", out_files, "-q"]
        if not result.aggressive_scan:
             cmd.extend(["-t", "5", "--delay", "500ms"])
        else:
             cmd.extend(["-t", "20"])
             
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            result.gobuster_files = parse_gobuster(out_files)
        except subprocess.TimeoutExpired:
            pass
            
    # Mode 3: Vhosts (if domain)
    if gobuster_path and domain and url.endswith(domain):
        vhost_wl = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if Path(vhost_wl).exists():
            out_vhost = f"/tmp/gobuster_vhost_{host_safe}.txt"
            cmd = ["gobuster", "vhost", "-u", url, "-w", vhost_wl, "--append-domain", "-o", out_vhost, "-q", "-t", "20"]
            try:
                subprocess.run(cmd, capture_output=True, timeout=120)
                vhosts = []
                if Path(out_vhost).exists():
                    with open(out_vhost, 'r') as f:
                        for line in f:
                            match = re.search(r"Found:\s+([\S]+)", line)
                            if match:
                                vhosts.append(match.group(1))
                result.gobuster_vhosts = vhosts
            except Exception:
                pass


def _aggregate_results(result: WebAppResult) -> None:
    """Combine and map to structured findings arrays."""
    int_paths = set()
    login_paths = set()
    backup_paths = set()
    exposed_paths = set()
    tech = set()
    flags = []

    # Aggregate interesting paths
    for gd in result.gobuster_dirs + result.gobuster_files:
        if gd.is_interesting or gd.status_code in [401, 403]:
            int_paths.add(gd.path)
            
        p_lower = gd.path.lower()
        if any(x in p_lower for x in ["login", "signin", "auth", "portal", "admin", "dashboard", "wp-login", "wp-admin", "administrator", "account", "user"]):
            login_paths.add(gd.path)
            
        if any(x in p_lower for x in [".bak", ".old", ".backup", ".zip", ".tar", ".gz", ".sql", ".db", ".sqlite", ".dump", "~", ".swp", ".orig"]):
            backup_paths.add(gd.path)
            
        if any(x in p_lower for x in [".env", ".git", ".htaccess", ".htpasswd", "config", "settings", "credentials", "secret", "key", "pem", "cert", "id_rsa"]):
            exposed_paths.add(gd.path)

    for nf in result.nikto_findings:
        if nf.category == "interesting_file":
            int_paths.add(nf.url)
        elif nf.category == "misconfig" and "directory" in nf.description.lower():
            flags.append(f"Directory listing enabled at {nf.url}")
        elif nf.method == "PUT":
            flags.append("HTTP PUT enabled — file upload may be possible")

    # Aggregate Tech Stack
    if result.whatweb:
        if result.whatweb.server: tech.add(result.whatweb.server)
        if result.whatweb.powered_by: tech.add(result.whatweb.powered_by)
        if result.whatweb.cms: tech.add(f"{result.whatweb.cms} {result.whatweb.cms_version}".strip())
    
    # Generate Risk Flags
    if result.waf and result.waf.detected:
        flags.append(f"WAF: {result.waf.waf_name} — adjust exploit approach")
        
    for ep in exposed_paths:
        if ".env" in ep.lower():
            flags.append(f"CRITICAL: .env file exposed at {ep}")
        if ".git" in ep.lower():
            flags.append(f"CRITICAL: .git directory exposed — source code may be recoverable")
            
    if login_paths and not (result.waf and result.waf.detected):
        lp = list(login_paths)[0]
        flags.append(f"Login page at {lp} — test default credentials")
        
    if result.whatweb and result.whatweb.cms:
        flags.append(f"CMS: {result.whatweb.cms} {result.whatweb.cms_version} — run specific scanner if applicable")
        
    for bp in backup_paths:
        if "phpmyadmin" in bp.lower():
            flags.append(f"CRITICAL: phpMyAdmin exposed at {bp}")

    # Set Aggregated Fields
    result.interesting_paths = list(int_paths)
    result.login_pages = list(login_paths)
    result.backup_files = list(backup_paths)
    result.exposed_files = list(exposed_paths)
    result.tech_stack = list(tech)
    result.risk_flags = flags


# ── Main Agent Entry Point ────────────────────────────────────────────────────

async def run_webapp_fingerprint(state: dict) -> dict:
    """
    Phase 2.5 — web app fingerprinting.
    Reads: state["target"] + state["subdomains"] + state["live_hosts"]
    Writes: state["webapp_results"]
    """
    hosts_input = state.get("live_hosts", [])
    subdomains_input = state.get("subdomains", [])
    domain = state.get("target", "")
    
    # Build list of dicts with {ip: ip, subdomain: sub} structure
    hosts = []
    
    # ── Always include the primary domain first ──────────────────────────
    if domain:
        hosts.append({"subdomain": domain})
    
    # Process from live_hosts (IPs)
    for host in hosts_input:
        if not any(h.get("ip") == host or h.get("subdomain") == host for h in hosts):
            hosts.append({"ip": host})
        
    # Process from subdomains
    for sub in subdomains_input:
        if sub.get("alive"): # Only take alive subdomains
            sub_name = sub.get("subdomain")
            # Make sure we don't duplicate (also skip if same as primary domain)
            if sub_name and sub_name != domain and not any(h.get("subdomain") == sub_name for h in hosts):
                 hosts.append({"ip": sub.get("ip"), "subdomain": sub_name})
    
    # If hosts is empty, directly return
    if not hosts:
        state["webapp_results"] = []
        return state

    results: list[WebAppResult] = []

    console.rule("[bold red]Phase 2.5 — Web App Fingerprinting[/bold red]")
    console.print(f"[dim]Fingerprinting {len(hosts)} live hosts (including primary domain)[/dim]\n")

    def _process_host(host_info: dict) -> Optional[WebAppResult]:
        host = host_info.get("subdomain") or host_info.get("ip")
        if not host:
            return None
            
        res = WebAppResult(host=host)

        # Determine which URLs to scan
        res.url_http = f"http://{host}"
        res.url_https = f"https://{host}"
        res.http_alive = _check_alive(res.url_http)
        res.https_alive = _check_alive(res.url_https)

        if not res.http_alive and not res.https_alive:
            console.print(f"[dim]  {host} — no web service, skipping[/dim]")
            return None

        # Use HTTPS preferentially if both alive
        active_url = res.url_https if res.https_alive else res.url_http

        console.print(f"\n[bold]{host}[/bold] — {active_url}")

        # Step 1: WAF check (always first)
        _run_wafw00f(active_url, res)
        waf_str = f"[red]WAF: {res.waf.waf_name}[/red]" if res.waf and res.waf.detected else "[green]No WAF[/green]"
        console.print(f"   wafw00f ........... {waf_str}")

        # Step 2: WhatWeb
        _run_whatweb(active_url, res)
        tech = ", ".join(res.tech_stack[:4]) if hasattr(res, "tech_stack") and res.tech_stack else "unknown"
        if res.whatweb:
             temps = []
             if res.whatweb.server: temps.append(res.whatweb.server)
             if res.whatweb.powered_by: temps.append(res.whatweb.powered_by)
             if res.whatweb.cms: temps.append(res.whatweb.cms)
             if temps:
                 tech = ", ".join(temps[:4])
                 
        console.print(f"   whatweb ........... {tech}")

        # Step 3: Nikto
        _run_nikto(active_url, res)
        console.print(f"   nikto ............. {len(res.nikto_findings)} findings")
        # Print individual nikto findings to terminal
        for nf in res.nikto_findings:
            severity_color = "red" if nf.category == "vuln" else "yellow" if nf.category == "misconfig" else "dim"
            console.print(f"     [{severity_color}]→ {nf.url or '/'}: {nf.description[:120]}[/{severity_color}]")

        # Step 4: Gobuster (pass user wordlist from state)
        user_wl = state.get("wordlist")
        _run_gobuster(active_url, domain, res, user_wordlist=user_wl)
        console.print(f"   gobuster .......... {len(res.gobuster_dirs)} dirs, {len(res.gobuster_files)} files")
        # Print discovered directories/files to terminal
        for gf in res.gobuster_dirs[:20]:
            tag = "[green]★[/green]" if gf.is_interesting else " "
            console.print(f"     {tag} [cyan]{gf.path}[/cyan] ({gf.status_code}) [{gf.size}B]{' → ' + gf.redirect_to if gf.redirect_to else ''}")
        for gf in res.gobuster_files[:10]:
            tag = "[green]★[/green]" if gf.is_interesting else " "
            console.print(f"     {tag} [magenta]{gf.path}[/magenta] ({gf.status_code}) [{gf.size}B]")
        if len(res.gobuster_dirs) > 20 or len(res.gobuster_files) > 10:
            console.print(f"     [dim]... and {max(0, len(res.gobuster_dirs)-20) + max(0, len(res.gobuster_files)-10)} more[/dim]")

        # Aggregate and flag
        _aggregate_results(res)

        if res.risk_flags:
            for flag in res.risk_flags:
                console.print(f"   [yellow]⚠ {flag}[/yellow]")
                
        return res

    import asyncio
    sem = asyncio.Semaphore(10)
    
    async def _bound_process(host_info):
        async with sem:
            return await asyncio.to_thread(_process_host, host_info)

    tasks = [
        _bound_process(host_info)
        for host_info in hosts
    ]
    
    completed_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for r in completed_results:
        if isinstance(r, Exception):
            console.print(f"[red]Error processing host:[/red] {r}")
        elif r is not None:
            results.append(r)

    # Print final summary table
    _print_summary(results)

    state["webapp_results"] = [r.model_dump() for r in results]
    return state

def _print_summary(results: list[WebAppResult]) -> None:
    table = Table(title="Web Application Fingerprinting Summary")
    table.add_column("Host", style="cyan")
    table.add_column("Tech Stack", style="green")
    table.add_column("Dirs", justify="right")
    table.add_column("Vulns", justify="right")
    table.add_column("Risk Flags", style="red")

    for res in results:
        tech_str = ", ".join(res.tech_stack[:3])
        dir_count = str(len(res.gobuster_dirs) + len(res.gobuster_files))
        vuln_count = str(len([n for n in res.nikto_findings if n.category == "vuln"]))
        flags_str = ", ".join(res.risk_flags[:2])
        if len(res.risk_flags) > 2:
            flags_str += "..."
            
        table.add_row(
            res.host,
            tech_str or "unknown",
            dir_count,
            vuln_count,
            flags_str or "-"
        )
        
    console.print(table)
