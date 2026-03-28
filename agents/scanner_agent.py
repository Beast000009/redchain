from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from tools.nmap_wrapper import run_nmap_scan
import ipaddress
import subprocess
import httpx
import time
from rich.console import Console
from packaging.version import Version, InvalidVersion
import json
import shutil
import nmap
import os
import sys

# Setup import from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import find_tool, require_sudo, IS_WINDOWS, get_temp_path, get_redchain_home, get_proxychains_prefix, make_httpx_transport
from config import run_config

console = Console()

class ServiceDetail(BaseModel):
    host: str
    port: int
    protocol: str               # tcp/udp
    state: str                  # open/filtered
    service_name: str           # ssh, http, ftp, etc
    product: str                # OpenSSH, Apache httpd, etc
    version: str                # 7.4, 2.4.51, etc
    extra_info: str             # debian, ubuntu, etc
    os_type: str
    cpe: list[str]              # cpe:/a:openbsd:openssh:7.4
    banner: str
    http_title: str             # from http-title script
    http_methods: list[str]     # from http-methods script
    ssl_subject: str            # from ssl-cert script
    ssl_issuer: str
    ssl_expiry: str
    ssh_hostkey: str            # from ssh-hostkey script
    smb_os: str                 # from smb-os-discovery
    script_output: dict         # raw nmap script outputs

class ExploitResult(BaseModel):
    edb_id: str
    title: str
    exploit_type: str           # remote / local / dos / webapps
    platform: str               # linux, windows, php, etc
    date: str
    url: str                    # https://www.exploit-db.com/exploits/{edb_id}
    local_path: str             # /usr/share/exploitdb/exploits/...
    verified: bool
    source: str                 # searchsploit / ghdb
    matched_on: str             # what query found this (e.g. "OpenSSH 7.4")
    exact_match: bool = False   # True if Version exactly matched

class GHDBDork(BaseModel):
    dork: str
    description: str
    category: str
    url: str                    # full ghdb entry URL

class ServiceExploits(BaseModel):
    service: ServiceDetail
    searchsploit_results: list[ExploitResult] = []
    ghdb_dorks: list[GHDBDork] = []
    cve_exploits: list[ExploitResult] = []  # EDB entries for known CVEs
    exploit_count: int = 0
    highest_risk: str = "none"  # remote/local/dos/none
    notes: list[str] = []       # human readable risk notes




def grab_banner(ip: str, port: int, timeout: int = 2) -> str:
    """Attempts to grab a basic banner using raw sockets."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in [80, 443, 8080, 8443]:
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            else:
                s.sendall(b"\r\n")
            return s.recv(1024).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""

import csv
import io

_EXPLOIT_DB_CSV = None

async def _fetch_exploit_db_csv() -> list[dict]:
    """
    Fetch (or load from disk cache) the ExploitDB files_exploits.csv.
    Cache is stored at ~/.redchain/exploitdb.csv and refreshed every 24h.
    """
    global _EXPLOIT_DB_CSV
    if _EXPLOIT_DB_CSV is not None:
        return _EXPLOIT_DB_CSV

    # ── Try disk cache first ─────────────────────────────────────────────────
    cache_path = get_redchain_home() / "exploitdb.csv"
    cache_ttl_seconds = 24 * 3600  # 24 hours

    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < cache_ttl_seconds:
            try:
                with open(cache_path, "r", encoding="utf-8", errors="ignore") as f:
                    _EXPLOIT_DB_CSV = list(csv.DictReader(f))
                console.print(f"[dim]ExploitDB CSV loaded from cache ({int(age/3600)}h old, {len(_EXPLOIT_DB_CSV)} entries)[/dim]")
                return _EXPLOIT_DB_CSV
            except Exception:
                pass

    # ── Download fresh copy ──────────────────────────────────────────────────
    url = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                raw = resp.text
                _EXPLOIT_DB_CSV = list(csv.DictReader(io.StringIO(raw)))
                # Persist to disk
                try:
                    cache_path.write_text(raw, encoding="utf-8")
                    console.print(f"[dim]ExploitDB CSV downloaded and cached ({len(_EXPLOIT_DB_CSV)} entries) → {cache_path}[/dim]")
                except Exception:
                    pass
                return _EXPLOIT_DB_CSV
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to fetch ExploitDB CSV: {e}[/yellow]")

    return []

async def _run_searchsploit(service: ServiceDetail) -> list[ExploitResult]:
    """Runs search by querying the ExploitDB CSV hosted on GitHub."""
    db = await _fetch_exploit_db_csv()
    if not db:
        return []
        
    results: dict[str, ExploitResult] = {}
    
    queries = []
    if service.product and service.version:
        queries.append((f"{service.product} {service.version}".lower(), True))
    if service.product:
        queries.append((service.product.lower(), False))
    if service.cpe:
        queries.append((service.cpe[0].lower(), False))
    if service.service_name and not service.product:
        queries.append((service.service_name.lower(), False))

    for q, exact in queries:
        q_terms = q.split()
        for row in db:
            # Simple AND search over description (title) and platform
            desc = row.get("description", "").lower()
            platform = row.get("platform", "").lower()
            
            # If all search terms are in the description + platform, it's a match
            text_to_search = f"{desc} {platform}"
            if all(term in text_to_search for term in q_terms):
                edb_id = row.get("id")
                if not edb_id or edb_id in results:
                    continue
                    
                exp_type = row.get("type", "unknown").lower()
                
                results[edb_id] = ExploitResult(
                    edb_id=str(edb_id),
                    title=row.get("description", ""),
                    exploit_type=exp_type,
                    platform=row.get("platform", ""),
                    date=row.get("date_published", ""),
                    url=f"https://www.exploit-db.com/exploits/{edb_id}",
                    local_path=row.get("file", ""),
                    verified=True, # CSV mostly contains verified exploits
                    source="exploitdb_csv",
                    matched_on=q,
                    exact_match=exact
                )
                
                # Cap per service to prevent overwhelming output on generic queries (like "http")
                if len(results) > 20: 
                    break
        if len(results) > 20:
            break

    return list(results.values())

async def _run_ghdb(service: ServiceDetail) -> list[GHDBDork]:
    """Queries Exploit-DB GHDB for dorks related to the service/product."""
    dorks = []
    queries = []
    
    if service.product:
        queries.append(service.product)
    elif service.service_name:
        queries.append(service.service_name)
        
    categories = []
    if service.port in (80, 443, 8080, 8443) or "http" in service.service_name:
        categories = ["intitle", "inurl"]
    elif "ftp" in service.service_name:
        categories = ["ftp"]
    elif "ssh" in service.service_name:
        categories = ["ssh"]
        
    async with httpx.AsyncClient(timeout=10.0) as client:
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        for q in queries:
            try:
                url = f"https://www.exploit-db.com/ghdb?ghdb_search={q}&action=search&start=0&length=5"
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        dork_id = item.get("id", "")
                        dorks.append(GHDBDork(
                            dork=item.get("url_title", item.get("ghdb_dork", "")), # GHDB API uses url_title sometimes
                            description=item.get("ghdb_description", ""),
                            category=item.get("category", {}).get("cat_title", ""),
                            url=f"https://www.exploit-db.com/ghdb/{dork_id}"
                        ))
            except Exception:
                pass
                
    return dorks

async def _check_cve_edb(cve_id: str) -> Optional[ExploitResult]:
    """Cross-references a CVE ID with Exploit-DB to see if public exploits exist."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        url = f"https://www.exploit-db.com/search?cve={cve_id}&action=search"
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("data", [])
                if results:
                    # Just grab the first verified one or top one
                    item = sorted(results, key=lambda x: int(x.get("verified", 0)), reverse=True)[0]
                    edb_id = item.get("id")
                    return ExploitResult(
                        edb_id=str(edb_id),
                        title=item.get("description", [None, ""])[1], # EDB API encapsulates in arrays sometimes
                        exploit_type=item.get("type_id", ""),
                        platform=item.get("platform_id", ""),
                        date=item.get("date_published", ""),
                        url=f"https://www.exploit-db.com/exploits/{edb_id}",
                        local_path="",
                        verified=bool(item.get("verified", 0)),
                        source="cve_edb",
                        matched_on=cve_id,
                        exact_match=True
                    )
        except Exception:
            pass
    return None

async def run_scanner(target: str, input_type: str, live_hosts: List[str], wordlist: Optional[str] = None, webapp_results: List[Dict[str, Any]] = []) -> tuple[List[str], List[Dict[str, Any]]]:
    """
    Executes Phase 3 Scanner Agent.
    Runs deep nmap scan on live hosts, parses output into ServiceDetail.
    Runs exploit discovery (searchsploit + GHDB).
    Runs gobuster for directory busting.
    Returns (updated_live_hosts, scan_results).
    """
    scan_targets = list(live_hosts)
    
    if not scan_targets:
        if input_type == "ip":
            scan_targets = [target]
        elif input_type == "cidr":
            try:
                network = ipaddress.ip_network(target, strict=False)
                scan_targets = [str(ip) for ip in list(network.hosts())[:256]]
            except ValueError:
                scan_targets = [target]
                
    if not scan_targets:
        return [], []

    # ── Deduplicate IPs ──────────────────────────────────────────────────────
    # Subdomains often resolve to the same IP (CDN, shared hosting).
    # Scanning duplicates wastes massive time.
    import socket
    ip_to_hosts: dict[str, list[str]] = {}
    for h in scan_targets:
        try:
            ip = socket.gethostbyname(h)
        except Exception:
            ip = h  # Already an IP or unresolvable
        ip_to_hosts.setdefault(ip, []).append(h)
    
    unique_ips = list(ip_to_hosts.keys())
    dedup_count = len(scan_targets) - len(unique_ips)
    if dedup_count > 0:
        console.print(f"[dim]Deduplicated {len(scan_targets)} hosts → {len(unique_ips)} unique IPs (removed {dedup_count} duplicates)[/dim]")
    scan_targets = unique_ips

    # --- NMAP Deep Scan ---
    nm = nmap.PortScanner()
    
    # ── Port count: user --ports flag overrides profile default ───────────
    user_ports = getattr(run_config, 'ports', 0)
    profile = getattr(run_config, 'profile', 'full')
    
    if user_ports > 0:
        # User explicitly chose a port count
        port_count = user_ports
        console.print(f"[dim]Using user-specified port count: --top-ports {port_count}[/dim]")
    elif profile == 'quick':
        port_count = 50
    elif profile == 'stealth':
        port_count = 100
    else:
        port_count = 200  # full / compliance — covers 95%+ of real services
    
    port_flag = f"--top-ports {port_count}"
    
    flags = f"-sV --version-intensity 5 -sC {port_flag}"
    # Added -Pn to skip host discovery
    flags += " -Pn"
    
    if require_sudo():
        flags += " -O"
        console.print("[dim]Root privileges detected: enabling Nmap OS validation (-O)[/dim]")
    else:
        console.print("[dim]Root privileges missing: skipping Nmap OS validation (-O) to prevent permission errors.[/dim]")
    
    # Focused scripts covering the full attack surface
    scripts = [
        "banner", "http-title", "http-server-header", "ssl-cert",
        "ssh-hostkey", "http-methods", "http-robots.txt",
        # SSL/TLS vulnerabilities
        "ssl-dh-params", "ssl-heartbleed", "ssl-poodle",
        # Service misconfigs
        "ftp-anon", "ftp-bounce",
        "smtp-commands", "smtp-open-relay",
        "ms-sql-info", "mysql-info",
        "ldap-rootdse",
        "rdp-enum-encryption",
        # Web / Auth
        "http-auth-finder", "http-backup-finder",
        # DNS
        "dns-zone-transfer",
    ]
    
    aggressive = not run_config.stealth
    for wa in webapp_results:
        if not wa.get("aggressive_scan", True):
            aggressive = False
            console.print(f"[yellow]WAF detected on {wa.get('host')} - switching to stealth (-T2) nmap scan.[/yellow]")
            
        tech = wa.get("tech_stack", [])
        if any("WordPress" in t for t in tech):
            console.print(f"[cyan]WordPress detected on {wa.get('host')} - adding http-wordpress scripts for Nmap enumeration.[/cyan]")
            scripts.extend(["http-wordpress-users", "http-wordpress-enum"])

    flags += f" --script={','.join(set(scripts))}"
    
    if aggressive:
        flags += " -T4"
    else:
        flags += " -T2"

    # ── Nmap timeout — prevent runaway scans ─────────────────────────────────
    # Scale timeout with port count: ~2 sec per port per host, minimum 5 min
    nmap_timeout = max(300, port_count * 2)
    flags += f" --host-timeout {nmap_timeout}s"
        
    # ── Batch scanning — scan max 8 hosts at a time ──────────────────────────
    BATCH_SIZE = 8
    all_nm_hosts: list[str] = []
    
    # ── Estimated time ───────────────────────────────────────────────────────
    time_per_host = {50: "~30s", 100: "~1m", 200: "~2m", 1000: "~5-10m"}
    est = time_per_host.get(port_count, f"~{port_count // 50}m")
    total_batches = (len(scan_targets) + BATCH_SIZE - 1) // BATCH_SIZE
    
    console.print(f"[bold cyan]Running Nmap scan: {len(scan_targets)} hosts × {port_count} ports ({est}/host, {total_batches} batch{'es' if total_batches > 1 else ''})[/bold cyan]")
    
    for i in range(0, len(scan_targets), BATCH_SIZE):
        batch = scan_targets[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (len(scan_targets) + BATCH_SIZE - 1) // BATCH_SIZE
        
        if total_batches > 1:
            console.print(f"[dim]  Batch {batch_num}/{total_batches}: {len(batch)} hosts[/dim]")
        
        target_str = " ".join(batch)
        try:
            try:
                nm.scan(hosts=target_str, arguments=flags)
            except nmap.PortScannerError as e:
                if "root privileges" in str(e).lower() or "requires root" in str(e).lower():
                    console.print("[yellow]Nmap OS detection (-O) failed due to lack of root privileges. Falling back without -O.[/yellow]")
                    fallback_flags = flags.replace(" -O", "")
                    nm.scan(hosts=target_str, arguments=fallback_flags)
                else:
                    raise e
            all_nm_hosts.extend(nm.all_hosts())
        except Exception as e:
            console.print(f"[bold red]Nmap batch {batch_num} failed: {e}[/bold red]")

    actual_live = []
    scan_results = []
    
    service_exploits_list: list[ServiceExploits] = []

    for host in all_nm_hosts:
        host_ip = host
        actual_live.append(host_ip)
        
        host_data = {
            "host": host_ip,
            "os_guess": None,
            "open_ports": [],
            "service_exploits": [],
            "directories": []
        }
        
        if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
            host_data['os_guess'] = nm[host]['osmatch'][0]['name']
            
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_data = nm[host][proto][port]
                if port_data['state'] == 'open':
                    
                    # Extract script outputs
                    scripts_dict = port_data.get('script', {})
                    
                    # Optional extra values
                    http_title = scripts_dict.get('http-title', '')
                    http_methods = scripts_dict.get('http-methods', '')  # Note: Nmap parses this weirdly as a string block
                    ssl_cert = scripts_dict.get('ssl-cert', '')
                    ssh_hostkey = scripts_dict.get('ssh-hostkey', '')
                    smb_os = scripts_dict.get('smb-os-discovery', '')
                    banner = scripts_dict.get('banner', '')
                    if not banner:
                        banner = grab_banner(host_ip, port)

                    svc = ServiceDetail(
                        host=host_ip,
                        port=port,
                        protocol=proto,
                        state=port_data['state'],
                        service_name=port_data.get('name', ''),
                        product=port_data.get('product', ''),
                        version=port_data.get('version', ''),
                        extra_info=port_data.get('extrainfo', ''),
                        os_type=port_data.get('ostype', ''),
                        cpe=[port_data['cpe']] if 'cpe' in port_data else [],
                        banner=banner,
                        http_title=http_title,
                        http_methods=[http_methods] if http_methods else [], # Simplification for now
                        ssl_subject=ssl_cert,
                        ssl_issuer="", # Will parse out if needed
                        ssl_expiry="",
                        ssh_hostkey=ssh_hostkey,
                        smb_os=smb_os,
                        script_output=scripts_dict
                    )
                    
                    console.print(f"[bold green][ SCAN ][/bold green] Host: {host_ip} Port {port} {svc.product} {svc.version} {svc.extra_info}")
                    
                    # Append raw generic port data for compatibility with earlier phases
                    host_data['open_ports'].append({
                        "port": port,
                        "protocol": proto,
                        "service": svc.service_name,
                        "version": svc.version,
                        "banner": banner
                    })
                    
                    service_exploits_list.append(ServiceExploits(service=svc))
        
        # Step 2 & 3: Run Exploit mapping for all services on this host concurrently
        import asyncio
        host_se_indices = [i for i, se in enumerate(service_exploits_list) if se.service.host == host_ip]
        if host_se_indices:
            search_tasks = [_run_searchsploit(service_exploits_list[i].service) for i in host_se_indices]
            ghdb_tasks = [_run_ghdb(service_exploits_list[i].service) for i in host_se_indices]
            
            console.print(f"[bold cyan]Running explicit exploit discovery for {len(host_se_indices)} services on {host_ip}...[/bold cyan]")
            search_results = await asyncio.gather(*search_tasks, return_exceptions=True)
            ghdb_results = await asyncio.gather(*ghdb_tasks, return_exceptions=True)
            
            for list_idx, se_idx in enumerate(host_se_indices):
                se = service_exploits_list[se_idx]
                
                s_res = search_results[list_idx]
                if isinstance(s_res, list):
                    se.searchsploit_results = s_res
                    se.exploit_count += len(s_res)
                    for exp in s_res:
                        if exp.exploit_type == "remote":
                            se.highest_risk = "remote"
                        elif exp.exploit_type == "local" and se.highest_risk != "remote":
                            se.highest_risk = "local"
                        elif exp.exploit_type == "dos" and se.highest_risk not in ("remote", "local"):
                            se.highest_risk = "dos"
                            
                g_res = ghdb_results[list_idx]
                if isinstance(g_res, list):
                    se.ghdb_dorks = g_res
                    if g_res:
                        se.notes.append(f"Found {len(g_res)} potentially relevant GHDB dorks.")
                
                if se.highest_risk != "none":
                    console.print(f"[bold red][ EXPLOIT FOUND ][/bold red] {se.service.product} {se.service.version} ({se.highest_risk})")
        
        # Directory Busting via Gobuster
        if wordlist:
            open_web_ports = [p["port"] for p in host_data.get("open_ports", []) if p["port"] in (80, 443, 8080, 8443)]
            dirs_found = []
            
            for port in open_web_ports:
                scheme = "https" if port in (443, 8443) else "http"
                url_host = target if input_type == "domain" and len(scan_targets) == 1 else host_ip
                url = f"{scheme}://{url_host}:{port}"
                
                console.print(f"[bold cyan]Running directory brute-force on {url}...[/bold cyan]")
                try:
                    proc = subprocess.run(
                        ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-z", "--no-error", "-t", "50"],
                        capture_output=True, text=True, timeout=600
                    )
                    for line in proc.stdout.splitlines():
                        if line.startswith("/"):
                            path = line.split(" ")[0].strip()
                            dirs_found.append(path)
                except FileNotFoundError:
                    console.print(f"[bold yellow]Warning:[/bold yellow] gobuster not found in PATH.")
                    break
                except subprocess.TimeoutExpired:
                    console.print(f"[bold yellow]Warning:[/bold yellow] gobuster timed out on {url}.")
                except Exception:
                    pass
                    
            if dirs_found:
                host_data["directories"] = sorted(list(set(dirs_found)))
        
        host_data["service_exploits"] = [se.model_dump() for se in service_exploits_list if se.service.host == host_ip]
        scan_results.append(host_data)
                    
    return actual_live, scan_results
