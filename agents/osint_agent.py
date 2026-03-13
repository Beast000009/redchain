import asyncio
import subprocess
import json
import re
import os
from pathlib import Path
from datetime import datetime

import httpx
import dns.resolver
import dns.zone
import whois
import shodan
import ipinfo
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from pydantic import BaseModel
from typing import Optional

# Setup import from project root
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import settings

console = Console()

# ── Pydantic output models ────────────────────────────────────────────────────

class WhoisData(BaseModel):
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: list[str] = []
    registrant_org: str = ""
    registrant_country: str = ""
    abuse_email: str = ""
    domain_age_days: int = 0
    newly_registered: bool = False
    expiring_soon: bool = False

class ShodanHost(BaseModel):
    ip: str
    ports: list[int] = []
    hostnames: list[str] = []
    org: str = ""
    os: str = ""
    vulns: list[str] = []
    banners: list[str] = []
    last_update: str = ""

class AsnInfo(BaseModel):
    asn: str = ""
    org: str = ""
    country: str = ""
    ip_ranges: list[str] = []

class DorkResult(BaseModel):
    dork: str
    description: str

class OsintResult(BaseModel):
    domain: str
    emails: list[str] = []
    employee_names: list[str] = []
    hostnames: list[str] = []
    subdomains: list[str] = []
    dns_records: dict[str, list[str]] = {}
    spf_record: str = ""
    dmarc_record: str = ""
    dkim_selectors_found: list[str] = []
    whois: Optional[WhoisData] = None
    shodan_hosts: list[ShodanHost] = []
    asn_info: Optional[AsnInfo] = None
    technologies: list[str] = []
    open_ports_shodan: list[int] = []
    passive_dns_history: list[dict] = []
    otx_malware_hits: int = 0
    urlscan_results: list[dict] = []
    google_dorks: list[DorkResult] = []
    sources_used: list[str] = []
    errors: dict[str, str] = {}


# ── Internal Source Functions ────────────────────────────────────────────────

def _run_harvester(domain: str, result: OsintResult):
    out_file = f"/tmp/harvest_{domain}"
    try:
        proc = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "all", "-l", "500", "-f", out_file],
            capture_output=True, text=True, timeout=120
        )
        # Parse JSON
        json_path = f"{out_file}.json"
        if os.path.exists(json_path):
            with open(json_path, "r") as f:
                data = json.load(f)
                result.emails.extend(data.get("emails", []))
                result.hostnames.extend(data.get("hosts", []))
                result.employee_names.extend(data.get("linkedin", []))
            # Cleanup
            for ext in [".json", ".xml", ".html"]:
                try: os.remove(f"{out_file}{ext}")
                except Exception: pass
            
        result.sources_used.append("theHarvester")
        console.print(f"[green]✓[/green] [gray]theHarvester[/gray]: {len(result.emails)} emails, {len(result.hostnames)} hosts")
    except FileNotFoundError:
        console.print(f"[yellow]![/yellow] [gray]theHarvester[/gray]: Not installed in PATH")
        result.errors["theHarvester"] = "Not in PATH"
    except Exception as e:
        result.errors["theHarvester"] = str(e)
        console.print(f"[yellow]✗[/yellow] [gray]theHarvester[/gray]: {e}")

def _run_subfinder(domain: str, result: OsintResult):
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-json"],
            capture_output=True, text=True, timeout=60
        )
        if proc.returncode == 0:
            count = 0
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        host = data.get("host")
                        if host:
                            result.subdomains.append(host.lower())
                            count += 1
                    except json.JSONDecodeError:
                        result.subdomains.append(line.strip().lower())
                        count += 1
            result.sources_used.append("subfinder")
            console.print(f"[green]✓[/green] [gray]subfinder[/gray]: {count} subdomains")
    except FileNotFoundError:
        console.print(f"[yellow]![/yellow] [gray]subfinder[/gray]: Not installed in PATH")
        result.errors["subfinder"] = "Not in PATH"
    except Exception as e:
        result.errors["subfinder"] = str(e)
        console.print(f"[yellow]✗[/yellow] [gray]subfinder[/gray]: {e}")

async def _run_crtsh(client: httpx.AsyncClient, domain: str, result: OsintResult):
    try:
        res = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
        if res.status_code == 200:
            count = 0
            for entry in res.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower()
                    if name.endswith(domain):
                        if name.startswith("*."): name = name[2:]
                        result.subdomains.append(name)
                        count += 1
            result.sources_used.append("crt.sh")
            console.print(f"[green]✓[/green] [gray]crt.sh[/gray]: {count} subdomains")
    except Exception as e:
        result.errors["crt.sh"] = str(e)

async def _run_hackertarget(client: httpx.AsyncClient, domain: str, result: OsintResult):
    try:
        res = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        count = 0
        if res.status_code == 200:
            for line in res.text.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith(domain):
                        result.subdomains.append(sub)
                        count += 1
        result.sources_used.append("HackerTarget")
        console.print(f"[green]✓[/green] [gray]HackerTarget[/gray]: {count} subdomains")
    except Exception as e:
        result.errors["HackerTarget"] = str(e)

async def _run_rapiddns(client: httpx.AsyncClient, domain: str, result: OsintResult):
    try:
        res = await client.get(f"https://rapiddns.io/subdomain/{domain}?full=1")
        count = 0
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, "html.parser")
            for row in soup.find_all("tr"):
                cols = row.find_all("td")
                if len(cols) > 0:
                    sub = cols[0].text.strip().lower()
                    if sub.endswith(domain):
                        result.subdomains.append(sub)
                        count += 1
        result.sources_used.append("RapidDNS")
        console.print(f"[green]✓[/green] [gray]RapidDNS[/gray]: {count} subdomains")
    except Exception as e:
        result.errors["RapidDNS"] = str(e)

async def _run_threatminer(client: httpx.AsyncClient, domain: str, result: OsintResult):
    try:
        res = await client.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5")
        count = 0
        if res.status_code == 200:
            data = res.json()
            if str(data.get("status_code")) == "200":
                for sub in data.get("results", []):
                    result.subdomains.append(sub.lower())
                    count += 1
        result.sources_used.append("ThreatMiner")
        console.print(f"[green]✓[/green] [gray]ThreatMiner[/gray]: {count} subdomains")
    except Exception as e:
        result.errors["ThreatMiner"] = str(e)

async def _run_otx(client: httpx.AsyncClient, domain: str, result: OsintResult):
    try:
        base = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
        
        # Passive DNS
        res_pdns = await client.get(f"{base}/passive_dns")
        if res_pdns.status_code == 200:
            pdns_data = res_pdns.json().get("passive_dns", [])
            for r in pdns_data:
                result.passive_dns_history.append({
                    "address": r.get("address"),
                    "record_type": r.get("record_type"),
                    "hostname": r.get("hostname")
                })
        
        # Malware
        res_mal = await client.get(f"{base}/malware")
        if res_mal.status_code == 200:
            result.otx_malware_hits = len(res_mal.json().get("data", []))
            
        result.sources_used.append("AlienVault OTX")
        console.print(f"[green]✓[/green] [gray]AlienVault OTX[/gray]: {len(result.passive_dns_history)} passive DNS, {result.otx_malware_hits} malware")
    except Exception as e:
        result.errors["AlienVault OTX"] = str(e)

async def _run_urlscan(client: httpx.AsyncClient, domain: str, result: OsintResult):
    try:
        res = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
        if res.status_code == 200:
            techs = set()
            for scan in res.json().get("results", []):
                result.urlscan_results.append(scan)
                # Just extract rough tech from simple responses
                page = scan.get("page", {})
                if 'server' in page: techs.add(page['server'])
            
            result.technologies.extend(list(techs))
            result.sources_used.append("URLScan.io")
            console.print(f"[green]✓[/green] [gray]URLScan.io[/gray]: {len(techs)} technologies")
    except Exception as e:
        result.errors["URLScan.io"] = str(e)

async def _run_dns(domain: str, result: OsintResult):
    try:
        results = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": []}
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        for rtype in results.keys():
            try:
                answers = await resolver.resolve(domain, rtype)
                for ans in answers:
                    val = ans.to_text().strip('"')
                    results[rtype].append(val)
                    if rtype == "TXT" and val.startswith("v=spf1"):
                        result.spf_record = val
            except Exception: pass
            
        result.dns_records = results
        
        # DMARC
        try:
            dmarc_ans = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            result.dmarc_record = dmarc_ans[0].to_text().strip('"')
        except Exception: pass
        
        # DKIM
        dkim_selectors = ["google", "selector1", "selector2", "default", "mail", "k1", "s1", "s2"]
        for sel in dkim_selectors:
            try:
                await resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                result.dkim_selectors_found.append(sel)
            except Exception: pass
            
        # AXFR
        def attempt_axfr():
            for ns in results["NS"]:
                try:
                    ns_ips = dns.resolver.resolve(ns, "A")
                    for ns_ip in ns_ips:
                        try:
                            z = dns.zone.from_xfr(dns.query.xfr(ns_ip.to_text(), domain, timeout=2))
                            # Success! We won't dump the whole zone to avoid blowing up the struct
                            return
                        except Exception: pass
                except Exception: pass
        await asyncio.to_thread(attempt_axfr)

        result.sources_used.append("DNS")
        console.print(f"[green]✓[/green] [gray]DNS[/gray]: SPF={'strict' if result.spf_record else 'none'} / DMARC={'set' if result.dmarc_record else 'none'}")
    except Exception as e:
        result.errors["DNS"] = str(e)

async def _run_whois(domain: str, result: OsintResult):
    wd = WhoisData()
    try:
        w = await asyncio.to_thread(whois.whois, domain)
        wd.registrar = str(w.registrar) if w.registrar else ""
        wd.registrant_org = str(w.org) if w.org else ""
        wd.registrant_country = str(w.country) if w.country else ""
        
        if isinstance(w.name_servers, list): wd.name_servers = [str(ns) for ns in w.name_servers]
        elif w.name_servers: wd.name_servers = [str(w.name_servers)]
            
        if isinstance(w.emails, list): wd.abuse_email = str(w.emails[0])
        elif w.emails: wd.abuse_email = str(w.emails)
            
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        
        if creation and isinstance(creation, datetime):
            wd.creation_date = creation.isoformat()
            wd.domain_age_days = (datetime.now() - creation).days
            wd.newly_registered = wd.domain_age_days < 180
            
        if expiration and isinstance(expiration, datetime):
            wd.expiration_date = expiration.isoformat()
            wd.expiring_soon = (expiration - datetime.now()).days < 30
            
        result.whois = wd
        result.sources_used.append("WHOIS")
        console.print(f"[green]✓[/green] [gray]WHOIS[/gray]: Age: {wd.domain_age_days} days")
    except Exception as e:
        result.errors["WHOIS"] = str(e)
        # Attempt minimal RDAP fallback
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(f"https://rdap.org/domain/{domain}")
                if res.status_code == 200:
                    wd.registrar = "RDAP Response Retrieved"
                    result.whois = wd
        except Exception: pass

async def _run_asn(client: httpx.AsyncClient, domain: str, result: OsintResult):
    ai = AsnInfo()
    try:
        # We need IPs to run ASN lookup. We grab one from DNS A records if available
        ips = result.dns_records.get("A", [])
        if ips:
            ip = ips[0]
            # ipinfo
            res = await client.get(f"https://ipinfo.io/{ip}/json")
            if res.status_code == 200:
                data = res.json()
                org = data.get("org", "")
                m = re.search(r'(AS\d+)', org)
                if m: ai.asn = m.group(1)
                ai.org = org
                ai.country = data.get("country", "")
                
            # RIPE NCC IP ranges (if we got ASN)
            if ai.asn:
                asn_clean = ai.asn.replace("AS", "")
                res = await client.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={asn_clean}")
                if res.status_code == 200:
                    for prefix in res.json().get('data', {}).get('ipv4', []):
                        ai.ip_ranges.append(prefix['prefix'])
                        
            result.asn_info = ai
            result.sources_used.append("ASN")
            console.print(f"[green]✓[/green] [gray]ASN[/gray]: {ai.asn} {ai.org}")
    except Exception as e:
        result.errors["ASN"] = str(e)

def _run_shodan(domain: str, result: OsintResult):
    if not settings.shodan_api_key:
        return
        
    try:
        api = shodan.Shodan(settings.shodan_api_key)
        
        # Search exact hostname
        search_res = api.search(f"hostname:{domain}")
        found_ips = [m['ip_str'] for m in search_res.get('matches', [])]
        
        # Search general domain mapping
        try:
            dom_res = api.domain(domain)
            for r in dom_res.get('data', []):
                if r['type'] in ['A', 'AAAA'] and 'value' in r:
                    found_ips.append(r['value'])
        except Exception: pass
            
        found_ips = list(set(found_ips))
        
        for ip in found_ips:
            try:
                info = api.host(ip)
                sh = ShodanHost(ip=ip)
                sh.ports = info.get("ports", [])
                sh.hostnames = info.get("hostnames", [])
                sh.org = info.get("org", "")
                sh.os = info.get("os", "")
                sh.vulns = info.get("vulns", [])
                sh.last_update = info.get("last_update", "")
                
                for item in info.get("data", []):
                    banner = item.get("data", "").strip()[:100]
                    if banner:
                        sh.banners.append(f"Port {item.get('port')}: {banner}")
                        
                result.shodan_hosts.append(sh)
            except Exception: pass
            
        result.sources_used.append("Shodan")
        console.print(f"[green]✓[/green] [gray]Shodan[/gray]: {len(result.shodan_hosts)} hosts")
    except Exception as e:
        result.errors["Shodan"] = str(e)

def _generate_dorks(domain: str, result: OsintResult):
    result.google_dorks = [
        DorkResult(dork=f"site:{domain} filetype:pdf", description="Exposed PDF docs"),
        DorkResult(dork=f"site:{domain} filetype:xls OR xlsx OR csv", description="Exposed spreadsheets"),
        DorkResult(dork=f"site:{domain} filetype:sql OR db OR sqlite", description="Database backups"),
        DorkResult(dork=f"site:{domain} inurl:admin OR login OR dashboard OR portal", description="Portals"),
        DorkResult(dork=f"site:{domain} inurl:config OR backup OR .env OR .git", description="Config/Backups"),
        DorkResult(dork=f'site:{domain} "index of" OR "directory listing"', description="Directory Listings"),
        DorkResult(dork=f'site:{domain} intext:"password" OR "credentials" OR "secret"', description="Credentials"),
        DorkResult(dork=f'"@{domain}" email harvesting', description="Email harvesting"),
        DorkResult(dork=f'"{domain}" site:linkedin.com/in', description="LinkedIn Employees"),
        DorkResult(dork=f'"{domain}" site:pastebin.com', description="Pastebin leaks"),
        DorkResult(dork=f'"{domain}" site:github.com password OR secret OR token OR key', description="GitHub secrets"),
        DorkResult(dork=f'"{domain}" site:trello.com OR site:notion.so', description="Trello/Notion docs"),
        DorkResult(dork=f"inurl:{domain} ext:log", description="Server logs"),
        DorkResult(dork=f'"{domain}" site:shodan.io', description="Shodan mentions")
    ]
    console.print(f"[green]✓[/green] [gray]Dork generator[/gray]: {len(result.google_dorks)} dorks ready")

def _print_summary(r: OsintResult):
    table = Table(title="OSINT Summary", show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Emails found", str(len(r.emails)))
    table.add_row("Subdomains", f"{len(r.subdomains)}")
    table.add_row("DNS config", f"SPF: {'✓' if r.spf_record else '✗'} / DMARC: {'✓' if r.dmarc_record else '✗'} / DKIM: {len(r.dkim_selectors_found)}")
    
    age_str = f"{r.whois.domain_age_days} days" if r.whois else "Unknown"
    table.add_row("Domain age", age_str)
    
    asn_str = f"{r.asn_info.asn} — {r.asn_info.org}" if r.asn_info else "Unknown"
    table.add_row("ASN", asn_str)
    
    vulns = sum(len(h.vulns) for h in r.shodan_hosts)
    table.add_row("Shodan hosts", f"{len(r.shodan_hosts)} hosts / {vulns} known CVEs")
    
    table.add_row("OTX malware hits", str(r.otx_malware_hits))
    table.add_row("Technologies", ", ".join(r.technologies[:5]) + "..." if len(r.technologies) > 5 else ", ".join(r.technologies))
    table.add_row("Manual dorks generated", str(len(r.google_dorks)))
    
    console.print(table)


# ── Main agent entry point ────────────────────────────────────────────────────

async def run_osint(target: str) -> dict:
    domain = target
    console.rule(f"[bold red]OSINT — {domain}[/bold red]")
    result = OsintResult(domain=domain)

    # Note: ASN lookup requires an IP. We must run DNS lookup first 
    # properly await it before triggering ASN, or we split the gather.
    # To maintain pure concurrency and avoid waterfalling, we will pull _run_dns
    # out.
    await _run_dns(domain, result)
    
    # Run all async sources concurrently
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        tasks = [
            _run_crtsh(client, domain, result),
            _run_hackertarget(client, domain, result),
            _run_rapiddns(client, domain, result),
            _run_threatminer(client, domain, result),
            _run_otx(client, domain, result),
            _run_urlscan(client, domain, result),
            _run_whois(domain, result),
            _run_asn(client, domain, result),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Sequential tools (subprocess / sync SDKs)
    
    # Needs to be wrapped in thread since they are blocking calls requested by user
    # to be called cleanly. theHarvester/subfinder are subprocesses, which block. 
    # shodan is a synchronous SDK network call.
    def run_sync_tools():
        _run_harvester(domain, result)
        _run_subfinder(domain, result)
        _run_shodan(domain, result)
        
    await asyncio.to_thread(run_sync_tools)

    # Dork generation (instant, no I/O)
    _generate_dorks(domain, result)

    # Deduplicate everything
    result.subdomains = sorted(set(result.subdomains))
    result.emails = sorted(set(result.emails))
    result.hostnames = sorted(set(result.hostnames))

    # Print summary table
    _print_summary(result)

    return result.model_dump()
