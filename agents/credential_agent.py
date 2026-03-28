"""
RedChain — Credential Agent
Phase 3.5 — Default credential testing on discovered services.
Tests SSH, FTP, HTTP Basic Auth, and login pages with a curated top-credentials list.
IMPORTANT: Only run against explicitly authorized targets.
"""

import asyncio
import subprocess
import socket
import os
import sys
import httpx
from typing import List, Dict, Any, Optional
from rich.console import Console

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import find_tool, get_temp_path, IS_WINDOWS, make_httpx_transport
from config import run_config

console = Console()

# ── Top Default Credential Pairs ──────────────────────────────────────────────

DEFAULT_CREDS = [
    ("admin",        "admin"),
    ("admin",        "password"),
    ("admin",        ""),
    ("admin",        "1234"),
    ("admin",        "admin123"),
    ("admin",        "pass"),
    ("root",         "root"),
    ("root",         "password"),
    ("root",         ""),
    ("root",         "toor"),
    ("administrator","administrator"),
    ("administrator","password"),
    ("user",         "user"),
    ("user",         "password"),
    ("guest",        "guest"),
    ("guest",        ""),
    ("test",         "test"),
    ("test",         "password"),
    ("pi",           "raspberry"),         # Raspberry Pi default
    ("ubnt",         "ubnt"),              # Ubiquiti default
    ("cisco",        "cisco"),             # Cisco default
    ("enable",       "enable"),            # Cisco enable
    ("support",      "support"),
    ("service",      "service"),
    ("nagios",       "nagios"),
    ("zabbix",       "zabbix"),
    ("postgres",     "postgres"),
    ("mysql",        "mysql"),
    ("oracle",       "oracle"),
    ("sa",           ""),                  # MSSQL default sa
]


# ── Per-Protocol Testers ───────────────────────────────────────────────────────

def _test_ssh(host: str, port: int, username: str, password: str) -> bool:
    """Test SSH login using paramiko (if installed) or skip."""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=port, username=username, password=password,
            timeout=4, look_for_keys=False, allow_agent=False
        )
        client.close()
        return True
    except Exception:
        return False


def _test_ftp(host: str, port: int, username: str, password: str) -> bool:
    """Test FTP login using ftplib."""
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=4)
        ftp.login(username, password)
        ftp.quit()
        return True
    except Exception:
        return False


async def _test_http_basic(
    client: httpx.AsyncClient, url: str, username: str, password: str
) -> bool:
    """Test HTTP Basic Auth."""
    try:
        r = await client.get(url, auth=(username, password), timeout=5)
        return r.status_code not in (401, 403, 407)
    except Exception:
        return False


async def _test_http_form(
    client: httpx.AsyncClient,
    url: str,
    username: str,
    password: str,
) -> bool:
    """
    Simple HTTP form POST login test.
    Tries common field names and checks for success indicators.
    """
    fail_indicators = ["invalid", "incorrect", "failed", "wrong", "error", "denied", "try again"]
    success_indicators = ["logout", "dashboard", "welcome", "profile", "sign out", "log out"]

    # Common form field name pairs to try
    field_variants = [
        ("username", "password"),
        ("user", "pass"),
        ("email", "password"),
        ("login", "password"),
        ("name", "password"),
    ]

    for user_field, pass_field in field_variants:
        try:
            data = {user_field: username, pass_field: password}
            r = await client.post(url, data=data, timeout=6, follow_redirects=True)
            body = r.text.lower()

            # Success: redirected somewhere useful OR body has success keywords
            if any(s in body for s in success_indicators):
                return True
            # The presence of fail indicators means it didn't work
            if any(f in body for f in fail_indicators):
                break
        except Exception:
            pass
    return False


# ── Main Credential Check ──────────────────────────────────────────────────────

async def run_credential_check(state: dict) -> dict:
    """
    Phase 3.5 — Default Credential Testing.
    Reads: state['scan_results'], state['webapp_results']
    Writes: state['credential_findings']
    """
    console.rule("[bold red]Phase 3.5 — Default Credential Testing[/bold red]")

    scan_results = state.get("scan_results", [])
    webapp_results = state.get("webapp_results", [])
    proxy = getattr(run_config, 'proxy', None)
    transport = make_httpx_transport(proxy)

    all_findings: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(10)

    # ── Phase A: Service-level (SSH, FTP) ────────────────────────────────────
    for host_data in scan_results:
        host = host_data.get("host", "")
        for port_info in host_data.get("open_ports", []):
            port = port_info.get("port")
            service = port_info.get("service", "").lower()

            if service in ("ssh",):
                console.print(f"[dim]Testing default SSH creds on {host}:{port}...[/dim]")
                for user, pwd in DEFAULT_CREDS[:15]:  # limit SSH to top 15 to avoid lockouts
                    try:
                        success = await asyncio.to_thread(_test_ssh, host, port, user, pwd)
                        if success:
                            finding = {
                                "host": host,
                                "port": port,
                                "service": "SSH",
                                "username": user,
                                "password": pwd,
                                "severity": "critical",
                                "description": f"Default SSH credentials accepted: {user}:{pwd}",
                                "source": "credential_check",
                            }
                            all_findings.append(finding)
                            console.print(f"[bold red]💥 DEFAULT CREDS: SSH {host}:{port} — {user}:{pwd}[/bold red]")
                            break  # Stop after first success for SSH
                    except Exception:
                        pass

            elif service in ("ftp",):
                console.print(f"[dim]Testing default FTP creds on {host}:{port}...[/dim]")
                for user, pwd in DEFAULT_CREDS[:10]:
                    try:
                        success = await asyncio.to_thread(_test_ftp, host, port, user, pwd)
                        if success:
                            finding = {
                                "host": host,
                                "port": port,
                                "service": "FTP",
                                "username": user,
                                "password": pwd,
                                "severity": "critical",
                                "description": f"Default FTP credentials accepted: {user}:{pwd}",
                                "source": "credential_check",
                            }
                            all_findings.append(finding)
                            console.print(f"[bold red]💥 DEFAULT CREDS: FTP {host}:{port} — {user}:{pwd}[/bold red]")
                            break
                    except Exception:
                        pass

    # ── Phase B: Web login pages ───────────────────────────────────────────────
    client_kwargs = dict(verify=False, follow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; security-scanner)"})
    if transport:
        client_kwargs["transport"] = transport

    async with httpx.AsyncClient(**client_kwargs) as client:
        for wa in webapp_results:
            host = wa.get("host", "")
            login_pages = wa.get("login_pages", [])
            active_url = wa.get("url_https") or wa.get("url_http") or f"https://{host}"

            # Also check common admin paths if none found
            if not login_pages:
                login_pages = ["/admin", "/login", "/wp-login.php", "/administrator"]

            for login_path in login_pages[:5]:  # cap to 5 per host
                login_url = active_url.rstrip("/") + login_path

                # First check if page requires HTTP Basic Auth
                try:
                    r = await client.get(login_url, timeout=5)
                    if r.status_code == 401 and "www-authenticate" in r.headers:
                        # HTTP Basic Auth — try creds
                        for user, pwd in DEFAULT_CREDS[:20]:
                            success = await _test_http_basic(client, login_url, user, pwd)
                            if success:
                                finding = {
                                    "host": host,
                                    "port": 443 if "https" in active_url else 80,
                                    "service": "HTTP Basic Auth",
                                    "username": user,
                                    "password": pwd,
                                    "url": login_url,
                                    "severity": "critical",
                                    "description": f"Default HTTP Basic Auth credentials: {user}:{pwd}",
                                    "source": "credential_check",
                                }
                                all_findings.append(finding)
                                console.print(f"[bold red]💥 HTTP BASIC AUTH: {login_url} — {user}:{pwd}[/bold red]")
                                break

                    elif r.status_code == 200 and "form" in r.text.lower():
                        # HTML form — try POST submissions
                        async with sem:
                            for user, pwd in DEFAULT_CREDS[:15]:
                                success = await _test_http_form(client, login_url, user, pwd)
                                if success:
                                    finding = {
                                        "host": host,
                                        "port": 443 if "https" in active_url else 80,
                                        "service": "HTTP Form Auth",
                                        "username": user,
                                        "password": pwd,
                                        "url": login_url,
                                        "severity": "critical",
                                        "description": f"Default form credentials accepted: {user}:{pwd} at {login_url}",
                                        "source": "credential_check",
                                    }
                                    all_findings.append(finding)
                                    console.print(f"[bold red]💥 FORM AUTH: {login_url} — {user}:{pwd}[/bold red]")
                                    break
                except Exception:
                    pass

    console.print(f"\n[bold green]Credential check complete:[/bold green] {len(all_findings)} default credential finding(s)")
    state["credential_findings"] = all_findings
    return state
