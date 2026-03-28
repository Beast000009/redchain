"""
RedChain — Subdomain Takeover Agent
Phase 2.7 — Checks all alive subdomains for takeover vulnerabilities.
Uses the canonical fingerprint database to detect dangling CNAME records.
"""

import asyncio
import socket
import os
import sys
import httpx
from typing import List, Dict, Any
from rich.console import Console

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import make_httpx_transport
from config import run_config

console = Console()

# ── Takeover Fingerprint Database ─────────────────────────────────────────────
# Source: https://github.com/EdOverflow/can-i-take-over-xyz

TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages",      "cname": ["github.io"],                                    "fingerprint": "There isn't a GitHub Pages site here",        "status": 404},
    {"service": "Heroku",            "cname": ["herokudns.com", "herokussl.com"],                "fingerprint": "No such app",                                  "status": None},
    {"service": "AWS S3",            "cname": ["s3.amazonaws.com", "amazonaws.com"],             "fingerprint": "NoSuchBucket",                                 "status": 404},
    {"service": "AWS CloudFront",    "cname": ["cloudfront.net"],                                "fingerprint": "The specified distribution does not exist",     "status": None},
    {"service": "Fastly",            "cname": ["fastly.net", "fastlylb.net"],                    "fingerprint": "Fastly error: unknown domain",                 "status": None},
    {"service": "Azure",             "cname": ["azurewebsites.net", "azure.com", "cloudapp.net"],"fingerprint": "404 Web Site not found",                       "status": 404},
    {"service": "Shopify",           "cname": ["myshopify.com"],                                 "fingerprint": "Sorry, this shop is currently unavailable",    "status": None},
    {"service": "Tumblr",            "cname": ["domains.tumblr.com"],                            "fingerprint": "Whatever you were looking for doesn't currently exist", "status": None},
    {"service": "Pantheon",          "cname": ["pantheonsite.io"],                               "fingerprint": "The gods are wise",                            "status": None},
    {"service": "Ghost",             "cname": ["ghost.io"],                                      "fingerprint": "The thing you were looking for is no longer here", "status": None},
    {"service": "Surge.sh",          "cname": ["surge.sh"],                                      "fingerprint": "project not found",                            "status": 404},
    {"service": "Netlify",           "cname": ["netlify.com", "netlify.app"],                    "fingerprint": "Not Found - Request ID",                       "status": 404},
    {"service": "Vercel",            "cname": ["vercel.app", "vercel.com"],                      "fingerprint": "The deployment could not be found",            "status": 404},
    {"service": "Webflow",           "cname": ["proxy.webflow.com"],                             "fingerprint": "The page you are looking for doesn't exist",   "status": None},
    {"service": "ReadTheDocs",       "cname": ["readthedocs.io"],                                "fingerprint": "unknown to Read the Docs",                     "status": 404},
    {"service": "Zendesk",           "cname": ["zendesk.com"],                                   "fingerprint": "Help Center Closed",                           "status": None},
    {"service": "HubSpot",           "cname": ["hubspot.net", "hs-sites.com"],                   "fingerprint": "does not exist in our system",                 "status": None},
    {"service": "Squarespace",       "cname": ["squarespace.com"],                               "fingerprint": "No Such Account",                              "status": None},
    {"service": "Campaign Monitor",  "cname": ["createsend.com"],                                "fingerprint": "Double check the URL",                         "status": None},
    {"service": "DigitalOcean",      "cname": ["digitalocean.app"],                               "fingerprint": "domain is not configured",                     "status": None},
]


def _get_cname(hostname: str) -> str | None:
    """Resolve CNAME for a hostname."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


async def _check_takeover(
    sub: str,
    client: httpx.AsyncClient,
) -> Dict[str, Any] | None:
    """
    Check a single subdomain for takeover vulnerability.
    Returns a finding dict if vulnerable, else None.
    """
    cname = await asyncio.to_thread(_get_cname, sub)
    if not cname:
        return None

    # Match CNAME against fingerprint database
    matched_service = None
    for fp in TAKEOVER_FINGERPRINTS:
        if any(c in cname for c in fp["cname"]):
            matched_service = fp
            break

    if not matched_service:
        return None

    # Check if the page returns the error fingerprint
    for scheme in ["https", "http"]:
        url = f"{scheme}://{sub}"
        try:
            r = await client.get(url, timeout=8)
            body = r.text.lower()
            fp_text = matched_service["fingerprint"].lower()

            if fp_text in body:
                finding = {
                    "subdomain": sub,
                    "cname": cname,
                    "service": matched_service["service"],
                    "fingerprint_matched": matched_service["fingerprint"],
                    "url": url,
                    "severity": "critical",
                    "description": (
                        f"Subdomain {sub} has a dangling CNAME pointing to {cname} "
                        f"({matched_service['service']}) and returns the takeover fingerprint. "
                        f"This subdomain can likely be claimed by registering the resource on {matched_service['service']}."
                    ),
                    "source": "takeover_check",
                }
                return finding
        except Exception:
            pass

    return None


async def run_takeover_check(state: dict) -> dict:
    """
    Phase 2.7 — Subdomain Takeover Detection.
    Reads: state['subdomains']
    Writes: state['takeover_findings']
    """
    console.rule("[bold red]Phase 2.7 — Subdomain Takeover Detection[/bold red]")

    subdomains = state.get("subdomains", [])
    alive_subs = [s["subdomain"] for s in subdomains if s.get("alive") and s.get("subdomain")]

    # Also check the primary domain's own CNAME (edge case)
    primary = state.get("target", "")
    if primary and primary not in alive_subs:
        alive_subs.append(primary)

    if not alive_subs:
        console.print("[dim]No alive subdomains to check for takeover.[/dim]")
        state["takeover_findings"] = []
        return state

    console.print(f"[dim]Checking {len(alive_subs)} subdomains for takeover vulnerabilities...[/dim]")

    proxy = getattr(run_config, 'proxy', None)
    transport = make_httpx_transport(proxy)
    client_kwargs = dict(
        timeout=10.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; security-scanner)"},
    )
    if transport:
        client_kwargs["transport"] = transport

    findings = []
    sem = asyncio.Semaphore(20)

    async def _bounded_check(sub):
        async with sem:
            return await _check_takeover(sub, client)

    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = [_bounded_check(sub) for sub in alive_subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, dict):
            findings.append(r)
            console.print(f"[bold red]⚡ TAKEOVER: {r['subdomain']} → {r['service']} ({r['cname']})[/bold red]")

    console.print(f"\n[bold green]Takeover check complete:[/bold green] {len(findings)} potential takeover(s) found")
    state["takeover_findings"] = findings
    return state
