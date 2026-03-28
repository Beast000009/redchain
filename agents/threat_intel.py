"""
RedChain — Advanced OSINT: VirusTotal, AbuseIPDB, GreyNoise threat intel integrations.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import httpx
from typing import Dict, Any, Optional
from config import settings
from rich.console import Console

console = Console()


async def query_virustotal(target: str) -> Dict[str, Any]:
    """Query VirusTotal for domain/IP intelligence."""
    api_key = settings.virustotal_api_key
    if not api_key:
        return {"source": "virustotal", "status": "skipped", "reason": "No API key"}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"x-apikey": api_key}
            
            # Try domain first, then IP
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            resp = await client.get(url, headers=headers)
            
            if resp.status_code == 404:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
                resp = await client.get(url, headers=headers)
            
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "status": "found",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", "N/A"),
                    "whois": data.get("whois", "")[:500],
                    "tags": data.get("tags", []),
                }
            return {"source": "virustotal", "status": "error", "code": resp.status_code}
    except Exception as e:
        return {"source": "virustotal", "status": "error", "error": str(e)}


async def query_abuseipdb(target: str) -> Dict[str, Any]:
    """Query AbuseIPDB for IP abuse reports."""
    api_key = settings.abuseipdb_api_key
    if not api_key:
        return {"source": "abuseipdb", "status": "skipped", "reason": "No API key"}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": target, "maxAgeInDays": "90", "verbose": ""}
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params
            )
            
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "status": "found",
                    "ip": data.get("ipAddress"),
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType", ""),
                }
            return {"source": "abuseipdb", "status": "error", "code": resp.status_code}
    except Exception as e:
        return {"source": "abuseipdb", "status": "error", "error": str(e)}


async def query_greynoise(target: str) -> Dict[str, Any]:
    """Query GreyNoise for IP noise/threat classification."""
    api_key = settings.greynoise_api_key
    if not api_key:
        return {"source": "greynoise", "status": "skipped", "reason": "No API key"}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"key": api_key, "Accept": "application/json"}
            resp = await client.get(
                f"https://api.greynoise.io/v3/community/{target}",
                headers=headers
            )
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "source": "greynoise",
                    "status": "found",
                    "ip": data.get("ip"),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", "unknown"),
                    "name": data.get("name", ""),
                    "link": data.get("link", ""),
                    "last_seen": data.get("last_seen", ""),
                    "message": data.get("message", ""),
                }
            return {"source": "greynoise", "status": "not_found"}
    except Exception as e:
        return {"source": "greynoise", "status": "error", "error": str(e)}


async def run_threat_intel(target: str) -> Dict[str, Any]:
    """
    Run all threat intel queries in parallel.
    Returns combined results from VirusTotal, AbuseIPDB, and GreyNoise.
    """
    import asyncio
    
    console.print("[cyan]Running advanced threat intelligence lookups...[/cyan]")
    
    results = await asyncio.gather(
        query_virustotal(target),
        query_abuseipdb(target),
        query_greynoise(target),
        return_exceptions=True,
    )
    
    threat_intel = {}
    for result in results:
        if isinstance(result, Exception):
            continue
        if isinstance(result, dict):
            source = result.get("source", "unknown")
            threat_intel[source] = result
            
            status = result.get("status", "unknown")
            if status == "found":
                console.print(f"  [green]✓[/green] {source}: data retrieved")
            elif status == "skipped":
                console.print(f"  [dim]-[/dim] {source}: {result.get('reason', 'skipped')}")
            else:
                console.print(f"  [yellow]![/yellow] {source}: {status}")
    
    return threat_intel
