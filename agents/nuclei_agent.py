"""
RedChain — Nuclei Agent
Phase 2.6 — Templated vulnerability scanning via ProjectDiscovery Nuclei.
Runs after WebApp fingerprinting, leverages tech stack info for targeted templates.
"""

import asyncio
import subprocess
import json
import os
import sys
import shutil
from typing import List, Dict, Any, Optional
from rich.console import Console

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import find_tool, get_temp_path, get_proxychains_prefix, IS_WINDOWS
from config import run_config

console = Console()


# ── Nuclei Fingerprint → Template Mapping ─────────────────────────────────────

_TECH_TEMPLATE_MAP = {
    "wordpress":   ["technologies/wordpress", "vulnerabilities/wordpress", "cves", "exposures"],
    "joomla":      ["technologies/joomla", "vulnerabilities/joomla", "cves"],
    "drupal":      ["technologies/drupal", "vulnerabilities/drupal", "cves"],
    "apache":      ["technologies/apache", "cves", "vulnerabilities/apache"],
    "nginx":       ["technologies/nginx", "cves"],
    "iis":         ["technologies/microsoft-iis", "cves"],
    "php":         ["vulnerabilities/php", "cves", "exposures/configs"],
    "laravel":     ["vulnerabilities/laravel", "technologies/laravel"],
    "django":      ["vulnerabilities/django", "technologies/django"],
    "jenkins":     ["exposures/apis/jenkins", "vulnerabilities/jenkins", "default-logins/jenkins"],
    "gitlab":      ["technologies/gitlab", "vulnerabilities/gitlab", "default-logins/gitlab"],
    "tomcat":      ["technologies/tomcat", "vulnerabilities/apache-tomcat", "default-logins/tomcat"],
    "elastic":     ["exposures/apis/elastic", "default-logins/elastic"],
    "mongodb":     ["exposures/apis/mongodb", "default-logins/mongodb"],
    "redis":       ["vulnerabilities/redis", "exposures/apis/redis"],
    "spring":      ["technologies/spring", "vulnerabilities/spring", "cves"],
    "grafana":     ["default-logins/grafana", "vulnerabilities/grafana"],
    "kubernetes":  ["exposures/apis/kubernetes", "exposures/configs/kubernetes"],
    "docker":      ["exposures/apis/docker"],
}

_DEFAULT_TEMPLATES = [
    "cves",
    "vulnerabilities",
    "exposures",
    "default-logins",
    "misconfiguration",
    "takeovers",
]


def _get_templates_for_tech(tech_stack: List[str]) -> List[str]:
    """Return template tags relevant to the detected tech stack."""
    templates = set(_DEFAULT_TEMPLATES)
    for tech in tech_stack:
        tech_lower = tech.lower()
        for key, tmpl_list in _TECH_TEMPLATE_MAP.items():
            if key in tech_lower:
                templates.update(tmpl_list)
    return list(templates)


def _run_nuclei_on_host(
    url: str,
    tech_stack: List[str],
    proxy: Optional[str] = None,
    stealth: bool = False,
) -> List[Dict[str, Any]]:
    """Run nuclei against a single URL. Returns list of finding dicts."""
    nuclei_path = find_tool("nuclei")
    if not nuclei_path:
        console.print("[yellow]  nuclei: not installed — skipping (install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)[/yellow]")
        return []

    host_safe = url.replace("://", "_").replace("/", "_").replace(".", "_")
    output_file = get_temp_path(f"nuclei_{host_safe}.json")

    templates = _get_templates_for_tech(tech_stack)

    # Base command
    cmd = [
        nuclei_path,
        "-u", url,
        "-severity", "critical,high,medium",
        "-silent",
        "-json",
        "-o", output_file,
        "-timeout", "10",
        "-retries", "1",
        "-no-color",
    ]

    # Template tags
    for tag in templates[:8]:  # cap to avoid very long scans
        cmd.extend(["-tags", tag])

    # Stealth / rate limiting
    if stealth or run_config.stealth:
        cmd.extend(["-rl", "5", "-bs", "5", "-c", "5"])
    else:
        cmd.extend(["-rl", "150", "-bs", "25", "-c", "25"])

    # Proxy
    if proxy:
        cmd.extend(["-proxy", proxy])

    try:
        console.print(f"  [cyan]nuclei[/cyan] → {url} (templates: {', '.join(templates[:4])}{'...' if len(templates) > 4 else ''})")
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,
            text=True
        )

        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        finding = {
                            "url": data.get("matched-at", url),
                            "template_id": data.get("template-id", ""),
                            "template_name": data.get("info", {}).get("name", ""),
                            "severity": data.get("info", {}).get("severity", "info"),
                            "description": data.get("info", {}).get("description", ""),
                            "tags": data.get("info", {}).get("tags", []),
                            "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score", 0.0),
                            "cve_ids": data.get("info", {}).get("classification", {}).get("cve-id", []),
                            "matcher_name": data.get("matcher-name", ""),
                            "source": "nuclei",
                        }
                        findings.append(finding)
                        sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(
                            finding["severity"], "dim"
                        )
                        console.print(f"    [{sev_color}]⚡ [{finding['severity'].upper()}] {finding['template_name']} @ {finding['url']}[/{sev_color}]")
                    except json.JSONDecodeError:
                        pass

            # Cleanup temp file
            try:
                os.remove(output_file)
            except Exception:
                pass

        console.print(f"  [green]✓[/green] nuclei: {len(findings)} findings on {url}")
        return findings

    except subprocess.TimeoutExpired:
        console.print(f"  [yellow]nuclei timed out on {url}[/yellow]")
        return []
    except Exception as e:
        console.print(f"  [red]nuclei error on {url}: {e}[/red]")
        return []


async def run_nuclei_scan(state: dict) -> dict:
    """
    Phase 2.6 — Nuclei templated scanning.
    Reads: state['webapp_results'], state['target']
    Writes: state['nuclei_findings']
    """
    console.rule("[bold red]Phase 2.6 — Nuclei Templated Scanning[/bold red]")

    webapp_results = state.get("webapp_results", [])
    proxy = getattr(run_config, 'proxy', None)
    stealth = getattr(run_config, 'stealth', False)

    # Build host → (url, tech_stack) mapping
    scan_targets = []

    # Primary domain
    domain = state.get("target", "")
    if domain:
        scan_targets.append({
            "url": f"https://{domain}" if not domain.startswith("http") else domain,
            "tech_stack": [],
        })

    # From webapp results
    for wa in webapp_results:
        host = wa.get("host", "")
        if not host:
            continue
        url = wa.get("url_https") or wa.get("url_http") or f"https://{host}"
        tech = wa.get("tech_stack", [])

        # Skip if we already have this URL from primary domain
        if any(t["url"].rstrip("/") == url.rstrip("/") for t in scan_targets):
            # Update tech stack for the existing entry
            for t in scan_targets:
                if t["url"].rstrip("/") == url.rstrip("/"):
                    t["tech_stack"] = tech
            continue

        scan_targets.append({"url": url, "tech_stack": tech})

    if not scan_targets:
        console.print("[dim]No targets for nuclei scan.[/dim]")
        state["nuclei_findings"] = []
        return state

    console.print(f"[dim]Running nuclei on {len(scan_targets)} target(s)[/dim]")

    all_findings = []
    for target_info in scan_targets:
        findings = await asyncio.to_thread(
            _run_nuclei_on_host,
            target_info["url"],
            target_info["tech_stack"],
            proxy,
            stealth,
        )
        all_findings.extend(findings)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda x: sev_order.get(x.get("severity", "info"), 5))

    console.print(f"\n[bold green]Nuclei complete:[/bold green] {len(all_findings)} total findings across {len(scan_targets)} targets")
    state["nuclei_findings"] = all_findings
    return state
