import asyncio
import subprocess
import json
import re
from typing import List, Dict, Any
from config import settings

# ── Version Normalization ──────────────────────────────────────────────────────

def normalize_version(version: str) -> str:
    """
    Strip distro/build suffixes from Nmap version strings so CVE queries match.

    Examples:
        '7.4p1'              -> '7.4'
        '2.4.51-ubuntu3.12'  -> '2.4.51'
        '3.9.2-1+deb11u1'    -> '3.9.2'
        '1.1.1k  3 Mar 2021' -> '1.1.1k'
    """
    if not version:
        return ""
    # Trim trailing metadata after whitespace (e.g. OpenSSL date strings)
    version = version.split()[0]
    # Strip common distro suffixes: -ubuntu3, +deb11, ~stretch, etc.
    version = re.sub(r'[-+~].*$', '', version)
    # Strip p1/p2 SSH patchlevel suffix: 7.4p1 -> 7.4
    version = re.sub(r'p\d+$', '', version)
    return version.strip()


# ── Main CVE Lookup ────────────────────────────────────────────────────────────

def run_cve_lookup(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Phase 4 — CVE Matching.
    Iterates over scan results, normalises versions, and queries cvemap.
    Falls back to NVD/Vulners if cvemap is not installed.
    Returns a unified sorted list of findings.
    """
    all_findings = []

    for host_data in scan_results:
        host = host_data.get("host", "Unknown")

        if "error" in host_data:
            continue

        for port_info in host_data.get("open_ports", []):
            service = port_info.get("service", "")
            raw_version = port_info.get("version", "")
            product = port_info.get("product", "")
            port = port_info.get("port")

            version = normalize_version(raw_version)

            # Build queries: try product+version first, then service+version
            queries_to_try = []
            if product and version:
                queries_to_try.append(f"{product} {version}")
            if service and version and service != product:
                queries_to_try.append(f"{service} {version}")
            if product and not version:
                queries_to_try.append(product)

            if not queries_to_try:
                continue

            found_for_port = False
            for query in queries_to_try:
                try:
                    proc = subprocess.run(
                        ["cvemap", "-q", query, "-json"],
                        capture_output=True, text=True, timeout=30
                    )

                    if proc.returncode == 0 and proc.stdout.strip():
                        for line in proc.stdout.strip().splitlines():
                            try:
                                data = json.loads(line)
                                cvss_val = 0.0
                                if data.get("cvss_metrics"):
                                    cvss_val = float(
                                        data["cvss_metrics"][0].get("cvss31", {}).get("score", 0.0)
                                    )
                                finding = {
                                    "cve_id": data.get("cve_id", "Unknown"),
                                    "cvss_score": cvss_val,
                                    "description": data.get("cve_description", "No description."),
                                    "host": host,
                                    "port": port,
                                    "service": f"{service} {version}".strip(),
                                    "source": "cvemap",
                                }
                                all_findings.append(finding)
                                found_for_port = True
                            except Exception:
                                pass

                    if found_for_port:
                        break  # Don't try next query if already got results

                except FileNotFoundError:
                    # Graceful degradation if cvemap is not installed
                    try:
                        from tools.nvd_lookup import query_nvd, query_vulners

                        fallback_findings = query_nvd(service, version)
                        if settings.vulners_api_key:
                            fallback_findings.extend(
                                query_vulners(service, version, settings.vulners_api_key)
                            )

                        for f in fallback_findings:
                            f["host"] = host
                            f["port"] = port
                            f["service"] = f"{service} {version}".strip()
                            f["source"] = "api_fallback"
                            all_findings.append(f)
                    except Exception:
                        pass
                    break  # Fallback runs once per port
                except Exception:
                    pass

    # Deduplicate based on CVE+Host+Port
    seen = set()
    deduped = []
    for f in all_findings:
        key = f"{f.get('cve_id')}-{f.get('host')}-{f.get('port')}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort descending by CVSS
    deduped.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)
    return deduped
