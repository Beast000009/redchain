import subprocess
import json
from typing import List, Dict, Any
from config import settings

def run_cve_lookup(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Executes Phase 4 CVE Matching.
    Iterates over scan results, extracting services + versions, and queries cvemap.
    Returns a unified sorted list of findings.
    """
    all_findings = []
    
    for host_data in scan_results:
        host = host_data.get("host", "Unknown")
        
        if "error" in host_data:
            continue
            
        for port_info in host_data.get("open_ports", []):
            service = port_info.get("service")
            version = port_info.get("version")
            product = port_info.get("product")
            port = port_info.get("port")
            
            # Prioritize product if available, else fallback to service
            query_term = product if product else service
            
            if query_term and version:
                query = f"{query_term} {version}"
                
                try:
                    proc = subprocess.run(
                        ["cvemap", "-q", query, "-json"],
                        capture_output=True, text=True, timeout=30
                    )
                    
                    if proc.returncode == 0 and proc.stdout.strip():
                        # cvemap returns newline-separated JSON objects
                        for line in proc.stdout.strip().splitlines():
                            try:
                                data = json.loads(line)
                                finding = {
                                    "cve_id": data.get("cve_id", "Unknown"),
                                    "cvss_score": float(data.get("cvss_metrics", [{}])[0].get("cvss31", {}).get("score", 0.0)) if data.get("cvss_metrics") else 0.0,
                                    "description": data.get("cve_description", "No description provided."),
                                    "host": host,
                                    "port": port,
                                    "service": f"{service} {version}",
                                    "source": "cvemap"
                                }
                                all_findings.append(finding)
                            except Exception:
                                pass
                except FileNotFoundError:
                    # Graceful degradation if cvemap is not installed, use NVD/Vulners
                    try:
                        from tools.nvd_lookup import query_nvd, query_vulners
                        
                        fallback_findings = query_nvd(service, version)
                        if settings.vulners_api_key:
                            fallback_findings.extend(query_vulners(service, version, settings.vulners_api_key))
                            
                        for f in fallback_findings:
                            f["host"] = host
                            f["port"] = port
                            f["service"] = f"{service} {version}"
                            f["source"] = "api_fallback"
                            all_findings.append(f)
                    except Exception:
                        pass
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
