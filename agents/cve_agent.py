from typing import List, Dict, Any
from tools.nvd_lookup import query_nvd, query_vulners
from config import settings

def run_cve_lookup(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Executes Phase 4 CVE Matching.
    Iterates over scan results, extracting services + versions, and queries NVD/Vulners.
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
            port = port_info.get("port")
            
            if service and version:
                # Query NVD
                nvd_results = query_nvd(service, version)
                
                # Query Vulners if configured
                vulners_results = query_vulners(service, version, settings.vulners_api_key)
                
                # Combine and deduplicate
                combined = {f["cve_id"]: f for f in nvd_results + vulners_results}
                
                for cve_id, finding in combined.items():
                    finding["host"] = host
                    finding["port"] = port
                    finding["service"] = f"{service} {version}"
                    all_findings.append(finding)
                    
    # Sort descending by CVSS
    all_findings.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)
    return all_findings
