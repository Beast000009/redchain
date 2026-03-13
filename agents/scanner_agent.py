from typing import List, Dict, Any
from tools.nmap_wrapper import run_nmap_scan
import ipaddress

def run_scanner(target: str, input_type: str, live_hosts: List[str]) -> tuple[List[str], List[Dict[str, Any]]]:
    """
    Executes Phase 3 Scanner Agent.
    If input_type is IP/CIDR, we populate live_hosts here if empty.
    Runs nmap scan on live hosts.
    Returns (updated_live_hosts, scan_results).
    """
    scan_targets = list(live_hosts)
    
    # If starting from IP/CIDR and no live hosts yet
    if not scan_targets:
        if input_type == "ip":
            scan_targets = [target]
        elif input_type == "cidr":
            try:
                # Basic quick sweep approximation (nmap normally does this better with -sn)
                network = ipaddress.ip_network(target, strict=False)
                # Cap the sweep to prevent massive resource locking if large subnet
                scan_targets = [str(ip) for ip in list(network.hosts())[:256]]
            except ValueError:
                scan_targets = [target]
                
    if not scan_targets:
        return [], []

    scan_results = run_nmap_scan(scan_targets)
    
    # Update live hosts based on nmap responding hosts
    actual_live = []
    for res in scan_results:
        if "host" in res:
            actual_live.append(res["host"])
            
    return actual_live, scan_results
