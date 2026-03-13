import subprocess
import socket
from typing import List, Dict, Any

def run_subfinder(domain: str) -> set[str]:
    """Runs subfinder (assumes installed in PATH)."""
    subdomains = set()
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.strip():
                    subdomains.add(line.strip())
    except FileNotFoundError:
        pass # Not installed
    except Exception:
        pass
    return subdomains

def resolve_and_ping(subdomains: set[str]) -> List[Dict[str, Any]]:
    """Resolves domains to IPs and marks them alive if resolved."""
    results = []
    # simplified resolution logic (dnspython can be used for more thorough resolution)
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            results.append({
                "subdomain": sub,
                "ip": ip,
                "alive": True
            })
        except (socket.gaierror, UnicodeError):
            results.append({
                "subdomain": sub,
                "ip": None,
                "alive": False
            })
    return results

def run_subdomain_enum(target: str, osint_hostnames: List[str]) -> List[Dict[str, Any]]:
    """Executes Phase 2 Subdomain Enumeration."""
    all_subs = set(osint_hostnames)
    
    # Add subfinder results
    all_subs.update(run_subfinder(target))
    
    if target not in all_subs:
        all_subs.add(target)
        
    # Resolve and compile results
    return resolve_and_ping(all_subs)
