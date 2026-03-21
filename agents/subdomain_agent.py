import asyncio
import subprocess
import socket
import os
import httpx
from typing import List, Dict, Any
from rich.console import Console

console = Console()

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

async def check_subdomain(sub: str, sem: asyncio.Semaphore) -> Dict[str, Any]:
    async with sem:
        alive = False
        ip = None
        
        # 1. DNS Resolution (Fastest path)
        def _resolve():
            try:
                return socket.gethostbyname(sub)
            except (socket.gaierror, UnicodeError, Exception):
                return None
        
        ip = await asyncio.to_thread(_resolve)
        if ip:
            alive = True
            
        # 2. Ping command (User requested fallback)
        if not alive:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-c", "1", "-W", "1000", sub,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                if proc.returncode == 0:
                    alive = True
            except Exception:
                pass
                
        # 3. HTTP / HTTPS check (Ultimate fallback for aggressive firewalls)
        if not alive:
            try:
                async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                    await client.get(f"http://{sub}")
                    alive = True
            except Exception:
                try:
                    async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                        await client.get(f"https://{sub}")
                        alive = True
                except Exception:
                    pass
                    
        return {
            "subdomain": sub,
            "ip": ip,
            "alive": alive
        }

def resolve_and_ping(subdomains: set[str]) -> List[Dict[str, Any]]:
    """Asynchronously resolves domains, pings, and HTTP checks them."""
    async def run_all():
        sem = asyncio.Semaphore(50) # Limit concurrent external connections
        tasks = [check_subdomain(sub, sem) for sub in subdomains]
        return await asyncio.gather(*tasks)
    
    return asyncio.run(run_all())

def run_subdomain_enum(target: str, osint_hostnames: List[str]) -> List[Dict[str, Any]]:
    """Executes Phase 2 Subdomain Enumeration."""
    all_subs = set(osint_hostnames)
    
    # Add subfinder results
    all_subs.update(run_subfinder(target))
    
    if target not in all_subs:
        all_subs.add(target)
        
    console.print(f"[bold blue]Testing {len(all_subs)} subdomains for active status via DNS, Ping, and HTTP...[/bold blue]")
    
    # Resolve and compile results
    results = resolve_and_ping(all_subs)
    
    # Save the alive subdomains to subhostup.txt
    alive_subs = [r["subdomain"] for r in results if r["alive"]]
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    out_file = os.path.join(reports_dir, f"{target}_subhostup.txt")
    
    with open(out_file, "w") as f:
        f.write("\n".join(sorted(alive_subs)))
        
    console.print(f"[bold green]➜ Alive subdomains saved to:[/bold green] {out_file} ({len(alive_subs)}/{len(all_subs)} alive)")
    
    return results
