import nmap
import socket
from typing import List, Dict, Any
from config import run_config

def grab_banner(ip: str, port: int, timeout: int = 2) -> str:
    """Attempts to grab a basic banner using raw sockets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Send an empty string or basic HTTP GET depending on port to trigger a response
            if port in [80, 443, 8080, 8443]:
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            else:
                s.sendall(b"\r\n")
                
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner
    except Exception:
        return ""

def run_nmap_scan(target_ips: List[str]) -> List[Dict[str, Any]]:
    """Runs nmap scan against a list of IPs."""
    if not target_ips:
        return []
        
    try:
        nm = nmap.PortScanner()
        target_str = " ".join(target_ips)
        
        # -sV: service version, -O: OS detection
        # Need root for OS detection ideally, fallback gracefully if not
        flags = "-sV -O"
        if run_config.stealth:
            flags += " -T2"
        else:
            flags += " -T4"
            
        # Add basic top ports for speed if not specifying
        flags += " --top-ports 100"
        
        nm.scan(hosts=target_str, arguments=flags)
        
        results = []
        for host in nm.all_hosts():
            host_data = {
                "host": host,
                "os_guess": None,
                "open_ports": []
            }
            
            if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
                host_data['os_guess'] = nm[host]['osmatch'][0]['name']
                
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    if nm[host][proto][port]['state'] == 'open':
                        service = nm[host][proto][port]['name']
                        version = nm[host][proto][port]['version']
                        
                        banner = grab_banner(host, port)
                        
                        host_data['open_ports'].append({
                            "port": port,
                            "protocol": proto,
                            "service": service,
                            "version": version,
                            "banner": banner
                        })
            results.append(host_data)
            
        return results
        
    except nmap.PortScannerError as e:
        return [{"error": f"Nmap error: {e}"}]
    except Exception as e:
        return [{"error": str(e)}]
