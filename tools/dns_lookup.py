import asyncio
import dns.asyncresolver
import dns.resolver
from typing import Dict, List, Any

# Common DKIM selectors to test
DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "mail", "k1"]

async def run_dns_lookup(domain: str) -> Dict[str, List[str]]:
    """
    Perform comprehensive DNS resolution (A, AAAA, MX, NS, TXT, CNAME, SOA).
    Attempts DMARC, DKIM, SPF parsing, and AXFR.
    """
    results: Dict[str, List[str]] = {
        "A": [], "AAAA": [], "MX": [], "NS": [], 
        "TXT": [], "CNAME": [], "SOA": [],
        "SPF": [], "DMARC": [], "DKIM": [], "Zone_Transfer": []
    }
    
    resolver = dns.asyncresolver.Resolver()
    # Use multiple public resolvers
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    
    async def fetch_record(rtype: str):
        try:
            answers = await resolver.resolve(domain, rtype)
            for rdata in answers:
                val = rdata.to_text().strip('"')
                results[rtype].append(val)
                
                # Special parsing for TXT
                if rtype == "TXT" and val.startswith("v=spf1"):
                    results["SPF"].append(val)
                    
        except Exception:
            pass # Record doesn't exist or timeout
            
    tasks = [fetch_record(rtype) for rtype in record_types]
    await asyncio.gather(*tasks)
    
    # Try DMARC
    try:
        dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            results["DMARC"].append(rdata.to_text().strip('"'))
    except Exception:
        pass
        
    # Try DKIM selectors
    async def check_dkim(selector: str):
        try:
            dkim_answers = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for rdata in dkim_answers:
                results["DKIM"].append(f"{selector}: {rdata.to_text().strip('\"')}")
        except Exception:
            pass
            
    dkim_tasks = [check_dkim(sel) for sel in DKIM_SELECTORS]
    await asyncio.gather(*dkim_tasks)
    
    # Identify NS providers
    for ns in results["NS"]:
        ns_lower = ns.lower()
        if "cloudflare" in ns_lower:
            results["NS"].append(f"Provider identified: Cloudflare ({ns})")
        elif "awsdns" in ns_lower:
            results["NS"].append(f"Provider identified: AWS Route53 ({ns})")
            
    # AXFR Zone Transfer attempt (usually synchronous in dnspython)
    def attempt_axfr():
        for ns_server in results["NS"]:
            # Ignore our notes about providers
            if "Provider" in ns_server:
                continue
            try:
                ns_ip_answers = dns.resolver.resolve(ns_server, "A")
                for ns_ip in ns_ip_answers:
                    try:
                        z = dns.zone.from_xfr(dns.query.xfr(ns_ip.to_text(), domain, timeout=2))
                        results["Zone_Transfer"].append(f"SUCCESS against {ns_server}")
                        return
                    except Exception as e:
                        continue
            except Exception:
                continue
        results["Zone_Transfer"].append("FAILED against all NS")
    
    # Run sync AXFR attempt in background
    await asyncio.to_thread(attempt_axfr)

    return results
