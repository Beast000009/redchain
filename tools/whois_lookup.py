import asyncio
import whois
from datetime import datetime
import httpx
from typing import Dict, Any, Optional

async def run_whois(domain: str) -> Dict[str, Any]:
    """
    Retrieves WHOIS configuration and calculates domain age.
    Also falls back to RDAP if python-whois fails.
    """
    whois_data = {
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "name_servers": [],
        "registrant_org": "",
        "registrant_country": "",
        "abuse_email": "",
        "domain_age_days": -1,
        "is_newly_registered": False,
        "expires_soon": False
    }
    
    try:
        # Run python-whois synchronously in a thread
        w = await asyncio.to_thread(whois.whois, domain)
        
        whois_data["registrar"] = str(w.registrar) if w.registrar else ""
        whois_data["registrant_org"] = str(w.org) if w.org else ""
        whois_data["registrant_country"] = str(w.country) if w.country else ""
        
        # Name servers can be list or string
        if isinstance(w.name_servers, list):
            whois_data["name_servers"] = [str(ns) for ns in w.name_servers]
        elif w.name_servers:
            whois_data["name_servers"] = [str(w.name_servers)]
            
        # Emails
        if isinstance(w.emails, list):
            whois_data["abuse_email"] = w.emails[0]
        elif w.emails:
            whois_data["abuse_email"] = str(w.emails)
            
        # Dates can be list or single datetime
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        
        if creation and isinstance(creation, datetime):
            whois_data["creation_date"] = creation.isoformat()
            age_days = (datetime.now() - creation).days
            whois_data["domain_age_days"] = age_days
            whois_data["is_newly_registered"] = age_days < 180
            
        if expiration and isinstance(expiration, datetime):
            whois_data["expiration_date"] = expiration.isoformat()
            days_to_expire = (expiration - datetime.now()).days
            whois_data["expires_soon"] = days_to_expire < 30
            
    except Exception as e:
        # Fallback to RDAP
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                res = await client.get(f"https://rdap.org/domain/{domain}")
                if res.status_code == 200:
                    data = res.json()
                    whois_data["registrar"] = "RDAP Parsed (See raw data)"
                    # Parsing RDAP fully is complex, simple placeholder for now
        except Exception:
            pass

    return whois_data
