import httpx
from typing import List, Dict, Any
from config import settings
import urllib.parse
import json

def query_nvd(service: str, version: str) -> List[Dict[str, Any]]:
    """Queries NVD API v2 for a given service and version."""
    if not service or not version:
        return []
        
    keyword = f"{service} {version}"
    # NVD API v2 requires keywordSearch
    encoded_keyword = urllib.parse.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_keyword}"
    
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
        
    try:
        response = httpx.get(url, headers=headers, timeout=10.0)
        
        if response.status_code == 200:
            data = response.json()
            findings = []
            
            vulnerabilities = data.get("vulnerabilities", [])
            # Cap results to top 5 to prevent exploding reports
            for vuln in vulnerabilities[:5]:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")
                
                # Extract Description
                description = ""
                for desc in cve_data.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value")
                        break
                        
                # Extract CVSS v3 score if available
                cvss_score = 0.0
                severity = "UNKNOWN"
                
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    base_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = base_data.get("baseScore", 0.0)
                    severity = base_data.get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV30" in metrics:
                    base_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_score = base_data.get("baseScore", 0.0)
                    severity = base_data.get("baseSeverity", "UNKNOWN")
                    
                findings.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": description
                })
                
            return findings
            
        return []
    except Exception as e:
        print(f"Error querying NVD: {e}")
        return []

def query_vulners(service: str, version: str, api_key: str) -> List[Dict[str, Any]]:
    """Queries Vulners API if key is present."""
    if not api_key or not service or not version:
        return []
        
    query = f"{service} {version}"
    url = "https://vulners.com/api/v3/search/lucene/"
    
    payload = {
        "query": query,
        "apiKey": api_key,
        "size": 5
    }
    
    try:
        response = httpx.post(url, json=payload, timeout=10.0)
        if response.status_code == 200:
            data = response.json()
            findings = []
            if data.get("result") == "OK":
                docs = data.get("data", {}).get("search", [])
                for doc in docs:
                    source = doc.get("_source", {})
                    cvss = source.get("cvss", {})
                    score = cvss.get("score", 0.0)
                    
                    found = {
                        "cve_id": source.get("id"),
                        "cvss_score": score,
                        "severity": "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW",
                        "description": source.get("description", "")
                    }
                    findings.append(found)
            return findings
    except Exception:
        pass
    return []
