from pydantic import BaseModel
from typing import List, Dict

class WhoisData(BaseModel):
    registrar: str
    creation_date: str
    expiration_date: str
    name_servers: List[str]
    registrant_org: str
    registrant_country: str
    abuse_email: str

class ShodanHost(BaseModel):
    ip: str
    ports: List[int]
    hostnames: List[str]
    org: str
    os: str
    vulns: List[str]       # CVEs shodan already knows about
    banners: List[str]
    last_update: str

class AsnInfo(BaseModel):
    asn: str
    org: str
    country: str
    ip_ranges: List[str]
    abuse_email: str

class DorkResult(BaseModel):
    dork: str
    description: str

class OsintResult(BaseModel):
    domain: str
    emails: List[str] = []
    employee_names: List[str] = []
    hostnames: List[str] = []
    dns_records: Dict[str, List[str]] = {}   # A, MX, NS, TXT, CNAME, SOA
    subdomains_crtsh: List[str] = []
    whois: WhoisData | None = None
    shodan_hosts: List[ShodanHost] = []      # empty if no key
    linkedin_employees: List[str] = []       # from theHarvester
    google_dorks: List[DorkResult] = []      # metadata only, no scraping
    asn_info: AsnInfo | None = None
    ip_ranges: List[str] = []
    technologies: List[str] = []             # from headers / shodan
    open_ports_shodan: List[int] = []        # from shodan, before nmap
    raw_harvester_output: str = ""
    sources_used: List[str] = []             # which sources ran successfully
    errors: Dict[str, str] = {}              # source -> error message if failed
