import json
import os
import sys
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import settings, run_config
from report.generator import generate_pdf, generate_md, generate_json_report, generate_csv_report
from llm import get_adapter
from i18n import get_report_language_instruction

# OWASP Top 10 (2021) mapping for compliance reports
OWASP_MAPPING = {
    "injection": "A03:2021 – Injection",
    "sql": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "broken_auth": "A07:2021 – Identification and Authentication Failures",
    "sensitive_data": "A02:2021 – Cryptographic Failures",
    "xxe": "A05:2021 – Security Misconfiguration",
    "access_control": "A01:2021 – Broken Access Control",
    "misconfig": "A05:2021 – Security Misconfiguration",
    "components": "A06:2021 – Vulnerable and Outdated Components",
    "logging": "A09:2021 – Security Logging and Monitoring Failures",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
}

# MITRE ATT&CK mapping
MITRE_MAPPING = {
    "reconnaissance": "TA0043 – Reconnaissance",
    "resource_development": "TA0042 – Resource Development",
    "initial_access": "TA0001 – Initial Access",
    "execution": "TA0002 – Execution",
    "persistence": "TA0003 – Persistence",
    "privilege_escalation": "TA0004 – Privilege Escalation",
    "defense_evasion": "TA0005 – Defense Evasion",
    "credential_access": "TA0006 – Credential Access",
    "discovery": "TA0007 – Discovery",
    "lateral_movement": "TA0008 – Lateral Movement",
    "collection": "TA0009 – Collection",
    "exfiltration": "TA0010 – Exfiltration",
    "impact": "TA0040 – Impact",
}


def classify_severity(cvss_score: float) -> str:
    """Classify CVSS score into severity rating."""
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score > 0.0:
        return "Low"
    return "Info"


def enrich_cve_findings(findings: list) -> list:
    """Add severity classification and compliance mappings to CVE findings."""
    for f in findings:
        score = f.get("cvss_score", 0.0)
        f["severity"] = classify_severity(score)

        # Map to OWASP
        desc_lower = f.get("description", "").lower()
        owasp_tags = []
        for keyword, owasp_id in OWASP_MAPPING.items():
            if keyword in desc_lower:
                owasp_tags.append(owasp_id)
        f["owasp_mapping"] = list(set(owasp_tags)) or ["A06:2021 \u2013 Vulnerable and Outdated Components"]

        # \u2500\u2500 Dynamic MITRE ATT&CK mapping (keyword-driven) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        mitre_tags = []
        d = desc_lower

        if any(x in d for x in ["recon", "enumerat", "discovery", "scan", "fingerprint"]):
            mitre_tags.append(MITRE_MAPPING["reconnaissance"])
        if any(x in d for x in ["remote code", "rce", "command injection", "code execution", "execute"]):
            mitre_tags.append(MITRE_MAPPING["execution"])
        if any(x in d for x in ["privilege escalat", "priv esc", "sudo", "suid", "local privilege"]):
            mitre_tags.append(MITRE_MAPPING["privilege_escalation"])
        if any(x in d for x in ["password", "credential", "authen", "brute", "hash", "ntlm", "kerberos", "dump"]):
            mitre_tags.append(MITRE_MAPPING["credential_access"])
        if any(x in d for x in ["backdoor", "persist", "rootkit", "startup", "cron", "scheduled"]):
            mitre_tags.append(MITRE_MAPPING["persistence"])
        if any(x in d for x in ["lateral", "pivot", "smb", "rdp", "wmi", "pass the hash"]):
            mitre_tags.append(MITRE_MAPPING["lateral_movement"])
        if any(x in d for x in ["exfil", "upload", "data breach", "leak", "exfiltrat"]):
            mitre_tags.append(MITRE_MAPPING["exfiltration"])
        if any(x in d for x in ["bypass", "evasion", "obfuscat", "disable log", "clear log", "antivirus"]):
            mitre_tags.append(MITRE_MAPPING["defense_evasion"])
        if any(x in d for x in ["denial of service", "dos", "ddos", "crash", "resource exhaust"]):
            mitre_tags.append(MITRE_MAPPING["impact"])
        if any(x in d for x in ["ssrf", "server-side request"]):
            mitre_tags.append(MITRE_MAPPING["collection"])
        # Fallback: initial access
        if not mitre_tags:
            mitre_tags.append(MITRE_MAPPING["initial_access"])

        f["mitre_mapping"] = list(set(mitre_tags))

    return findings


def _get_llm_api_key(provider: str) -> str | None:
    """Get the appropriate API key for the selected provider."""
    if provider == "gemini":
        return settings.gemini_api_key
    elif provider == "openai":
        return settings.openai_api_key
    elif provider == "ollama":
        return None  # No key needed
    return None


def run_report_agent(state_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Executes Phase 5 Report generation.
    Uses multi-LLM adapter, generates narrative, and creates reports in multiple formats.
    """
    provider = run_config.llm_provider
    api_key = _get_llm_api_key(provider)
    language = run_config.language
    
    # Enrich CVE findings with severity + compliance mappings
    state_data["cve_findings"] = enrich_cve_findings(state_data.get("cve_findings", []))
    
    # Check if LLM is available
    if provider != "ollama" and not api_key:
        from rich.console import Console
        console = Console()
        console.print(f"[yellow]No API key for {provider}. Generating raw report without AI narrative.[/yellow]")
        
        # ── Build a structured raw report from scan data ─────────────────────
        target_name = state_data.get("target", "Unknown")
        
        # Summarise services found
        services_summary = []
        for sr in state_data.get("scan_results", []):
            for p in sr.get("open_ports", []):
                services_summary.append(f"  • {sr.get('host')}:{p.get('port')} — {p.get('product','')} {p.get('version','')}")
        
        # Summarise CVEs
        cve_lines = []
        for c in state_data.get("cve_findings", []):
            sev = c.get("severity", "Info")
            cve_lines.append(f"  • [{sev}] {c.get('cve_id','?')} — {c.get('description','')[:120]}")
        
        # Summarise webapp fingerprinting
        webapp_lines = []
        for w in state_data.get("webapp_results", []):
            waf = w.get("waf", {})
            waf_name = waf.get("waf_name", "None") if isinstance(waf, dict) else "Unknown"
            tech = ", ".join(w.get("tech_stack", [])) or "Unknown"
            nikto_count = len(w.get("nikto_findings", []))
            dirs_count = len(w.get("gobuster_dirs", []))
            webapp_lines.append(f"  • {w.get('host','')} — Tech: {tech} | WAF: {waf_name} | Nikto: {nikto_count} | Dirs: {dirs_count}")
        
        raw_narrative = {
            "executive_summary": (
                f"Automated scan of {target_name} completed. "
                f"Found {len(services_summary)} open services, "
                f"{len(state_data.get('cve_findings',[]))} CVEs, "
                f"and {len(state_data.get('webapp_results',[]))} web services fingerprinted. "
                f"No AI narrative was generated (no {provider} API key). "
                f"Review the raw findings below."
            ),
            "kill_chain_narrative": (
                f"## Reconnaissance\n"
                f"OSINT gathered {len(state_data.get('osint_results',{}).get('subdomains',[]))} subdomains, "
                f"{len(state_data.get('osint_results',{}).get('emails',[]))} emails.\n\n"
                f"## Web App Fingerprinting\n" + ("\n".join(webapp_lines) or "  No web services fingerprinted.") + "\n\n"
                f"## Service Discovery\n" + ("\n".join(services_summary) or "  No open services found.") + "\n\n"
                f"## Vulnerability Assessment\n" + ("\n".join(cve_lines) or "  No CVEs matched.")
            ),
            "attack_path_ascii": "Recon → Subdomain Enum → Web Fingerprint → Port Scan → CVE Match → Report",
            "remediation_table": [],
            "owasp_findings": [],
            "mitre_techniques": [],
        }
        
        state_data["ai_report"] = raw_narrative
        state_data["llm_provider"] = f"{provider} (raw — no API key)"
        
        # ── Generate all report files ────────────────────────────────────────
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        target_clean = target_name.replace("/", "_").replace(":", "_")
        
        json_path = os.path.join(reports_dir, f"{target_clean}_redchain_report.json")
        md_path = os.path.join(reports_dir, f"{target_clean}_redchain_report.md")
        csv_path = os.path.join(reports_dir, f"{target_clean}_redchain_findings.csv")
        
        report_paths = {}
        
        output_fmt = run_config.output_format
        if output_fmt in ("md", "both"):
            generate_md(state_data, md_path)
            report_paths["md"] = md_path
        
        if output_fmt == "csv":
            generate_csv_report(state_data, csv_path)
            report_paths["csv"] = csv_path
        
        # Always generate JSON as raw data dump
        generate_json_report(state_data, json_path)
        report_paths["json"] = json_path
        
        console.print(f"[bold green]Raw reports generated (no AI):[/bold green]")
        for fmt, path in report_paths.items():
            console.print(f"  [cyan]→ {fmt.upper()}: {path}[/cyan]")
        
        return {
            "kill_chain_narrative": raw_narrative["kill_chain_narrative"],
            "report_paths": report_paths
        }
        
    try:
        adapter = get_adapter(
            provider=provider,
            api_key=api_key,
            model=run_config.llm_model,
            base_url=settings.ollama_base_url if provider == "ollama" else settings.openai_base_url
        )
        
        if not adapter.is_available():
            return {"error": f"LLM provider '{provider}' is not available.", "report_paths": {}}
        
        lang_instruction = get_report_language_instruction(language)
        
        system_instruction = (
            "You are a senior red team consultant writing a penetration test report. "
            "Reason as an attacker following the Cyber Kill Chain framework: "
            "Reconnaissance, Weaponisation, Delivery, Exploitation, Installation, C2, Actions on Objectives. "
            "Be technical, specific, and cite actual CVE IDs and service versions found. "
            "Map findings to OWASP Top 10 and MITRE ATT&CK where applicable. "
            f"{lang_instruction} "
            "Return ONLY valid JSON matching this schema: "
            "{\"executive_summary\": \"...\", \"kill_chain_narrative\": \"...\", "
            "\"attack_path_ascii\": \"...\", "
            "\"remediation_table\": [{\"issue\": \"...\", \"fix\": \"...\", \"priority\": \"critical|high|medium|low\"}], "
            "\"owasp_findings\": [{\"category\": \"...\", \"description\": \"...\"}], "
            "\"mitre_techniques\": [{\"technique_id\": \"...\", \"name\": \"...\", \"description\": \"...\"}]}"
        )
        
        prompt = (
            f"Here are the findings:\n"
            f"Target: {state_data.get('target')}\n"
            f"OSINT: {json.dumps(state_data.get('osint_results', {}))[:1500]}...\n"
            f"Live Hosts: {state_data.get('live_hosts', [])}\n"
            f"Web Fingerprints (Phase 2.5): {json.dumps(state_data.get('webapp_results', []))[:3000]}...\n"
            f"Scan Results: {json.dumps(state_data.get('scan_results', []))[:2000]}...\n"
            f"CVEs: {json.dumps(state_data.get('cve_findings', []))[:3000]}...\n"
            f"Node Errors: {json.dumps(state_data.get('node_errors', {}))}\n"
            f"\nEnsure to include a highly detailed Web App Fingerprinting section if Web Fingerprints are provided. "
            f"Include interesting paths, WAFs detected, tech stack, and highlight risk flags in the executive summary. "
            f"Include OWASP Top 10 and MITRE ATT&CK mappings for each finding."
        )
        
        narrative_data = adapter.generate_report(system_instruction, prompt)
        
        # Add generated narrative back into state data for the templates
        state_data["ai_report"] = narrative_data
        state_data["llm_provider"] = adapter.get_name()
        
        # Generate physical report files
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        target_clean = state_data.get("target", "target").replace("/", "_").replace(":", "_")
        pdf_path = os.path.join(reports_dir, f"{target_clean}_redchain_report.pdf")
        md_path = os.path.join(reports_dir, f"{target_clean}_redchain_report.md")
        json_path = os.path.join(reports_dir, f"{target_clean}_redchain_report.json")
        csv_path = os.path.join(reports_dir, f"{target_clean}_redchain_findings.csv")
        
        output_fmt = run_config.output_format
        report_paths = {}
        
        if output_fmt in ("pdf", "both"):
            generate_pdf(state_data, pdf_path)
            report_paths["pdf"] = pdf_path
            
        if output_fmt in ("md", "both"):
            generate_md(state_data, md_path)
            report_paths["md"] = md_path
            
        if output_fmt == "json":
            generate_json_report(state_data, json_path)
            report_paths["json"] = json_path
            
        if output_fmt == "csv":
            generate_csv_report(state_data, csv_path)
            report_paths["csv"] = csv_path
        
        # Always generate JSON as raw data dump
        generate_json_report(state_data, json_path)
        report_paths["json"] = json_path
        
        return {
            "kill_chain_narrative": narrative_data.get("kill_chain_narrative", ""),
            "report_paths": report_paths
        }
        
    except Exception as e:
        return {"error": f"Failed to generate report: {e}", "report_paths": {}}
