import json
import os
from typing import Dict, Any
from google import genai
from google.genai import types
from config import settings
from report.generator import generate_pdf, generate_md

def run_report_agent(state_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Executes Phase 5 Report generation.
    Passes finding context to Gemini, generates narrative, and creates PDF/MD.
    """
    if not settings.gemini_api_key:
        return {
            "error": "No Gemini API key provided. Skipping AI narrative.",
            "report_paths": {}
        }
        
    try:
        client = genai.Client(api_key=settings.gemini_api_key)
        
        system_instruction = (
            "You are a senior red team consultant writing a penetration test report. "
            "Reason as an attacker following the Cyber Kill Chain framework: "
            "Reconnaissance, Weaponisation, Delivery, Exploitation, Installation, C2, Actions on Objectives. "
            "Be technical, specific, and cite actual CVE IDs and service versions found. "
            "Return ONLY valid JSON matching this schema: "
            "{\"executive_summary\": \"...\", \"kill_chain_narrative\": \"...\", \"attack_path_ascii\": \"...\", \"remediation_table\": [{\"issue\": \"...\", \"fix\": \"...\"}]}"
        )
        
        prompt = (
            f"Here are the findings:\n"
            f"Target: {state_data.get('target')}\n"
            f"OSINT: {json.dumps(state_data.get('osint_results', {}))[:1000]}...\n" # Truncated to avoid huge limits if many results
            f"Live Hosts: {state_data.get('live_hosts', [])}\n"
            f"Scan Results: {json.dumps(state_data.get('scan_results', []))[:2000]}...\n"
            f"CVEs: {json.dumps(state_data.get('cve_findings', []))[:3000]}...\n"
        )
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=f"{system_instruction}\n\n{prompt}",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
            )
        )
        
        narrative_data = json.loads(response.text)
        
        # Add generated narrative back into state data for the templates
        state_data["ai_report"] = narrative_data
        
        # Generate physical report files
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        target_clean = state_data.get("target", "target").replace("/", "_").replace(":", "_")
        pdf_path = os.path.join(reports_dir, f"{target_clean}_redchain_report.pdf")
        md_path = os.path.join(reports_dir, f"{target_clean}_redchain_report.md")
        
        generate_pdf(state_data, pdf_path)
        generate_md(state_data, md_path)
        
        return {
            "kill_chain_narrative": narrative_data.get("kill_chain_narrative", ""),
            "report_paths": {"pdf": pdf_path, "md": md_path}
        }
        
    except Exception as e:
        return {"error": f"Failed to generate report: {e}", "report_paths": {}}
