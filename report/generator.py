import os
import json
import csv
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from datetime import datetime


def generate_pdf(state_data: dict, output_path: str):
    """Generates a professional PDF report using Jinja2 and WeasyPrint."""
    try:
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        os.makedirs(template_dir, exist_ok=True)
        
        template_file = os.path.join(template_dir, "report.html.j2")
        if not os.path.exists(template_file):
            _create_default_template(template_file)

        env = Environment(loader=FileSystemLoader(template_dir))
        env.filters['severity_color'] = _severity_color
        env.filters['severity_badge'] = _severity_badge
        template = env.get_template("report.html.j2")
        
        # Add metadata
        state_data["report_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state_data["report_version"] = "2.0"
        
        html_out = template.render(state_data)
        HTML(string=html_out).write_pdf(output_path)
        print(f"[+] PDF report generated: {output_path}")
    except Exception as e:
        print(f"Error generating PDF: {e}")


def generate_md(state_data: dict, output_path: str):
    """Generates a comprehensive Markdown report."""
    ai_rep = state_data.get("ai_report", {})
    target = state_data.get('target', 'Unknown')
    provider = state_data.get('llm_provider', 'Unknown')
    
    md = f"""# RedChain Penetration Test Report
## Target: {target}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**AI Provider:** {provider}  
**Report Version:** 2.0

---

## Executive Summary
{ai_rep.get('executive_summary', 'N/A')}

---

## Kill Chain Narrative
{ai_rep.get('kill_chain_narrative', 'N/A')}

---

## Attack Path
```text
{ai_rep.get('attack_path_ascii', 'N/A')}
```

---

## Vulnerability Findings

| Host | Port | Service | CVE | Severity | CVSS | OWASP |
|------|------|---------|-----|----------|------|-------|
"""
    for cve in state_data.get("cve_findings", []):
        owasp = ", ".join(cve.get("owasp_mapping", [])[:1])
        md += f"| {cve.get('host')} | {cve.get('port')} | {cve.get('service')} | {cve.get('cve_id')} | {cve.get('severity', 'N/A')} | {cve.get('cvss_score')} | {owasp} |\n"
    
    if not state_data.get("cve_findings"):
        md += "| - | - | - | No vulnerabilities found | - | - | - |\n"

    md += f"""
---

## OWASP Top 10 Mapping

"""
    for finding in ai_rep.get("owasp_findings", []):
        md += f"### {finding.get('category', 'N/A')}\n{finding.get('description', 'N/A')}\n\n"

    md += f"""---

## MITRE ATT&CK Techniques

| Technique ID | Name | Description |
|-------------|------|-------------|
"""
    for tech in ai_rep.get("mitre_techniques", []):
        md += f"| {tech.get('technique_id', '')} | {tech.get('name', '')} | {tech.get('description', '')} |\n"

    md += f"""
---

## Remediation Plan

| Priority | Issue | Recommended Fix |
|----------|-------|-----------------|
"""
    for rem in ai_rep.get('remediation_table', []):
        md += f"| {rem.get('priority', 'medium')} | {rem.get('issue', '')} | {rem.get('fix', '')} |\n"

    # Web App section
    webapp_results = state_data.get("webapp_results", [])
    if webapp_results:
        md += "\n---\n\n## Web Application Fingerprinting\n\n"
        for wa in webapp_results:
            if isinstance(wa, dict):
                md += f"### {wa.get('host', 'Unknown')}\n"
                md += f"- **Tech Stack:** {', '.join(wa.get('tech_stack', []))}\n"
                waf = wa.get('waf', {})
                if isinstance(waf, dict):
                    waf_name = waf.get('waf_name', 'None detected')
                    md += f"- **WAF:** {waf_name}\n"
                else:
                    md += "- **WAF:** N/A\n"
                
                # Risk flags
                for flag in wa.get("risk_flags", []):
                    md += f"- ⚠️ {flag}\n"
                
                # Nikto findings
                nikto = wa.get("nikto_findings", [])
                if nikto:
                    md += f"\n#### Nikto Findings ({len(nikto)})\n\n"
                    md += "| URL | Description | Category |\n"
                    md += "|-----|-------------|----------|\n"
                    for nf in nikto:
                        if isinstance(nf, dict):
                            md += f"| {nf.get('url', '/')} | {nf.get('description', '')[:150]} | {nf.get('category', '')} |\n"
                
                # Gobuster directories
                gb_dirs = wa.get("gobuster_dirs", [])
                gb_files = wa.get("gobuster_files", [])
                if gb_dirs or gb_files:
                    md += f"\n#### Discovered Paths ({len(gb_dirs)} dirs, {len(gb_files)} files)\n\n"
                    md += "| Path | Status | Size | Type | Interesting |\n"
                    md += "|------|--------|------|------|-------------|\n"
                    for gf in gb_dirs:
                        if isinstance(gf, dict):
                            star = "★" if gf.get("is_interesting") else ""
                            redir = f" → {gf.get('redirect_to')}" if gf.get("redirect_to") else ""
                            md += f"| {gf.get('path', '')}{redir} | {gf.get('status_code', '')} | {gf.get('size', '')}B | dir | {star} |\n"
                    for gf in gb_files:
                        if isinstance(gf, dict):
                            star = "★" if gf.get("is_interesting") else ""
                            md += f"| {gf.get('path', '')} | {gf.get('status_code', '')} | {gf.get('size', '')}B | file | {star} |\n"
                
                # Interesting/exposed paths
                interesting = wa.get("interesting_paths", [])
                exposed = wa.get("exposed_files", [])
                login = wa.get("login_pages", [])
                backup = wa.get("backup_files", [])
                if interesting or exposed or login or backup:
                    md += "\n#### Notable Discoveries\n"
                    if interesting:
                        md += f"- **Interesting Paths:** {', '.join(interesting[:10])}\n"
                    if exposed:
                        md += f"- **Exposed Files:** {', '.join(exposed[:10])}\n"
                    if login:
                        md += f"- **Login Pages:** {', '.join(login[:5])}\n"
                    if backup:
                        md += f"- **Backup Files:** {', '.join(backup[:5])}\n"
                
                md += "\n"

    # Pipeline errors
    errors = state_data.get("node_errors", {})
    if errors:
        md += "\n---\n\n## Pipeline Warnings\n\n"
        for node, err in errors.items():
            md += f"- **{node}:** {err}\n"

    # ── Nuclei Findings ───────────────────────────────────────────────────────
    nuclei_findings = state_data.get("nuclei_findings", [])
    if nuclei_findings:
        md += "\n---\n\n## Nuclei Templated Scan Findings\n\n"
        md += "| Severity | Template | URL | CVEs |\n"
        md += "|----------|----------|-----|------|\n"
        for nf in nuclei_findings:
            cves = ", ".join(nf.get("cve_ids", [])) or "-"
            md += f"| {nf.get('severity', '').upper()} | {nf.get('template_name', '')} | {nf.get('url', '')} | {cves} |\n"

    # ── Takeover Findings ───────────────────────────────────────────────────
    takeover_findings = state_data.get("takeover_findings", [])
    if takeover_findings:
        md += "\n---\n\n## ⚠\ufe0f Subdomain Takeover Vulnerabilities\n\n"
        for tf in takeover_findings:
            md += f"### 🚨 {tf.get('subdomain')} → {tf.get('service')}\n"
            md += f"- **CNAME:** `{tf.get('cname')}`\n"
            md += f"- **Fingerprint:** `{tf.get('fingerprint_matched')}`\n"
            md += f"- **URL:** {tf.get('url')}\n"
            md += f"- **Severity:** CRITICAL\n"
            md += f"- {tf.get('description', '')}\n\n"

    # ── Credential Findings ──────────────────────────────────────────────────
    credential_findings = state_data.get("credential_findings", [])
    if credential_findings:
        md += "\n---\n\n## 💥 Default Credentials Accepted\n\n"
        md += "| Host | Port | Service | Username | Password | URL |\n"
        md += "|------|------|---------|----------|----------|-----|\n"
        for cf in credential_findings:
            url = cf.get("url", "-")
            md += f"| {cf.get('host')} | {cf.get('port')} | {cf.get('service')} | `{cf.get('username')}` | `{cf.get('password')}` | {url} |\n"

    md += f"\n---\n*Generated by RedChain v2.0 — Autonomous AI Red Team Agent*\n"
    
    try:
        with open(output_path, "w") as f:
            f.write(md)
        print(f"[+] Markdown report generated: {output_path}")
    except Exception as e:
        print(f"Error writing Markdown: {e}")


def generate_json_report(state_data: dict, output_path: str):
    """Generates a structured JSON report for programmatic consumption."""
    report = {
        "meta": {
            "target": state_data.get("target"),
            "date": datetime.now().isoformat(),
            "version": "2.0",
            "llm_provider": state_data.get("llm_provider", "unknown"),
        },
        "executive_summary": state_data.get("ai_report", {}).get("executive_summary", ""),
        "kill_chain_narrative": state_data.get("ai_report", {}).get("kill_chain_narrative", ""),
        "attack_path": state_data.get("ai_report", {}).get("attack_path_ascii", ""),
        "findings": state_data.get("cve_findings", []),
        "nuclei_findings": state_data.get("nuclei_findings", []),
        "takeover_findings": state_data.get("takeover_findings", []),
        "credential_findings": state_data.get("credential_findings", []),
        "scan_results": state_data.get("scan_results", []),
        "webapp_results": state_data.get("webapp_results", []),
        "osint_results": state_data.get("osint_results", {}),
        "remediation": state_data.get("ai_report", {}).get("remediation_table", []),
        "owasp_findings": state_data.get("ai_report", {}).get("owasp_findings", []),
        "mitre_techniques": state_data.get("ai_report", {}).get("mitre_techniques", []),
        "errors": state_data.get("node_errors", {}),
    }
    try:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] JSON report generated: {output_path}")
    except Exception as e:
        print(f"Error writing JSON: {e}")


def generate_csv_report(state_data: dict, output_path: str):
    """Generates a CSV export of all vulnerability findings."""
    findings = state_data.get("cve_findings", [])
    
    try:
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "Service", "CVE ID", "CVSS Score", 
                           "Severity", "Description", "OWASP Mapping", "Source"])
            
            for cve in findings:
                writer.writerow([
                    cve.get("host", ""),
                    cve.get("port", ""),
                    cve.get("service", ""),
                    cve.get("cve_id", ""),
                    cve.get("cvss_score", ""),
                    cve.get("severity", ""),
                    cve.get("description", "")[:200],
                    "; ".join(cve.get("owasp_mapping", [])),
                    cve.get("source", ""),
                ])
        print(f"[+] CSV report generated: {output_path}")
    except Exception as e:
        print(f"Error writing CSV: {e}")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _severity_color(severity: str) -> str:
    """Return CSS color for severity level."""
    colors = {
        "Critical": "#d32f2f",
        "High": "#f57c00",
        "Medium": "#fbc02d",
        "Low": "#388e3c",
        "Info": "#1976d2",
    }
    return colors.get(severity, "#757575")


def _severity_badge(severity: str) -> str:
    """Return HTML badge for severity level."""
    color = _severity_color(severity)
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;">{severity}</span>'


def _create_default_template(filepath: str):
    """Create the professional report HTML template."""
    template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            color: #1a1a2e;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: #ffffff;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .header .meta {
            opacity: 0.8;
            font-size: 14px;
        }
        
        h2 {
            color: #0f3460;
            font-size: 20px;
            font-weight: 600;
            border-bottom: 2px solid #e94560;
            padding-bottom: 8px;
            margin: 30px 0 15px 0;
        }
        
        h3 {
            color: #16213e;
            font-size: 16px;
            margin: 20px 0 10px 0;
        }
        
        p { margin-bottom: 12px; font-size: 14px; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 13px;
        }
        
        th {
            background: #16213e;
            color: white;
            padding: 10px 12px;
            text-align: left;
            font-weight: 500;
        }
        
        td {
            border-bottom: 1px solid #e0e0e0;
            padding: 8px 12px;
        }
        
        tr:nth-child(even) { background: #f8f9fa; }
        
        .severity-critical { background: #ffebee !important; border-left: 4px solid #d32f2f; }
        .severity-high { background: #fff3e0 !important; border-left: 4px solid #f57c00; }
        .severity-medium { background: #fffde7 !important; border-left: 4px solid #fbc02d; }
        .severity-low { background: #e8f5e9 !important; border-left: 4px solid #388e3c; }
        
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            color: white;
        }
        
        .badge-critical { background: #d32f2f; }
        .badge-high { background: #f57c00; }
        .badge-medium { background: #fbc02d; color: #333; }
        .badge-low { background: #388e3c; }
        .badge-info { background: #1976d2; }
        
        pre {
            background: #1a1a2e;
            color: #a9b7c6;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 13px;
            line-height: 1.4;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
            border: 1px solid #e0e0e0;
        }
        
        .stat-card .number {
            font-size: 28px;
            font-weight: 700;
            color: #0f3460;
        }
        
        .stat-card .label {
            font-size: 12px;
            color: #666;
            margin-top: 4px;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            font-size: 12px;
            color: #999;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔴 RedChain Penetration Test Report</h1>
        <div class="meta">
            <strong>Target:</strong> {{ target }} &nbsp;|&nbsp;
            <strong>Date:</strong> {{ report_date }} &nbsp;|&nbsp;
            <strong>AI Provider:</strong> {{ llm_provider | default('Gemini') }}
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="number">{{ cve_findings | length }}</div>
            <div class="label">CVEs Found</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ live_hosts | length }}</div>
            <div class="label">Live Hosts</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ scan_results | length }}</div>
            <div class="label">Hosts Scanned</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ webapp_results | default([]) | length }}</div>
            <div class="label">Web Apps</div>
        </div>
    </div>
    
    <h2>Executive Summary</h2>
    <p>{{ ai_report.get('executive_summary', 'N/A') }}</p>
    
    <h2>Kill Chain Narrative</h2>
    <p>{{ ai_report.get('kill_chain_narrative', 'N/A') }}</p>
    
    <h2>Attack Path</h2>
    <pre>{{ ai_report.get('attack_path_ascii', 'N/A') }}</pre>
    
    <h2>Vulnerability Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Host</th>
                <th>Port/Service</th>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>OWASP</th>
            </tr>
        </thead>
        <tbody>
            {% for cve in cve_findings %}
            <tr class="severity-{{ cve.severity | default('info') | lower }}">
                <td>{{ cve.host }}</td>
                <td>{{ cve.port }} / {{ cve.service }}</td>
                <td>{{ cve.cve_id }}</td>
                <td><span class="badge badge-{{ cve.severity | default('info') | lower }}">{{ cve.severity | default('N/A') }}</span></td>
                <td>{{ cve.cvss_score }}</td>
                <td>{{ cve.owasp_mapping | default([]) | join(', ') }}</td>
            </tr>
            {% endfor %}
            {% if not cve_findings %}
            <tr><td colspan="6">No vulnerabilities found.</td></tr>
            {% endif %}
        </tbody>
    </table>
    
    <h2>Remediation Plan</h2>
    <table>
        <thead>
            <tr>
                <th>Priority</th>
                <th>Issue</th>
                <th>Recommended Fix</th>
            </tr>
        </thead>
        <tbody>
            {% for rem in ai_report.get('remediation_table', []) %}
            <tr>
                <td><span class="badge badge-{{ rem.priority | default('medium') | lower }}">{{ rem.priority | default('medium') }}</span></td>
                <td>{{ rem.issue }}</td>
                <td>{{ rem.fix }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <div class="footer">
        Generated by RedChain v2.0 — Autonomous AI Red Team Agent
    </div>
</body>
</html>"""
    
    with open(filepath, "w") as f:
        f.write(template)
