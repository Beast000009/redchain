import os
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader

def generate_pdf(state_data: dict, output_path: str):
    """Generates a PDF report using Jinja2 and WeasyPrint."""
    try:
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        
        # Creating a basic embedded style if template missing
        if not os.path.exists(os.path.join(template_dir, "report.html.j2")):
            os.makedirs(template_dir, exist_ok=True)
            with open(os.path.join(template_dir, "report.html.j2"), "w") as f:
                f.write("""
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; }
                        h1 { color: #d32f2f; }
                        h2 { color: #1976d2; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        .critical { background-color: #ffcdd2; font-weight: bold; }
                        .high { background-color: #ffe0b2; }
                        pre { background-color: #2b2b2b; color: #a9b7c6; padding: 10px; border-radius: 5px; }
                    </style>
                </head>
                <body>
                    <h1>RedChain Autonomous Pentest Report</h1>
                    <p><strong>Target:</strong> {{ target }}</p>
                    
                    <h2>Executive Summary</h2>
                    <p>{{ ai_report.get('executive_summary', 'N/A') }}</p>
                    
                    <h2>Kill Chain Narrative</h2>
                    <p>{{ ai_report.get('kill_chain_narrative', 'N/A') }}</p>
                    
                    <h2>Attack Path</h2>
                    <pre>{{ ai_report.get('attack_path_ascii', 'N/A') }}</pre>
                    
                    <h2>Vulnerabilities Discovered</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Host</th>
                                <th>Port/Service</th>
                                <th>CVE ID</th>
                                <th>Severity</th>
                                <th>CVSS Score</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for cve in cve_findings %}
                            <tr class="{{ cve.severity | lower }}">
                                <td>{{ cve.host }}</td>
                                <td>{{ cve.port }} / {{ cve.service }}</td>
                                <td>{{ cve.cve_id }}</td>
                                <td>{{ cve.severity }}</td>
                                <td>{{ cve.cvss_score }}</td>
                            </tr>
                            {% endfor %}
                            {% if not cve_findings %}
                            <tr><td colspan="5">No vulnerabilities found.</td></tr>
                            {% endif %}
                        </tbody>
                    </table>
                    
                    <h2>Remediation Plan</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Issue</th>
                                <th>Recommended Fix</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for rem in ai_report.get('remediation_table', []) %}
                            <tr>
                                <td>{{ rem.issue }}</td>
                                <td>{{ rem.fix }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </body>
                </html>
                """)

        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html.j2")
        html_out = template.render(state_data)
        
        HTML(string=html_out).write_pdf(output_path)
    except Exception as e:
        print(f"Error generating PDF: {e}")

def generate_md(state_data: dict, output_path: str):
    """Generates a raw Markdown report."""
    md = f"# RedChain Pentest Report: {state_data.get('target')}\n\n"
    ai_rep = state_data.get("ai_report", {})
    
    md += f"## Executive Summary\n{ai_rep.get('executive_summary', 'N/A')}\n\n"
    md += f"## Kill Chain Narrative\n{ai_rep.get('kill_chain_narrative', 'N/A')}\n\n"
    md += f"## Attack Path\n```text\n{ai_rep.get('attack_path_ascii', 'N/A')}\n```\n\n"
    
    md += "## Vulnerabilities\n"
    md += "| Host | Service | CVE | Severity | CVSS |\n"
    md += "|---|---|---|---|---|\n"
    for cve in state_data.get("cve_findings", []):
        md += f"| {cve.get('host')} | {cve.get('port')} {cve.get('service')} | {cve.get('cve_id')} | {cve.get('severity')} | {cve.get('cvss_score')} |\n"
        
    try:
        with open(output_path, "w") as f:
            f.write(md)
    except Exception as e:
        print(f"Error writing Markdown: {e}")
