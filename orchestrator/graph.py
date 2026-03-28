import operator
import sys
import os
from typing import TypedDict, Annotated, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from rich.console import Console
import asyncio
import traceback

# Add the project root to sys.path so agents can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

console = Console()

# ── State Schema ──────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    target: str
    input_type: str  # domain, ip, cidr
    wordlist: Optional[str] # for directory busting

    # Phase 1: OSINT
    osint_results: Dict[str, Any]

    # Phase 2: Subdomain
    subdomains: List[Dict[str, Any]]

    # Phase 2.5: WebApp Fingerprinting
    webapp_results: List[Dict[str, Any]]

    # Phase 2.6: Nuclei Templated Scanning
    nuclei_findings: List[Dict[str, Any]]

    # Phase 2.7: Subdomain Takeover
    takeover_findings: List[Dict[str, Any]]

    # Phase 3: Scanner
    live_hosts: List[str]
    scan_results: List[Dict[str, Any]]

    # Phase 3.5: Credential Testing
    credential_findings: List[Dict[str, Any]]

    # Phase 4: CVE
    cve_findings: List[Dict[str, Any]]

    # Phase 5: Report
    kill_chain_narrative: str
    report_paths: Dict[str, str]

    # Error tracking
    node_errors: Dict[str, str]


# ── State Validation ──────────────────────────────────────────────────────────

def validate_state(state: AgentState, required_keys: list[str], node_name: str) -> list[str]:
    """Validate that required state keys exist and are not None. Returns list of warnings."""
    warnings = []
    for key in required_keys:
        if key not in state or state.get(key) is None:
            warnings.append(f"[{node_name}] Missing required state key: '{key}'")
    return warnings


# ── Node Functions ────────────────────────────────────────────────────────────

from agents.osint_agent import run_osint
from agents.subdomain_agent import run_subdomain_enum
from agents.scanner_agent import run_scanner
from agents.cve_agent import run_cve_lookup
from agents.report_agent import run_report_agent
from agents.webapp_agent import run_webapp_fingerprint
from agents.nuclei_agent import run_nuclei_scan
from agents.takeover_agent import run_takeover_check
from agents.credential_agent import run_credential_check


def osint_node(state: AgentState):
    console.print(f"[bold blue][OSINT Node][/bold blue] Running OSINT on {state['target']}")
    try:
        warnings = validate_state(state, ["target"], "OSINT")
        for w in warnings:
            console.print(f"[yellow]{w}[/yellow]")
        
        results = asyncio.run(run_osint(state["target"]))
        return {"osint_results": results}
    except Exception as e:
        console.print(f"[bold red][OSINT Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "osint_results": {},
            "node_errors": {**state.get("node_errors", {}), "osint": str(e)}
        }


def subdomain_node(state: AgentState):
    console.print(f"[bold blue][Subdomain Node][/bold blue] Enumerating subdomains for {state['target']}")
    try:
        warnings = validate_state(state, ["target", "osint_results"], "Subdomain")
        for w in warnings:
            console.print(f"[yellow]{w}[/yellow]")
        
        osint = state.get("osint_results", {})
        hostnames = osint.get("hostnames", [])
        subs = osint.get("subdomains", [])
        
        # Combine everything OSINT found
        all_discovered = list(set(hostnames + subs))
        
        subdomains = run_subdomain_enum(state["target"], all_discovered)
        return {"subdomains": subdomains}
    except Exception as e:
        console.print(f"[bold red][Subdomain Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "subdomains": [],
            "node_errors": {**state.get("node_errors", {}), "subdomain": str(e)}
        }


def webapp_node(state: AgentState):
    console.print("[cyan][WebApp Node] Fingerprinting web services...[/cyan]")
    try:
        warnings = validate_state(state, ["target", "subdomains"], "WebApp")
        for w in warnings:
            console.print(f"[yellow]{w}[/yellow]")

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        new_state = loop.run_until_complete(run_webapp_fingerprint(state))
        return new_state
    except Exception as e:
        console.print(f"[bold red][WebApp Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "webapp_results": [],
            "node_errors": {**state.get("node_errors", {}), "webapp": str(e)}
        }


def nuclei_node(state: AgentState):
    console.print("[cyan][Nuclei Node] Running templated vulnerability scanning...[/cyan]")
    try:
        new_state = asyncio.run(run_nuclei_scan(state))
        return {"nuclei_findings": new_state.get("nuclei_findings", [])}
    except Exception as e:
        console.print(f"[bold red][Nuclei Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "nuclei_findings": [],
            "node_errors": {**state.get("node_errors", {}), "nuclei": str(e)}
        }


def takeover_node(state: AgentState):
    console.print("[cyan][Takeover Node] Checking for subdomain takeover vulnerabilities...[/cyan]")
    try:
        new_state = asyncio.run(run_takeover_check(state))
        return {"takeover_findings": new_state.get("takeover_findings", [])}
    except Exception as e:
        console.print(f"[bold red][Takeover Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "takeover_findings": [],
            "node_errors": {**state.get("node_errors", {}), "takeover": str(e)}
        }


def scanner_node(state: AgentState):
    console.print(f"[bold blue][Scanner Node][/bold blue] Running vulnerability scans...")
    try:
        warnings = validate_state(state, ["target", "input_type"], "Scanner")
        for w in warnings:
            console.print(f"[yellow]{w}[/yellow]")

        live = state.get("live_hosts", [])
        if not live:
            for sub in state.get("subdomains", []):
                if sub.get("alive") and sub.get("ip"):
                    live.append(sub.get("ip"))

        actual_live, scan_results = asyncio.run(run_scanner(
            state["target"],
            state["input_type"],
            live,
            state.get("wordlist"),
            state.get("webapp_results", [])
        ))
        return {"live_hosts": actual_live, "scan_results": scan_results}
    except Exception as e:
        console.print(f"[bold red][Scanner Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "live_hosts": [],
            "scan_results": [],
            "node_errors": {**state.get("node_errors", {}), "scanner": str(e)}
        }


def credential_node(state: AgentState):
    console.print("[cyan][Credential Node] Testing default credentials...[/cyan]")
    try:
        new_state = asyncio.run(run_credential_check(state))
        return {"credential_findings": new_state.get("credential_findings", [])}
    except Exception as e:
        console.print(f"[bold red][Credential Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "credential_findings": [],
            "node_errors": {**state.get("node_errors", {}), "credentials": str(e)}
        }


def cve_node(state: AgentState):
    console.print(f"[bold blue][CVE Node][/bold blue] Looking up CVEs for services...")
    try:
        warnings = validate_state(state, ["scan_results"], "CVE")
        for w in warnings:
            console.print(f"[yellow]{w}[/yellow]")
        
        findings = run_cve_lookup(state.get("scan_results", []))
        console.print(f"Found [red]{len(findings)}[/red] CVEs.")
        return {"cve_findings": findings}
    except Exception as e:
        console.print(f"[bold red][CVE Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "cve_findings": [],
            "node_errors": {**state.get("node_errors", {}), "cve": str(e)}
        }


def report_node(state: AgentState):
    console.print(f"[bold blue][Report Node][/bold blue] Generating AI narrative and PDF report...")
    try:
        # Report should always run even if earlier phases had errors
        node_errors = state.get("node_errors", {})
        if node_errors:
            console.print(f"[yellow]Note: {len(node_errors)} node(s) had errors during scan: {', '.join(node_errors.keys())}[/yellow]")
        
        results = run_report_agent(state)
        return {
            "kill_chain_narrative": results.get("kill_chain_narrative", ""),
            "report_paths": results.get("report_paths", {})
        }
    except Exception as e:
        console.print(f"[bold red][Report Node] FAILED: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return {
            "kill_chain_narrative": f"Report generation failed: {e}",
            "report_paths": {},
            "node_errors": {**state.get("node_errors", {}), "report": str(e)}
        }


# ── Routing Logic ─────────────────────────────────────────────────────────────

def route_initial(state: AgentState):
    input_type = state["input_type"]
    if input_type == "domain":
        return "osint"
    elif input_type in ["ip", "cidr"]:
        return "scanner"
    return "osint" # fallback


# ── Build the Graph ───────────────────────────────────────────────────────────

workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("osint", osint_node)
workflow.add_node("subdomain", subdomain_node)
workflow.add_node("takeover", takeover_node)
workflow.add_node("webapp", webapp_node)
workflow.add_node("nuclei", nuclei_node)
workflow.add_node("scanner", scanner_node)
workflow.add_node("credential", credential_node)
workflow.add_node("cve", cve_node)
workflow.add_node("report", report_node)

# Add Edges
workflow.set_conditional_entry_point(
    route_initial,
    {
        "osint": "osint",
        "scanner": "scanner"
    }
)

workflow.add_edge("osint",      "subdomain")
workflow.add_edge("subdomain",  "takeover")
workflow.add_edge("takeover",   "webapp")
workflow.add_edge("webapp",     "nuclei")
workflow.add_edge("nuclei",     "scanner")
workflow.add_edge("scanner",    "credential")
workflow.add_edge("credential", "cve")
workflow.add_edge("cve",        "report")
workflow.add_edge("report",     END)

# Compile graph
app = workflow.compile()

def run_workflow(target: str, input_type: str, wordlist: Optional[str] = None):
    """Entry point for cli.py to trigger the flow."""
    console.print(f"[bold green]Starting LangGraph Workflow for {target} ({input_type})[/bold green]")

    initial_state = AgentState(
        target=target,
        input_type=input_type,
        wordlist=wordlist,
        osint_results={},
        subdomains=[],
        webapp_results=[],
        nuclei_findings=[],
        takeover_findings=[],
        live_hosts=[],
        scan_results=[],
        credential_findings=[],
        cve_findings=[],
        kill_chain_narrative="",
        report_paths={},
        node_errors={}
    )
    
    # Run the graph
    final_state = None
    for output in app.stream(initial_state):
        for key, value in output.items():
            console.print(f"[gray]Finished phase:[/gray] {key}")
        final_state = output
    
    # Summary of errors if any
    if final_state:
        # Collect node_errors from the last output
        for key, value in final_state.items():
            if isinstance(value, dict) and "node_errors" in value:
                errors = value["node_errors"]
                if errors:
                    console.print(f"\n[bold yellow]⚠ Pipeline completed with errors in: {', '.join(errors.keys())}[/bold yellow]")
                    for node, err in errors.items():
                        console.print(f"  [red]{node}:[/red] {err}")
    
    console.print("[bold green]Workflow completed![/bold green]")
