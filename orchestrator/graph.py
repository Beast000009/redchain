import operator
import sys
import os
from typing import TypedDict, Annotated, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from rich.console import Console

# Add the project root to sys.path so agents can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

console = Console()

# Define the StateSchema
class AgentState(TypedDict):
    target: str
    input_type: str  # domain, ip, cidr
    
    # Phase 1: OSINT
    osint_results: Dict[str, Any]
    
    # Phase 2: Subdomain
    subdomains: List[Dict[str, Any]]
    
    # Phase 3: Scanner
    live_hosts: List[str]
    scan_results: List[Dict[str, Any]]
    
    # Phase 4: CVE
    cve_findings: List[Dict[str, Any]]
    
    # Phase 5: Report
    kill_chain_narrative: str
    report_paths: Dict[str, str]

# --- Dummy Node Functions (Will be replaced by actual agents) ---

from agents.osint_agent import run_osint
from agents.subdomain_agent import run_subdomain_enum
from agents.scanner_agent import run_scanner
from agents.cve_agent import run_cve_lookup
from agents.report_agent import run_report_agent

import asyncio

def osint_node(state: AgentState):
    console.print(f"[bold blue][OSINT Node][/bold blue] Running OSINT on {state['target']}")
    results = asyncio.run(run_osint(state["target"]))
    return {"osint_results": results}

def subdomain_node(state: AgentState):
    console.print(f"[bold blue][Subdomain Node][/bold blue] Enumerating subdomains for {state['target']}")
    hostnames = state.get("osint_results", {}).get("hostnames", [])
    subdomains = run_subdomain_enum(state["target"], hostnames)
    return {"subdomains": subdomains}

def scanner_node(state: AgentState):
    console.print(f"[bold blue][Scanner Node][/bold blue] Scanning hosts...")
    
    # Gather live hosts from previous steps if available
    live = state.get("live_hosts", [])
    if not live:
        # Extract from subdomains if domain step ran
        for sub in state.get("subdomains", []):
            if sub.get("alive") and sub.get("ip"):
                live.append(sub.get("ip"))
                
    actual_live, scan_results = run_scanner(state["target"], state["input_type"], live)
    return {"live_hosts": actual_live, "scan_results": scan_results}

def cve_node(state: AgentState):
    console.print(f"[bold blue][CVE Node][/bold blue] Looking up CVEs for services...")
    findings = run_cve_lookup(state.get("scan_results", []))
    console.print(f"Found [red]{len(findings)}[/red] CVEs.")
    return {"cve_findings": findings}

def report_node(state: AgentState):
    console.print(f"[bold blue][Report Node][/bold blue] Generating AI narrative and PDF report...")
    results = run_report_agent(state)
    return {
        "kill_chain_narrative": results.get("kill_chain_narrative", ""),
        "report_paths": results.get("report_paths", {})
    }


# --- Routing Logic ---

def route_initial(state: AgentState):
    input_type = state["input_type"]
    if input_type == "domain":
        return "osint"
    elif input_type in ["ip", "cidr"]:
        return "scanner"
    return "osint" # fallback

# --- Build the Graph ---

workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("osint", osint_node)
workflow.add_node("subdomain", subdomain_node)
workflow.add_node("scanner", scanner_node)
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

workflow.add_edge("osint", "subdomain")
workflow.add_edge("subdomain", "scanner")
workflow.add_edge("scanner", "cve")
workflow.add_edge("cve", "report")
workflow.add_edge("report", END)

# Compile graph
app = workflow.compile()

def run_workflow(target: str, input_type: str):
    """"Entry point for cli.py to trigger the flow."""
    console.print(f"[bold green]Starting LangGraph Workflow for {target} ({input_type})[/bold green]")
    
    initial_state = AgentState(
        target=target,
        input_type=input_type,
        osint_results={},
        subdomains=[],
        live_hosts=[],
        scan_results=[],
        cve_findings=[],
        kill_chain_narrative="",
        report_paths={}
    )
    
    # Run the graph
    for output in app.stream(initial_state):
        # We can yield or print progress here
        for key, value in output.items():
            console.print(f"[gray]Finished part:[/gray] {key}")
    
    console.print("[bold green]Workflow completed![/bold green]")
