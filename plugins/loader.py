"""
RedChain Plugin Loader — Auto-discovers and loads plugins from directories.
"""

import os
import sys
import importlib
import importlib.util
from pathlib import Path
from typing import List, Dict, Any
from rich.console import Console
from plugins import RedChainPlugin

console = Console()

# Default plugin search paths
PLUGIN_PATHS = [
    os.path.join(os.path.dirname(__file__), "community"),  # Built-in community plugins
    os.path.expanduser("~/.redchain/plugins"),              # User-installed plugins
]


def discover_plugins(extra_paths: List[str] = None) -> List[RedChainPlugin]:
    """
    Discover and load all plugins from search paths.
    
    Each plugin must be a .py file containing a class that inherits from RedChainPlugin.
    """
    plugins: List[RedChainPlugin] = []
    search_paths = PLUGIN_PATHS + (extra_paths or [])
    
    for plugin_dir in search_paths:
        if not os.path.isdir(plugin_dir):
            continue
            
        for filename in sorted(os.listdir(plugin_dir)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
                
            filepath = os.path.join(plugin_dir, filename)
            module_name = f"plugin_{filename[:-3]}"
            
            try:
                spec = importlib.util.spec_from_file_location(module_name, filepath)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Find all RedChainPlugin subclasses in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, RedChainPlugin) and 
                            attr is not RedChainPlugin):
                            plugin_instance = attr()
                            plugins.append(plugin_instance)
                            console.print(f"[dim]  Loaded plugin: {plugin_instance}[/dim]")
            except Exception as e:
                console.print(f"[yellow]  Failed to load plugin {filename}: {e}[/yellow]")
    
    return plugins


def run_plugins_for_phase(plugins: List[RedChainPlugin], phase: str, 
                          state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run all plugins registered for a specific phase.
    
    Args:
        plugins: List of loaded plugins
        phase: Pipeline phase to run plugins for
        state: Current pipeline state
        
    Returns:
        Updated state dict with plugin results merged in
    """
    phase_plugins = [p for p in plugins if p.phase == phase and p.is_available()]
    
    if not phase_plugins:
        return state
    
    console.print(f"[cyan]Running {len(phase_plugins)} plugin(s) for phase: {phase}[/cyan]")
    
    plugin_results = []
    for plugin in phase_plugins:
        try:
            console.print(f"[dim]  Running {plugin.name}...[/dim]")
            result = plugin.run(state)
            if result:
                # Merge plugin results into state
                for key, value in result.items():
                    if key in state and isinstance(state[key], list) and isinstance(value, list):
                        state[key].extend(value)
                    elif key in state and isinstance(state[key], dict) and isinstance(value, dict):
                        state[key].update(value)
                    else:
                        state[key] = value
                plugin_results.append({"plugin": plugin.name, "status": "success"})
        except Exception as e:
            console.print(f"[red]  Plugin {plugin.name} failed: {e}[/red]")
            plugin_results.append({"plugin": plugin.name, "status": "error", "error": str(e)})
    
    # Store plugin execution results
    state.setdefault("plugin_results", []).extend(plugin_results)
    return state
