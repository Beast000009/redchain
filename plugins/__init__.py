"""
RedChain Plugin Architecture — Base class and registration for community plugins.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class RedChainPlugin(ABC):
    """Base class for all RedChain plugins."""
    
    name: str = "unnamed_plugin"
    description: str = ""
    version: str = "0.1.0"
    author: str = ""
    phase: str = "osint"  # "osint", "scan", "exploit", "report", "post"
    
    @abstractmethod
    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the plugin within the pipeline.
        
        Args:
            state: The current AgentState dictionary
            
        Returns:
            dict of state updates to merge back
        """
        ...
    
    @abstractmethod
    def get_requirements(self) -> List[str]:
        """
        Return list of required Python packages or system tools.
        Example: ["nmap", "masscan"] or ["requests>=2.28"]
        """
        ...
    
    def is_available(self) -> bool:
        """Check if all requirements are met for this plugin."""
        return True
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Return JSON schema for plugin-specific configuration."""
        return {}
    
    def __repr__(self):
        return f"<Plugin: {self.name} v{self.version} ({self.phase})>"
