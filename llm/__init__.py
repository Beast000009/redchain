"""
RedChain LLM — Abstract adapter layer for multi-provider AI support.
Supports Gemini, OpenAI, Anthropic, and Ollama (offline/air-gapped).
"""

from abc import ABC, abstractmethod
from typing import Optional


class LLMAdapter(ABC):
    """Abstract base class for LLM providers."""
    
    provider_name: str = "base"
    
    @abstractmethod
    def generate_report(self, system_prompt: str, context: str) -> dict:
        """
        Generate a structured report from scan findings.
        
        Args:
            system_prompt: System-level instruction for the LLM
            context: The full scan findings context
            
        Returns:
            dict with keys: executive_summary, kill_chain_narrative, 
                           attack_path_ascii, remediation_table
        """
        ...
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and reachable."""
        ...
    
    def get_name(self) -> str:
        return self.provider_name


def get_adapter(provider: str, api_key: Optional[str] = None, 
                model: Optional[str] = None, base_url: Optional[str] = None) -> LLMAdapter:
    """
    Factory function to get the appropriate LLM adapter.
    
    Args:
        provider: One of 'gemini', 'openai', 'anthropic', 'ollama'
        api_key: API key for the provider (not needed for ollama)
        model: Model name override
        base_url: Base URL override (for ollama or custom endpoints)
    """
    if provider == "gemini":
        from llm.gemini_adapter import GeminiAdapter
        return GeminiAdapter(api_key=api_key, model=model)
    elif provider == "openai":
        from llm.openai_adapter import OpenAIAdapter
        return OpenAIAdapter(api_key=api_key, model=model, base_url=base_url)
    elif provider == "ollama":
        from llm.ollama_adapter import OllamaAdapter
        return OllamaAdapter(model=model, base_url=base_url)
    else:
        raise ValueError(f"Unknown LLM provider: '{provider}'. Choose from: gemini, openai, ollama")
