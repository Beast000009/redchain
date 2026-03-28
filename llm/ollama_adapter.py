"""Ollama LLM Adapter — Local/offline AI backend for air-gapped environments."""

import json
from typing import Optional
from llm import LLMAdapter


class OllamaAdapter(LLMAdapter):
    provider_name = "ollama"
    
    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        self.model = model or "llama3.1"
        self.base_url = (base_url or "http://localhost:11434").rstrip("/")
    
    def is_available(self) -> bool:
        import httpx
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=3.0)
            return r.status_code == 200
        except Exception:
            return False
    
    def generate_report(self, system_prompt: str, context: str) -> dict:
        import httpx
        
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": f"{system_prompt}\n\n{context}",
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.3,
                    "num_predict": 8000
                }
            },
            timeout=300.0  # Local models can be slow
        )
        response.raise_for_status()
        result = response.json()
        return json.loads(result.get("response", "{}"))
