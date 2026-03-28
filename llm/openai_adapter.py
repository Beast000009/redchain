"""OpenAI LLM Adapter — OpenAI/Azure/Compatible API backend."""

import json
from typing import Optional
from llm import LLMAdapter


class OpenAIAdapter(LLMAdapter):
    provider_name = "openai"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None,
                 base_url: Optional[str] = None):
        self.api_key = api_key
        self.model = model or "gpt-4o"
        self.base_url = base_url  # For Azure or compatible APIs
    
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def generate_report(self, system_prompt: str, context: str) -> dict:
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "OpenAI provider requires the 'openai' package. "
                "Install with: pip install openai"
            )
        
        kwargs = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
            
        client = OpenAI(**kwargs)
        response = client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": context}
            ],
            temperature=0.3,
            max_tokens=8000
        )
        return json.loads(response.choices[0].message.content)
