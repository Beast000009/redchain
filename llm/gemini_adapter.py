"""Gemini LLM Adapter — Google's Gemini AI backend."""

import json
from typing import Optional
from llm import LLMAdapter


class GeminiAdapter(LLMAdapter):
    provider_name = "gemini"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key
        self.model = model or "gemini-2.5-flash"
    
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def generate_report(self, system_prompt: str, context: str) -> dict:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=self.api_key)
        response = client.models.generate_content(
            model=self.model,
            contents=f"{system_prompt}\n\n{context}",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
            )
        )
        return json.loads(response.text)
