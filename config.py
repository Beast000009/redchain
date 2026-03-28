import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    """
    Configuration settings for RedChain.
    Loads from environment variables or a .env file.
    """
    # API Keys
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API Key")
    vulners_api_key: Optional[str] = Field(default=None, description="Vulners API Key")
    gemini_api_key: Optional[str] = Field(default=None, description="Google Gemini API Key")
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API Key")
    
    # NVD API settings
    nvd_api_key: Optional[str] = Field(default=None, description="NVD API Key (optional but recommended for rate limits)")
    
    # Threat Intelligence API Keys
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API Key")
    abuseipdb_api_key: Optional[str] = Field(default=None, description="AbuseIPDB API Key")
    greynoise_api_key: Optional[str] = Field(default=None, description="GreyNoise API Key")
    
    # LLM Provider settings
    llm_provider: str = Field(default="gemini", description="LLM provider: gemini, openai, ollama")
    llm_model: Optional[str] = Field(default=None, description="LLM model override")
    ollama_base_url: str = Field(default="http://localhost:11434", description="Ollama server URL")
    openai_base_url: Optional[str] = Field(default=None, description="OpenAI-compatible API base URL")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

class RunConfig:
    """Runtime configuration set via CLI args."""
    def __init__(self):
        self.stealth: bool = False
        self.output_format: str = "both"  # pdf, md, json, csv, both
        self.language: str = "en"         # report language
        self.llm_provider: str = "gemini" # gemini, openai, ollama
        self.llm_model: Optional[str] = None
        self.threads: int = 10            # concurrency limit
        self.profile: str = "full"        # quick, full, stealth, compliance
        self.proxy: Optional[str] = None  # HTTP/SOCKS5 proxy
        self.ports: int = 0               # 0 = auto (based on profile), or 50/100/200/1000

# Global settings instance
settings = Settings()
run_config = RunConfig()
